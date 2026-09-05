"""Telemetry collector (Phase 1 + 2).

Runs a steady sampling loop. Each window it snapshots host + network state, drains
file events, aggregates everything into ONE feature row (see common.features), and
writes it to:
  * a JSONL stream in data/raw/   (unified event log)
  * a labeled CSV  in data/processed/ (training dataset)

Usage examples (from the project root):

  # Record normal activity for 5 minutes while you browse / edit code:
  python sensors/collector.py --label Normal --duration 300

  # In another terminal, run a simulation and record it as suspicious:
  python sensors/collector.py --label Suspicious --duration 120

Both write to the same CSV by default so you build one combined dataset.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import time

# Make the project root importable when run as a script (python sensors/collector.py).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.features import (
    FEATURE_COLUMNS,
    SUSPICIOUS_PROCESS_NAMES,
    LABEL_UNLABELED,
)
from sensors.host_sensor import sample_host
from sensors.network_sensor import sample_network
from sensors.file_sensor import FileMonitor
from sensors.schema import new_event, append_jsonl


def build_feature_row(prev_pids: set, interval: float, file_events: list) -> tuple[dict, set, dict]:
    """Aggregate one window of telemetry into a feature row.

    Returns ``(feature_row, current_pids, host_snapshot)``. ``current_pids`` is fed
    back in as ``prev_pids`` next window to detect newly spawned processes.
    """
    host = sample_host()
    net = sample_network()

    current_pids = {p["pid"] for p in host["processes"]}
    new_pids = current_pids - prev_pids
    suspicious = sum(1 for p in host["processes"] if p["name"] in SUSPICIOUS_PROCESS_NAMES)

    creates = sum(1 for e in file_events if e["action"] in ("created", "moved"))
    deletes = sum(1 for e in file_events if e["action"] == "deleted")

    remote_ips = {c["raddr_ip"] for c in net if c["raddr_ip"]}
    remote_ports = {c["raddr_port"] for c in net if c["raddr_port"]}
    established = sum(1 for c in net if c["status"] == "ESTABLISHED")

    row = {
        "cpu_pct": host["cpu_pct"],
        "ram_pct": host["ram_pct"],
        "process_count": len(current_pids),
        "new_process_count": len(new_pids),
        "file_create_count": creates,
        "file_delete_count": deletes,
        "file_event_rate": (creates + deletes) / max(interval, 1e-6),
        "conn_count": len(net),
        "distinct_remote_ips": len(remote_ips),
        "distinct_remote_ports": len(remote_ports),
        "established_count": established,
        "suspicious_proc_count": suspicious,
    }
    return row, current_pids, host


def _default_watch_dir() -> str:
    return os.path.join(os.path.expanduser("~"), "Downloads")


def _append_csv(path: str, row: dict, label: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(FEATURE_COLUMNS + ["label"])
        writer.writerow([row[c] for c in FEATURE_COLUMNS] + [label])


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Cyber Crime Observation Device -- telemetry collector")
    parser.add_argument("--label", default=LABEL_UNLABELED,
                        help="Label for rows collected in this run (Normal / Suspicious).")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Seconds per sampling window (default 1.0).")
    parser.add_argument("--duration", type=float, default=0.0,
                        help="Total seconds to run; 0 = until Ctrl+C.")
    parser.add_argument("--watch-dir", default=_default_watch_dir(),
                        help="Directory watched for file events (default: ~/Downloads).")
    parser.add_argument("--csv", default=os.path.join(_ROOT, "data", "processed", "dataset.csv"),
                        help="Feature CSV to append to.")
    parser.add_argument("--raw", default=os.path.join(_ROOT, "data", "raw", "events.jsonl"),
                        help="JSONL event stream to append to.")
    args = parser.parse_args()

    print(f"[collector] label={args.label} interval={args.interval}s "
          f"duration={'infinite' if args.duration == 0 else str(args.duration) + 's'}")
    print(f"[collector] watching: {args.watch_dir}")
    print(f"[collector] csv -> {args.csv}")
    print("[collector] Ctrl+C to stop.\n")

    monitor = FileMonitor(args.watch_dir)
    monitor.start()

    prev_pids: set = set()
    windows = 0
    try:
        # Prime cpu_percent and the process set so the first window's readings
        # (cpu %, new_process_count) reflect real activity instead of a cold start.
        sample_host()
        prev_pids = {p["pid"] for p in sample_host()["processes"]}
        # Start the duration clock AFTER priming so it measures actual collection time.
        start = time.time()
        while True:
            window_start = time.time()
            file_events = monitor.drain()
            row, prev_pids, _ = build_feature_row(prev_pids, args.interval, file_events)

            _append_csv(args.csv, row, args.label)
            append_jsonl(args.raw, new_event("window", label=args.label, **row))
            windows += 1

            print(f"[{windows:>4}] cpu={row['cpu_pct']:>5.1f}% ram={row['ram_pct']:>5.1f}% "
                  f"procs={row['process_count']:>3} new={row['new_process_count']:>2} "
                  f"file_rate={row['file_event_rate']:>6.2f}/s susp_proc={row['suspicious_proc_count']:>2} "
                  f"conns={row['conn_count']:>3} label={args.label}")

            if args.duration and (time.time() - start) >= args.duration:
                break

            elapsed = time.time() - window_start
            time.sleep(max(0.0, args.interval - elapsed))
    except KeyboardInterrupt:
        print("\n[collector] stopped by user.")
    finally:
        monitor.stop()
        print(f"[collector] wrote {windows} rows to {args.csv}")


if __name__ == "__main__":
    main()
