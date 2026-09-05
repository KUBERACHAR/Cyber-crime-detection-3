"""SAFE simulation: process spawn bursts (mimics living-off-the-land script abuse).

Repeatedly launches a harmless shell process that immediately exits. This drives up
new_process_count and suspicious_proc_count without running anything malicious --
each child just prints a line and quits.

Run WHILE the collector records with --label Suspicious:

  # terminal 1
  python sensors/collector.py --label Suspicious --duration 90
  # terminal 2
  python simulations/process_burst.py --count 60

On Windows it spawns powershell.exe; elsewhere it spawns /bin/sh.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time


def _spawn_one() -> None:
    if os.name == "nt":
        # Harmless: print a string and exit. -NoProfile keeps it fast.
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'sim'"],
            capture_output=True,
        )
    else:
        subprocess.run(["/bin/sh", "-c", "echo sim"], capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe process-spawn-burst simulation")
    parser.add_argument("--count", type=int, default=40, help="Number of processes to spawn.")
    parser.add_argument("--pause", type=float, default=0.1, help="Seconds between spawns.")
    args = parser.parse_args()

    shell = "powershell.exe" if os.name == "nt" else "/bin/sh"
    print(f"[sim:process_burst] spawning {args.count} x {shell} (each exits immediately)")

    try:
        for i in range(args.count):
            _spawn_one()
            if (i + 1) % 10 == 0:
                print(f"[sim:process_burst] spawned {i + 1}/{args.count}")
            time.sleep(args.pause)
    except KeyboardInterrupt:
        print("\n[sim:process_burst] interrupted.")
    print("[sim:process_burst] done.")


if __name__ == "__main__":
    main()
