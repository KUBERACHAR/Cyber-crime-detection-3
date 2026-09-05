"""SAFE simulation: rapid file dumping (mimics ransomware / data-staging bursts).

This creates many small text files very quickly inside your watch directory, then
(optionally) deletes them. It is completely benign -- it only touches files it
creates itself, inside a dedicated subfolder, and cleans up after itself.

Run this WHILE the collector is recording with --label Suspicious:

  # terminal 1
  python sensors/collector.py --label Suspicious --duration 90
  # terminal 2
  python simulations/file_dump.py --count 800 --burst 40

By default it writes into <watch-dir>/_sim_dump so it never mixes with your real
files. Point --dir at the same directory the collector is watching.
"""

from __future__ import annotations

import argparse
import os
import shutil
import time


def _default_dir() -> str:
    return os.path.join(os.path.expanduser("~"), "Downloads", "_sim_dump")


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe rapid file-dump simulation")
    parser.add_argument("--dir", default=_default_dir(),
                        help="Folder to dump into (default: ~/Downloads/_sim_dump).")
    parser.add_argument("--count", type=int, default=500, help="Total files to create.")
    parser.add_argument("--burst", type=int, default=25, help="Files per burst.")
    parser.add_argument("--pause", type=float, default=0.05, help="Seconds between bursts.")
    parser.add_argument("--keep", action="store_true",
                        help="Keep the files instead of deleting them at the end.")
    args = parser.parse_args()

    os.makedirs(args.dir, exist_ok=True)
    print(f"[sim:file_dump] creating {args.count} files in {args.dir}")

    created = 0
    try:
        while created < args.count:
            for _ in range(min(args.burst, args.count - created)):
                path = os.path.join(args.dir, f"dump_{created:06d}.tmp")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("simulated payload chunk\n")
                created += 1
            print(f"[sim:file_dump] created {created}/{args.count}")
            time.sleep(args.pause)
    except KeyboardInterrupt:
        print("\n[sim:file_dump] interrupted.")
    finally:
        if not args.keep:
            print("[sim:file_dump] cleaning up simulated files...")
            shutil.rmtree(args.dir, ignore_errors=True)
        print("[sim:file_dump] done.")


if __name__ == "__main__":
    main()
