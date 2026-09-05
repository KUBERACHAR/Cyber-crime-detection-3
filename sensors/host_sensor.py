"""Host sensor: CPU, RAM, running processes, and logged-in users via psutil."""

from __future__ import annotations

import psutil


def sample_host() -> dict:
    """Take a point-in-time snapshot of host resources and processes.

    ``cpu_pct`` is measured non-blocking (interval=None): it reports utilization
    since the previous call, so callers should sample on a steady cadence.
    """
    cpu_pct = psutil.cpu_percent(interval=None)
    ram_pct = psutil.virtual_memory().percent

    processes = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "username", "create_time"]):
        try:
            info = proc.info
            processes.append(
                {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": (info.get("name") or "").lower(),
                    "username": info.get("username"),
                    "create_time": info.get("create_time"),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process vanished mid-iteration or is protected; skip it.
            continue

    try:
        users = [u.name for u in psutil.users()]
    except Exception:
        users = []

    return {
        "cpu_pct": cpu_pct,
        "ram_pct": ram_pct,
        "processes": processes,
        "users": users,
    }
