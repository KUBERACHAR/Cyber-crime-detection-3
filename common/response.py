"""Active response: identify and terminate threatening processes -- with guards.

This is the ONLY part of the system that acts on the host rather than just observing
it, so it is deliberately conservative:

  * It never kills core Windows/OS processes (an allowlist of protected names + low PIDs).
  * It never kills the monitor itself or its parent chain (that would take the
    dashboard down with it).
  * Termination is always driven by an explicit user action in the UI -- nothing
    here fires automatically.

Killing the wrong process can destabilize a running system, which is why the spec
kept response out of scope; this adds it behind a human-in-the-loop confirmation.
"""

from __future__ import annotations

import os

import psutil

from common.features import SUSPICIOUS_PROCESS_NAMES

# Core processes that must never be terminated -- doing so can crash or hang Windows.
PROTECTED_NAMES = {
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
    "fontdrvhost.exe", "spoolsv.exe", "explorer.exe",
    # POSIX equivalents, for completeness on non-Windows hosts:
    "systemd", "init", "kthreadd",
}


def _self_pids() -> set:
    """PIDs of the monitor process and its parents -- never terminate these."""
    pids = {os.getpid()}
    try:
        proc = psutil.Process(os.getpid())
        for parent in proc.parents():
            pids.add(parent.pid)
    except Exception:
        pass
    return pids


def is_protected(proc_info: dict) -> bool:
    """True if this process must not be terminated (system-critical or invalid PID)."""
    pid = proc_info.get("pid")
    name = (proc_info.get("name") or "").lower()
    if pid is None or pid <= 4:  # 0/4 are System/Idle on Windows
        return True
    return name in PROTECTED_NAMES


def list_kill_candidates(host: dict) -> list[dict]:
    """Return terminable processes worth flagging this window.

    Currently: running LOLBins (the same suspicious-process signal the model uses),
    excluding protected processes and the monitor itself, de-duplicated by PID.
    Note: file-burst / ransomware activity is not attributable to a PID from file
    events alone, so such an alert may yield no candidate here -- that is expected.
    """
    self_pids = _self_pids()
    seen: set = set()
    candidates: list[dict] = []
    for proc in host.get("processes", []):
        pid = proc.get("pid")
        if proc.get("name") not in SUSPICIOUS_PROCESS_NAMES:
            continue
        if pid in seen or pid in self_pids or is_protected(proc):
            continue
        seen.add(pid)
        candidates.append(proc)
    return candidates


def terminate_pid(pid: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Attempt to terminate ``pid``. Returns ``(success, message)``.

    Tries a graceful terminate first, then a hard kill if it does not exit within
    ``timeout``. Refuses protected processes and the monitor's own process tree.
    """
    if pid in _self_pids():
        return False, f"Refused: PID {pid} is the monitor's own process."

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return False, f"PID {pid} no longer exists."

    name = ""
    try:
        name = (proc.name() or "").lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    if is_protected({"pid": pid, "name": name}):
        return False, f"Refused: '{name}' (PID {pid}) is a protected system process."

    try:
        proc.terminate()  # graceful (SIGTERM / TerminateProcess)
        try:
            proc.wait(timeout=timeout)
        except psutil.TimeoutExpired:
            proc.kill()  # force
            proc.wait(timeout=timeout)
        return True, f"Terminated '{name or 'process'}' (PID {pid})."
    except psutil.NoSuchProcess:
        return True, f"PID {pid} already exited."
    except psutil.AccessDenied:
        return False, f"Access denied for PID {pid} -- run the dashboard as Administrator."
    except Exception as exc:
        return False, f"Failed to terminate PID {pid}: {exc}"
