"""Network sensor: active inet socket connections via psutil.

Captures connection headers only (addresses, ports, TCP state) -- never payloads.
Deep packet / payload inspection is explicitly out of scope per the spec.
"""

from __future__ import annotations

import psutil


def sample_network() -> list[dict]:
    """Return the current inet (TCP/UDP) connections as a list of dicts."""
    try:
        raw = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # On some systems enumerating all connections needs elevation; degrade
        # gracefully to an empty list rather than crashing the collector.
        return []

    connections = []
    for conn in raw:
        laddr = conn.laddr
        raddr = conn.raddr
        connections.append(
            {
                "pid": conn.pid,
                "status": conn.status,
                "laddr_ip": laddr.ip if laddr else None,
                "laddr_port": laddr.port if laddr else None,
                "raddr_ip": raddr.ip if raddr else None,
                "raddr_port": raddr.port if raddr else None,
            }
        )
    return connections
