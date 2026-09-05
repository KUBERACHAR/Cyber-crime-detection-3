"""Single source of truth for the feature vector.

Both the sensor collector (training data) and the dashboard (live prediction)
import from here, so the columns and their order are guaranteed identical. If the
two ever disagreed, the model would receive scrambled inputs and predictions would
be meaningless -- keeping one definition here prevents that class of bug.
"""

from __future__ import annotations

# Order matters: model training and live prediction both build vectors in THIS order.
FEATURE_COLUMNS = [
    "cpu_pct",               # host CPU utilization (%)
    "ram_pct",               # host RAM utilization (%)
    "process_count",         # number of running processes this window
    "new_process_count",     # processes that appeared since the previous window (spawn bursts)
    "file_create_count",     # file create/move events in the watched dir this window
    "file_delete_count",     # file delete events in the watched dir this window
    "file_event_rate",       # (creates + deletes) per second -- rapid dumping signal
    "conn_count",            # active network connections
    "distinct_remote_ips",   # unique remote IPs connected to
    "distinct_remote_ports", # unique remote ports -- scanning / beaconing signal
    "established_count",     # connections in ESTABLISHED state
    "suspicious_proc_count", # running processes whose name is a common LOLBin
]

# Labels used throughout the pipeline.
LABEL_NORMAL = "Normal"
LABEL_SUSPICIOUS = "Suspicious"
LABEL_UNLABELED = "unlabeled"

# "Living off the land" binaries frequently abused by fileless / script-based attacks.
# A process merely being one of these is not proof of an attack -- it is one weak
# signal the model weighs alongside the others.
SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "powershell", "pwsh",
    "cmd.exe", "cmd",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
}


def empty_row() -> dict:
    """A zeroed feature row (all columns present)."""
    return {c: 0 for c in FEATURE_COLUMNS}


def to_vector(row: dict) -> list[float]:
    """Convert a feature dict into an ordered numeric list for the model.

    Missing keys default to 0.0 so a partial row never raises.
    """
    return [float(row.get(c, 0) or 0) for c in FEATURE_COLUMNS]
