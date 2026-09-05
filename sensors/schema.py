"""Unified event schema + JSON Lines writer.

Every sensor payload flows through here so all telemetry shares one consistent
JSON shape (a spec requirement). Feature rows are written one JSON object per line
(JSONL), which is append-friendly and trivially streamable.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from common.features import LABEL_UNLABELED


def new_event(event_type: str, label: str = LABEL_UNLABELED, **fields) -> dict:
    """Build a canonical event dict with a UTC timestamp and arbitrary fields."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "label": label,
    }
    event.update(fields)
    return event


def append_jsonl(path: str, obj: dict) -> None:
    """Append one JSON object as a line to ``path`` (creating parent dirs)."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(obj) + "\n")
