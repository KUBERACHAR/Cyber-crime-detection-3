"""File-system sensor: create/delete/move events in a watched directory.

Uses watchdog's OS-native file notifications. Events accumulate in a thread-safe
buffer; the collector drains the buffer once per window to count activity.
"""

from __future__ import annotations

import os
import threading

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class _BufferingHandler(FileSystemEventHandler):
    """Appends file events into a shared, lock-protected list."""

    def __init__(self, buffer: list, lock: threading.Lock):
        self._buffer = buffer
        self._lock = lock

    def on_created(self, event):
        self._record("created", event)

    def on_deleted(self, event):
        self._record("deleted", event)

    def on_moved(self, event):
        self._record("moved", event)

    def _record(self, action: str, event):
        with self._lock:
            self._buffer.append(
                {
                    "action": action,
                    "path": getattr(event, "dest_path", None) or event.src_path,
                    "is_directory": event.is_directory,
                }
            )


class FileMonitor:
    """Watches ``watch_dir`` recursively; call :meth:`drain` each window."""

    def __init__(self, watch_dir: str):
        self.watch_dir = watch_dir
        self._buffer: list = []
        self._lock = threading.Lock()
        self._observer = Observer()
        self._started = False

    def start(self) -> None:
        os.makedirs(self.watch_dir, exist_ok=True)
        handler = _BufferingHandler(self._buffer, self._lock)
        self._observer.schedule(handler, self.watch_dir, recursive=True)
        self._observer.start()
        self._started = True

    def drain(self) -> list:
        """Return all buffered events since the last drain and clear the buffer."""
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
        return items

    def stop(self) -> None:
        if not self._started:
            return
        try:
            self._observer.stop()
            self._observer.join(timeout=3)
        except Exception:
            pass
