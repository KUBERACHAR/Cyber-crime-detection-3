"""Flask-based SOC dashboard server (Desktop Web UI replacement for Streamlit).

Run from the project root:
  python dashboard/server.py

Opens a local web server at http://localhost:5000 which serves the full
desktop-grade UI. All sensor logic and model inference are identical to the
Streamlit version — only the presentation layer changed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import threading
from collections import deque

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from flask import Flask, Response, jsonify, request, send_from_directory

from common.features import FEATURE_COLUMNS, SUSPICIOUS_PROCESS_NAMES, LABEL_SUSPICIOUS, to_vector
from common.response import list_kill_candidates, terminate_pid
from sensors.collector import build_feature_row
from sensors.file_sensor import FileMonitor

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
MODEL_PATH = os.path.join(_ROOT, "models", "model.pkl")
POPUP_PATH  = os.path.join(_ROOT, "alerts", "popup.py")
STATIC_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")

# ---------------------------------------------------------------------------
# Global monitor state  (single user — desktop app)
# ---------------------------------------------------------------------------
_state = {
    "monitor":       None,
    "watch_dir":     os.path.join(os.path.expanduser("~"), "Downloads"),
    "prev_pids":     set(),
    "history":       deque(maxlen=60),
    "actions":       [],          # audit log
    "snooze_until":  0.0,
    "popup_shown":   False,
    "interval":      2.0,
    "threshold":     0.7,
    "allow_terminate": True,
    "popup_alerts":  True,
    "running":       True,
    "scorer_name":   "Unknown",
    "bundle":        None,
    "bundle_error":  None,
    "last_row":      None,
    "last_score":    0.0,
    "last_host":     None,
    "last_candidates": [],
}
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def _load_bundle():
    if not os.path.exists(MODEL_PATH):
        return None, None
    try:
        import joblib
        b = joblib.load(MODEL_PATH)
        return b, None
    except Exception as exc:
        return None, str(exc)


bundle, bundle_error = _load_bundle()
with _lock:
    _state["bundle"]       = bundle
    _state["bundle_error"] = bundle_error
    if bundle is None and bundle_error is None:
        _state["scorer_name"] = "Heuristic (no model)"
    elif bundle_error:
        _state["scorer_name"] = "Heuristic (load failed)"
    else:
        _state["scorer_name"] = f"Random Forest (acc={bundle.get('accuracy', 0):.2f})"

# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def heuristic_score(row: dict) -> float:
    file_sig  = min(row["file_event_rate"]    / 20.0, 1.0)
    proc_sig  = min(row["suspicious_proc_count"] / 3.0, 1.0)
    spawn_sig = min(row["new_process_count"]  / 10.0, 1.0)
    return round(0.5 * file_sig + 0.3 * proc_sig + 0.2 * spawn_sig, 4)


def model_score(row: dict, bundle: dict) -> float:
    rf      = bundle["rf"]
    classes = bundle.get("classes", list(rf.classes_))
    proba   = rf.predict_proba([to_vector(row)])[0]
    if LABEL_SUSPICIOUS in classes:
        return float(proba[classes.index(LABEL_SUSPICIOUS)])
    return float(max(proba))

# ---------------------------------------------------------------------------
# File monitor helpers
# ---------------------------------------------------------------------------

def _pythonw() -> str:
    cand = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return cand if os.path.exists(cand) else sys.executable


def _fire_popup(pct: int, url: str) -> None:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.Popen([_pythonw(), POPUP_PATH, str(pct), url], creationflags=flags)
    except Exception:
        pass


def _ensure_monitor(watch_dir: str) -> None:
    """Start/restart file monitor if watch_dir changed."""
    with _lock:
        old = _state.get("monitor")
        if old is not None and _state["watch_dir"] == watch_dir:
            return
        if old is not None:
            try:
                old.stop()
            except Exception:
                pass
        m = FileMonitor(watch_dir)
        try:
            m.start()
        except Exception:
            pass
        _state["monitor"]    = m
        _state["watch_dir"]  = watch_dir
        _state["prev_pids"]  = set()
        _state["history"]    = deque(maxlen=60)

# ---------------------------------------------------------------------------
# Background sampling thread
# ---------------------------------------------------------------------------

def _sampling_loop() -> None:
    """Continuously sample telemetry and update shared state."""
    # Prime psutil CPU meter
    from sensors.host_sensor import sample_host
    sample_host()

    while True:
        with _lock:
            running   = _state["running"]
            interval  = _state["interval"]
            threshold = _state["threshold"]
            watch_dir = _state["watch_dir"]
            allow_terminate = _state["allow_terminate"]
            popup_on  = _state["popup_alerts"]
            b         = _state["bundle"]
            monitor   = _state["monitor"]
            prev_pids = _state["prev_pids"]
            snooze    = _state["snooze_until"]

        if not running:
            time.sleep(0.5)
            continue

        _ensure_monitor(watch_dir)

        with _lock:
            monitor   = _state["monitor"]
            prev_pids = _state["prev_pids"]

        if monitor is None:
            time.sleep(interval)
            continue

        file_events = monitor.drain()
        try:
            row, new_pids, host = build_feature_row(prev_pids, interval, file_events)
        except Exception:
            time.sleep(interval)
            continue

        score = model_score(row, b) if b else heuristic_score(row)
        alert_active = score >= threshold
        candidates   = list_kill_candidates(host) if alert_active else []

        # Desktop popup — fires once per episode
        now = time.time()
        with _lock:
            popup_shown = _state["popup_shown"]
            if alert_active and not popup_shown and popup_on and now > _state["snooze_until"]:
                _fire_popup(int(score * 100), "http://localhost:5000")
                _state["popup_shown"] = True
            elif not alert_active:
                _state["popup_shown"] = False

            _state["prev_pids"]      = new_pids
            _state["history"].append(score)
            _state["last_row"]       = row
            _state["last_score"]     = score
            _state["last_host"]      = host
            _state["last_candidates"] = candidates

        time.sleep(interval)


_sampling_thread = threading.Thread(target=_sampling_loop, daemon=True)
_sampling_thread.start()

# ---------------------------------------------------------------------------
# Routes — static pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    with _lock:
        row        = _state["last_row"] or {c: 0 for c in FEATURE_COLUMNS}
        score      = _state["last_score"]
        host       = _state["last_host"] or {"processes": [], "users": []}
        history    = list(_state["history"])
        candidates = _state["last_candidates"]
        actions    = list(_state["actions"])[-20:]
        scorer     = _state["scorer_name"]
        threshold  = _state["threshold"]
        watch_dir  = _state["watch_dir"]
        running    = _state["running"]
        interval   = _state["interval"]
        allow_term = _state["allow_terminate"]
        popup_on   = _state["popup_alerts"]
        b_err      = _state["bundle_error"]

    alert_active = score >= threshold

    flagged = [
        p for p in host["processes"]
        if p["name"] in SUSPICIOUS_PROCESS_NAMES
    ]

    feature_vec = [{"feature": c, "value": row.get(c, 0)} for c in FEATURE_COLUMNS]

    return jsonify({
        "score":       score,
        "pct":         int(score * 100),
        "alert":       alert_active,
        "scorer":      scorer,
        "bundle_error": b_err,
        "threshold":   threshold,
        "watch_dir":   watch_dir,
        "running":     running,
        "interval":    interval,
        "allow_terminate": allow_term,
        "popup_alerts": popup_on,
        "metrics": {
            "cpu_pct":         row.get("cpu_pct", 0),
            "ram_pct":         row.get("ram_pct", 0),
            "process_count":   row.get("process_count", 0),
            "file_event_rate": row.get("file_event_rate", 0),
            "new_process_count": row.get("new_process_count", 0),
            "conn_count":      row.get("conn_count", 0),
        },
        "history":     history,
        "flagged":     flagged,
        "candidates":  candidates,
        "feature_vec": feature_vec,
        "actions":     actions,
    })


@app.route("/api/settings", methods=["POST"])
def api_settings():
    data = request.get_json(force=True) or {}
    with _lock:
        if "interval" in data:
            _state["interval"] = float(data["interval"])
        if "threshold" in data:
            _state["threshold"] = float(data["threshold"])
        if "watch_dir" in data:
            new_dir = str(data["watch_dir"])
            if new_dir != _state["watch_dir"]:
                _state["watch_dir"] = new_dir
                # Force monitor restart by clearing it
                old = _state.get("monitor")
                if old:
                    try: old.stop()
                    except Exception: pass
                _state["monitor"] = None
        if "running" in data:
            _state["running"] = bool(data["running"])
        if "allow_terminate" in data:
            _state["allow_terminate"] = bool(data["allow_terminate"])
        if "popup_alerts" in data:
            _state["popup_alerts"] = bool(data["popup_alerts"])
    return jsonify({"ok": True})


@app.route("/api/terminate", methods=["POST"])
def api_terminate():
    data = request.get_json(force=True) or {}
    pid  = int(data.get("pid", 0))
    with _lock:
        allow = _state["allow_terminate"]
    if not allow:
        return jsonify({"ok": False, "message": "Process termination is disabled."})
    ok, msg = terminate_pid(pid)
    stamp = time.strftime("%H:%M:%S")
    with _lock:
        _state["actions"].append(f"[{stamp}] {msg}")
        _state["prev_pids"].discard(pid)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/snooze", methods=["POST"])
def api_snooze():
    with _lock:
        _state["snooze_until"] = time.time() + 30
    return jsonify({"ok": True, "snooze_until": _state["snooze_until"]})


# ---------------------------------------------------------------------------
# SSE stream for live push  (optional — UI also polls via fetch)
# ---------------------------------------------------------------------------

@app.route("/api/stream")
def api_stream():
    def event_gen():
        while True:
            with _lock:
                score   = _state["last_score"]
                history = list(_state["history"])
                metrics = {
                    "cpu_pct":           _state["last_row"].get("cpu_pct", 0) if _state["last_row"] else 0,
                    "ram_pct":           _state["last_row"].get("ram_pct", 0) if _state["last_row"] else 0,
                    "process_count":     _state["last_row"].get("process_count", 0) if _state["last_row"] else 0,
                    "file_event_rate":   _state["last_row"].get("file_event_rate", 0) if _state["last_row"] else 0,
                    "new_process_count": _state["last_row"].get("new_process_count", 0) if _state["last_row"] else 0,
                    "conn_count":        _state["last_row"].get("conn_count", 0) if _state["last_row"] else 0,
                }
                threshold  = _state["threshold"]
                interval   = _state["interval"]
            payload = json.dumps({"score": score, "history": history, "metrics": metrics,
                                  "threshold": threshold, "alert": score >= threshold})
            yield f"data: {payload}\n\n"
            time.sleep(max(0.5, interval))

    return Response(event_gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import webbrowser
    print("\n" + "="*60)
    print("  AI-Based Cyber Crime Observation Device")
    print("  SOC Dashboard  ->  http://localhost:5000")
    print("="*60 + "\n")
    # Open browser after a short delay so Flask is ready
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5000")).start()
    # Initialise the file monitor for the default directory
    _ensure_monitor(_state["watch_dir"])
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
