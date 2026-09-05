"""Real-time SOC dashboard (Phase 5).

Run from the project root:
  streamlit run dashboard/app.py

Each refresh it samples one telemetry window (reusing the same sensors and feature
definition as the collector), predicts a threat probability with the trained model,
and renders the score, live metrics, process table, and alerts. If models/model.pkl
does not exist yet, it falls back to a transparent rule-based score so the dashboard
is demoable before training.
"""

from __future__ import annotations

import os
import sys
import time
from collections import deque

import pandas as pd
import streamlit as st

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.features import FEATURE_COLUMNS, SUSPICIOUS_PROCESS_NAMES, LABEL_SUSPICIOUS, to_vector
from sensors.collector import build_feature_row
from sensors.file_sensor import FileMonitor

MODEL_PATH = os.path.join(_ROOT, "models", "model.pkl")

st.set_page_config(page_title="Cyber Crime Observation Device", page_icon="🛡️", layout="wide")


@st.cache_resource
def load_bundle():
    """Load the trained model bundle once. Returns None if not trained yet."""
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        import joblib
        return joblib.load(MODEL_PATH)
    except Exception as exc:  # version mismatch, corrupt file, etc.
        return {"error": str(exc)}


def heuristic_score(row: dict) -> float:
    """Transparent fallback used when no model is available.

    Weighted blend of the strongest attack signals, each capped at 1.0.
    """
    file_sig = min(row["file_event_rate"] / 20.0, 1.0)
    proc_sig = min(row["suspicious_proc_count"] / 3.0, 1.0)
    spawn_sig = min(row["new_process_count"] / 10.0, 1.0)
    return round(0.5 * file_sig + 0.3 * proc_sig + 0.2 * spawn_sig, 4)


def model_score(row: dict, bundle: dict) -> float:
    """Probability of the Suspicious class from the Random Forest."""
    rf = bundle["rf"]
    classes = bundle.get("classes", list(rf.classes_))
    proba = rf.predict_proba([to_vector(row)])[0]
    if LABEL_SUSPICIOUS in classes:
        return float(proba[classes.index(LABEL_SUSPICIOUS)])
    return float(max(proba))


def render_gauge(score: float) -> str:
    pct = int(score * 100)
    if score >= 0.7:
        color, label = "#dc2626", "HIGH THREAT"
    elif score >= 0.4:
        color, label = "#f59e0b", "ELEVATED"
    else:
        color, label = "#16a34a", "NORMAL"
    return f"""
    <div style="border:1px solid #333;border-radius:12px;padding:18px;text-align:center;">
      <div style="font-size:14px;color:#888;letter-spacing:1px;">THREAT SEVERITY</div>
      <div style="font-size:56px;font-weight:800;color:{color};line-height:1.1;">{pct}%</div>
      <div style="font-size:18px;font-weight:700;color:{color};">{label}</div>
      <div style="background:#222;border-radius:6px;height:12px;margin-top:10px;overflow:hidden;">
        <div style="width:{pct}%;height:100%;background:{color};"></div>
      </div>
    </div>
    """


# --- Sidebar controls ---
st.sidebar.title("🛡️ Controls")
bundle = load_bundle()
if bundle is None:
    st.sidebar.warning("No trained model found.\nUsing rule-based fallback.\nTrain in Colab → commit models/model.pkl.")
    scorer_name = "Heuristic (no model)"
elif "error" in bundle:
    st.sidebar.error(f"Model failed to load:\n{bundle['error']}\n\nCheck scikit-learn versions match.")
    bundle = None
    scorer_name = "Heuristic (load failed)"
else:
    st.sidebar.success(f"Model loaded (RF acc={bundle.get('accuracy', 0):.2f})")
    scorer_name = "Random Forest model"

interval = st.sidebar.slider("Refresh interval (s)", 1.0, 5.0, 2.0, 0.5)
default_watch = os.path.join(os.path.expanduser("~"), "Downloads")
watch_dir = st.sidebar.text_input("Watched directory", value=default_watch)
threshold = st.sidebar.slider("Alert threshold", 0.0, 1.0, 0.7, 0.05)
running = st.sidebar.toggle("Live monitoring", value=True)

# --- Persistent state across reruns ---
if "monitor" not in st.session_state or st.session_state.get("watch_dir") != watch_dir:
    old = st.session_state.get("monitor")
    if old is not None:
        old.stop()
    monitor = FileMonitor(watch_dir)
    try:
        monitor.start()
    except Exception as exc:
        st.error(f"Could not watch '{watch_dir}': {exc}")
    st.session_state.monitor = monitor
    st.session_state.watch_dir = watch_dir
    st.session_state.prev_pids = set()
    st.session_state.history = deque(maxlen=60)

monitor = st.session_state.monitor

# --- Header ---
st.title("AI-Based Cyber Crime Observation Device")
st.caption(f"Software-defined SOC · scorer: **{scorer_name}** · watching `{watch_dir}`")

# --- Sample one window ---
file_events = monitor.drain()
row, st.session_state.prev_pids, host = build_feature_row(
    st.session_state.prev_pids, interval, file_events
)
score = model_score(row, bundle) if bundle else heuristic_score(row)
st.session_state.history.append(score)

# --- Layout ---
left, right = st.columns([1, 2])
with left:
    st.markdown(render_gauge(score), unsafe_allow_html=True)
    if score >= threshold:
        st.error(f"🚨 ALERT — suspicious activity detected ({int(score*100)}%)")

with right:
    c1, c2, c3 = st.columns(3)
    c1.metric("CPU", f"{row['cpu_pct']:.0f}%")
    c2.metric("RAM", f"{row['ram_pct']:.0f}%")
    c3.metric("Processes", f"{row['process_count']}")
    c4, c5, c6 = st.columns(3)
    c4.metric("File events/s", f"{row['file_event_rate']:.1f}")
    c5.metric("New processes", f"{row['new_process_count']}")
    c6.metric("Connections", f"{row['conn_count']}")

st.subheader("Threat score history")
st.line_chart(pd.DataFrame({"threat": list(st.session_state.history)}))

col_a, col_b = st.columns(2)
with col_a:
    st.subheader("Flagged processes (LOLBins)")
    flagged = [p for p in host["processes"] if p["name"] in SUSPICIOUS_PROCESS_NAMES]
    if flagged:
        st.dataframe(
            pd.DataFrame(flagged)[["pid", "ppid", "name", "username"]],
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("None in this window.")

with col_b:
    st.subheader("Current feature vector")
    st.dataframe(
        pd.DataFrame({"feature": FEATURE_COLUMNS, "value": [row[c] for c in FEATURE_COLUMNS]}),
        use_container_width=True, hide_index=True,
    )

# --- Auto-refresh: rerun after the interval so controls stay responsive ---
if running:
    time.sleep(interval)
    st.rerun()
