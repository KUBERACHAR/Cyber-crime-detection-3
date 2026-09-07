# Development Roadmap — AI-Based Cyber Crime Observation Device

This is the ordered, no-code procedure for building the system. Each phase maps to
an objective in [`../spec.md`](../spec.md). Do the phases in order — later phases
depend on outputs from earlier ones.

> **Environment reminder**
> - **Laptop / VS Code** → sensors, data collection, dashboard, git (Phases 1, 2, 3, 5, 6)
> - **Google Colab** → all ML training (Phase 4)
> - **GitHub** → the bridge that moves code, data, and the trained model between them

---

## Phase 0 — One-time pre-setup (do this first)

**On the laptop:**
1. Confirm tools: `python --version` (3.11+), `git --version`, VS Code with the
   *Python* and *Jupyter* extensions installed.
2. Create and activate a virtual environment, then install laptop deps:
   ```
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
**On GitHub:**
3. Create a new **empty private** repository (do NOT let GitHub add a README —
   this scaffold already has one).
4. Connect and push:
   ```
   git remote add origin https://github.com/<you>/<repo>.git
   git branch -M main
   git push -u origin main
   ```
**On Google:**
5. Confirm you can open https://colab.research.google.com and sign in.

**Handoff decision (already chosen):** the trained `model.pkl` will be committed
into `models/` in the repo (it will be small — a few MB). Google Drive mount is the
fallback only if that file ever grows large.

---

## Phase 1 — Sensors (laptop / VS Code)

**Goal:** modular Python sensors that emit a unified JSON event schema.

Build these in `sensors/`:
- **Host sensor** — CPU %, RAM %, active process list, user sessions (`psutil`).
- **Network sensor** — active socket connections: source/dest IP, ports, TCP state
  (`psutil.net_connections`).
- **File sensor** — create/delete events in a watched directory (`watchdog`).
- **Schema module** — one canonical JSON event shape shared by all sensors, so every
  payload validates identically (spec requires consistent JSON across sensors).

**Suggested unified event fields:** `timestamp`, `event_type`, `cpu_pct`, `ram_pct`,
`process_name`, `pid`, `parent_pid`, `src_ip`, `dst_ip`, `dst_port`, `tcp_state`,
`file_path`, `file_action`, `label` (left blank here; filled during collection).

**Milestone:** running the sensors prints/appends live activity as valid JSON events.

---

## Phase 2 — Data collection & labeling (laptop)

**Goal:** a labeled dataset the model can learn from.

1. **Collect Normal data.** Run the sensors during ordinary use — browsing in Chrome,
   editing in VS Code, reading a PDF — for a sustained period. Tag every event
   `label = Normal`. Save to `data/raw/`.
2. **Collect Suspicious data** using SAFE, self-contained simulations (no real
   malware, run only on your own machine, in a temp folder):
   - Rapid file dumping: a script that creates hundreds of files quickly in a temp
     folder (mimics ransomware/exfil staging).
   - Benign PowerShell spawn loop: repeatedly launch and exit `powershell.exe`
     (mimics living-off-the-land process bursts).
   Tag these events `label = Suspicious`. Save to `data/raw/`.
3. **Consolidate** the raw logs into a single cleaned, labeled CSV in
   `data/processed/` (e.g. `sample_dataset.csv`). Balance the classes reasonably.

**Safety note:** simulations must be reversible and confined to a temp directory you
control. Do not download or execute real malicious payloads.

**Milestone:** one labeled CSV with both Normal and Suspicious rows.

---

## Phase 3 — Push to GitHub (laptop) — the handoff point

1. Commit your sensor code.
2. Force-add the small labeled sample (raw data is git-ignored by default):
   ```
   git add sensors/ data/processed/sample_dataset.csv
   git commit -m "Phase 1-2: sensors + labeled sample dataset"
   git push
   ```
This makes the dataset available to Colab.

---

## Phase 4 — Machine learning (Google Colab)

**Goal:** trained models that hit the spec's >90% accuracy with low false positives.

1. Open `notebooks/train_model.ipynb` in Colab (File → Open notebook → GitHub tab →
   pick your repo), or upload the CSV directly.
2. Pull the dataset — either `!git clone <repo>` or upload `sample_dataset.csv`.
3. Install training deps: `!pip install -r requirements-colab.txt`.
4. **Feature engineering** — turn raw events into a numeric feature vector
   (e.g. file-creation rate per second, process spawn frequency, unusual dest ports,
   CPU/RAM deltas).
5. **Train Random Forest** (supervised) to classify Normal vs Suspicious.
6. **Train Isolation Forest** (unsupervised) for anomaly/zero-day scoring.
7. **Evaluate** — accuracy, precision/recall, confusion matrix, feature importance.
   Target: >90% accuracy, minimized false positives on routine workflows.
8. **Export** the fitted model(s) with `joblib.dump(...)` → `model.pkl`.
9. **Commit the model back** to `models/` (from Colab: configure git, or download
   `model.pkl` and commit it from the laptop).

**Version alignment:** keep scikit-learn the same version in Colab and on the laptop
(`requirements-colab.txt` ↔ `requirements.txt`) so `model.pkl` loads without errors.

**Milestone:** `models/model.pkl` exists in the repo and evaluation meets the target.

---

## Phase 5 — Dashboard (laptop / VS Code)

**Goal:** live Streamlit SOC UI matching the spec's demonstration flow.

Build `dashboard/app.py`:
- On startup, `git pull` and `joblib.load('models/model.pkl')`.
- Consume the live sensor JSON stream, build the same feature vector used in training.
- Predict a **threat probability score** for the current activity.
- Render: threat severity score/gauge, live system metrics (CPU/RAM), active process
  table, and a **red alert** when the score crosses a threshold.
- Run with `streamlit run dashboard/app.py`.

**Milestone:** the full demo works — baseline shows Normal; triggering the file-dump
or PowerShell simulation flips the dashboard to a red high-threat alert.

---

## Phase 6 — Validate & iterate

- Measure end-to-end latency (event → feature → prediction → UI). Target < 500 ms.
- Tune features and thresholds to reduce false positives during normal workflows.
- Collect more data (Phase 2), retrain in Colab (Phase 4), re-pull the model (Phase 5).
- Repeat until detection quality and latency are stable.

---

## Out of scope (per spec — do not build)

- Kernel-level / Ring-0 memory inspection or driver development.
- Fully automated (no-confirmation) response or remote endpoint isolation.
  (Human-in-the-loop termination IS now built into the dashboard — see common/response.py.)
- Deep packet payload decryption of SSL/TLS traffic.
- Multi-tenant enterprise cloud database cluster sync.

---

## Quick reference — who does what

| Task | Where | Phase |
|------|-------|-------|
| Write sensors | Laptop / VS Code | 1 |
| Collect + label data | Laptop | 2 |
| Push code & data | Laptop → GitHub | 3 |
| Train & export model | Colab | 4 |
| Commit model back | Colab/Laptop → GitHub | 4 |
| Build dashboard | Laptop / VS Code | 5 |
| Validate & tune | Laptop (+ Colab retrain) | 6 |
