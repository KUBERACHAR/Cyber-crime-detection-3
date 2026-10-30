# AI-Based Cyber Crime Observation Device

A lightweight, software-only endpoint telemetry and threat-monitoring engine that
emulates a Security Operations Center (SOC) on a single laptop. It captures host
metrics, active processes, network sockets, and file-system events, classifies
behavior as **Normal** or **Suspicious** using machine learning, and surfaces the
result in a real-time **premium desktop web dashboard** (Flask + HTML/CSS/JS).

See [`spec.md`](spec.md) for the full concept and objectives.

---

## Architecture (two-environment split)

Because training ML models is CPU/GPU heavy, work is split across two machines and
bridged by GitHub:

| Environment | Responsibility |
|-------------|----------------|
| **VS Code (this laptop)** | Sensors, data collection, Flask web dashboard, git |
| **Google Colab** | Feature engineering + training Random Forest & Isolation Forest |
| **GitHub** | Bridge: push logs/code up, pull trained `model.pkl` back down |

**Key idea:** Colab produces a trained `model.pkl`. The laptop only *loads and runs*
it — running a Random Forest is cheap, so your hardware is never the bottleneck.

---

## Repository layout

```
Cyber-project/
├── spec.md                  # project specification
├── README.md                # this file
├── requirements.txt         # laptop dependencies (sensors + Flask dashboard)
├── requirements-colab.txt   # Colab dependencies (ML training)
├── run_dashboard.bat        # Windows double-click launcher
├── .gitignore
├── common/                  # shared feature definition + active-response logic
├── sensors/                 # host, network, file-system sensors + collector
├── simulations/             # safe attack simulations for generating labeled data
├── training/                # model training pipeline (Random Forest + Isolation Forest)
├── data/
│   ├── raw/                 # collected telemetry logs (git-ignored by default)
│   └── processed/           # cleaned feature CSVs for training
├── models/                  # trained model.pkl (produced in Colab)
├── alerts/                  # desktop popup alert (tkinter)
├── dashboard/               # Flask web SOC dashboard
│   ├── server.py            # Flask backend - sensors, model inference, REST API
│   └── static/
│       ├── index.html       # Premium dark-mode desktop web UI
│       ├── style.css        # Glassmorphism / neon cyberpunk styles
│       └── app.js           # Live polling, chart, gauge, process table
├── notebooks/
│   └── train_model.ipynb    # Colab training notebook
└── docs/
    ├── ROADMAP.md           # full step-by-step development guide
    └── COMMANDS.md          # command cheat-sheet
```

---

## Getting started

1. Read [`docs/ROADMAP.md`](docs/ROADMAP.md) -- it is the ordered, phase-by-phase guide.
2. Set up the laptop environment:
   ```
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. **Start the SOC Dashboard** (two options):
   - **Option A -- double-click:** `run_dashboard.bat`
   - **Option B -- terminal:**
     ```
     python dashboard/server.py
     ```
   - The dashboard opens automatically at **http://localhost:5000**

4. Create an empty **private** GitHub repo, then:
   ```
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```
5. Begin **Phase 1 -- Sensors** as described in the roadmap.

---

## Dashboard features

| Feature | Description |
|---------|-------------|
| **Threat gauge** | Live SVG arc gauge -- green/amber/red by severity |
| **Metric tiles** | CPU, RAM, Processes, File rate, New spawns, Connections |
| **History chart** | Rolling 60-sample threat score chart (canvas, no deps) |
| **Process table** | Flagged LOLBin processes with terminate buttons |
| **Feature vector** | Live 12-feature model input with bar visualization |
| **Settings panel** | Interval, threshold, watch directory, toggles -- all live |
| **Action log** | Timestamped audit trail of every termination action |
| **Desktop popup** | Tkinter floating alert fires when a threat is detected |

---

## Scope

**In scope:** endpoint resource tracking, network connection tracking, file
create/delete events, supervised ML classification, real-time dashboard, and
**human-in-the-loop active response** -- on an alert the dashboard asks permission
and terminates a flagged process only after the user confirms (see
[`common/response.py`](common/response.py)). Core system processes and the monitor
itself are always protected.

**Out of scope:** kernel/Ring-0 inspection, *automated* (no-confirmation) response
or remote endpoint isolation, TLS payload decryption, multi-tenant cloud database
sync.
