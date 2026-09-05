# AI-Based Cyber Crime Observation Device

A lightweight, software-only endpoint telemetry and threat-monitoring engine that
emulates a Security Operations Center (SOC) on a single laptop. It captures host
metrics, active processes, network sockets, and file-system events, classifies
behavior as **Normal** or **Suspicious** using machine learning, and surfaces the
result in a real-time Streamlit dashboard.

See [`spec.md`](spec.md) for the full concept and objectives.

---

## Architecture (two-environment split)

Because training ML models is CPU/GPU heavy, work is split across two machines and
bridged by GitHub:

| Environment | Responsibility |
|-------------|----------------|
| **VS Code (this laptop)** | Sensors, data collection, Streamlit dashboard, git |
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
├── requirements.txt         # laptop dependencies (sensors + dashboard)
├── requirements-colab.txt   # Colab dependencies (ML training)
├── .gitignore
├── sensors/                 # host, network, and file-system sensors
├── data/
│   ├── raw/                 # collected telemetry logs (git-ignored by default)
│   └── processed/           # cleaned feature CSVs for training
├── models/                  # trained model.pkl (produced in Colab)
├── dashboard/               # Streamlit SOC dashboard
├── notebooks/
│   └── train_model.ipynb    # Colab training notebook
└── docs/
    └── ROADMAP.md           # full step-by-step development guide
```

---

## Getting started

1. Read [`docs/ROADMAP.md`](docs/ROADMAP.md) — it is the ordered, phase-by-phase guide.
2. Set up the laptop environment:
   ```
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Create an empty **private** GitHub repo (no README from GitHub's side), then:
   ```
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```
4. Begin **Phase 1 — Sensors** as described in the roadmap.

---

## Scope

**In scope:** endpoint resource tracking, network connection tracking, file
create/delete events, supervised ML classification, real-time dashboard.

**Out of scope:** kernel/Ring-0 inspection, automated response/isolation, TLS
payload decryption, multi-tenant cloud database sync.
