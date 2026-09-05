# Commands Cheat-Sheet

All commands run from the project root with the virtual environment active.

## One-time setup (laptop)
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Phase 2 — Collect data
Record normal activity (browse, code, read PDFs) for 5 minutes:
```
python sensors/collector.py --label Normal --duration 300
```
Record suspicious activity — run the collector, then a simulation in a second terminal:
```
# terminal 1
python sensors/collector.py --label Suspicious --duration 120

# terminal 2 (choose one or run both)
python simulations/file_dump.py --count 800 --burst 40
python simulations/process_burst.py --count 60
```
Both runs append to `data/processed/dataset.csv` (one combined dataset).

## Phase 3 — Push to GitHub
```
git add -A
git add -f data/processed/dataset.csv   # raw data is git-ignored; force-add the sample
git commit -m "Phase 1-2: sensors + dataset"
git push
```

## Phase 4 — Train (in Google Colab)
Open `notebooks/train_model.ipynb` in Colab and run the cells, or from a shell:
```
python training/train.py --csv data/processed/dataset.csv
python training/train.py --synthetic     # pipeline test without real data
```
Then commit `models/model.pkl` back to the repo.

## Phase 5 — Run the dashboard (laptop)
```
git pull                                  # get the freshly trained model
streamlit run dashboard/app.py
```
Trigger a live alert during the demo by running a simulation while the dashboard
watches the same directory:
```
python simulations/file_dump.py --count 800 --burst 40
```

## Notes
- Keep scikit-learn the SAME version in `requirements.txt` and `requirements-colab.txt`,
  or `model.pkl` may not load on the laptop.
- The dashboard works before a model exists — it falls back to a rule-based score.
