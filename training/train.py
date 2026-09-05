"""Training pipeline (Phase 4) -- run in Google Colab or locally.

Trains two models on the collected telemetry:
  * RandomForestClassifier  -- supervised Normal vs Suspicious (primary threat score)
  * IsolationForest         -- unsupervised anomaly score (catches unseen behavior)

Both, plus the feature-column order and the scikit-learn version, are saved together
in a single bundle at models/model.pkl. The dashboard loads that exact bundle, so
the feature order used at prediction time always matches training.

Usage:
  python training/train.py --csv data/processed/dataset.csv
  python training/train.py --synthetic     # generate fake data to test the pipeline
"""

from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import pandas as pd
import joblib
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

# matplotlib is only needed for the evaluation plots. It is optional so training
# still succeeds on a minimal laptop install (plots are simply skipped there).
try:
    import matplotlib
    matplotlib.use("Agg")  # headless: save plots to files, no display needed
    import matplotlib.pyplot as plt
    _HAVE_MPL = True
except Exception:
    _HAVE_MPL = False

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.features import FEATURE_COLUMNS, LABEL_NORMAL, LABEL_SUSPICIOUS


def make_synthetic(n_per_class: int = 1500, seed: int = 42) -> pd.DataFrame:
    """Generate plausible synthetic telemetry so the pipeline can be validated
    end-to-end BEFORE you have collected real data. Not a substitute for real
    telemetry -- use it only to confirm training/evaluation/export works.
    """
    rng = np.random.default_rng(seed)

    def normal_block(n):
        return pd.DataFrame({
            "cpu_pct": rng.normal(18, 8, n).clip(0, 100),
            "ram_pct": rng.normal(45, 10, n).clip(0, 100),
            "process_count": rng.normal(180, 20, n).clip(50, 400).round(),
            "new_process_count": rng.poisson(0.5, n),
            "file_create_count": rng.poisson(0.6, n),
            "file_delete_count": rng.poisson(0.3, n),
            "file_event_rate": rng.gamma(1.0, 0.5, n).clip(0, 5),
            "conn_count": rng.normal(40, 12, n).clip(0, 200).round(),
            "distinct_remote_ips": rng.normal(12, 5, n).clip(0, 80).round(),
            "distinct_remote_ports": rng.normal(10, 4, n).clip(0, 80).round(),
            "established_count": rng.normal(15, 6, n).clip(0, 100).round(),
            "suspicious_proc_count": rng.poisson(0.4, n),
            "label": LABEL_NORMAL,
        })

    def suspicious_block(n):
        return pd.DataFrame({
            "cpu_pct": rng.normal(55, 20, n).clip(0, 100),
            "ram_pct": rng.normal(60, 15, n).clip(0, 100),
            "process_count": rng.normal(210, 30, n).clip(50, 500).round(),
            "new_process_count": rng.poisson(8, n),
            "file_create_count": rng.poisson(25, n),
            "file_delete_count": rng.poisson(8, n),
            "file_event_rate": rng.gamma(6.0, 4.0, n).clip(0, 200),
            "conn_count": rng.normal(70, 25, n).clip(0, 400).round(),
            "distinct_remote_ips": rng.normal(35, 15, n).clip(0, 200).round(),
            "distinct_remote_ports": rng.normal(40, 18, n).clip(0, 200).round(),
            "established_count": rng.normal(25, 12, n).clip(0, 200).round(),
            "suspicious_proc_count": rng.poisson(4, n),
            "label": LABEL_SUSPICIOUS,
        })

    df = pd.concat([normal_block(n_per_class), suspicious_block(n_per_class)], ignore_index=True)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def load_dataset(csv_path: str, use_synthetic: bool) -> pd.DataFrame:
    if use_synthetic:
        print("[train] using SYNTHETIC data (pipeline test only).")
        return make_synthetic()
    if not os.path.exists(csv_path):
        raise SystemExit(
            f"[train] dataset not found: {csv_path}\n"
            f"        Collect data first (see docs/ROADMAP.md Phase 2), or pass --synthetic."
        )
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_COLUMNS + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"[train] dataset is missing columns: {missing}")
    return df


def train(df: pd.DataFrame, models_dir: str) -> dict:
    os.makedirs(models_dir, exist_ok=True)

    X = df[FEATURE_COLUMNS].astype(float)
    y = df["label"].astype(str)
    print(f"[train] samples={len(df)}  class balance:\n{y.value_counts().to_string()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # --- Random Forest (supervised) ---
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=None, class_weight="balanced", random_state=42, n_jobs=-1
    )
    # Fit on plain arrays (no column names) so the models accept the list-based
    # vectors the live dashboard sends, without emitting feature-name warnings.
    rf.fit(X_train.values, y_train)
    y_pred = rf.predict(X_test.values)

    acc = accuracy_score(y_test, y_pred)
    print(f"\n[train] Random Forest accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))

    if _HAVE_MPL:
        # Confusion matrix plot
        cm = confusion_matrix(y_test, y_pred, labels=rf.classes_)
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=rf.classes_)
        fig, ax = plt.subplots(figsize=(4.5, 4))
        disp.plot(ax=ax, colorbar=False, cmap="Blues")
        ax.set_title(f"Confusion Matrix (acc={acc:.3f})")
        fig.tight_layout()
        cm_path = os.path.join(models_dir, "confusion_matrix.png")
        fig.savefig(cm_path, dpi=120)
        plt.close(fig)
        print(f"[train] saved {cm_path}")

        # Feature importance plot
        importances = pd.Series(rf.feature_importances_, index=FEATURE_COLUMNS).sort_values()
        fig, ax = plt.subplots(figsize=(6, 4.5))
        importances.plot.barh(ax=ax, color="#2563eb")
        ax.set_title("Feature Importance (Random Forest)")
        fig.tight_layout()
        fi_path = os.path.join(models_dir, "feature_importance.png")
        fig.savefig(fi_path, dpi=120)
        plt.close(fig)
        print(f"[train] saved {fi_path}")
    else:
        print("[train] matplotlib not installed -- skipping evaluation plots.")

    # --- Isolation Forest (unsupervised anomaly) fit on Normal rows only ---
    normal_X = X_train[y_train == LABEL_NORMAL]
    iso = None
    if len(normal_X) >= 20:
        iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
        iso.fit(normal_X.values)
        print(f"[train] Isolation Forest fit on {len(normal_X)} normal samples.")
    else:
        print("[train] not enough Normal samples for Isolation Forest; skipping.")

    bundle = {
        "rf": rf,
        "iso": iso,
        "feature_columns": FEATURE_COLUMNS,
        "classes": list(rf.classes_),
        "sklearn_version": sklearn.__version__,
        "accuracy": float(acc),
    }
    model_path = os.path.join(models_dir, "model.pkl")
    joblib.dump(bundle, model_path)
    print(f"\n[train] saved model bundle -> {model_path}")
    print(f"[train] scikit-learn version baked in: {sklearn.__version__}")
    print("[train] IMPORTANT: the laptop must use the same scikit-learn version to load this.")
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Train threat-detection models")
    parser.add_argument("--csv", default=os.path.join(_ROOT, "data", "processed", "dataset.csv"))
    parser.add_argument("--models-dir", default=os.path.join(_ROOT, "models"))
    parser.add_argument("--synthetic", action="store_true",
                        help="Use generated synthetic data to test the pipeline.")
    args = parser.parse_args()

    df = load_dataset(args.csv, args.synthetic)
    train(df, args.models_dir)


if __name__ == "__main__":
    main()
