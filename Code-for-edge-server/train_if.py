"""
train_if.py — Isolation Forest pre-training on AWID3 normal windows.

Input  : preprocessed/windows_normal.csv   (from preprocess_awid3.py)
Output : models/if_pretrain.pkl            (saved model)
         charts/if_*.png                   (charts for report)

Split  : 80% train / 20% validation (time-ordered, no random shuffle)
Vector : to_averaged_vector() -> (7,) — consistent with deployment
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_curve, auc, precision_recall_curve
import pickle

# ── Paths ─────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
NORMAL_CSV  = os.path.join(BASE_DIR, "preprocessed", "windows_normal.csv")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
CHART_DIR   = os.path.join(BASE_DIR, "charts")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

FEATURE_COLS = [
    "deauth_ratio", "beacon_ratio", "packet_rate",
    "rssi_range",   "mac_density",  "ssid_density", "rssi_std",
]

# IF hyperparameter - fraction of expected outliers in training data
# Krack normal phase should be very clean, so keep low
CONTAMINATION = 0.02
RANDOM_STATE  = 42


# ── Load data ─────────────────────────────────────────────────────────────
print("Loading data...")
df = pd.read_csv(NORMAL_CSV)
print(f"  Loaded {len(df)} windows  features={FEATURE_COLS}")

X = df[FEATURE_COLS].values

# Time-ordered 80/20 split (no shuffle - avoids window leakage)
split = int(len(X) * 0.80)
X_train = X[:split]
X_val   = X[split:]
print(f"  Train: {len(X_train)}  Val: {len(X_val)}")


# ── Train ─────────────────────────────────────────────────────────────────
print("\nTraining Isolation Forest...")
print(f"  contamination={CONTAMINATION}  n_estimators=100")

model = IsolationForest(
    n_estimators  = 100,
    contamination = CONTAMINATION,
    random_state  = RANDOM_STATE,
    n_jobs        = -1,
)
model.fit(X_train)
print("  Done.")


# ── Score ─────────────────────────────────────────────────────────────────
# IF score_samples returns negative average path length (higher = more normal)
# We negate it so higher score = more anomalous (easier to reason about)
train_scores = -model.score_samples(X_train)
val_scores   = -model.score_samples(X_val)

print(f"\nScore summary (higher = more anomalous):")
print(f"  Train: mean={train_scores.mean():.4f}  std={train_scores.std():.4f}"
      f"  min={train_scores.min():.4f}  max={train_scores.max():.4f}")
print(f"  Val  : mean={val_scores.mean():.4f}  std={val_scores.std():.4f}"
      f"  min={val_scores.min():.4f}  max={val_scores.max():.4f}")

# Default threshold from IF (contamination-based)
threshold = -model.offset_
print(f"  IF threshold (contamination={CONTAMINATION}): {threshold:.4f}")

# Fraction flagged as anomalous on validation
flagged = (val_scores > threshold).mean()
print(f"  Flagged as anomalous on val: {flagged:.1%}  (expect ~{CONTAMINATION:.0%})")


# ── Charts ────────────────────────────────────────────────────────────────
print("\nGenerating charts...")

STYLE = {
    "figure.facecolor":  "white",
    "axes.facecolor":    "white",
    "axes.grid":         True,
    "grid.alpha":        0.3,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "font.size":         11,
}
plt.rcParams.update(STYLE)

TRAIN_COL = "#378ADD"
VAL_COL   = "#1D9E75"
THRESH_COL= "#D85A30"


# ── Chart 1: score distributions ──────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
fig.suptitle("Isolation Forest — anomaly score distribution (normal data)",
             fontsize=13, fontweight="normal", y=1.01)

for ax, scores, label, color in [
    (axes[0], train_scores, f"Train  (n={len(X_train)})", TRAIN_COL),
    (axes[1], val_scores,   f"Val    (n={len(X_val)})",   VAL_COL),
]:
    ax.hist(scores, bins=30, color=color, alpha=0.75, edgecolor="white", linewidth=0.4)
    ax.axvline(threshold, color=THRESH_COL, linewidth=1.5, linestyle="--",
               label=f"Threshold = {threshold:.3f}")
    ax.set_xlabel("Anomaly score  (higher = more anomalous)")
    ax.set_ylabel("Window count")
    ax.set_title(label)
    ax.legend(fontsize=9)

plt.tight_layout()
p = os.path.join(CHART_DIR, "if_score_distribution.png")
plt.savefig(p, dpi=150, bbox_inches="tight")
plt.close()
print(f"  Saved: {p}")


# ── Chart 2: contamination sensitivity ────────────────────────────────────
contams = [0.01, 0.02, 0.03, 0.05, 0.08, 0.10, 0.15, 0.20]
flagged_rates = []
thresholds    = []

for c in contams:
    m = IsolationForest(n_estimators=100, contamination=c,
                        random_state=RANDOM_STATE, n_jobs=-1)
    m.fit(X_train)
    thr = -m.offset_
    sc  = -m.score_samples(X_val)
    flagged_rates.append((sc > thr).mean())
    thresholds.append(thr)

fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
fig.suptitle("Isolation Forest - contamination hyperparameter sensitivity",
             fontsize=13, fontweight="normal", y=1.01)

axes[0].plot([c*100 for c in contams], [r*100 for r in flagged_rates],
             "o-", color=TRAIN_COL, linewidth=1.5, markersize=5)
axes[0].axvline(CONTAMINATION*100, color=THRESH_COL, linestyle="--",
                linewidth=1.2, label=f"Chosen: {CONTAMINATION*100:.0f}%")
axes[0].set_xlabel("Contamination (%)")
axes[0].set_ylabel("Val windows flagged (%)")
axes[0].set_title("Flagged rate on validation set")
axes[0].legend()

axes[1].plot([c*100 for c in contams], thresholds,
             "s-", color=VAL_COL, linewidth=1.5, markersize=5)
axes[1].axvline(CONTAMINATION*100, color=THRESH_COL, linestyle="--",
                linewidth=1.2, label=f"Chosen: {CONTAMINATION*100:.0f}%")
axes[1].set_xlabel("Contamination (%)")
axes[1].set_ylabel("Decision threshold")
axes[1].set_title("Threshold vs contamination")
axes[1].legend()

plt.tight_layout()
p = os.path.join(CHART_DIR, "if_contamination_sensitivity.png")
plt.savefig(p, dpi=150, bbox_inches="tight")
plt.close()
print(f"  Saved: {p}")


# ── Chart 3: feature importance (mean path length contribution) ───────────
# Proxy: std of scores when each feature is shuffled (permutation importance)
from copy import deepcopy
base_scores = -model.score_samples(X_val)
importances = []
rng = np.random.RandomState(0)
for j in range(X_val.shape[1]):
    X_perm = X_val.copy()
    X_perm[:, j] = rng.permutation(X_perm[:, j])
    perm_scores = -model.score_samples(X_perm)
    importances.append(np.mean(np.abs(perm_scores - base_scores)))

importances = np.array(importances)
importances /= importances.sum()   # normalise to sum=1
order = np.argsort(importances)[::-1]

fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.barh(
    [FEATURE_COLS[i] for i in order[::-1]],
    importances[order[::-1]],
    color=TRAIN_COL, alpha=0.8, edgecolor="white", linewidth=0.4
)
ax.set_xlabel("Relative importance (permutation)")
ax.set_title("Feature importance - Isolation Forest (validation set)")
for bar, val in zip(bars, importances[order[::-1]]):
    ax.text(val + 0.002, bar.get_y() + bar.get_height()/2,
            f"{val:.3f}", va="center", fontsize=9)
plt.tight_layout()
p = os.path.join(CHART_DIR, "if_feature_importance.png")
plt.savefig(p, dpi=150, bbox_inches="tight")
plt.close()
print(f"  Saved: {p}")


# ── Chart 4: score over time (validation set) ─────────────────────────────
fig, ax = plt.subplots(figsize=(12, 4))
ax.plot(val_scores, color=TRAIN_COL, linewidth=0.8, alpha=0.8, label="Anomaly score")
ax.axhline(threshold, color=THRESH_COL, linewidth=1.5, linestyle="--",
           label=f"Threshold = {threshold:.3f}")
ax.fill_between(range(len(val_scores)), val_scores, threshold,
                where=(val_scores > threshold),
                color=THRESH_COL, alpha=0.25, label="Flagged windows")
ax.set_xlabel("Window index (time-ordered)")
ax.set_ylabel("Anomaly score")
ax.set_title("Anomaly score over time - validation set")
ax.legend(fontsize=9)
plt.tight_layout()
p = os.path.join(CHART_DIR, "if_score_over_time.png")
plt.savefig(p, dpi=150, bbox_inches="tight")
plt.close()
print(f"  Saved: {p}")


# ── Save model ────────────────────────────────────────────────────────────
model_path = os.path.join(MODEL_DIR, "if_pretrain.pkl")
with open(model_path, "wb") as f:
    pickle.dump({
        "model":         model,
        "threshold":     threshold,
        "contamination": CONTAMINATION,
        "feature_cols":  FEATURE_COLS,
        "train_size":    len(X_train),
        "val_size":      len(X_val),
        "train_score_mean": float(train_scores.mean()),
        "train_score_std":  float(train_scores.std()),
        "val_score_mean":   float(val_scores.mean()),
        "val_score_std":    float(val_scores.std()),
    }, f)
print(f"\nModel saved: {model_path}")


# ── Summary ───────────────────────────────────────────────────────────────
print(f"\n{'='*55}")
print(f"TRAINING COMPLETE")
print(f"  Train windows      : {len(X_train)}")
print(f"  Val windows        : {len(X_val)}")
print(f"  Contamination      : {CONTAMINATION}")
print(f"  Threshold          : {threshold:.4f}")
print(f"  Val flagged rate   : {flagged:.1%}  (expect ~{CONTAMINATION:.0%})")
print(f"  Charts saved to    : {CHART_DIR}/")
print(f"  Model saved to     : {model_path}")