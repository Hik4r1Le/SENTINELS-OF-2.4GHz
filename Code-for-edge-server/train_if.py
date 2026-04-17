"""
train_if.py — train Isolation Forest on real-world normal data.

Input  : preprocessed/rw_normal_train.csv   (60% — train_morning + train_evening)
         preprocessed/rw_normal_val.csv      (20% — val_morning)
         preprocessed/rw_normal_test.csv     (20% — test_evening)
         preprocessed/windows_rf1_pretrain.csv (attack windows for comparison charts)
Output : models/if_model.pkl
         charts/if_*.png
"""

import os, sys, pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_curve, auc, confusion_matrix, ConfusionMatrixDisplay

BASE_DIR     = os.path.dirname(__file__)
TRAIN_CSV    = os.path.join(BASE_DIR, "preprocessed", "rw_normal_train.csv")
VAL_CSV      = os.path.join(BASE_DIR, "preprocessed", "rw_normal_val.csv")
TEST_CSV     = os.path.join(BASE_DIR, "preprocessed", "rw_normal_test.csv")
ATTACK_CSV   = os.path.join(BASE_DIR, "preprocessed", "windows_rf1_pretrain.csv")
MODEL_DIR    = os.path.join(BASE_DIR, "models")
CHART_DIR    = os.path.join(BASE_DIR, "charts")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

FEATURES = [
    "deauth_ratio", "beacon_ratio", "packet_rate",
    "rssi_range",   "mac_density",  "ssid_density", "rssi_std",
]
CONTAMINATION = 0.02
RANDOM_STATE  = 42

plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white",
    "axes.grid": True, "grid.alpha": 0.3,
    "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 11,
})
BLUE   = "#378ADD"
GREEN  = "#1D9E75"
ORANGE = "#D85A30"


# ── Load ──────────────────────────────────────────────────────────────────
def load(path, required=True):
    if not os.path.exists(path):
        if required:
            sys.exit(f"Missing: {path}")
        return None
    df = pd.read_csv(path)
    return df[FEATURES].values if not df.empty else None

print("Loading data...")
X_train  = load(TRAIN_CSV)
X_val    = load(VAL_CSV)
X_test   = load(TEST_CSV)
X_attack = load(ATTACK_CSV, required=False)

for name, X in [("train", X_train), ("val", X_val),
                ("test", X_test), ("attack", X_attack)]:
    print(f"  {name:8s}: {len(X) if X is not None else 'not found'} windows")


# ── Train ─────────────────────────────────────────────────────────────────
print(f"\nTraining IF  contamination={CONTAMINATION}  n_estimators=100")
model = IsolationForest(n_estimators=100, contamination=CONTAMINATION,
                        random_state=RANDOM_STATE, n_jobs=-1)
model.fit(X_train)
threshold = float(-model.offset_)
print(f"  Threshold: {threshold:.4f}")


# ── Score helper ──────────────────────────────────────────────────────────
def score(X):
    return -model.score_samples(X)

s_train  = score(X_train)
s_val    = score(X_val)
s_test   = score(X_test)
s_attack = score(X_attack) if X_attack is not None else None

for name, s in [("train", s_train), ("val", s_val), ("test", s_test)]:
    flagged = (s > threshold).mean()
    print(f"  {name:8s}: mean={s.mean():.4f}  flagged={flagged:.1%}")


# ── Chart 1: score distributions (train / val / test) ─────────────────────
fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
fig.suptitle("IF — anomaly score distribution (normal data)", fontsize=13, y=1.01)
for ax, s, label, color in [
    (axes[0], s_train, f"Train  n={len(X_train)}", BLUE),
    (axes[1], s_val,   f"Val    n={len(X_val)}",   GREEN),
    (axes[2], s_test,  f"Test   n={len(X_test)}",  GREEN),
]:
    ax.hist(s, bins=30, color=color, alpha=0.75, edgecolor="white", linewidth=0.4)
    ax.axvline(threshold, color=ORANGE, linewidth=1.5, linestyle="--",
               label=f"Threshold={threshold:.3f}")
    ax.set_xlabel("Anomaly score")
    ax.set_ylabel("Count")
    ax.set_title(label)
    ax.legend(fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "if_score_distribution.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 2: normal vs attack ──────────────────────────────────────────────
if s_attack is not None:
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.hist(s_train,  bins=40, alpha=0.55, color=BLUE,   density=True, label=f"Normal  n={len(s_train)}")
    ax.hist(s_attack, bins=40, alpha=0.55, color=ORANGE, density=True, label=f"Attack  n={len(s_attack)}")
    ax.axvline(threshold, color="black", linewidth=1.5, linestyle="--",
               label=f"Threshold={threshold:.3f}")
    ax.set_xlabel("Anomaly score (higher = more anomalous)")
    ax.set_ylabel("Density")
    ax.set_title("IF — Normal vs Attack score distribution")
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "if_normal_vs_attack.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Normal flagged : {(s_train  > threshold).mean():.1%}")
    print(f"  Attack flagged : {(s_attack > threshold).mean():.1%}")


# ── Chart 3: ROC curve (requires attack labels) ────────────────────────────
if s_attack is not None:
    y_true   = np.concatenate([np.zeros(len(s_test)), np.ones(len(s_attack))])
    y_scores = np.concatenate([s_test, s_attack])
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc      = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, color=BLUE, linewidth=2, label=f"AUC = {roc_auc:.3f}")
    ax.plot([0,1], [0,1], color="gray", linestyle="--", linewidth=1)
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("IF — ROC curve (test normal vs attack)")
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "if_roc_curve.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ROC AUC: {roc_auc:.3f}")


# ── Chart 4: confusion matrix (test set + attack) ─────────────────────────
if s_attack is not None:
    n_attack = min(len(s_attack), len(s_test))
    y_true_cm = np.concatenate([
        np.zeros(len(s_test)),
        np.ones(n_attack)
    ])
    y_pred_cm = np.concatenate([
        (s_test > threshold).astype(int),
        (s_attack[:n_attack] > threshold).astype(int)
    ])
    cm = confusion_matrix(y_true_cm, y_pred_cm)
    fig, ax = plt.subplots(figsize=(5, 4))
    disp = ConfusionMatrixDisplay(cm, display_labels=["Normal", "Attack"])
    disp.plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title(f"IF — Confusion matrix (threshold={threshold:.3f})")
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "if_confusion_matrix.png"), dpi=150, bbox_inches="tight")
    plt.close()


# ── Chart 5: contamination sensitivity ────────────────────────────────────
contams       = [0.01, 0.02, 0.03, 0.05, 0.08, 0.10, 0.15, 0.20]
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
fig.suptitle("IF — contamination sensitivity", fontsize=13, y=1.01)
axes[0].plot([c*100 for c in contams], [r*100 for r in flagged_rates],
             "o-", color=BLUE, linewidth=1.5, markersize=5)
axes[0].axvline(CONTAMINATION*100, color=ORANGE, linestyle="--",
                linewidth=1.2, label=f"Chosen: {CONTAMINATION*100:.0f}%")
axes[0].set_xlabel("Contamination (%)")
axes[0].set_ylabel("Val windows flagged (%)")
axes[0].set_title("Flagged rate on val set")
axes[0].legend()

axes[1].plot([c*100 for c in contams], thresholds,
             "s-", color=GREEN, linewidth=1.5, markersize=5)
axes[1].axvline(CONTAMINATION*100, color=ORANGE, linestyle="--",
                linewidth=1.2, label=f"Chosen: {CONTAMINATION*100:.0f}%")
axes[1].set_xlabel("Contamination (%)")
axes[1].set_ylabel("Decision threshold")
axes[1].set_title("Threshold vs contamination")
axes[1].legend()
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "if_contamination_sensitivity.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 6: feature importance ───────────────────────────────────────────
base   = score(X_val)
rng    = np.random.RandomState(0)
imps   = []
for j in range(X_val.shape[1]):
    Xp = X_val.copy()
    Xp[:, j] = rng.permutation(Xp[:, j])
    imps.append(np.mean(np.abs(score(Xp) - base)))
imps  = np.array(imps)
imps /= imps.sum()
order = np.argsort(imps)

fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.barh([FEATURES[i] for i in order], imps[order],
               color=BLUE, alpha=0.8, edgecolor="white", linewidth=0.4)
for bar, val in zip(bars, imps[order]):
    ax.text(val + 0.002, bar.get_y() + bar.get_height()/2,
            f"{val:.3f}", va="center", fontsize=9)
ax.set_xlabel("Relative importance (permutation)")
ax.set_title("IF — feature importance (val set)")
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "if_feature_importance.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 7: score over time ───────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(12, 4))
ax.plot(s_test, color=BLUE, linewidth=0.8, alpha=0.8, label="Anomaly score")
ax.axhline(threshold, color=ORANGE, linewidth=1.5, linestyle="--",
           label=f"Threshold={threshold:.3f}")
ax.fill_between(range(len(s_test)), s_test, threshold,
                where=(s_test > threshold), color=ORANGE, alpha=0.25,
                label="Flagged")
ax.set_xlabel("Window index (time-ordered)")
ax.set_ylabel("Anomaly score")
ax.set_title("IF — score over time (test set, normal only)")
ax.legend(fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "if_score_over_time.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Save ──────────────────────────────────────────────────────────────────
model_path = os.path.join(MODEL_DIR, "if_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump({
        "model": model, "threshold": threshold,
        "contamination": CONTAMINATION, "feature_cols": FEATURES,
        "train_size": len(X_train), "val_size": len(X_val), "test_size": len(X_test),
    }, f)

print(f"\n{'='*50}")
print(f"Train: {len(X_train)}  Val: {len(X_val)}  Test: {len(X_test)}")
print(f"Threshold   : {threshold:.4f}")
print(f"Val flagged : {(s_val > threshold).mean():.1%}")
print(f"Charts      : {CHART_DIR}/")
print(f"Model       : {model_path}")