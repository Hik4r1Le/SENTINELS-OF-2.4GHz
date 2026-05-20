"""
train_rf2.py - train Random Forest for node-proximity localization (RF2).

RF2 answers: which node is the attacker closest to?
Output is a per-class probability vector (node1, node2, node3) used for
confidence-based ranking at deployment - not a hard zone assignment.

Input CSVs are already baseline-normalized by preprocess_rf2.py.
Baselines are loaded from preprocessed/rf2_baselines.json and saved into
the model pkl so deployment can apply the same normalization.

Input  : preprocessed/rf2_train.csv
         preprocessed/rf2_val.csv
         preprocessed/rf2_test.csv
         preprocessed/rf2_zone4_test.csv   (optional - confidence stream)
         preprocessed/rf2_baselines.json
Output : models/rf2_model.pkl
         charts/rf2_*.png
"""

import json
import os, sys, pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix, ConfusionMatrixDisplay,
    classification_report, roc_curve, auc,
)
from sklearn.preprocessing import label_binarize
from sklearn.model_selection import cross_val_score
from matplotlib.patches import Patch

BASE_DIR       = os.path.dirname(__file__)
TRAIN_CSV      = os.path.join(BASE_DIR, "preprocessed", "rf2_train.csv")
VAL_CSV        = os.path.join(BASE_DIR, "preprocessed", "rf2_val.csv")
TEST_CSV       = os.path.join(BASE_DIR, "preprocessed", "rf2_test.csv")
ZONE4_CSV      = os.path.join(BASE_DIR, "preprocessed", "rf2_zone4_test.csv")
ZONE5_CSV      = os.path.join(BASE_DIR, "preprocessed", "rf2_zone5_test.csv")
BASELINES_JSON = os.path.join(BASE_DIR, "preprocessed", "rf2_baselines.json")
MODEL_DIR      = os.path.join(BASE_DIR, "models")
CHART_DIR      = os.path.join(BASE_DIR, "charts")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

sys.path.insert(0, BASE_DIR)
from sniffer.core import WindowResult
FEATURES     = WindowResult.rf2_feature_names()   # 18 normalized features
CLASSES      = ["node1", "node2", "node3"]
RANDOM_STATE = 42

plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white",
    "axes.grid": True, "grid.alpha": 0.3,
    "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 11,
})
BLUE   = "#378ADD"
GREEN  = "#1D9E75"
ORANGE = "#D85A30"
COLORS = [BLUE, ORANGE, GREEN]


# ── Load baselines ────────────────────────────────────────────────────────

if not os.path.exists(BASELINES_JSON):
    sys.exit(f"Missing baselines: {BASELINES_JSON}\nRun preprocess_rf2.py first.")

with open(BASELINES_JSON) as f:
    # Keys are strings in JSON - convert back to int node IDs
    baselines = {int(k): v for k, v in json.load(f).items()}
print("Baselines loaded:")
for n, feats in baselines.items():
    for feat, val in feats.items():
        print(f"  node{n} {feat}: {val:.4f}")


# ── Load CSVs ─────────────────────────────────────────────────────────────

def load(path, required=True):
    if not os.path.exists(path):
        if required:
            sys.exit(f"Missing: {path}")
        return None, None
    df = pd.read_csv(path)
    if df.empty:
        return None, None
    # label column absent in zone4 file
    y = df["label"].values if "label" in df.columns else None
    return df[FEATURES].values, y

print("\nLoading data...")
X_train, y_train = load(TRAIN_CSV)
X_val,   y_val   = load(VAL_CSV)
X_test,  y_test  = load(TEST_CSV)
for name, y in [("train", y_train), ("val", y_val), ("test", y_test)]:
    counts = {c: int((y == c).sum()) for c in CLASSES}
    print(f"  {name:6s}: {len(y)} windows  {counts}")


# ── Train ─────────────────────────────────────────────────────────────────

print(f"\nTraining RF2  n_estimators=200  random_state={RANDOM_STATE}")
model = RandomForestClassifier(
    n_estimators     = 200,
    max_depth        = None,
    min_samples_leaf = 2,
    class_weight     =  "balanced", 
    random_state     = RANDOM_STATE,
    n_jobs           = -1,
)
model.fit(X_train, y_train)

cv = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
print(f"  5-fold CV: {cv.mean():.3f} ± {cv.std():.3f}")


# ── Evaluate ──────────────────────────────────────────────────────────────

def evaluate(X, y, name):
    y_pred = model.predict(X)
    print(f"\n--- {name} ---")
    print(classification_report(y, y_pred, target_names=CLASSES, digits=3))
    return y_pred

y_pred_val  = evaluate(X_val,  y_val,  "Val")
y_pred_test = evaluate(X_test, y_test, "Test")


# ── Chart 1: confusion matrices ───────────────────────────────────────────

fig, axes = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle("RF2 - Confusion matrices (node proximity, normalized)", fontsize=13)
for ax, yt, yp, title in [
    (axes[0], y_val,  y_pred_val,  "Validation"),
    (axes[1], y_test, y_pred_test, "Test"),
]:
    cm = confusion_matrix(yt, yp, labels=CLASSES)
    ConfusionMatrixDisplay(cm, display_labels=CLASSES).plot(
        ax=ax, colorbar=False, cmap="Blues"
    )
    ax.set_title(title)
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf2_confusion_matrix.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 2: feature importance ───────────────────────────────────────────

imps  = model.feature_importances_
std   = np.std([t.feature_importances_ for t in model.estimators_], axis=0)
order = np.argsort(imps)

# Per-node features = first 9 (3 features × 3 nodes), differentials = last 9
n_per_node = 9
colors_bar = [BLUE if i < n_per_node else ORANGE for i in order]

fig, ax = plt.subplots(figsize=(9, 6))
ax.barh(
    [FEATURES[i] for i in order], imps[order],
    xerr=std[order], color=colors_bar, alpha=0.8,
    edgecolor="white", linewidth=0.4,
    error_kw={"elinewidth": 1, "ecolor": "gray", "capsize": 3},
)
for i, idx in enumerate(order):
    ax.text(imps[idx] + std[idx] + 0.002, i,
            f"{imps[idx]:.3f}", va="center", fontsize=8)
ax.legend(handles=[
    Patch(facecolor=BLUE,   label="Per-node (normalized)"),
    Patch(facecolor=ORANGE, label="Differential"),
], fontsize=9)
ax.set_xlabel("Mean decrease in impurity")
ax.set_title("RF2 - Feature importance (baseline-normalized)")
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf2_feature_importance.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 3: per-class probability distributions ──────────────────────────

y_prob_test = model.predict_proba(X_test)
fig, axes   = plt.subplots(1, 3, figsize=(15, 4.5))
fig.suptitle("RF2 - Predicted probability per class (test set)", fontsize=13, y=1.01)
bins = np.linspace(0, 1, 21)
for i, (cls, ax, color) in enumerate(zip(CLASSES, axes, COLORS)):
    mask_c = (y_test == cls)
    mask_o = (y_test != cls)
    ax.hist(y_prob_test[:, i][mask_c], bins=bins, alpha=0.65, color=color,
            label=f"True {cls}  n={mask_c.sum()}")
    ax.hist(y_prob_test[:, i][mask_o], bins=bins, alpha=0.40, color="gray",
            label=f"Others  n={mask_o.sum()}")
    ax.set_xlabel(f"P({cls})"); ax.set_ylabel("Count")
    ax.set_title(cls); ax.legend(fontsize=8)
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf2_class_probabilities.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 4: one-vs-rest ROC ──────────────────────────────────────────────

y_bin  = label_binarize(y_test, classes=CLASSES)
y_prob = model.predict_proba(X_test)
fig, ax = plt.subplots(figsize=(7, 5))
for i, (cls, color) in enumerate(zip(CLASSES, COLORS)):
    fpr, tpr, _ = roc_curve(y_bin[:, i], y_prob[:, i])
    ax.plot(fpr, tpr, color=color, linewidth=2,
            label=f"{cls}  AUC={auc(fpr, tpr):.3f}")
ax.plot([0, 1], [0, 1], color="gray", linestyle="--", linewidth=1)
ax.set_xlabel("FPR"); ax.set_ylabel("TPR")
ax.set_title("RF2 - One-vs-rest ROC (test set)")
ax.legend(); plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf2_roc_curves.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 5: decision confidence on val set ───────────────────────────────

y_prob_val = model.predict_proba(X_val)
max_conf   = y_prob_val.max(axis=1)
correct    = (model.predict(X_val) == y_val)
fig, ax    = plt.subplots(figsize=(12, 4))
idx        = np.argsort(max_conf)
ax.bar(range(len(max_conf)), max_conf[idx],
       color=[GREEN if c else ORANGE for c in correct[idx]],
       width=1.0, linewidth=0)
ax.axhline(0.5, color="gray", linestyle="--", linewidth=1, label="0.5 threshold")
ax.set_xlabel("Windows (sorted by confidence)")
ax.set_ylabel("Max class probability")
ax.set_title("RF2 - Decision confidence on val set  (green=correct, orange=wrong)")
ax.legend(fontsize=9); plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf2_decision_confidence.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 6: zone4 confidence stream ─────────────────────────────────────

X_zone4, _ = load(ZONE4_CSV, required=False)
if X_zone4 is not None:
    z4_prob = model.predict_proba(X_zone4)
    t_axis  = np.arange(len(z4_prob))

    fig, ax = plt.subplots(figsize=(14, 5))
    for i, (cls, color) in enumerate(zip(CLASSES, COLORS)):
        ax.plot(t_axis, z4_prob[:, i], color=color, linewidth=1.2,
                alpha=0.85, label=cls)
    ax.axhline(0.33, color="gray", linestyle="--", linewidth=1,
               label="Equal probability (0.33)")
    ax.set_xlabel("Window index (time-ordered)")
    ax.set_ylabel("Predicted probability")
    ax.set_title("RF2 - Confidence stream in Zone 4 (overlap region)\n"
                 "Attacker position interpreted from relative node confidences")
    ax.legend(fontsize=9); plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "rf2_zone4_confidence_stream.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\nZone 4 confidence stream saved ({len(X_zone4)} windows)")
else:
    print("\nNo zone4 test data found - skipping confidence stream chart.")

# ── Chart extra: zone5 confidence stream ─────────────────────────────────────

X_zone5, _ = load(ZONE5_CSV, required=False)
if X_zone5 is not None:
    z5_prob = model.predict_proba(X_zone5)
    t_axis  = np.arange(len(z5_prob))

    fig, ax = plt.subplots(figsize=(14, 5))
    for i, (cls, color) in enumerate(zip(CLASSES, COLORS)):
        ax.plot(t_axis, z5_prob[:, i], color=color, linewidth=1.2,
                alpha=0.85, label=cls)
    ax.axhline(0.33, color="gray", linestyle="--", linewidth=1,
               label="Equal probability (0.33)")
    ax.set_xlabel("Window index (time-ordered)")
    ax.set_ylabel("Predicted probability")
    ax.set_title("RF2 - Confidence stream in Zone 5 (obstructed area)\n"
                 "Attacker position interpreted from relative node confidences")
    ax.legend(fontsize=9); plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, "rf2_zone5_confidence_stream.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\nZone 5 confidence stream saved ({len(X_zone5)} windows)")
else:
    print("\nNo zone5 test data found - skipping confidence stream chart.")


# ── Chart 7: n_estimators tuning ──────────────────────────────────────────

print("\nTuning n_estimators...")
counts = [10, 25, 50, 100, 200, 300, 500]
vaccs  = []
for n in counts:
    m = RandomForestClassifier(
        n_estimators=n, min_samples_leaf=2,
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1
    )
    m.fit(X_train, y_train)
    vaccs.append((m.predict(X_val) == y_val).mean())

fig, ax = plt.subplots(figsize=(8, 4))
ax.plot(counts, vaccs, "o-", color=BLUE, linewidth=1.5, markersize=5)
ax.axvline(200, color=ORANGE, linestyle="--", linewidth=1.2, label="Chosen: 200")
ax.set_xlabel("n_estimators"); ax.set_ylabel("Val accuracy")
ax.set_title("RF2 - n_estimators sensitivity"); ax.legend()
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf2_estimator_tuning.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Save model + baselines ────────────────────────────────────────────────

model_path = os.path.join(MODEL_DIR, "rf2_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump({
        "model":         model,
        "classes":       CLASSES,
        "feature_cols":  FEATURES,
        "baselines":     baselines,   # needed at inference time
        "train_size":    len(X_train),
        "val_size":      len(X_val),
        "test_size":     len(X_test),
        "val_accuracy":  (y_pred_val  == y_val ).mean(),
        "test_accuracy": (y_pred_test == y_test).mean(),
    }, f)

print(f"\n{'='*50}")
print(f"Train: {len(X_train)}  Val: {len(X_val)}  Test: {len(X_test)}")
print(f"Val accuracy  : {(y_pred_val  == y_val ).mean():.3f}")
print(f"Test accuracy : {(y_pred_test == y_test).mean():.3f}")
print(f"CV accuracy   : {cv.mean():.3f} ± {cv.std():.3f}")
print(f"Charts        : {CHART_DIR}/")
print(f"Model         : {model_path}")