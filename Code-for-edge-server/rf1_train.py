"""
train_rf1.py — train Random Forest classifier on real-world attack data.

Triggered by IF when it detects an anomaly window.
RF1 classifies the window as: normal / deauth / evil_twin / beacon_spam.

Including normal as a 4th class lets RF1 act as a second opinion on
IF false positives, and tests whether it can distinguish normal traffic
from all three attack types independently of IF.

Input  : preprocessed/rw_attacks_train.csv  (60%)
         preprocessed/rw_attacks_val.csv     (20%)
         preprocessed/rw_attacks_test.csv    (20%)
         preprocessed/rw_normal_train.csv    (60%)
         preprocessed/rw_normal_val.csv      (20%)
         preprocessed/rw_normal_test.csv     (20%)
Output : models/rf1_model.pkl
         charts/rf1_*.png
"""

import os, sys, pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix, ConfusionMatrixDisplay,
    classification_report, roc_curve, auc
)
from sklearn.preprocessing import label_binarize
from sklearn.model_selection import cross_val_score

BASE_DIR        = os.path.dirname(__file__)
ATTACK_TRAIN    = os.path.join(BASE_DIR, "preprocessed", "rw_attacks_train.csv")
ATTACK_VAL      = os.path.join(BASE_DIR, "preprocessed", "rw_attacks_val.csv")
ATTACK_TEST     = os.path.join(BASE_DIR, "preprocessed", "rw_attacks_test.csv")
NORMAL_TRAIN    = os.path.join(BASE_DIR, "preprocessed", "rw_normal_train.csv")
NORMAL_VAL      = os.path.join(BASE_DIR, "preprocessed", "rw_normal_val.csv")
NORMAL_TEST     = os.path.join(BASE_DIR, "preprocessed", "rw_normal_test.csv")
MODEL_DIR       = os.path.join(BASE_DIR, "models")
CHART_DIR       = os.path.join(BASE_DIR, "charts")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

FEATURES = [
    "deauth_ratio", "beacon_ratio", "packet_rate",
    "rssi_range",   "mac_density",  "ssid_density", "rssi_std",
]
CLASSES      = ["beacon_spam", "deauth", "evil_twin", "normal"]  # alphabetical = sklearn default
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
PURPLE = "#8E44AD"
COLORS = [BLUE, ORANGE, GREEN, PURPLE]


# ── Load ──────────────────────────────────────────────────────────────────
def load_csv(path):
    if not os.path.exists(path):
        sys.exit(f"Missing: {path}")
    return pd.read_csv(path)

def make_split(attack_path, normal_path):
    atk = load_csv(attack_path)
    nrm = load_csv(normal_path)
    nrm["label"] = "normal"          # ensure label column exists on normal data
    df  = pd.concat([atk, nrm], ignore_index=True).sample(
        frac=1, random_state=RANDOM_STATE   # shuffle so normal isn't all at the end
    ).reset_index(drop=True)
    X = df[FEATURES].values
    y = df["label"].values
    return X, y

print("Loading data...")
X_train, y_train = make_split(ATTACK_TRAIN, NORMAL_TRAIN)
X_val,   y_val   = make_split(ATTACK_VAL,   NORMAL_VAL)
X_test,  y_test  = make_split(ATTACK_TEST,  NORMAL_TEST)

for name, y in [("train", y_train), ("val", y_val), ("test", y_test)]:
    counts = {c: int((y == c).sum()) for c in CLASSES}
    print(f"  {name:6s}: {len(y)} windows  {counts}")


# ── Train ─────────────────────────────────────────────────────────────────
print(f"\nTraining Random Forest  n_estimators=200  random_state={RANDOM_STATE}")
model = RandomForestClassifier(
    n_estimators  = 200,
    max_depth     = None,       # grow full trees — RF handles overfitting via bagging
    min_samples_leaf = 2,       # slight regularisation for small real-world dataset
    class_weight  = "balanced", # guard against any remaining class imbalance
    random_state  = RANDOM_STATE,
    n_jobs        = -1,
)
model.fit(X_train, y_train)

# 5-fold CV on training set to check variance
cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
print(f"  5-fold CV accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")


# ── Evaluate ──────────────────────────────────────────────────────────────
def evaluate(X, y, split_name):
    y_pred = model.predict(X)
    acc    = (y_pred == y).mean()
    print(f"\n  {split_name} accuracy: {acc:.3f}")
    print(classification_report(y, y_pred, target_names=CLASSES, digits=3))
    return y_pred

print("\nEvaluating...")
y_pred_val  = evaluate(X_val,  y_val,  "Val")
y_pred_test = evaluate(X_test, y_test, "Test")


# ── Chart 1: confusion matrix — val ───────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle("RF1 — Confusion matrices", fontsize=13)

for ax, y_true, y_pred, title in [
    (axes[0], y_val,  y_pred_val,  "Validation set"),
    (axes[1], y_test, y_pred_test, "Test set"),
]:
    cm   = confusion_matrix(y_true, y_pred, labels=CLASSES)
    disp = ConfusionMatrixDisplay(cm, display_labels=CLASSES)
    disp.plot(ax=ax, colorbar=False, cmap="Blues")
    ax.set_title(title)
    # Rotate x labels for readability
    ax.set_xticklabels(ax.get_xticklabels(), rotation=20, ha="right")

plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf1_confusion_matrix.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 2: feature importance ───────────────────────────────────────────
importances = model.feature_importances_
std         = np.std([t.feature_importances_ for t in model.estimators_], axis=0)
order       = np.argsort(importances)

fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.barh(
    [FEATURES[i] for i in order], importances[order],
    xerr=std[order], color=BLUE, alpha=0.8,
    edgecolor="white", linewidth=0.4,
    error_kw={"elinewidth": 1, "ecolor": "gray", "capsize": 3},
)
for bar, val in zip(bars, importances[order]):
    ax.text(val + std[order[bars.index(bar)]] + 0.003,
            bar.get_y() + bar.get_height() / 2,
            f"{val:.3f}", va="center", fontsize=9)
ax.set_xlabel("Mean decrease in impurity (± std across trees)")
ax.set_title("RF1 — Feature importance")
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf1_feature_importance.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 3: per-class probability distributions ──────────────────────────
# Shows how confident RF1 is on correct vs incorrect predictions.
# Good separation between classes here means the model is calibrated.
y_proba_test = model.predict_proba(X_test)

fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
fig.suptitle("RF1 — Predicted probability for each class (test set)", fontsize=13, y=1.01)

fixed_bins = np.linspace(0, 1, 21)

for i, (cls, ax, color) in enumerate(zip(CLASSES, axes, COLORS)):
    mask_correct = (y_test == cls)
    mask_wrong   = (y_test != cls)
    probs = y_proba_test[:, i]
    
    ax.hist(probs[mask_correct], bins=fixed_bins, alpha=0.65, color=color,
            label=f"True {cls}  n={mask_correct.sum()}")
    ax.hist(probs[mask_wrong], bins=fixed_bins, alpha=0.45, color="gray",
            label=f"Other classes n={mask_wrong.sum()}")
    
    ax.set_xlabel(f"P({cls})")
    ax.set_ylabel("Count")
    ax.set_title(cls)
    ax.legend(fontsize=8)

plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf1_class_probabilities.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 4: one-vs-rest ROC curves ───────────────────────────────────────
y_test_bin  = label_binarize(y_test,  classes=CLASSES)   # (n, 3)
y_proba_all = model.predict_proba(X_test)

fig, ax = plt.subplots(figsize=(7, 5))
for i, (cls, color) in enumerate(zip(CLASSES, COLORS)):
    fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_proba_all[:, i])
    roc_auc     = auc(fpr, tpr)
    ax.plot(fpr, tpr, color=color, linewidth=2, label=f"{cls}  AUC={roc_auc:.3f}")

ax.plot([0, 1], [0, 1], color="gray", linestyle="--", linewidth=1)
ax.set_xlabel("False positive rate")
ax.set_ylabel("True positive rate")
ax.set_title("RF1 — One-vs-rest ROC curves (test set)")
ax.legend()
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf1_roc_curves.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 5: n_estimators tuning ──────────────────────────────────────────
print("\nTuning n_estimators...")
estimator_counts = [10, 25, 50, 100, 200, 300, 500]
val_accs = []
for n in estimator_counts:
    m = RandomForestClassifier(
        n_estimators=n, min_samples_leaf=2,
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1
    )
    m.fit(X_train, y_train)
    val_accs.append((m.predict(X_val) == y_val).mean())

fig, ax = plt.subplots(figsize=(8, 4))
ax.plot(estimator_counts, val_accs, "o-", color=BLUE, linewidth=1.5, markersize=5)
ax.axvline(200, color=ORANGE, linestyle="--", linewidth=1.2, label="Chosen: 200")
ax.set_xlabel("n_estimators")
ax.set_ylabel("Validation accuracy")
ax.set_title("RF1 — n_estimators sensitivity")
ax.legend()
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf1_estimator_tuning.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Chart 6: decision confidence on val set (sorted) ──────────────────────
# Plots max predicted probability per window — low confidence = ambiguous windows.
# Useful to see if evil_portal windows are systematically less certain.
y_proba_val  = model.predict_proba(X_val)
max_conf     = y_proba_val.max(axis=1)
y_pred_val_l = model.predict(X_val)
correct      = (y_pred_val_l == y_val)

fig, ax = plt.subplots(figsize=(12, 4))
indices = np.argsort(max_conf)
colors_bar = [GREEN if c else ORANGE for c in correct[indices]]
ax.bar(range(len(max_conf)), max_conf[indices], color=colors_bar,
       width=1.0, linewidth=0)
ax.axhline(0.5, color="gray", linestyle="--", linewidth=1, label="0.5 confidence")
ax.set_xlabel("Windows (sorted by confidence)")
ax.set_ylabel("Max class probability")
ax.set_title("RF1 — Decision confidence on val set  (green=correct, orange=wrong)")
ax.legend(fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(CHART_DIR, "rf1_decision_confidence.png"), dpi=150, bbox_inches="tight")
plt.close()


# ── Save ──────────────────────────────────────────────────────────────────
model_path = os.path.join(MODEL_DIR, "rf1_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump({
        "model":         model,
        "classes":       CLASSES,
        "feature_cols":  FEATURES,
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
print(f"CV  accuracy  : {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
print(f"Charts        : {CHART_DIR}/")
print(f"Model         : {model_path}")