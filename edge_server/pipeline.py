"""
RF2 requires baseline normalization stored inside the pkl:
  baselines = {node_id: {"rssi_range": float, "rssi_std": float, "rssi_avg_mean": float}}
  normalized = raw - baseline  (per node, per feature)
"""

import logging
import pickle
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from core import WindowResult, RF2_NODE_KEYS, NODE_IDS

log = logging.getLogger(__name__)


# ── Result dataclass ──────────────────────────────────────────────────────

@dataclass
class PipelineResult:
    timestamp:      float                        # window_end epoch

    # Stage 1
    if_score:       float  = 0.0                 # anomaly score (higher = more anomalous)
    if_flagged:     bool   = False

    # Stage 2
    rf1_label:      str    = "normal"            # predicted class
    rf1_proba:      dict   = field(default_factory=dict)   # {class: prob}
    rf1_flagged:    bool   = False               # True when predicted != "normal"

    # Stage 3 (None when not triggered)
    rf2_node:       Optional[str]  = None        # dominant node (e.g. "node2")
    rf2_proba:      Optional[dict] = None        # {"node1": p1, "node2": p2, "node3": p3}

    # Convenience
    @property
    def attack_detected(self) -> bool:
        return self.if_flagged or self.rf1_flagged

    @property
    def summary(self) -> str:
        if not self.attack_detected:
            return "normal"
        label = self.rf1_label if self.rf1_flagged else "anomaly"
        loc   = f" near {self.rf2_node}" if self.rf2_node else ""
        return f"{label}{loc}"


# ── Pipeline ──────────────────────────────────────────────────────────────

class DetectionPipeline:

    def __init__(self, models_dir: str = "models"):
        self._models_dir = Path(models_dir)
        self._if_model    = None
        self._if_threshold: float = 0.0
        self._rf1_model   = None
        self._rf1_classes: list[str] = []
        self._rf2_model   = None
        self._rf2_classes: list[str] = []
        self._rf2_baselines: dict = {}   # {node_id: {feat: baseline_value}}
        self._load_models()

    # ── Model loading ──────────────────────────────────────────────────────

    def _load_models(self):
        # IF
        if_path = self._models_dir / "if_model.pkl"
        with open(if_path, "rb") as f:
            bundle = pickle.load(f)
        self._if_model     = bundle["model"]
        self._if_threshold = bundle["threshold"]
        log.info("IF loaded  threshold=%.4f", self._if_threshold)

        # RF1
        rf1_path = self._models_dir / "rf1_model.pkl"
        with open(rf1_path, "rb") as f:
            bundle = pickle.load(f)
        self._rf1_model   = bundle["model"]
        self._rf1_classes = bundle["classes"]
        log.info("RF1 loaded  classes=%s", self._rf1_classes)

        # RF2
        rf2_path = self._models_dir / "rf2_model.pkl"
        with open(rf2_path, "rb") as f:
            bundle = pickle.load(f)
        self._rf2_model     = bundle["model"]
        self._rf2_classes   = bundle["classes"]
        # baselines keys may be int or str depending on json load; normalise to int
        self._rf2_baselines = {int(k): v for k, v in bundle["baselines"].items()}
        log.info(
            "RF2 loaded  classes=%s  baseline_nodes=%s",
            self._rf2_classes, list(self._rf2_baselines.keys())
        )

    # ── RF2 baseline normalization ────────────────────────────────────────

    def _normalize_rf2(self, window: WindowResult) -> np.ndarray:
        """
        Apply per-node baseline subtraction (paper eq. 2), then build the
        15-dim vector: 9 normalized per-node values + 6 pairwise differentials.
        """
        node_vals: dict[int, dict[str, float]] = {}
        zeros = {k: 0.0 for k in RF2_NODE_KEYS}

        for n in NODE_IDS:
            raw   = window.node_features.get(n)
            base  = self._rf2_baselines.get(n, {})
            if raw is not None:
                node_vals[n] = {
                    k: raw.get(k, 0.0) - base.get(k, 0.0)
                    for k in RF2_NODE_KEYS
                }
            else:
                node_vals[n] = dict(zeros)

        per_node = [node_vals[n][k] for n in NODE_IDS for k in RF2_NODE_KEYS]

        rr = [node_vals[n]["rssi_range"] for n in NODE_IDS]
        rs = [node_vals[n]["rssi_std"]   for n in NODE_IDS]
        differentials = [
            rr[0] - rr[1],
            rr[0] - rr[2],
            rr[1] - rr[2],
            rs[0] - rs[1],
            rs[0] - rs[2],
            rs[1] - rs[2],
        ]

        return np.array(per_node + differentials, dtype=float)

    # ── Main inference ────────────────────────────────────────────────────

    def run(self, window: WindowResult) -> PipelineResult:
        result = PipelineResult(timestamp=window.window_end)

        # ── Stage 1: IF ───────────────────────────────────────────────────
        x_avg = window.to_averaged_vector().reshape(1, -1)
        if_score = float(-self._if_model.score_samples(x_avg)[0])
        result.if_score   = if_score
        result.if_flagged = if_score > self._if_threshold

        # ── Stage 2: RF1 (parallel) ───────────────────────────────────────
        rf1_proba = self._rf1_model.predict_proba(x_avg)[0]
        rf1_label = self._rf1_classes[int(np.argmax(rf1_proba))]
        result.rf1_label  = rf1_label
        result.rf1_proba  = dict(zip(self._rf1_classes, rf1_proba.tolist()))
        result.rf1_flagged = (rf1_label != "normal")

        # ── Stage 3: RF2 (only when Stage 1 OR Stage 2 flagged) ──────────
        if result.attack_detected:
            x_rf2 = self._normalize_rf2(window).reshape(1, -1)
            rf2_proba = self._rf2_model.predict_proba(x_rf2)[0]
            rf2_node  = self._rf2_classes[int(np.argmax(rf2_proba))]
            result.rf2_node  = rf2_node
            result.rf2_proba = dict(zip(self._rf2_classes, rf2_proba.tolist()))

        if result.attack_detected:
            log.warning(
                "ATTACK  label=%-12s  if=%.3f(%s)  rf1_conf=%.2f  loc=%s  rf2=%s",
                result.rf1_label,
                result.if_score,
                "FLAG" if result.if_flagged else "ok",
                max(result.rf1_proba.values()),
                result.rf2_node or "-",
                {k: f"{v:.2f}" for k, v in result.rf2_proba.items()} if result.rf2_proba else "-",
            )
        else:
            log.debug("normal  if=%.3f", result.if_score)

        return result
