"""
core.py - SnifferRow, SlidingWindowEngine, WindowResult.

The engine is source-agnostic and phase-agnostic.
What changes between training / testing / deployment is only
how you feed rows in and what you do with WindowResult.

Vectors
-------
to_averaged_vector()  → shape (7,)   - IF and RF1 (attack detection/classification)
to_rf2_vector()       → shape (21,)  - RF2 (node proximity / localization)

RF2 vector composition
----------------------
  15 per-node features  : 5 spatially-informative features × 3 nodes
  6  differential features : pairwise differences for packet_rate and rssi_range
"""

from __future__ import annotations
import threading
from collections import defaultdict, deque, Counter
from dataclasses import dataclass
from typing import Callable, Optional

import numpy as np

WINDOW_SIZE_S = 5.0
STRIDE_S      = 1.0
MAX_NODES     = 3
NODE_IDS      = list(range(1, MAX_NODES + 1))


# ── IF / RF1 features (averaged across nodes)
# Contract: never reorder, only append.
FEATURE_KEYS = (
    "deauth_ratio",   # mean(deauth) / mean(total)
    "beacon_ratio",   # mean(beacon) / mean(total)
    "packet_rate",    # sum(total)   / WINDOW_SIZE_S
    "rssi_range",     # mean(rssi_max) - mean(rssi_min)
    "mac_density",    # mean(unique_macs) / mean(total)
    "ssid_density",   # mean(unique_ssids) / mean(beacon)
    "rssi_std",       # std(rssi_avg across rows)
)

RF2_NODE_KEYS = (
    "rssi_range",
    "rssi_std",
    "rssi_avg_mean",
)

_ZEROS_ALL = tuple(0.0 for _ in FEATURE_KEYS)
_ZEROS_RF2 = tuple(0.0 for _ in RF2_NODE_KEYS)


@dataclass
class SnifferRow:
    """One aggregated sniffer reading. Same schema for all sources."""
    timestamp:     float
    node:          int
    total:         int
    beacon:        int
    deauth:        int
    probe_req:     int
    probe_resp:    int
    data:          int
    ctrl:          int
    crc_err:       int
    rssi_avg:      float
    rssi_max:      float
    rssi_min:      float
    unique_macs:   int
    unique_bssids: int
    unique_ssids:  int
    label:         Optional[str] = None   # None during deployment


def _extract(rows: list[SnifferRow]) -> dict[str, float]:
    total    = np.array([r.total        for r in rows], dtype=float)
    beacon   = np.array([r.beacon       for r in rows], dtype=float)
    deauth   = np.array([r.deauth       for r in rows], dtype=float)
    rssi_avg = np.array([r.rssi_avg     for r in rows], dtype=float)
    rssi_max = np.array([r.rssi_max     for r in rows], dtype=float)
    rssi_min = np.array([r.rssi_min     for r in rows], dtype=float)
    macs     = np.array([r.unique_macs  for r in rows], dtype=float)
    ssids    = np.array([r.unique_ssids for r in rows], dtype=float)

    mt = float(np.mean(total)) or 1.0
    mb = float(np.mean(beacon))

    return {
        "deauth_ratio":  float(np.mean(deauth)) / mt,
        "beacon_ratio":  float(np.mean(beacon)) / mt,
        "packet_rate":   float(np.sum(total))   / WINDOW_SIZE_S,
        "rssi_range":    float(np.mean(rssi_max) - np.mean(rssi_min)),
        "mac_density":   float(np.mean(macs))   / mt,
        "ssid_density":  float(np.mean(ssids))  / mb if mb > 0 else 0.0,
        "rssi_std":      float(np.std(rssi_avg)),
        "rssi_avg_mean": float(np.mean(rssi_avg)),  # for RF2 only - not in FEATURE_KEYS
    }


@dataclass
class WindowResult:
    window_start:  float
    window_end:    float
    node_features: dict[int, dict[str, float]]  # only nodes that had data
    active_nodes:  list[int]
    label:         Optional[str] = None

    # ── IF / RF1 ──────────────────────────────────────────────────────────

    def to_averaged_vector(self) -> np.ndarray:
        feats = list(self.node_features.values())
        return np.array(
            [float(np.mean([f[k] for f in feats])) for k in FEATURE_KEYS],
            dtype=float,
        )

    @staticmethod
    def averaged_feature_names() -> list[str]:
        return list(FEATURE_KEYS)

    # ── RF2 ───────────────────────────────────────────────────────────────

    def to_rf2_vector(self) -> np.ndarray:
        """
        Shape (12,) - for RF2 node-proximity localization.

        Layout
        ------
        [0:6]   Per-node features (2 × 3 nodes, absent node = zeros):
                  n1_rssi_std, n1_rssi_avg_mean,
                  n2_*, n3_*

        [6:12]  Differential features (pairwise differences):
                  rssi_std      : n1-n2, n1-n3, n2-n3
                  rssi_avg_mean : n1-n2, n1-n3, n2-n3

        Feature selection validated on real collected data:
          rssi_std      - 83% closest-node accuracy (closest node sees most variation)
          rssi_avg_mean - 68% closest-node accuracy (less negative = closer)
          Differentials cancel environment-wide drift and encode direction.
          rssi_range/packet_rate/beacon_ratio/mac_density dropped - hardware
          signatures or insufficient zone separation in real data.
        """
        # Per-node block - collect values for differential computation too
        per_node: list[float] = []
        node_vals: dict[int, dict[str, float]] = {}
        for n in NODE_IDS:
            f = self.node_features.get(n)
            if f is not None:
                per_node.extend(f[k] for k in RF2_NODE_KEYS)
                node_vals[n] = f
            else:
                per_node.extend(_ZEROS_RF2)
                node_vals[n] = {k: 0.0 for k in RF2_NODE_KEYS}

        # Differential block - both features have confirmed sign-flip between zones
        rs = [node_vals[n]["rssi_std"]      for n in NODE_IDS]
        ra = [node_vals[n]["rssi_avg_mean"] for n in NODE_IDS]

        differentials = [
            rs[0] - rs[1],   # rssi_std      n1-n2
            rs[0] - rs[2],   # rssi_std      n1-n3
            rs[1] - rs[2],   # rssi_std      n2-n3
            ra[0] - ra[1],   # rssi_avg_mean n1-n2
            ra[0] - ra[2],   # rssi_avg_mean n1-n3
            ra[1] - ra[2],   # rssi_avg_mean n2-n3
        ]

        return np.array(per_node + differentials, dtype=float)

    @staticmethod
    def rf2_feature_names() -> list[str]:
        per_node = [f"n{n}_{k}" for n in NODE_IDS for k in RF2_NODE_KEYS]
        diffs    = [
            "diff_rs_n1_n2", "diff_rs_n1_n3", "diff_rs_n2_n3",   # rssi_std
            "diff_ra_n1_n2", "diff_ra_n1_n3", "diff_ra_n2_n3",   # rssi_avg_mean
        ]
        return per_node + diffs

    # ── CSV export ────────────────────────────────────────────────────────

    def to_rf2_dict(self) -> dict:
        """Serialise to a flat dict for CSV writing (preprocess_rf2.py)."""
        row = {
            "window_start": self.window_start,
            "window_end":   self.window_end,
            "active_nodes": ",".join(str(n) for n in self.active_nodes),
        }
        row.update(zip(self.rf2_feature_names(), self.to_rf2_vector()))
        if self.label is not None:
            row["label"] = self.label
        return row


# ── Sliding window engine ─────────────────────────────────────────────────

class SlidingWindowEngine:

    def __init__(
        self,
        on_window:   Callable[[WindowResult], None],
        window_size: float = WINDOW_SIZE_S,
        stride:      float = STRIDE_S,
    ):
        self.on_window   = on_window
        self.window_size = window_size
        self.stride      = stride
        self._buffers:   dict[int, deque[SnifferRow]] = defaultdict(deque)
        self._next_emit: Optional[float] = None
        self._lock = threading.Lock()

    def ingest(self, row: SnifferRow) -> None:
        if row.total == 0:
            return
        with self._lock:
            self._buffers[row.node].append(row)
            if self._next_emit is None:
                self._next_emit = row.timestamp + self.stride
                return
            while row.timestamp >= self._next_emit:
                self._emit(self._next_emit)
                self._next_emit += self.stride

    def _emit(self, now: float) -> None:
        cutoff = now - self.window_size
        node_rows: dict[int, list[SnifferRow]] = {}
        for nid, buf in self._buffers.items():
            while buf and buf[0].timestamp < cutoff:
                buf.popleft()
            if buf:
                node_rows[nid] = list(buf)
        if not node_rows:
            return

        labels = [r.label for rows in node_rows.values() for r in rows if r.label]
        self.on_window(WindowResult(
            window_start  = cutoff,
            window_end    = now,
            node_features = {n: _extract(rows) for n, rows in node_rows.items()},
            active_nodes  = sorted(node_rows),
            label         = Counter(labels).most_common(1)[0][0] if labels else None,
        ))