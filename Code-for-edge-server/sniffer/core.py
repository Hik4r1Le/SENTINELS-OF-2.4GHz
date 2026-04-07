"""
core.py — SnifferRow, SlidingWindowEngine, WindowResult.

The engine is source-agnostic and phase-agnostic.
What changes between training / testing / deployment is only
how you feed rows in and what you do with WindowResult.

Usage patterns
--------------
Training / testing (from file):
    results = []
    engine = SlidingWindowEngine(on_window=results.append)
    for row in your_source:          # AWID3, CSV, etc.
        engine.ingest(row)
    X = np.array([r.to_vector() for r in results])
    y = [r.label for r in results]

Deployment (from serial, live):
    def on_window(result):
        pred = model.predict([result.to_vector()])
        ...
    engine = SlidingWindowEngine(on_window=on_window)
    # feed rows from serial in a loop
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


# Contract with the model — never reorder, only append
FEATURE_KEYS = (
    "deauth_ratio",   # mean(deauth) / mean(total)
    "beacon_ratio",   # mean(beacon) / mean(total)
    "packet_rate",    # sum(total)   / WINDOW_SIZE_S
    "rssi_range",     # mean(rssi_max) - mean(rssi_min)
    "mac_density",    # mean(unique_macs) / mean(total)
    "ssid_density",   # mean(unique_ssids) / mean(beacon)
    "rssi_std",       # std(rssi_avg across rows)
)

VECTOR_SIZE = MAX_NODES * len(FEATURE_KEYS)   
_ZEROS = tuple(0.0 for _ in FEATURE_KEYS)   # absent node placeholder

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
    if rssi_min > rssi_max:
        rssi_min = rssi_max = rssi_avg  # sanity fallback - witnessed anomaly where min > max > avg
    macs     = np.array([r.unique_macs  for r in rows], dtype=float)
    ssids    = np.array([r.unique_ssids for r in rows], dtype=float)

    mt = float(np.mean(total))  or 1.0
    mb = float(np.mean(beacon))

    return {
        "deauth_ratio": float(np.mean(deauth)) / mt,
        "beacon_ratio": float(np.mean(beacon)) / mt,
        "packet_rate":  float(np.sum(total))   / WINDOW_SIZE_S,
        "rssi_range":   float(np.mean(rssi_max) - np.mean(rssi_min)),
        "mac_density":  float(np.mean(macs))   / mt,
        "ssid_density": float(np.mean(ssids))  / mb if mb > 0 else 0.0,
        "rssi_std":     float(np.std(rssi_avg)),
    }

@dataclass
class WindowResult:
    window_start:  float
    window_end:    float
    node_features: dict[int, dict[str, float]]  # only nodes that had data
    active_nodes:  list[int]
    label:         Optional[str] = None

    def to_vector(self) -> np.ndarray:
        """
        Shape (VECTOR_SIZE,) = (MAX_NODES * N_FEATURES,).
        Absent nodes = zeros. Used by RF2.
        """
        parts: list[float] = []
        for n in NODE_IDS:
            feats = self.node_features.get(n)
            if feats is not None:
                parts.extend(feats[k] for k in FEATURE_KEYS)
            else:
                parts.extend(_ZEROS)
        return np.array(parts, dtype=float)

    def to_averaged_vector(self) -> np.ndarray:
        """
        Shape (N_FEATURES,) = (7,) - for IF and RF1
        Averages features across all active nodes.
        """
        feats = list(self.node_features.values())
        return np.array(
            [float(np.mean([f[k] for f in feats])) for k in FEATURE_KEYS],
            dtype=float
        )

    @staticmethod
    def averaged_feature_names() -> list[str]:
        """Column names for to_averaged_vector()."""
        return list(FEATURE_KEYS)

    @staticmethod
    def feature_names() -> list[str]:
        return [f"n{n}_{k}" for n in NODE_IDS for k in FEATURE_KEYS]

    def to_dict(self) -> dict:
        row = {
            "window_start": self.window_start,
            "window_end":   self.window_end,
            "active_nodes": ",".join(str(n) for n in self.active_nodes),
        }
        row.update(zip(self.feature_names(), self.to_vector()))
        if self.label is not None:
            row["label"] = self.label
        return row

class SlidingWindowEngine:
    """
    Fixed time grid: emits on t0+stride, t0+2*stride, ...
    regardless of data arrival speed.
    """

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