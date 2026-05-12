"""
preprocess_rf2.py - process RF2 raw CSVs into windowed, normalized feature CSVs.

Normalization
-------------
Each per-node feature (rssi_range, rssi_std, rssi_avg_mean) is baseline-subtracted using
the mean computed from ALL training windows across ALL zones. This removes the
node hardware bias caused by node 3 being physically co-located with the router,
which otherwise makes node 3 dominate every absolute RSSI metric regardless of
where the attacker actually is.

Baseline is computed from train windows only, then applied to val/test/zone4.
Baselines are saved to preprocessed/rf2_baselines.json for use at inference.

Output files (in preprocessed/)
---------------------------------
    rf2_train.csv        - normalized training windows (node1 + node2 + node3)
    rf2_val.csv          - normalized validation windows
    rf2_test.csv         - normalized test windows
    rf2_zone4_test.csv   - normalized zone4 test windows (confidence stream)
    rf2_baselines.json   - per-node feature baselines (for deployment)

Session -> split mapping
    train  →  train
    val    →  val
    test   →  test
"""

import csv
import glob
import json
import os
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from sniffer.core import SlidingWindowEngine, SnifferRow, WindowResult, NODE_IDS, RF2_NODE_KEYS

BASELINE_DIR = os.path.join(os.path.dirname(__file__), "data", "raw")
RAW_DIR    = os.path.join(os.path.dirname(__file__), "data", "rf2")
OUT_DIR    = os.path.join(os.path.dirname(__file__), "preprocessed")
os.makedirs(OUT_DIR, exist_ok=True)

VALID_ZONES    = {"node1", "node2", "node3"}
VALID_SESSIONS = {"train", "val", "test"}
SKIP_WARMUP    = 6


# ── CSV writer (writes normalized feature dicts) ──────────────────────────

class RF2CSVWriter:
    def __init__(self, filepath):
        self._f      = open(filepath, "w", newline="")
        self._writer = None
        self._count  = 0

    def write(self, row: dict):
        if self._writer is None:
            self._writer = csv.DictWriter(self._f, fieldnames=list(row.keys()))
            self._writer.writeheader()
        self._writer.writerow(row)
        self._count += 1
        if self._count % 200 == 0:
            self._f.flush()

    def close(self):
        self._f.flush()
        self._f.close()

    @property
    def count(self):
        return self._count


# ── Load one raw RF2 CSV → SnifferRows ────────────────────────────────────

def load_raw_csv(filepath, zone):
    rows = []
    with open(filepath, newline="", encoding="utf-8") as f:
        for raw in csv.DictReader(f):
            try:
                total = int(raw["total"])
                if total == 0:
                    continue
                rows.append(SnifferRow(
                    timestamp     = float(raw["timestamp"]),
                    node          = int(raw["node"]),
                    total         = total,
                    beacon        = int(raw["beacon"]),
                    deauth        = int(raw["deauth"]),
                    probe_req     = int(raw["probe_req"]),
                    probe_resp    = int(raw["probe_resp"]),
                    data          = int(raw["data"]),
                    ctrl          = int(raw["ctrl"]),
                    crc_err       = int(raw["crc_err"]),
                    rssi_avg      = float(raw["rssi_avg"]),
                    rssi_max      = float(raw["rssi_max"]),
                    rssi_min      = float(raw["rssi_min"]),
                    unique_macs   = int(raw["unique_macs"]),
                    unique_bssids = int(raw["unique_bssids"]),
                    unique_ssids  = int(raw["unique_ssids"]),
                    label         = zone,
                ))
            except (KeyError, ValueError):
                continue
    return rows


# ── Process one file → WindowResults (all 3 nodes active only) ────────────

def process_file(filepath, zone):
    rows = load_raw_csv(filepath, zone)
    if not rows:
        return []
    results = []

    def on_window(w: WindowResult):
        if len(w.active_nodes) == 3:
            results.append(w)

    engine = SlidingWindowEngine(on_window=on_window)
    for r in rows:
        engine.ingest(r)
    return results[SKIP_WARMUP:] if len(results) > SKIP_WARMUP else []


# ── Compute per-node baseline from training windows ───────────────────────

def compute_baselines(train_windows: list[WindowResult]) -> dict:
    """
    For each node and each RF2_NODE_KEY, compute the mean across all
    training windows. This is subtracted at write time to remove the
    node hardware / router-proximity bias.

    Returns: {node_id: {feature: mean_value}}
    """
    accum = {n: defaultdict(list) for n in NODE_IDS}
    for w in train_windows:
        for n in NODE_IDS:
            f = w.node_features.get(n)
            if f is None:
                continue
            for key in RF2_NODE_KEYS:
                if key in f:
                    accum[n][key].append(f[key])

    baselines = {}
    for n in NODE_IDS:
        baselines[n] = {}
        for key in RF2_NODE_KEYS:
            vals = accum[n][key]
            baselines[n][key] = float(np.mean(vals)) if vals else 0.0
    return baselines


# ── Apply baseline and build normalized feature row ───────────────────────

def normalize_and_build_row(w: WindowResult, baselines: dict) -> dict:
    """
    Subtract per-node baseline from each RF2_NODE_KEY, then compute
    differential features from the normalized values.
    Returns a flat dict ready for CSV writing.
    """
    feat_names = WindowResult.rf2_feature_names()

    # Normalized per-node values
    norm = {}
    for n in NODE_IDS:
        f = w.node_features.get(n)
        for key in RF2_NODE_KEYS:
            raw = f[key] if (f is not None and key in f) else 0.0
            norm[(n, key)] = raw - baselines[n][key]

    # Build per-node block (same order as rf2_feature_names)
    per_node = []
    for n in NODE_IDS:
        for key in RF2_NODE_KEYS:
            per_node.append(norm[(n, key)])

    # Differential block - use normalized values
    # RF2_NODE_KEYS = ('rssi_range', 'rssi_std', 'rssi_avg_mean')
    rr = [norm[(n, "rssi_range")]    for n in NODE_IDS]
    rs = [norm[(n, "rssi_std")]      for n in NODE_IDS]
    ra = [norm[(n, "rssi_avg_mean")] for n in NODE_IDS]

    differentials = [
        rr[0] - rr[1],   # rssi_range    n1-n2
        rr[0] - rr[2],   # rssi_range    n1-n3
        rr[1] - rr[2],   # rssi_range    n2-n3
        rs[0] - rs[1],   # rssi_std      n1-n2
        rs[0] - rs[2],   # rssi_std      n1-n3
        rs[1] - rs[2],   # rssi_std      n2-n3
        ra[0] - ra[1],   # rssi_avg_mean n1-n2
        ra[0] - ra[2],   # rssi_avg_mean n1-n3
        ra[1] - ra[2],   # rssi_avg_mean n2-n3
    ]

    values = per_node + differentials

    row = {
        "window_start": w.window_start,
        "window_end":   w.window_end,
        "active_nodes": ",".join(str(n) for n in w.active_nodes),
    }
    row.update(zip(feat_names, values))
    if w.label is not None:
        row["label"] = w.label
    return row


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    print(f"Loading baseline-only files from {BASELINE_DIR}...")
    baseline_files = glob.glob(os.path.join(BASELINE_DIR, "normal_*.csv"))
    
    if not baseline_files:
        sys.exit(f"CRITICAL ERROR: No baseline files found in {BASELINE_DIR}. Check naming: normal_<type>_...")

    all_baseline_windows = []
    for filepath in baseline_files:
        windows = process_file(filepath, zone="baseline") 
        all_baseline_windows.extend(windows)
        print(f"  Loaded {len(windows)} windows from {os.path.basename(filepath)}")

    print(f"Computing per-node baselines from {len(all_baseline_windows)} TOTAL normal windows...")
    baselines = compute_baselines(all_baseline_windows)
    for n in NODE_IDS:
        for key in RF2_NODE_KEYS:
            print(f"  node{n} {key}: baseline={baselines[n][key]:.4f}")


    raw_files = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))
    if not raw_files:
        print(f"No CSV files found in {RAW_DIR}")
        print("Run collect_rf2.py first.")
        return

    print(f"Found {len(raw_files)} raw files in {RAW_DIR}\n")

    buckets    = defaultdict(list)   # split → [WindowResult]
    zone4_test = []

    for filepath in raw_files:
        fname = os.path.basename(filepath)
        stem  = fname.replace(".csv", "")
        parts = stem.split("_")

        session = None
        zone    = None
        for i, p in enumerate(parts):
            if p in VALID_SESSIONS:
                session = p
                zone    = "_".join(parts[:i])
                break

        if session is None or zone is None:
            print(f"  SKIP (unrecognised filename): {fname}")
            continue

        windows = process_file(filepath, zone)

        if zone == "zone4":
            if session == "test":
                zone4_test.extend(windows)
                print(f"  {fname}: {len(windows)} windows  [zone4 / test]")
            else:
                print(f"  SKIP zone4 non-test: {fname}")
            continue

        if zone not in VALID_ZONES:
            print(f"  SKIP (unknown zone '{zone}'): {fname}")
            continue

        buckets[session].extend(windows)
        print(f"  {fname}: {len(windows)} windows  [{zone} / {session}]")

    for n in NODE_IDS:
        for key in RF2_NODE_KEYS:
            print(f"  node{n} {key}: baseline={baselines[n][key]:.4f}")

    # Save baselines for deployment
    baselines_path = os.path.join(OUT_DIR, "rf2_baselines.json")
    # JSON requires string keys
    baselines_json = {str(n): v for n, v in baselines.items()}
    with open(baselines_path, "w") as f:
        json.dump(baselines_json, f, indent=2)
    print(f"\n  Baselines saved → {baselines_path}")

    # ── Write normalized CSVs ─────────────────────────────────────────────
    print(f"\n{'='*55}")
    print("Writing normalized output CSVs...\n")

    split_files = {
        "train": os.path.join(OUT_DIR, "rf2_train.csv"),
        "val":   os.path.join(OUT_DIR, "rf2_val.csv"),
        "test":  os.path.join(OUT_DIR, "rf2_test.csv"),
    }

    for split, out_path in split_files.items():
        windows = buckets.get(split, [])
        if not windows:
            print(f"  WARNING: no {split} windows - skipping")
            continue
        writer = RF2CSVWriter(out_path)
        for w in windows:
            writer.write(normalize_and_build_row(w, baselines))
        writer.close()
        labels = defaultdict(int)
        for w in windows:
            labels[w.label] += 1
        print(f"  rf2_{split}.csv: {writer.count} windows  {dict(labels)}")

    if zone4_test:
        z4_path = os.path.join(OUT_DIR, "rf2_zone4_test.csv")
        writer  = RF2CSVWriter(z4_path)
        for w in zone4_test:
            writer.write(normalize_and_build_row(w, baselines))
        writer.close()
        print(f"  rf2_zone4_test.csv: {writer.count} windows  [confidence stream]")

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print("SUMMARY\n")
    try:
        import pandas as pd
        for name in ["rf2_train.csv", "rf2_val.csv", "rf2_test.csv", "rf2_zone4_test.csv"]:
            path = os.path.join(OUT_DIR, name)
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                continue
            df = pd.read_csv(path)
            if df.empty:
                continue
            labels = df["label"].value_counts().to_dict() if "label" in df.columns else "n/a"
            print(f"  {name:<28} {len(df):>5} windows   {labels}")
    except ImportError:
        pass


if __name__ == "__main__":
    main()