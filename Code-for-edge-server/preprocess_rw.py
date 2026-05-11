"""
preprocess_realworld.py - process collected real-world CSVs into window CSVs.

Reads all CSVs from data/raw/, groups by label+session, runs each group
through the sliding window engine, outputs train/val/test splits.

Output files (in preprocessed/)
---------------------------------
  rw_normal_train.csv       IF fine-tune train
  rw_normal_val.csv         IF fine-tune val
  rw_normal_test.csv        IF test

  rw_attacks_train.csv      RF1 fine-tune train  (deauth+evil_twin+beacon_spam)
  rw_attacks_val.csv        RF1 fine-tune val
  rw_attacks_test.csv       RF1 test

Session -> split mapping (from your collection plan)
  train_morning + train_evening  ->  train  (60%)
  val_morning                    ->  val    (20%)
  test_evening                   ->  test   (20%)
"""

import csv
import glob
import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

from sniffer.core import SlidingWindowEngine, SnifferRow

RAW_DIR  = os.path.join(os.path.dirname(__file__), "data", "raw")
OUT_DIR  = os.path.join(os.path.dirname(__file__), "preprocessed")
os.makedirs(OUT_DIR, exist_ok=True)

FEATURE_COLS = [
    "deauth_ratio", "beacon_ratio", "packet_rate",
    "rssi_range",   "mac_density",  "ssid_density", "rssi_std",
]

# session name -> split bucket
SESSION_SPLIT = {
    "train_morning": "train",
    "train_evening": "train",
    "val_morning":   "val",
    "test_evening":  "test",
}

ATTACK_LABELS = {"deauth", "evil_twin", "beacon_spam"}


# ── Averaged CSV writer ───────────────────────────────────────────────────

class AveragedWindowCSVWriter:
    def __init__(self, filepath):
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        self._f      = open(filepath, "w", newline="")
        self._writer = None
        self._count  = 0

    def __call__(self, result):
        vec   = result.to_averaged_vector()
        names = result.averaged_feature_names()
        row   = {
            "window_start": result.window_start,
            "window_end":   result.window_end,
            "active_nodes": ",".join(str(n) for n in result.active_nodes),
        }
        row.update(zip(names, vec))
        if result.label is not None:
            row["label"] = result.label
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


# ── Parse one raw CSV into SnifferRows ────────────────────────────────────

def load_raw_csv(filepath):
    rows = []
    with open(filepath, newline="", encoding="utf-8") as f:
        for raw in csv.DictReader(f):
            try:
                total = int(raw["total"])
                if total == 0:
                    continue    # skip empty channel readings
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
                    label         = raw.get("label") or None,
                ))
            except (KeyError, ValueError):
                continue
    return rows


# ── Process one session file -> windows ──────────────────────────────────

def process_session(filepath, skip_warmup=True):
    rows = load_raw_csv(filepath)
    if not rows:
        return []

    results = []
    engine  = SlidingWindowEngine(on_window=results.append)
    for r in rows:
        engine.ingest(r)

    return results[6:] if skip_warmup else results


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    raw_files = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))
    if not raw_files:
        print(f"No CSV files found in {RAW_DIR}")
        print("Run collect.py first to gather real-world data.")
        return

    print(f"Found {len(raw_files)} raw files in {RAW_DIR}\n")

    # Organise: {label: {split: [WindowResult, ...]}}
    from collections import defaultdict
    buckets = defaultdict(lambda: defaultdict(list))

    for filepath in raw_files:
        fname = os.path.basename(filepath)
        stem = fname.replace(".csv", "")
        session = None
        label   = None
        for key in SESSION_SPLIT:
            idx = stem.find(f"_{key}_")
            if idx != -1:
                label   = stem[:idx]
                session = key
                break
        if session is None or label is None:
            print(f"  SKIP (unknown session): {fname}")
            continue

        if session is None:
            print(f"  SKIP (unknown session): {fname}")
            continue

        split  = SESSION_SPLIT[session]
        windows = process_session(filepath)
        buckets[label][split].extend(windows)
        print(f"  {fname}: {len(windows)} windows  [{label} / {split}]")

    if not buckets:
        print("\nNo valid files processed.")
        return

    print(f"\n{'='*55}")
    print("Writing output CSVs...\n")

    # ── Normal splits (for IF) ────────────────────────────────────────────
    normal_files = {
        "train": os.path.join(OUT_DIR, "rw_normal_train.csv"),
        "val":   os.path.join(OUT_DIR, "rw_normal_val.csv"),
        "test":  os.path.join(OUT_DIR, "rw_normal_test.csv"),
    }

    # Deauth ratio threshold for normal data cleaning
    # Windows where deauth_ratio exceeds this are dropped from normal training
    # to prevent IF learning that deauth activity is "normal"
    DEAUTH_CLEAN_THRESHOLD = 0.3   # drop if >x% of frames are deauth

    for split, out_path in normal_files.items():
        windows = buckets.get("normal", {}).get(split, [])
        if not windows:
            print(f"  WARNING: no normal/{split} windows - skipping")
            continue
        writer    = AveragedWindowCSVWriter(out_path)
        dropped   = 0
        for w in windows:
            vec = w.to_averaged_vector()
            deauth_ratio = vec[0]   # first feature is deauth_ratio
            if deauth_ratio > DEAUTH_CLEAN_THRESHOLD:
                dropped += 1
                continue
            writer(w)
        writer.close()
        drop_pct = dropped / max(len(windows), 1)
        print(f"  rw_normal_{split}.csv: {writer.count} windows "
              f"(dropped {dropped} with deauth_ratio>{DEAUTH_CLEAN_THRESHOLD}  {drop_pct:.0%})")
        if drop_pct > 0.30:
            print(f"  WARNING: >30% of normal windows dropped - "
                  f"check if deauth attack was running during collection")

    # ── Attack splits (for RF1) ───────────────────────────────────────────
    attack_files = {
        "train": os.path.join(OUT_DIR, "rw_attacks_train.csv"),
        "val":   os.path.join(OUT_DIR, "rw_attacks_val.csv"),
        "test":  os.path.join(OUT_DIR, "rw_attacks_test.csv"),
    }

    for split, out_path in attack_files.items():
        writer = AveragedWindowCSVWriter(out_path)
        for label in ["deauth", "evil_twin", "beacon_spam"]:
            windows = buckets.get(label, {}).get(split, [])
            for w in windows:
                writer(w)
        if writer.count == 0:
            print(f"  WARNING: no attack/{split} windows - skipping")
            writer.close()
            continue
        writer.close()
        print(f"  rw_attacks_{split}.csv: {writer.count} windows")

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print("SUMMARY\n")
    import pandas as pd
    for name in ["rw_normal_train.csv", "rw_normal_val.csv", "rw_normal_test.csv",
                 "rw_attacks_train.csv", "rw_attacks_val.csv", "rw_attacks_test.csv"]:
        path = os.path.join(OUT_DIR, name)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            continue
        try:
            df = pd.read_csv(path)
            if df.empty:
                continue
            labels = df['label'].value_counts().to_dict() if 'label' in df.columns else {}
            print(f"  {name:<30} {len(df):>5} windows   {labels}")
        except Exception:
            continue


if __name__ == "__main__":
    main()