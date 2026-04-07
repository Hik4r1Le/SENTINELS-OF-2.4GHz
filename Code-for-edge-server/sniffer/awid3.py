"""
awid3.py — AWID3 2021 preprocessor.
"""

from __future__ import annotations
import csv
import glob
import os
import statistics
from collections import Counter
from typing import Callable, Optional

from .core import SlidingWindowEngine, SnifferRow, WindowResult

# AWID3 column names
COL_TIME    = "frame.time_epoch"
COL_TYPE    = "wlan.fc.type"
COL_SUBTYPE = "wlan.fc.subtype"
COL_RSSI_1   = "radiotap.dbm_antsignal"   # primary
COL_RSSI_2   = "wlan_radio.signal_dbm"    # fallback
COL_TA      = "wlan.ta"
COL_BSSID   = "wlan.bssid"
COL_SSID    = "wlan.ssid"
COL_LABEL   = "Label"

# (fc_type, fc_subtype) -> SnifferRow field
_FRAME_MAP: dict[tuple[int, int], str] = {
    (0, 8):  "beacon",
    (0, 4):  "probe_req",
    (0, 5):  "probe_resp",
    (0, 12): "deauth",
}

# AWID3 label -> RF1 class (None = discard this frame)
LABEL_MAP: dict[str, Optional[str]] = {
    "Normal":     "normal",
    "Deauth":     "deauth",
    "Evil_Twin":  "evil_twin",
    # Krack, Kr00k, and others -> None (not target classes)
}

BUCKET_S        = 0.9    # match ESP32 channel-hop cadence
# Median pkts/cycle across 3 nodes, afternoon (low activity)
# Based on: node1 median=32, node2 median=65.5, node3 simulated=49.2
ENV_MEDIAN = 50.0

def process_folder(
    on_window:        Callable[[WindowResult], None],
    folder_label_map: dict[str, list[str]],
    force_label_map:  Optional[dict[str, str]] = None,
    skip_files:       Optional[list[str]] = None,
    skip_warmup:      bool = True,
) -> None:
    """
    Process multiple AWID3 folders and feed windows to on_window.

    Parameters
    ----------
    on_window        : callback or WindowCSVWriter instance
    folder_label_map : {folder_path: [labels_to_keep]}
                       e.g. {"data/Krack": ["normal"],
                              "data/Deauth": ["normal", "deauth"]}
    force_label_map  : {filename: forced_label} — override Label column
                       for specific files, labelling every row as forced_label
                       e.g. {"Deauth_28.csv": "deauth", "Deauth_29.csv": "deauth"}
    skip_files       : list of filenames to skip entirely
                       e.g. ["Deauth_22.csv", ..., "Deauth_27.csv"]  (Att1 range)
    skip_warmup      : drop first 6 windows per file (warmup artifact)

    Each file gets its own fresh engine to prevent cross-file bleed.
    """
    force_label_map = force_label_map or {}
    skip_files      = set(skip_files or [])

    for folder, keep_labels in folder_label_map.items():
        files = sorted(glob.glob(os.path.join(folder, "*.csv")))
        if not files:
            print(f"[process_folder] WARNING: no CSV files in {folder}")
            continue
        print(f"\n[process_folder] {folder}  keep={keep_labels}  files={len(files)}")

        for filepath in files:
            fname = os.path.basename(filepath)

            if fname in skip_files:
                print(f"  {fname}: SKIPPED")
                continue

            forced = force_label_map.get(fname)   # None = use Label column

            emitted: list[WindowResult] = []
            engine = SlidingWindowEngine(on_window=emitted.append)
            AWID3Source(
                engine, filepath,
                keep_labels=keep_labels,
                force_label=forced,
            ).run()

            windows = emitted[6:] if skip_warmup else emitted
            label_counts: Counter = Counter()
            for w in windows:
                on_window(w)
                label_counts[w.label] += 1

            print(f"  {fname}: "
                  f"{len(emitted)} windows total, "
                  f"{len(windows)} after warmup skip  "
                  f"labels={dict(label_counts)}"
                  + (f"  [forced={forced}]" if forced else ""))


class AWID3Source:
    """
    Reads one AWID3 CSV, aggregates frames into SnifferRows (0.9s buckets),
    labels each bucket by majority vote of row-level Labels,
    discards buckets whose majority label is not in keep_labels,
    normalises packet rate, feeds engine.

    Parameters
    ----------
    engine      : SlidingWindowEngine
    filepath    : path to one AWID3 CSV
    keep_labels : which RF1 classes to keep, e.g. ["normal", "deauth"]
                  buckets whose majority label is not in this list are dropped
    node_id     : node slot to fill (others stay zero)
    bucket_s    : aggregation bucket width in seconds
    """

    def __init__(
        self,
        engine:      SlidingWindowEngine,
        filepath:    str,
        keep_labels: list[str],
        force_label: Optional[str] = None,
        node_id:     int   = 1,
        bucket_s:    float = BUCKET_S,
    ):
        self.engine      = engine
        self.filepath    = filepath
        self.keep_labels = set(keep_labels)
        self.force_label = force_label   # if set, overrides Label column
        self.node_id     = node_id
        self.bucket_s    = bucket_s

    def run(self) -> None:
        baseline = self._compute_baseline()
        self._process(baseline)

    def _compute_baseline(self) -> float:
        """Median packet rate from the first 300 buckets (all frames)."""
        bucket_start: Optional[float] = None
        bucket_total = 0
        samples: list[int] = []

        with open(self.filepath, newline="", encoding="utf-8", errors="ignore") as f:
            for raw in csv.DictReader(f):
                ts = _float(raw.get(COL_TIME, ""))
                if ts is None:
                    continue
                if bucket_start is None:
                    bucket_start = ts
                if ts - bucket_start >= self.bucket_s:
                    samples.append(bucket_total)
                    bucket_total = 0
                    bucket_start = ts
                    if len(samples) >= 300:
                        break
                bucket_total += 1

        if not samples:
            return ENV_MEDIAN

        samples.sort()
        p25_idx  = max(0, int(len(samples) * 0.25))
        baseline = float(samples[p25_idx] or 1.0)
        scale    = ENV_MEDIAN / baseline
        print(f"  baseline={baseline:.0f} pkts/bucket  "
              f"env_target={ENV_MEDIAN:.0f}  scale={scale:.4f}")
        return baseline

    def _process(self, baseline: float) -> None:
        scale = ENV_MEDIAN / baseline

        bucket_start: Optional[float] = None
        acc = _empty_acc()

        with open(self.filepath, newline="", encoding="utf-8", errors="ignore") as f:
            for raw in csv.DictReader(f):
                ts     = _float(raw.get(COL_TIME,    ""))
                rssi   = _float(raw.get(COL_RSSI_1, "")) or _float(raw.get(COL_RSSI_2, ""))
                ftype  = _int(raw.get(COL_TYPE,      "")) or 0
                fsub   = _int(raw.get(COL_SUBTYPE,   "")) or 0
                ta     = raw.get(COL_TA,    "") or ""
                bssid  = raw.get(COL_BSSID, "") or ""
                ssid   = raw.get(COL_SSID,  "") or ""
                # Map AWID3 label -> RF1 class
                # force_label overrides the Label column entirely (for attack files)
                if self.force_label is not None:
                    mapped = self.force_label
                else:
                    raw_label = raw.get(COL_LABEL, "").strip()
                    mapped    = LABEL_MAP.get(raw_label)   # None if not a target class

                if ts is None:
                    continue
                if bucket_start is None:
                    bucket_start = ts

                if ts - bucket_start >= self.bucket_s:
                    row = _flush(acc, bucket_start, self.node_id,
                                 scale, self.keep_labels)
                    if row:
                        self.engine.ingest(row)
                    acc          = _empty_acc()
                    bucket_start = ts

                # Accumulate frame - track mapped label (None = unknown)
                acc["total"] += 1
                if rssi is not None:
                    acc["rssi_vals"].append(rssi)
                acc["labels"].append(mapped)   # None entries are ignored in vote

                if ta and ta != "ff:ff:ff:ff:ff:ff":
                    acc["macs"].add(ta)
                if bssid:
                    acc["bssids"].add(bssid)
                if ssid:
                    acc["ssids"].add(ssid)

                if ftype == 1:
                    acc["ctrl"] += 1
                elif ftype == 2:
                    acc["data"] += 1
                elif ftype == 0:
                    field = _FRAME_MAP.get((ftype, fsub))
                    if field:
                        acc[field] += 1

        if acc["total"] > 0 and bucket_start is not None:
            row = _flush(acc, bucket_start, self.node_id,
                         scale, self.keep_labels)
            if row:
                self.engine.ingest(row)


class WindowCSVWriter:
    """
    Saves WindowResult objects to CSV. Use as context manager.

    Example
    -------
        with WindowCSVWriter("windows_train.csv") as writer:
            process_folder(writer, {
                "data/Krack":     ["normal"],
                "data/Deauth":    ["normal", "deauth"],
                "data/Evil_Twin": ["normal", "evil_twin"],
            })
    """

    def __init__(self, filepath: str):
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        self._f      = open(filepath, "w", newline="")
        self._writer = None
        self._count  = 0

    def __call__(self, result: WindowResult) -> None:
        row = result.to_dict()
        if self._writer is None:
            self._writer = csv.DictWriter(self._f, fieldnames=list(row.keys()))
            self._writer.writeheader()
        self._writer.writerow(row)
        self._count += 1
        if self._count % 100 == 0:
            self._f.flush()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._f.flush()
        self._f.close()
        print(f"\n[WindowCSVWriter] {self._count} windows -> {self._f.name}")


def _empty_acc() -> dict:
    return dict(
        total=0, beacon=0, deauth=0, probe_req=0, probe_resp=0,
        data=0, ctrl=0, crc_err=0,
        rssi_vals=[],   # only frames with real RSSI
        macs=set(), bssids=set(), ssids=set(),
        labels=[],   # mapped RF1 labels per frame (None = unknown)
    )


def _flush(
    acc:         dict,
    ts:          float,
    node_id:     int,
    scale:       float,
    keep_labels: set[str],
) -> Optional[SnifferRow]:
    if acc["total"] == 0:
        return None

    # Majority vote over known labels only (ignore None)
    known = [l for l in acc["labels"] if l is not None]
    if not known:
        return None   # entire bucket has unknown labels — skip

    majority = Counter(known).most_common(1)[0][0]

    # Drop bucket if majority label is not in keep_labels
    if majority not in keep_labels:
        return None

    def s(n: int) -> int:
        return max(0, round(n * scale))

    # RSSI stats — only from frames that actually had a signal reading
    rv = acc["rssi_vals"]
    import numpy as _np
    if rv:
        rssi_avg = float(_np.mean(rv))
        rssi_max = float(_np.max(rv))
        rssi_min = float(_np.min(rv))
    else:
        rssi_avg = rssi_max = rssi_min = 0.0

    return SnifferRow(
        timestamp     = ts,
        node          = node_id,
        total         = s(acc["total"]),
        beacon        = s(acc["beacon"]),
        deauth        = s(acc["deauth"]),
        probe_req     = s(acc["probe_req"]),
        probe_resp    = s(acc["probe_resp"]),
        data          = s(acc["data"]),
        ctrl          = s(acc["ctrl"]),
        crc_err       = s(acc["crc_err"]),
        rssi_avg      = rssi_avg,
        rssi_max      = rssi_max,
        rssi_min      = rssi_min,
        unique_macs   = len(acc["macs"]),
        unique_bssids = len(acc["bssids"]),
        unique_ssids  = len(acc["ssids"]),
        label         = majority,
    )


def _float(s: str) -> Optional[float]:
    try:
        return float(s)
    except (ValueError, TypeError):
        return None


def _int(s: str) -> Optional[int]:
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return None