"""
preprocess_awid3.py - run on your Windows machine.

Outputs (all use averaged (7,) vector — no zero-padding bias):
  windows_normal.csv      Krack files 0-24     label=normal   -> IF pre-train
  windows_deauth.csv      Deauth files 22-31   label=deauth   -> RF1 pre-train
  windows_evil_twin.csv   Evil_Twin files 28-54 label=evil_twin -> RF1 pre-train
  windows_rf1_pretrain.csv  deauth + evil_twin combined       -> RF1 pre-train
"""

import sys, os, glob
sys.path.insert(0, os.path.dirname(__file__))

# ── Paths — update these ──────────────────────────────────────────────────
AWID3_ROOT = r"D:\University_Stuff\6._HK2_2025-2026\NT114-Specialized_Project\AWID3_Dataset_CSV\CSV"
OUT_DIR    = r"D:\University_Stuff\6._HK2_2025-2026\NT114-Specialized_Project\preprocessed"
# ─────────────────────────────────────────────────────────────────────────

from sniffer.core import SlidingWindowEngine
from sniffer.awid3 import AWID3Source, WindowCSVWriter, process_folder
import csv, pandas as pd

os.makedirs(OUT_DIR, exist_ok=True)


# ── Averaged CSV writer (7 features) - for awid3

class AveragedWindowCSVWriter:
    """
    Saves WindowResult using to_averaged_vector() -> (7,) per row.
    Avoids zero-padding bias from absent nodes in AWID3.
    """
    def __init__(self, filepath: str):
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

    def __enter__(self): return self
    def __exit__(self, *_):
        self._f.flush()
        self._f.close()
        print(f"  saved {self._count} windows -> {self._f.name}")


def process_awid3_folder(
    folder:          str,
    out_path:        str,
    keep_labels:     list,
    skip_files:      list = None,
    force_label_map: dict = None,
    skip_warmup:     bool = True,
):
    files = sorted(glob.glob(os.path.join(folder, "*.csv")))
    skip_set   = set(skip_files or [])
    force_map  = force_label_map or {}

    print(f"\n{'='*60}")
    print(f"Folder : {os.path.basename(folder)}")
    print(f"Files  : {len(files)}  |  skip={len(skip_set)}  |  force={len(force_map)}")
    print(f"Output : {os.path.basename(out_path)}")

    total_windows = 0
    from collections import Counter
    label_counts = Counter()

    with AveragedWindowCSVWriter(out_path) as writer:
        for filepath in files:
            fname = os.path.basename(filepath)

            if fname in skip_set:
                continue

            forced = force_map.get(fname)
            emitted = []
            engine  = SlidingWindowEngine(on_window=emitted.append)
            AWID3Source(
                engine, filepath,
                keep_labels=keep_labels,
                force_label=forced,
            ).run()

            windows = emitted[6:] if skip_warmup else emitted
            for w in windows:
                writer(w)
                label_counts[w.label] += 1
            total_windows += len(windows)

    print(f"  total windows : {total_windows}")
    print(f"  label counts  : {dict(label_counts)}")

    df = pd.read_csv(out_path)
    print(f"  shape         : {df.shape}")
    print(f"  any NaN       : {df.iloc[:,3:].isnull().any().any()}")
    feat_cols = [c for c in df.columns
                 if c not in ("label","window_start","window_end","active_nodes")]
    print(f"  feature cols  : {len(feat_cols)}  (expect 7)")
    return df


# ── 1. Normal — Krack files 0-24 

KRACK_FOLDER = os.path.join(AWID3_ROOT, "5.Krack")
KRACK_SKIP   = [f"Krack_{i}.csv" for i in range(25, 100)]   # skip attack files

df_normal = process_awid3_folder(
    folder      = KRACK_FOLDER,
    out_path    = os.path.join(OUT_DIR, "windows_normal.csv"),
    keep_labels = ["normal"],
    skip_files  = KRACK_SKIP,
)


# ── 2. Deauth — files 22-31 (Att1 + Att2), skip 0-21 

DEAUTH_FOLDER    = os.path.join(AWID3_ROOT, "1.Deauth")
DEAUTH_SKIP      = [f"Deauth_{i}.csv" for i in range(0, 22)]   # normal phase, 5GHz
DEAUTH_FORCE     = {f"Deauth_{i}.csv": "deauth" for i in range(22, 32)}

df_deauth = process_awid3_folder(
    folder          = DEAUTH_FOLDER,
    out_path        = os.path.join(OUT_DIR, "windows_deauth.csv"),
    keep_labels     = ["deauth"],
    skip_files      = DEAUTH_SKIP,
    force_label_map = DEAUTH_FORCE,
)


# ── 3. Evil_Twin — files 28-54 (Att19), skip 0-27 

ET_FOLDER = os.path.join(AWID3_ROOT, "12.Evil_Twin")
ET_SKIP   = [f"Evil_Twin_{i}.csv" for i in range(0, 28)]    # normal phase, 5GHz
ET_FORCE  = {f"Evil_Twin_{i}.csv": "evil_twin" for i in range(28, 55)}

df_et = process_awid3_folder(
    folder          = ET_FOLDER,
    out_path        = os.path.join(OUT_DIR, "windows_evil_twin.csv"),
    keep_labels     = ["evil_twin"],
    skip_files      = ET_SKIP,
    force_label_map = ET_FORCE,
)


# ── 4. RF1 pre-train = deauth + evil_twin combined 

print(f"\n{'='*60}")
print("Combining deauth + evil_twin -> windows_rf1_pretrain.csv")

df_rf1 = pd.concat([df_deauth, df_et], ignore_index=True)
rf1_path = os.path.join(OUT_DIR, "windows_rf1_pretrain.csv")
df_rf1.to_csv(rf1_path, index=False)

print(f"  shape        : {df_rf1.shape}")
print(f"  label counts :\n{df_rf1['label'].value_counts().to_string()}")
print(f"  saved -> {rf1_path}")


# ── 5. Summary ─

print(f"\n{'='*60}")
print("PREPROCESSING COMPLETE\n")
print(f"{'File':<35} {'Windows':>8}  {'Labels'}")
for name, df in [
    ("windows_normal.csv",       df_normal),
    ("windows_deauth.csv",       df_deauth),
    ("windows_evil_twin.csv",    df_et),
    ("windows_rf1_pretrain.csv", df_rf1),
]:
    counts = df['label'].value_counts().to_dict()
    print(f"  {name:<35} {len(df):>8}  {counts}")

print(f"\nVector shape per row: (7,) averaged — no zero-padding bias")
print(f"Next step: load these CSVs for IF and RF1 training.")