"""
Deauth file ranges (from AWID3 paper Table 3, 50000 rows/file):
  Deauth_0  .. Deauth_21  : normal traffic only
  Deauth_22 .. Deauth_27  : Att1 (targeted unicast deauth) — SKIPPED
  Deauth_28 .. Deauth_31  : Att2 (broadcast deauth) — forced label "deauth"

Set TEST_FILE_ONLY = True first to check one normal + one attack file.
Set TEST_FILE_ONLY = False to run the full folder.
"""

import sys, os, glob
sys.path.insert(0, os.path.dirname(__file__))

DEAUTH_FOLDER = r"D:\University_Stuff\6._HK2_2025-2026\NT114-Specialized_Project\AWID3_Dataset_CSV\CSV\1.Deauth"
OUTPUT_CSV    = r"D:\University_Stuff\6._HK2_2025-2026\NT114-Specialized_Project\windows_deauth_test.csv"
TEST_FILE_ONLY = True   # True = spot check; False = full run
# ──────────────────────────────────────────────────────────────────────────

from sniffer.core import SlidingWindowEngine
from sniffer.awid3 import process_folder, WindowCSVWriter
import pandas as pd

ATT1_SKIP = [f"Deauth_{i}.csv" for i in range(22, 28)]
ATT2_FORCE = {f"Deauth_{i}.csv": "deauth" for i in range(28, 32)}


def main():
    all_files = sorted(glob.glob(os.path.join(DEAUTH_FOLDER, "*.csv")))
    print(f"Found {len(all_files)} files in folder")
    print(f"Skipping Att1: {ATT1_SKIP}")
    print(f"Forcing deauth: {list(ATT2_FORCE.keys())}")

    if TEST_FILE_ONLY:
        # Spot check: one normal file + one attack file
        test_folder = os.path.join(os.path.dirname(OUTPUT_CSV), "_test_subset")
        os.makedirs(test_folder, exist_ok=True)
        import shutil
        for fname in ["Deauth_0.csv", "Deauth_28.csv"]:
            src = os.path.join(DEAUTH_FOLDER, fname)
            dst = os.path.join(test_folder, fname)
            if os.path.exists(src) and not os.path.exists(dst):
                shutil.copy(src, dst)
        folder_to_use = test_folder
        print(f"\nTEST MODE: Deauth_0 (normal) + Deauth_28 (attack)")
    else:
        folder_to_use = DEAUTH_FOLDER
        print(f"\nFULL RUN: all {len(all_files)} files")

    with WindowCSVWriter(OUTPUT_CSV) as writer:
        process_folder(
            writer,
            folder_label_map={folder_to_use: ["normal", "deauth"]},
            force_label_map=ATT2_FORCE,
            skip_files=ATT1_SKIP,
        )

    # ── Summary 
    df = pd.read_csv(OUTPUT_CSV)
    print(f"\nShape       : {df.shape}")
    print(f"Label counts:\n{df['label'].value_counts().to_string()}")

    feat_cols = [c for c in df.columns
                 if c not in ("label","window_start","window_end","active_nodes")]
    n1 = [c for c in feat_cols if c.startswith("n1_")]

    print(f"\nFeature stats by label:")
    print(df.groupby("label")[n1].mean().round(4).to_string())

    print(f"\nAny NaN: {df[feat_cols].isnull().any().any()}")
    print(f"\nOutput: {OUTPUT_CSV}")

    if TEST_FILE_ONLY:
        print("\nSet TEST_FILE_ONLY = False and rerun for full dataset.")


if __name__ == "__main__":
    main()