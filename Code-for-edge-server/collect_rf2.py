"""
collect_rf2.py - data collection for RF2 node-proximity localization.

Usage
-----
    # Training - 6 minutes near node 1, random attacks running
    python collect_rf2.py --zone node1 --session train --duration 6

    # Validation - 2 minutes near node 2
    python collect_rf2.py --zone node2 --session val --duration 2

    # Test - 2 minutes per zone, run sequentially zone1→zone4→zone2→zone3
    python collect_rf2.py --zone node1 --session test --duration 2
    python collect_rf2.py --zone zone4 --session test --duration 2   # overlap zone
    python collect_rf2.py --zone node2 --session test --duration 2
    python collect_rf2.py --zone node3 --session test --duration 2

Arguments
---------
    --zone      : node1 | node2 | node3 | zone4
    --session   : train | val | test
    --duration  : minutes to record
    --port      : serial port (default COM11)
    --baud      : baud rate (default 115200)

Notes
-----
    - Attack type is NOT recorded - RF2 localizes regardless of attack.
    - Run whatever attacks you want during collection; the label is zone only.
    - zone4 is collected for test only (overlap region, confidence-based output).
    - Output filename: data/rf2/{zone}_{session}_{date}.csv

Output CSV columns
------------------
    timestamp, node, channel, total, beacon, deauth, probe_req, probe_resp,
    data, ctrl, crc_err, rssi_avg, rssi_max, rssi_min,
    unique_macs, unique_bssids, unique_ssids, zone, session
"""

import argparse
import csv
import os
import re
import sys
import time
from datetime import datetime

FIELDS = [
    "timestamp", "node", "channel", "total", "beacon", "deauth",
    "probe_req", "probe_resp", "data", "ctrl", "crc_err",
    "rssi_avg", "rssi_max", "rssi_min",
    "unique_macs", "unique_bssids", "unique_ssids",
    "zone", "session",
]

CHANNEL_RE = re.compile(
    r"Channel: (\d+), Total: (\d+), Beacon: (\d+), Deauth: (\d+), "
    r"Probe Req: (\d+), Probe Resp: (\d+), Data: (\d+), Ctrl: (\d+), "
    r"CRC Err: (\d+), RSSI Avg: (-?\d+), RSSI Max: (-?\d+), RSSI Min: (-?\d+), "
    r"Unique MACs: (\d+), Unique BSSIDs: (\d+), Unique SSIDs: (\d+)"
)

VALID_ZONES    = {"node1", "node2", "node3", "zone4"}
VALID_SESSIONS = {"train", "val", "test"}

# zone4 is for test only - warn if used in train/val
ZONE4_TRAIN_WARNING = (
    "WARNING: zone4 is the overlap region and should only be used for test.\n"
    "         RF2 is trained on node1/node2/node3 only."
)


def main():
    parser = argparse.ArgumentParser(description="Collect RF2 localization data")
    parser.add_argument("--zone",     required=True,  choices=VALID_ZONES)
    parser.add_argument("--session",  required=True,  choices=VALID_SESSIONS)
    parser.add_argument("--duration", required=True,  type=float,
                        help="Recording duration in minutes")
    parser.add_argument("--port",     default="COM11",
                        help="Serial port (e.g. COM11 or /dev/ttyUSB0)")
    parser.add_argument("--baud",     default=115200,  type=int)
    args = parser.parse_args()

    if args.zone == "zone4" and args.session in {"train", "val"}:
        print(ZONE4_TRAIN_WARNING)
        sys.exit(1)

    duration_s = args.duration * 60
    date_str   = datetime.now().strftime("%Y-%m-%d")
    out_dir    = os.path.join(os.path.dirname(__file__), "data", "rf2")
    os.makedirs(out_dir, exist_ok=True)

    filename = f"{args.zone}_{args.session}_{date_str}.csv"
    out_path = os.path.join(out_dir, filename)

    print(f"{'='*55}")
    print(f"  Zone    : {args.zone}")
    print(f"  Session : {args.session}")
    print(f"  Duration: {args.duration} min  ({duration_s:.0f}s)")
    print(f"  Port    : {args.port} @ {args.baud}")
    print(f"  Output  : {out_path}")
    print(f"{'='*55}")
    print(f"  Attack type is NOT recorded - run any attack you want.")
    print(f"  Starting in 3 seconds... Ctrl+C to stop early.")
    time.sleep(3)

    try:
        import serial
    except ImportError:
        print("ERROR: pyserial not installed. Run: pip install pyserial")
        sys.exit(1)

    row_count    = 0
    current_node = None
    start_time   = time.time()

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()

        try:
            with serial.Serial(args.port, args.baud, timeout=1) as ser:
                print(f"\n  Recording... (press Ctrl+C to stop early)\n")

                while True:
                    elapsed   = time.time() - start_time
                    remaining = duration_s - elapsed

                    if remaining <= 0:
                        break

                    if int(elapsed) % 30 == 0 and int(elapsed) > 0:
                        print(f"  {elapsed/60:.1f} min / {args.duration} min"
                              f"  -  {row_count} rows saved", end="\r")

                    line = ser.readline().decode(errors="ignore").strip()
                    if not line:
                        continue

                    if "Received data from node" in line:
                        try:
                            current_node = int(line.split()[-1])
                        except ValueError:
                            pass
                        continue

                    m = CHANNEL_RE.search(line)
                    if m and current_node is not None:
                        v = list(map(int, m.groups()))
                        writer.writerow({
                            "timestamp":     time.time(),
                            "node":          current_node,
                            "channel":       v[0],
                            "total":         v[1],
                            "beacon":        v[2],
                            "deauth":        v[3],
                            "probe_req":     v[4],
                            "probe_resp":    v[5],
                            "data":          v[6],
                            "ctrl":          v[7],
                            "crc_err":       v[8],
                            "rssi_avg":      v[9],
                            "rssi_max":      v[10],
                            "rssi_min":      v[11],
                            "unique_macs":   v[12],
                            "unique_bssids": v[13],
                            "unique_ssids":  v[14],
                            "zone":          args.zone,
                            "session":       args.session,
                        })
                        row_count += 1
                        f.flush()

        except KeyboardInterrupt:
            elapsed = time.time() - start_time
            print(f"\n  Stopped early at {elapsed/60:.1f} min")

    elapsed = time.time() - start_time
    print(f"\n{'='*55}")
    print(f"  Done.")
    print(f"  Elapsed  : {elapsed/60:.1f} min")
    print(f"  Rows     : {row_count}")
    print(f"  Saved to : {out_path}")
    if row_count < 100:
        print(f"  WARNING  : very few rows - check serial connection")


if __name__ == "__main__":
    main()