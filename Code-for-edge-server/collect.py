"""
collect.py — real-world data collection via serial port.

Usage
-----
    # Normal traffic, morning session, 4.5 minutes
    python collect.py --label normal --duration 4.5 --session train_morning

    # Deauth attack, evening session, 4.5 minutes
    python collect.py --label deauth --duration 4.5 --session train_evening

    # Validation session
    python collect.py --label normal --duration 3 --session val_morning

Arguments
---------
    --label     : normal | deauth | evil_twin | beacon_spam
    --duration  : minutes to record (e.g. 4.5)
    --session   : train_morning | train_evening | val_morning | test_evening
    --port      : serial port (default COM9)
    --baud      : baud rate (default 115200)

Output
------
    data/raw/{label}_{session}_{date}.csv
    e.g. data/raw/normal_train_morning_2025-04-15.csv

CSV columns
-----------
    timestamp, node, channel, total, beacon, deauth, probe_req, probe_resp,
    data, ctrl, crc_err, rssi_avg, rssi_max, rssi_min,
    unique_macs, unique_bssids, unique_ssids, label, session
"""

import argparse
import csv
import os
import re
import sys
import time
from datetime import datetime

# serial is only needed at runtime
FIELDS = [
    "timestamp", "node", "channel", "total", "beacon", "deauth",
    "probe_req", "probe_resp", "data", "ctrl", "crc_err",
    "rssi_avg", "rssi_max", "rssi_min",
    "unique_macs", "unique_bssids", "unique_ssids",
    "label", "session",
]

CHANNEL_RE = re.compile(
    r"Channel: (\d+), Total: (\d+), Beacon: (\d+), Deauth: (\d+), "
    r"Probe Req: (\d+), Probe Resp: (\d+), Data: (\d+), Ctrl: (\d+), "
    r"CRC Err: (\d+), RSSI Avg: (-?\d+), RSSI Max: (-?\d+), RSSI Min: (-?\d+), "
    r"Unique MACs: (\d+), Unique BSSIDs: (\d+), Unique SSIDs: (\d+)"
)

VALID_LABELS   = {"normal", "deauth", "evil_twin", "beacon_spam"}
VALID_SESSIONS = {"train_morning", "train_evening", "val_morning", "test_evening"}


def main():
    parser = argparse.ArgumentParser(description="Collect real-world WiFi sniffer data")
    parser.add_argument("--label",    required=True, choices=VALID_LABELS)
    parser.add_argument("--session",  required=True, choices=VALID_SESSIONS)
    parser.add_argument("--duration", required=True, type=float,
                        help="Recording duration in minutes")
    parser.add_argument("--port",     default="COM11", help="Serial port (e.g. COM11 or /dev/ttyUSB0)")
    parser.add_argument("--baud",     default=115200, type=int)
    args = parser.parse_args()

    duration_s = args.duration * 60
    date_str   = datetime.now().strftime("%Y-%m-%d")
    out_dir    = os.path.join(os.path.dirname(__file__), "data", "raw")
    os.makedirs(out_dir, exist_ok=True)

    filename = f"{args.label}_{args.session}_{date_str}.csv"
    out_path = os.path.join(out_dir, filename)

    print(f"{'='*55}")
    print(f"  Label   : {args.label}")
    print(f"  Session : {args.session}")
    print(f"  Duration: {args.duration} min  ({duration_s:.0f}s)")
    print(f"  Port    : {args.port} @ {args.baud}")
    print(f"  Output  : {out_path}")
    print(f"{'='*55}")
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
                print(f"  Recording... (press Ctrl+C to stop early)\n")

                while True:
                    elapsed = time.time() - start_time
                    remaining = duration_s - elapsed

                    if remaining <= 0:
                        break

                    # Progress every 30 seconds
                    if int(elapsed) % 30 == 0 and int(elapsed) > 0:
                        print(f"  {elapsed/60:.1f} min / {args.duration} min"
                              f"  —  {row_count} rows saved", end="\r")

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
                            "label":         args.label,
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
        print(f"  WARNING  : very few rows — check serial connection")


if __name__ == "__main__":
    main()