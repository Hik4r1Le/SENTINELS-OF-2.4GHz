import serial
import re
import time

PORT = 'COM9'
# or PORT = '/dev/ttyUSB0' for Linux
BAUD_RATE = 115200

channel_pattern = re.compile(
    r'Channel: (\d+), Total: (\d+), Beacon: (\d+), Deauth: (\d+), '
    r'Probe Req: (\d+), Probe Resp: (\d+), Data: (\d+), Ctrl: (\d+), '
    r'CRC Err: (\d+), RSSI Avg: (-?\d+), RSSI Max: (-?\d+), RSSI Min: (-?\d+), '
    r'Unique MACs: (\d+), Unique BSSIDs: (\d+), Unique SSIDs: (\d+)'
)

def main():
    ser = serial.Serial(PORT, BAUD_RATE, timeout=1)
    print(f"Listening on {PORT} at {BAUD_RATE} baud...")
    current_node = None
    try:
        while True:
            line = ser.readline().decode(errors='ignore').strip()
            receiving_time = time.time()
            if not line:
                continue
            
            if "Received data from node" in line:
                current_node = int (line.split()[-1])
                print(f"\n--- Node {current_node} ---")
            
            match = channel_pattern.search(line)
            if match:
                value = list(map(int, match.groups()))
                data = {
                    "timestamp": receiving_time,
                    "node" : current_node,
                    "channel": value[0],
                    "total": value[1],
                    "beacon": value[2],
                    "deauth": value[3],
                    "probe_req": value[4],
                    "probe_resp": value[5],
                    "data": value[6],
                    "ctrl": value[7],
                    "crc_err": value[8],
                    "rssi_avg": value[9],
                    "rssi_max": value[10],
                    "rssi_min": value[11],
                    "unique_macs": value[12],
                    "unique_bssids": value[13],
                    "unique_ssids": value[14]
                }
                print (data)
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        ser.close()

if __name__ == "__main__":
    main()