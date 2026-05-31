"""
serial_reader.py
Reads ESP32 gateway output over USB-serial (UART).
"""

import re
import time
import threading
import logging
from typing import Callable

import serial

from core import SnifferRow

log = logging.getLogger(__name__)

# Matches the channel data line (works with or without ESP-IDF log prefix)
CHANNEL_RE = re.compile(
    r"Channel: (\d+), Total: (\d+), Beacon: (\d+), Deauth: (\d+), "
    r"Probe Req: (\d+), Probe Resp: (\d+), Data: (\d+), Ctrl: (\d+), "
    r"CRC Err: (\d+), RSSI Avg: (-?\d+), RSSI Max: (-?\d+), RSSI Min: (-?\d+), "
    r"Unique MACs: (\d+), Unique BSSIDs: (\d+), Unique SSIDs: (\d+)"
)


class SerialReader:
    """
    Background thread: reads from serial port, calls on_row() for every
    parsed SnifferRow. Reconnects automatically if the port drops.
    """

    def __init__(
        self,
        port:            str,
        baud:            int,
        on_row:          Callable[[SnifferRow], None],
        reconnect_delay: float = 5.0,
    ):
        self.port            = port
        self.baud            = baud
        self.on_row          = on_row
        self.reconnect_delay = reconnect_delay
        self._stop           = threading.Event()
        self._thread         = threading.Thread(
            target=self._run, daemon=True, name="serial-reader"
        )

    def start(self):
        self._thread.start()
        log.info("SerialReader started  port=%s  baud=%d", self.port, self.baud)

    def stop(self):
        self._stop.set()

    # ── internal ──────────────────────────────────────────────────────────

    def _run(self):
        while not self._stop.is_set():
            try:
                with serial.Serial(self.port, self.baud, timeout=1) as ser:
                    log.info("Serial port %s opened", self.port)
                    current_node: int | None = None

                    while not self._stop.is_set():
                        raw = ser.readline()
                        if not raw:
                            continue

                        line = raw.decode(errors="ignore").strip()
                        if not line:
                            continue

                        # Node-ID line  (e.g. "...Received data from node 2")
                        if "Received data from node" in line:
                            try:
                                current_node = int(line.split()[-1])
                                log.debug("Node %d", current_node)
                            except ValueError:
                                log.warning("Cannot parse node id: %s", line)
                            continue

                        # Channel data line
                        m = CHANNEL_RE.search(line)
                        if m and current_node is not None:
                            v = list(map(int, m.groups()))
                            row = SnifferRow(
                                timestamp     = time.time(),
                                node          = current_node,
                                total         = v[1],
                                beacon        = v[2],
                                deauth        = v[3],
                                probe_req     = v[4],
                                probe_resp    = v[5],
                                data          = v[6],
                                ctrl          = v[7],
                                crc_err       = v[8],
                                rssi_avg      = float(v[9]),
                                rssi_max      = float(v[10]),
                                rssi_min      = float(v[11]),
                                unique_macs   = v[12],
                                unique_bssids = v[13],
                                unique_ssids  = v[14],
                            )
                            try:
                                self.on_row(row)
                            except Exception:
                                log.exception("on_row callback raised")

            except serial.SerialException as exc:
                log.error("Serial error: %s — retry in %.0fs", exc, self.reconnect_delay)
                time.sleep(self.reconnect_delay)
            except Exception:
                log.exception("Unexpected error in serial reader — retrying")
                time.sleep(self.reconnect_delay)
