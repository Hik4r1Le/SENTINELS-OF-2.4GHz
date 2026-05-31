import logging
import os
import signal
import sys
import time

import config
from core import SlidingWindowEngine, WindowResult
from serial_reader import SerialReader
from pipeline import DetectionPipeline
from tb_publisher import ThingsBoardPublisher

# ── Logging ───────────────────────────────────────────────────────────────

logging.basicConfig(
    level   = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format  = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt = "%H:%M:%S",
)
log = logging.getLogger("edge")


# ── Wiring ────────────────────────────────────────────────────────────────

def build_system():
    log.info("Loading models from '%s'...", config.MODELS_DIR)
    pipeline  = DetectionPipeline(models_dir=config.MODELS_DIR)

    log.info("Connecting to ThingsBoard  %s:%d ...", config.TB_HOST, config.TB_PORT)
    publisher = ThingsBoardPublisher(
        host         = config.TB_HOST,
        port         = config.TB_PORT,
        access_token = config.TB_ACCESS_TOKEN,
    )
    publisher.connect()

    # Give MQTT a moment to connect before first publish
    time.sleep(2)

    def on_window(window: WindowResult):
        """Called by SlidingWindowEngine for every 5-s window."""
        result = pipeline.run(window)
        publisher.publish(result, active_nodes=window.active_nodes)

        # Console summary (always printed regardless of log level)
        ts     = time.strftime("%H:%M:%S", time.localtime(window.window_end))
        nodes  = ",".join(str(n) for n in window.active_nodes)
        if result.attack_detected:
            rf1_conf = max(result.rf1_proba.values())
            loc      = f"  📍 {result.rf2_node}" if result.rf2_node else ""
            print(
                f"[{ts}]  ⚠️  ATTACK  label={result.rf1_label:<12}"
                f"  IF={result.if_score:.3f}({'▲' if result.if_flagged else '·'})"
                f"  RF1={rf1_conf:.2f}{loc}"
                f"  nodes=[{nodes}]"
            )
        else:
            print(
                f"[{ts}]  ✅ normal"
                f"  IF={result.if_score:.3f}"
                f"  nodes=[{nodes}]"
            )

    engine = SlidingWindowEngine(on_window=on_window)

    port = os.environ.get("SERIAL_PORT", config.SERIAL_PORT)
    reader = SerialReader(
        port    = port,
        baud    = config.SERIAL_BAUD,
        on_row  = engine.ingest,
    )

    return reader, engine, publisher


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    log.info("=" * 55)
    log.info("SENTINELS OF 2.4 GHz — Edge Server")
    log.info("=" * 55)

    reader, engine, publisher = build_system()

    # Graceful shutdown on Ctrl-C or SIGTERM
    stop_event = signal.Event() if hasattr(signal, "Event") else None

    def shutdown(sig, frame):
        log.info("Shutting down...")
        reader.stop()
        publisher.disconnect()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    reader.start()
    log.info("Listening on %s — waiting for data...", config.SERIAL_PORT)

    # Keep main thread alive
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
