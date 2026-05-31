"""
Payload schema published each window
-------------------------------------
{
  "ts": <epoch ms>,
  "values": {
    "attack_detected": true/false,
    "attack_label":    "deauth" | "beacon_spam" | "evil_twin" | "normal",
    "if_score":        float,
    "if_flagged":      true/false,
    "rf1_label":       str,
    "rf1_conf":        float,          -- max class probability
    "rf2_node":        "node1" | ...,  -- null if not triggered
    "rf2_node1_prob":  float,
    "rf2_node2_prob":  float,
    "rf2_node3_prob":  float,
    "active_nodes":    "1,2,3"
  }
}
"""

import json
import logging
import threading
import time
from typing import Optional

import paho.mqtt.client as mqtt

from pipeline import PipelineResult

log = logging.getLogger(__name__)

_TB_TELEMETRY_TOPIC = "v1/devices/me/telemetry"


class ThingsBoardPublisher:

    def __init__(
        self,
        host:         str,
        port:         int,
        access_token: str,
        reconnect_delay: float = 10.0,
    ):
        self._host            = host
        self._port            = port
        self._access_token    = access_token
        self._reconnect_delay = reconnect_delay
        self._connected       = False
        self._lock            = threading.Lock()

        self._client = mqtt.Client(client_id="sentinels-edge")
        self._client.username_pw_set(access_token)
        self._client.on_connect    = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_publish    = self._on_publish

    # ── Connection management ─────────────────────────────────────────────

    def connect(self):
        """Start async MQTT connection (non-blocking)."""
        self._client.connect_async(self._host, self._port, keepalive=60)
        self._client.loop_start()
        log.info("ThingsBoard MQTT connecting  %s:%d", self._host, self._port)

    def disconnect(self):
        self._client.loop_stop()
        self._client.disconnect()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected = True
            log.info("ThingsBoard MQTT connected")
        else:
            log.error("ThingsBoard MQTT connect failed  rc=%d", rc)

    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        if rc != 0:
            log.warning("ThingsBoard MQTT disconnected unexpectedly  rc=%d — will reconnect", rc)

    def _on_publish(self, client, userdata, mid):
        log.debug("ThingsBoard publish ack  mid=%d", mid)

    # ── Publish ───────────────────────────────────────────────────────────

    def publish(self, result: PipelineResult, active_nodes: Optional[list] = None):
        """
        Serialise PipelineResult to ThingsBoard telemetry JSON and publish.
        Drops silently (with a warning) if not connected.
        """
        if not self._connected:
            log.warning("ThingsBoard not connected — dropping telemetry")
            return

        rf2_n1 = rf2_n2 = rf2_n3 = 0.0
        if result.rf2_proba:
            rf2_n1 = result.rf2_proba.get("node1", 0.0)
            rf2_n2 = result.rf2_proba.get("node2", 0.0)
            rf2_n3 = result.rf2_proba.get("node3", 0.0)

        rf1_conf = max(result.rf1_proba.values()) if result.rf1_proba else 0.0

        payload = {
            "ts": int(result.timestamp * 1000),   # epoch ms for ThingsBoard
            "values": {
                "attack_detected": result.attack_detected,
                "attack_label":    result.rf1_label if result.rf1_flagged else "normal",
                "if_score":        round(result.if_score, 4),
                "if_flagged":      result.if_flagged,
                "rf1_label":       result.rf1_label,
                "rf1_conf":        round(rf1_conf, 4),
                "rf2_node":        result.rf2_node or "",
                "rf2_node1_prob":  round(rf2_n1, 4),
                "rf2_node2_prob":  round(rf2_n2, 4),
                "rf2_node3_prob":  round(rf2_n3, 4),
                "active_nodes":    ",".join(str(n) for n in (active_nodes or [])),
            },
        }

        self._client.publish(
            _TB_TELEMETRY_TOPIC,
            json.dumps(payload),
            qos=1,
        )
        log.debug("ThingsBoard publish  %s", payload["values"])
