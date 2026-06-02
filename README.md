# SENTINELS OF 2.4 GHz

> A distributed IoT system for real-time 2.4 GHz Wi-Fi attack detection and attacker localization.  
> Submission for **NT114 - Specialized Project**, University of Information Technology (UIT) and **ATC2026 Conference** (not yet reviewed as of 02/06/2026).
> The main contribution focuses around distributed sensing and attacker localization.

---

## Overview

Most Wi-Fi intrusion detection systems rely on a single monitoring point, which limits their ability to distinguish whether an anomaly originates nearby or from a distant source. **SENTINELS OF 2.4 GHz** addresses this by deploying three ESP32 sensor nodes in promiscuous mode across a physical environment. Each node passively captures frame-level statistics on channels 1, 6, and 11, relays them to a gateway via ESP-NOW, and the gateway forwards the data to a Raspberry Pi 5 edge server over UART.

The edge server processes the data through a three-stage pipeline:

1. **Isolation Forest** - unsupervised anomaly detection on normal traffic baseline
2. **Random Forest classifier (RF1)** - supervised attack classification (deauth / beacon spam / evil twin / normal), running in parallel with Stage 1
3. **Random Forest localizer (RF2)** - baseline-normalized, 15-feature proximity model that outputs a per-node confidence vector when either Stage 1 or 2 raises a flag

Results are published to a **ThingsBoard** dashboard via MQTT for real-time operator visualization.

---

## System Architecture

<img width="856" height="779" alt="architecture" src="https://github.com/user-attachments/assets/2e95ed4f-7b0a-4433-b91b-f43bfc55dc8a" />

Each node scans 3 channels × 300 ms dwell = one full cycle per 900 ms.  
The edge server aggregates readings into **5-second sliding windows** with a **1-second stride**.

---

## Detection Pipeline

<img width="551" height="461" alt="Flow Diagram drawio" src="https://github.com/user-attachments/assets/fe8848a9-9767-4f73-91e4-c65b55295188" />

Running Stage 1 and Stage 2 in **parallel** (flagging on either) maximises recall - a missed attack costs more than a false positive. Stage 3 runs only when needed, keeping latency low during normal traffic.

---

## Features Extracted Per Window

| Feature | Description | Used in |
|---|---|---|
| `deauth_ratio` | deauth frames / total frames | IF, RF1 |
| `beacon_ratio` | beacon frames / total frames | IF, RF1 |
| `packet_rate` | total frames / window size (s) | IF, RF1 |
| `rssi_range` | mean(RSSI max) − mean(RSSI min) | IF, RF1, RF2 |
| `mac_density` | unique MACs / total frames | IF, RF1 |
| `ssid_density` | unique SSIDs / beacon count | IF, RF1 |
| `rssi_std` | std of per-row RSSI avg | IF, RF1, RF2 |
| `rssi_avg_mean` | mean of per-row RSSI avg | RF2 only |

For RF2, the three RSSI features are extracted **per node** and combined with **six pairwise differentials** (rssi_range and rssi_std for node pairs 1-2, 1-3, 2-3) to form a 15-dimensional localization vector. Each value is baseline-normalized by subtracting the per-node mean computed from a short normal-traffic calibration session at deployment.

---

## Hardware

<img width="958" height="912" alt="floor_plan" src="https://github.com/user-attachments/assets/febba93e-07e0-4279-95f4-8392b5b3510f" />


| Component | Role |
|---|---|
| ESP32-WROOM (×2) | Sensor nodes - bedroom + living room left |
| ESP32-CAM | Sensor node - living room right |
| ESP32-S3 | Gateway — collects ESP-NOW, relays over UART |
| Raspberry Pi 5 | Edge server - windowing, inference, MQTT |
| Flipper Zero + ESP32 (attacker) | Deauth / beacon spam / evil twin / evil portal |

---

## Getting Started

### 1. Flash the sensor nodes

Open `ESP32/` in VS Code with the ESP-IDF extension. Set `NODE_ID` and `GATEWAY_MAC` in `esp-now.h`, then flash each node.

### 2. Flash the gateway

Open `ESP32-gateway/` and flash to the gateway ESP32. Connect it to the Raspberry Pi via USB.

### 3. Collect training data

```bash
cd AI-related/

# Normal traffic, 4.5 minutes
python collect.py --label normal --session train_morning --duration 4.5

# Deauth attack
python collect.py --label deauth --session train_evening --duration 4.5
```

### 4. Train the models

```bash
python preprocess_rw.py
python if_train.py
python rf1_train.py
python rf2_train.py
# Models saved to models/
```

### 5. Deploy the edge server

```bash
cd edge_server/
pip install -r requirements.txt

# Edit config.py: set SERIAL_PORT, TB_HOST, TB_ACCESS_TOKEN
python edge_server.py
```

---

## ThingsBoard Dashboard

The edge server publishes these telemetry keys each window:

| Key | Type | Description |
|---|---|---|
| `attack_detected` | bool | True when IF or RF1 flags |
| `attack_label` | string | deauth / beacon_spam / evil_twin / normal |
| `if_score` | float | Isolation Forest anomaly score |
| `rf1_label` | string | RF1 predicted class |
| `rf1_conf` | float | RF1 max class probability |
| `rf2_node` | string | Closest node (node1/node2/node3) |
| `rf2_node1_prob` | float | RF2 proximity confidence - Node 1 |
| `rf2_node2_prob` | float | RF2 proximity confidence - Node 2 |
| `rf2_node3_prob` | float | RF2 proximity confidence - Node 3 |
| `active_nodes` | string | Nodes reporting this window, e.g. "1,2,3" |

---

## Deployment Notes

- The RF2 baseline (`rf2_baselines` inside `rf2_model.pkl`) must be recomputed if the system is redeployed in a new environment. Run a short normal-traffic calibration session and retrain RF2.
- Evil twin and karma attacks are harder to localize (RF2 limitation) because their near-normal frame volume provides insufficient per-node RSSI contrast. Classification via RF1 sometimes confuses between normal and evil twin during live deployment. Also, IF drifts in the normal session as well. This can be the result of environmental shifts and requires further study to understand the problems and the environment.
- The system is intentionally **passive** - no packets are injected, no association is made. All monitoring is done in promiscuous mode.

---

## License

This project is a academic coursework for NT114 at UIT and submission for ATC2026 Conference. Please contact the authors before reuse.
