# SENTINELS OF 2.4 GHz — Edge Server

Runs on **Raspberry Pi 5** (Raspberry Pi OS, no desktop).  
Reads ESP32 gateway over USB-serial → sliding windows → IF + RF1 + RF2 → ThingsBoard MQTT.

---

## File layout

```
edge_server/
├── edge_server.py      ← main entry point  (python edge_server.py)
├── config.py           ← ALL settings live here — edit before running
├── core.py             ← SnifferRow, SlidingWindowEngine, WindowResult
├── serial_reader.py    ← USB-serial reader thread
├── pipeline.py         ← 3-stage detection pipeline
├── tb_publisher.py     ← ThingsBoard MQTT publisher
├── requirements.txt
└── models/             ← put your 3 pkl files here
    ├── if_model.pkl
    ├── rf1_model.pkl
    └── rf2_model.pkl
```

---

## 1. Copy files to the Pi

From your laptop (replace `pi@raspberrypi.local` with your Pi's IP if needed):

```bash
scp -r edge_server/ pi@raspberrypi.local:~/
```

Or use a USB drive / `git clone` if you push it to your repo.

---

## 2. Install dependencies on the Pi

```bash
cd ~/edge_server
pip3 install -r requirements.txt
```

---

## 3. Copy your model pkl files

```bash
mkdir -p ~/edge_server/models
# from your laptop:
scp models/if_model.pkl  models/rf1_model.pkl  models/rf2_model.pkl \
    pi@raspberrypi.local:~/edge_server/models/
```

---

## 4. Find the serial port

Plug the ESP32 gateway USB into the Pi, then:

```bash
ls /dev/tty*
# Usually /dev/ttyUSB0 (CH340/CP2102) or /dev/ttyACM0 (native USB)
```

If you get a permission error when running:
```bash
sudo usermod -aG dialout $USER
# then log out and back in
```

---

## 5. Set up ThingsBoard on Windows laptop

1. Install ThingsBoard Community Edition:  
   https://thingsboard.io/docs/user-guide/install/windows/

2. Start ThingsBoard, open http://localhost:8080

3. Login: `tenant@thingsboard.org` / `tenant`

4. Go to **Devices → Add device** → name it `sentinels-edge`

5. Click the device → **Manage credentials** → copy the **Access Token**

6. Find your laptop's IP on the same LAN as the Pi:  
   `ipconfig` → Wi-Fi IPv4 Address (e.g. `192.168.1.42`)

---

## 6. Edit config.py

```python
SERIAL_PORT     = "/dev/ttyUSB0"       # from step 4
TB_HOST         = "192.168.1.42"       # your laptop IP from step 5
TB_ACCESS_TOKEN = "YOUR_TOKEN_HERE"    # from step 5
LOG_LEVEL       = "INFO"
```

---

## 7. Run

```bash
cd ~/edge_server
python3 edge_server.py
```

Expected output:
```
10:42:01  INFO     edge  Loading models from 'models'...
10:42:02  INFO     edge  Connecting to ThingsBoard 192.168.1.42:1883 ...
10:42:03  INFO     edge  Listening on /dev/ttyUSB0 — waiting for data...
[10:42:08]  ✅ normal  IF=0.312  nodes=[1,2,3]
[10:42:09]  ✅ normal  IF=0.298  nodes=[1,2,3]
[10:42:14]  ⚠️  ATTACK  label=deauth       IF=0.721(▲)  RF1=0.97  📍 node2  nodes=[1,2,3]
```

---

## 8. ThingsBoard dashboard

In ThingsBoard, go to your device → **Latest telemetry**. You should see:

| Key             | Value         |
|-----------------|---------------|
| attack_detected | true/false    |
| attack_label    | deauth/normal/… |
| if_score        | float         |
| rf1_label       | string        |
| rf1_conf        | float         |
| rf2_node        | node1/node2/… |
| rf2_node1_prob  | float         |
| rf2_node2_prob  | float         |
| rf2_node3_prob  | float         |
| active_nodes    | "1,2,3"       |

Create widgets (time-series chart for `if_score`, alarm card for `attack_detected`, etc.)  
using the standard ThingsBoard widget library.

---

## 9. Run automatically on boot (optional, for final deployment)

```bash
# Create a systemd service
sudo nano /etc/systemd/system/sentinels.service
```

Paste:
```ini
[Unit]
Description=SENTINELS OF 2.4GHz Edge Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/pi/edge_server/edge_server.py
WorkingDirectory=/home/pi/edge_server
Restart=always
RestartSec=5
User=pi

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinels
sudo systemctl start sentinels

# Check logs:
sudo journalctl -u sentinels -f
```

---

## Pipeline logic

```
Every 1-second stride, a 5-second window is emitted
         │
         ├─► Stage 1: Isolation Forest   (7 averaged features)
         │           flag if score > threshold
         │
         ├─► Stage 2: RF1 classifier     (7 averaged features)  [PARALLEL]
         │           flag if predicted != "normal"
         │
         └─► Either flagged?
                  │
               YES└─► Stage 3: RF2 localizer  (15 baseline-normalized features)
                               output: node1/node2/node3 probability vector
```

The "parallel and flag on either" design maximises recall - a missed attack
costs more than a false positive.
