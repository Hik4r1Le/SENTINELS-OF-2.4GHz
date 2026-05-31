# ── Serial (USB to ESP32 gateway) 
# On Raspberry Pi OS the gateway will appear as /dev/ttyUSB0 or /dev/ttyACM0.
# Run `ls /dev/tty*` before and after plugging in USB to find the right one.
SERIAL_PORT = "/dev/ttyUSB0"
SERIAL_BAUD = 115200

# ── Model files 
# Path to the directory that contains if_model.pkl, rf1_model.pkl, rf2_model.pkl
MODELS_DIR = "models"

# ── ThingsBoard
# HOST: IP of your Windows laptop running ThingsBoard on the same LAN.
TB_HOST         = "192.168.1.42"
TB_PORT         = 1883               # default ThingsBoard MQTT port
TB_ACCESS_TOKEN = "YOUR_DEVICE_TOKEN_HERE"   # copy from ThingsBoard device credentials

# ── Logging
# DEBUG  — prints every window (noisy, good for initial testing)
# INFO   — prints attacks + connection events
# WARNING — prints attacks only
LOG_LEVEL = "INFO"
