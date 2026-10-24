"""
Configuration settings for the Cybersecurity Threat Detection System.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Server & Dashboard Settings
SOC_HOST = "127.0.0.1"
SOC_PORT = 5050
SECRET_KEY = os.getenv("SOC_SECRET_KEY", "threat-detection-soc-secret-key-2026")

# Maximum alerts and events kept in in-memory circular buffer
MAX_EVENT_HISTORY = 10000
MAX_ALERT_HISTORY = 2000

# Behavioral Detection Thresholds
BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_FAILURE_THRESHOLD = 5

PORT_SCAN_WINDOW_SECONDS = 15
PORT_SCAN_PORT_THRESHOLD = 6

DOS_WINDOW_SECONDS = 5
DOS_REQUEST_THRESHOLD = 35

# Machine Learning Anomaly Detection Settings
ANOMALY_CONTAMINATION_RATE = 0.05
ANOMALY_SCORE_THRESHOLD = -0.15  # IsolationForest decision function cutoff (lower = more anomalous)
ML_MODEL_PATH = BASE_DIR / "core" / "anomaly_model.joblib"

# High-Risk / Suspicious Ports to flag on the host
SUSPICIOUS_PORTS = {
    4444: "Metasploit Default Listener",
    1337: "Common Hacker/Backdoor Port",
    31337: "Back Orifice Trojan",
    6667: "IRC Botnet C2",
    8888: "Suspicious HTTP Proxy / Reverse Shell",
    9001: "Tor / Netcat Relay",
    5555: "Android Debug Bridge / Cryptominer Backdoor",
    4445: "Metasploit Secondary Listener",
}

# Suspicious Process Names (common attack utilities, cryptominers, shells)
SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz.exe",
    "nc.exe",
    "netcat",
    "nmap",
    "masscan",
    "sqlmap",
    "xmrig",
    "xmrig.exe",
    "meterpreter",
    "chisel",
    "ngrok.exe",
    "cobaltstrike",
    "hydra",
    "john.exe",
    "hashcat",
]

# Suspicious Command Line Keywords/Patterns
SUSPICIOUS_CMDLINE_PATTERNS = [
    "downloadstring",
    "-enc",
    "-encodedcommand",
    "bypass -noprofile",
    "invoke-expression",
    "iex(",
    "whoami /priv",
    "vssadmin delete shadows",
    "certutil -urlcache",
    "curl -s http://",
    "wget -O /tmp/",
    "/dev/tcp/",
    "bash -i",
    "nc -e /bin/sh",
    "nc.exe -lvnp",
]

# File Integrity Monitoring (FIM) default watch locations
FIM_WATCH_DIRECTORIES = [
    str(BASE_DIR / "monitored_assets"),
]
FIM_STATE_FILE = BASE_DIR / "fim_baseline.json"
