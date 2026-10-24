#  Autonomous Cybersecurity Threat Detection System & SIEM

It is an enterprise-grade, multi-vector Intrusion Detection System (IDS), Security Information & Event Management (SIEM) correlator, and Host Integrity Monitor (HIDS) built with Python, Scikit-Learn, and Flask.

---

## Key Features & Architecture

### 1. Multi-Vector Threat Detection Engine
- **Signature & Heuristic Engine (`core/signature_engine.py`)**:
  - **SQL Injection (SQLi)**: UNION SELECT, DDL/DML tampering, tautology bypass (`' OR '1'='1`), inline comment truncations, time-based blind injection (`WAITFOR DELAY`, `SLEEP()`), and stored procedure execution (`xp_cmdshell`).
  - **Cross-Site Scripting (XSS)**: Inline script injections (`<script>`), event handler triggers (`onerror=`, `onload=`), document cookie theft, DOM manipulation.
  - **Remote Code Execution (RCE) / Command Injection**: Shell chaining (`;`, `|`, `` ` ``), pipe exploitation, reverse TCP netcat listeners, `/dev/tcp` sockets, obfuscated PowerShell flags.
  - **Path Traversal / Local File Inclusion (LFI)**: Relative traversal sequences (`../../`), access to sensitive system files (`/etc/passwd`, `/etc/shadow`, `boot.ini`, `win.ini`).
  - **Reconnaissance & Scanners**: Signature detection for automated probing tools (`sqlmap`, `Nikto`, `Nmap NSE`, `masscan`, `gobuster`).
  - **Web Shells & Backdoors**: Evaluation of PHP backdoor artifacts (`eval(base64_decode)`, `passthru()`, `system($_GET)`).

- **Machine Learning Anomaly Engine (`core/anomaly_engine.py`)**:
  - Employs **Scikit-Learn's Isolation Forest** with Shannon entropy feature engineering ($H(X) = -\sum P(x) \log_2 P(x)$).
  - Flags zero-day exploits, encrypted/obfuscated payloads, binary injection attempts, and abnormal parameter density that bypass static regex signatures.

- **Stateful Behavioral Engine (`core/behavioral_engine.py`)**:
  - Sliding-window time-series correlation:
    - **Brute Force Credential Guessing**: Detects repeated authentication failures within configurable time windows.
    - **Port Scanning Sweeps**: Detects horizontal and vertical port scanning across distinct ports.
    - **Denial of Service (DoS)**: Flags volumetric HTTP and packet floods exceeding request thresholds.

- **Host-Based Intrusion Detection & FIM (`core/host_monitor.py`)**:
  - **File Integrity Monitoring (FIM)**: Maintains SHA-256 cryptographic baselines to detect unauthorized file tampering, creation, or deletion in monitored directories.
  - **Rogue Process & Command-Line Auditor**: Inspects running OS processes for malware executables (`mimikatz`, `nc`, `xmrig`, `meterpreter`) and hostile PowerShell/bash patterns.
  - **High-Risk Port Monitor**: Detects unauthorized listening sockets bound to known backdoor ports (`4444`, `1337`, `31337`, `6667`).

- **MITRE ATT&CK Framework Mapping (`core/mitre_mapper.py`)**:
  - Mapped automatically to official MITRE Tactics (*Initial Access, Execution, Credential Access, Discovery, Impact, Reconnaissance*) and Technique IDs (*T1190, T1059, T1110, T1046, T1498*).
  - Generates actionable mitigation and remediation advisories for each incident.

- **Active Defense & Automated Mitigation (`core/correlation_engine.py`)**:
  - Automatically isolates and quarantines malicious IP addresses upon detection of critical exploits or repeated hostile behavior.
  - Supports live manual quarantine and unblocking.

---

## Project Structure

```
├── main.py                         # Unified CLI and SOC entry point
├── config.py                       # Configuration (thresholds, ports, paths)
├── requirements.txt                # Python dependencies
├── core/
│   ├── __init__.py
│   ├── models.py                   # Dataclasses: SecurityEvent, Alert, SeverityLevel
│   ├── signature_engine.py         # Regex & pattern matching for known exploits
│   ├── anomaly_engine.py           # Isolation Forest ML anomaly detector
│   ├── behavioral_engine.py        # Sliding-window rate & volume correlator
│   ├── host_monitor.py             # HIDS: Process audit, Port audit & SHA-256 FIM
│   ├── mitre_mapper.py             # MITRE ATT&CK tactics, techniques & remediation
│   └── correlation_engine.py       # Central SIEM coordinator & Active Defense
├── simulator/
│   ├── __init__.py
│   └── attack_simulator.py         # Realistic cyberattack simulator & traffic injector
├── web/
│   ├── __init__.py
│   ├── app.py                      # Flask REST API & Web Dashboard application
│   ├── templates/
│   │   └── dashboard.html          # High-tech Cyberpunk SOC Dashboard
│   └── static/
│       ├── css/
│       │   └── style.css           # Modern dark-mode SOC theme
│       └── js/
│           └── dashboard.js        # Real-time polling, Chart.js telemetry & controls
└── tests/
    ├── __init__.py
    └── test_detection.py           # Automated unit & integration test suite
```

---

## Installation & Setup

1. **Clone or navigate to the directory**:
   ```bash
   cd c:\Users\LENOVO\Documents\antigravity\lively-hubble
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Operating Modes & Usage

### Mode 1: Interactive SOC Web Dashboard (Recommended)
Launch the full web dashboard:
```bash
python main.py --mode soc
```
Open your browser to: **`http://127.0.0.1:5050`**

### Mode 2: Live Demo Mode
Starts the web dashboard and automatically activates the continuous attack simulation feed:
```bash
python main.py --mode demo
```
Open **`http://127.0.0.1:5050`** to watch the threat detection telemetry, charts, and automated quarantine in real time.

### Mode 3: Autonomous Command-Line Incident Drill
Runs an automated multi-stage incident drill directly in the terminal:
```bash
python main.py --mode simulate
```

### Mode 4: Host-Based HIDS & File Integrity Audit
Audits running processes, high-risk listening ports, and SHA-256 file baselines:
```bash
python main.py --mode scan-host
```

### Mode 5: Log File Scanner
Parses and inspects an access log file:0
```bash
python main.py --mode scan-log --file path/to/access.log
```
*(If no file is provided, a realistic sample log `sample_access.log` is generated and scanned automatically).*

---

## REST API Reference

The built-in REST API enables integration with external SIEMs, WAFs, load balancers, and log shippers:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/metrics` | Retrieve live SOC metrics, DEFCON status, severity counts, and host vitals |
| `GET` | `/api/alerts?limit=50` | Retrieve recent alerts with MITRE mappings and remediation steps |
| `POST` | `/api/ingest` | Ingest external security events (JSON payload) |
| `POST` | `/api/simulate/<type>` | Trigger test attack (`sqli`, `xss`, `rce`, `lfi`, `brute_force`, `port_scan`, `dos`, `anomaly`) |
| `POST` | `/api/simulator/toggle` | Toggle continuous simulation background feed |
| `POST` | `/api/scan/host` | Trigger on-demand Host HIDS and FIM scan |
| `POST` | `/api/blacklist/unblock` | Unblock an IP address (`{"ip": "198.51.100.45"}`) |
| `POST` | `/api/blacklist/block` | Manually quarantine an IP address |
| `POST` | `/api/clear` | Clear session alerts and reset DEFCON posture |
| `GET` | `/api/export` | Download complete incident investigation report as JSON |

---

## Running Automated Tests

Run the test suite covering signature matching, Isolation Forest ML anomaly detection, behavioral sliding windows, FIM integrity, and REST APIs:
```bash
python -m unittest tests/test_detection.py
```
All 15 tests execute cleanly with 100% pass rate.
