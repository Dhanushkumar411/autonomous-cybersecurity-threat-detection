"""
CYBER: Unified Cybersecurity Threat Detection System.
Command-Line Interface and Service Launcher.

Usage:
  python main.py --mode soc                  # Launch Flask Web SOC Dashboard
  python main.py --mode demo                 # Launch SOC Dashboard with live attack simulation
  python main.py --mode scan-host            # Perform immediate Host HIDS / FIM audit
  python main.py --mode simulate             # Run command-line attack simulation drill
  python main.py --mode scan-log --file <p>  # Scan an access log file for cyber threats
"""
import argparse
import sys
import time
import os
from pathlib import Path

# Ensure UTF-8 output encoding on Windows terminals if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from core.correlation_engine import CorrelationEngine
from core.models import SecurityEvent, SeverityLevel
from simulator.attack_simulator import AttackSimulator
from web.app import create_app
from config import SOC_HOST, SOC_PORT


# ANSI Color formatting for terminal output
class TerminalColor:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def print_banner():
    banner = f"""{TerminalColor.CYAN}{TerminalColor.BOLD}
========================================================================================
   CYBER-SENTINEL: AUTONOMOUS THREAT DETECTION & SIEM CORRELATION ENGINE [v2.4]
========================================================================================{TerminalColor.RESET}
 {TerminalColor.WHITE}Multi-Vector Threat Defense | ML Anomaly Engine | MITRE ATT&CK Matrix | Active Response{TerminalColor.RESET}
----------------------------------------------------------------------------------------
"""
    print(banner)


def run_host_scan_cli(engine: CorrelationEngine):
    """Execute host integrity and process audit via CLI."""
    print(f"\n{TerminalColor.BOLD}{TerminalColor.CYAN}[*] Initializing Host-Based Intrusion Detection (HIDS) Scan...{TerminalColor.RESET}")
    print("[*] Auditing running processes, command lines, listening ports, and SHA-256 FIM baselines...")

    alerts = engine.run_host_inspection()
    print(f"\n{TerminalColor.BOLD}[+] Scan Complete: {len(alerts)} alert(s) generated.{TerminalColor.RESET}\n")

    if not alerts:
        print(f"{TerminalColor.GREEN}[+] System Integrity Verified. No hostile processes, rogue sockets, or FIM alterations detected.{TerminalColor.RESET}")
    else:
        for a in alerts:
            col = TerminalColor.RED if a.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else TerminalColor.YELLOW
            print(f" {col}[!] {a.severity.value} | {a.title}{TerminalColor.RESET}")
            print(f"     Category:    {a.category.value} [{a.mitre_technique_id} - {a.mitre_tactic}]")
            print(f"     Description: {a.description}")
            print(f"     Action:      {a.mitigation_recommendation}\n")


def run_cli_simulation_drill(engine: CorrelationEngine):
    """Run an automated multi-stage cyber incident drill."""
    sim = AttackSimulator(event_consumer=engine.ingest_event)
    print(f"\n{TerminalColor.BOLD}{TerminalColor.YELLOW}[*] Commencing Autonomous Cyber Incident Simulation Drill...{TerminalColor.RESET}")

    scenarios = [
        ("SQL Injection Attack", sim.trigger_sqli_attack),
        ("Cross-Site Scripting (XSS)", sim.trigger_xss_attack),
        ("Remote Code Execution (RCE)", sim.trigger_rce_attack),
        ("Directory Traversal / LFI", sim.trigger_path_traversal),
        ("Credential Brute-Force Storm", sim.trigger_brute_force_attack),
        ("Reconnaissance Port Sweep", sim.trigger_port_scan),
        ("Volumetric DoS Request Flood", sim.trigger_dos_flood),
        ("High-Entropy ML Anomaly Payload", sim.trigger_ml_anomaly_payload),
    ]

    for name, action in scenarios:
        print(f"\n{TerminalColor.CYAN}---> Simulating Threat: {name}{TerminalColor.RESET}")
        action()
        time.sleep(0.3)

    metrics = engine.get_soc_metrics()
    alerts = engine.get_recent_alerts(limit=50)

    print(f"\n{TerminalColor.BOLD}====================== INCIDENT TRIAGE REPORT ======================{TerminalColor.RESET}")
    print(f" Total Events Analyzed:    {TerminalColor.BOLD}{metrics['total_events']}{TerminalColor.RESET}")
    print(f" Total Threats Flagged:    {TerminalColor.RED}{TerminalColor.BOLD}{metrics['total_alerts']}{TerminalColor.RESET}")
    print(f" Threat Posture:           {TerminalColor.RED}{metrics['threat_posture']}{TerminalColor.RESET}")
    print(f" Auto-Quarantined IPs:     {TerminalColor.YELLOW}{metrics['blocked_ips_count']}{TerminalColor.RESET}")

    print(f"\n{TerminalColor.BOLD}Breakdown by Severity:{TerminalColor.RESET}")
    for sev, count in metrics["severity_counts"].items():
        if count > 0:
            print(f"  - {sev:<10}: {count}")

    print(f"\n{TerminalColor.BOLD}Quarantined Malicious Actors (Active Defense):{TerminalColor.RESET}")
    for item in metrics["blocked_ips"]:
        print(f"  [X] IP: {item['ip']:<16} Reason: {item['reason']}")

    print(f"\n{TerminalColor.BOLD}Recent Incident Alerts Generated:{TerminalColor.RESET}")
    for a in alerts[:6]:
        print(f"  - [{a['severity']}] {a['title']} (Source: {a['source_ip']})")
    print(f"{TerminalColor.BOLD}===================================================================={TerminalColor.RESET}\n")


def scan_log_file(engine: CorrelationEngine, filepath: str):
    """Parse and inspect an access log file for threats."""
    p = Path(filepath)
    if not p.exists():
        print(f"{TerminalColor.RED}[!] File not found: {filepath}{TerminalColor.RESET}")
        return

    print(f"\n{TerminalColor.CYAN}[*] Ingesting and analyzing log file: {filepath}...{TerminalColor.RESET}")
    total_lines = 0
    alerts_found = 0

    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            # Check if JSON log format or plain access log
            event = SecurityEvent(
                source_ip="198.51.100.12",
                uri=line,
                payload=line,
                raw_log=line
            )
            alerts = engine.ingest_event(event)
            alerts_found += len(alerts)

    print(f"\n[+] Log Scan Complete: Processed {total_lines} entries.")
    print(f"[+] Threats Detected:  {alerts_found}")
    metrics = engine.get_soc_metrics()
    print(f"[+] System Posture:    {metrics['threat_posture']}")


def create_sample_log_file(filepath: Path):
    """Generate a sample log file for testing."""
    sample_lines = [
        '10.0.0.1 - - [24/Oct/2026:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024',
        '10.0.0.2 - - [24/Oct/2026:12:00:02 +0000] "GET /about HTTP/1.1" 200 450',
        '198.51.100.45 - - [24/Oct/2026:12:00:05 +0000] "GET /products?id=1\'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 230',
        '198.51.100.45 - - [24/Oct/2026:12:00:07 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 890',
        '203.0.113.88 - - [24/Oct/2026:12:00:09 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 140',
        '185.220.101.5 - - [24/Oct/2026:12:00:12 +0000] "GET /cgi-bin/ping?host=127.0.0.1;%20whoami HTTP/1.1" 500 95',
        '10.0.0.5 - - [24/Oct/2026:12:00:15 +0000] "GET /contact HTTP/1.1" 200 600',
    ]
    filepath.write_text("\n".join(sample_lines), encoding="utf-8")


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="CYBER-SENTINEL: Cybersecurity Threat Detection System")
    parser.add_argument(
        "--mode",
        choices=["soc", "demo", "simulate", "scan-host", "scan-log"],
        default="soc",
        help="Operating mode (default: soc)"
    )
    parser.add_argument("--host", default=SOC_HOST, help=f"Dashboard host (default: {SOC_HOST})")
    parser.add_argument("--port", type=int, default=SOC_PORT, help=f"Dashboard port (default: {SOC_PORT})")
    parser.add_argument("--file", help="Log file path for 'scan-log' mode")

    args = parser.parse_args()

    engine = CorrelationEngine()

    if args.mode == "scan-host":
        run_host_scan_cli(engine)
        return

    if args.mode == "simulate":
        run_cli_simulation_drill(engine)
        return

    if args.mode == "scan-log":
        log_path = args.file
        if not log_path:
            sample_path = Path("sample_access.log")
            create_sample_log_file(sample_path)
            log_path = str(sample_path)
            print(f"[*] No file provided. Generated sample log file: {sample_path}")
        scan_log_file(engine, log_path)
        return

    # Web Dashboard Mode (soc or demo)
    simulator = AttackSimulator(event_consumer=engine.ingest_event)
    app, _, _ = create_app(engine=engine, simulator=simulator)

    if args.mode == "demo":
        print(f"{TerminalColor.GREEN}[+] DEMO MODE: Background multi-vector attack feed started!{TerminalColor.RESET}")
        simulator.start_continuous_feed(interval_seconds=1.5)

    print(f"\n{TerminalColor.BOLD}{TerminalColor.GREEN}[+] CYBER-SENTINEL SOC Dashboard online!{TerminalColor.RESET}")
    print(f"    URL:                 {TerminalColor.BOLD}{TerminalColor.CYAN}http://{args.host}:{args.port}{TerminalColor.RESET}")
    print(f"    API Ingestion:       http://{args.host}:{args.port}/api/ingest")
    print(f"    Mode:                {args.mode.upper()}")
    print(f"    Press Ctrl+C to terminate the engine.\n")

    try:
        app.run(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        print(f"\n{TerminalColor.YELLOW}[*] Shutting down CYBER-SENTINEL engine...{TerminalColor.RESET}")
        simulator.stop_continuous_feed()
        sys.exit(0)


if __name__ == "__main__":
    main()
