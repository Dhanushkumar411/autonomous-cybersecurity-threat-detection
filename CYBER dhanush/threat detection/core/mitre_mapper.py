"""
MITRE ATT&CK Framework Mapping and Incident Mitigation Advisory.
Provides enterprise-grade mappings of detected threats to MITRE ATT&CK Tactics, Techniques, and Remediation steps.
"""
from typing import Dict, Any
from core.models import ThreatCategory


MITRE_TACTIC_TECHNIQUE_MAP: Dict[ThreatCategory, Dict[str, str]] = {
    ThreatCategory.SQL_INJECTION: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "remediation": "Apply parameterized queries/prepared statements, validate input schemas, and enforce WAF rules blocking SQL meta-characters."
    },
    ThreatCategory.XSS: {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "remediation": "Implement strict Content-Security-Policy (CSP) headers, contextual output HTML encoding, and HTTP-only cookie flags."
    },
    ThreatCategory.COMMAND_INJECTION: {
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell / PowerShell",
        "tactic": "Execution",
        "remediation": "Avoid invoking shell sub-processes with user input; restrict execution permissions, and sanitize command parameters."
    },
    ThreatCategory.PATH_TRAVERSAL: {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "remediation": "Canonicalize file paths before access, use strict whitelist validation for filenames, and enforce chroot/sandbox jails."
    },
    ThreatCategory.BRUTE_FORCE: {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "remediation": "Enforce exponential backoff/rate limiting, activate Multi-Factor Authentication (MFA), and temporarily blacklist the offending IP."
    },
    ThreatCategory.PORT_SCAN: {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "remediation": "Drop unsolicited scan packets at firewall boundary, configure IDS/IPS dynamic blocking rules, and mask internal network topology."
    },
    ThreatCategory.DOS_ATTACK: {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Flood",
        "tactic": "Impact",
        "remediation": "Implement rate limiting via reverse proxy (Nginx/Cloudflare), activate SYN cookies, and drop requests exceeding threshold."
    },
    ThreatCategory.MALICIOUS_SCANNER: {
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "remediation": "Block automated scanner user-agents and source IPs at reverse proxy, monitor honey-tokens, and audit perimeter exposures."
    },
    ThreatCategory.ML_ANOMALY: {
        "technique_id": "T1005",
        "technique_name": "Data from Local System / Behavioral Anomaly",
        "tactic": "Collection",
        "remediation": "Inspect anomalous payload entropy and flow characteristics, review host process context, and triage for zero-day exploitation."
    },
    ThreatCategory.HOST_TAMPERING: {
        "technique_id": "T1565.001",
        "technique_name": "Data Manipulation: Stored Data Manipulation",
        "tactic": "Impact",
        "remediation": "Isolate host immediately, compare modified files against verified golden image baseline, and inspect system audit logs."
    },
    ThreatCategory.SUSPICIOUS_PROCESS: {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter / Rogue Process",
        "tactic": "Execution",
        "remediation": "Terminate suspicious PID immediately, quarantine binary executable, and perform memory forensics for persistence mechanisms."
    },
    ThreatCategory.SUSPICIOUS_PORT: {
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port / Unauthorized Listener",
        "tactic": "Command and Control",
        "remediation": "Terminate the binding process, inspect netstat foreign connections, and verify firewall port whitelist rules."
    },
}


def get_mitre_info(category: ThreatCategory) -> Dict[str, str]:
    """Retrieve MITRE ATT&CK metadata for a given threat category."""
    return MITRE_TACTIC_TECHNIQUE_MAP.get(
        category,
        {
            "technique_id": "T1204",
            "technique_name": "User Execution / Unknown Threat",
            "tactic": "Initial Access",
            "remediation": "Investigate source IP and analyze system logs for unusual behavior."
        }
    )
