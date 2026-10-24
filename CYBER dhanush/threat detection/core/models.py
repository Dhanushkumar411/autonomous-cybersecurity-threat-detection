"""
Data models for the Cybersecurity Threat Detection System.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, Optional
import time
import uuid


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    SQL_INJECTION = "SQL Injection (SQLi)"
    XSS = "Cross-Site Scripting (XSS)"
    COMMAND_INJECTION = "Command Injection / RCE"
    PATH_TRAVERSAL = "Path Traversal / LFI"
    BRUTE_FORCE = "Brute Force Authentication"
    PORT_SCAN = "Port Scanning / Reconnaissance"
    DOS_ATTACK = "Denial of Service (DoS)"
    MALICIOUS_SCANNER = "Vulnerability Scanner"
    ML_ANOMALY = "Behavioral / Payload Anomaly"
    HOST_TAMPERING = "File Integrity Violation (FIM)"
    SUSPICIOUS_PROCESS = "Malicious Host Process"
    SUSPICIOUS_PORT = "Unauthorized High-Risk Port"


@dataclass
class SecurityEvent:
    """Represents an incoming security event (network packet, web request, host event, or syslog)."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = field(default_factory=time.time)
    source_ip: str = "127.0.0.1"
    destination_ip: str = "127.0.0.1"
    source_port: int = 0
    destination_port: int = 80
    protocol: str = "HTTP"
    method: str = "GET"
    uri: str = "/"
    payload: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    status_code: int = 200
    user_agent: str = "Mozilla/5.0"
    process_name: Optional[str] = None
    process_cmdline: Optional[str] = None
    event_type: str = "WEB_REQUEST"  # WEB_REQUEST, HOST_PROCESS, NETWORK_FLOW, AUTH_ATTEMPT
    raw_log: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["formatted_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return data


@dataclass
class Alert:
    """Represents a flagged security alert or incident."""
    alert_id: str = field(default_factory=lambda: f"ALT-{str(uuid.uuid4())[:8].upper()}")
    timestamp: float = field(default_factory=time.time)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    category: ThreatCategory = ThreatCategory.SQL_INJECTION
    title: str = ""
    description: str = ""
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    mitre_technique_id: str = "T1190"
    mitre_technique_name: str = "Exploit Public-Facing Application"
    mitre_tactic: str = "Initial Access"
    signature_matched: Optional[str] = None
    anomaly_score: Optional[float] = None
    mitigation_recommendation: str = ""
    event_id: Optional[str] = None
    raw_payload_snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        data["formatted_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return data
