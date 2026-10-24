"""
Behavioral and Rate-Based Correlation Engine.
Identifies multi-event attacks across time windows:
- Brute Force Credential Guessing
- Horizontal & Vertical Port Scanning
- Denial of Service (DoS) / Traffic Flooding
"""
import time
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple
from core.models import SecurityEvent, Alert, SeverityLevel, ThreatCategory
from core.mitre_mapper import get_mitre_info
from config import (
    BRUTE_FORCE_WINDOW_SECONDS,
    BRUTE_FORCE_FAILURE_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    PORT_SCAN_PORT_THRESHOLD,
    DOS_WINDOW_SECONDS,
    DOS_REQUEST_THRESHOLD,
)


class BehavioralEngine:
    """Stateful sliding-window tracker for behavioral anomaly and volumetric attack detection."""

    def __init__(self):
        # source_ip -> deque of timestamps of failed auths
        self.failed_auth_history: Dict[str, deque] = defaultdict(deque)

        # source_ip -> deque of (timestamp, dest_port)
        self.port_access_history: Dict[str, deque] = defaultdict(deque)

        # source_ip -> deque of timestamps of requests
        self.request_rate_history: Dict[str, deque] = defaultdict(deque)

        # Deduplication tracker to avoid alert spamming for continuous ongoing attacks
        self.last_alerted: Dict[Tuple[str, str], float] = {}

    def _purge_old_entries(self, ip: str, now: float):
        """Purge entries outside the respective sliding windows."""
        # Purge auth history
        auth_queue = self.failed_auth_history[ip]
        while auth_queue and (now - auth_queue[0]) > BRUTE_FORCE_WINDOW_SECONDS:
            auth_queue.popleft()

        # Purge port scan history
        port_queue = self.port_access_history[ip]
        while port_queue and (now - port_queue[0][0]) > PORT_SCAN_WINDOW_SECONDS:
            port_queue.popleft()

        # Purge DoS history
        dos_queue = self.request_rate_history[ip]
        while dos_queue and (now - dos_queue[0]) > DOS_WINDOW_SECONDS:
            dos_queue.popleft()

    def _should_suppress_alert(self, ip: str, attack_type: str, now: float, cooldown: float = 30.0) -> bool:
        """Rate limit alert generation for identical IP and attack type."""
        key = (ip, attack_type)
        last_time = self.last_alerted.get(key, 0.0)
        if (now - last_time) < cooldown:
            return True
        self.last_alerted[key] = now
        return False

    def evaluate(self, event: SecurityEvent) -> List[Alert]:
        """
        Evaluate an incoming event against sliding-window state trackers.
        Returns any behavioral alerts triggered.
        """
        alerts: List[Alert] = []
        ip = event.source_ip
        now = event.timestamp or time.time()

        self._purge_old_entries(ip, now)

        # --- 1. Track DoS / High-Frequency Request Flooding ---
        self.request_rate_history[ip].append(now)
        req_count = len(self.request_rate_history[ip])
        if req_count >= DOS_REQUEST_THRESHOLD:
            if not self._should_suppress_alert(ip, "DOS", now, cooldown=20.0):
                mitre = get_mitre_info(ThreatCategory.DOS_ATTACK)
                alerts.append(Alert(
                    severity=SeverityLevel.CRITICAL if req_count > (DOS_REQUEST_THRESHOLD * 2) else SeverityLevel.HIGH,
                    category=ThreatCategory.DOS_ATTACK,
                    title="Denial of Service (DoS) Flood Detected",
                    description=(
                        f"Abnormal request volume from {ip}: {req_count} requests within {DOS_WINDOW_SECONDS}s "
                        f"(Threshold: {DOS_REQUEST_THRESHOLD}). Potential HTTP flood attack."
                    ),
                    source_ip=ip,
                    destination_ip=event.destination_ip,
                    mitre_technique_id=mitre["technique_id"],
                    mitre_technique_name=mitre["technique_name"],
                    mitre_tactic=mitre["tactic"],
                    mitigation_recommendation=mitre["remediation"],
                    event_id=event.event_id,
                    raw_payload_snippet=f"{req_count} reqs in {DOS_WINDOW_SECONDS}s"
                ))

        # --- 2. Track Port Scanning / Reconnaissance ---
        self.port_access_history[ip].append((now, event.destination_port))
        unique_ports = {port for _, port in self.port_access_history[ip]}
        if len(unique_ports) >= PORT_SCAN_PORT_THRESHOLD:
            if not self._should_suppress_alert(ip, "PORT_SCAN", now, cooldown=30.0):
                mitre = get_mitre_info(ThreatCategory.PORT_SCAN)
                port_list = sorted(list(unique_ports))[:10]
                alerts.append(Alert(
                    severity=SeverityLevel.HIGH,
                    category=ThreatCategory.PORT_SCAN,
                    title="Port Scanning / Service Reconnaissance Sweep",
                    description=(
                        f"Host {ip} scanned {len(unique_ports)} distinct ports within {PORT_SCAN_WINDOW_SECONDS}s. "
                        f"Sample targets: {port_list}."
                    ),
                    source_ip=ip,
                    destination_ip=event.destination_ip,
                    mitre_technique_id=mitre["technique_id"],
                    mitre_technique_name=mitre["technique_name"],
                    mitre_tactic=mitre["tactic"],
                    mitigation_recommendation=mitre["remediation"],
                    event_id=event.event_id,
                    raw_payload_snippet=f"Scanned ports: {port_list}"
                ))

        # --- 3. Track Brute Force Authentication Attempts ---
        is_auth_failure = (
            event.status_code == 401
            or "login" in event.uri.lower() and event.status_code in (401, 403)
            or event.event_type == "AUTH_ATTEMPT" and event.status_code != 200
        )

        if is_auth_failure:
            self.failed_auth_history[ip].append(now)
            fail_count = len(self.failed_auth_history[ip])
            if fail_count >= BRUTE_FORCE_FAILURE_THRESHOLD:
                if not self._should_suppress_alert(ip, "BRUTE_FORCE", now, cooldown=45.0):
                    mitre = get_mitre_info(ThreatCategory.BRUTE_FORCE)
                    alerts.append(Alert(
                        severity=SeverityLevel.HIGH if fail_count < 15 else SeverityLevel.CRITICAL,
                        category=ThreatCategory.BRUTE_FORCE,
                        title="Brute Force Credential Guessing Detected",
                        description=(
                            f"Repeated authentication failures detected from {ip}: "
                            f"{fail_count} failed logins within {BRUTE_FORCE_WINDOW_SECONDS}s."
                        ),
                        source_ip=ip,
                        destination_ip=event.destination_ip,
                        mitre_technique_id=mitre["technique_id"],
                        mitre_technique_name=mitre["technique_name"],
                        mitre_tactic=mitre["tactic"],
                        mitigation_recommendation=mitre["remediation"],
                        event_id=event.event_id,
                        raw_payload_snippet=f"{fail_count} failed attempts on {event.uri}"
                    ))

        return alerts
