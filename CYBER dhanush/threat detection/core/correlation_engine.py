"""
Central SIEM Correlation Engine.
Aggregates alerts across Signature, Machine Learning, Behavioral, and Host engines.
Handles deduplication, automatic IP blacklisting (Active Defense), and metric generation.
"""
import time
from collections import deque, Counter
from typing import List, Dict, Any, Optional, Set
from threading import Lock

from core.models import SecurityEvent, Alert, SeverityLevel, ThreatCategory
from core.signature_engine import SignatureEngine
from core.anomaly_engine import AnomalyEngine
from core.behavioral_engine import BehavioralEngine
from core.host_monitor import HostMonitor
from config import MAX_EVENT_HISTORY, MAX_ALERT_HISTORY


class CorrelationEngine:
    """Enterprise SIEM & Multi-Vector Threat Correlator."""

    def __init__(self):
        self.lock = Lock()
        self.signature_engine = SignatureEngine()
        self.anomaly_engine = AnomalyEngine()
        self.behavioral_engine = BehavioralEngine()
        self.host_monitor = HostMonitor()

        # In-memory alert and event stores
        self.events: deque[SecurityEvent] = deque(maxlen=MAX_EVENT_HISTORY)
        self.alerts: deque[Alert] = deque(maxlen=MAX_ALERT_HISTORY)

        # Active Defense / IP Blacklist
        # ip -> {reason, blocked_at, alert_count}
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.ip_alert_counts: Counter = Counter()

        # Statistics
        self.start_time = time.time()
        self.total_events_processed = 0

        # Initialize FIM baseline on startup
        self.host_monitor.initialize_fim_baseline()

    def ingest_event(self, event: SecurityEvent) -> List[Alert]:
        """
        Process a security event across all detection layers:
        1. Signature Engine (Known threats & heuristics)
        2. ML Anomaly Engine (Deviations from normal baseline)
        3. Behavioral Engine (Stateful sliding window attacks)
        """
        with self.lock:
            self.total_events_processed += 1
            self.events.append(event)
            new_alerts: List[Alert] = []

            # 1. Signature Inspection
            sig_alerts = self.signature_engine.evaluate(event)
            new_alerts.extend(sig_alerts)

            # 2. ML Anomaly Inspection (run if not already flagged as critical signature, to save cycles)
            if not any(a.severity == SeverityLevel.CRITICAL for a in sig_alerts):
                anomaly_alert = self.anomaly_engine.evaluate(event)
                if anomaly_alert:
                    new_alerts.append(anomaly_alert)

            # 3. Behavioral / Stateful Inspection
            beh_alerts = self.behavioral_engine.evaluate(event)
            new_alerts.extend(beh_alerts)

            # Record alerts & enforce Active Defense
            for alert in new_alerts:
                self.alerts.append(alert)
                self.ip_alert_counts[alert.source_ip] += 1

                # Active Defense Auto-Mitigation:
                # Blacklist IP if it hits CRITICAL alert or >= 3 total alerts
                if alert.source_ip not in ("127.0.0.1", "localhost", "0.0.0.0"):
                    if alert.severity == SeverityLevel.CRITICAL or self.ip_alert_counts[alert.source_ip] >= 3:
                        if alert.source_ip not in self.blocked_ips:
                            self.blocked_ips[alert.source_ip] = {
                                "ip": alert.source_ip,
                                "reason": f"{alert.title} ({alert.severity.value})",
                                "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "alert_count": self.ip_alert_counts[alert.source_ip]
                            }

            return new_alerts

    def run_host_inspection(self) -> List[Alert]:
        """Trigger an immediate Host-based scan (FIM, processes, high-risk ports)."""
        with self.lock:
            hids_alerts: List[Alert] = []

            # Check rogue processes
            proc_alerts = self.host_monitor.check_processes()
            hids_alerts.extend(proc_alerts)

            # Check open high-risk ports
            port_alerts = self.host_monitor.check_suspicious_ports()
            hids_alerts.extend(port_alerts)

            # Check file integrity
            fim_alerts = self.host_monitor.check_file_integrity()
            hids_alerts.extend(fim_alerts)

            for alert in hids_alerts:
                self.alerts.append(alert)

            return hids_alerts

    def unblock_ip(self, ip: str) -> bool:
        """Manually remove an IP from the active blacklist."""
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self.ip_alert_counts[ip] = 0
                return True
            return False

    def block_ip_manually(self, ip: str, reason: str = "Manual Analyst Quarantine") -> None:
        """Manually add an IP to the active blacklist."""
        with self.lock:
            self.blocked_ips[ip] = {
                "ip": ip,
                "reason": reason,
                "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "alert_count": self.ip_alert_counts[ip]
            }

    def get_soc_metrics(self) -> Dict[str, Any]:
        """Compute aggregated metrics and statistics for the SOC dashboard."""
        with self.lock:
            severity_counts = {
                SeverityLevel.CRITICAL.value: 0,
                SeverityLevel.HIGH.value: 0,
                SeverityLevel.MEDIUM.value: 0,
                SeverityLevel.LOW.value: 0,
                SeverityLevel.INFO.value: 0,
            }
            category_counts = Counter()
            tactic_counts = Counter()

            for alert in self.alerts:
                severity_counts[alert.severity.value] += 1
                category_counts[alert.category.value] += 1
                tactic_counts[alert.mitre_tactic] += 1

            # Top offending source IPs
            top_offenders = [
                {"ip": ip, "count": count, "blocked": ip in self.blocked_ips}
                for ip, count in self.ip_alert_counts.most_common(5)
            ]

            # System overall threat posture calculation
            crit_count = severity_counts[SeverityLevel.CRITICAL.value]
            high_count = severity_counts[SeverityLevel.HIGH.value]
            if crit_count > 0:
                threat_posture = "ELEVATED DEFCON 2 (CRITICAL)"
                posture_color = "#ef4444"
            elif high_count > 0:
                threat_posture = "DEFCON 3 (HIGH THREAT)"
                posture_color = "#f97316"
            elif len(self.alerts) > 0:
                threat_posture = "DEFCON 4 (GUARDED)"
                posture_color = "#eab308"
            else:
                threat_posture = "DEFCON 5 (NORMAL / SECURE)"
                posture_color = "#22c55e"

            uptime_sec = int(time.time() - self.start_time)
            host_vitals = self.host_monitor.get_system_vitals()

            return {
                "total_events": self.total_events_processed,
                "total_alerts": len(self.alerts),
                "severity_counts": severity_counts,
                "category_counts": dict(category_counts),
                "mitre_tactic_counts": dict(tactic_counts),
                "top_offenders": top_offenders,
                "blocked_ips_count": len(self.blocked_ips),
                "blocked_ips": list(self.blocked_ips.values()),
                "threat_posture": threat_posture,
                "posture_color": posture_color,
                "uptime_seconds": uptime_sec,
                "host_vitals": host_vitals
            }

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent alerts formatted for display."""
        with self.lock:
            # Alerts are stored in chronological order; return reversed for newest first
            alerts_list = list(self.alerts)[-limit:]
            alerts_list.reverse()
            return [alert.to_dict() for alert in alerts_list]

    def clear_all(self):
        """Reset all in-memory alerts, events, and blacklist."""
        with self.lock:
            self.alerts.clear()
            self.events.clear()
            self.blocked_ips.clear()
            self.ip_alert_counts.clear()
            self.total_events_processed = 0
