"""
Host-based Intrusion Detection System (HIDS) & File Integrity Monitor (FIM).
Monitors host processes, network socket bindings, and file integrity baselines using SHA-256.
"""
import hashlib
import json
import os
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.models import Alert, SeverityLevel, ThreatCategory
from core.mitre_mapper import get_mitre_info
from config import (
    SUSPICIOUS_PROCESS_NAMES,
    SUSPICIOUS_CMDLINE_PATTERNS,
    SUSPICIOUS_PORTS,
    FIM_WATCH_DIRECTORIES,
    FIM_STATE_FILE,
)


class HostMonitor:
    """Performs host integrity checks, socket inspection, and rogue process discovery."""

    def __init__(self, baseline_file: Optional[Path] = None):
        self.baseline_file = baseline_file or FIM_STATE_FILE
        self.baseline: Dict[str, str] = self._load_baseline()

    def _load_baseline(self) -> Dict[str, str]:
        """Load stored file hashes from disk if available."""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_baseline(self):
        """Save file hashes to disk."""
        try:
            self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.baseline_file, "w", encoding="utf-8") as f:
                json.dump(self.baseline, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def calculate_file_hash(filepath: Path) -> Optional[str]:
        """Compute SHA-256 hash of a file."""
        if not filepath.is_file():
            return None
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None

    def initialize_fim_baseline(self, target_dirs: Optional[List[str]] = None) -> int:
        """Establish or refresh SHA-256 integrity baseline for target directories."""
        dirs = target_dirs or FIM_WATCH_DIRECTORIES
        indexed_count = 0
        baseline_resolved = str(self.baseline_file.resolve())

        for dir_path in dirs:
            p = Path(dir_path)
            if not p.exists():
                p.mkdir(parents=True, exist_ok=True)
                # Create a sample config file for FIM demonstration
                sample_file = p / "sys_config.cfg"
                if not sample_file.exists():
                    sample_file.write_text("SECURITY_MODE=STRICT\nFIREWALL_ENABLED=TRUE\n")

            for item in p.rglob("*"):
                if item.is_file():
                    abs_path = str(item.resolve())
                    if abs_path == baseline_resolved:
                        continue
                    h = self.calculate_file_hash(item)
                    if h:
                        self.baseline[abs_path] = h
                        indexed_count += 1

        self._save_baseline()
        return indexed_count

    def check_file_integrity(self, target_dirs: Optional[List[str]] = None) -> List[Alert]:
        """Scan monitored assets and compare against the SHA-256 baseline."""
        dirs = target_dirs or FIM_WATCH_DIRECTORIES
        alerts: List[Alert] = []
        current_files: Dict[str, str] = {}
        baseline_resolved = str(self.baseline_file.resolve())
        resolved_dirs = [str(Path(d).resolve()) for d in dirs]

        for dir_path in dirs:
            p = Path(dir_path)
            if not p.exists():
                continue
            for item in p.rglob("*"):
                if item.is_file():
                    abs_path = str(item.resolve())
                    if abs_path == baseline_resolved:
                        continue
                    h = self.calculate_file_hash(item)
                    if h:
                        current_files[abs_path] = h

        # 1. Check for Modified or Deleted Files
        for path_str, original_hash in self.baseline.items():
            # Only consider files belonging to target directories
            if not any(path_str.startswith(d) for d in resolved_dirs):
                continue
            if path_str == baseline_resolved:
                continue

            if path_str not in current_files:
                mitre = get_mitre_info(ThreatCategory.HOST_TAMPERING)
                alerts.append(Alert(
                    severity=SeverityLevel.HIGH,
                    category=ThreatCategory.HOST_TAMPERING,
                    title="FIM: Monitored Critical File Deleted",
                    description=f"Monitored asset was deleted or moved: {path_str}",
                    source_ip="127.0.0.1",
                    destination_ip="127.0.0.1",
                    mitre_technique_id=mitre["technique_id"],
                    mitre_technique_name=mitre["technique_name"],
                    mitre_tactic=mitre["tactic"],
                    mitigation_recommendation=mitre["remediation"],
                    raw_payload_snippet=f"Missing: {path_str}"
                ))
            elif current_files[path_str] != original_hash:
                mitre = get_mitre_info(ThreatCategory.HOST_TAMPERING)
                alerts.append(Alert(
                    severity=SeverityLevel.CRITICAL,
                    category=ThreatCategory.HOST_TAMPERING,
                    title="FIM: File Hash Integrity Mismatch (Tampering Detected)",
                    description=(
                        f"Cryptographic hash alteration detected in {Path(path_str).name}.\n"
                        f"Expected SHA-256: {original_hash[:16]}...\n"
                        f"Current SHA-256:  {current_files[path_str][:16]}..."
                    ),
                    source_ip="127.0.0.1",
                    destination_ip="127.0.0.1",
                    mitre_technique_id=mitre["technique_id"],
                    mitre_technique_name=mitre["technique_name"],
                    mitre_tactic=mitre["tactic"],
                    mitigation_recommendation=mitre["remediation"],
                    raw_payload_snippet=f"Modified: {path_str}"
                ))

        # 2. Check for Newly Introduced Files
        for path_str in current_files:
            if path_str == baseline_resolved:
                continue
            if path_str not in self.baseline:
                mitre = get_mitre_info(ThreatCategory.HOST_TAMPERING)
                alerts.append(Alert(
                    severity=SeverityLevel.MEDIUM,
                    category=ThreatCategory.HOST_TAMPERING,
                    title="FIM: New Unregistered File Created in Secure Zone",
                    description=f"New unexpected file discovered: {path_str}",
                    source_ip="127.0.0.1",
                    destination_ip="127.0.0.1",
                    mitre_technique_id=mitre["technique_id"],
                    mitre_technique_name=mitre["technique_name"],
                    mitre_tactic=mitre["tactic"],
                    mitigation_recommendation=mitre["remediation"],
                    raw_payload_snippet=f"Created: {path_str}"
                ))

        return alerts

    def check_processes(self) -> List[Alert]:
        """Scan running host processes for known malware executables or malicious command lines."""
        alerts: List[Alert] = []

        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    info = proc.info
                    name = (info.get("name") or "").lower()
                    cmdline_list = info.get("cmdline") or []
                    cmdline = " ".join(cmdline_list).lower()
                    pid = info.get("pid")

                    # Check process name against blacklist
                    for bad_name in SUSPICIOUS_PROCESS_NAMES:
                        if bad_name.lower() in name:
                            mitre = get_mitre_info(ThreatCategory.SUSPICIOUS_PROCESS)
                            alerts.append(Alert(
                                severity=SeverityLevel.CRITICAL,
                                category=ThreatCategory.SUSPICIOUS_PROCESS,
                                title=f"Malicious Process Detected: {name}",
                                description=f"Known hostile process identified: {name} (PID: {pid}). Command: {cmdline[:100]}",
                                source_ip="127.0.0.1",
                                destination_ip="127.0.0.1",
                                mitre_technique_id=mitre["technique_id"],
                                mitre_technique_name=mitre["technique_name"],
                                mitre_tactic=mitre["tactic"],
                                mitigation_recommendation=mitre["remediation"],
                                raw_payload_snippet=f"PID {pid}: {name}"
                            ))
                            break

                    # Check suspicious command line invocations
                    for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
                        if pattern.lower() in cmdline:
                            mitre = get_mitre_info(ThreatCategory.SUSPICIOUS_PROCESS)
                            alerts.append(Alert(
                                severity=SeverityLevel.HIGH,
                                category=ThreatCategory.SUSPICIOUS_PROCESS,
                                title=f"Suspicious Process Command-Line: '{pattern}'",
                                description=f"Process (PID: {pid}, {name}) executing suspicious pattern: {cmdline[:120]}",
                                source_ip="127.0.0.1",
                                destination_ip="127.0.0.1",
                                mitre_technique_id=mitre["technique_id"],
                                mitre_technique_name=mitre["technique_name"],
                                mitre_tactic=mitre["tactic"],
                                mitigation_recommendation=mitre["remediation"],
                                raw_payload_snippet=f"PID {pid}: {cmdline[:80]}"
                            ))
                            break

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        return alerts

    def check_suspicious_ports(self) -> List[Alert]:
        """Inspect listening sockets and open ports against known backdoor/trojan ports."""
        alerts: List[Alert] = []
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if conn.status == "LISTEN" and conn.laddr:
                    port = conn.laddr.port
                    if port in SUSPICIOUS_PORTS:
                        threat_desc = SUSPICIOUS_PORTS[port]
                        mitre = get_mitre_info(ThreatCategory.SUSPICIOUS_PORT)
                        alerts.append(Alert(
                            severity=SeverityLevel.HIGH,
                            category=ThreatCategory.SUSPICIOUS_PORT,
                            title=f"Unauthorized High-Risk Port Open: {port} ({threat_desc})",
                            description=f"Host is actively listening on high-risk port {port} (Associated threat: {threat_desc}). PID: {conn.pid}",
                            source_ip="127.0.0.1",
                            destination_ip=conn.laddr.ip,
                            mitre_technique_id=mitre["technique_id"],
                            mitre_technique_name=mitre["technique_name"],
                            mitre_tactic=mitre["tactic"],
                            mitigation_recommendation=mitre["remediation"],
                            raw_payload_snippet=f"Port {port} LISTEN"
                        ))
        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception:
            pass

        return alerts

    def get_system_vitals(self) -> Dict[str, Any]:
        """Return real-time host hardware and network metrics."""
        try:
            cpu_pct = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            net = psutil.net_io_counters()
            conn_count = len(psutil.net_connections(kind="inet"))
        except Exception:
            cpu_pct = 0.0
            mem = type("obj", (), {"percent": 0.0, "used": 0, "total": 0})
            net = type("obj", (), {"bytes_sent": 0, "bytes_recv": 0})
            conn_count = 0

        return {
            "cpu_percent": cpu_pct,
            "memory_percent": getattr(mem, "percent", 0.0),
            "total_ram_gb": round(getattr(mem, "total", 0) / (1024**3), 2),
            "bytes_sent_mb": round(getattr(net, "bytes_sent", 0) / (1024**2), 2),
            "bytes_recv_mb": round(getattr(net, "bytes_recv", 0) / (1024**2), 2),
            "active_connections": conn_count
        }
