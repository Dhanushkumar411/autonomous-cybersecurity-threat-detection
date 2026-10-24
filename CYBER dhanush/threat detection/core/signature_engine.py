"""
Signature-based Threat Detection Engine.
Inspects incoming security events (URIs, payloads, headers, user-agents) against high-fidelity regex signatures.
"""
import re
import urllib.parse
from typing import List, Optional, Tuple
from core.models import SecurityEvent, Alert, SeverityLevel, ThreatCategory
from core.mitre_mapper import get_mitre_info


class SignatureEngine:
    """Evaluates SecurityEvents against known attack signatures and CVE heuristics."""

    def __init__(self):
        self._compile_signatures()

    def _compile_signatures(self):
        # 1. SQL Injection Signatures
        self.sqli_patterns = [
            (re.compile(r"(?i)(\bUNION(\s+ALL)?\s+SELECT\b)", re.VERBOSE), "SQLi: UNION SELECT Injection", SeverityLevel.CRITICAL),
            (re.compile(r"(?i)(\b(SELECT.+FROM|INSERT\s+INTO.+VALUES|DELETE\s+FROM|DROP\s+(TABLE|DATABASE)|ALTER\s+TABLE)\b)"), "SQLi: DDL/DML Injection Attempt", SeverityLevel.CRITICAL),
            (re.compile(r"(?i)((\%27|\')\s*(or|and)\s*[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+)"), "SQLi: Tautology Authentication Bypass (' OR '1'='1)", SeverityLevel.HIGH),
            (re.compile(r"(?i)(--\s*$|/\*.*?\*/|;\s*--|#\s*$)"), "SQLi: Inline SQL Comment Truncation", SeverityLevel.MEDIUM),
            (re.compile(r"(?i)(\b(WAITFOR\s+DELAY|SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(|PG_SLEEP\s*\())"), "SQLi: Time-based Blind SQL Injection", SeverityLevel.CRITICAL),
            (re.compile(r"(?i)(\bxp_cmdshell\b)"), "SQLi: Stored Procedure RCE (xp_cmdshell)", SeverityLevel.CRITICAL),
        ]

        # 2. Cross-Site Scripting (XSS) Signatures
        self.xss_patterns = [
            (re.compile(r"(?i)(<\s*script[^>]*>.*?<\s*/\s*script\s*>)"), "XSS: Inline Script Tag Injection", SeverityLevel.HIGH),
            (re.compile(r"(?i)(<\s*script[^>]*|javascript\s*:|vbscript\s*:)"), "XSS: Malicious Script Scheme / Unclosed Tag", SeverityLevel.HIGH),
            (re.compile(r"(?i)(\b(onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=\s*[\'\"]?[^>\s]+)"), "XSS: Event Handler Payload Execution", SeverityLevel.HIGH),
            (re.compile(r"(?i)(<img[^>]+src=[^>]*onerror=|<iframe[^>]+src=|document\.cookie|eval\s*\()"), "XSS: DOM Manipulation / Cookie Theft Attempt", SeverityLevel.HIGH),
        ]

        # 3. Remote Code Execution (RCE) / Command Injection Signatures
        self.rce_patterns = [
            (re.compile(r"(?i)(;\s*(cat|ls|id|whoami|uname|dir|type|net\s+user|ipconfig|ifconfig)\b)"), "RCE: Shell Command Chaining (; cmd)", SeverityLevel.CRITICAL),
            (re.compile(r"(?i)(\|\s*(cat|ls|id|whoami|uname|dir|type|net\s+user|bash|sh|powershell)\b)"), "RCE: Pipe Command Chaining (| cmd)", SeverityLevel.CRITICAL),
            (re.compile(r"(?i)(`\s*(whoami|id|cat|uname|ls)\s*`)"), "RCE: Backtick Command Substitution", SeverityLevel.CRITICAL),
            (re.compile(r"(?i)(\b(nc|netcat|ncat)\s+.*-e\s+(/bin/sh|/bin/bash|cmd\.exe))"), "RCE: Reverse Shell Netcat Listener", SeverityLevel.CRITICAL),
            (re.compile(r"(/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+)"), "RCE: Bash Interactive Reverse Socket (/dev/tcp)", SeverityLevel.CRITICAL),
            (re.compile(r"(?i)(\$\{IFS\}|\bpowershell(\.exe)?\s+(-enc|-encodedcommand)\b)"), "RCE: Obfuscated PowerShell / IFS Evasion", SeverityLevel.CRITICAL),
        ]

        # 4. Path / Directory Traversal & LFI Signatures
        self.lfi_patterns = [
            (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)"), "LFI: Relative Directory Traversal Sequence", SeverityLevel.HIGH),
            (re.compile(r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts|c:\\windows\\system32|c:/windows/system32|boot\.ini|win\.ini)"), "LFI: Sensitive System File Access Attempt", SeverityLevel.CRITICAL),
        ]

        # 5. Malicious Scanners & Automated Reconnaissance
        self.scanner_patterns = [
            (re.compile(r"(?i)(sqlmap|nikto|nmap\s+scripting|masscan|zgrab|gobuster|dirbuster|wfuzz|acunetix|nessus|openvas|hydra|wpscan|havij|arachni)"), "Recon: Automated Vulnerability Scanner Detected", SeverityLevel.MEDIUM),
        ]

        # 6. Web Shell & Backdoor Signatures
        self.webshell_patterns = [
            (re.compile(r"(?i)(c99shell|r57shell|wso\s+shell|b374k|eval\s*\(\s*base64_decode|passthru\s*\(|system\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec\s*\()"), "Backdoor: Web Shell Artifact / PHP Code Execution", SeverityLevel.CRITICAL),
        ]

    def _normalize_string(self, text: str) -> str:
        """Decode URL encoding and unescape common obfuscations for inspection."""
        if not text:
            return ""
        try:
            # Multi-pass URL decode to counter double encoding (e.g. %252e%252e%252f)
            decoded = urllib.parse.unquote(urllib.parse.unquote(text))
            return decoded
        except Exception:
            return text

    def evaluate(self, event: SecurityEvent) -> List[Alert]:
        """
        Analyze a SecurityEvent against all signature rules.
        Returns a list of generated Alerts (can be empty if clean).
        """
        alerts: List[Alert] = []

        # Aggregate fields to inspect
        raw_combined = f"{event.uri} {event.payload} {event.raw_log or ''}"
        norm_combined = self._normalize_string(raw_combined)
        user_agent = event.user_agent or ""

        # 1. Check Scanners
        for pattern, sig_name, severity in self.scanner_patterns:
            if pattern.search(user_agent) or pattern.search(norm_combined):
                alerts.append(self._create_alert(
                    event=event,
                    category=ThreatCategory.MALICIOUS_SCANNER,
                    severity=severity,
                    title=f"Scanner Activity: {sig_name}",
                    description=f"Automated security scanner probe detected from {event.source_ip}. Identified tool: {sig_name}.",
                    signature_matched=sig_name,
                    snippet=user_agent[:120] if pattern.search(user_agent) else norm_combined[:120]
                ))
                break

        # 2. Check SQL Injection
        for pattern, sig_name, severity in self.sqli_patterns:
            match = pattern.search(norm_combined)
            if match:
                alerts.append(self._create_alert(
                    event=event,
                    category=ThreatCategory.SQL_INJECTION,
                    severity=severity,
                    title=f"SQL Injection Detected: {sig_name}",
                    description=f"Potentially hostile SQL statement or bypass clause identified in HTTP request from {event.source_ip}.",
                    signature_matched=sig_name,
                    snippet=match.group(0)[:120]
                ))
                break

        # 3. Check XSS
        for pattern, sig_name, severity in self.xss_patterns:
            match = pattern.search(norm_combined)
            if match:
                alerts.append(self._create_alert(
                    event=event,
                    category=ThreatCategory.XSS,
                    severity=severity,
                    title=f"Cross-Site Scripting (XSS): {sig_name}",
                    description=f"Client-side script execution payload or unescaped event handler detected from {event.source_ip}.",
                    signature_matched=sig_name,
                    snippet=match.group(0)[:120]
                ))
                break

        # 4. Check RCE
        for pattern, sig_name, severity in self.rce_patterns:
            match = pattern.search(norm_combined)
            if match:
                alerts.append(self._create_alert(
                    event=event,
                    category=ThreatCategory.COMMAND_INJECTION,
                    severity=severity,
                    title=f"Command Injection / RCE Attempt: {sig_name}",
                    description=f"Arbitrary system command execution or reverse shell attempt flagged from {event.source_ip}.",
                    signature_matched=sig_name,
                    snippet=match.group(0)[:120]
                ))
                break

        # 5. Check LFI / Path Traversal
        for pattern, sig_name, severity in self.lfi_patterns:
            match = pattern.search(norm_combined)
            if match:
                alerts.append(self._create_alert(
                    event=event,
                    category=ThreatCategory.PATH_TRAVERSAL,
                    severity=severity,
                    title=f"Path Traversal Attempt: {sig_name}",
                    description=f"Directory traversal or unauthorized file access attempt targeting sensitive system files from {event.source_ip}.",
                    signature_matched=sig_name,
                    snippet=match.group(0)[:120]
                ))
                break

        # 6. Check Web Shells
        for pattern, sig_name, severity in self.webshell_patterns:
            match = pattern.search(norm_combined)
            if match:
                alerts.append(self._create_alert(
                    event=event,
                    category=ThreatCategory.COMMAND_INJECTION,
                    severity=severity,
                    title=f"Web Shell Activity: {sig_name}",
                    description=f"Indicators of web shell deployment or backdoor commands detected from {event.source_ip}.",
                    signature_matched=sig_name,
                    snippet=match.group(0)[:120]
                ))
                break

        return alerts

    def _create_alert(self, event: SecurityEvent, category: ThreatCategory, severity: SeverityLevel,
                      title: str, description: str, signature_matched: str, snippet: str) -> Alert:
        mitre = get_mitre_info(category)
        return Alert(
            severity=severity,
            category=category,
            title=title,
            description=description,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            mitre_technique_id=mitre["technique_id"],
            mitre_technique_name=mitre["technique_name"],
            mitre_tactic=mitre["tactic"],
            signature_matched=signature_matched,
            mitigation_recommendation=mitre["remediation"],
            event_id=event.event_id,
            raw_payload_snippet=snippet
        )
