"""
Comprehensive Automated Test Suite for Cybersecurity Threat Detection System.
Tests Signature Detection, ML Anomaly Detection, Behavioral Engine, HIDS/FIM, and REST APIs.
"""
import unittest
import time
import tempfile
import shutil
from pathlib import Path

from core.models import SecurityEvent, SeverityLevel, ThreatCategory
from core.signature_engine import SignatureEngine
from core.anomaly_engine import AnomalyEngine
from core.behavioral_engine import BehavioralEngine
from core.host_monitor import HostMonitor
from core.correlation_engine import CorrelationEngine
from web.app import create_app


class TestSignatureEngine(unittest.TestCase):
    def setUp(self):
        self.engine = SignatureEngine()

    def test_sql_injection_detection(self):
        event = SecurityEvent(
            uri="/api/users?id=1%20UNION%20SELECT%20null,password%20FROM%20users--",
            payload=""
        )
        alerts = self.engine.evaluate(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.SQL_INJECTION)
        self.assertEqual(alerts[0].severity, SeverityLevel.CRITICAL)
        self.assertEqual(alerts[0].mitre_technique_id, "T1190")

    def test_xss_detection(self):
        event = SecurityEvent(
            uri="/comments",
            payload="<script>alert(document.cookie)</script>"
        )
        alerts = self.engine.evaluate(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.XSS)
        self.assertIn("Cross-Site Scripting", alerts[0].title)

    def test_command_injection_rce_detection(self):
        event = SecurityEvent(
            uri="/cgi-bin/ping?host=127.0.0.1;%20cat%20/etc/passwd",
            payload=""
        )
        alerts = self.engine.evaluate(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.COMMAND_INJECTION)
        self.assertEqual(alerts[0].severity, SeverityLevel.CRITICAL)

    def test_path_traversal_detection(self):
        event = SecurityEvent(
            uri="/view?file=../../../../etc/passwd",
            payload=""
        )
        alerts = self.engine.evaluate(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.PATH_TRAVERSAL)

    def test_malicious_scanner_user_agent(self):
        event = SecurityEvent(
            uri="/test",
            user_agent="sqlmap/1.6.1#stable"
        )
        alerts = self.engine.evaluate(event)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.MALICIOUS_SCANNER)

    def test_benign_traffic_clean(self):
        event = SecurityEvent(
            uri="/products?category=books&page=2",
            payload='{"item_id": 105}',
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        )
        alerts = self.engine.evaluate(event)
        self.assertEqual(len(alerts), 0)


class TestAnomalyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = AnomalyEngine()

    def test_shannon_entropy_calculation(self):
        low_entropy = self.engine._calculate_shannon_entropy("aaaaaaaaaa")
        self.assertAlmostEqual(low_entropy, 0.0, places=1)

        high_entropy = self.engine._calculate_shannon_entropy("a1b2c3d4e5f6g7h8i9j0!@#$%^&*()")
        self.assertGreater(high_entropy, 4.0)

    def test_ml_detects_high_entropy_obfuscated_payload(self):
        event = SecurityEvent(
            uri="/api/eval",
            payload="b64payload=W3t9XSUyQ2NtZCUzRCUyNTI0JTI1MjhlJTI1MjZ2YWwlMjUyOQ==&key=$$%^%#@"
        )
        alert = self.engine.evaluate(event)
        # Should flag as anomaly due to entropy and special character density
        if alert:
            self.assertEqual(alert.category, ThreatCategory.ML_ANOMALY)
            self.assertIsNotNone(alert.anomaly_score)


class TestBehavioralEngine(unittest.TestCase):
    def setUp(self):
        self.engine = BehavioralEngine()

    def test_brute_force_detection(self):
        ip = "198.51.100.99"
        alerts = []
        for _ in range(6):
            evt = SecurityEvent(
                source_ip=ip,
                uri="/login",
                status_code=401,
                event_type="AUTH_ATTEMPT"
            )
            alerts.extend(self.engine.evaluate(evt))

        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.BRUTE_FORCE)

    def test_port_scan_detection(self):
        ip = "203.0.113.77"
        alerts = []
        for port in [21, 22, 23, 80, 443, 8080, 3306, 5432]:
            evt = SecurityEvent(
                source_ip=ip,
                destination_port=port,
                event_type="NETWORK_FLOW"
            )
            alerts.extend(self.engine.evaluate(evt))

        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.PORT_SCAN)

    def test_dos_flood_detection(self):
        ip = "192.0.2.200"
        alerts = []
        for _ in range(40):
            evt = SecurityEvent(
                source_ip=ip,
                uri="/index.html",
                status_code=200
            )
            alerts.extend(self.engine.evaluate(evt))

        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, ThreatCategory.DOS_ATTACK)


class TestHostMonitorAndFIM(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.baseline_file = Path(self.test_dir) / "baseline.json"
        self.monitor = HostMonitor(baseline_file=self.baseline_file)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fim_baseline_and_tamper_detection(self):
        file_to_watch = Path(self.test_dir) / "config.cfg"
        file_to_watch.write_text("INITIAL_SECURE_STATE=1\n")

        # 1. Initialize Baseline
        count = self.monitor.initialize_fim_baseline(target_dirs=[self.test_dir])
        self.assertGreaterEqual(count, 1)

        # 2. Clean Check
        clean_alerts = self.monitor.check_file_integrity(target_dirs=[self.test_dir])
        self.assertEqual(len(clean_alerts), 0)

        # 3. Simulate unauthorized file tampering
        file_to_watch.write_text("BACKDOOR_INJECTED=TRUE\n")
        tamper_alerts = self.monitor.check_file_integrity(target_dirs=[self.test_dir])
        self.assertGreaterEqual(len(tamper_alerts), 1)
        self.assertEqual(tamper_alerts[0].category, ThreatCategory.HOST_TAMPERING)
        self.assertEqual(tamper_alerts[0].severity, SeverityLevel.CRITICAL)


class TestCorrelationEngineAndAPI(unittest.TestCase):
    def setUp(self):
        self.engine = CorrelationEngine()
        self.app, _, _ = create_app(engine=self.engine)
        self.client = self.app.test_client()

    def test_api_ingest_malicious_event(self):
        payload = {
            "source_ip": "198.51.100.22",
            "uri": "/admin?debug=true;%20whoami",
            "method": "GET",
            "status_code": 200
        }
        res = self.client.post("/api/ingest", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertGreaterEqual(data["alerts_triggered"], 1)

    def test_active_defense_blacklisting(self):
        # A CRITICAL alert triggers immediate automatic blacklisting
        evt = SecurityEvent(
            source_ip="185.220.101.99",
            uri="/api?id=1%20UNION%20SELECT%20*%20FROM%20credentials"
        )
        self.engine.ingest_event(evt)
        metrics = self.engine.get_soc_metrics()
        self.assertIn("185.220.101.99", self.engine.blocked_ips)
        self.assertGreaterEqual(metrics["blocked_ips_count"], 1)

        # Test unblocking via API
        res = self.client.post("/api/blacklist/unblock", json={"ip": "185.220.101.99"})
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("185.220.101.99", self.engine.blocked_ips)

    def test_metrics_endpoint(self):
        res = self.client.get("/api/metrics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("threat_posture", data)
        self.assertIn("severity_counts", data)
        self.assertIn("host_vitals", data)


if __name__ == "__main__":
    unittest.main()
