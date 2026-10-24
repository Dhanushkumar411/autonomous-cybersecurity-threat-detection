"""
SOC Dashboard Web Application & REST API.
Provides an interactive Security Operations Center interface, live alert streaming,
and control over threat simulation and host integrity auditing.
"""
from flask import Flask, render_template, jsonify, request, Response
import json
import time

from core.correlation_engine import CorrelationEngine
from core.models import SecurityEvent
from simulator.attack_simulator import AttackSimulator
from config import SOC_HOST, SOC_PORT, SECRET_KEY


def create_app(engine: CorrelationEngine = None, simulator: AttackSimulator = None):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY

    # Shared instances
    engine = engine or CorrelationEngine()
    simulator = simulator or AttackSimulator(event_consumer=engine.ingest_event)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/metrics", methods=["GET"])
    def get_metrics():
        metrics = engine.get_soc_metrics()
        metrics["simulator_active"] = simulator.is_running
        return jsonify(metrics)

    @app.route("/api/alerts", methods=["GET"])
    def get_alerts():
        limit = request.args.get("limit", default=50, type=int)
        alerts = engine.get_recent_alerts(limit=limit)
        return jsonify({"alerts": alerts, "total": len(alerts)})

    @app.route("/api/ingest", methods=["POST"])
    def ingest_event():
        """External endpoint for log shippers, webhooks, or agents to submit security events."""
        try:
            data = request.get_json(force=True)
            event = SecurityEvent(
                source_ip=data.get("source_ip", request.remote_addr or "127.0.0.1"),
                destination_ip=data.get("destination_ip", "127.0.0.1"),
                source_port=int(data.get("source_port", 0)),
                destination_port=int(data.get("destination_port", 80)),
                protocol=data.get("protocol", "HTTP"),
                method=data.get("method", "GET"),
                uri=data.get("uri", "/"),
                payload=data.get("payload", ""),
                headers=data.get("headers", {}),
                status_code=int(data.get("status_code", 200)),
                user_agent=data.get("user_agent", request.headers.get("User-Agent", "")),
                event_type=data.get("event_type", "WEB_REQUEST"),
                raw_log=data.get("raw_log")
            )
            alerts = engine.ingest_event(event)
            return jsonify({
                "status": "success",
                "event_id": event.event_id,
                "alerts_triggered": len(alerts),
                "alerts": [a.to_dict() for a in alerts]
            }), 201
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 400

    @app.route("/api/simulate/<attack_type>", methods=["POST"])
    def simulate_attack(attack_type: str):
        """Simulate specific threat patterns."""
        actions = {
            "sqli": ("SQL Injection", simulator.trigger_sqli_attack),
            "xss": ("Cross-Site Scripting", simulator.trigger_xss_attack),
            "rce": ("Remote Code Execution", simulator.trigger_rce_attack),
            "lfi": ("Path Traversal", simulator.trigger_path_traversal),
            "brute_force": ("Brute Force Storm", simulator.trigger_brute_force_attack),
            "port_scan": ("Port Scan Sweep", simulator.trigger_port_scan),
            "dos": ("DoS Flood", simulator.trigger_dos_flood),
            "scanner": ("Malicious Scanner Probe", simulator.trigger_scanner_probe),
            "anomaly": ("ML Payload Anomaly", simulator.trigger_ml_anomaly_payload),
            "benign": ("Benign Traffic Event", simulator.trigger_benign_traffic),
        }

        if attack_type not in actions:
            return jsonify({"status": "error", "message": f"Unknown attack type: {attack_type}"}), 400

        name, func = actions[attack_type]
        func()
        return jsonify({"status": "success", "message": f"Simulated {name} dispatched successfully."})

    @app.route("/api/simulator/toggle", methods=["POST"])
    def toggle_simulator():
        """Toggle background simulated attack feed."""
        if simulator.is_running:
            simulator.stop_continuous_feed()
            status = "stopped"
        else:
            simulator.start_continuous_feed(interval_seconds=1.2)
            status = "started"
        return jsonify({"status": "success", "simulator_state": status})

    @app.route("/api/scan/host", methods=["POST"])
    def scan_host():
        """Trigger an immediate Host-based scan (FIM, processes, high-risk ports)."""
        alerts = engine.run_host_inspection()
        return jsonify({
            "status": "success",
            "host_alerts_found": len(alerts),
            "alerts": [a.to_dict() for a in alerts]
        })

    @app.route("/api/blacklist/unblock", methods=["POST"])
    def unblock_ip():
        data = request.get_json(force=True) or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"status": "error", "message": "Missing 'ip' parameter."}), 400
        removed = engine.unblock_ip(ip)
        return jsonify({"status": "success", "unblocked": removed, "ip": ip})

    @app.route("/api/blacklist/block", methods=["POST"])
    def manual_block_ip():
        data = request.get_json(force=True) or {}
        ip = data.get("ip")
        reason = data.get("reason", "Manual SOC Analyst Quarantine")
        if not ip:
            return jsonify({"status": "error", "message": "Missing 'ip' parameter."}), 400
        engine.block_ip_manually(ip, reason=reason)
        return jsonify({"status": "success", "blocked": True, "ip": ip})

    @app.route("/api/clear", methods=["POST"])
    def clear_dashboard():
        """Reset dashboard session data."""
        engine.clear_all()
        return jsonify({"status": "success", "message": "All session alerts and metrics reset."})

    @app.route("/api/export", methods=["GET"])
    def export_report():
        """Export all current alerts as a JSON download."""
        metrics = engine.get_soc_metrics()
        alerts = engine.get_recent_alerts(limit=1000)
        report_data = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "soc_metrics": metrics,
            "incident_alerts": alerts
        }
        json_output = json.dumps(report_data, indent=2)
        return Response(
            json_output,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=threat_incident_report.json"}
        )

    return app, engine, simulator
