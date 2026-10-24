"""
Machine Learning Anomaly Detection Engine.
Uses Scikit-Learn's Isolation Forest and statistical feature extraction (Shannon entropy,
character distribution, length metrics) to identify novel, zero-day, or obfuscated cyber threats.
"""
import math
import string
import numpy as np
import joblib
from pathlib import Path
from typing import Optional, List
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from core.models import SecurityEvent, Alert, SeverityLevel, ThreatCategory
from core.mitre_mapper import get_mitre_info
from config import ML_MODEL_PATH, ANOMALY_CONTAMINATION_RATE, ANOMALY_SCORE_THRESHOLD


class AnomalyEngine:
    """Detects statistical and behavioral outliers in network payloads and HTTP requests."""

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or ML_MODEL_PATH
        self.pipeline: Optional[Pipeline] = None
        self._initialize_model()

    def _calculate_shannon_entropy(self, text: str) -> float:
        """
        Calculate the Shannon Entropy of a string: H(X) = -sum(P(x) * log2(P(x))).
        Normal human text / URL params typically have entropy 2.0 - 3.8.
        Obfuscated shellcode, base64 payloads, or encrypted C2 commands have entropy > 4.5.
        """
        if not text:
            return 0.0
        length = len(text)
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(entropy)

    def _extract_features(self, event: SecurityEvent) -> np.ndarray:
        """
        Extract numerical feature vector from a SecurityEvent:
        [
            0: uri_length,
            1: payload_length,
            2: payload_entropy,
            3: special_char_ratio,
            4: digit_ratio,
            5: is_non_standard_port,
            6: is_error_status
        ]
        """
        uri = event.uri or ""
        payload = event.payload or ""
        combined_text = f"{uri} {payload}"

        total_len = len(combined_text)
        uri_len = float(len(uri))
        payload_len = float(len(payload))
        entropy = self._calculate_shannon_entropy(combined_text)

        # Special character ratio (common in exploits)
        special_chars = set("!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~")
        if total_len > 0:
            special_count = sum(1 for c in combined_text if c in special_chars)
            digit_count = sum(1 for c in combined_text if c.isdigit())
            special_ratio = special_count / total_len
            digit_ratio = digit_count / total_len
        else:
            special_ratio = 0.0
            digit_ratio = 0.0

        is_non_standard_port = 1.0 if event.destination_port not in (80, 443, 8080, 5050) else 0.0
        is_error_status = 1.0 if event.status_code >= 400 else 0.0

        return np.array([
            uri_len,
            payload_len,
            entropy,
            special_ratio,
            digit_ratio,
            is_non_standard_port,
            is_error_status
        ], dtype=np.float32)

    def _generate_normal_training_baseline(self) -> np.ndarray:
        """
        Generates synthetic training samples representing typical, legitimate enterprise web traffic.
        Ensures the Isolation Forest has a solid baseline without requiring external gigabyte dumps.
        """
        normal_samples = []

        # Common regular endpoints and normal benign payloads
        normal_uris = [
            "/",
            "/index.html",
            "/api/v1/products",
            "/api/v1/products?category=electronics&sort=asc&page=1",
            "/about-us",
            "/contact",
            "/static/css/bootstrap.min.css",
            "/static/js/app.js",
            "/images/logo.png",
            "/api/users/profile",
            "/search?q=laptop+accessories",
            "/dashboard",
            "/account/settings",
            "/api/notifications?unread=true",
            "/blog/cybersecurity-best-practices",
            "/api/v1/health",
        ]

        normal_payloads = [
            "",
            '{"name": "Alice Smith", "email": "alice@example.com"}',
            '{"theme": "dark", "notifications": true}',
            '{"search": "mechanical keyboard", "filters": {"in_stock": true}}',
            'username=johndoe&remember=true',
            '{"status": "active", "page": 2, "limit": 20}',
            '{"item_id": 402, "quantity": 1}',
            'action=refresh&session_id=user_session_49204',
        ]

        np.random.seed(42)
        # Synthesize 400 normal events with slight variations
        for _ in range(400):
            uri = np.random.choice(normal_uris)
            payload = np.random.choice(normal_payloads) if np.random.rand() > 0.4 else ""
            status = int(np.random.choice([200, 200, 200, 204, 301, 302, 304, 404]))
            port = int(np.random.choice([80, 443, 8080]))

            evt = SecurityEvent(
                uri=uri,
                payload=payload,
                destination_port=port,
                status_code=status
            )
            features = self._extract_features(evt)
            # Add subtle gaussian noise for realistic variance
            noisy_features = features + np.random.normal(0, 0.02, size=features.shape)
            normal_samples.append(np.maximum(0, noisy_features))

        return np.array(normal_samples, dtype=np.float32)

    def _initialize_model(self):
        """Load an existing trained model or train a fresh baseline model."""
        if self.model_path.exists():
            try:
                self.pipeline = joblib.load(self.model_path)
                return
            except Exception:
                pass

        # Train a robust Isolation Forest pipeline
        X_train = self._generate_normal_training_baseline()
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("isolation_forest", IsolationForest(
                n_estimators=120,
                contamination=ANOMALY_CONTAMINATION_RATE,
                random_state=42,
                n_jobs=-1
            ))
        ])
        self.pipeline.fit(X_train)

        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.pipeline, self.model_path)
        except Exception:
            pass

    def evaluate(self, event: SecurityEvent) -> Optional[Alert]:
        """
        Score a security event using the ML pipeline.
        Returns an Alert if the event significantly deviates from baseline.
        """
        if self.pipeline is None:
            return None

        features = self._extract_features(event).reshape(1, -1)
        iso_forest: IsolationForest = self.pipeline.named_steps["isolation_forest"]
        scaler: StandardScaler = self.pipeline.named_steps["scaler"]

        X_scaled = scaler.transform(features)
        score = float(iso_forest.decision_function(X_scaled)[0])  # Lower is more anomalous
        prediction = int(iso_forest.predict(X_scaled)[0])         # -1 for anomaly, 1 for normal

        entropy = float(features[0][2])
        special_ratio = float(features[0][3])

        # Flag if model predicts anomaly and score is beyond threshold, OR extreme entropy/special characters
        is_anomalous = (prediction == -1 and score <= ANOMALY_SCORE_THRESHOLD) or (entropy > 4.6 and special_ratio > 0.28)

        if is_anomalous:
            severity = SeverityLevel.HIGH if score < (ANOMALY_SCORE_THRESHOLD - 0.1) or entropy > 5.0 else SeverityLevel.MEDIUM
            mitre = get_mitre_info(ThreatCategory.ML_ANOMALY)

            desc = (
                f"Statistical anomaly detected by Isolation Forest (Anomaly Score: {score:.3f}, "
                f"Payload Entropy: {entropy:.2f}, Special Char Ratio: {special_ratio:.1%}). "
                f"Deviates substantially from typical baseline profiles."
            )

            snippet = (event.payload or event.uri)[:120]

            return Alert(
                severity=severity,
                category=ThreatCategory.ML_ANOMALY,
                title="ML Anomaly: Deviant Behavioral / Payload Pattern",
                description=desc,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                mitre_technique_id=mitre["technique_id"],
                mitre_technique_name=mitre["technique_name"],
                mitre_tactic=mitre["tactic"],
                anomaly_score=round(score, 4),
                signature_matched="ML Isolation Forest Anomaly",
                mitigation_recommendation=mitre["remediation"],
                event_id=event.event_id,
                raw_payload_snippet=snippet
            )

        return None
