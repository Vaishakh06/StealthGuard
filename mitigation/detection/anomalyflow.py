"""
StealthGuard - AnomalyFlow Decision Layer

Implements the existing Notebook 06 AnomalyFlow logic:

    Model confidence uncertainty
              +
    Rényi statistical evidence
              ↓
        AnomalyFlow score
              ↓
    NORMAL / SUSPICIOUS / HIGH_EVIDENCE
              ↓
       Security severity
"""

from pathlib import Path

import joblib
import numpy as np


# -------------------------------------------------------------------
# Existing project configuration
# -------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

LABEL_ENCODER_PATH = PROJECT_ROOT / "models" / "label_encoder.pkl"


# -------------------------------------------------------------------
# Existing model classes
# -------------------------------------------------------------------

DDOS_CLASSES = {
    "DrDoS_DNS",
    "DrDoS_LDAP",
    "DrDoS_MSSQL",
    "DrDoS_NTP",
    "DrDoS_NetBIOS",
    "DrDoS_SNMP",
    "DrDoS_SSDP",
    "DrDoS_UDP",
    "MSSQL",
    "NetBIOS",
    "Portmap",
    "Syn",
    "TFTP",
    "UDP",
    "UDP-lag",
}


# -------------------------------------------------------------------
# AnomalyFlow configuration
# -------------------------------------------------------------------

CONFIDENCE_WEIGHT = 0.5
RENYI_WEIGHT = 0.5

NORMAL_THRESHOLD = 0.25
HIGH_EVIDENCE_THRESHOLD = 0.40


class AnomalyFlow:
    """
    AnomalyFlow decision layer.

    The confidence and Rényi values passed to this class must already
    be normalized using the same validation-fitted normalization used
    by Notebook 06.
    """

    def __init__(
        self,
        confidence_weight=CONFIDENCE_WEIGHT,
        renyi_weight=RENYI_WEIGHT,
        normal_threshold=NORMAL_THRESHOLD,
        high_evidence_threshold=HIGH_EVIDENCE_THRESHOLD,
    ):
        self.confidence_weight = confidence_weight
        self.renyi_weight = renyi_weight
        self.normal_threshold = normal_threshold
        self.high_evidence_threshold = high_evidence_threshold

        if not np.isclose(
            confidence_weight + renyi_weight,
            1.0
        ):
            raise ValueError(
                "AnomalyFlow weights must sum to 1.0."
            )

    def calculate_score(
        self,
        confidence_normalized,
        renyi_normalized,
    ):
        """
        Calculate the combined AnomalyFlow score.
        """

        confidence_normalized = float(confidence_normalized)
        renyi_normalized = float(renyi_normalized)

        if not np.isfinite(confidence_normalized):
            raise ValueError(
                "Confidence normalized value is not finite."
            )

        if not np.isfinite(renyi_normalized):
            raise ValueError(
                "Rényi normalized value is not finite."
            )

        score = (
            self.confidence_weight * confidence_normalized
            + self.renyi_weight * renyi_normalized
        )

        return float(score)

    def decision_state(self, score):
        """
        Existing AnomalyFlow thresholds.
        """

        score = float(score)

        if score < self.normal_threshold:
            return "NORMAL"

        if score < self.high_evidence_threshold:
            return "SUSPICIOUS"

        return "HIGH_EVIDENCE"

    def security_severity(
        self,
        predicted_class,
        decision_state,
    ):
        """
        Existing Notebook 06 severity mapping.

        Non-DDoS:
            NORMAL        -> NORMAL
            SUSPICIOUS    -> MONITOR
            HIGH_EVIDENCE -> INVESTIGATE

        DDoS:
            NORMAL        -> LOW
            SUSPICIOUS    -> MEDIUM
            HIGH_EVIDENCE -> HIGH
        """

        predicted_class = str(predicted_class)
        decision_state = str(decision_state)

        is_ddos = predicted_class in DDOS_CLASSES

        if is_ddos:
            if decision_state == "NORMAL":
                return "LOW"

            if decision_state == "SUSPICIOUS":
                return "MEDIUM"

            if decision_state == "HIGH_EVIDENCE":
                return "HIGH"

        else:
            if decision_state == "NORMAL":
                return "NORMAL"

            if decision_state == "SUSPICIOUS":
                return "MONITOR"

            if decision_state == "HIGH_EVIDENCE":
                return "INVESTIGATE"

        raise ValueError(
            f"Unknown decision state: {decision_state}"
        )

    def evaluate(
        self,
        predicted_class,
        confidence_normalized,
        renyi_normalized,
    ):
        """
        Complete AnomalyFlow evaluation.
        """

        score = self.calculate_score(
            confidence_normalized,
            renyi_normalized,
        )

        decision = self.decision_state(score)

        severity = self.security_severity(
            predicted_class,
            decision,
        )

        return {
            "predicted_class": str(predicted_class),
            "confidence_normalized": float(
                confidence_normalized
            ),
            "renyi_normalized": float(
                renyi_normalized
            ),
            "anomalyflow_score": float(score),
            "decision_state": decision,
            "security_severity": severity,
        }


def run_test():
    """
    Basic logic test.

    Normal DDoS evidence:
        low score -> NORMAL -> LOW

    Suspicious DDoS:
        medium score -> SUSPICIOUS -> MEDIUM

    High DDoS evidence:
        high score -> HIGH_EVIDENCE -> HIGH

    Non-DDoS high evidence:
        HIGH_EVIDENCE -> INVESTIGATE
    """

    print("=" * 70)
    print("STEALTHGUARD CHECKPOINT 2")
    print("AnomalyFlow Decision Layer Test")
    print("=" * 70)

    anomalyflow = AnomalyFlow()

    # ---------------------------------------------------------------
    # Test 1: DDoS + NORMAL
    # ---------------------------------------------------------------

    result = anomalyflow.evaluate(
        predicted_class="DrDoS_UDP",
        confidence_normalized=0.10,
        renyi_normalized=0.10,
    )

    assert result["anomalyflow_score"] == 0.10
    assert result["decision_state"] == "NORMAL"
    assert result["security_severity"] == "LOW"

    print()
    print("Test 1: DDoS + NORMAL")
    print(result)

    # ---------------------------------------------------------------
    # Test 2: DDoS + SUSPICIOUS
    # ---------------------------------------------------------------

    result = anomalyflow.evaluate(
        predicted_class="DrDoS_UDP",
        confidence_normalized=0.30,
        renyi_normalized=0.30,
    )

    assert result["anomalyflow_score"] == 0.30
    assert result["decision_state"] == "SUSPICIOUS"
    assert result["security_severity"] == "MEDIUM"

    print()
    print("Test 2: DDoS + SUSPICIOUS")
    print(result)

    # ---------------------------------------------------------------
    # Test 3: DDoS + HIGH_EVIDENCE
    # ---------------------------------------------------------------

    result = anomalyflow.evaluate(
        predicted_class="DrDoS_UDP",
        confidence_normalized=0.60,
        renyi_normalized=0.60,
    )

    assert result["anomalyflow_score"] == 0.60
    assert result["decision_state"] == "HIGH_EVIDENCE"
    assert result["security_severity"] == "HIGH"

    print()
    print("Test 3: DDoS + HIGH_EVIDENCE")
    print(result)

    # ---------------------------------------------------------------
    # Test 4: Non-DDoS + HIGH_EVIDENCE
    # ---------------------------------------------------------------

    result = anomalyflow.evaluate(
        predicted_class="BENIGN",
        confidence_normalized=0.60,
        renyi_normalized=0.60,
    )

    assert result["anomalyflow_score"] == 0.60
    assert result["decision_state"] == "HIGH_EVIDENCE"
    assert result["security_severity"] == "INVESTIGATE"

    print()
    print("Test 4: BENIGN + HIGH_EVIDENCE")
    print(result)

    print()
    print("=" * 70)
    print("CHECKPOINT 2 LOGIC TEST PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_test()