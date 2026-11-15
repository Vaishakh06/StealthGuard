from dataclasses import dataclass


POLICY = {
    "NORMAL": {
        "action": "ALLOW",
        "priority": "NONE",
        "simulation": "Traffic allowed, no mitigation required",
        "alert_generated": False,
        "alert_level": "NONE",
        "alert_type": "NONE",
    },
    "LOW": {
        "action": "MONITOR",
        "priority": "LOW",
        "simulation": "Traffic monitored for continued suspicious activity",
        "alert_generated": True,
        "alert_level": "LOW",
        "alert_type": "MONITORING",
    },
    "MEDIUM": {
        "action": "RATE_LIMIT",
        "priority": "MEDIUM",
        "simulation": "Traffic rate limited",
        "alert_generated": True,
        "alert_level": "MEDIUM",
        "alert_type": "RATE_LIMIT_TRIGGERED",
    },
    "HIGH": {
        "action": "TEMPORARY_BLOCK",
        "priority": "CRITICAL",
        "simulation": "Source IP temporarily blocked",
        "alert_generated": True,
        "alert_level": "CRITICAL",
        "alert_type": "TEMPORARY_BLOCK",
    },
    # Non-DDoS edge-case severities (BENIGN + SUSPICIOUS / HIGH_EVIDENCE).
    # These are informational only: no firewall enforcement.
    "MONITOR": {
        "action": "MONITOR",
        "priority": "LOW",
        "simulation": "Non-DDoS suspicious traffic monitored",
        "alert_generated": True,
        "alert_level": "LOW",
        "alert_type": "MONITORING",
    },
    "INVESTIGATE": {
        "action": "INVESTIGATE",
        "priority": "MEDIUM",
        "simulation": "Non-DDoS high-evidence traffic flagged for investigation",
        "alert_generated": True,
        "alert_level": "MEDIUM",
        "alert_type": "INVESTIGATION",
    },
}


@dataclass
class MitigationRecommendation:
    security_severity: str
    action: str
    priority: str
    simulation: str
    alert_generated: bool
    alert_level: str
    alert_type: str


def get_recommendation(security_severity: str) -> MitigationRecommendation:
    severity = str(security_severity).upper()

    if severity not in POLICY:
        raise ValueError(
            f"Unsupported security severity: {security_severity}"
        )

    p = POLICY[severity]

    return MitigationRecommendation(
        security_severity=severity,
        action=p["action"],
        priority=p["priority"],
        simulation=p["simulation"],
        alert_generated=p["alert_generated"],
        alert_level=p["alert_level"],
        alert_type=p["alert_type"],
    )


if __name__ == "__main__":
    for severity in POLICY:
        result = get_recommendation(severity)
        print(
            f"{severity:12} -> "
            f"{result.action:22} | "
            f"{result.priority:8} | "
            f"{result.alert_type}"
        )

    print("\nCHECKPOINT 3 POLICY TEST PASSED")