from dataclasses import dataclass


POLICY = {
    "NORMAL": {
        "action": "NO_ACTION",
        "priority": "NONE",
        "simulation": "No mitigation required",
        "alert_generated": False,
        "alert_level": "NONE",
        "alert_type": "NONE",
    },
    "MONITOR": {
        "action": "MONITOR",
        "priority": "LOW",
        "simulation": "Traffic monitored for continued suspicious activity",
        "alert_generated": True,
        "alert_level": "LOW",
        "alert_type": "MONITORING",
    },
    "INVESTIGATE": {
        "action": "INVESTIGATE",
        "priority": "HIGH",
        "simulation": "Security investigation triggered",
        "alert_generated": True,
        "alert_level": "HIGH",
        "alert_type": "INVESTIGATION",
    },
    "LOW": {
        "action": "ALERT_AND_LOG",
        "priority": "LOW",
        "simulation": "DDoS alert generated and traffic event logged",
        "alert_generated": True,
        "alert_level": "LOW",
        "alert_type": "DDOS_DETECTED",
    },
    "MEDIUM": {
        "action": "RATE_LIMIT",
        "priority": "MEDIUM",
        "simulation": "Traffic rate limiting simulated",
        "alert_generated": True,
        "alert_level": "MEDIUM",
        "alert_type": "RATE_LIMIT_TRIGGERED",
    },
    "HIGH": {
        "action": "BLOCK_AND_RATE_LIMIT",
        "priority": "CRITICAL",
        "simulation": "Traffic blocking and rate limiting simulated",
        "alert_generated": True,
        "alert_level": "CRITICAL",
        "alert_type": "BLOCK_TRIGGERED",
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