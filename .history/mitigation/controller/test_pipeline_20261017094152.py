import json

from mitigation_policy import get_recommendation
from mitigation_controller import MitigationController


def main():

    controller = MitigationController(dry_run=True)

    # These represent the fields produced by the existing
    # AnomalyFlow + Security Severity layer.
    anomalyflow_events = [
        {
            "client": "172.28.0.10",
            "server": "172.29.0.10",
            "port": 8080,
            "predicted_label": "DrDoS_UDP",
            "confidence": 0.91,
            "anomalyflow_score": 0.18,
            "decision_state": "NORMAL",
            "security_severity": "LOW",
        },
        {
            "client": "172.28.0.11",
            "server": "172.29.0.10",
            "port": 8080,
            "predicted_label": "DrDoS_UDP",
            "confidence": 0.82,
            "anomalyflow_score": 0.34,
            "decision_state": "SUSPICIOUS",
            "security_severity": "MEDIUM",
        },
        {
            "client": "172.28.0.12",
            "server": "172.29.0.10",
            "port": 8080,
            "predicted_label": "DrDoS_UDP",
            "confidence": 0.97,
            "anomalyflow_score": 0.67,
            "decision_state": "HIGH_EVIDENCE",
            "security_severity": "HIGH",
        },
    ]

    for event in anomalyflow_events:

        recommendation = get_recommendation(
            event["security_severity"]
        )

        event["mitigation_action"] = recommendation.action
        event["mitigation_priority"] = recommendation.priority

        result = controller.process_event(event)

        print(json.dumps(result, indent=2))

    print()
    print("CHECKPOINT 5 PIPELINE CONNECTION PASSED")


if __name__ == "__main__":
    main()