import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from controller.mitigation_policy import get_recommendation


ROOT = Path(__file__).resolve().parents[2]

LOG_DIR = ROOT / "mitigation" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

EVENT_LOG = LOG_DIR / "mitigation_events.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("mitigation-controller")


ALLOWED_ACTIONS = {
    "NO_ACTION",
    "MONITOR",
    "INVESTIGATE",
    "ALERT_AND_LOG",
    "RATE_LIMIT",
    "BLOCK_AND_RATE_LIMIT",
}


class MitigationController:

    def __init__(self, dry_run=True):
        self.dry_run = dry_run

    def process_event(self, event):
        """
        Process one detection event.

        Expected event fields:
            client
            server
            port
            predicted_label
            confidence
            anomalyflow_score
            decision_state
            security_severity
        """

        required_fields = {
            "client",
            "server",
            "port",
            "predicted_label",
            "confidence",
            "anomalyflow_score",
            "decision_state",
            "security_severity",
        }

        missing = required_fields - set(event.keys())

        if missing:
            raise ValueError(
                f"Missing required fields: {sorted(missing)}"
            )

        recommendation = get_recommendation(
            event["security_severity"]
        )

        if recommendation.action not in ALLOWED_ACTIONS:
            raise ValueError(
                f"Action not allowed: {recommendation.action}"
            )

        timestamp = datetime.now(timezone.utc).isoformat()

        result = {
            "timestamp": timestamp,
            "status": "DRY_RUN" if self.dry_run else "PENDING",
            "client": event["client"],
            "server": event["server"],
            "port": event["port"],
            "predicted_label": event["predicted_label"],
            "confidence": event["confidence"],
            "anomalyflow_score": event["anomalyflow_score"],
            "decision_state": event["decision_state"],
            "security_severity": event["security_severity"],
            "mitigation_action": recommendation.action,
            "mitigation_priority": recommendation.priority,
            "alert_generated": recommendation.alert_generated,
            "alert_level": recommendation.alert_level,
            "alert_type": recommendation.alert_type,
            "mitigation_outcome": (
                "SIMULATED"
                if self.dry_run
                else "NOT_APPLIED"
            ),
        }

        self._write_event(result)

        logger.info(
            "MITIGATION | severity=%s | action=%s | "
            "client=%s | server=%s:%s | status=%s",
            result["security_severity"],
            result["mitigation_action"],
            result["client"],
            result["server"],
            result["port"],
            result["status"],
        )

        return result

    @staticmethod
    def _write_event(event):
        with EVENT_LOG.open(
            "a",
            encoding="utf-8",
        ) as f:
            f.write(
                json.dumps(
                    event,
                    default=str,
                )
                + "\n"
            )


def run_test():

    controller = MitigationController(
        dry_run=True
    )

    test_events = [
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

    for event in test_events:
        result = controller.process_event(event)

        print(
            json.dumps(
                result,
                indent=2
            )
        )

    print()
    print("CHECKPOINT 4 DRY-RUN CONTROLLER PASSED")


if __name__ == "__main__":
    run_test()