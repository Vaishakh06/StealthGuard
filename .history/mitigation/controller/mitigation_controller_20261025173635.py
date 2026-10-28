import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..mitigation_policy import get_recommendationimport firewall_controller


ROOT = Path(__file__).resolve().parents[2]

LOG_DIR = ROOT / "mitigation" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

EVENT_LOG = LOG_DIR / "mitigation_events.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("mitigation-controller")


# Known lab target only.
ALLOWED_CLIENT = "172.28.0.10"
ALLOWED_SERVER = "172.29.0.10"
ALLOWED_PORT = 8080

# Only enforcement currently implemented and tested
# by Person 1's firewall controller.
FIREWALL_ACTION = "BLOCK"


class MitigationController:

    def __init__(self, dry_run=True):
        self.dry_run = dry_run

    def process_event(self, event):
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

        # Enforce the known lab target.
        if (
            event["client"] != ALLOWED_CLIENT
            or event["server"] != ALLOWED_SERVER
            or int(event["port"]) != ALLOWED_PORT
        ):
            raise ValueError(
                "Target rejected: only the approved lab target "
                f"{ALLOWED_CLIENT} -> "
                f"{ALLOWED_SERVER}:{ALLOWED_PORT} is allowed."
            )

        recommendation = get_recommendation(
            event["security_severity"]
        )

        timestamp = datetime.now(timezone.utc).isoformat()

        # LOW currently produces ALERT_AND_LOG, so no firewall
        # enforcement is required.
        if recommendation.action in {
            "NO_ACTION",
            "MONITOR",
            "INVESTIGATE",
            "ALERT_AND_LOG",
        }:
            status = "DRY_RUN" if self.dry_run else "NO_FIREWALL_ACTION"
            outcome = "SIMULATED" if self.dry_run else "NOT_REQUIRED"

        # MEDIUM/HIGH request actions that are not currently
        # implemented by the verified firewall controller.
        elif recommendation.action in {
            "RATE_LIMIT",
            "BLOCK_AND_RATE_LIMIT",
        }:
            if self.dry_run:
                status = "DRY_RUN"
                outcome = "SIMULATED"
            else:
                raise NotImplementedError(
                    f"Policy action '{recommendation.action}' cannot be "
                    "executed because rate limiting is not implemented "
                    "in the verified firewall controller."
                )

        else:
            raise ValueError(
                f"Unsupported mitigation action: "
                f"{recommendation.action}"
            )

        result = {
            "timestamp": timestamp,
            "status": status,
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
            "mitigation_outcome": outcome,
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
                json.dumps(event, default=str) + "\n"
            )


if __name__ == "__main__":
    print("Integrated mitigation controller loaded.")