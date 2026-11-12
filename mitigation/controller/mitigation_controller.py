import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .mitigation_policy import get_recommendation
from .. import firewall_controller

ROOT = Path(__file__).resolve().parents[2]

LOG_DIR = ROOT / "mitigation" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

EVENT_LOG = LOG_DIR / "mitigation_events.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("mitigation-controller")


# Known lab networks only. Accept any client in 172.28.0.0/24
# and any server in 172.29.0.0/24 on any port.
ALLOWED_CLIENT_NETWORK = "172.28."
ALLOWED_SERVER_NETWORK = "172.29."

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

        # Enforce the known lab networks.
        client = str(event["client"])
        server = str(event["server"])
        if (
            not client.startswith(ALLOWED_CLIENT_NETWORK)
            or not server.startswith(ALLOWED_SERVER_NETWORK)
        ):
            raise ValueError(
                "Target rejected: only lab targets in "
                f"{ALLOWED_CLIENT_NETWORK}0/24 -> "
                f"{ALLOWED_SERVER_NETWORK}0/24 are allowed."
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
                client_ip = str(event["client"])
                server_ip = str(event["server"])
                port = int(event["port"])
                protocol = str(event.get("protocol", "tcp"))

                if recommendation.action == "BLOCK_AND_RATE_LIMIT":
                    firewall_controller.apply_temporary_block(
                        client_ip=client_ip,
                        server_ip=server_ip,
                        port=port,
                        protocol=protocol,
                        duration=15,
                    )
                    firewall_controller.apply_temporary_rate_limit(
                        client_ip=client_ip,
                        server_ip=server_ip,
                        port=port,
                        protocol=protocol,
                        duration=30,
                        rate=20,
                        burst=40,
                    )
                    status = "APPLIED"
                    outcome = "BLOCK_AND_RATE_LIMIT_APPLIED"
                else:
                    firewall_controller.apply_temporary_rate_limit(
                        client_ip=client_ip,
                        server_ip=server_ip,
                        port=port,
                        protocol=protocol,
                        duration=30,
                        rate=20,
                        burst=40,
                    )
                    status = "APPLIED"
                    outcome = "RATE_LIMIT_APPLIED"

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

        if event.get("ground_truth") is not None:
            result["ground_truth"] = event["ground_truth"]

        if event.get("experiment_id") is not None:
            result["experiment_id"] = event["experiment_id"]

        if event.get("window_id") is not None:
            result["window_id"] = event["window_id"]

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