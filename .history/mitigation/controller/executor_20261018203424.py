from datetime import datetime, timezone


class MitigationExecutor:
    """
    Executes or simulates mitigation actions.

    Current implementation supports DRY RUN only.
    Actual nftables enforcement will be connected later through
    the Linux gateway interface.
    """

    def __init__(self, dry_run=True):
        self.dry_run = dry_run

    def execute(
        self,
        action,
        source_ip,
        destination_ip,
        destination_port,
        event_id,
    ):
        timestamp = datetime.now(timezone.utc).isoformat()

        if self.dry_run:
            return {
                "event_id": event_id,
                "timestamp": timestamp,
                "action": action,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "mode": "DRY_RUN",
                "status": "VALIDATED",
                "executed": False,
                "rule_id": None,
                "error": None,
            }

        # Actual enforcement will be implemented later.
        raise NotImplementedError(
            "Live enforcement is not connected yet. "
            "Use dry_run=True."
        )