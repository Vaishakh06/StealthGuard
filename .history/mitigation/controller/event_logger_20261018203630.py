import json
from pathlib import Path


class MitigationEventLogger:

    def __init__(self, output_dir="results/mitigation_events"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

    def log(self, event):
        event_id = event["event_id"]

        output_file = self.output_dir / f"{event_id}.json"

        with output_file.open(
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                event,
                f,
                indent=2,
            )

        return output_file