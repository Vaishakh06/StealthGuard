import json
from pathlib import Path

import pandas as pd

from mitigation.detection.detection_event_adapter import DetectionEventAdapter
from mitigation.controller.mitigation_controller import MitigationController


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ENGINEERED_DATASET = (
    PROJECT_ROOT / "dataset" / "engineered" / "engineered_dataset.pkl"
)

CLIENT_IP = "172.28.0.10"
SERVER_IP = "172.29.0.10"
SERVER_PORT = 8080


def main():
    print("=" * 70)
    print("STEALTHGUARD REAL DETECTION → REAL MITIGATION TEST")
    print("=" * 70)

    print("\nLoading engineered dataset...")
    df = pd.read_pickle(ENGINEERED_DATASET)

    print(f"Dataset loaded: {len(df)} rows")

    detector = DetectionEventAdapter()

    # ---------------------------------------------------------
    # Find a genuine HIGH-severity event.
    #
    # We do NOT hardcode the prediction, AnomalyFlow score,
    # decision state, or severity.
    # Those are produced by the real detection pipeline.
    # ---------------------------------------------------------
    print("\nSearching for a genuine HIGH-severity detection...")

    high_event = None
    high_index = None

    # Search a bounded number of rows first.
    # This avoids running inference over all 3.3M rows.
    search_limit = min(len(df), 10000)

    for index in range(search_limit):
        sample = df.iloc[[index]].copy()

        event = detector.create_event(
            engineered_features=sample,
            client=CLIENT_IP,
            server=SERVER_IP,
            port=SERVER_PORT,
        )

        if event["security_severity"] == "HIGH":
            high_event = event
            high_index = index
            break

    if high_event is None:
        print(
            f"\nNo HIGH-severity event found in the first "
            f"{search_limit} rows."
        )
        print("No firewall action was attempted.")
        return

    print(f"\nHIGH-severity sample found at dataset row: {high_index}")

    print("\nREAL HIGH DETECTION EVENT:")
    print(json.dumps(high_event, indent=2, default=str))

    # ---------------------------------------------------------
    # REAL mitigation controller
    #
    # This enables the already-tested firewall controller.
    # ---------------------------------------------------------
    controller = MitigationController(dry_run=False)

    print("\nSending HIGH event to REAL MitigationController...")

    result = controller.process_event(high_event)

    print("\nREAL CONTROLLER RESULT:")
    print(json.dumps(result, indent=2, default=str))

    print("\n" + "=" * 70)
    print("REAL DETECTION → REAL MITIGATION TEST COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()