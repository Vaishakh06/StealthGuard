import json
from pathlib import Path

import pandas as pd

from mitigation.detection.detection_event_adapter import DetectionEventAdapter
from mitigation.controller.mitigation_controller import MitigationController


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ENGINEERED_DATASET = (
    PROJECT_ROOT / "dataset" / "engineered" / "engineered_dataset.pkl"
)

# Approved lab traffic
CLIENT_IP = "172.28.0.10"
SERVER_IP = "172.29.0.10"
SERVER_PORT = 8080


def main():
    print("=" * 70)
    print("STEALTHGUARD REAL DETECTION → MITIGATION TEST")
    print("=" * 70)

    print("\nLoading engineered dataset...")
    df = pd.read_pickle(ENGINEERED_DATASET)

    print(f"Dataset loaded: {len(df)} rows")

    # Use the same engineered 48-feature input expected by
    # InferenceAdapter / DetectionEventAdapter.
    #
    # The first row is used here only to verify the complete
    # detection → controller connection.
    engineered_sample = df.iloc[[0]].copy()

    print("\nInitializing detection event adapter...")
    detector = DetectionEventAdapter()

    # IMPORTANT:
    # Keep enforcement disabled for this first real integration test.
    # The detection values themselves are completely real.
    controller = MitigationController(dry_run=True)

    print("\nRunning real detection pipeline...")

    event = detector.create_event(
        engineered_features=engineered_sample,
        client=CLIENT_IP,
        server=SERVER_IP,
        port=SERVER_PORT,
    )

    print("\nREAL DETECTION EVENT:")
    print(json.dumps(event, indent=2, default=str))

    print("\nSending real detection event to MitigationController...")

    result = controller.process_event(event)

    print("\nCONTROLLER RESULT:")
    print(json.dumps(result, indent=2, default=str))

    print("\n" + "=" * 70)
    print("REAL DETECTION → CONTROLLER PIPELINE PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()