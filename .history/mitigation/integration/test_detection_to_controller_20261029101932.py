import json

from mitigation.detection.detection_event_adapter import DetectionEventAdapter
from mitigation.controller.mitigation_controller import MitigationController


def main():
    print("=" * 70)
    print("STEALTHGUARD DETECTION → MITIGATION INTEGRATION")
    print("=" * 70)

    # Real detection event adapter
    detector = DetectionEventAdapter()

    # Dry-run controller: no firewall action yet
    controller = MitigationController(dry_run=True)

    print("\nDetection adapter and mitigation controller loaded.")

    # ---------------------------------------------------------
    # Temporary integration input
    # ---------------------------------------------------------
    # This represents one already-engineered 48-feature sample.
    # We will replace this with the actual flow-window input
    # once the integration path is verified.
    #
    # IMPORTANT:
    # Do not manually create anomalyflow/severity values here.
    # The DetectionEventAdapter must calculate those.
    # ---------------------------------------------------------

    print("\nIntegration components initialized successfully.")

    print("\nCHECKPOINT:")
    print("  InferenceAdapter")
    print("        ↓")
    print("  DetectionEventAdapter")
    print("        ↓")
    print("  MitigationController")

    print("\nDETECTION → CONTROLLER INTEGRATION INITIALIZATION PASSED")


if __name__ == "__main__":
    main()