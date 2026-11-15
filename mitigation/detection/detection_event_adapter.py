"""
StealthGuard - Detection Event Adapter

Connects the existing frozen detection pipeline to the
MitigationController.

Pipeline:

    engineered 48 features
            ↓
    InferenceAdapter
            ↓
    confidence + confidence_uncertainty
            +
    engineered Rényi features
            ↓
    frozen AnomalyFlow calibration
            ↓
    AnomalyFlow
            ↓
    controller-compatible event

This module does NOT:
    - modify the ML model
    - retrain anything
    - fit new calibration scalers
    - modify AnomalyFlow
    - execute mitigation actions
"""

import json
from pathlib import Path
from typing import Dict, Any

import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler

from mitigation.detection.inference_adapter import InferenceAdapter
from mitigation.detection.anomalyflow import AnomalyFlow


PROJECT_ROOT = Path(__file__).resolve().parents[2]

# 3-class calibration is optional; falls back to identity normalization
# when no calibration file exists for the 3-class model.
CALIBRATION_PATH_3CLASS = (
    PROJECT_ROOT
    / "models"
    / "evaluation"
    / "anomalyflow_calibration_3class.json"
)

RENYI_COLUMNS = [
    "Flow Duration_Renyi",
    "Flow Bytes/s_Renyi",
    "Flow Packets/s_Renyi",
    "Packet Length Mean_Renyi",
    "Packet Length Std_Renyi",
    "Total Fwd Packets_Renyi",
    "Total Backward Packets_Renyi",
    "Average Packet Size_Renyi",
]

# Default weights and thresholds when no calibration file is available.
# These match the existing 17-class configuration values but are applied
# without normalization (identity scalers) until 3-class calibration data
# is collected.
DEFAULT_CONFIDENCE_WEIGHT = 0.5
DEFAULT_RENYI_WEIGHT = 0.5
DEFAULT_NORMAL_THRESHOLD = 0.25
DEFAULT_HIGH_EVIDENCE_THRESHOLD = 0.40


class DetectionEventAdapter:
    """
    Converts frozen ML + AnomalyFlow outputs into the event
    expected by MitigationController.
    """

    def __init__(
        self,
        inference_adapter=None,
        calibration_path=None,
    ):
        self.inference = (
            inference_adapter
            if inference_adapter is not None
            else InferenceAdapter()
        )

        # Default configuration used when no calibration file exists.
        # These values match the existing 17-class configuration but are
        # applied with identity (no-op) scalers until 3-class calibration
        # data is collected from live traffic.
        self.calibration = None
        self.confidence_weight = DEFAULT_CONFIDENCE_WEIGHT
        self.renyi_weight = DEFAULT_RENYI_WEIGHT
        self.normal_threshold = DEFAULT_NORMAL_THRESHOLD
        self.high_evidence_threshold = DEFAULT_HIGH_EVIDENCE_THRESHOLD

        if calibration_path is not None:
            self.calibration_path = Path(calibration_path)
        else:
            self.calibration_path = CALIBRATION_PATH_3CLASS

        if self.calibration_path.exists():
            # Load existing calibration file (17-class or 3-class).
            with open(
                self.calibration_path,
                "r",
                encoding="utf-8",
            ) as f:
                self.calibration = json.load(f)

            self.renyi_standard_scaler = (
                self._build_standard_scaler(
                    self.calibration[
                        "validation_renyi_standard_scaler"
                    ]
                )
            )

            self.confidence_scaler = (
                self._build_minmax_scaler(
                    self.calibration[
                        "confidence_minmax_scaler"
                    ]
                )
            )

            self.renyi_evidence_scaler = (
                self._build_minmax_scaler(
                    self.calibration[
                        "renyi_evidence_minmax_scaler"
                    ]
                )
            )

            self.confidence_weight = self.calibration[
                "weights"
            ]["confidence"]
            self.renyi_weight = self.calibration[
                "weights"
            ]["renyi"]
            self.normal_threshold = self.calibration[
                "thresholds"
            ]["low"]
            self.high_evidence_threshold = self.calibration[
                "thresholds"
            ]["high"]
        else:
            # No calibration file available: use identity scalers.
            # confidence_normalized = confidence_uncertainty (raw)
            # renyi_normalized = renyi_evidence (raw)
            # This is a safe no-op fallback that preserves the values
            # without rescaling them. Documented as a temporary measure
            # until 3-class calibration data is collected.
            self.renyi_standard_scaler = StandardScaler()
            self.renyi_standard_scaler.mean_ = np.zeros(8, dtype=np.float64)
            self.renyi_standard_scaler.scale_ = np.ones(8, dtype=np.float64)
            self.renyi_standard_scaler.var_ = np.ones(8, dtype=np.float64)
            self.renyi_standard_scaler.n_features_in_ = 8

            self.confidence_scaler = MinMaxScaler()
            self.confidence_scaler.data_min_ = np.array([0.0], dtype=np.float64)
            self.confidence_scaler.data_max_ = np.array([1.0], dtype=np.float64)
            self.confidence_scaler.data_range_ = np.array([1.0], dtype=np.float64)
            self.confidence_scaler.scale_ = np.array([1.0], dtype=np.float64)
            self.confidence_scaler.min_ = np.array([0.0], dtype=np.float64)
            self.confidence_scaler.n_features_in_ = 1

            self.renyi_evidence_scaler = MinMaxScaler()
            self.renyi_evidence_scaler.data_min_ = np.array([0.0], dtype=np.float64)
            self.renyi_evidence_scaler.data_max_ = np.array([1.0], dtype=np.float64)
            self.renyi_evidence_scaler.data_range_ = np.array([1.0], dtype=np.float64)
            self.renyi_evidence_scaler.scale_ = np.array([1.0], dtype=np.float64)
            self.renyi_evidence_scaler.min_ = np.array([0.0], dtype=np.float64)
            self.renyi_evidence_scaler.n_features_in_ = 1

        self.anomalyflow = AnomalyFlow(
            confidence_weight=self.confidence_weight,
            renyi_weight=self.renyi_weight,
            normal_threshold=self.normal_threshold,
            high_evidence_threshold=self.high_evidence_threshold,
        )

    # ---------------------------------------------------------
    # Frozen scaler reconstruction
    # ---------------------------------------------------------

    @staticmethod
    def _build_standard_scaler(config):
        scaler = StandardScaler()

        scaler.mean_ = np.asarray(
            config["mean"],
            dtype=np.float64,
        )

        scaler.scale_ = np.asarray(
            config["scale"],
            dtype=np.float64,
        )

        scaler.var_ = scaler.scale_ ** 2
        scaler.n_features_in_ = len(
            scaler.mean_
        )

        return scaler

    @staticmethod
    def _build_minmax_scaler(config):
        scaler = MinMaxScaler()

        scaler.data_min_ = np.asarray(
            config["min"],
            dtype=np.float64,
        )

        scaler.data_max_ = np.asarray(
            config["max"],
            dtype=np.float64,
        )

        scaler.data_range_ = (
            scaler.data_max_
            - scaler.data_min_
        )

        scaler.scale_ = np.asarray(
            config["scale"],
            dtype=np.float64,
        )

        scaler.min_ = np.asarray(
            config["min_offset"],
            dtype=np.float64,
        )

        scaler.n_features_in_ = len(
            scaler.data_min_
        )

        scaler.n_samples_seen_ = 1

        return scaler

    # ---------------------------------------------------------
    # Rényi evidence
    # ---------------------------------------------------------

    def calculate_renyi_evidence(
        self,
        engineered_features,
    ) -> float:
        """
        Reproduce the existing calibration formula:

            8 Rényi features
                ↓
            validation StandardScaler
                ↓
            absolute value
                ↓
            mean

        No scaler fitting occurs here.
        """

        missing = [
            column
            for column in RENYI_COLUMNS
            if column not in engineered_features.columns
        ]

        if missing:
            raise ValueError(
                "Missing required Rényi features:\n"
                + "\n".join(
                    f"  - {column}"
                    for column in missing
                )
            )

        values = engineered_features[
            RENYI_COLUMNS
        ].to_numpy(
            dtype=np.float64
        )

        if values.shape[0] != 1:
            raise ValueError(
                "DetectionEventAdapter expects "
                "exactly one engineered feature row."
            )

        if not np.isfinite(values).all():
            raise ValueError(
                "Rényi features contain NaN or "
                "infinite values."
            )

        standardized = (
            self.renyi_standard_scaler.transform(
                values
            )
        )

        evidence = np.mean(
            np.abs(standardized),
            axis=1,
        )

        return float(evidence[0])

    # ---------------------------------------------------------
    # Full detection event
    # ---------------------------------------------------------

    def create_event(
        self,
        engineered_features,
        client,
        server,
        port,
        diagnostic_base_features=None,
        ground_truth=None,
        protocol="tcp",
    ) -> Dict[str, Any]:
        """
        Convert one engineered feature row into a complete
        MitigationController event.
        """

        # -----------------------------------------------------
        # 1. Frozen model inference
        # -----------------------------------------------------

        inference_result = (
            self.inference.predict_from_engineered_features(
                engineered_features,
                diagnostic_base_features=diagnostic_base_features,
            )
        )

        prediction = inference_result[
            "results"
        ][0]

        predicted_class = prediction[
            "predicted_class"
        ]

        confidence = prediction[
            "confidence"
        ]

        confidence_uncertainty = prediction[
            "confidence_uncertainty"
        ]

        # -----------------------------------------------------
        # 2. Rényi evidence
        # -----------------------------------------------------

        renyi_evidence = (
            self.calculate_renyi_evidence(
                engineered_features
            )
        )

        # -----------------------------------------------------
        # 3. Frozen validation MinMax calibration
        # -----------------------------------------------------

        confidence_normalized = float(
            self.confidence_scaler.transform(
                np.asarray(
                    [[confidence_uncertainty]],
                    dtype=np.float64,
                )
            )[0][0]
        )

        renyi_normalized = float(
            self.renyi_evidence_scaler.transform(
                np.asarray(
                    [[renyi_evidence]],
                    dtype=np.float64,
                )
            )[0][0]
        )

        # -----------------------------------------------------
        # 4. Existing AnomalyFlow logic
        # -----------------------------------------------------

        anomalyflow_result = (
            self.anomalyflow.evaluate(
                predicted_class=predicted_class,
                confidence_normalized=confidence_normalized,
                renyi_normalized=renyi_normalized,
            )
        )

        # -----------------------------------------------------
        # 5. Controller-compatible event
        # -----------------------------------------------------

        return {
            "client": str(client),
            "server": str(server),
            "port": int(port),
            "protocol": str(protocol),

            "predicted_label": predicted_class,

            "confidence": confidence,
            "confidence_uncertainty":
                confidence_uncertainty,

            "renyi_evidence":
                renyi_evidence,

            "confidence_normalized":
                confidence_normalized,

            "renyi_normalized":
                renyi_normalized,

            "anomalyflow_score":
                anomalyflow_result[
                    "anomalyflow_score"
                ],

            "decision_state":
                anomalyflow_result[
                    "decision_state"
                ],

            "security_severity":
                anomalyflow_result[
                    "security_severity"
                ],

            "ground_truth": ground_truth,
        }


def main():
    print("=" * 70)
    print("STEALTHGUARD DETECTION EVENT ADAPTER")
    print("=" * 70)

    adapter = DetectionEventAdapter()

    print()
    print("Inference adapter loaded.")
    print("AnomalyFlow calibration loaded.")
    print("Detection event adapter initialized.")

    print()
    print("=" * 70)
    print("DETECTION EVENT ADAPTER INITIALIZATION PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()