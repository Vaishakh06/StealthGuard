"""
StealthGuard - ML Inference Adapter

Checkpoint 1:
    Flow records
        -> 48 statistical features
        -> saved scaler
        -> frozen Hybrid CNN + BiLSTM + Attention model
        -> label encoder
        -> prediction + confidence

This module intentionally does NOT:
    - perform AnomalyFlow decision logic
    - execute mitigation actions
    - modify firewall rules
    - execute shell commands

Those components will be added in later checkpoints.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn


# ============================================================
# PROJECT PATHS
# ============================================================

# inference_adapter.py
#     mitigation/
#         detection/
#             inference_adapter.py
#
# parents[0] = detection
# parents[1] = mitigation
# parents[2] = StealthGuard

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = PROJECT_ROOT / "models" / "hybrid_model.pth"
SCALER_PATH = PROJECT_ROOT / "models" / "scaler.pkl"
LABEL_ENCODER_PATH = PROJECT_ROOT / "models" / "label_encoder.pkl"


# ============================================================
# NOTEBOOK 04 CONFIGURATION
# ============================================================

STAT_FEATURES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Average Packet Size",
]

WINDOW_SIZE = 100
STRIDE = 20
RENYI_ALPHA = 2
RENYI_BINS = 20


# ============================================================
# MODEL
# ============================================================

class Attention(nn.Module):
    """
    Attention layer used by Notebook 06.
    """

    def __init__(self, hidden_size: int):
        super().__init__()

        self.attention = nn.Linear(
            hidden_size * 2,
            1
        )

    def forward(self, lstm_output):
        """
        Parameters
        ----------
        lstm_output:
            Shape:
                (batch_size, sequence_length, hidden_size * 2)

        Returns
        -------
        context:
            Shape:
                (batch_size, hidden_size * 2)

        weights:
            Attention weights.
        """

        scores = self.attention(lstm_output)

        weights = torch.softmax(
            scores,
            dim=1
        )

        context = torch.sum(
            weights * lstm_output,
            dim=1
        )

        return context, weights


class HybridDDoSModel(nn.Module):
    """
    Exact Hybrid CNN + BiLSTM + Attention architecture
    from Notebook 06.
    """

    def __init__(
        self,
        input_channels: int = 1,
        num_classes: int = 17
    ):
        super().__init__()

        # ----------------------------------------------------
        # CNN
        # ----------------------------------------------------

        self.cnn = nn.Sequential(

            nn.Conv1d(
                in_channels=input_channels,
                out_channels=64,
                kernel_size=3,
                padding=1
            ),

            nn.BatchNorm1d(64),

            nn.ReLU(),

            nn.MaxPool1d(
                kernel_size=2
            ),

            nn.Conv1d(
                in_channels=64,
                out_channels=128,
                kernel_size=3,
                padding=1
            ),

            nn.BatchNorm1d(128),

            nn.ReLU()
        )

        # ----------------------------------------------------
        # Bi-LSTM
        # ----------------------------------------------------

        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=128,
            num_layers=1,
            batch_first=True,
            bidirectional=True
        )

        # ----------------------------------------------------
        # Attention
        # ----------------------------------------------------

        self.attention = Attention(
            hidden_size=128
        )

        # ----------------------------------------------------
        # Classifier
        # ----------------------------------------------------

        self.classifier = nn.Sequential(

            nn.Dropout(0.3),

            nn.Linear(
                256,
                64
            ),

            nn.ReLU(),

            nn.Dropout(0.2),

            nn.Linear(
                64,
                num_classes
            )
        )

    def forward(self, x):

        # CNN
        x = self.cnn(x)

        # (batch, channels, sequence)
        # ->
        # (batch, sequence, channels)
        x = x.permute(
            0,
            2,
            1
        )

        # Bi-LSTM
        lstm_output, _ = self.lstm(x)

        # Attention
        context, _ = self.attention(
            lstm_output
        )

        # Classifier
        output = self.classifier(
            context
        )

        return output


# ============================================================
# FEATURE ENGINEERING
# ============================================================

def calculate_renyi_entropy(
    values,
    alpha: float = RENYI_ALPHA
) -> float:
    """
    Calculate Rényi entropy exactly as Notebook 04.

    Notebook 04:
        - removes non-finite values
        - 20-bin histogram
        - converts histogram to probabilities
        - removes zero-probability bins
        - alpha = 2
    """

    values = np.asarray(
        values,
        dtype=np.float64
    )

    values = values[
        np.isfinite(values)
    ]

    if len(values) == 0:
        return 0.0

    hist, _ = np.histogram(
        values,
        bins=RENYI_BINS
    )

    hist_sum = np.sum(hist)

    if hist_sum == 0:
        return 0.0

    prob = hist / hist_sum

    prob = prob[
        prob > 0
    ]

    if len(prob) == 0:
        return 0.0

    if alpha == 1:
        return float(
            -np.sum(
                prob * np.log2(prob)
            )
        )

    entropy = (
        1.0 / (1.0 - alpha)
    ) * np.log2(
        np.sum(
            prob ** alpha
        )
    )

    return float(entropy)


def extract_statistics(
    window: pd.DataFrame
) -> Dict[str, float]:
    """
    Convert one 100-flow window into the exact 48
    statistical features used by Notebook 04.

    For every one of the 8 base features:

        Mean
        Std
        Variance
        Min
        Max
        Renyi

    8 x 6 = 48 features.
    """

    feature_vector = {}

    for feature in STAT_FEATURES:

        values = window[
            feature
        ].to_numpy(
            dtype=np.float64
        )

        feature_vector[
            f"{feature}_Mean"
        ] = float(
            np.mean(values)
        )

        feature_vector[
            f"{feature}_Std"
        ] = float(
            np.std(values)
        )

        feature_vector[
            f"{feature}_Variance"
        ] = float(
            np.var(values)
        )

        feature_vector[
            f"{feature}_Min"
        ] = float(
            np.min(values)
        )

        feature_vector[
            f"{feature}_Max"
        ] = float(
            np.max(values)
        )

        feature_vector[
            f"{feature}_Renyi"
        ] = calculate_renyi_entropy(
            values,
            alpha=RENYI_ALPHA
        )

    return feature_vector


def create_feature_columns():
    """
    Return the 48 engineered feature names in the same
    order generated by Notebook 04.
    """

    columns = []

    for feature in STAT_FEATURES:

        columns.append(
            f"{feature}_Mean"
        )

        columns.append(
            f"{feature}_Std"
        )

        columns.append(
            f"{feature}_Variance"
        )

        columns.append(
            f"{feature}_Min"
        )

        columns.append(
            f"{feature}_Max"
        )

        columns.append(
            f"{feature}_Renyi"
        )

    return columns


FEATURE_COLUMNS = create_feature_columns()


# ============================================================
# INFERENCE ADAPTER
# ============================================================

class InferenceAdapter:
    """
    Frozen-model inference adapter.

    Loads:
        hybrid_model.pth
        scaler.pkl
        label_encoder.pkl

    and performs prediction on a 100-flow window.
    """

    def __init__(
        self,
        model_path: Path = MODEL_PATH,
        scaler_path: Path = SCALER_PATH,
        label_encoder_path: Path = LABEL_ENCODER_PATH
    ):

        self.model_path = Path(
            model_path
        )

        self.scaler_path = Path(
            scaler_path
        )

        self.label_encoder_path = Path(
            label_encoder_path
        )

        self.device = torch.device(
            "cpu"
        )

        self._validate_artifacts()

        # ----------------------------------------------------
        # Load scaler
        # ----------------------------------------------------

        self.scaler = joblib.load(
            self.scaler_path
        )

        # ----------------------------------------------------
        # Load label encoder
        # ----------------------------------------------------

        self.label_encoder = joblib.load(
            self.label_encoder_path
        )

        # ----------------------------------------------------
        # Load model
        # ----------------------------------------------------

        self.model = HybridDDoSModel(
            input_channels=1,
            num_classes=17
        )

        checkpoint = torch.load(
            self.model_path,
            map_location=self.device,
            weights_only=True
        )

        if (
            isinstance(checkpoint, dict)
            and "model_state_dict" in checkpoint
        ):
            state_dict = checkpoint[
                "model_state_dict"
            ]
        else:
            state_dict = checkpoint

        self.model.load_state_dict(
            state_dict
        )

        self.model = self.model.to(
            self.device
        )

        self.model.eval()

        # ----------------------------------------------------
        # Validate scaler dimensionality
        # ----------------------------------------------------

        if not hasattr(
            self.scaler,
            "n_features_in_"
        ):
            raise ValueError(
                "Loaded scaler does not expose "
                "n_features_in_."
            )

        if self.scaler.n_features_in_ != 48:
            raise ValueError(
                "Scaler expects "
                f"{self.scaler.n_features_in_} "
                "features, but the existing "
                "pipeline requires 48."
            )

        if len(FEATURE_COLUMNS) != 48:
            raise RuntimeError(
                "Internal feature list does not contain "
                "exactly 48 features."
            )

        if len(self.label_encoder.classes_) != 17:
            raise ValueError(
                "Label encoder does not contain "
                "the expected 17 classes."
            )

    # --------------------------------------------------------
    # ARTIFACT VALIDATION
    # --------------------------------------------------------

    def _validate_artifacts(self):

        missing = []

        for path in [
            self.model_path,
            self.scaler_path,
            self.label_encoder_path
        ]:

            if not path.exists():
                missing.append(
                    str(path)
                )

        if missing:

            message = (
                "Missing required ML artifacts:\n"
                + "\n".join(
                    f"  - {path}"
                    for path in missing
                )
            )

            raise FileNotFoundError(
                message
            )

    # --------------------------------------------------------
    # FLOW WINDOW -> 48 FEATURES
    # --------------------------------------------------------

    def window_to_features(
        self,
        flow_window: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Convert exactly one 100-flow window into
        a single-row 48-feature DataFrame.
        """

        if not isinstance(
            flow_window,
            pd.DataFrame
        ):
            raise TypeError(
                "flow_window must be a pandas DataFrame."
            )

        if len(flow_window) != WINDOW_SIZE:
            raise ValueError(
                f"Expected exactly {WINDOW_SIZE} "
                f"flows, received {len(flow_window)}."
            )

        missing = [
            column
            for column in STAT_FEATURES
            if column not in flow_window.columns
        ]

        if missing:

            raise ValueError(
                "Missing required flow features:\n"
                + "\n".join(
                    f"  - {column}"
                    for column in missing
                )
            )

        feature_vector = extract_statistics(
            flow_window
        )

        return pd.DataFrame(
            [
                feature_vector
            ],
            columns=FEATURE_COLUMNS
        )

    # --------------------------------------------------------
    # 48 FEATURES -> MODEL
    # --------------------------------------------------------

    def predict_from_engineered_features(
        self,
        engineered_features: pd.DataFrame,
        diagnostic_base_features: Optional[pd.DataFrame] = None,
    ) -> Dict[str, Any]:
        """
        Run the frozen model on one or more rows of
        already-engineered 48-feature data.
        """

        if not isinstance(
            engineered_features,
            pd.DataFrame
        ):
            raise TypeError(
                "engineered_features must be a pandas DataFrame."
            )

        missing = [
            column
            for column in FEATURE_COLUMNS
            if column not in engineered_features.columns
        ]

        if missing:

            raise ValueError(
                "Missing engineered features:\n"
                + "\n".join(
                    f"  - {column}"
                    for column in missing
                )
            )

        # IMPORTANT:
        # Reorder columns explicitly.
        #
        # This prevents a DataFrame with the correct
        # columns but incorrect order from silently
        # producing wrong predictions.

        X = engineered_features[
            FEATURE_COLUMNS
        ].to_numpy(
            dtype=np.float64
        )

        # Ensure finite input.
        if not np.isfinite(X).all():

            raise ValueError(
                "Engineered feature matrix contains "
                "NaN or infinite values."
            )

        # ----------------------------------------------------
        # Existing StandardScaler
        # ----------------------------------------------------

        X_scaled = self.scaler.transform(
            X
        )

        # ----------------------------------------------------
        # Model expects:
        #
        # (batch, 1, 48)
        # ----------------------------------------------------

        X_tensor = torch.tensor(
            X_scaled,
            dtype=torch.float32,
            device=self.device
        ).unsqueeze(1)

        if X_tensor.shape[2] != 48:

            raise RuntimeError(
                "Model input does not have 48 features. "
                f"Received shape: {tuple(X_tensor.shape)}"
            )

        # ----------------------------------------------------
        # Inference
        # ----------------------------------------------------

        with torch.no_grad():

            logits = self.model(
                X_tensor
            )

            probabilities = torch.softmax(
                logits,
                dim=1
            )

            confidence, predicted_indices = (
                torch.max(
                    probabilities,
                    dim=1
                )
            )

        predicted_indices = (
            predicted_indices
            .cpu()
            .numpy()
        )

        confidence = (
            confidence
            .cpu()
            .numpy()
        )

        probabilities = (
            probabilities
            .cpu()
            .numpy()
        )

        predicted_labels = (
            self.label_encoder.inverse_transform(
                predicted_indices
            )
        )

        results = []

        for i in range(
            len(predicted_labels)
        ):

            results.append({

                "predicted_class":
                    str(
                        predicted_labels[i]
                    ),

                "predicted_index":
                    int(
                        predicted_indices[i]
                    ),

                "confidence":
                    float(
                        confidence[i]
                    ),

                "confidence_uncertainty":
                    float(
                        1.0 - confidence[i]
                    ),

                "probabilities":
                    probabilities[i].tolist()
            })

        if (
            os.getenv("STEALTHGUARD_CAPTURE_INFERENCE_DIAGNOSTICS")
            == "1"
            and diagnostic_base_features is not None
        ):
            timestamp = datetime.now(timezone.utc)
            output_dir = PROJECT_ROOT / "diagnostics" / "live_inference"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / (
                f"inference_{timestamp.strftime('%Y%m%dT%H%M%S_%fZ')}.json"
            )

            class_labels = [
                str(label)
                for label in self.label_encoder.classes_
            ]
            diagnostic = {
                "captured_at": timestamp.isoformat(),
                "base_flow_features": {
                    "columns": list(diagnostic_base_features.columns),
                    "rows": diagnostic_base_features.to_numpy().tolist(),
                },
                "engineered_features": {
                    "columns": list(FEATURE_COLUMNS),
                    "rows": engineered_features[
                        FEATURE_COLUMNS
                    ].to_numpy().tolist(),
                },
                "scaled_features": {
                    "columns": list(FEATURE_COLUMNS),
                    "rows": X_scaled.tolist(),
                },
                "class_probabilities": [
                    {
                        label: float(probability)
                        for label, probability in zip(
                            class_labels,
                            probability_row,
                        )
                    }
                    for probability_row in probabilities
                ],
                "predictions": [
                    {
                        "predicted_label": result["predicted_class"],
                        "confidence": result["confidence"],
                    }
                    for result in results
                ],
            }

            with output_path.open("w", encoding="utf-8") as diagnostic_file:
                json.dump(
                    diagnostic,
                    diagnostic_file,
                    indent=2,
                    allow_nan=False,
                )

            print(f"Inference diagnostics saved to: {output_path}")

        return {
            "results": results,
            "input_shape": list(
                X_tensor.shape
            )
        }

    # --------------------------------------------------------
    # FLOW WINDOW -> PREDICTION
    # --------------------------------------------------------

    def predict_window(
        self,
        flow_window: pd.DataFrame
    ) -> Dict[str, Any]:
        """
        Complete Checkpoint-1 inference:

            100 flow records
                ↓
            48 statistical features
                ↓
            saved scaler
                ↓
            frozen model
                ↓
            label encoder
        """

        engineered = (
            self.window_to_features(
                flow_window
            )
        )

        return self.predict_from_engineered_features(
            engineered
        )


# ============================================================
# BASIC SELF TEST
# ============================================================

def run_artifact_test():

    print("=" * 70)
    print("STEALTHGUARD CHECKPOINT 1")
    print("Frozen ML Artifact Test")
    print("=" * 70)

    print()
    print("Project root:")
    print(PROJECT_ROOT)

    print()
    print("Model:")
    print(MODEL_PATH)

    print()
    print("Scaler:")
    print(SCALER_PATH)

    print()
    print("Label encoder:")
    print(LABEL_ENCODER_PATH)

    print()
    print("Feature count:")
    print(len(FEATURE_COLUMNS))

    print()
    print("Expected model input:")
    print("(batch, 1, 48)")

    adapter = InferenceAdapter()

    print()
    print("Artifacts loaded successfully.")

    print()
    print("Model:")
    print(
        type(adapter.model).__name__
    )

    print()
    print("Scaler features:")
    print(
        adapter.scaler.n_features_in_
    )

    print()
    print("Classes:")
    print(
        list(
            adapter.label_encoder.classes_
        )
    )

    print()
    print("=" * 70)
    print("CHECKPOINT 1 ARTIFACT TEST PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_artifact_test()