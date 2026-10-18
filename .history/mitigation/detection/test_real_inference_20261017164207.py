import sys
from pathlib import Path

import pandas as pd
import torch

# Make project root importable
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mitigation.detection.inference_adapter import InferenceAdapter


DATASET = ROOT / "dataset" / "engineered" / "engineered_dataset.csv"


def main():

    print("=" * 70)
    print("REAL ENGINEERED-DATASET INFERENCE TEST")
    print("=" * 70)

    # Read only one real engineered sample.
    df = pd.read_csv(DATASET, nrows=1)

    print("Dataset sample shape:", df.shape)
    print("Total columns:", len(df.columns))

    if "Label" not in df.columns:
        raise RuntimeError("Label column not found")

    feature_df = df.drop(columns=["Label"])

    print("Feature count:", len(feature_df.columns))
    print("True label:", df["Label"].iloc[0])

    if len(feature_df.columns) != 48:
        raise RuntimeError(
            f"Expected 48 features, got {len(feature_df.columns)}"
        )

    adapter = InferenceAdapter()

    # Run exactly the existing engineered feature vector
    # through the saved scaler + saved hybrid model.
        result = adapter.predict_from_engineered_features(feature_df)

    prediction = result["results"][0]

    print("\nMODEL RESULT")
    print("-" * 70)
    print("True label              :", df["Label"].iloc[0])
    print("Predicted class         :", prediction["predicted_class"])
    print("Predicted index         :", prediction["predicted_index"])
    print("Confidence              :", prediction["confidence"])
    print("Confidence uncertainty  :", prediction["confidence_uncertainty"])
    print("Model input shape       :", result["input_shape"])

    print("\nCHECKPOINT 6 REAL INFERENCE PASSED")


if __name__ == "__main__":
    main()