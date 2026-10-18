"""
StealthGuard - Checkpoint 1B
Inference Adapter Smoke Test

Creates one valid 100-flow window using the exact 8 base features,
runs the complete:

100 flows
-> 48 statistical features
-> scaler
-> Hybrid CNN + BiLSTM + Attention
-> predicted class

This is only a pipeline smoke test.
"""

import numpy as np
import pandas as pd

from inference_adapter import (
    InferenceAdapter,
    STAT_FEATURES,
    WINDOW_SIZE,
)


def main():
    print("=" * 70)
    print("STEALTHGUARD CHECKPOINT 1B")
    print("Inference Pipeline Smoke Test")
    print("=" * 70)

    # ---------------------------------------------------------
    # Create a structurally valid 100-flow window.
    # ---------------------------------------------------------
    rng = np.random.default_rng(42)

    flow_window = pd.DataFrame({
        "Flow Duration": rng.uniform(1000, 100000, WINDOW_SIZE),
        "Flow Bytes/s": rng.uniform(1000, 1000000, WINDOW_SIZE),
        "Flow Packets/s": rng.uniform(1, 10000, WINDOW_SIZE),
        "Packet Length Mean": rng.uniform(40, 1500, WINDOW_SIZE),
        "Packet Length Std": rng.uniform(1, 500, WINDOW_SIZE),
        "Total Fwd Packets": rng.integers(1, 1000, WINDOW_SIZE),
        "Total Backward Packets": rng.integers(1, 1000, WINDOW_SIZE),
        "Average Packet Size": rng.uniform(40, 1500, WINDOW_SIZE),
    })

    print()
    print("Flow window shape:")
    print(flow_window.shape)

    print()
    print("Required base features:")
    print(STAT_FEATURES)

    # ---------------------------------------------------------
    # Load frozen artifacts.
    # ---------------------------------------------------------
    adapter = InferenceAdapter()

    # ---------------------------------------------------------
    # Generate 48 engineered features.
    # ---------------------------------------------------------
    engineered = adapter.window_to_features(flow_window)

    print()
    print("Engineered feature shape:")
    print(engineered.shape)

    print()
    print("Engineered feature count:")
    print(len(engineered.columns))

    # ---------------------------------------------------------
    # Run model inference.
    # ---------------------------------------------------------
    result = adapter.predict_from_engineered_features(engineered)

    prediction = result["results"][0]

    print()
    print("Model input shape:")
    print(result["input_shape"])

    print()
    print("Predicted class:")
    print(prediction["predicted_class"])

    print()
    print("Predicted index:")
    print(prediction["predicted_index"])

    print()
    print("Confidence:")
    print(f'{prediction["confidence"]:.6f}')

    print()
    print("Confidence uncertainty:")
    print(f'{prediction["confidence_uncertainty"]:.6f}')

    print()
    print("=" * 70)
    print("CHECKPOINT 1B PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()