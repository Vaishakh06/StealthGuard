import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler


RESULTS_PATH = "mitigation/anomalyflow_test_results.csv"
CALIBRATION_PATH = "models/evaluation/anomalyflow_calibration.json"

print("=" * 70)
print("VALIDATING ANOMALYFLOW CALIBRATION")
print("=" * 70)

# ------------------------------------------------------------
# Load files
# ------------------------------------------------------------
with open(CALIBRATION_PATH, "r", encoding="utf-8") as f:
    calibration = json.load(f)

df = pd.read_csv(RESULTS_PATH)

print("\nRows:", len(df))
print("Columns:", len(df.columns))

# ------------------------------------------------------------
# Reconstruct validation MinMax scalers
# ------------------------------------------------------------
confidence_scaler = MinMaxScaler()

confidence_scaler.data_min_ = np.array(
    calibration["confidence_minmax_scaler"]["min"],
    dtype=float
)
confidence_scaler.data_max_ = np.array(
    calibration["confidence_minmax_scaler"]["max"],
    dtype=float
)
confidence_scaler.data_range_ = (
    confidence_scaler.data_max_
    - confidence_scaler.data_min_
)
confidence_scaler.scale_ = np.array(
    calibration["confidence_minmax_scaler"]["scale"],
    dtype=float
)
confidence_scaler.min_ = np.array(
    calibration["confidence_minmax_scaler"]["min_offset"],
    dtype=float
)
confidence_scaler.n_features_in_ = 1


renyi_scaler = MinMaxScaler()

renyi_scaler.data_min_ = np.array(
    calibration["renyi_evidence_minmax_scaler"]["min"],
    dtype=float
)
renyi_scaler.data_max_ = np.array(
    calibration["renyi_evidence_minmax_scaler"]["max"],
    dtype=float
)
renyi_scaler.data_range_ = (
    renyi_scaler.data_max_
    - renyi_scaler.data_min_
)
renyi_scaler.scale_ = np.array(
    calibration["renyi_evidence_minmax_scaler"]["scale"],
    dtype=float
)
renyi_scaler.min_ = np.array(
    calibration["renyi_evidence_minmax_scaler"]["min_offset"],
    dtype=float
)
renyi_scaler.n_features_in_ = 1

# ------------------------------------------------------------
# Raw values produced by Notebook 06
# ------------------------------------------------------------
confidence_uncertainty = df[
    "Confidence_Uncertainty"
].values

renyi_evidence = df[
    "Renyi_Evidence"
].values

# ------------------------------------------------------------
# Recalculate normalized values
# ------------------------------------------------------------
confidence_normalized = confidence_scaler.transform(
    confidence_uncertainty.reshape(-1, 1)
).flatten()

renyi_normalized = renyi_scaler.transform(
    renyi_evidence.reshape(-1, 1)
).flatten()

# ------------------------------------------------------------
# Recalculate AnomalyFlow
# ------------------------------------------------------------
score = (
    0.5 * confidence_normalized
    + 0.5 * renyi_normalized
)

# ------------------------------------------------------------
# Compare against Notebook 06
# ------------------------------------------------------------
expected_confidence = df[
    "Confidence_Normalized"
].values

expected_renyi = df[
    "Renyi_Normalized"
].values

expected_score = df[
    "AnomalyFlow_Score"
].values

confidence_diff = np.abs(
    confidence_normalized - expected_confidence
)

renyi_diff = np.abs(
    renyi_normalized - expected_renyi
)

score_diff = np.abs(
    score - expected_score
)

print("\nMAX DIFFERENCES")
print(
    "Confidence normalized:",
    confidence_diff.max()
)
print(
    "Rényi normalized      :",
    renyi_diff.max()
)
print(
    "AnomalyFlow score     :",
    score_diff.max()
)

# ------------------------------------------------------------
# Decision state
# ------------------------------------------------------------
def decision_state(value):
    if value < 0.25:
        return "NORMAL"
    elif value < 0.40:
        return "SUSPICIOUS"
    return "HIGH_EVIDENCE"


predicted_states = np.array([
    decision_state(x)
    for x in score
])

expected_states = df[
    "Decision_State"
].values

state_matches = np.sum(
    predicted_states == expected_states
)

print("\nDECISION STATE MATCH")
print(
    f"{state_matches}/{len(df)} "
    f"({state_matches / len(df) * 100:.4f}%)"
)

# ------------------------------------------------------------
# Checkpoint
# ------------------------------------------------------------
if (
    confidence_diff.max() < 1e-5
    and renyi_diff.max() < 1e-5
    and score_diff.max() < 1e-5
    and state_matches == len(df)
):
    print(
        "\nCHECKPOINT 8 ANOMALYFLOW "
        "CALIBRATION VALIDATION PASSED"
    )
else:
    print(
        "\nCHECKPOINT 8 FAILED"
    )