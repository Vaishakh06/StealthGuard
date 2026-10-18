import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

RESULTS_PATH = "mitigation/anomalyflow_test_results.csv"
CALIBRATION_PATH = "models/evaluation/anomalyflow_calibration.json"

print("=" * 70)
print("VALIDATING ANOMALYFLOW TEST REPRODUCTION")
print("=" * 70)

df = pd.read_csv(RESULTS_PATH)

print("\nRows:", len(df))
print("Columns:", len(df.columns))

# ------------------------------------------------------------
# Notebook 06 exact validation-calibrated normalization
# ------------------------------------------------------------

with open(CALIBRATION_PATH, "r", encoding="utf-8") as f:
    calibration = json.load(f)

conf_calib = calibration["confidence_minmax_scaler"]
renyi_calib = calibration["renyi_evidence_minmax_scaler"]

# Validation-fitted MinMaxScalers applied to test evidence (Notebook 06 Cell 53)
confidence_scaler = MinMaxScaler()
confidence_scaler.data_min_ = np.array(conf_calib["min"], dtype=np.float64)
confidence_scaler.data_max_ = np.array(conf_calib["max"], dtype=np.float64)
confidence_scaler.data_range_ = confidence_scaler.data_max_ - confidence_scaler.data_min_
confidence_scaler.scale_ = np.array(conf_calib["scale"], dtype=np.float64)
confidence_scaler.min_ = np.array(conf_calib["min_offset"], dtype=np.float64)
confidence_scaler.n_features_in_ = 1
confidence_scaler.n_samples_seen_ = 1

renyi_scaler = MinMaxScaler()
renyi_scaler.data_min_ = np.array(renyi_calib["min"], dtype=np.float64)
renyi_scaler.data_max_ = np.array(renyi_calib["max"], dtype=np.float64)
renyi_scaler.data_range_ = renyi_scaler.data_max_ - renyi_scaler.data_min_
renyi_scaler.scale_ = np.array(renyi_calib["scale"], dtype=np.float64)
renyi_scaler.min_ = np.array(renyi_calib["min_offset"], dtype=np.float64)
renyi_scaler.n_features_in_ = 1
renyi_scaler.n_samples_seen_ = 1

confidence_values = df["Confidence_Uncertainty"].values.reshape(-1, 1)
renyi_values = df["Renyi_Evidence"].values.reshape(-1, 1)

confidence_normalized = (
    confidence_scaler.transform(confidence_values)
    .flatten()
)

renyi_normalized = (
    renyi_scaler.transform(renyi_values)
    .flatten()
)

# ------------------------------------------------------------
# Exact AnomalyFlow score (Notebook 06 Cell 54)
# ------------------------------------------------------------

weights = calibration.get("weights", {"confidence": 0.5, "renyi": 0.5})
conf_weight = weights.get("confidence", 0.5)
renyi_weight = weights.get("renyi", 0.5)

score = (
    conf_weight * confidence_normalized
    + renyi_weight * renyi_normalized
)

# ------------------------------------------------------------
# Compare against frozen Notebook 06 output
# ------------------------------------------------------------

expected_confidence = df["Confidence_Normalized"].values
expected_renyi = df["Renyi_Normalized"].values
expected_score = df["AnomalyFlow_Score"].values

confidence_diff = np.abs(
    confidence_normalized - expected_confidence
)

renyi_diff = np.abs(
    renyi_normalized - expected_renyi
)

score_diff = np.abs(
    score - expected_score
)

print("\nVALIDATION-CALIBRATED NORMALIZATION")
print("Confidence min:", confidence_scaler.data_min_[0])
print("Confidence max:", confidence_scaler.data_max_[0])
print("Rényi min    :", renyi_scaler.data_min_[0])
print("Rényi max    :", renyi_scaler.data_max_[0])

print("\nMAX DIFFERENCES")
print("Confidence normalized:", confidence_diff.max())
print("Rényi normalized      :", renyi_diff.max())
print("AnomalyFlow score     :", score_diff.max())

# ------------------------------------------------------------
# Decision states (Notebook 06 Cell 49 / 55)
# ------------------------------------------------------------

thresholds = calibration.get("thresholds", {"low": 0.25, "high": 0.40})
low_threshold = thresholds.get("low", 0.25)
high_threshold = thresholds.get("high", 0.40)

def decision_state(value):
    if value < low_threshold:
        return "NORMAL"
    elif value < high_threshold:
        return "SUSPICIOUS"
    return "HIGH_EVIDENCE"

predicted_states = np.array([
    decision_state(x) for x in score
])

expected_states = df["Decision_State"].values

state_matches = np.sum(
    predicted_states == expected_states
)

print("\nDECISION STATE MATCH")
print(
    f"{state_matches}/{len(df)} "
    f"({state_matches / len(df) * 100:.4f}%)"
)

# ------------------------------------------------------------
# Final validation
# ------------------------------------------------------------

row_count_correct = (len(df) == 338445)
confidence_norm_correct = (confidence_diff.max() < 1e-4)
renyi_norm_correct = (renyi_diff.max() < 1e-4)
score_correct = (score_diff.max() < 1e-4)
decision_states_correct = (state_matches == len(df))

if (
    row_count_correct
    and confidence_norm_correct
    and renyi_norm_correct
    and score_correct
    and decision_states_correct
):
    print(
        "\nCHECKPOINT 8 ANOMALYFLOW TEST "
        "REPRODUCTION PASSED"
    )
else:
    print("\nCHECKPOINT 8 FAILED")