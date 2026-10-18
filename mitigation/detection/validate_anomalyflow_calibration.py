import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

RESULTS_PATH = "mitigation/anomalyflow_test_results.csv"

print("=" * 70)
print("VALIDATING ANOMALYFLOW TEST REPRODUCTION")
print("=" * 70)

df = pd.read_csv(RESULTS_PATH)

print("\nRows:", len(df))
print("Columns:", len(df.columns))

# ------------------------------------------------------------
# Notebook 06 exact test-set normalization
# ------------------------------------------------------------

confidence_values = df["Confidence_Uncertainty"].values.reshape(-1, 1)
renyi_values = df["Renyi_Evidence"].values.reshape(-1, 1)

# Notebook 06 fits MinMaxScaler directly on TEST values
confidence_scaler = MinMaxScaler()
renyi_scaler = MinMaxScaler()

confidence_normalized = (
    confidence_scaler.fit_transform(confidence_values)
    .flatten()
)

renyi_normalized = (
    renyi_scaler.fit_transform(renyi_values)
    .flatten()
)

# ------------------------------------------------------------
# Exact AnomalyFlow score
# ------------------------------------------------------------

score = (
    0.5 * confidence_normalized
    + 0.5 * renyi_normalized
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

print("\nTEST-SET NORMALIZATION")
print("Confidence min:", confidence_scaler.data_min_[0])
print("Confidence max:", confidence_scaler.data_max_[0])
print("Rényi min    :", renyi_scaler.data_min_[0])
print("Rényi max    :", renyi_scaler.data_max_[0])

print("\nMAX DIFFERENCES")
print("Confidence normalized:", confidence_diff.max())
print("Rényi normalized      :", renyi_diff.max())
print("AnomalyFlow score     :", score_diff.max())

# ------------------------------------------------------------
# Decision states
# ------------------------------------------------------------

def decision_state(value):
    if value < 0.25:
        return "NORMAL"
    elif value < 0.40:
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

if (
    confidence_diff.max() < 1e-10
    and renyi_diff.max() < 1e-10
    and score_diff.max() < 1e-10
    and state_matches == len(df)
):
    print(
        "\nCHECKPOINT 8 ANOMALYFLOW TEST "
        "REPRODUCTION PASSED"
    )
else:
    print("\nCHECKPOINT 8 FAILED")