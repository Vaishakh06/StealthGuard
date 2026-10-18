import os
import json
import pickle
import numpy as np
import pandas as pd
import torch

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler

from inference_adapter import InferenceAdapter


DATASET_PATH = "dataset/engineered/engineered_dataset.pkl"
OUTPUT_PATH = "models/evaluation/anomalyflow_calibration.json"

STAT_RENYI_COLUMNS = [
    "Flow Duration_Renyi",
    "Flow Bytes/s_Renyi",
    "Flow Packets/s_Renyi",
    "Packet Length Mean_Renyi",
    "Packet Length Std_Renyi",
    "Total Fwd Packets_Renyi",
    "Total Backward Packets_Renyi",
    "Average Packet Size_Renyi",
]

print("=" * 70)
print("RECONSTRUCTING ANOMALYFLOW VALIDATION CALIBRATION")
print("=" * 70)

# ------------------------------------------------------------
# 1. Load engineered dataset
# ------------------------------------------------------------
print("\nLoading dataset...")
df = pd.read_pickle(DATASET_PATH)

feature_columns = [c for c in df.columns if c != "Label"]

X = df[feature_columns].values
y = df["Label"].values

print("Dataset shape:", X.shape)
print("Feature count:", len(feature_columns))

# ------------------------------------------------------------
# 2. Reproduce Notebook 06 exact split
# ------------------------------------------------------------
X_train, X_temp, y_train, y_temp = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

X_val, X_test, y_val, y_test = train_test_split(
    X_temp,
    y_temp,
    test_size=0.50,
    random_state=42,
    stratify=y_temp
)

print("Training:", X_train.shape)
print("Validation:", X_val.shape)
print("Test:", X_test.shape)

# ------------------------------------------------------------
# 3. Load frozen model/scaler/encoder
# ------------------------------------------------------------
adapter = InferenceAdapter()

# ------------------------------------------------------------
# 4. Generate validation model predictions
# ------------------------------------------------------------
print("\nGenerating validation predictions...")

X_val_scaled = adapter.scaler.transform(X_val)

X_val_tensor = torch.tensor(
    X_val_scaled,
    dtype=torch.float32
).unsqueeze(1)

model = adapter.model
model.eval()

all_probabilities = []

batch_size = 512

with torch.no_grad():
    for start in range(0, len(X_val_tensor), batch_size):
        batch = X_val_tensor[start:start + batch_size]
        logits = model(batch)
        probabilities = torch.softmax(logits, dim=1)
        all_probabilities.append(probabilities.cpu().numpy())

all_probabilities = np.concatenate(all_probabilities, axis=0)

confidence_uncertainty = 1.0 - np.max(
    all_probabilities,
    axis=1
)

print("Validation predictions generated.")
print("Prediction shape:", all_probabilities.shape)

# ------------------------------------------------------------
# 5. Reconstruct validation Rényi evidence
# ------------------------------------------------------------
print("\nReconstructing Rényi evidence...")

renyi_indices = [
    feature_columns.index(col)
    for col in STAT_RENYI_COLUMNS
]

X_val_renyi = X_val[:, renyi_indices]

val_renyi_scaler = StandardScaler()

val_renyi_standardized = (
    val_renyi_scaler.fit_transform(X_val_renyi)
)

val_renyi_evidence = np.mean(
    np.abs(val_renyi_standardized),
    axis=1
)

print("Rényi evidence generated.")
print("Shape:", val_renyi_evidence.shape)

# ------------------------------------------------------------
# 6. Reconstruct exact validation MinMax scalers
# ------------------------------------------------------------
val_confidence_scaler = MinMaxScaler()
val_confidence_scaler.fit(
    confidence_uncertainty.reshape(-1, 1)
)

val_renyi_scaler_final = MinMaxScaler()
val_renyi_scaler_final.fit(
    val_renyi_evidence.reshape(-1, 1)
)

# ------------------------------------------------------------
# 7. Save calibration parameters
# ------------------------------------------------------------
calibration = {
    "source": "Notebook 06 exact validation reconstruction",
    "split": {
        "first_test_size": 0.20,
        "first_random_state": 42,
        "second_test_size": 0.50,
        "second_random_state": 42,
        "stratified": True,
    },
    "renyi_columns": STAT_RENYI_COLUMNS,
    "renyi_standard_scaler": {
        "mean": val_renyi_scaler.mean_.tolist(),
        "scale": val_renyi_scaler.scale_.tolist(),
    },
    "confidence_minmax_scaler": {
        "min": val_confidence_scaler.data_min_.tolist(),
        "max": val_confidence_scaler.data_max_.tolist(),
        "scale": val_confidence_scaler.scale_.tolist(),
        "min_offset": val_confidence_scaler.min_.tolist(),
    },
    "renyi_evidence_minmax_scaler": {
        "min": val_renyi_scaler_final.data_min_.tolist(),
        "max": val_renyi_scaler_final.data_max_.tolist(),
        "scale": val_renyi_scaler_final.scale_.tolist(),
        "min_offset": val_renyi_scaler_final.min_.tolist(),
    },
    "thresholds": {
        "low": 0.25,
        "high": 0.40,
    },
    "weights": {
        "confidence": 0.5,
        "renyi": 0.5,
    },
}

os.makedirs(
    os.path.dirname(OUTPUT_PATH),
    exist_ok=True
)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(calibration, f, indent=2)

print("\nCalibration saved to:")
print(OUTPUT_PATH)

print("\nCHECKPOINT 7 CALIBRATION RECONSTRUCTION PASSED")