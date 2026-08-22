# AnomalyFlow
## A Hybrid Deep Learning and Statistical Framework for Stealthy Low-Rate DDoS Detection

---

# Project Objective

Develop a real-time DDoS detection framework that combines statistical traffic analysis with deep learning to detect stealthy low-rate DDoS attacks and provide intelligent mitigation.

---

# Final Architecture


Network Traffic
↓
Data Preprocessing
↓
Rényi Entropy / Statistical Feature Engineering
↓
Sliding Window
↓
CNN
↓
Bi-LSTM
↓
Attention
↓
Attack Classification
↓
AnomalyFlow Decision Layer
↓
Security Severity
↓
Mitigation Engine
↓
Alerts + Mitigation Decisions
↓
Dashboard


---

# Dataset

Dataset:
CIC-DDoS2019

Merged Dataset

Location:
dataset/processed/final_dataset.csv

Shape:

67,812,080 × 63

---

# Notebook Progress

## ✅ 01_EDA.ipynb

Completed

Tasks:
- Dataset exploration
- Missing value analysis
- Infinite value analysis
- Duplicate analysis
- Label distribution
- Correlation analysis

Status:
Completed

---

## ✅ 02_Preprocessing.ipynb

Completed

Tasks:
- Remove duplicates
- Handle missing values
- Handle infinite values
- Remove identifier columns
- Remove constant columns
- Merge all processed datasets

Output:

dataset/processed/final_dataset.csv

Shape:

67,812,080 × 63

Status:
Completed

---

## ✅ 03_Model_Preparation.ipynb

Completed

Tasks:
- Load merged dataset
- Label encoding
- Save label encoder
- Feature/target separation

Important Decision:

No train-test split performed.

Reason:

Sliding-window feature engineering must occur first.

Saved:

models/label_encoder.pkl

Status:
Completed

---

## ✅ 04_Statistical_Features.ipynb

Completed

Configuration

Chunk Size:
50000

Window Size:
100

Stride:
20

Rényi Alpha:
2

Statistical Features

- Flow Duration
- Flow Bytes/s
- Flow Packets/s
- Packet Length Mean
- Packet Length Std
- Total Fwd Packets
- Total Backward Packets
- Average Packet Size

Pipeline

Chunk Reader

↓

Sliding Window

↓

Statistical Features

↓

Rényi Entropy

↓

Majority Label

↓

Engineered Dataset

Output

dataset/engineered/engineered_dataset.csv

dataset/engineered/engineered_dataset.pkl

Final Dataset

Shape:

3,385,176 × 49

Quality Checks

Missing Values:
0

Duplicate Rows:
731
(Removed before final save)

Status:
Completed

---

# Notebook 05 — CNN + Bi-LSTM + Attention

## ✅ 05_CNN_BiLSTM_Attention.ipynb

Completed

Notebook 05 was implemented section-wise and cell-wise in Google Colab using a T4 GPU.

### Section 1 — Environment & Device Setup

Completed

Tasks:
- Google Colab environment setup
- T4 GPU verification
- PyTorch/device setup

---

### Section 2 — Dataset Loading

Completed

Tasks:
- Load engineered dataset
- Verify dataset shape
- Verify column names and data types
- Check missing values
- Check duplicate rows
- Inspect target classes

Loaded dataset:

3,384,445 × 49

---

### Section 3 — Data Preparation

Completed

Tasks:
- Prepare features and labels
- Confirm 17-class classification
- Perform 80/10/10 train-validation-test split

Final split:

Training:
2,707,556

Validation:
338,444

Test:
338,445

### Class Mapping

```text
0  → BENIGN
1  → DrDoS_DNS
2  → DrDoS_LDAP
3  → DrDoS_MSSQL
4  → DrDoS_NTP
5  → DrDoS_NetBIOS
6  → DrDoS_SNMP
7  → DrDoS_SSDP
8  → DrDoS_UDP
9  → LDAP
10 → MSSQL
11 → NetBIOS
12 → Portmap
13 → Syn
14 → TFTP
15 → UDP
16 → UDP-lag
```

---

### Section 4 — DataLoaders

Completed

Tasks:
- Tensor conversion
- Dataset preparation
- DataLoader creation
- Batch size: 512

---

### Section 5 — Hybrid Model

Completed

Actual model:

```text
Conv1D(1, 64, kernel_size=3)
        ↓
BatchNorm1D(64)
        ↓
ReLU
        ↓
MaxPool1D(kernel_size=2)
        ↓
Conv1D(64, 128, kernel_size=3)
        ↓
BatchNorm1D(128)
        ↓
ReLU
        ↓
Bi-LSTM(input_size=128, hidden_size=128, bidirectional=True)
        ↓
Attention(256 → 1)
        ↓
Dropout
        ↓
Linear(256 → 64)
        ↓
ReLU
        ↓
Dropout
        ↓
Linear(64 → 17)
```

Forward-pass verification:

Input:
`torch.Size([512, 1, 48])`

Output:
`torch.Size([512, 17])`

Status:
Completed

---

### Section 6 — Model Training

Completed

Training configuration:

- Maximum epochs: 30
- Batch size: 512
- Optimizer: AdamW
- Initial learning rate: 0.001
- Weight decay: 0.0001
- Gradient clipping: 1.0
- Early stopping patience: 5
- Scheduler: ReduceLROnPlateau
- Mixed precision: enabled on T4
- Loss: standard CrossEntropyLoss

Training stopped at:

Epoch 22

Best epoch:

17

Best validation loss:

0.2495

Best validation accuracy:

89.45%

Training accuracy at best epoch:

89.37%

Learning rate:

Initial: 0.001000
Final: 0.000250

Best model:

models/hybrid_model.pth

Training history:

models/training_history.json

Resume checkpoint:

models/training_checkpoint.pth

Status:
Completed

---

### Section 7 — Training Performance Analysis

Completed

Tasks:
- Load actual saved training history
- Generate training/validation loss curves
- Generate training/validation accuracy curves
- Analyze learning-rate behavior
- Identify best epoch
- Check for obvious overfitting

Best epoch:

17

Best epoch metrics:

Training Loss:
0.2532

Validation Loss:
0.2495

Training Accuracy:
89.37%

Validation Accuracy:
89.45%

Accuracy Gap:
-0.09%

An isolated validation anomaly occurred at Epoch 18:

Validation Loss:
14.4891

Validation Accuracy:
22.66%

The model recovered at Epoch 19. The best checkpoint from Epoch 17 remained preserved.

Status:
Completed

---

### Section 8 — Test Set Evaluation

Completed

The saved best model from validation was loaded before test evaluation.

Test samples:

338,445

Correct predictions:

302,665

Incorrect predictions:

35,780

Test accuracy:

89.43%

### Overall Metrics

Macro Precision:
84.92%

Macro Recall:
81.07%

Macro F1:
82.04%

Weighted F1:
89.28%

### Evaluation Outputs

- Classification report
- Confusion matrix
- Normalized confusion matrix
- Top confusion-pair analysis

### Strong Detection Classes

Examples:

- DrDoS_NTP: F1 = 99.85%
- DrDoS_DNS: F1 = 99.79%
- TFTP: F1 = 99.79%
- Syn: F1 = 98.68%
- DrDoS_SNMP: F1 = 97.36%
- BENIGN: F1 = 96.43%

### Main Weak Detection Areas

- Portmap
- DrDoS_SSDP
- DrDoS_UDP
- UDP
- DrDoS_MSSQL / MSSQL
- DrDoS_NetBIOS / NetBIOS

### Important Confusion Patterns

- MSSQL → DrDoS_MSSQL: 4,493
- DrDoS_MSSQL → MSSQL: 3,838
- DrDoS_SSDP → DrDoS_UDP: 4,152
- UDP → DrDoS_UDP: 3,701
- DrDoS_UDP → UDP: 3,649
- DrDoS_SSDP → UDP: 3,246
- DrDoS_NetBIOS → NetBIOS: 2,921
- NetBIOS → DrDoS_NetBIOS: 2,207
- DrDoS_UDP → DrDoS_SSDP: 1,820
- Portmap → DrDoS_NetBIOS: 524

Status:
Completed

---


## ✅ 06_AnomalyFlow_Decision_Security_Layer.ipynb

Completed

Notebook 06 adds the project-specific AnomalyFlow decision/security layer around the frozen CNN-BiLSTM-Attention baseline.

---

## Section 1 — Project Artifact Loading

Completed

Loaded and verified:

- Engineered dataset
- Label encoder
- Scaler
- Best baseline model
- Required project artifacts

---

## Section 2 — Engineered Dataset Verification

Completed

Engineered dataset:

3,384,445 × 49

Features:

48

Target:

Label

Quality:

- Missing values: 0
- Duplicate rows: 0
- Classes: 17

---

## Section 3 — Baseline Model Verification

Completed

The actual saved CNN-BiLSTM-Attention architecture was reconstructed and the saved model was successfully loaded.

The model structure used:

CNN
↓
Bi-LSTM
↓
Attention
↓
Classifier

---

## Section 4 — Baseline Prediction & Confidence Analysis

Completed

Test samples:

338,445

Correct predictions:

302,678

Baseline errors:

35,767

Test accuracy:

89.43%

### Confidence

Correct predictions:

- Mean confidence: 0.9243
- Median confidence: 1.0000

Incorrect predictions:

- Mean confidence: 0.6241
- Median confidence: 0.6003

Lower confidence was associated with baseline prediction errors.

### Rényi Evidence

Eight Rényi features were analyzed.

Correct predictions:

- Mean evidence: 0.7430
- Median evidence: 0.6680

Incorrect predictions:

- Mean evidence: 0.9655
- Median evidence: 1.0393

---

## Section 5 — AnomalyFlow Decision Score

Completed

AnomalyFlow combines:

Confidence Uncertainty
+
Rényi Statistical Evidence
↓
AnomalyFlow Score

Configuration:

Confidence Weight = 0.5
Rényi Weight      = 0.5

Validation-derived thresholds:

Score < 0.25
→ NORMAL

0.25 ≤ Score < 0.40
→ SUSPICIOUS

Score ≥ 0.40
→ HIGH_EVIDENCE

Validation error rates:

- NORMAL: 3.05%
- SUSPICIOUS: 32.71%
- HIGH_EVIDENCE: 49.44%

---

## Section 6 — Final AnomalyFlow Test Evaluation

Completed

The validation-derived configuration was frozen before final test evaluation.

No threshold tuning was performed on the final test set.

### Final Decision States

- NORMAL: 270,361 (79.88%)
- SUSPICIOUS: 37,300 (11.02%)
- HIGH_EVIDENCE: 30,784 (9.10%)

### Error Rate by State

- NORMAL: 3.05%
- SUSPICIOUS: 32.87%
- HIGH_EVIDENCE: 49.56%

### AnomalyFlow Error Detection

- Total baseline errors: 35,767
- Errors caught: 27,519
- Error Recall: 76.94%
- Correct predictions flagged: 40,565
- Correct Flag Rate: 13.40%

Important:

The 76.94% value is baseline-error recall, not DDoS detection recall.

---

## Section 7 — Security Severity & DDoS Interpretation

Completed

### Binary DDoS Interpretation

DDoS-related classes:

- DrDoS_DNS
- DrDoS_LDAP
- DrDoS_MSSQL
- DrDoS_NTP
- DrDoS_NetBIOS
- DrDoS_SNMP
- DrDoS_SSDP
- DrDoS_UDP
- MSSQL
- NetBIOS
- Portmap
- Syn
- TFTP
- UDP
- UDP-lag

Non-DDoS classes:

- BENIGN
- LDAP

### Binary DDoS Results

- Accuracy: 99.58%
- Precision: 99.73%
- Recall: 99.84%
- F1-score: 99.78%

Confusion Matrix:

[[8914, 899],
 [519, 328113]]

### DDoS Rate by AnomalyFlow State

Actual DDoS rate:

- NORMAL: 96.68%
- SUSPICIOUS: 97.89%
- HIGH_EVIDENCE: 99.86%

Higher AnomalyFlow evidence was associated with a higher DDoS concentration.

However, AnomalyFlow states are not treated as direct DDoS probabilities.

---

## Security Severity Mapping

Predicted Non-DDoS + NORMAL
→ NORMAL

Predicted Non-DDoS + SUSPICIOUS
→ MONITOR

Predicted Non-DDoS + HIGH_EVIDENCE
→ INVESTIGATE

Predicted DDoS + NORMAL
→ LOW

Predicted DDoS + SUSPICIOUS
→ MEDIUM

Predicted DDoS + HIGH_EVIDENCE
→ HIGH

### Final Security Severity Distribution

- HIGH: 30,736 (9.08%)
- MEDIUM: 36,607 (10.82%)
- LOW: 261,669 (77.32%)
- INVESTIGATE: 48 (0.01%)
- MONITOR: 693 (0.20%)
- NORMAL: 8,692 (2.57%)

Important:

LOW means predicted DDoS with low AnomalyFlow evidence. It does not mean safe traffic.

---

## Section 8 — Save AnomalyFlow Results

Completed

Saved artifacts:

evaluation/anomalyflow_config.json

evaluation/anomalyflow_final_summary.json

Saved configuration:

confidence_weight = 0.5
renyi_weight      = 0.5
low_threshold     = 0.25
high_threshold    = 0.40

Artifact verification:

Configuration exists: True
Final summary exists: True

Status:

Completed

---

# Current Project Status

## Completed

01_EDA.ipynb
02_Preprocessing.ipynb
03_Model_Preparation.ipynb
04_Statistical_Features.ipynb
05_CNN_BiLSTM_Attention.ipynb
06_AnomalyFlow_Decision_Security_Layer.ipynb

Current system:

Network Traffic
↓
Preprocessing
↓
Statistical Feature Engineering
↓
CNN + Bi-LSTM + Attention
↓
Attack Classification
↓
Confidence Uncertainty
+
Rényi Statistical Evidence
↓
AnomalyFlow Score
↓
NORMAL / SUSPICIOUS / HIGH_EVIDENCE
↓
Security Severity
↓
Mitigation Engine
↓
Dashboard

---

# Next Development Stage

## ✅ 07_Mitigation_Engine.ipynb

Completed

Notebook 07 implements the mitigation layer directly on the verified sample-level output generated by Notebook 06.

### Section 1 — Environment & Project Paths

Completed

Tasks:
- Configure project root
- Configure mitigation directories
- Verify Notebook 06 mitigation artifacts
- Confirm required input files are available

---

### Section 2 — Load Notebook 06 Artifact

Completed

Loaded:

mitigation/anomalyflow_test_results.csv

mitigation/mitigation_input_summary.json

Verified:

- Total samples: 338,445
- Notebook 06 sample-level decisions preserved
- Notebook 06 summary successfully loaded

---

### Section 3 — Verify Mitigation Inputs

Completed

Structural verification:

- Rows: 338,445
- Columns: 11
- Missing columns: 0
- Unexpected columns: 0
- Test_Index range: 0–338444
- Test_Index unique values: 338,445

Decision-state verification:

- NORMAL: 270,361
- SUSPICIOUS: 37,300
- HIGH_EVIDENCE: 30,784

Security-severity verification:

- LOW: 261,669
- MEDIUM: 36,607
- HIGH: 30,736
- NORMAL: 8,692
- MONITOR: 693
- INVESTIGATE: 48

All Notebook 06 mitigation inputs matched the verified source artifact.

---

### Section 4 — Mitigation Decision Engine

Completed

A severity-based mitigation policy was implemented.

### Mitigation Mapping

NORMAL
→ NO_ACTION

MONITOR
→ MONITOR

INVESTIGATE
→ INVESTIGATE

LOW
→ ALERT_AND_LOG

MEDIUM
→ RATE_LIMIT

HIGH
→ BLOCK_AND_RATE_LIMIT

### Reason

The mitigation layer converts the security severity produced by Notebook 06 into graduated and actionable security responses.

LOW severity is treated as predicted DDoS with low AnomalyFlow evidence. It is therefore logged and alerted rather than automatically blocked.

MEDIUM severity triggers simulated rate limiting.

HIGH severity triggers simulated blocking and rate limiting.

The mitigation policy covers all security severities produced by Notebook 06.

---

### Section 5 — Alert Generation

Completed

Sample-level security alerts were generated from the mitigation decisions.

Alert types:

- DDOS_DETECTED
- RATE_LIMIT_TRIGGERED
- BLOCK_TRIGGERED
- MONITORING
- INVESTIGATION
- NONE

Alert levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL
- NONE

Final alert distribution:

- Alerts generated: 329,753 (97.43%)
- No alert required: 8,692 (2.57%)

Important:

The 97.43% alert rate is not treated as a false-positive rate. It represents the number of samples receiving a security alert according to the mitigation policy.

---

### Section 6 — Mitigation Simulation

Completed

Mitigation actions were simulated at sample level.

Simulation flags:

- Simulated_Block
- Simulated_Rate_Limit
- Simulated_Monitoring
- Simulated_Investigation

Final simulation results:

- Simulated blocking: 30,736 (9.08%)
- Simulated rate limiting: 67,343 (19.90%)
- Simulated monitoring: 693 (0.20%)
- Investigations required: 48 (0.01%)

### Mitigation Outcomes

- ALERT_LOGGED: 261,669
- RATE_LIMIT_SIMULATED: 36,607
- BLOCK_AND_RATE_LIMIT_SIMULATED: 30,736
- NO_ACTION_REQUIRED: 8,692
- MONITORING_ACTIVE: 693
- INVESTIGATION_REQUIRED: 48

Important:

Notebook 07 implements and evaluates mitigation decisions using simulation. Actual network enforcement is reserved for the backend/deployment layer.

The HIGH mitigation decision represents traffic that should be blocked and rate-limited.

---

### Section 7 — Save Final Mitigation Outputs

Completed

Final sample-level mitigation output:

mitigation/final_mitigation_results.csv

Shape:

338,445 × 23

Final output contains:

- Notebook 06 detection and AnomalyFlow fields
- Security severity
- Mitigation action
- Mitigation priority
- Mitigation simulation description
- Alert status
- Alert level
- Alert type
- Alert message
- Simulated blocking
- Simulated rate limiting
- Simulated monitoring
- Simulated investigation
- Mitigation outcome

Final mitigation summary:

mitigation/final_mitigation_summary.json

The summary contains:

- Mitigation policy
- Alert policy
- Security-severity counts
- Mitigation-action counts
- Alert statistics
- Simulation statistics
- Final output schema

---

### Section 8 — Final Verification

Completed

Final CSV verification:

- File exists: True
- Rows: 338,445
- Columns: 23
- Missing required columns: 0
- Test_Index integrity: PASS
- Missing required values: 0

Final JSON verification:

- File exists: True
- Total samples: 338,445
- Output schema: verified

Final consistency verification:

- Security severity distribution: PASS
- Mitigation action distribution: PASS
- Simulated blocking count: PASS
- Simulated rate-limiting count: PASS
- Alert count: PASS
- Mitigation outcome distribution: PASS

Overall final verification:

PASS

Status:
Completed


---

# Future Development

## ⬜ 08_Dashboard.ipynb

Planned:

- Streamlit dashboard
- Live prediction interface
- Attack visualization
- Severity visualization
- Security alerts
- Mitigation status
- Traffic statistics

The dashboard should consume the validated outputs and demonstrate the complete AnomalyFlow detection-to-mitigation workflow.

Status:
Not Started


---

# Current Model & System State

### Frozen Baseline Model

Hybrid CNN-BiLSTM-Attention

Best model:

models/hybrid_model.pth

### Frozen AnomalyFlow Configuration

Confidence weight:
0.5

Rényi weight:
0.5

Low threshold:
0.25

High threshold:
0.40


---

# Key Project Artifacts

The main artifacts generated so far include:

dataset/processed/final_dataset.csv

dataset/engineered/engineered_dataset.csv

dataset/engineered/engineered_dataset.pkl

models/label_encoder.pkl

models/scaler.pkl

models/hybrid_model.pth

models/training_history.json

models/training_checkpoint.pth

models/evaluation/classification_report.json

models/evaluation/confusion_matrix.npy

models/evaluation/normalized_confusion_matrix.npy

models/evaluation/evaluation_summary.json

evaluation/anomalyflow_config.json

evaluation/anomalyflow_final_summary.json

mitigation/anomalyflow_test_results.csv

mitigation/mitigation_input_summary.json

mitigation/final_mitigation_results.csv

mitigation/final_mitigation_summary.json


---

# Final Development Notes

Notebook 04 generates the engineered statistical and Rényi features used by the deep learning model.

Notebook 05 implements, trains, analyzes, and evaluates the hybrid CNN-BiLSTM-Attention baseline.

Notebook 06 adds and evaluates the AnomalyFlow decision and security layer using model confidence uncertainty and Rényi statistical evidence.

Notebook 07 implements the mitigation engine directly on the verified Notebook 06 sample-level output.

Notebook 07 converts security severity into graduated mitigation actions, generates security alerts, and simulates blocking, rate limiting, monitoring, and investigation decisions.

The CNN-BiLSTM-Attention model and AnomalyFlow configuration remain frozen.

The mitigation engine does not retrain the model or repeat AnomalyFlow analysis.

The current mitigation implementation evaluates blocking and rate-limiting decisions safely through simulation. Actual network enforcement is reserved for the backend/deployment layer.

The next development stage is the dashboard, which will provide the user-facing interface for the complete detection, severity, alert, and mitigation workflow.

The project remains focused on DDoS detection with emphasis on:

- Fast inference
- Memory efficiency
- Reproducibility
- Explainability
- Practical deployment
- Safe mitigation simulation