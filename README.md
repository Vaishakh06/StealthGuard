# StealthGuard – Network-Based DDoS Detection and Automated Mitigation System

B.E. Major Project – A real-time, network-based DDoS detection and automated mitigation system using a hybrid CNN + BiLSTM + Attention model with AnomalyFlow severity assessment and nftables-based firewall mitigation.

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Project Directory Structure](#project-directory-structure)
4. [Pipeline Details](#pipeline-details)
5. [ML Model](#ml-model)
6. [Event Schema](#event-schema)
7. [Dashboard](#dashboard)
8. [Docker Lab Environment](#docker-lab-environment)
9. [Configuration](#configuration)
10. [Quick Start](#quick-start)
11. [Traffic Generator](#traffic-generator)
12. [Known Limitations](#known-limitations)
13. [Project Decisions](#project-decisions)

---

## 1. Overview

StealthGuard is a network-based DDoS detection and automated mitigation system developed as a B.E. major project. It detects DDoS attacks in real time using ML-based flow classification, assesses security severity via the AnomalyFlow decision layer, and applies automated firewall mitigation using nftables. A Streamlit dashboard provides real-time visualization of detection and mitigation results.

### Key Features

- **Network-based DDoS detection** using a hybrid CNN + BiLSTM + Attention model
- **100-flow inference windows** with sliding-window processing
- **48 statistical features** per window (8 base features × 6 statistics)
- **AnomalyFlow decision layer** with confidence uncertainty and Rényi evidence
- **Security severity classification** (LOW, MEDIUM, HIGH, CRITICAL, NORMAL)
- **Automated nftables firewall mitigation** (block and rate-limit actions)
- **Streamlit dashboard** with six monitoring sections
- **Isolated Docker lab environment** for safe experimentation

---

## 2. System Architecture

The pipeline flows from network traffic capture through detection, decision, mitigation, and visualization:

```
Docker Traffic
    ↓
Flow Collector
    ↓
Feature Engineering (48 features per 100-flow window)
    ↓
Hybrid CNN + BiLSTM + Attention Model
    ↓
Predicted Class + Confidence
    ↓
AnomalyFlow Decision Layer
    ↓
Security Severity Classification
    ↓
Mitigation Controller
    ↓
Firewall Controller (nftables)
    ↓
Structured Event Logs (JSONL)
    ↓
Streamlit Dashboard
```

### Component Overview

| Component | Responsibility | Location |
|-----------|---------------|----------|
| Flow Collector | Captures live network traffic, builds bidirectional flows, extracts 8 base features per flow | `mitigation/detection/flow_collector.py` |
| Feature Engineering | Computes 48 statistical features per 100-flow window | `mitigation/detection/inference_adapter.py` |
| ML Model | Hybrid CNN + BiLSTM + Attention classifier (17 classes) | `mitigation/detection/inference_adapter.py`, `models/hybrid_model.pth` |
| AnomalyFlow | Decision layer producing anomalyflow score, decision state, security severity | `mitigation/detection/anomalyflow.py` |
| Mitigation Controller | Maps severity to firewall actions, logs detection events | `mitigation/controller/mitigation_controller.py` |
| Firewall Controller | Applies nftables block and rate-limit rules | `mitigation/firewall_controller.py` |
| Dashboard | Streamlit UI with 6 monitoring sections | `dashboard/app.py` |
| Traffic Generator | Generates controlled attack traffic for testing | `network_lab/attack_generator/traffic_generator.py` |

---

## 3. Project Directory Structure

```
StealthGuard/
├── dashboard/
│   ├── app.py                      # Streamlit dashboard entry point
│   ├── pages/                      # Dashboard page modules (overview, traffic monitor, detection results, severity, firewall, experiment results)
│   ├── components/                 # Reusable UI components (metric cards, charts, tables)
│   ├── services/                   # Data services (log reader, event processor, metrics calculator, firewall state)
│   ├── schemas/                    # Event schema definitions
│   ├── sample_data/                # Sample JSONL data for development/demo
│   ├── requirements.txt
│   └── README.md
├── mitigation/
│   ├── controller/
│   │   ├── mitigation_controller.py   # Mitigation decision engine
│   │   ├── mitigation_policy.py       # Severity-to-action policy mapping
│   │   ├── target_validator.py        # Target validation
│   │   ├── action_validator.py        # Action validation
│   │   ├── executor.py                # Mitigation executor
│   │   └── event_logger.py            # Event logging
│   ├── detection/
│   │   ├── flow_collector.py          # Live flow collector & inference pipeline
│   │   ├── inference_adapter.py       # Inference adapter (feature extraction → model prediction)
│   │   ├── detection_event_adapter.py # Detection event creation
│   │   ├── anomalyflow.py             # AnomalyFlow decision layer
│   │   └── test_*.py                  # Test scripts
│   ├── config/
│   │   ├── event_schema.json          # Event schema definition
│   │   └── lab_config.json            # Lab configuration
│   └── logs/
│       └── mitigation_events.jsonl    # Live detection event log
├── mitigation_actions.jsonl           # Firewall action lifecycle log
├── dashboard/
│   └── (see above)
├── network_lab/
│   ├── attack_generator/
│   │   └── traffic_generator.py       # Traffic generator for testing
│   ├── client/                        # Client container Dockerfile
│   ├── gateway/                       # Gateway container Dockerfile
│   ├── protected_server/              # Protected server container Dockerfile
│   └── compose.yaml                   # Docker Compose configuration
├── dataset/
│   ├── engineered/
│   │   ├── engineered_dataset.csv     # Engineered training dataset
│   │   └── engineered_dataset.pkl     # Pickled engineered dataset
│   └── raw/                           # Raw dataset (CIC-DDoS2019)
├── models/
│   ├── hybrid_model.pth               # Trained CNN-BiLSTM-Attention model
│   ├── label_encoder.pkl              # Label encoder
│   ├── scaler.pkl                     # Feature scaler (StandardScaler)
│   └── evaluation/
│       ├── classification_report.json
│       ├── confusion_matrix.npy
│       ├── anomalyflow_final_summary.json
│       ├── anomalyflow_config.json
│       └── evaluation_summary.json
├── notebooks/
│   ├── 04_Statistical_Features.ipynb
│   ├── 05_CNN_BiLSTM_Attention.ipynb
│   └── 06_AnomalyFlow_Decision_Security_Layer.ipynb
├── PROJECT_DECISIONS_FINAL_CORRECTED.md
├── README.md                          # This file
└── .gitignore
```

---

## 4. Pipeline Details

### Pipeline Flow

```
Docker Traffic → Flow Collector → Feature Extraction → 100-Flow Window → ML Model → AnomalyFlow → Mitigation Controller → Firewall Controller → nftables → JSONL Logs → Streamlit Dashboard
```

### Flow Collection

The flow collector runs on the gateway container and captures network traffic using Scapy. It:

1. Captures packets on the Docker bridge interface (`br-a56e51d39a9c` by default)
2. Groups packets into bidirectional flows (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
3. Computes 8 base features per flow:
   - Flow Duration
   - Flow Bytes/s
   - Flow Packets/s
   - Packet Length Mean
   - Packet Length Std
   - Total Fwd Packets
   - Total Backward Packets
   - Average Packet Size
4. Expires completed flows after 5 seconds of inactivity
5. Feeds completed flows to the inference pipeline

### Feature Engineering

Each inference window contains 100 flows. For each flow, 8 base features are extracted. For each base feature, 6 statistical descriptors are computed across the window:

| Statistic | Description |
|-----------|-------------|
| Mean | Mean value |
| Std | Standard deviation |
| Variance | Variance |
| Min | Minimum |
| Max | Maximum |
| Renyi | Rényi entropy (α=2) |

This produces **48 features per window** (8 features × 6 statistics).

### Inference Window

The model processes windows of 100 flows:
- **Training**: Sliding windows with stride=20 (80% overlap)
- **Live inference**: Non-overlapping windows of 100 flows
- Each window produces one prediction (class + confidence)

---

## 5. ML Model

### Architecture: Hybrid CNN + BiLSTM + Attention

The model is a hybrid deep learning architecture:

1. **CNN** (1D Convolutional): Learns local feature interactions within the 48-feature window
2. **Bi-LSTM** (Bidirectional LSTM): Learns temporal dependencies across sequential inference windows
3. **Attention**: Focuses on the most informative temporal patterns
4. **Classifier**: Dense layers with dropout for final classification

### Model Configuration

| Parameter | Value |
|-----------|-------|
| Input shape | (batch, 1, 48) - 48 features per window |
| Hidden layers | CNN → BiLSTM → Attention → Classifier |
| Output classes | 17 (15 DDoS attack classes + BENIGN + LDAP) |
| Optimizer | AdamW |
| Loss | CrossEntropyLoss |
| Batch size | 512 |
| Max epochs | 30 |
| Early stopping patience | 5 |

### Supported Classes (17 total)

| Class | Type |
|-------|------|
| BENIGN | Non-attack |
| LDAP | Non-attack |
| DrDoS_DNS | DDoS |
| DrDoS_LDAP | DDoS |
| DrDoS_MSSQL | DDoS |
| DrDoS_NTP | DDoS |
| DrDoS_NetBIOS | DDoS |
| DrDoS_SNMP | DDoS |
| DrDoS_SSDP | DDoS |
| DrDoS_UDP | DDoS |
| MSSQL | DDoS |
| NetBIOS | DDoS |
| Portmap | DDoS |
| Syn | DDoS |
| TFTP | DDoS |
| UDP | DDoS |
| UDP-lag | DDoS |

---

## 5. Event Schema

### Detection Events (`mitigation/logs/mitigation_events.jsonl`)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | Event timestamp |
| `status` | string | DRY_RUN / APPLIED / NO_FIREWALL_ACTION |
| `client` | string | Source IP |
| `server` | string | Destination IP |
| `port` | integer | Destination port |
| `protocol` | string | TCP / UDP |
| `predicted_label` | string | ML predicted class |
| `confidence` | float | Model confidence |
| `confidence_uncertainty` | float | Confidence uncertainty |
| `renyi_evidence` | float | Rényi evidence score |
| `confidence_normalized` | float | Normalized confidence |
| `renyi_normalized` | float | Normalized Rényi evidence |
| `anomalyflow_score` | float | AnomalyFlow score |
| `decision_state` | string | NORMAL / SUSPICIOUS / HIGH_EVIDENCE |
| `security_severity` | string | NORMAL / LOW / MEDIUM / HIGH / CRITICAL |
| `mitigation_action` | string | NO_ACTION / ALERT_AND_LOG / RATE_LIMIT / BLOCK_AND_RATE_LIMIT |
| `mitigation_priority` | string | NONE / LOW / MEDIUM / CRITICAL |
| `alert_generated` | boolean | Whether an alert was raised |
| `alert_level` | string | Alert level |
| `alert_type` | string | Alert type |
| `mitigation_outcome` | string | NOT_REQUIRED / SIMULATED / BLOCK_APPLIED / RATE_LIMIT_APPLIED |
| `experiment_id` | string | Experiment correlation ID (optional) |
| `window_id` | string | 100-flow window identifier (optional) |
| `ground_truth` | string | True class for evaluation (optional) |

### Firewall Events (`mitigation/controller/mitigation_actions.jsonl`)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | Event timestamp |
| `event` | string | block_applied / block_removed / rate_limit_applied / rate_limit_removed / controller_error |
| `client` | string | Source IP |
| `server` | string | Destination IP |
| `port` | integer | Destination port |
| `duration_seconds` | integer | Block/rate-limit duration |
| `rate_per_second` | integer | Configured rate limit |
| `burst_packets` | integer | Configured burst size |

---

## 6. Dashboard

The Streamlit dashboard provides real-time monitoring with six sections:

| Section | Description |
|---------|-------------|
| **1. System Overview** | Component status cards, key metrics (windows processed, attacks detected, mitigations, active rules) |
| **2. Traffic Monitor** | Traffic volume, source IP distribution, benign vs attack windows |
| **3. ML Detection Results** | Detection table, class distribution, per-class metrics |
| **4. AnomalyFlow Severity** | Severity distribution, AnomalyFlow score histogram |
| **5. Firewall Monitor** | Blocked IPs and rate-limited IPs in separate panels |
| **6. Experiment Results** | Per-experiment summaries with CSV export |

### Running the Dashboard

```bash
cd dashboard
pip install -r requirements.txt
streamlit run app.py
```

Access at `http://localhost:8501`.

**Data Modes**: SAMPLE (bundled demo data) or LIVE (reads StealthGuard JSONL logs). Selectable from the sidebar.

---

## 7. Docker Lab Environment

The project includes an isolated Docker network for safe experimentation:

| Container | IP Address | Purpose |
|-----------|------------|---------|
| cp-client | 172.28.0.10 | Traffic generation |
| cp-gateway | 172.28.0.2 / 172.29.0.2 | Gateway and firewall |
| cp-protected-server | 172.29.0.10 | Protected server |

### Docker Networks

- **cp-client-net**: 172.28.0.0/24 (client side)
- **cp-server-net**: 172.29.0.0/24 (server side)

### Starting the Lab

```bash
cd network_lab
docker compose up -d
```

The gateway has IP forwarding enabled (`net.ipv4.ip_forward=1`) and nftables available for mitigation testing.

---

## 8. Configuration

### Dashboard Configuration (`dashboard/config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `MITIGATION_EVENTS_LOG` | `mitigation/logs/mitigation_events.jsonl` | Detection event log path |
| `MITIGATION_ACTIONS_LOG` | `mitigation/controller/mitigation_actions.jsonl` | Firewall action log path |
| `SAMPLE_DATA_DIR` | `dashboard/sample_data/` | Sample data directory |
| `REFRESH_INTERVAL_SECONDS` | 3 | Dashboard refresh interval |
| `DEFAULT_MODE` | "sample" | Default data mode (sample/live) |

### Lab Configuration (`mitigation/config/lab_config.json`)

```json
{
  "allowed_client_networks": ["172.28.0.0/24"],
  "allowed_destination_networks": ["172.29.0.0/24"]
}
```

### Event Schema (`mitigation/config/event_schema.json`)

Defines required fields, allowed actions, severities, and decision states for detection and firewall events.

---

## 8. Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Streamlit, pandas, plotly

### Step 1: Start the Docker Lab

```bash
cd /mnt/StealthGuard/network_lab
docker compose up -d
```

### Step 2: Start the Flow Collector (on Ubuntu VM)

```bash
cd /mnt/StealthGuard
source /home/vboxuser/stealthguard-venv/bin/activate
sudo python mitigation/detection/flow_collector.py --iface br-a56e51d39a9c
```

### Step 3: Generate Traffic

```bash
# Copy traffic generator to client
docker cp /mnt/StealthGuard/network_lab/attack_generator/traffic_generator.py cp-client:/workspace/

# Generate traffic for a specific class
docker exec cp-client bash -c 'STEALTHGUARD_GROUND_TRUTH=DrDoS_NTP python /workspace/traffic_generator.py --class DrDoS_NTP --count 100'
```

**Supported classes**: Syn, UDP, UDP-lag, TFTP, Portmap, MSSQL, NetBIOS, DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP

### Step 4: Run the Dashboard

```bash
cd /mnt/StealthGuard/dashboard
source /home/vboxuser/stealthguard-venv/bin/activate
python -m streamlit run app.py
```

Access at `http://localhost:8501`.

---

## 9. Traffic Generator

The traffic generator (`network_lab/attack_generator/traffic_generator.py`) creates controlled DDoS traffic for testing:

```bash
python /workspace/traffic_generator.py --class <class_name> --count <count>
```

| Option | Description |
|--------|-------------|
| `--class` | Attack class to generate (required) |
| `--count` | Number of flows to generate (default: 100) |
| `--rate` | Packets per second (default: 10.0) |
| `--dst` | Destination IP (default: 172.29.0.10) |
| `--list` | List all available classes |

### Supported Attack Classes

Syn, UDP, UDP-lag, TFTP, Portmap, MSSQL, NetBIOS, DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NTP, DrDoS_NetBIOS, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP

---

## 10. Known Limitations

| Limitation | Description |
|------------|-------------|
| Classification accuracy | Live traffic may not perfectly match training distribution due to Docker networking, synthetic traffic generation, and windowing differences |
| Firewall status | Active/Expired status is estimated from lifecycle log events; live nftables state is not directly queried |
| Classification metrics | Require `ground_truth` fields in detection events; without them, accuracy metrics are N/A |
| Auto-refresh | Browser tab must remain open for Streamlit auto-refresh to work |
| Missing log files | Handled gracefully (empty state shown) in LIVE mode |

### Classes with Lower Classification Reliability

Based on training evaluation:
- **Portmap**: Recall 0.155 (highest confusion with DrDoS_NetBIOS)
- **DrDoS_SSDP**: Recall 0.411
- **DrDoS_UDP**: Recall 0.645
- **UDP-lag**: Recall 0.661
- **UDP**: Recall 0.764

These classes have higher confusion with similar classes and may require additional traffic generator tuning for reliable live classification.

---

## 11. Project Decisions

Key architectural decisions are documented in `PROJECT_DECISIONS_FINAL_CORRECTED.md`. Key decisions include:

- **Dataset**: CIC-DDoS2019
- **Feature Engineering**: 8 base features × 6 statistics = 48 features per 100-flow window
- **Windowing**: Sliding windows of 100 flows with stride=20 (training); non-overlapping windows (live inference - under improvement)
- **Model**: Hybrid CNN + BiLSTM + Attention, 17 classes
- **AnomalyFlow**: Confidence uncertainty + Rényi evidence for security severity
- **Mitigation**: Severity-mapped actions (ALERT_AND_LOG, RATE_LIMIT, BLOCK_AND_RATE_LIMIT)
- **No retraining of baseline**: The trained CNN-BiLSTM-Attention model is kept frozen; improvements come via the AnomalyFlow decision layer

---

## 12. Contributing

This is a B.E. major project. The architecture is designed to be modular:

1. Detection pipeline (flow collector → feature extraction → model)
2. Decision layer (AnomalyFlow)
3. Mitigation layer (controller → firewall)
4. Visualization (Streamlit dashboard)

When contributing, please:
1. Follow the existing modular structure
2. Document design decisions in PROJECT_DECISIONS_FINAL_CORRECTED.md
3. Test with both SAMPLE and LIVE modes
4. Preserve the 48-feature schema and 17-class model interface

---

## License

This is a B.E. major project. All rights reserved.

---

*Last updated: November 2026*