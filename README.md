# StealthGuard – Network-Based DDoS Detection and Automated Mitigation System

B.E. Major Project – A real-time, network-based DDoS detection and automated mitigation system using a hybrid CNN + BiLSTM + Attention model with AnomalyFlow severity assessment and nftables-based firewall mitigation.

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Project Directory Structure](#project-directory-structure)
4. [Pipeline Details](#pipeline-details)
5. [ML Models (17-Class Baseline + 3-Class Active)](#ml-models-17-class-baseline--3-class-active)
6. [Event Schema](#event-schema)
7. [Dashboard](#dashboard)
8. [Docker Lab Environment](#docker-lab-environment)
9. [Configuration](#configuration)
10. [Traffic Generator](#traffic-generator)
11. [Running the StealthGuard Live Demonstration (Ubuntu VM)](#running-the-stealthguard-live-demonstration-ubuntu-vm)
12. [Known Limitations](#known-limitations)
13. [Project Decisions](#project-decisions)
14. [Contributing](#contributing)
15. [License](#license)

---

## 1. Overview

StealthGuard is a network-based DDoS detection and automated mitigation system developed as a B.E. major project. It detects DDoS attacks in real time using ML-based flow classification, assesses security severity via the AnomalyFlow decision layer, and applies automated firewall mitigation using nftables. A Streamlit dashboard provides real-time visualization of detection and mitigation results.

All project execution — Docker containers, flow collector, traffic generator, detection pipeline, and dashboard — runs inside an Ubuntu VirtualBox VM at `/mnt/StealthGuard`.

### Key Features

- **Network-based DDoS detection** using a hybrid CNN + BiLSTM + Attention model
- **3-class classification**: BENIGN, TCP_DDoS, UDP_DDoS
- **17-class baseline model preserved** (frozen, untouched, archived in `models/`)
- **100-flow inference windows** with sliding-window processing
- **48 statistical features** per window (8 base features × 6 statistics)
- **AnomalyFlow decision layer** with confidence uncertainty and Rényi evidence
- **Security severity classification** (NORMAL, LOW, MEDIUM, HIGH, MONITOR, INVESTIGATE)
- **Automated nftables firewall mitigation** (ALLOW, MONITOR, RATE_LIMIT, TEMPORARY_BLOCK)
- **Streamlit dashboard** with six monitoring sections
- **Isolated Docker lab environment** for safe experimentation
- **Buffer reset mechanism** (SIGUSR1) for clean testing between attack classes

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
Hybrid CNN + BiLSTM + Attention Model (3 classes)
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
| ML Model (3-Class Active) | Hybrid CNN + BiLSTM + Attention classifier (BENIGN, TCP_DDoS, UDP_DDoS) | `mitigation/detection/inference_adapter.py`, `models/threeclass/best_model.pth` |
| ML Model (17-Class Baseline) | Frozen 17-class model, preserved untouched | `models/hybrid_model.pth` |
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
│   ├── sample_data/                # Sample JSONL data for development/demo (3-class labels)
│   ├── requirements.txt
│   └── README.md
├── mitigation/
│   ├── controller/
│   │   ├── mitigation_controller.py   # Mitigation decision engine (3-class actions)
│   │   ├── mitigation_policy.py       # Severity-to-action policy mapping (3-class)
│   │   ├── target_validator.py        # Target validation
│   │   ├── action_validator.py        # Action validation
│   │   ├── executor.py                # Mitigation executor
│   │   ├── event_logger.py            # Event logging
│   │   └── mitigation_actions.jsonl   # Firewall action lifecycle log
│   ├── detection/
│   │   ├── flow_collector.py          # Live flow collector & inference pipeline
│   │   ├── inference_adapter.py       # Inference adapter (feature extraction → model prediction, loads 3-class artifacts)
│   │   ├── detection_event_adapter.py # Detection event creation (3-class calibration optional)
│   │   ├── anomalyflow.py             # AnomalyFlow decision layer (DDOS_CLASSES: TCP_DDoS, UDP_DDoS only)
│   │   └── test_*.py                  # Test scripts
│   ├── config/
│   │   ├── event_schema.json          # Event schema definition (3-class actions/severities)
│   │   └── lab_config.json            # Lab configuration
│   └── logs/
│       └── mitigation_events.jsonl    # Live detection event log
├── dashboard/
│   └── (see above)
├── network_lab/
│   ├── attack_generator/
│   │   ├── traffic_generator.py       # Traffic generator for testing (with --ground-truth)
│   │   └── http_burst.py              # BENIGN traffic generator (with --ground-truth)
│   ├── client/                        # Client container Dockerfile
│   ├── gateway/                       # Gateway container Dockerfile
│   ├── protected_server/              # Protected server container Dockerfile
│   └── compose.yaml                   # Docker Compose configuration
├── dataset/
│   ├── engineered/
│   │   ├── engineered_dataset.csv     # Engineered training dataset (17-class)
│   │   ├── engineered_3class.csv      # Engineered 3-class dataset
│   │   ├── engineered_dataset.pkl     # Pickled engineered dataset
│   │   └── prepare_3class_dataset.py  # 3-class dataset preparation script
│   └── raw/                           # Raw dataset (CIC-DDoS2019)
├── models/
│   ├── hybrid_model.pth               # Trained 17-class model (frozen, untouched)
│   ├── label_encoder.pkl              # 17-class label encoder (frozen, untouched)
│   ├── scaler.pkl                     # 17-class feature scaler (frozen, untouched)
│   ├── evaluation/                    # 17-class evaluation artifacts (frozen, untouched)
│   │   ├── classification_report.json
│   │   ├── confusion_matrix.npy
│   │   ├── anomalyflow_final_summary.json
│   │   ├── anomalyflow_config.json
│   │   └── evaluation_summary.json
│   └── threeclass/                    # 3-class model artifacts (active model)
│       ├── best_model.pth             # Best validation 3-class model
│       ├── hybrid_model_3class.pth    # Final 3-class model
│       ├── label_encoder_3class.pkl   # 3-class label encoder ({0: BENIGN, 1: TCP_DDoS, 2: UDP_DDoS})
│       ├── scaler_3class.pkl          # 3-class feature scaler (StandardScaler)
│       ├── model_config.json          # 3-class model configuration
│       ├── training_history_3class.pkl| Training history
│       └── training_checkpoint.pth    # Resume checkpoint
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
Docker Traffic → Flow Collector → Feature Extraction → 100-Flow Window → ML Model (3-Class) → AnomalyFlow → Mitigation Controller → Firewall Controller → nftables → JSONL Logs → Streamlit Dashboard
```

### Flow Collection

The flow collector runs on the Ubuntu VM host (not inside a container) and captures network traffic using Scapy. It:

1. Captures packets on the Docker bridge interface
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

### Buffer Reset Mechanism (Testing Support)

Between individual attack tests, flows from a previous attack class can remain in the inference buffer (sliding window retains 80 flows after processing 100). To prevent cross-contamination:

- Send `SIGUSR1` to the flow collector process to clear the pending inference buffer
- Packet capture continues uninterrupted
- New flows start filling the buffer from empty
- Detection logs are NOT erased

```bash
pgrep -af flow_collector    # Get collector PID
sudo kill -USR1 <pid>       # Reset buffer
```

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
- **Live inference**: Sliding windows with stride=20
- Each window produces one prediction (class + confidence)

---

## 5. ML Models (17-Class Baseline + 3-Class Active)

### Architecture: Hybrid CNN + BiLSTM + Attention

The model is a hybrid deep learning architecture:

1. **CNN** (1D Convolutional): Learns local feature interactions within the 48-feature window
2. **Bi-LSTM** (Bidirectional LSTM): Learns temporal dependencies across sequential inference windows
3. **Attention**: Focuses on the most informative temporal patterns
4. **Classifier**: Dense layers with dropout for final classification

### 3-Class Active Model Configuration

| Parameter | Value |
|-----------|-------|
| Input shape | (batch, 1, 48) - 48 features per window |
| Hidden layers | CNN → BiLSTM → Attention → Classifier |
| Output classes | 3 (BENIGN, TCP_DDoS, UDP_DDoS) |
| Optimizer | AdamW |
| Loss | CrossEntropyLoss |
| Batch size | 512 |
| Max epochs | 30 |
| Early stopping patience | 5 |
| Best validation loss | 0.2495 |
| Best validation accuracy | 99.29% |
| Test accuracy | 99.29% |
| Macro F1 | 95.71% |
| Training samples | 2,707,556 |
| Validation samples | 338,444 |
| Test samples | 338,445 |
| Training time | ~34 minutes (GPU) |

### 3-Class Label Mapping

CIC-DDoS2019 classes mapped to 3 classes:

| Original Class | Protocol | 3-Class Label |
|---------------|----------|---------------|
| BENIGN | N/A | BENIGN |
| Syn | TCP | TCP_DDoS |
| Portmap | TCP | TCP_DDoS |
| MSSQL | TCP | TCP_DDoS |
| DrDoS_MSSQL | TCP | TCP_DDoS |
| DrDoS_DNS | UDP | UDP_DDoS |
| DrDoS_NTP | UDP | UDP_DDoS |
| DrDoS_SNMP | UDP | UDP_DDoS |
| DrDoS_NetBIOS | UDP | UDP_DDoS |
| DrDoS_SSDP | UDP | UDP_DDoS |
| DrDoS_UDP | UDP | UDP_DDoS |
| TFTP | UDP | UDP_DDoS |
| UDP | UDP | UDP_DDoS |
| UDP-lag | UDP | UDP_DDoS |
| DrDoS_LDAP | UDP | UDP_DDoS |
| NetBIOS | UDP | UDP_DDoS |
| LDAP | UDP | UDP_DDoS |

**Note**: LDAP was moved from BENIGN to UDP_DDoS in the 3-class mapping because LDAP is an attack class (reflection/amplification, UDP port 389) in CIC-DDoS2019.

### DDOS_CLASSES (AnomalyFlow)

Only `TCP_DDoS` and `UDP_DDoS` are treated as DDoS attack classes. BENIGN follows the Non-DDoS severity path and never triggers attack mitigation.

### 17-Class Baseline Model (Preserved)

The original 17-class model and all its artifacts are **frozen and untouched**:

- `models/hybrid_model.pth` — frozen 17-class model state dict
- `models/scaler.pkl` — 17-class StandardScaler
- `models/label_encoder.pkl` — 17-class label encoder
- `models/evaluation/` — 17-class evaluation results

The 17-class model is preserved for reference and comparison but is **not used** in the active pipeline.

---

## 6. Event Schema

### Detection Events (`mitigation/logs/mitigation_events.jsonl`)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | Event timestamp |
| `status` | string | DRY_RUN / APPLIED / NO_FIREWALL_ACTION |
| `client` | string | Source IP |
| `server` | string | Destination IP |
| `port` | integer | Destination port |
| `protocol` | string | TCP / UDP |
| `predicted_label` | string | ML predicted class (BENIGN / TCP_DDoS / UDP_DDoS) |
| `confidence` | float | Model confidence |
| `confidence_uncertainty` | float | Confidence uncertainty |
| `renyi_evidence` | float | Rényi evidence score |
| `confidence_normalized` | float | Normalized confidence |
| `renyi_normalized` | float | Normalized Rényi evidence |
| `anomalyflow_score` | float | AnomalyFlow score |
| `decision_state` | string | NORMAL / SUSPICIOUS / HIGH_EVIDENCE |
| `security_severity` | string | NORMAL / LOW / MEDIUM / HIGH / MONITOR / INVESTIGATE |
| `mitigation_action` | string | ALLOW / MONITOR / RATE_LIMIT / TEMPORARY_BLOCK / INVESTIGATE |
| `mitigation_priority` | string | NONE / LOW / MEDIUM / CRITICAL |
| `alert_generated` | boolean | Whether an alert was raised |
| `alert_level` | string | Alert level |
| `alert_type` | string | Alert type |
| `mitigation_outcome` | string | NOT_REQUIRED / SIMULATED / TEMPORARY_BLOCK_APPLIED / RATE_LIMIT_APPLIED |
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
| `duration_seconds` | integer | Block/rate-limit duration (block: 60s, rate-limit: 45s) |
| `rate_per_second` | integer | Configured rate limit |
| `burst_packets` | integer | Configured burst size |

---

## 7. Dashboard

The Streamlit dashboard provides real-time monitoring with six sections:

| Section | Description |
|---------|-------------|
| **1. System Overview** | Component status cards, key metrics (windows processed, attacks detected, mitigations, active rules) |
| **2. Traffic Monitor** | Traffic volume, source IP distribution, benign vs attack windows |
| **3. ML Detection Results** | Detection table, class distribution (BENIGN/TCP_DDoS/UDP_DDoS), per-class metrics |
| **4. AnomalyFlow Severity** | Severity distribution (NORMAL/LOW/MEDIUM/HIGH/MONITOR/INVESTIGATE), AnomalyFlow score histogram |
| **5. Firewall Monitor** | Blocked IPs and rate-limited IPs in separate panels, with ACTIVE/EXPIRED/REMOVED status |
| **6. Experiment Results** | Per-experiment summaries with CSV export |

### Running the Dashboard

```bash
cd /mnt/StealthGuard/dashboard
source /home/vboxuser/stealthguard-venv/bin/activate
/home/vboxuser/stealthguard-venv/bin/python -m streamlit run app.py
```

Access at `http://localhost:8501`.

**Data Modes**: SAMPLE (bundled demo data with 3-class labels) or LIVE (reads StealthGuard JSONL logs). Selectable from the sidebar.

---

## 8. Docker Lab Environment

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
cd /mnt/StealthGuard/network_lab
docker compose up -d
```

The gateway has IP forwarding enabled (`net.ipv4.ip_forward=1`) and nftables available for mitigation testing.

---

## 9. Configuration

### Dashboard Configuration (`dashboard/config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `MITIGATION_EVENTS_LOG` | `mitigation/logs/mitigation_events.jsonl` | Detection event log path |
| `MITIGATION_ACTIONS_LOG` | `mitigation/controller/mitigation_actions.jsonl` | Firewall action log path |
| `SAMPLE_DATA_DIR` | `dashboard/sample_data/` | Sample data directory |
| `REFRESH_INTERVAL_SECONDS` | 3 | Dashboard refresh interval |
| `DEFAULT_MODE` | "sample" | Default data mode (sample/live) |

### Mitigation Durations (`mitigation/firewall_controller.py`)

| Variable | Default | Environment Override |
|----------|---------|---------------------|
| `BLOCK_DURATION` | 60 seconds | `STEALTHGUARD_BLOCK_DURATION` |
| `RATE_LIMIT_DURATION` | 45 seconds | `STEALTHGUARD_RATE_LIMIT_DURATION` |
| `RATE_LIMIT_RATE` | 20/second | `STEALTHGUARD_RATE_LIMIT_RATE` |
| `RATE_LIMIT_BURST` | 40 packets | `STEALTHGUARD_RATE_LIMIT_BURST` |

### Lab Configuration (`mitigation/config/lab_config.json`)

```json
{
  "allowed_client_networks": ["172.28.0.0/24"],
  "allowed_destination_networks": ["172.29.0.0/24"]
}
```

### Event Schema (`mitigation/config/event_schema.json`)

Defines required fields, allowed actions, severities, and decision states for detection and firewall events.

Allowed actions: ALLOW, MONITOR, RATE_LIMIT, TEMPORARY_BLOCK, INVESTIGATE

Allowed severities: NORMAL, LOW, MEDIUM, HIGH, MONITOR, INVESTIGATE

Allowed decision states: NORMAL, SUSPICIOUS, HIGH_EVIDENCE

---

## 10. Traffic Generator

The traffic generator (`network_lab/attack_generator/traffic_generator.py`) creates controlled DDoS traffic for testing:

```bash
python /workspace/traffic_generator.py --class <class_name> --count <count> --ground-truth <BENIGN|TCP_DDoS|UDP_DDoS>
```

| Option | Description |
|--------|-------------|
| `--class` | Attack class to generate (required) |
| `--count` | Number of flows to generate (default: 100) |
| `--rate` | Packets per second (default: 10.0) |
| `--dst` | Destination IP (default: 172.29.0.10) |
| `--ground-truth` | Expected 3-class label for evaluation metadata (BENIGN, TCP_DDoS, UDP_DDoS) |

### BENIGN Traffic Generator

The standalone script `network_lab/attack_generator/http_burst.py` generates normal HTTP traffic:

```bash
python /workspace/http_burst.py --ground-truth BENIGN
```

| Option | Description |
|--------|-------------|
| `--count` | Number of HTTP requests to generate (default: 100) |
| `--delay` | Delay between requests in seconds (default: 0.1) |
| `--ground-truth` | Expected 3-class label for evaluation metadata |

### Supported Attack Classes (3-Class Mapping)

| Class | Protocol | 3-Class Label |
|-------|----------|---------------|
| BENIGN (http_burst.py) | TCP | BENIGN |
| Portmap | TCP | TCP_DDoS |
| MSSQL | TCP | TCP_DDoS |
| Syn | TCP | TCP_DDoS |
| DrDoS_DNS | UDP | UDP_DDoS |
| DrDoS_NTP | UDP | UDP_DDoS |
| DrDoS_SNMP | UDP | UDP_DDoS |
| DrDoS_LDAP | UDP | UDP_DDoS |
| DrDoS_MSSQL | UDP | UDP_DDoS |
| DrDoS_NetBIOS | UDP | UDP_DDoS |
| DrDoS_SSDP | UDP | UDP_DDoS |
| DrDoS_UDP | UDP | UDP_DDoS |
| TFTP | UDP | UDP_DDoS |
| UDP | UDP | UDP_DDoS |
| UDP-lag | UDP | UDP_DDoS |

### Bidirectional Attack Support

The following attacks now generate bidirectional traffic (forward + backward packets) to better match CIC-DDoS2019 training distributions:

- **Portmap**: TCP, bidirectional, 4-6 packets/flow
- **MSSQL**: TCP, bidirectional, 4-6 packets/flow
- **DrDoS_NTP**: UDP, bidirectional (request + response), 2 packets/flow
- **DrDoS_MSSQL**: UDP, bidirectional, 2-3 packets/flow
- **Syn**: TCP, bidirectional (SYN + response), 2 packets/flow

Forward-only attacks (unchanged): TFTP, NetBIOS, DrDoS_DNS, DrDoS_SNMP, DrDoS_LDAP, DrDoS_NetBIOS, DrDoS_UDP, UDP, UDP-lag.

All attacks produce at least 2 packets per flow to satisfy the flow collector's minimum packet threshold.

---

## 11. Running the StealthGuard Live Demonstration (Ubuntu VM)

All demonstration commands below run inside the Ubuntu VirtualBox VM at `/mnt/StealthGuard`. The flow collector runs on the VM host; Docker containers run on the same VM. The traffic generator executes inside the `cp-client` container.

### Terminal 1 — Start the Flow Collector

This terminal must remain running throughout the demonstration. It captures traffic on the Docker bridge interface and runs inference on every 100-flow window.

```bash
sudo mount -t vboxsf StealthGuard /mnt/StealthGuard
cd /mnt/StealthGuard
source /home/vboxuser/stealthguard-venv/bin/activate
sudo /home/vboxuser/stealthguard-venv/bin/python -m mitigation.detection.flow_collector
```

The collector prints diagnostic output for each completed flow and each inference window. Keep this terminal open; do not close it during testing.

### Terminal 2 — Start Docker Containers and Prepare the Generator

```bash
docker start cp-gateway cp-client cp-protected-server
```

Copy the traffic generator into the client container:

```bash
docker cp /mnt/StealthGuard/network_lab/attack_generator/traffic_generator.py cp-client:/workspace/traffic_generator.py
docker cp /mnt/StealthGuard/network_lab/attack_generator/http_burst.py cp-client:/workspace/http_burst.py
```

Find the collector PID (identify the actual Python process, not `sudo` or `grep`):

```bash
pgrep -af flow_collector
```

Store the correct PID in a shell variable for convenience:

```bash
COLLECTOR_PID=<actual_python_collector_pid>
```

Reset the inference buffer between individual attack tests:

```bash
sudo kill -USR1 "$COLLECTOR_PID"
```

This clears only the pending inference buffer; packet capture continues uninterrupted and detection logs are not erased.

### Terminal 3 — Individual Live Test Commands

Run each test from Terminal 3 (inside the VM). Reset the buffer between tests to prevent flows from the previous attack from mixing into the next inference window.

**Test 1 — BENIGN**

```bash
docker exec cp-client python /workspace/http_burst.py --ground-truth BENIGN
```

Reset buffer:

```bash
sudo kill -USR1 "$COLLECTOR_PID"
```

**Test 2 — DrDoS_DNS (UDP_DDoS)**

```bash
docker exec cp-client python /workspace/traffic_generator.py --class DrDoS_DNS --count 100 --ground-truth UDP_DDoS
```

Reset buffer:

```bash
sudo kill -USR1 "$COLLECTOR_PID"
```

**Test 3 — Syn (TCP_DDoS)**

```bash
docker exec cp-client python /workspace/traffic_generator.py --class Syn --count 100 --ground-truth TCP_DDoS
```

Reset buffer:

```bash
sudo kill -USR1 "$COLLECTOR_PID"
```

**Test 4 — DrDoS_SNMP (UDP_DDoS)**

```bash
docker exec cp-client python /workspace/traffic_generator.py --class DrDoS_SNMP --count 100 --ground-truth UDP_DDoS
```

Reset buffer:

```bash
sudo kill -USR1 "$COLLECTOR_PID"
```

**Test 5 — DrDoS_LDAP (UDP_DDoS)**

```bash
docker exec cp-client python /workspace/traffic_generator.py --class DrDoS_LDAP --count 100 --ground-truth UDP_DDoS
```

Reset buffer:

```bash
sudo kill -USR1 "$COLLECTOR_PID"
```

**Test 6 — TFTP (UDP_DDoS)**

```bash
docker exec cp-client python /workspace/traffic_generator.py --class TFTP --count 100 --ground-truth UDP_DDoS
```

Expected predictions:
- BENIGN → `BENIGN`
- DrDoS_DNS → `UDP_DDoS`
- Syn → `TCP_DDoS`
- DrDoS_SNMP → `UDP_DDoS`
- DrDoS_LDAP → `UDP_DDoS`
- TFTP → `UDP_DDoS`

`--ground-truth` is evaluation metadata only; it is recorded in the JSONL log but **never** influences model inference, predictions, confidence, severity, or mitigation decisions.

### Terminal 4 — Inspect Detection and Mitigation Logs

Inspect detection events (ground truth, predicted class, confidence, severity, mitigation action):

```bash
tail -f /mnt/StealthGuard/mitigation/logs/mitigation_events.jsonl
```

Inspect firewall action lifecycle:

```bash
tail -f /mnt/StealthGuard/mitigation/controller/mitigation_actions.jsonl
```

Inspect nftables rules on the gateway:

```bash
sudo nft list ruleset
```

A typical detection event record contains:

```json
{
  "timestamp": "2026-11-16T...",
  "status": "APPLIED",
  "client": "172.28.0.10",
  "server": "172.29.0.10",
  "port": 8080,
  "protocol": "udp",
  "predicted_label": "UDP_DDoS",
  "confidence": 0.91,
  "anomalyflow_score": 0.18,
  "decision_state": "NORMAL",
  "security_severity": "LOW",
  "mitigation_action": "MONITOR",
  "mitigation_outcome": "SIMULATED",
  "ground_truth": "UDP_DDoS"
}
```

### Launching the Dashboard

```bash
cd /mnt/StealthGuard/dashboard
source /home/vboxuser/stealthguard-venv/bin/activate
/home/vboxuser/stealthguard-venv/bin/python -m streamlit run app.py
```

Access at `http://localhost:8501`. Switch to **LIVE** mode in the sidebar to read real StealthGuard JSONL logs.

---

## 12. Known Limitations

| Limitation | Description |
|------------|-------------|
| Classification accuracy | Live traffic may not perfectly match training distribution due to Docker networking, synthetic traffic generation, and windowing differences |
| No 3-class calibration | `anomalyflow_calibration_3class.json` does not exist; identity scalers are used. Severity thresholds (0.25/0.40) were tuned for 17-class data |
| Firewall status | Active/Expired status is estimated from lifecycle log events; live nftables state is not directly queried |
| Classification metrics | Require `ground_truth` fields in detection events; without them, accuracy metrics are N/A |
| Auto-refresh | Browser tab must remain open for Streamlit auto-refresh to work |
| Missing log files | Handled gracefully (empty state shown) in LIVE mode |
| Buffer reset is manual | Operator must send SIGUSR1 between attack tests; no automated test orchestration |
| Single source IP | All traffic originates from 172.28.0.10; CIC-DDoS2019 has many source IPs |

---

## 13. Project Decisions

Key architectural decisions are documented in `PROJECT_DECISIONS_FINAL_CORRECTED.md`. Key decisions include:

- **Dataset**: CIC-DDoS2019
- **Feature Engineering**: 8 base features × 6 statistics = 48 features per 100-flow window
- **Windowing**: Sliding windows of 100 flows with stride=20 (training and live inference)
- **Model**: Hybrid CNN + BiLSTM + Attention, 3 active classes (BENIGN, TCP_DDoS, UDP_DDoS)
- **17-class baseline**: Frozen and preserved untouched in `models/`
- **AnomalyFlow**: Confidence uncertainty + Rényi evidence for security severity
- **Mitigation**: Severity-mapped actions (ALLOW, MONITOR, RATE_LIMIT, TEMPORARY_BLOCK, INVESTIGATE)
- **LDAP mapping**: Moved from BENIGN to UDP_DDoS (attack class in CIC-DDoS2019)
- **Firewall durations**: Block 60s, rate limit 45s (configurable via environment variables)
- **No retraining of baseline**: The trained 3-class model is kept frozen; improvements come via traffic generator tuning and calibration

---

## 14. Contributing

This is a B.E. major project. The architecture is designed to be modular:

1. Detection pipeline (flow collector → feature extraction → model)
2. Decision layer (AnomalyFlow)
3. Mitigation layer (controller → firewall)
4. Visualization (Streamlit dashboard)

When contributing, please:

1. Follow the existing modular structure
2. Document design decisions in PROJECT_DECISIONS_FINAL_CORRECTED.md
3. Test with both SAMPLE and LIVE modes
4. Do not modify the original 17-class model artifacts
5. Preserve the 48-feature schema

---

## License

This is a B.E. major project. All rights reserved.

---

*Last updated: November 2026*
