# StealthGuard Dashboard

Real-time monitoring dashboard for the **StealthGuard – Network-Based DDoS Detection and Automated Mitigation System** B.E. major project.

## Features

Six sections:

1. **System Overview** – component status cards and key metrics
2. **Traffic Monitor** – traffic volume, source IP distribution, benign vs attack windows
3. **ML Detection Results** – detection table, accuracy/precision/recall/F1, confusion matrix
4. **AnomalyFlow Severity Analysis** – severity distribution, AnomalyFlow score histogram
5. **Firewall Action Monitor** – blocked IPs and rate-limited IPs in separate panels
6. **Experiment Results** – per-experiment summaries with CSV export

## Quick Start

```bash
# From the project root
cd dashboard
pip install -r requirements.txt
streamlit run app.py
```

Open the URL Streamlit prints (typically http://localhost:8501).

## Data Modes

The dashboard supports two modes, selectable from the sidebar:

| Mode | Data Source | Purpose |
|------|-------------|---------|
| **SAMPLE** | `dashboard/sample_data/*.jsonl` | Development and demo |
| **LIVE** | `mitigation/logs/mitigation_events.jsonl` and `mitigation/controller/mitigation_actions.jsonl` | Real StealthGuard output |

Sample data is clearly labelled with a red "SAMPLE DATA MODE" banner. Sample data is never mixed with live results.

## Event Schema

### Detection events (`mitigation_events.jsonl`)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | Event timestamp |
| `status` | string | DRY_RUN / APPLIED / NO_FIREWALL_ACTION |
| `client` | string | Source IP |
| `server` | string | Destination IP |
| `port` | integer | Destination port |
| `predicted_label` | string | ML predicted class (e.g. BENIGN, DrDoS_UDP, DDoS) |
| `confidence` | float | Model confidence |
| `anomalyflow_score` | float | AnomalyFlow score |
| `decision_state` | string | NORMAL / SUSPICIOUS / HIGH_EVIDENCE / ATTACK |
| `security_severity` | string | NORMAL / LOW / MEDIUM / HIGH |
| `mitigation_action` | string | NO_ACTION / ALERT_AND_LOG / RATE_LIMIT / BLOCK_AND_RATE_LIMIT |
| `mitigation_priority` | string | NONE / LOW / MEDIUM / CRITICAL |
| `alert_generated` | boolean | Whether an alert was raised |
| `alert_level` | string | Alert level |
| `alert_type` | string | Alert type |
| `mitigation_outcome` | string | SIMULATED / NOT_REQUIRED / BLOCK_APPLIED / RATE_LIMIT_APPLIED / FAILED |

Optional fields used when present:
- `experiment_id` – correlation ID for experiment grouping
- `window_id` – 100-flow window identifier
- `ground_truth` – true class for accuracy calculation
- `confidence_uncertainty`, `renyi_evidence`, `confidence_normalized`, `renyi_normalized` – AnomalyFlow internals
- `inference_latency_ms` – inference timing

### Firewall events (`mitigation_actions.jsonl`)

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

## Integration for Person 1 (PCAP Replay)

The dashboard reads JSONL files. To integrate the PCAP replay system:

1. Write detection events to `mitigation/logs/mitigation_events.jsonl` using the schema above (one JSON object per line).
2. Write firewall lifecycle events to `mitigation/controller/mitigation_actions.jsonl`.
3. Switch the dashboard to LIVE mode (or set `STEALTHGUARD_DEFAULT_MODE=live`).
4. Use `experiment_id` and `window_id` to correlate detection events with experiment metadata.

The dashboard does not modify the ML model, AnomalyFlow, or mitigation controller.

## Switching from Sample to Live

1. In the sidebar, change "Data Mode" from SAMPLE to LIVE.
2. Ensure the StealthGuard pipeline has written to the JSONL log files.
3. The dashboard auto-refreshes every 3 seconds.

Or set the environment variable:
```bash
set STEALTHGUARD_DEFAULT_MODE=live
streamlit run dashboard/app.py
```

## Testing

```bash
cd dashboard
pip install -r requirements.txt
streamlit run app.py
```

Verify:
- All six sections load without errors
- Sample data banner shows in SAMPLE mode
- Metrics display correctly from sample JSONL
- CSV export produces valid files
- Switching to LIVE mode reads real logs (if present)

## Known Limitations

- Firewall status (ACTIVE/EXPIRED) is estimated from block_applied/block_removed pairs in logs; live nftables state is not queried.
- Classification metrics require `ground_truth` in detection events; without them, accuracy/precision/recall/F1 are shown as N/A.
- Auto-refresh uses Streamlit rerun; the browser tab must remain open.
- In LIVE mode, missing log files are handled gracefully (empty state shown).
