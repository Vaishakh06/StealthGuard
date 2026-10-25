# Major Project — Mitigation System Architecture and Work Division

**Document purpose:** Source of truth for continuing the mitigation-system implementation across conversations and between two team members.

## 1. Project status and guiding rule

The existing project pipeline is already implemented through mitigation recommendations:

Network traffic → preprocessing → statistical feature engineering → CNN + Bi-LSTM + Attention → attack classification → AnomalyFlow decision layer → security severity → mitigation recommendation → dashboard charts.

**Do not rebuild or retrain the existing ML pipeline by default.** First inspect the existing notebooks and artifacts, preserve their interfaces, and add the network environment and enforcement components around them. Retraining or redesign is considered only if inspection proves a compatibility issue.

## 2. Chosen high-level approach

Build a local, isolated, software-only network lab. No physical server, hardware gateway, hardware sensor, or paid cloud service is required for the initial demonstration.

Preferred starting point: Docker Compose, with Linux networking and `nftables` for enforcement. Confirm each person's host OS and Docker support before providing exact installation commands.

The network must be routed so that test traffic actually passes through the gateway. A normal Docker bridge alone does not guarantee that a gateway firewall will see or control the traffic.

### Logical architecture

1. **Traffic generators**
   - Legitimate client sends ordinary requests.
   - Controlled attack generator creates bounded, lab-only DDoS-like traffic.
2. **Linux gateway / enforcement point**
   - Two network interfaces: client-side and server-side.
   - Forwards traffic between isolated networks.
   - Provides the enforcement point for `nftables`.
3. **Traffic sensor**
   - Use `tcpdump` and/or Python packet capture to observe traffic.
   - Aggregate packets into flow/window features as appropriate.
4. **Existing ML detection pipeline**
   - Use the saved model, feature schema, preprocessing transformations and class mapping.
   - CNN + Bi-LSTM + Attention → attack classification → AnomalyFlow → severity → recommendation.
5. **Mitigation controller**
   - Validate recommendations and targets.
   - Start in dry-run mode.
   - Apply approved, lab-scoped firewall actions only after dry-run validation.
   - Record action results and provide rule expiry/cleanup and recovery.
6. **Protected server**
   - Simple local Python web server, preferably with a health-check endpoint.
   - Record request success, latency and request counts.
7. **Dashboard and evaluation**
   - Preserve existing charts.
   - Add detection events, mitigation status, traffic before/after, legitimate request success, response latency, detection-to-action time, rule execution status and recovery.

## 3. Network environment and tools

| Component | Proposed tool | Purpose |
|---|---|---|
| Container orchestration | Docker Compose | Starts and connects lab services |
| Linux environment | Linux container or VM | Runs gateway and server networking components |
| Routing | Linux networking | Forwards traffic between client and server networks |
| Firewall | `nftables` | Blocks or rate-limits selected lab traffic |
| Packet capture | `tcpdump`; Wireshark optional | Observes traffic and helps debug |
| Traffic generators | Python | Generates benign and controlled test traffic |
| Protected service | Python HTTP server | Gives a measurable target |
| ML integration | Existing Python/model artifacts | Reuses the current detector |
| Mitigation controller | Python | Validates, executes and logs actions |
| Dashboard | Existing dashboard code | Displays detection and mitigation outcomes |

Keep the initial environment local to avoid cloud costs. Docker Desktop licensing depends on its terms and the user's situation; ordinary individual student use is generally covered by its free-use terms. Do not promise all possible organizational use is free.

## 4. Feature compatibility is a critical dependency

Before building live inference, inspect the notebooks and model artifacts to determine:
- exact feature columns and order;
- expected input shape;
- preprocessing/scaler objects;
- label encoder and class mapping, if any;
- how flow or time-window features were generated during training;
- what Notebook 06 and Notebook 07 output;
- whether live captured traffic can produce compatible features.

Raw packets must not be passed directly to a model trained on engineered features. If compatibility is not established, validate with existing processed samples or traffic replay before claiming live end-to-end ML detection.

## 5. Mitigation behavior

Start in **dry-run mode**: accept an event, validate the proposed action, and log what would happen without changing traffic.

Possible actions:
1. Alert/log only.
2. Rate-limit a selected lab traffic flow.
3. Temporarily block a validated source/flow in the isolated lab.
4. Expire and remove temporary rules, with a manual recovery procedure.

Do not execute arbitrary shell commands from model output. Use allowlisted actions, validated lab-only targets and least necessary privileges. A source IP alone may not reliably identify an attacker, particularly if spoofing is possible. Enable enforcement only after dry-run tests pass.

## 6. Team division: two people, one Mac and one Windows computer

The roles are responsibilities, not strict OS restrictions. Either person could run either role; the Mac/Windows assignments below are the agreed default.

### Person 1 — Mac: network and firewall
Owns:
- verify Docker installation;
- create client-side and server-side isolated networks;
- configure the Linux gateway and forwarding;
- create the protected web server;
- create legitimate and bounded lab-only attack traffic generators;
- configure packet capture;
- implement and test `nftables` actions, temporary rules, expiry and cleanup;
- measure server-side traffic and connectivity before/after enforcement.

**Deliverable:** repeatable isolated network lab with verified forwarding and firewall enforcement.

### Person 2 — Windows: ML integration and mitigation logic
Owns:
- inspect Notebook 06 and Notebook 07;
- inspect saved model and preprocessing artifacts;
- document input schema, model output and recommendation format;
- build an inference adapter that reuses the existing model;
- define a shared event schema;
- implement policy validation, dry-run mode, event logging and execution-status handling;
- integrate the controller with Person 1's gateway interface;
- extend the dashboard and prepare evaluation results.

**Deliverable:** validated ML-to-mitigation flow with observable execution status and dashboard integration.

### Shared responsibilities
- Agree on interfaces early.
- Test together at every integration checkpoint.
- Keep existing notebooks/artifacts unchanged until integration is validated.
- Document commands and results so both people can reproduce the demo.

## 7. Integration checkpoints

1. **Independent setup:** Person 1 starts a basic gateway/server lab; Person 2 inspects notebooks/artifacts.
2. **Interface agreement:** document gateway API/command interface, target representation, event schema and action response.
3. **Dry-run integration:** send a sample detection event through the controller without altering traffic.
4. **Controlled enforcement:** test approved firewall actions only inside the isolated lab.
5. **End-to-end evaluation:** verify detection, rule application, server impact, legitimate request success and recovery.
6. **Dashboard/report:** display actual measurements, not assumed improvements.

Illustrative event schema (must be adapted to the real Notebook 07 outputs):

```json
{
  "event_id": "test-001",
  "predicted_class": "example_attack_class",
  "severity": "high",
  "recommended_action": "temporary_block",
  "target": "lab_test_source",
  "dry_run": true
}
```

The controller must resolve `target` to a validated lab address or flow and reject arbitrary targets.

## 8. Proposed repository structure

Adapt to the existing repository rather than renaming files unnecessarily.

```text
Major_Project/
├── notebooks/
│   ├── Notebook_06.ipynb
│   ├── Notebook_07.ipynb
│   ├── Model_comparison_Notebook.ipynb
│   └── Dashboard_Notebook.ipynb
├── artifacts/
│   ├── model/
│   └── preprocessing/
├── mitigation_system/
│   ├── config/
│   ├── traffic/
│   ├── detection/
│   ├── controller/
│   ├── monitoring/
│   └── tests/
├── network_lab/
│   ├── compose.yaml
│   ├── gateway/
│   ├── client/
│   ├── attack_generator/
│   └── protected_server/
├── results/
│   ├── traffic/
│   ├── mitigation_events/
│   └── evaluation/
└── dashboard/
```

Do not commit credentials, large raw datasets or machine-specific paths. Share the project through Git if practical; otherwise use a shared folder and agreed versions.

## 9. Suggested work schedule

This is a planning estimate, not a guarantee.

| Days | Person 1 — Mac | Person 2 — Windows |
|---|---|---|
| 1–2 | Verify Docker; run simple container | Inspect notebooks and artifacts |
| 3–4 | Basic gateway and server | Validate model inputs and event schema |
| 5–6 | Capture traffic and test forwarding | Inference adapter and dry-run controller |
| 7–8 | Firewall actions and cleanup | Controller/gateway integration |
| 9–10 | Mitigation and recovery tests | Dashboard integration and metrics |
| 11–12 | Support end-to-end testing | Evaluation and demo documentation |

Prioritize one reliable end-to-end demonstration over adding extra features.

## 10. Required files to inspect first

Request:
1. Notebook 07 — mitigation recommendation.
2. Notebook 06 — decision state and severity.
3. Saved trained model and preprocessing/scaler objects.
4. Feature column list and class mapping/label encoder, if used.
5. Model comparison notebook, if final model choice is documented there.
6. Current dashboard notebook/source.
7. Supporting configuration, requirements and sample processed/mitigation output.

Avoid uploading a huge raw dataset unless it becomes necessary.

## 11. Demonstration scenarios and evidence

Run these scenarios in the isolated lab:
1. Normal traffic, mitigation disabled.
2. Controlled attack traffic, mitigation disabled.
3. Same attack scenario, mitigation enabled.
4. Normal traffic after rule removal.

Record:
- attack detection rate and false-positive rate where ground truth is available;
- attack traffic reaching the server before/after;
- legitimate request success;
- response latency;
- detection-to-action time;
- firewall rule execution success;
- recovery time.

Do not claim mitigation success from a successful firewall command alone; verify traffic and service metrics.

## 12. Continuity rule for future conversations

Treat this document as the source of truth for the Major Project mitigation system. Continue with the same architecture, work division and safety boundaries unless the user explicitly approves a change. Before coding, inspect the uploaded notebooks and artifacts and adapt to their actual interfaces. Do not claim that persistent ChatGPT memory was updated unless a memory feature is available and the update actually succeeds.

**Next action:** upload Notebook 06 and Notebook 07, plus model/preprocessing artifacts if available. Person 1 can meanwhile verify Docker on the Mac; Person 2 can inspect the existing ML interfaces on Windows.
