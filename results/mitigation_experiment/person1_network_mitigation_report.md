# Network Lab and Firewall Mitigation — Person 1 Report

## 1. Objective

Implement and evaluate an isolated network lab for the Major Project's
DDoS detection and mitigation system. Person 1's scope covers network
isolation, traffic generation, gateway forwarding, firewall enforcement,
packet capture, and before/during/after measurements.

The existing machine-learning pipeline and mitigation recommendation
engine are outside the scope of this implementation. They are not rebuilt
or retrained as part of these experiments.

## 2. System Architecture

The existing project pipeline is:

Network Traffic
-> Preprocessing
-> Statistical Feature Engineering
-> CNN + Bi-LSTM + Attention
-> Attack Classification
-> AnomalyFlow Decision Layer
-> Security Severity
-> Mitigation Recommendation
-> Alerts and Dashboard

The network enforcement lab is a separate implementation component:

Client Container
-> Gateway Container with nftables
-> Protected HTTP Server Container

The client and server use separate isolated Docker bridge networks.
The gateway connects both networks and routes traffic between them.

## 3. Environment

- Host: Intel Mac running macOS Tahoe 26
- Virtualization: VirtualBox
- Guest: Ubuntu 24.04.5 LTS
- Allocated VM resources: 6 GB RAM and 2 CPUs
- Container runtime: Docker Engine and Docker Compose inside Ubuntu
- Shared project directory: /media/sf_CyberProject

### Network addressing

| Component | Address |
|---|---|
| Client | 172.28.0.10 |
| Gateway client-side interface | 172.28.0.2 |
| Gateway server-side interface | 172.29.0.2 |
| Protected server | 172.29.0.10 |
| HTTP service | TCP port 8080 |

Client network: 172.28.0.0/24
Server network: 172.29.0.0/24

The protected server exposes a /health endpoint returning JSON.
Client requests traverse the gateway between the isolated networks.

## 4. Implementation

### 4.1 Network lab

The Docker Compose configuration defines three services:
client, gateway, and protected_server. The gateway has forwarding
enabled and connects to both networks. Static routes direct client
traffic through the gateway and provide a return path from the server.

### 4.2 Traffic generation

The existing attack_generator/http_burst.py script sends 20 HTTP
requests to the protected server with a 0.5-second delay.

This is a bounded HTTP-burst test. It is not a comprehensive or
high-volume DDoS simulation.

For the controlled mitigation experiment, a separate batch of
10 HTTP requests was used in each phase.

### 4.3 Packet capture

Existing packet captures are stored at:

- results/traffic_captures/normal_traffic.pcap
- results/traffic_captures/burst_traffic.pcap

These captures were collected on October 15, 2026. The controlled
before/during/after experiment was conducted on October 21, 2026.
They are separate evidence sets.

Packet counts can include TCP handshakes, retransmissions, and
observations from multiple interfaces. Therefore, packet counts are
not treated as equivalent to unique HTTP requests.

### 4.4 Firewall enforcement

A dedicated nftables table named inet mitigation contains a forward
chain with an accept policy. A temporary rule matches:

- Source address: 172.28.0.10
- Destination address: 172.29.0.10
- TCP destination port: 8080
- Action: drop

The rule is restricted to the project's isolated lab traffic.

The controller invokes nft through docker exec against cp-gateway.
It uses an allowlisted source, destination, and port; validates the
requested duration to 1–60 seconds; tags its rule with the comment
temporary-lab-mitigation; and records JSON Lines events.

Cleanup deletes only rules carrying the controller's unique comment.
The controller creates its dedicated table and chain if they are
missing. Docker's NAT table is not modified by this implementation.

### 4.5 Controller recovery

The controller was updated to respond to SIGINT and SIGTERM by
requesting orderly shutdown and executing cleanup.

Testing confirmed that:
- A missing dedicated mitigation table and chain can be recreated.
- A temporary rule can be applied and removed.
- SIGTERM triggers cleanup in the tested case.
- The chain was empty after cleanup.
- HTTP connectivity returned after cleanup.

Python cleanup cannot be guaranteed after SIGKILL, VM failure,
host power loss, or other abrupt termination. An independent recovery
mechanism has not been implemented.

## 5. Controlled Experiment Method

Three phases were measured:

1. Baseline: send 10 HTTP requests with mitigation inactive.
2. Mitigation: activate the temporary firewall rule, confirm the
   controller's block_applied event, and send 10 requests.
3. Recovery: after rule removal, send 10 more HTTP requests.

The client logs record HTTP outcomes. The protected server's application
logs record incoming GET requests and paths. Server-side log counts,
rather than raw packet counts, are used to estimate requests handled
by the application.

## 6. Results

| Metric | Baseline | Mitigation active | Recovery |
|---|---:|---:|---:|
| Client requests attempted | 10 | 10 | 10 |
| HTTP successes | 10 | 0 | 10 |
| HTTP failures/timeouts | 0 | 10 | 0 |
| Server /health requests logged | 10 | 0 | 10 |

During the mitigation phase, the nftables rule counter showed
11 dropped packets and 660 bytes. These are packet-level measurements,
not HTTP request counts.

Controller timestamps:
- Rule applied: 2026-10-21T14:08:16.690698+00:00
- Rule removed: 2026-10-21T14:09:01.955334+00:00

The observed interval was approximately 45 seconds.

### Interpretation

In this controlled experiment, all 10 baseline requests succeeded.
While the rule was active, all 10 client requests timed out and the
server logged zero /health requests for the measured phase. After
the rule was removed, all 10 recovery requests succeeded and the
server logged 10 /health requests.

These observations support successful enforcement and recovery for
the tested source, destination, protocol, and port in this lab.

They do not demonstrate protection against all DDoS attack types,
large-scale traffic, distributed sources, or production workloads.

## 7. Evidence Inventory

Experiment evidence:
- results/mitigation_experiment/baseline_client.log
- results/mitigation_experiment/baseline_server.log
- results/mitigation_experiment/baseline_metadata.txt
- results/mitigation_experiment/mitigation_client.log
- results/mitigation_experiment/mitigation_server.log
- results/mitigation_experiment/mitigation_firewall.txt
- results/mitigation_experiment/mitigation_controller.log
- results/mitigation_experiment/mitigation_metadata.txt
- results/mitigation_experiment/recovery_client.log
- results/mitigation_experiment/recovery_server.log
- results/mitigation_experiment/recovery_metadata.txt
- results/mitigation_experiment/missing_table_test.log
- results/mitigation_experiment/experiment_summary.md

Controller implementation and history:
- mitigation/controller/mitigation_controller.py
- mitigation/controller/mitigation_controller.py.bak
- mitigation/controller/mitigation_actions.jsonl

Packet captures:
- results/traffic_captures/normal_traffic.pcap
- results/traffic_captures/burst_traffic.pcap

The SIGTERM test output was captured in /tmp/mitigation_signal_test.log
inside the Ubuntu VM. Copy it into the experiment directory if it needs
to be retained with the shared project evidence.

## 8. Limitations and Future Work

- The HTTP burst is a bounded functional test, not a comprehensive DDoS
  workload.
- The experiment used one client and one protected HTTP endpoint.
- The results establish behavior for this rule and traffic pattern only.
- Packet counts must not be used as a proxy for unique HTTP requests.
- The temporary rule can be removed on normal controller completion and
  tested graceful termination, but abrupt process or VM failure can leave
  a rule active.
- Independent watchdog-based or startup recovery is future work.
- Before/after throughput, latency under load, multiple traffic sources,
  and longer-duration tests would be needed for broader performance claims.
- The firewall interface must be coordinated with Person 2 before ML
  inference or mitigation recommendations are allowed to trigger it.
- Any production deployment would require additional access control,
  authorization, audit, failure handling, and security testing.

## 9. Conclusion

Person 1 implemented an isolated three-container network lab, routed
traffic through a Linux gateway, captured traffic, and implemented
temporary nftables enforcement through a Python controller.

The controlled experiment showed 10 successful requests before
mitigation, zero requests handled by the server during the measured
blocking phase, and 10 successful requests after recovery. Missing-table
initialization and graceful SIGTERM cleanup were also verified.

The results demonstrate lab-level firewall enforcement and recovery
for the tested traffic. They do not establish universal or production-
scale DDoS protection. Integration with the ML mitigation interface and
independent recovery from abrupt failures remain future work.
