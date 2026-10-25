# Network Mitigation Experiment

Date: 2026-10-21
Environment: Ubuntu 24.04.5 LTS in VirtualBox on macOS Tahoe
Lab: Docker Engine; isolated client, gateway, and protected-server networks
Client: 172.28.0.10
Gateway: 172.28.0.2 / 172.29.0.2
Protected server: 172.29.0.10:8080

## Controlled HTTP experiment

| Phase | Attempts | HTTP successes | HTTP failures | Server /health requests |
|---|---:|---:|---:|---:|
| Baseline | 10 | 10 | 0 | 10 |
| Mitigation active | 10 | 0 | 10 | 0 |
| Recovery | 10 | 10 | 0 | 10 |

During mitigation, the dedicated nftables rule counter reported 11 dropped
packets and 660 bytes. Packet counts must not be interpreted as HTTP request
counts.

The controller applied the rule at 2026-10-21T14:08:16.690698+00:00 and
logged removal at 2026-10-21T14:09:01.955334+00:00.

## Recovery tests

- Missing-table test: passed. Controller recreated the dedicated table and
  chain, applied and removed its rule, and HTTP returned 200.
- SIGTERM test: passed. Controller logged controller_interrupted and
  block_removed; exit code was 0, chain was empty, and HTTP returned 200.

## Evidence files

- baseline_client.log
- baseline_server.log
- baseline_metadata.txt
- mitigation_client.log
- mitigation_server.log
- mitigation_firewall.txt
- mitigation_controller.log
- mitigation_metadata.txt
- recovery_client.log
- recovery_server.log
- recovery_metadata.txt
- missing_table_test.log

Controller action history is in mitigation/controller/mitigation_actions.jsonl.

## Limitations

This is a small, controlled HTTP reachability and firewall-enforcement test.
It is not evidence of protection against all DDoS attack types or at production
scale. A forced kill, VM crash, or power loss can bypass Python cleanup.
