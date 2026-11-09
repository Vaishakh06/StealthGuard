"""Internal event schema for the StealthGuard dashboard.

This module defines the canonical internal representation that every
external event source (JSONL logs, future PCAP replay, etc.) is mapped
into.  The adapter layer in :mod:`dashboard.services.event_processor`
translates existing StealthGuard log fields into this schema.

Existing StealthGuard fields (from mitigation_events.jsonl):

    timestamp, status, client, server, port, predicted_label,
    confidence, anomalyflow_score, decision_state, security_severity,
    mitigation_action, mitigation_priority, alert_generated,
    alert_level, alert_type, mitigation_outcome

Existing firewall lifecycle fields (from mitigation_actions.jsonl):

    timestamp, event, client/server/port, duration_seconds,
    rate_per_second, burst_packets
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class DetectionEvent:
    """A single 100-flow window inference result."""

    timestamp: str
    experiment_id: Optional[str] = None
    window_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    predicted_class: Optional[str] = None
    confidence: Optional[float] = None
    confidence_uncertainty: Optional[float] = None
    renyi_evidence: Optional[float] = None
    confidence_normalized: Optional[float] = None
    renyi_normalized: Optional[float] = None
    anomalyflow_score: Optional[float] = None
    decision_state: Optional[str] = None
    security_severity: Optional[str] = None
    mitigation_action: Optional[str] = None
    mitigation_priority: Optional[str] = None
    alert_generated: bool = False
    alert_level: Optional[str] = None
    alert_type: Optional[str] = None
    mitigation_outcome: Optional[str] = None
    ground_truth: Optional[str] = None
    evaluation_status: str = "not_evaluated"
    inference_latency_ms: Optional[float] = None


@dataclass
class FirewallRuleEvent:
    """A single firewall rule lifecycle event."""

    timestamp: str
    event: str  # block_applied, block_removed, rate_limit_applied, ...
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    duration_seconds: Optional[int] = None
    rate_per_second: Optional[int] = None
    burst_packets: Optional[int] = None
    experiment_id: Optional[str] = None


@dataclass
class ExperimentMetadata:
    """Summary metadata for one experiment run."""

    experiment_id: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total_packets: Optional[int] = None
    total_flows: Optional[int] = None
    total_windows: Optional[int] = None


@dataclass
class DashboardState:
    """Aggregated view of everything the dashboard displays."""

    detection_events: list[DetectionEvent] = field(default_factory=list)
    firewall_events: list[FirewallRuleEvent] = field(default_factory=list)
    experiments: list[ExperimentMetadata] = field(default_factory=list)
    mode: str = "sample"
    sample_mode: bool = True
    last_refresh: Optional[str] = None
    errors: list[str] = field(default_factory=list)
