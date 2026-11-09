"""Event processor: translates StealthGuard log records into the
dashboard's internal :mod:`dashboard.schemas.event_schema` representation."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import (
    ALLOWED_ACTIONS,
    ALLOWED_DECISION_STATES,
    ALLOWED_SEVERITIES,
    MITIGATION_ACTIONS_LOG,
    MITIGATION_EVENTS_LOG,
)
from services.log_reader import read_jsonl, tail_jsonl
from schemas.event_schema import (
    DashboardState,
    DetectionEvent,
    ExperimentMetadata,
    FirewallRuleEvent,
)

logger = logging.getLogger("stealthguard.dashboard.event_processor")

# ---------------------------------------------------------------------------
# Field mapping: StealthGuard -> dashboard internal schema
# ---------------------------------------------------------------------------

_DETECTION_FIELD_MAP = {
    "client": "source_ip",
    "server": "destination_ip",
    "port": "destination_port",
    "predicted_label": "predicted_class",
    "security_severity": "security_severity",
    "mitigation_action": "mitigation_action",
    "mitigation_priority": "mitigation_priority",
    "mitigation_outcome": "mitigation_outcome",
    "decision_state": "decision_state",
    "anomalyflow_score": "anomalyflow_score",
    "confidence": "confidence",
}


def _normalise_severity(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip().upper()
    if s in ALLOWED_SEVERITIES:
        return s
    return s


def _normalise_decision_state(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip().upper()
    if s in ALLOWED_DECISION_STATES:
        return s
    return s


def _normalise_action(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip().upper()
    if s in ALLOWED_ACTIONS:
        return s
    return s


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value: Any) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return str(value)


def map_detection_record(record: dict) -> DetectionEvent:
    """Map one StealthGuard mitigation-events record to DetectionEvent."""
    mapped: dict[str, Any] = {"timestamp": _parse_timestamp(record.get("timestamp"))}

    for sg_field, internal_field in _DETECTION_FIELD_MAP.items():
        if sg_field in record:
            mapped[internal_field] = record[sg_field]

    mapped["security_severity"] = _normalise_severity(mapped.get("security_severity"))
    mapped["decision_state"] = _normalise_decision_state(mapped.get("decision_state"))
    mapped["mitigation_action"] = _normalise_action(mapped.get("mitigation_action"))
    mapped["confidence"] = _to_float(mapped.get("confidence"))
    mapped["anomalyflow_score"] = _to_float(mapped.get("anomalyflow_score"))
    mapped["confidence_uncertainty"] = _to_float(record.get("confidence_uncertainty"))
    mapped["renyi_evidence"] = _to_float(record.get("renyi_evidence"))
    mapped["confidence_normalized"] = _to_float(record.get("confidence_normalized"))
    mapped["renyi_normalized"] = _to_float(record.get("renyi_normalized"))
    mapped["destination_port"] = _to_int(mapped.get("destination_port"))
    mapped["alert_generated"] = bool(record.get("alert_generated", False))
    mapped["alert_level"] = record.get("alert_level")
    mapped["alert_type"] = record.get("alert_type")
    mapped["experiment_id"] = record.get("experiment_id")
    mapped["window_id"] = record.get("window_id")
    mapped["ground_truth"] = record.get("ground_truth")
    mapped["inference_latency_ms"] = _to_float(record.get("inference_latency_ms"))

    # Compute evaluation status from ground truth vs predicted class
    gt = mapped.get("ground_truth")
    pred = mapped.get("predicted_class")
    if gt is not None and pred is not None:
        mapped["evaluation_status"] = "correct" if str(gt).strip() == str(pred).strip() else "incorrect"
    else:
        mapped["evaluation_status"] = "not_evaluated"

    return DetectionEvent(**mapped)


def map_firewall_record(record: dict) -> FirewallRuleEvent:
    """Map one StealthGuard firewall-actions record to FirewallRuleEvent."""
    return FirewallRuleEvent(
        timestamp=_parse_timestamp(record.get("timestamp")),
        event=str(record.get("event", "unknown")),
        source_ip=record.get("client") or record.get("source_ip"),
        destination_ip=record.get("server") or record.get("destination_ip"),
        destination_port=_to_int(
            record.get("port")
            or record.get("destination_port")
            or record.get("SERVER_PORT")
        ),
        duration_seconds=_to_int(record.get("duration_seconds")),
        rate_per_second=_to_int(record.get("rate_per_second")),
        burst_packets=_to_int(record.get("burst_packets")),
        experiment_id=record.get("experiment_id"),
    )


def load_state(
    mode: str = "sample",
    sample_events_path: Path | None = None,
    sample_actions_path: Path | None = None,
) -> DashboardState:
    """Load detection and firewall events into a DashboardState.

    In *sample* mode the sample data files are used; in *live* mode the
    real StealthGuard log files are read.  Missing files produce an
    empty state rather than crashing.
    """
    state = DashboardState(mode=mode, sample_mode=(mode == "sample"))

    # --- detection events ---
    det_path: Path
    if mode == "sample" and sample_events_path is not None:
        det_path = sample_events_path
    else:
        det_path = MITIGATION_EVENTS_LOG

    try:
        raw = read_jsonl(det_path)
        for rec in raw:
            try:
                state.detection_events.append(map_detection_record(rec))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping bad detection record: %s", exc)
                state.errors.append(f"Detection record parse error: {exc}")
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load detection events: %s", exc)
        state.errors.append(f"Detection events load error: {exc}")

    # --- firewall events ---
    fw_path: Path
    if mode == "sample" and sample_actions_path is not None:
        fw_path = sample_actions_path
    else:
        fw_path = MITIGATION_ACTIONS_LOG

    try:
        raw = read_jsonl(fw_path)
        for rec in raw:
            try:
                state.firewall_events.append(map_firewall_record(rec))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping bad firewall record: %s", exc)
                state.errors.append(f"Firewall record parse error: {exc}")
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load firewall events: %s", exc)
        state.errors.append(f"Firewall events load error: {exc}")

    # --- experiments ---
    state.experiments = _derive_experiments(state.detection_events)

    state.last_refresh = datetime.now(timezone.utc).isoformat()
    return state


def _derive_experiments(events: list[DetectionEvent]) -> list[ExperimentMetadata]:
    """Group detection events by experiment_id and summarise."""
    by_exp: dict[str, list[DetectionEvent]] = {}
    for ev in events:
        eid = ev.experiment_id or "default"
        by_exp.setdefault(eid, []).append(ev)

    experiments: list[ExperimentMetadata] = []
    for eid, evs in by_exp.items():
        timestamps = [ev.timestamp for ev in evs if ev.timestamp]
        experiments.append(
            ExperimentMetadata(
                experiment_id=eid,
                start_time=min(timestamps) if timestamps else None,
                end_time=max(timestamps) if timestamps else None,
                total_windows=len(evs),
            )
        )
    experiments.sort(key=lambda e: e.start_time or "")
    return experiments


def refresh_state(
    state: DashboardState,
    since_line_det: int = 0,
    since_line_fw: int = 0,
    sample_events_path: Path | None = None,
    sample_actions_path: Path | None = None,
) -> tuple[DashboardState, int, int]:
    """Append-only refresh: read only new lines since the given offsets.

    Returns (updated_state, new_det_lines, new_fw_lines).
    """
    mode = state.mode
    det_path = sample_events_path if mode == "sample" else MITIGATION_EVENTS_LOG
    fw_path = sample_actions_path if mode == "sample" else MITIGATION_ACTIONS_LOG

    new_det, total_det = tail_jsonl(det_path, since_line_det)
    new_fw, total_fw = tail_jsonl(fw_path, since_line_fw)

    for rec in new_det:
        try:
            state.detection_events.append(map_detection_record(rec))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping new detection record: %s", exc)
            state.errors.append(f"Detection refresh error: {exc}")

    for rec in new_fw:
        try:
            state.firewall_events.append(map_firewall_record(rec))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping new firewall record: %s", exc)
            state.errors.append(f"Firewall refresh error: {exc}")

    state.experiments = _derive_experiments(state.detection_events)
    state.last_refresh = datetime.now(timezone.utc).isoformat()
    return state, total_det, total_fw
