"""Metrics calculations built from processed DetectionEvent / FirewallRuleEvent lists."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from schemas.event_schema import (
    DashboardState,
    DetectionEvent,
    FirewallRuleEvent,
)


# ---------------------------------------------------------------------------
# Section 1: System overview
# ---------------------------------------------------------------------------

def overview_metrics(state: DashboardState) -> dict[str, Any]:
    events = state.detection_events
    fw = state.firewall_events

    total_windows = len(events)
    attacks = sum(1 for e in events if e.predicted_class and e.predicted_class != "BENIGN")
    mitigations = sum(1 for e in events if e.mitigation_action and e.mitigation_action != "NO_ACTION")

    # Active firewall rules: block_applied without a matching block_removed
    active_blocks = _count_active_blocks(fw)
    active_rate_limits = _count_active_rate_limits(fw)

    return {
        "total_windows": total_windows,
        "total_attacks": attacks,
        "total_mitigations": mitigations,
        "active_blocks": active_blocks,
        "active_rate_limits": active_rate_limits,
        "active_rules": active_blocks + active_rate_limits,
    }


def _count_active_blocks(events: list[FirewallRuleEvent]) -> int:
    applied = [e for e in events if e.event == "block_applied"]
    removed = [e for e in events if e.event == "block_removed"]
    return max(0, len(applied) - len(removed))


def _count_active_rate_limits(events: list[FirewallRuleEvent]) -> int:
    applied = [e for e in events if e.event == "rate_limit_applied"]
    removed = [e for e in events if e.event == "rate_limit_removed"]
    return max(0, len(applied) - len(removed))


# ---------------------------------------------------------------------------
# Section 3: Detection results
# ---------------------------------------------------------------------------

def detection_metrics(events: list[DetectionEvent]) -> dict[str, Any]:
    total = len(events)
    evaluated = [e for e in events if e.evaluation_status != "not_evaluated"]
    correct = sum(1 for e in evaluated if e.evaluation_status == "correct")
    incorrect = sum(1 for e in evaluated if e.evaluation_status == "incorrect")

    accuracy = (correct / len(evaluated)) if evaluated else None

    # Per-class precision / recall / F1 (only for classes with ground truth)
    classes = sorted({e.predicted_class for e in evaluated if e.predicted_class})
    per_class: dict[str, dict[str, float | None]] = {}
    for cls in classes:
        tp = sum(1 for e in evaluated if e.predicted_class == cls and e.ground_truth == cls and e.evaluation_status == "correct")
        fp = sum(1 for e in evaluated if e.predicted_class == cls and e.ground_truth != cls and e.evaluation_status == "incorrect")
        fn = sum(1 for e in evaluated if e.ground_truth == cls and e.predicted_class != cls)
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and (precision + recall) > 0
            else None
        )
        per_class[cls] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": tp + fn,
        }

    macro_precision = (
        sum(v["precision"] or 0 for v in per_class.values()) / len(per_class)
        if per_class else None
    )
    macro_recall = (
        sum(v["recall"] or 0 for v in per_class.values()) / len(per_class)
        if per_class else None
    )
    macro_f1 = (
        sum(v["f1"] or 0 for v in per_class.values()) / len(per_class)
        if per_class else None
    )

    return {
        "total_windows": total,
        "evaluated": len(evaluated),
        "correct": correct,
        "incorrect": incorrect,
        "unevaluated": total - len(evaluated),
        "accuracy": accuracy,
        "precision": macro_precision,
        "recall": macro_recall,
        "f1": macro_f1,
        "per_class": per_class,
    }


def predicted_class_distribution(events: list[DetectionEvent]) -> dict[str, int]:
    return dict(Counter(e.predicted_class or "unknown" for e in events))


def severity_distribution(events: list[DetectionEvent]) -> dict[str, int]:
    return dict(Counter(e.security_severity or "unknown" for e in events))


# ---------------------------------------------------------------------------
# Section 5: Firewall monitor
# ---------------------------------------------------------------------------

def firewall_metrics(events: list[FirewallRuleEvent]) -> dict[str, Any]:
    blocks_applied = [e for e in events if e.event == "block_applied"]
    blocks_removed = [e for e in events if e.event == "block_removed"]
    rate_applied = [e for e in events if e.event == "rate_limit_applied"]
    rate_removed = [e for e in events if e.event == "rate_limit_removed"]

    failed = [e for e in events if "error" in (e.event or "").lower() or "failed" in (e.event or "").lower()]

    return {
        "total_blocks": len(blocks_applied),
        "active_blocks": max(0, len(blocks_applied) - len(blocks_removed)),
        "removed_blocks": len(blocks_removed),
        "total_rate_limits": len(rate_applied),
        "active_rate_limits": max(0, len(rate_applied) - len(rate_removed)),
        "removed_rate_limits": len(rate_removed),
        "failed_actions": len(failed),
        "total_actions": len(blocks_applied) + len(rate_applied),
    }


def active_blocks(events: list[FirewallRuleEvent]) -> list[FirewallRuleEvent]:
    """Return block_applied events that have no matching block_removed."""
    applied = [e for e in events if e.event == "block_applied"]
    removed_ips = {e.source_ip for e in events if e.event == "block_removed" and e.source_ip}
    return [e for e in applied if e.source_ip not in removed_ips]


def active_rate_limits(events: list[FirewallRuleEvent]) -> list[FirewallRuleEvent]:
    applied = [e for e in events if e.event == "rate_limit_applied"]
    removed_ips = {e.source_ip for e in events if e.event == "rate_limit_removed" and e.source_ip}
    return [e for e in applied if e.source_ip not in removed_ips]


# ---------------------------------------------------------------------------
# Section 6: Experiment results
# ---------------------------------------------------------------------------

def experiment_summary(
    events: list[DetectionEvent], fw_events: list[FirewallRuleEvent]
) -> list[dict[str, Any]]:
    """Per-experiment summary rows."""
    by_exp: dict[str, list[DetectionEvent]] = defaultdict(list)
    for e in events:
        by_exp[e.experiment_id or "default"].append(e)

    rows: list[dict[str, Any]] = []
    for eid, evs in by_exp.items():
        total = len(evs)
        evaluated = [e for e in evs if e.ground_truth is not None]
        correct = sum(1 for e in evaluated if e.predicted_class == e.ground_truth)
        incorrect = len(evaluated) - correct
        severity_counts = Counter(e.security_severity or "unknown" for e in evs)
        mitigations = sum(1 for e in evs if e.mitigation_action and e.mitigation_action != "NO_ACTION")
        successful = sum(1 for e in evs if e.mitigation_outcome in {"APPLIED", "BLOCK_APPLIED", "RATE_LIMIT_APPLIED"})
        failed = sum(1 for e in evs if e.mitigation_outcome in {"FAILED", "NOT_REQUIRED"} and e.mitigation_action != "NO_ACTION")

        accuracy = (correct / len(evaluated)) if evaluated else None

        rows.append({
            "experiment_id": eid,
            "start_time": min((e.timestamp for e in evs if e.timestamp), default=None),
            "end_time": max((e.timestamp for e in evs if e.timestamp), default=None),
            "total_windows": total,
            "correct": correct,
            "incorrect": incorrect,
            "unevaluated": total - len(evaluated),
            "accuracy": accuracy,
            "low": severity_counts.get("LOW", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "high": severity_counts.get("HIGH", 0),
            "total_mitigations": mitigations,
            "successful_mitigations": successful,
            "failed_mitigations": failed,
        })
    rows.sort(key=lambda r: r["start_time"] or "")
    return rows
