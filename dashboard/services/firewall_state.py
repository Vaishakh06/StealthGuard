"""Firewall state derived from lifecycle log events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from services.metrics_calculator import (
    active_blocks,
    active_rate_limits,
    firewall_metrics,
)


def firewall_summary(state) -> dict[str, Any]:
    """Build the firewall summary card block."""
    metrics = firewall_metrics(state.firewall_events)
    return {
        "total_blocks": metrics["total_blocks"],
        "active_blocks": metrics["active_blocks"],
        "total_rate_limits": metrics["total_rate_limits"],
        "active_rate_limits": metrics["active_rate_limits"],
        "failed_actions": metrics["failed_actions"],
        "total_actions": metrics["total_actions"],
    }


def _status_from_events(
    applied_events: list[Any],
    removed_events: list[Any],
    now: datetime,
) -> list[dict[str, Any]]:
    """Build rows with ACTIVE / EXPIRED / REMOVED status for each block."""
    removed_ips = {e.source_ip for e in removed_events if e.source_ip}
    rows: list[dict[str, Any]] = []
    for e in applied_events:
        ip = e.source_ip or "unknown"
        if ip in removed_ips:
            status = "REMOVED"
        else:
            # Determine if the block duration has elapsed
            expiry = _expiration(e.timestamp, e.duration_seconds)
            if expiry is None:
                status = "ACTIVE"
            else:
                try:
                    expiry_dt = datetime.fromisoformat(
                        expiry.replace("Z", "+00:00")
                    )
                    if expiry_dt <= now:
                        status = "EXPIRED"
                    else:
                        status = "ACTIVE"
                except Exception:
                    status = "ACTIVE"

        rows.append({
            "source_ip": ip,
            "destination_ip": e.destination_ip or "unknown",
            "destination_port": e.destination_port or "unknown",
            "predicted_class": getattr(e, "predicted_class", "unknown") or "unknown",
            "security_severity": getattr(e, "security_severity", "unknown") or "unknown",
            "block_start": e.timestamp,
            "duration_seconds": e.duration_seconds,
            "expiration": expiry,
            "remaining": _remaining(e.timestamp, e.duration_seconds, now),
            "status": status,
        })
    return rows


def blocked_ips_table(state) -> list[dict[str, Any]]:
    """All block events with ACTIVE / EXPIRED / REMOVED status."""
    applied = [e for e in state.firewall_events if e.event == "block_applied"]
    removed = [e for e in state.firewall_events if e.event == "block_removed"]
    now = datetime.now(timezone.utc)
    return _status_from_events(applied, removed, now)


def rate_limited_ips_table(state) -> list[dict[str, Any]]:
    """All rate-limit events with ACTIVE / EXPIRED / REMOVED status."""
    applied = [e for e in state.firewall_events if e.event == "rate_limit_applied"]
    removed = [e for e in state.firewall_events if e.event == "rate_limit_removed"]
    now = datetime.now(timezone.utc)
    return _status_from_events(applied, removed, now)


def _expiration(timestamp: str | None, duration: int | None) -> str | None:
    if not timestamp or duration is None:
        return None
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return (dt + timedelta(seconds=duration)).isoformat()
    except Exception:
        return None


def _remaining(
    timestamp: str | None, duration: int | None, now: datetime
) -> str | None:
    if not timestamp or duration is None:
        return None
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        expiry = dt + timedelta(seconds=duration)
        delta = expiry - now
        if delta.total_seconds() <= 0:
            return "Expired"
        minutes = int(delta.total_seconds() // 60)
        seconds = int(delta.total_seconds() % 60)
        return f"{minutes}m {seconds}s"
    except Exception:
        return None
