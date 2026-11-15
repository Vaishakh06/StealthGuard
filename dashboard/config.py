"""StealthGuard Dashboard configuration."""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Data source paths (configurable via environment variables)
# ---------------------------------------------------------------------------

MITIGATION_EVENTS_LOG = Path(
    os.getenv(
        "STEALTHGUARD_MITIGATION_EVENTS_LOG",
        str(PROJECT_ROOT / "mitigation" / "logs" / "mitigation_events.jsonl"),
    )
)

MITIGATION_ACTIONS_LOG = Path(
    os.getenv(
        "STEALTHGUARD_MITIGATION_ACTIONS_LOG",
        str(
            PROJECT_ROOT
            / "mitigation"
            / "controller"
            / "mitigation_actions.jsonl"
        ),
    )
)

SAMPLE_DATA_DIR = PROJECT_ROOT / "dashboard" / "sample_data"

# ---------------------------------------------------------------------------
# Dashboard behaviour
# ---------------------------------------------------------------------------

REFRESH_INTERVAL_SECONDS = int(
    os.getenv("STEALTHGUARD_REFRESH_INTERVAL", "3")
)

DEFAULT_MODE = os.getenv("STEALTHGUARD_DEFAULT_MODE", "sample")

# ---------------------------------------------------------------------------
# Severity / action colour scheme (consistent across the app)
# ---------------------------------------------------------------------------

SEVERITY_COLOURS = {
    "NORMAL": "#10b981",   # emerald-500
    "LOW": "#3b82f6",      # blue-500
    "MEDIUM": "#f59e0b",   # amber-500
    "HIGH": "#ef4444",     # red-500
    "CRITICAL": "#7f1d1d", # red-900
    "MONITOR": "#6b7280",  # gray-500
    "INVESTIGATE": "#8b5cf6",  # violet-500
}

ACTION_COLOURS = {
    "ALLOW": "#10b981",      # emerald-500
    "MONITOR": "#3b82f6",    # blue-500
    "RATE_LIMIT": "#f59e0b", # amber-500
    "TEMPORARY_BLOCK": "#ef4444",  # red-500
    "INVESTIGATE": "#8b5cf6",  # violet-500
}

STATUS_COLOURS = {
    "ACTIVE": "#10b981",
    "EXPIRED": "#6b7280",
    "FAILED": "#ef4444",
    "REMOVED": "#6b7280",
    "APPLIED": "#10b981",
    "DRY_RUN": "#3b82f6",
    "SIMULATED": "#3b82f6",
    "NOT_REQUIRED": "#6b7280",
    "TEMPORARY_BLOCK_APPLIED": "#ef4444",
    "RATE_LIMIT_APPLIED": "#f59e0b",
    "UNKNOWN": "#9ca3af",
}

# ---------------------------------------------------------------------------
# Allowed severities / decision states / actions for the 3-class model
# ---------------------------------------------------------------------------

ALLOWED_SEVERITIES = ["NORMAL", "LOW", "MEDIUM", "HIGH", "MONITOR", "INVESTIGATE"]
ALLOWED_DECISION_STATES = ["NORMAL", "SUSPICIOUS", "HIGH_EVIDENCE"]
ALLOWED_ACTIONS = [
    "ALLOW",
    "MONITOR",
    "RATE_LIMIT",
    "TEMPORARY_BLOCK",
    "INVESTIGATE",
]

MODES = ["sample", "live"]
