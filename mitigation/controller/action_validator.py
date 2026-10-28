class ActionValidationError(ValueError):
    """Raised when a mitigation action is not allowed."""


ALLOWED_ACTIONS = {
    "NO_ACTION",
    "MONITOR",
    "INVESTIGATE",
    "ALERT_AND_LOG",
    "RATE_LIMIT",
    "BLOCK_AND_RATE_LIMIT",
}


def validate_action(action):
    if not isinstance(action, str):
        raise ActionValidationError(
            "Mitigation action must be a string."
        )

    action = action.strip().upper()

    if action not in ALLOWED_ACTIONS:
        raise ActionValidationError(
            f"Unsupported mitigation action: {action}"
        )

    return action