"""Section 1: System Overview."""

from __future__ import annotations

import streamlit as st

from components.metric_cards import metric_row, status_card
from services.metrics_calculator import overview_metrics
from config import STATUS_COLOURS


def render(state):
    st.header("System Overview")

    # Experiment filter
    exp_ids = ["All"] + sorted(
        {e.experiment_id for e in state.detection_events if e.experiment_id}
    )
    selected_exp = st.selectbox(
        "Filter by Experiment",
        exp_ids,
        key="overview_exp_filter",
        help="Show metrics for a specific experiment only, or all experiments.",
    )

    events = state.detection_events
    fw = state.firewall_events

    if selected_exp != "All":
        events = [e for e in events if e.experiment_id == selected_exp]
        fw = [e for e in fw if e.experiment_id == selected_exp]

    total_windows = len(events)
    attacks = sum(1 for e in events if e.predicted_class and e.predicted_class != "BENIGN")
    mitigations = sum(1 for e in events if e.mitigation_action and e.mitigation_action != "NO_ACTION")

    # Active firewall rules
    active_blocks = sum(1 for e in fw if e.event == "block_applied") - sum(
        1 for e in fw if e.event == "block_removed"
    )
    active_rate_limits = sum(1 for e in fw if e.event == "rate_limit_applied") - sum(
        1 for e in fw if e.event == "rate_limit_removed"
    )
    active_blocks = max(0, active_blocks)
    active_rate_limits = max(0, active_rate_limits)

    metric_row([
        ("Gateway", "RUNNING", None),
        ("Protected Server", "ACTIVE", None),
        ("Flow Collector", "RUNNING", None),
        ("ML Model", "ACTIVE", None),
    ])
    metric_row([
        ("AnomalyFlow", "ACTIVE", None),
        ("Firewall", "ACTIVE", None),
    ])

    st.divider()

    metric_row([
        ("Windows Processed", total_windows, None),
        ("Attacks Detected", attacks, None),
        ("Mitigation Actions", mitigations, None),
        ("Active Firewall Rules", active_blocks + active_rate_limits, None),
    ])

    st.divider()

    st.subheader("Component Status")
    status_col1, status_col2, status_col3, status_col4 = st.columns(4)
    with status_col1:
        status_card("Gateway", "RUNNING", STATUS_COLOURS)
    with status_col2:
        status_card("ML Model", "ACTIVE", STATUS_COLOURS)
    with status_col3:
        status_card("AnomalyFlow", "ACTIVE", STATUS_COLOURS)
    with status_col4:
        status_card("Firewall", "ACTIVE", STATUS_COLOURS)

    if selected_exp != "All":
        st.caption(f"Showing experiment: **{selected_exp}**")

    if state.errors:
        with st.expander("Load Errors", expanded=False):
            for err in state.errors:
                st.error(err)
