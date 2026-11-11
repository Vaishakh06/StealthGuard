"""Section 1: System Overview."""

from __future__ import annotations

import streamlit as st

from components.metric_cards import metric_row, status_card
from services.metrics_calculator import overview_metrics
from config import STATUS_COLOURS


def render(state):
    st.header("System Overview")

    metrics = overview_metrics(state)

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
        ("Windows Processed", metrics["total_windows"], None),
        ("Attacks Detected", metrics["total_attacks"], None),
        ("Mitigation Actions", metrics["total_mitigations"], None),
        ("Active Firewall Rules", metrics["active_rules"], None),
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

    if state.errors:
        with st.expander("Load Errors", expanded=False):
            for err in state.errors:
                st.error(err)
