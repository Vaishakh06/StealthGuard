"""Section 5: Firewall Action Monitor."""

from __future__ import annotations

import streamlit as st

from components.metric_cards import metric_row, status_card
from components.tables import firewall_table
from services.firewall_state import (
    firewall_summary,
    blocked_ips_table,
    rate_limited_ips_table,
)
from config import STATUS_COLOURS


def render(state):
    st.header("Firewall Action Monitor")

    summary = firewall_summary(state)

    st.subheader("Firewall Summary")
    metric_row([
        ("Blocked IPs (all time)", summary["total_blocks"], None),
        ("Currently Blocked", summary["active_blocks"], None),
        ("Rate-Limited IPs (all time)", summary["total_rate_limits"], None),
        ("Currently Rate-Limited", summary["active_rate_limits"], None),
    ])

    st.divider()

    st.subheader("A. Blocked IP Addresses")
    blocked = blocked_ips_table(state)
    col_a, col_b, col_c, col_d = st.columns(4)
    with col_a:
        st.metric("Total Blocks", summary["total_blocks"])
    with col_b:
        st.metric("Currently Active", summary["active_blocks"])
    with col_c:
        expired = sum(1 for r in blocked if r["status"] == "EXPIRED")
        st.metric("Expired", expired)
    with col_d:
        removed = sum(1 for r in blocked if r["status"] == "REMOVED")
        st.metric("Removed", removed)

    if blocked:
        # Add status colour chips
        for row in blocked:
            status = row["status"]
            colour = STATUS_COLOURS.get(status, "#9ca3af")
            row["_status_colour"] = colour

        st.dataframe(
            blocked,
            use_container_width=True,
            hide_index=True,
            height=350,
            column_config={
                "status": st.column_config.TextColumn(
                    "Status",
                    help="ACTIVE = block currently in force, EXPIRED = duration elapsed, REMOVED = rule explicitly removed",
                ),
                "_status_colour": None,
            },
        )
    else:
        st.info("No block events logged yet.")

    st.divider()

    st.subheader("B. Rate-Limited IP Addresses")
    rate_limited = rate_limited_ips_table(state)
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.metric("Total Rate-Limits", summary["total_rate_limits"])
    with col_b:
        st.metric("Currently Active", summary["active_rate_limits"])
    with col_c:
        removed = sum(1 for r in rate_limited if r["status"] == "REMOVED")
        st.metric("Removed", removed)

    if rate_limited:
        st.dataframe(
            rate_limited,
            use_container_width=True,
            hide_index=True,
            height=350,
            column_config={
                "status": st.column_config.TextColumn(
                    "Status",
                    help="ACTIVE = rate limit currently in force, EXPIRED = duration elapsed, REMOVED = rule explicitly removed",
                ),
            },
        )
    else:
        st.info("No rate-limit events logged yet.")

    st.divider()

    st.subheader("C. Firewall Summary Details")
    metric_row([
        ("Total Block Actions", summary["total_blocks"], None),
        ("Active Block Rules", summary["active_blocks"], None),
        ("Total Rate-Limit Actions", summary["total_rate_limits"], None),
        ("Active Rate-Limit Rules", summary["active_rate_limits"], None),
    ])

    st.info(
        "Firewall state is derived from historical lifecycle log events "
        "(block_applied / block_removed / rate_limit_applied / "
        "rate_limit_removed). Status: ACTIVE = rule currently in force, "
        "EXPIRED = duration has elapsed, REMOVED = rule explicitly removed. "
        "This dashboard is read-only: no firewall commands are executed from here."
    )
