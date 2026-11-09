"""Reusable table components."""

from __future__ import annotations

import streamlit as st
import pandas as pd


def detection_table(events: list[dict]):
    """Render the live detection results table."""
    if not events:
        st.info("No detection events available.")
        return
    df = pd.DataFrame(events)
    display_cols = [
        c for c in [
            "timestamp", "experiment_id", "window_id", "source_ip",
            "destination_ip", "destination_port", "predicted_class",
            "confidence", "security_severity", "mitigation_action",
            "mitigation_outcome", "evaluation_status",
        ] if c in df.columns
    ]
    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True,
        height=400,
    )


def firewall_table(rows: list[dict], key: str):
    """Render a firewall action table."""
    if not rows:
        st.info("No firewall rules available.")
        return
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True, height=350, key=key)


def experiment_table(rows: list[dict]):
    """Render the experiment results table."""
    if not rows:
        st.info("No experiment data available.")
        return
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True, height=400)


def csv_export_button(df: pd.DataFrame, filename: str, label: str = "Download CSV"):
    """Render a CSV download button."""
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label=label,
        data=csv,
        file_name=filename,
        mime="text/csv",
    )
