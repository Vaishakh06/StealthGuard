"""Section 6: Experiment Results and Performance."""

from __future__ import annotations

import streamlit as st
import pandas as pd

from components.charts import events_over_time_chart
from components.metric_cards import metric_row
from components.tables import experiment_table, csv_export_button
from services.metrics_calculator import experiment_summary


def render(state):
    st.header("Experiment Results and Performance")

    events = state.detection_events
    summaries = experiment_summary(events, state.firewall_events)

    if not summaries:
        st.info("No experiment data available.")
        return

    # --- Filter controls ---
    exp_ids = ["All"] + [s["experiment_id"] for s in summaries]
    selected_exp = st.selectbox("Filter by Experiment ID", exp_ids, key="exp_filter")

    sev_options = ["All", "LOW", "MEDIUM", "HIGH"]
    selected_sev = st.selectbox("Filter by Severity", sev_options, key="sev_filter")

    filtered = summaries
    if selected_exp != "All":
        filtered = [s for s in filtered if s["experiment_id"] == selected_exp]
    if selected_sev != "All":
        filtered = [
            s for s in filtered
            if (selected_sev == "LOW" and s["low"] > 0)
            or (selected_sev == "MEDIUM" and s["medium"] > 0)
            or (selected_sev == "HIGH" and s["high"] > 0)
        ]

    st.divider()

    st.subheader("Experiment Summary Table")
    experiment_table(filtered)

    if filtered:
        df = pd.DataFrame(filtered)
        csv_export_button(df, "experiment_results.csv", "Download Experiment Results CSV")

    st.divider()

    if selected_exp != "All":
        st.subheader(f"Performance Details: {selected_exp}")
        exp_events = [e for e in events if e.experiment_id == selected_exp]

        col1, col2, col3, col4 = st.columns(4)
        total = len(exp_events)
        correct = sum(1 for e in exp_events if e.ground_truth and e.predicted_class == e.ground_truth)
        evaluated = [e for e in exp_events if e.ground_truth is not None]
        accuracy = (correct / len(evaluated)) if evaluated else None

        with col1:
            st.metric("Total Windows", total)
        with col2:
            st.metric("Correct", correct)
        with col3:
            st.metric("Accuracy", f"{accuracy:.2%}" if accuracy is not None else "N/A")
        with col4:
            latencies = [e.inference_latency_ms for e in exp_events if e.inference_latency_ms is not None]
            avg_lat = sum(latencies) / len(latencies) if latencies else None
            st.metric("Avg Inference Latency", f"{avg_lat:.1f} ms" if avg_lat else "N/A")

        st.divider()
        st.subheader("Detection Events Over Time")
        table_data = [
            {"timestamp": e.timestamp}
            for e in exp_events
            if e.timestamp
        ]
        st.plotly_chart(
            events_over_time_chart(table_data),
            use_container_width=True,
        )
