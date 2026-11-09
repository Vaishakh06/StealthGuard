"""Section 3: ML Detection Results."""

from __future__ import annotations

import streamlit as st

from components.charts import (
    predicted_class_distribution_chart,
    confusion_matrix_chart,
    events_over_time_chart,
    per_class_metrics_chart,
)
from components.metric_cards import metric_row
from components.tables import detection_table, csv_export_button
from services.metrics_calculator import detection_metrics, predicted_class_distribution
import pandas as pd


def render(state):
    st.header("ML Detection Results")

    events = state.detection_events
    metrics = detection_metrics(events)

    metric_row([
        ("Total Windows Evaluated", metrics["total_windows"], None),
        ("Correct Predictions", metrics["correct"], None),
        ("Incorrect Predictions", metrics["incorrect"], None),
        ("Unevaluated Windows", metrics["unevaluated"], None),
    ])

    st.divider()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        acc = metrics["accuracy"]
        st.metric("Classification Accuracy", f"{acc:.2%}" if acc is not None else "N/A")
    with col2:
        st.metric("Precision (macro)", f"{metrics['precision']:.2%}" if metrics["precision"] is not None else "N/A")
    with col3:
        st.metric("Recall (macro)", f"{metrics['recall']:.2%}" if metrics["recall"] is not None else "N/A")
    with col4:
        st.metric("F1-Score (macro)", f"{metrics['f1']:.2%}" if metrics["f1"] is not None else "N/A")

    if metrics["accuracy"] is None:
        st.info(
            "Classification accuracy is not calculated because ground-truth "
            "labels are not available for these windows."
        )

    st.divider()

    st.subheader("Detection Events Table")
    table_data = [
        {
            "timestamp": e.timestamp,
            "experiment_id": e.experiment_id,
            "window_id": e.window_id,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "destination_port": e.destination_port,
            "ground_truth": e.ground_truth or "—",
            "predicted_class": e.predicted_class,
            "confidence": round(e.confidence, 3) if e.confidence is not None else None,
            "security_severity": e.security_severity,
            "mitigation_action": e.mitigation_action,
            "mitigation_outcome": e.mitigation_outcome,
            "evaluation_status": e.evaluation_status,
        }
        for e in events
    ]
    detection_table(table_data)

    if table_data:
        df = pd.DataFrame(table_data)
        csv_export_button(df, "detection_results.csv", "Download Detection Results CSV")

    st.divider()

    st.subheader("Charts")
    c1, c2 = st.columns(2)
    with c1:
        dist = predicted_class_distribution(events)
        st.plotly_chart(
            predicted_class_distribution_chart(dist),
            use_container_width=True,
        )
    with c2:
        st.plotly_chart(
            events_over_time_chart(table_data),
            use_container_width=True,
        )

    st.subheader("Per-Class Metrics")
    if metrics["per_class"]:
        st.plotly_chart(
            per_class_metrics_chart(metrics["per_class"]),
            use_container_width=True,
        )
    else:
        st.info("Per-class metrics require ground-truth labels.")
