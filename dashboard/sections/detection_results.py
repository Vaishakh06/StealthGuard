"""Section 3: ML Detection Results."""

from __future__ import annotations

import streamlit as st

from components.charts import (
    predicted_class_distribution_chart,
    events_over_time_chart,
)
from components.metric_cards import metric_row
from components.tables import detection_table, csv_export_button
from services.metrics_calculator import predicted_class_distribution
import pandas as pd


def render(state):
    st.header("ML Detection Results")

    events = state.detection_events

    metric_row([
        ("Total Windows Evaluated", len(events), None),
        ("Unique Classes Predicted", len({e.predicted_class for e in events if e.predicted_class}), None),
    ])

    st.divider()

    st.subheader("Detection Events Table")
    table_data = [
        {
            "timestamp": e.timestamp,
            "experiment_id": e.experiment_id or "—",
            "window_id": e.window_id or "—",
            "source_ip": e.source_ip or "—",
            "destination_ip": e.destination_ip or "—",
            "destination_port": e.destination_port or "—",
            "ground_truth": e.ground_truth or "—",
            "predicted_class": e.predicted_class or "—",
            "confidence": round(e.confidence, 3) if e.confidence is not None else None,
            "security_severity": e.security_severity or "—",
            "mitigation_action": e.mitigation_action or "—",
            "mitigation_outcome": e.mitigation_outcome or "—",
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

    st.info(
        "Each row is one 100-flow inference window. The predicted_class is the "
        "model output; ground_truth is the intended traffic class when available. "
        "If ground_truth shows '—', it was not provided for that window."
    )
