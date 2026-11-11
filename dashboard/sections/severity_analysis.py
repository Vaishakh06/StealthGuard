"""Section 4: AnomalyFlow Severity Analysis."""

from __future__ import annotations

import streamlit as st

from components.charts import (
    severity_distribution_chart,
    events_over_time_chart,
    score_distribution_chart,
)
from components.metric_cards import severity_counts_card, metric_row
from services.metrics_calculator import severity_distribution


def render(state):
    st.header("AnomalyFlow Severity Analysis")

    events = state.detection_events
    dist = severity_distribution(events)

    st.subheader("Severity Summary")
    severity_counts_card("Events by Severity", dist)

    st.divider()

    metric_row([
        ("LOW Events", dist.get("LOW", 0), None),
        ("MEDIUM Events", dist.get("MEDIUM", 0), None),
        ("HIGH Events", dist.get("HIGH", 0), None),
    ])

    st.divider()

    st.subheader("Severity Charts")
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(
            severity_distribution_chart(dist),
            use_container_width=True,
        )
    with c2:
        table_data = [
            {"timestamp": e.timestamp, "security_severity": e.security_severity}
            for e in events
            if e.timestamp
        ]
        st.plotly_chart(
            events_over_time_chart(table_data),
            use_container_width=True,
        )

    st.divider()

    st.subheader("AnomalyFlow Score Distribution")
    scores = [e.anomalyflow_score for e in events if e.anomalyflow_score is not None]
    st.plotly_chart(
        score_distribution_chart(scores),
        use_container_width=True,
    )

    st.divider()

    st.subheader("Severity Event Details")
    detail_rows = [
        {
            "timestamp": e.timestamp,
            "experiment_id": e.experiment_id,
            "window_id": e.window_id,
            "source_ip": e.source_ip,
            "predicted_class": e.predicted_class,
            "confidence": round(e.confidence, 3) if e.confidence is not None else None,
            "anomalyflow_score": round(e.anomalyflow_score, 3) if e.anomalyflow_score is not None else None,
            "decision_state": e.decision_state,
            "security_severity": e.security_severity,
        }
        for e in events
    ]
    st.dataframe(
        detail_rows,
        use_container_width=True,
        hide_index=True,
        height=400,
    )

    st.info(
        "Severity values are produced by the existing AnomalyFlow decision "
        "layer and are never re-calculated by this dashboard."
    )
