"""Section 2: Traffic Monitor."""

from __future__ import annotations

import streamlit as st

from components.charts import traffic_volume_chart
from components.metric_cards import metric_row
from components.tables import detection_table


def render(state):
    st.header("Traffic Monitor")

    events = state.detection_events

    total_windows = len(events)
    benign = sum(1 for e in events if e.predicted_class == "BENIGN")
    attack = total_windows - benign

    metric_row([
        ("Inference Windows Processed", total_windows, None),
        ("Benign Windows", benign, None),
        ("Attack Windows", attack, None),
        (
            "Ground Truth",
            "Available" if any(e.ground_truth for e in events) else "Unavailable",
            None,
        ),
    ])

    st.divider()

    st.subheader("Traffic Volume Over Time")
    points = [
        {"timestamp": e.timestamp, "volume": 1}
        for e in events
        if e.timestamp
    ]
    st.plotly_chart(traffic_volume_chart(points), use_container_width=True)

    st.divider()

    st.subheader("Traffic Composition")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Benign Windows", benign)
    with col2:
        st.metric("Attack Windows", attack)

    st.divider()

    st.subheader("Source IP Distribution")
    ip_counts = {}
    for e in events:
        ip = e.source_ip or "unknown"
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    if ip_counts:
        df = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        st.bar_chart({k: v for k, v in df})
    else:
        st.info("No source IP data available.")

    st.info(
        "Note: The ML model operates on 100-flow windows. Each row above "
        "represents one inference window, not one individual flow."
    )
