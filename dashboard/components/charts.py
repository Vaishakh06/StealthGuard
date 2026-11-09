"""Reusable chart components using Plotly."""

from __future__ import annotations

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from config import SEVERITY_COLOURS, ACTION_COLOURS, STATUS_COLOURS


_DARK_TEMPLATE = "plotly_dark"


def severity_distribution_chart(counts: dict[str, int]):
    """Bar chart of severity counts."""
    if not counts:
        return _empty_chart("No severity data")
    df = pd.DataFrame(
        {"severity": list(counts.keys()), "count": list(counts.values())}
    )
    colours = [SEVERITY_COLOURS.get(s.upper(), "#9ca3af") for s in df["severity"]]
    fig = go.Figure(
        data=[
            go.Bar(
                x=df["severity"],
                y=df["count"],
                marker_color=colours,
                text=df["count"],
                textposition="outside",
            )
        ]
    )
    fig.update_layout(
        title="Severity Distribution",
        xaxis_title="Security Severity",
        yaxis_title="Event Count",
        template=_DARK_TEMPLATE,
        showlegend=False,
        height=350,
        margin=dict(t=50, b=40, l=40, r=20),
    )
    return fig


def predicted_class_distribution_chart(counts: dict[str, int]):
    """Bar chart of predicted class distribution."""
    if not counts:
        return _empty_chart("No detection data")
    df = pd.DataFrame(
        {"class": list(counts.keys()), "count": list(counts.values())}
    )
    fig = px.bar(
        df,
        x="class",
        y="count",
        title="Predicted Class Distribution",
        color_discrete_sequence=["#3b82f6"],
        template=_DARK_TEMPLATE,
    )
    fig.update_layout(
        xaxis_title="Predicted Class",
        yaxis_title="Window Count",
        height=350,
        margin=dict(t=50, b=40, l=40, r=20),
        showlegend=False,
    )
    return fig


def confusion_matrix_chart(cm: list[list[int]], labels: list[str]):
    """Confusion matrix heatmap."""
    fig = go.Figure(
        data=go.Heatmap(
            z=cm,
            x=[f"Pred: {l}" for l in labels],
            y=[f"True: {l}" for l in labels],
            colorscale="Blues",
            showscale=True,
        )
    )
    fig.update_layout(
        title="Confusion Matrix",
        xaxis_title="Predicted",
        yaxis_title="Ground Truth",
        template=_DARK_TEMPLATE,
        height=400,
        margin=dict(t=50, b=40, l=60, r=20),
    )
    return fig


def events_over_time_chart(events: list[dict], time_key: str = "timestamp"):
    """Line chart of events over time."""
    if not events:
        return _empty_chart("No events over time")
    df = pd.DataFrame(events)
    if time_key not in df.columns:
        return _empty_chart("No timestamp data")
    df["_dt"] = pd.to_datetime(df[time_key], errors="coerce")
    df = df.dropna(subset=["_dt"])
    if df.empty:
        return _empty_chart("No valid timestamps")
    df = df.sort_values("_dt")
    df["_count"] = range(1, len(df) + 1)
    fig = px.line(
        df,
        x="_dt",
        y="_count",
        title="Events Over Time",
        template=_DARK_TEMPLATE,
        color_discrete_sequence=["#3b82f6"],
    )
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Cumulative Events",
        height=350,
        margin=dict(t=50, b=40, l=40, r=20),
        showlegend=False,
    )
    return fig


def score_distribution_chart(scores: list[float]):
    """Histogram of AnomalyFlow scores."""
    if not scores:
        return _empty_chart("No score data")
    fig = go.Figure(
        data=[go.Histogram(x=scores, marker_color="#3b82f6", nbinsx=20)]
    )
    fig.update_layout(
        title="AnomalyFlow Score Distribution",
        xaxis_title="AnomalyFlow Score",
        yaxis_title="Count",
        template=_DARK_TEMPLATE,
        height=350,
        margin=dict(t=50, b=40, l=40, r=20),
        showlegend=False,
    )
    return fig


def per_class_metrics_chart(per_class: dict[str, dict]):
    """Grouped bar chart of precision/recall/F1 per class."""
    if not per_class:
        return _empty_chart("No per-class metrics")
    classes = list(per_class.keys())
    precision = [v.get("precision") or 0 for v in per_class.values()]
    recall = [v.get("recall") or 0 for v in per_class.values()]
    f1 = [v.get("f1") or 0 for v in per_class.values()]

    fig = go.Figure()
    fig.add_trace(go.Bar(name="Precision", x=classes, y=precision, marker_color="#3b82f6"))
    fig.add_trace(go.Bar(name="Recall", x=classes, y=recall, marker_color="#f59e0b"))
    fig.add_trace(go.Bar(name="F1-Score", x=classes, y=f1, marker_color="#10b981"))

    fig.update_layout(
        title="Per-Class Precision / Recall / F1",
        xaxis_title="Class",
        yaxis_title="Score",
        barmode="group",
        template=_DARK_TEMPLATE,
        height=350,
        margin=dict(t=50, b=40, l=40, r=20),
    )
    return fig


def traffic_volume_chart(points: list[dict]):
    """Traffic volume over time line chart."""
    if not points:
        return _empty_chart("No traffic data")
    df = pd.DataFrame(points)
    if "timestamp" not in df.columns or "volume" not in df.columns:
        return _empty_chart("Invalid traffic data")
    df["_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["_dt"])
    if df.empty:
        return _empty_chart("No valid traffic timestamps")
    fig = px.area(
        df.sort_values("_dt"),
        x="_dt",
        y="volume",
        title="Traffic Volume Over Time",
        template=_DARK_TEMPLATE,
        color_discrete_sequence=["#3b82f6"],
    )
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Volume",
        height=350,
        margin=dict(t=50, b=40, l=40, r=20),
        showlegend=False,
    )
    return fig


def _empty_chart(message: str) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.5,
        showarrow=False,
        font=dict(color="#9ca3af", size=14),
    )
    fig.update_layout(
        template="plotly_dark",
        height=350,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        margin=dict(t=40, b=40, l=40, r=20),
    )
    return fig
