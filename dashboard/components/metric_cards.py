"""Reusable metric card components for the StealthGuard dashboard."""

from __future__ import annotations

import streamlit as st


def metric_card(label: str, value, delta: str | None = None, help_text: str | None = None):
    """Render a single metric card."""
    st.metric(label=label, value=value, delta=delta, help=help_text)


def metric_row(metrics: list[tuple[str, object, str | None]]):
    """Render a row of metric cards side-by-side.

    Each item is (label, value, delta_or_none).
    """
    cols = st.columns(len(metrics))
    for col, (label, value, delta) in zip(cols, metrics):
        with col:
            st.metric(label=label, value=value, delta=delta)


def status_card(label: str, status: str, colours: dict[str, str] | None = None):
    """Render a status pill card."""
    colours = colours or {}
    colour = colours.get(status.upper(), "#9ca3af")
    st.markdown(
        f"""
        <div style="
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            background: {colour};
            color: white;
            font-weight: 600;
            font-size: 0.85rem;
        ">
            {label}: <span style="text-transform:uppercase">{status}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_counts_card(label: str, counts: dict[str, int]):
    """Render severity summary cards (LOW / MEDIUM / HIGH)."""
    cols = st.columns(3)
    severity_order = [("LOW", "#3b82f6"), ("MEDIUM", "#f59e0b"), ("HIGH", "#ef4444")]
    for col, (sev, colour) in zip(cols, severity_order):
        with col:
            st.markdown(
                f"""
                <div style="
                    padding: 12px;
                    border-radius: 8px;
                    background: {colour}1a;
                    border: 1px solid {colour};
                    text-align: center;
                ">
                    <div style="color: {colour}; font-weight: 700; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px;">
                        {sev}
                    </div>
                    <div style="font-size: 1.5rem; font-weight: 700; color: #111827;">
                        {counts.get(sev, 0)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
