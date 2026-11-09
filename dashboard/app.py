"""StealthGuard Dashboard - main entry point.

Run with:  streamlit run dashboard/app.py
"""

from __future__ import annotations

import time
import streamlit as st

from config import MODES, DEFAULT_MODE, REFRESH_INTERVAL_SECONDS, SAMPLE_DATA_DIR
from services.event_processor import load_state, refresh_state
from pages import overview, traffic_monitor, detection_results, severity_analysis, firewall_monitor, experiment_results

PAGES = {
    "1. System Overview": overview,
    "2. Traffic Monitor": traffic_monitor,
    "3. ML Detection Results": detection_results,
    "4. AnomalyFlow Severity": severity_analysis,
    "5. Firewall Monitor": firewall_monitor,
    "6. Experiment Results": experiment_results,
}

SAMPLE_EVENTS = SAMPLE_DATA_DIR / "detection_events.jsonl"
SAMPLE_ACTIONS = SAMPLE_DATA_DIR / "mitigation_actions.jsonl"


def _init_session_state():
    if "mode" not in st.session_state:
        st.session_state.mode = DEFAULT_MODE
    if "state" not in st.session_state:
        st.session_state.state = None
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = 0.0
    if "det_line_offset" not in st.session_state:
        st.session_state.det_line_offset = 0
    if "fw_line_offset" not in st.session_state:
        st.session_state.fw_line_offset = 0


def _render_sidebar():
    st.sidebar.title("StealthGuard")
    st.sidebar.caption("DDoS Detection & Mitigation Dashboard")

    st.sidebar.divider()

    mode = st.sidebar.radio(
        "Data Mode",
        MODES,
        index=MODES.index(st.session_state.mode),
        key="mode_radio",
        help="SAMPLE uses bundled demo data. LIVE reads StealthGuard JSONL logs.",
    )
    st.session_state.mode = mode

    if st.session_state.mode == "sample":
        st.sidebar.error("SAMPLE DATA MODE — demo data only, not live results")
    else:
        st.sidebar.success("LIVE MODE — reading StealthGuard logs")

    st.sidebar.divider()
    st.sidebar.subheader("Refresh")
    auto = st.sidebar.toggle("Auto-refresh (2–3s)", value=True, key="auto_refresh")
    if st.sidebar.button("Refresh Now", key="refresh_btn"):
        st.session_state.last_refresh = 0.0  # force reload

    st.sidebar.divider()
    st.sidebar.subheader("Navigation")
    selection = st.sidebar.radio(
        "Go to",
        list(PAGES.keys()),
        key="nav_radio",
    )

    st.sidebar.divider()
    st.sidebar.caption("streamlit run dashboard/app.py")

    return selection, auto


def _load_or_refresh_state():
    now = time.time()
    if (
        st.session_state.state is None
        or now - st.session_state.last_refresh > REFRESH_INTERVAL_SECONDS
        or st.session_state.last_refresh == 0.0
    ):
        mode = st.session_state.mode
        if mode == "sample":
            state = load_state(
                mode="sample",
                sample_events_path=SAMPLE_EVENTS,
                sample_actions_path=SAMPLE_ACTIONS,
            )
        else:
            state = load_state(mode="live")

        st.session_state.state = state
        st.session_state.last_refresh = now


def main():
    st.set_page_config(
        page_title="StealthGuard Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    _init_session_state()
    selection, auto_refresh = _render_sidebar()

    _load_or_refresh_state()

    state = st.session_state.state
    if state is None:
        st.error("Failed to load dashboard state.")
        return

    # Sample mode banner
    if state.sample_mode:
        st.error(
            "SAMPLE DATA MODE — displaying bundled demonstration data. "
            "Switch to LIVE mode in the sidebar to read real StealthGuard logs.",
            icon="⚠️",
        )

    page = PAGES[selection]
    page.render(state)

    if auto_refresh:
        time.sleep(REFRESH_INTERVAL_SECONDS)
        st.rerun()


if __name__ == "__main__":
    main()
