
import streamlit as st
import pandas as pd
import json
from pathlib import Path
import matplotlib.pyplot as plt


# ============================================================
# PROJECT PATHS
# ============================================================

DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent

CONFIG_PATH = DASHBOARD_DIR / "dashboard_config.json"


# ============================================================
# LOAD CONFIGURATION
# ============================================================

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    dashboard_config = json.load(f)


MITIGATION_RESULTS = (
    DASHBOARD_DIR / dashboard_config["mitigation_results"]
).resolve()

ANOMALYFLOW_CONFIG = (
    DASHBOARD_DIR / dashboard_config["anomalyflow_config"]
).resolve()


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AnomalyFlow Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data
def load_data():

    df = pd.read_csv(MITIGATION_RESULTS)

    with open(ANOMALYFLOW_CONFIG, "r", encoding="utf-8") as f:
        config = json.load(f)

    return df, config


df, anomalyflow_config = load_data()


# ============================================================
# PAGE HEADER
# ============================================================

st.title("AnomalyFlow Security Dashboard")

st.caption(
    "Hybrid deep-learning and statistical network traffic "
    "analysis with automated security decision and mitigation simulation."
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header("Dashboard Controls")

severity_filter = st.sidebar.multiselect(
    "Security Severity",
    options=sorted(df["Security_Severity"].unique()),
    default=sorted(df["Security_Severity"].unique())
)

decision_filter = st.sidebar.multiselect(
    "Decision State",
    options=sorted(df["Decision_State"].unique()),
    default=sorted(df["Decision_State"].unique())
)

filtered_df = df[
    df["Security_Severity"].isin(severity_filter)
    & df["Decision_State"].isin(decision_filter)
]


# ============================================================
# KPI CALCULATIONS
# ============================================================

total_samples = len(filtered_df)

alerts_generated = int(
    filtered_df["Alert_Generated"].sum()
)

high_evidence = int(
    (filtered_df["Decision_State"] == "HIGH_EVIDENCE").sum()
)

simulated_blocks = int(
    filtered_df["Simulated_Block"].sum()
)

rate_limits = int(
    filtered_df["Simulated_Rate_Limit"].sum()
)

ddos_classes = {
    "DrDoS_DNS",
    "DrDoS_LDAP",
    "DrDoS_MSSQL",
    "DrDoS_NTP",
    "DrDoS_NetBIOS",
    "DrDoS_SNMP",
    "DrDoS_SSDP",
    "DrDoS_UDP",
    "LDAP",
    "MSSQL",
    "NetBIOS",
    "Portmap",
    "Syn",
    "TFTP",
    "UDP",
    "UDP-lag"
}

predicted_ddos = int(
    filtered_df["Predicted_Label"].isin(ddos_classes).sum()
)


# ============================================================
# KPI CARDS
# ============================================================

st.subheader("Security Overview")

col1, col2, col3, col4, col5, col6 = st.columns(6)

col1.metric("Total Samples", f"{total_samples:,}")
col2.metric("Predicted DDoS", f"{predicted_ddos:,}")
col3.metric("Alerts Generated", f"{alerts_generated:,}")
col4.metric("High Evidence", f"{high_evidence:,}")
col5.metric("Simulated Blocks", f"{simulated_blocks:,}")
col6.metric("Rate Limits", f"{rate_limits:,}")


# ============================================================
# DECISION STATE + SECURITY SEVERITY
# ============================================================

st.subheader("Security Decision Analysis")

col1, col2 = st.columns(2)

with col1:

    st.markdown("#### AnomalyFlow Decision States")

    decision_counts = (
        filtered_df["Decision_State"]
        .value_counts()
        .reindex(
            ["NORMAL", "SUSPICIOUS", "HIGH_EVIDENCE"],
            fill_value=0
        )
    )

    st.bar_chart(decision_counts)


with col2:

    st.markdown("#### Security Severity")

    severity_counts = (
        filtered_df["Security_Severity"]
        .value_counts()
    )

    st.bar_chart(severity_counts)


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

st.subheader("Predicted Attack Distribution")

attack_counts = (
    filtered_df["Predicted_Label"]
    .value_counts()
)

st.bar_chart(attack_counts)


# ============================================================
# MITIGATION ANALYSIS
# ============================================================

st.subheader("Mitigation Analysis")

col1, col2 = st.columns(2)

with col1:

    st.markdown("#### Mitigation Actions")

    mitigation_counts = (
        filtered_df["Mitigation_Action"]
        .value_counts()
    )

    st.bar_chart(mitigation_counts)


with col2:

    st.markdown("#### Alert Types")

    alert_counts = (
        filtered_df["Alert_Type"]
        .value_counts()
    )

    st.bar_chart(alert_counts)


# ============================================================
# ANOMALYFLOW SCORE DISTRIBUTION
# ============================================================

st.subheader("AnomalyFlow Score Distribution")

fig, ax = plt.subplots(figsize=(10, 4))

ax.hist(
    filtered_df["AnomalyFlow_Score"],
    bins=50
)

ax.axvline(
    anomalyflow_config["low_threshold"],
    linestyle="--",
    label="Suspicious Threshold"
)

ax.axvline(
    anomalyflow_config["high_threshold"],
    linestyle="--",
    label="High-Evidence Threshold"
)

ax.set_xlabel("AnomalyFlow Score")
ax.set_ylabel("Number of Samples")
ax.set_title("AnomalyFlow Score Distribution")
ax.legend()

fig.tight_layout()

st.pyplot(fig)


# ============================================================
# HIGH-EVIDENCE SECURITY EVENTS
# ============================================================

st.subheader("Highest-Evidence Security Events")

event_columns = [
    "Test_Index",
    "Predicted_Label",
    "Confidence",
    "AnomalyFlow_Score",
    "Decision_State",
    "Security_Severity",
    "Mitigation_Action",
    "Alert_Level",
    "Alert_Type",
    "Mitigation_Outcome"
]

top_events = (
    filtered_df[event_columns]
    .sort_values(
        "AnomalyFlow_Score",
        ascending=False
    )
    .head(20)
)

st.dataframe(
    top_events,
    use_container_width=True,
    hide_index=True
)


# ============================================================
# ANOMALYFLOW CONFIGURATION
# ============================================================

with st.expander("AnomalyFlow Configuration"):

    config_col1, config_col2 = st.columns(2)

    config_col1.metric(
        "Confidence Weight",
        anomalyflow_config["confidence_weight"]
    )

    config_col2.metric(
        "Rényi Weight",
        anomalyflow_config["renyi_weight"]
    )

    config_col1.metric(
        "Low Threshold",
        anomalyflow_config["low_threshold"]
    )

    config_col2.metric(
        "High Threshold",
        anomalyflow_config["high_threshold"]
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "AnomalyFlow | Network Traffic Detection, Security Decision "
    "and Mitigation Simulation"
)
