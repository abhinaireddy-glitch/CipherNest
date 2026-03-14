"""
dashboard/app.py
CipherNest — Real-time SOC Dashboard built with Streamlit.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CipherNest SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Exo 2', sans-serif;
    background-color: #0a0e1a;
    color: #c9d1d9;
}
.stApp { background-color: #0a0e1a; }

h1, h2, h3 { font-family: 'Exo 2', sans-serif; font-weight: 800; }

.metric-card {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 20px 24px;
    text-align: center;
    box-shadow: 0 0 20px rgba(0,255,136,0.05);
}
.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1.1;
}
.metric-label {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #8b949e;
    margin-top: 4px;
}
.critical { color: #ff4d4d; }
.high     { color: #ff9f43; }
.medium   { color: #ffd32a; }
.ok       { color: #00ff88; }

.stDataFrame { border-radius: 8px; }
div[data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #21262d; }
</style>
""", unsafe_allow_html=True)


# ── Data Loaders ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_logs():
    path = "data/processed_logs.csv"
    if not os.path.exists(path):
        st.error("⚠️ No processed logs found. Run `python main.py` first.")
        st.stop()
    df = pd.read_csv(path, parse_dates=["timestamp"])
    return df

@st.cache_data(ttl=30)
def load_blocked_ips():
    path = "data/blocked_ips.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []

@st.cache_data(ttl=30)
def load_actions():
    path = "data/response_actions.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ CipherNest")
    st.markdown("*Multi-Agent Cybersecurity SOC*")
    st.divider()

    st.markdown("### Filters")
    blocked_ips = load_blocked_ips()
    actions = load_actions()

    df_all = load_logs()

    attack_types = ["All"] + sorted(df_all["attack_type"].unique().tolist())
    selected_attack = st.selectbox("Attack Type", attack_types)

    severities = ["All"] + sorted(df_all["severity"].unique().tolist())
    selected_severity = st.selectbox("Severity", severities)

    show_threats_only = st.checkbox("Threats Only", value=False)

    st.divider()
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()

    st.markdown("### Pipeline")
    st.markdown("""
    ```
    Attack Simulator
         ↓
    Network Monitor
         ↓
    Log Analyzer
         ↓
    Threat Detector (ML)
         ↓
    Orchestrator
         ↓
    Response Agent
    ```
    """)


# ── Apply Filters ─────────────────────────────────────────────────────────────
df = df_all.copy()
if selected_attack != "All":
    df = df[df["attack_type"] == selected_attack]
if selected_severity != "All":
    df = df[df["severity"] == selected_severity]
if show_threats_only:
    df = df[df["attack_type"] != "normal"]


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ CipherNest — Security Operations Center")
st.markdown(f"**Live Threat Dashboard** &nbsp;|&nbsp; `{len(df_all)}` events analyzed")
st.divider()


# ── KPI Cards ─────────────────────────────────────────────────────────────────
total       = len(df_all)
threats     = len(df_all[df_all["attack_type"] != "normal"])
critical    = len(df_all[df_all["severity"] == "CRITICAL"])
blocked_cnt = len(blocked_ips)

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value ok">{total}</div>
        <div class="metric-label">Total Events</div>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value high">{threats}</div>
        <div class="metric-label">Threats Detected</div>
    </div>""", unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value critical">{critical}</div>
        <div class="metric-label">Critical Alerts</div>
    </div>""", unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-value medium">{blocked_cnt}</div>
        <div class="metric-label">IPs Blocked</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ── Charts Row ────────────────────────────────────────────────────────────────
col1, col2 = st.columns([1.4, 1])

with col1:
    st.markdown("### 📈 Events Over Time")
    time_df = df_all.copy()
    time_df["minute"] = time_df["timestamp"].dt.floor("5min")
    time_grp = time_df.groupby(["minute", "attack_type"]).size().reset_index(name="count")

    color_map = {
        "normal":      "#00ff88",
        "port_scan":   "#ff9f43",
        "ddos":        "#ff4d4d",
        "brute_force": "#ffd32a",
        "suspicious":  "#a29bfe",
        "data_exfil":  "#fd79a8",
    }

    fig_time = px.area(
        time_grp, x="minute", y="count", color="attack_type",
        color_discrete_map=color_map,
        template="plotly_dark",
    )
    fig_time.update_layout(
        paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
        legend_title="", margin=dict(t=10, b=10, l=10, r=10),
        height=280,
    )
    st.plotly_chart(fig_time, use_container_width=True)

with col2:
    st.markdown("### 🥧 Attack Distribution")
    attack_counts = df_all["attack_type"].value_counts().reset_index()
    attack_counts.columns = ["attack_type", "count"]

    fig_pie = px.pie(
        attack_counts, names="attack_type", values="count",
        color="attack_type", color_discrete_map=color_map,
        template="plotly_dark", hole=0.45,
    )
    fig_pie.update_layout(
        paper_bgcolor="#0d1117",
        legend_title="",
        margin=dict(t=10, b=10, l=10, r=10),
        height=280,
    )
    st.plotly_chart(fig_pie, use_container_width=True)


# ── Anomaly Score Distribution ────────────────────────────────────────────────
st.markdown("### 🔬 Anomaly Score Distribution (ML)")
fig_hist = px.histogram(
    df_all, x="anomaly_score", color="attack_type",
    nbins=50, barmode="overlay",
    color_discrete_map=color_map,
    template="plotly_dark",
)
fig_hist.update_layout(
    paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
    margin=dict(t=10, b=10, l=10, r=10), height=220,
    bargap=0.05,
)
st.plotly_chart(fig_hist, use_container_width=True)


# ── Threat Log Table ──────────────────────────────────────────────────────────
st.markdown("### 🚨 Threat Event Log")

severity_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
display_df = df[["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                  "bytes_sent", "packets", "attack_type", "severity",
                  "anomaly_score", "response_action"]].copy()
display_df["severity"] = display_df["severity"].apply(
    lambda s: f"{severity_color.get(s, '')} {s}"
)

st.dataframe(
    display_df.sort_values("timestamp", ascending=False),
    use_container_width=True,
    height=300,
)


# ── Blocked IPs ───────────────────────────────────────────────────────────────
col_b, col_a = st.columns(2)

with col_b:
    st.markdown("### 🚫 Blocked IP Addresses")
    if blocked_ips:
        for ip in blocked_ips:
            st.code(f"🚫  {ip}", language=None)
    else:
        st.info("No IPs blocked yet.")

with col_a:
    st.markdown("### 📋 Response Actions Log")
    if actions:
        actions_df = pd.DataFrame(actions)
        st.dataframe(actions_df, use_container_width=True, height=200)
    else:
        st.info("No response actions recorded yet.")


# ── Top Attacking IPs ─────────────────────────────────────────────────────────
st.markdown("### 🌐 Top Attacking Source IPs")
threat_ips = df_all[df_all["attack_type"] != "normal"]["src_ip"].value_counts().head(10).reset_index()
threat_ips.columns = ["src_ip", "event_count"]

fig_bar = px.bar(
    threat_ips, x="event_count", y="src_ip", orientation="h",
    color="event_count", color_continuous_scale="Reds",
    template="plotly_dark",
)
fig_bar.update_layout(
    paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
    margin=dict(t=10, b=10, l=10, r=10), height=280,
    coloraxis_showscale=False, yaxis_title="", xaxis_title="Threat Events",
)
st.plotly_chart(fig_bar, use_container_width=True)

st.divider()
st.markdown(
    "<center style='color:#444;font-size:0.8rem;'>CipherNest v1.0 — Multi-Agent Cybersecurity SOC | Hackathon Edition</center>",
    unsafe_allow_html=True,
)
