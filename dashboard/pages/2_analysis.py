import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# 📊 Page Title
st.title("📊 Advanced Cyber Risk Analysis")

# ⚠️ Check if scan data exists
if "scan_df" not in st.session_state:
    st.warning("⚠️ Run a scan first")
    st.stop()

# 📥 Load scanned data
df = st.session_state["scan_df"]

# ───────── ROW 1 ─────────
# 👉 Shows service distribution + severity distribution
col1, col2 = st.columns(2)

with col1:
    # 📊 Count number of open services
    service_counts = df["service"].value_counts().reset_index()
    service_counts.columns = ["Service", "Count"]

    # 📈 Bar chart of services
    fig1 = px.bar(service_counts, x="Service", y="Count",
                  color="Count", color_continuous_scale="Blues",
                  title="🛠️ Open Services")
    fig1.update_traces(textposition="outside")
    st.plotly_chart(fig1, use_container_width=True)

with col2:
    # 🥧 Pie chart showing severity distribution
    fig2 = px.pie(df, names="severity", hole=0.5,
                  title="🚨 Severity Distribution",
                  color="severity",
                  color_discrete_map={
                      "Low": "green",
                      "Medium": "orange",
                      "High": "red",
                      "Critical": "darkred"
                  })
    st.plotly_chart(fig2, use_container_width=True)

# ───────── ROW 2 ─────────
# 👉 Shows risk relationship + avg risk per service
col3, col4 = st.columns(2)

with col3:
    # 🌍 Scatter plot (Risk Heatmap)
    # X = exposure, Y = threat, size = risk
    fig3 = px.scatter(df,
                      x="exposure_score",
                      y="threat_score",
                      size="risk_score",
                      color="risk_score",
                      text="ip",
                      color_continuous_scale="RdYlGn_r",
                      title="🌍 Risk Heatmap")
    fig3.update_traces(textposition="top center")
    st.plotly_chart(fig3, use_container_width=True)

with col4:
    # 📈 Average risk per service
    avg_risk = df.groupby("service")["risk_score"].mean().reset_index()

    fig4 = px.bar(avg_risk,
                  x="risk_score",
                  y="service",
                  orientation="h",
                  color="risk_score",
                  color_continuous_scale="RdYlGn_r",
                  title="📈 Avg Risk per Service")
    st.plotly_chart(fig4, use_container_width=True)

# ───────── ROW 3 ─────────
# 👉 Shows VirusTotal threat data + risk trend
col5, col6 = st.columns(2)

with col5:
    # 🧪 Aggregate malicious & suspicious reports per IP
    vt = df.groupby("ip")[["malicious", "suspicious"]].sum().reset_index()

    # 📊 Bar chart for threat reports
    fig5 = go.Figure()
    fig5.add_bar(x=vt["ip"], y=vt["malicious"], name="Malicious", marker_color="red")
    fig5.add_bar(x=vt["ip"], y=vt["suspicious"], name="Suspicious", marker_color="orange")

    fig5.update_layout(title="🧪 Threat Reports", barmode="group")
    st.plotly_chart(fig5, use_container_width=True)

with col6:
    # 🕒 Create artificial timeline for visualization
    df["scan_time"] = pd.date_range(end=pd.Timestamp.now(), periods=len(df))

    # 📉 Calculate max & average risk over time
    trend = df.groupby("scan_time").agg(
        max_risk=("risk_score", "max"),
        avg_risk=("risk_score", "mean")
    ).reset_index()

    # 📈 Line chart for risk trend
    fig6 = px.line(trend,
                   x="scan_time",
                   y=["max_risk", "avg_risk"],
                   markers=True,
                   title="📉 Risk Trend Over Time")

    st.plotly_chart(fig6, use_container_width=True)

# ───────── FULL WIDTH ─────────
# 👉 Hierarchical view of risk
st.subheader("🧩 Risk Hierarchy")

# 🌳 Sunburst chart (IP → Severity → Service)
fig7 = px.sunburst(df,
                   path=["ip", "severity", "service"],
                   values="risk_score",
                   color="risk_score",
                   color_continuous_scale="RdYlGn_r")

st.plotly_chart(fig7, use_container_width=True)