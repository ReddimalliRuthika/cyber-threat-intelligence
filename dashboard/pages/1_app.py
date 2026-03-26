import streamlit as st
import pandas as pd
import sys, os, time
from dotenv import load_dotenv

# ─────────────────────────────
# 🔐 LOAD ENV VARIABLES (API KEYS)
# ─────────────────────────────
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# ─────────────────────────────
# 📁 FIX PATH FOR MODULE IMPORTS
# ─────────────────────────────
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
# 🔗 Import project modules
from modules.scanner import run_nmap_scan, parse_nmap_xml, check_virustotal
from modules.analyser import enrich_dataframe
from modules.database import save_scan
from modules.emailer import send_alert_email

# ─────────────────────────────
# 🌐 PAGE CONFIG
# ─────────────────────────────
st.set_page_config(page_title="Cyber Risk Dashboard", layout="wide")

# ─────────────────────────────
# 🎨 PREMIUM CSS (UI STYLING)
# ─────────────────────────────
st.markdown("""
<style>
.big-title {
    font-size: 36px;
    font-weight: 700;
}

.input-label {
    font-size: 22px;
    font-weight: 600;
    margin-bottom: 6px;
}

.glass {
    background: rgba(255,255,255,0.05);
    padding: 15px;
    border-radius: 12px;
    border: 1px solid rgba(255,255,255,0.1);
    margin-bottom: 10px;
}

.stButton > button {
    height: 50px;
    font-size: 16px;
    border-radius: 10px;
    background-color: #2563eb;
    color: white;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────
# 🧭 HEADER
# ─────────────────────────────
st.markdown('<div class="big-title">🛡️ Cyber Risk Assessment Dashboard</div>', unsafe_allow_html=True)
st.caption("🚀 Real-time Vulnerability Scanner")

st.divider()

# ─────────────────────────────
# 🎯 INPUT SECTION
# ─────────────────────────────
st.markdown('<div class="input-label">🎯 Enter Targets (comma separated)</div>', unsafe_allow_html=True)

# 🖥️ User enters targets
targets_input = st.text_input(
    "",
    placeholder="scanme.nmap.org, testphp.vulnweb.com"
)

# 📧 EMAIL INPUT FOR ALERTS
st.markdown('<div class="input-label">📧 Enter your Email for Alerts</div>', unsafe_allow_html=True)

user_email = st.text_input(
    "",
    placeholder="example@gmail.com"
)

# 🔘 BUTTONS
col1, col2 = st.columns(2)
run = col1.button("🚀 Run Scan", use_container_width=True)
refresh = col2.button("🔄 Refresh", use_container_width=True)

# 🔄 Refresh clears previous session data
if refresh:
    st.session_state.clear()
    st.rerun()

# ─────────────────────────────
# 🔍 SCAN PROCESS
# ─────────────────────────────
if run:

    # ⚠️ Validate target input
    if not targets_input:
        st.warning("⚠️ Please enter at least one target")
        st.stop()

    # ⚠️ Validate email
    if not user_email:
        st.warning("⚠️ Please enter your email")
        st.stop()

    if "@" not in user_email:
        st.warning("⚠️ Enter a valid email")
        st.stop()

    # 🧹 Convert input into list
    targets = [t.strip() for t in targets_input.split(",") if t.strip()]
    total = len(targets)

    # 📊 UI placeholders for progress
    title_box = st.empty()
    progress_bar = st.progress(0)
    status_box = st.empty()
    log_box = st.empty()

    title_box.markdown("### 🔍 Scan in Progress...")

    all_data = []

    # 🔁 Loop through each target
    for i, target in enumerate(targets):

        # 📡 Show current scanning target
        status_box.markdown(f"""
        <div class="glass">
        🔎 <b>Scanning Target {i+1}/{total}</b><br>
        🌐 {target}
        </div>
        """, unsafe_allow_html=True)

        # 🚀 Run scan
        with st.spinner(f"Scanning {target}..."):
            xml = run_nmap_scan(target)         # Run Nmap
            rows = parse_nmap_xml(xml)          # Parse results
            time.sleep(0.5)

        # ➕ Add target name to results
        for r in rows:
            r["target"] = target

        # 📊 Live log display
        with log_box.container():
            if rows:
                st.success(f"✅ {target} → {len(rows)} open ports")
            else:
                st.warning(f"⚠️ {target} → No open ports")

        # 📦 Collect all scan data
        all_data.extend(rows)

        # 📈 Update progress bar
        progress_bar.progress((i + 1) / total)

    # 🧹 CLEAN UI AFTER SCAN
    title_box.empty()
    status_box.empty()
    progress_bar.empty()
    log_box.empty()

    # ❌ No data case
    if not all_data:
        st.error("❌ No scan data collected")
        st.stop()

    # 📊 Convert to DataFrame
    df = pd.DataFrame(all_data)

    # ─────────────────────────────
    # 🌐 VIRUSTOTAL INTEGRATION
    # ─────────────────────────────
    with st.spinner("🌐 Fetching Threat Intelligence..."):
        vt_data = {}

        # 🔁 Get threat data for each IP
        for ip in df["ip"].unique():
            vt_data[ip] = check_virustotal(ip, VT_API_KEY)

    # 🧠 Add risk calculations
    df = enrich_dataframe(df, vt_data)

    # 🕒 Add scan timestamp
    df["scan_time"] = pd.Timestamp.now()

    # 💾 Save to database
    save_scan(df)

    # 📧 Send alert email
    email_status = send_alert_email(df, user_email)

    # 📬 Email result messages
    if email_status == "sent":
        st.success("📧 Alert email sent successfully!")
    elif email_status == "no_risk":
        st.info("ℹ️ No high/critical risks detected")
    elif email_status == "no_email":
        st.warning("⚠️ Enter email to receive alerts")
    else:
        st.error("❌ Failed to send email")

    # 💾 Store in session for reuse
    st.session_state["scan_df"] = df

    st.success("🎉 Scan Completed Successfully!")

# ─────────────────────────────
# 📊 RESULTS DISPLAY
# ─────────────────────────────
if "scan_df" in st.session_state:

    df = st.session_state["scan_df"]

    st.divider()
    st.subheader("📊 Summary")

    # 📊 KPI METRICS
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("🖥️ Hosts", df["ip"].nunique())
    col2.metric("🔓 Ports", len(df))
    col3.metric("⚠️ High", (df["severity"] == "High").sum())
    col4.metric("🔥 Critical", (df["severity"] == "Critical").sum())

    # 📈 EXTRA INSIGHTS
    col5, col6, col7 = st.columns(3)

    col5.metric("📈 Avg Risk", round(df["risk_score"].mean(), 2))
    col6.metric("⚡ Most Risky Service", df.groupby("service")["risk_score"].mean().idxmax())
    col7.metric("🎯 Most Vulnerable Host", df.groupby("ip")["risk_score"].sum().idxmax())

    st.divider()

    # 🔍 FILTERS
    st.subheader("🔍 Filters")

    colf1, colf2, colf3 = st.columns(3)

    severity_filter = colf1.selectbox("Severity", ["All"] + sorted(df["severity"].unique()))
    ip_filter = colf2.selectbox("IP", ["All"] + sorted(df["ip"].unique()))
    service_filter = colf3.selectbox("Service", ["All"] + sorted(df["service"].unique()))

    filtered_df = df.copy()

    # 🎯 Apply filters
    if severity_filter != "All":
        filtered_df = filtered_df[filtered_df["severity"] == severity_filter]

    if ip_filter != "All":
        filtered_df = filtered_df[filtered_df["ip"] == ip_filter]

    if service_filter != "All":
        filtered_df = filtered_df[filtered_df["service"] == service_filter]

    st.divider()

    # 🔥 TOP RISKY HOSTS
    st.subheader("🔥 Top 5 Risky Hosts")

    top_risk = (
        df.groupby("ip")["risk_score"]
        .sum()
        .sort_values(ascending=False)
        .head(5)
        .reset_index()
    )

    st.dataframe(top_risk, use_container_width=True)

    st.divider()

    # 📂 FINAL RESULTS TABLE
    st.subheader("📂 Scan Results")
    st.dataframe(filtered_df, use_container_width=True)

else:
    st.info("👉 Enter targets and click 'Run Scan'")