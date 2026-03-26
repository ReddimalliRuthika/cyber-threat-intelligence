import streamlit as st
import pandas as pd
from modules.database import load_history

# ─────────────────────────────
# 📜 PAGE TITLE
# ─────────────────────────────
st.title("📜 Scan History")

# ─────────────────────────────
# 📥 LOAD DATA FROM DATABASE
# ─────────────────────────────
df = load_history()

# ⚠️ If no history exists
if df.empty:
    st.info("📭 No previous scans found")
    st.stop()

# ─────────────────────────────
# 🧹 PROCESS DATA
# ─────────────────────────────

# Convert scan_time to datetime format
df["scan_time"] = pd.to_datetime(df["scan_time"])

# Sort scans (latest first)
df = df.sort_values(by="scan_time", ascending=False)

# Get unique scan timestamps (each scan = one group)
scan_times = df["scan_time"].drop_duplicates()

# Show total number of scans
st.success(f"📦 Total Scans: {len(scan_times)}")

# ─────────────────────────────
# 📂 DISPLAY EACH SCAN
# ─────────────────────────────
for i, scan_time in enumerate(scan_times):

    # 📊 Filter data for a specific scan
    group = df[df["scan_time"] == scan_time]

    # 🕒 Create expandable section for each scan
    with st.expander(
        f"🕒 Scan: {scan_time.strftime('%Y-%m-%d %H:%M:%S')}",
        expanded=(i == 0)  # Latest scan open by default
    ):

        # ─── 📊 METRICS ───
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("🖥️ Hosts", group["ip"].nunique())
        col2.metric("🔓 Ports", len(group))
        col3.metric("⚠️ High", (group["severity"] == "High").sum())
        col4.metric("🔥 Critical", (group["severity"] == "Critical").sum())

        # ─── 📋 TABLE ───
        # Display scan results
        st.dataframe(group, use_container_width=True)

        st.divider()