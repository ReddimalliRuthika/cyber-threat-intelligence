import streamlit as st
import pandas as pd
import sys, os, json

# 📁 Fix import path to access modules folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 📄 Import PDF generation module
from modules.report import generate_pdf

# 📄 Page title
st.title("📄 Download Report")

# ─────────────────────────────
# ⚠️ CHECK IF DATA EXISTS
# ─────────────────────────────
if "scan_df" not in st.session_state:
    st.warning("⚠️ Run a scan first")
    st.stop()

# 📥 Load current scan data
df = st.session_state["scan_df"]

# ─────────────────────────────
# 📊 SUMMARY SECTION
# ─────────────────────────────
st.subheader("📊 Current Scan Summary")

# 📊 KPI metrics
col1, col2, col3, col4 = st.columns(4)

col1.metric("🖥️ Hosts", df["ip"].nunique())
col2.metric("🔓 Ports", len(df))
col3.metric("⚠️ High", (df["severity"] == "High").sum())
col4.metric("🔥 Critical", (df["severity"] == "Critical").sum())

st.divider()

# ─────────────────────────────
# 🔥 TOP RISKY HOSTS
# ─────────────────────────────
st.subheader("🔥 Top Risky Hosts")

# 📊 Calculate top 5 risky IPs
top_risk = (
    df.groupby("ip")["risk_score"]
    .sum()
    .sort_values(ascending=False)
    .head(5)
    .reset_index()
)

# 📋 Display table
st.dataframe(top_risk, use_container_width=True)

st.divider()

# ─────────────────────────────
# ⬇️ DOWNLOAD OPTIONS
# ─────────────────────────────
st.subheader("⬇️ Download Options")

# Create 3 columns for download buttons
col1, col2, col3 = st.columns(3)

# 📄 PDF DOWNLOAD
with col1:
    if st.button("📄 Generate PDF"):
        # Generate PDF file
        file_path = generate_pdf(df)

        # Provide download option
        with open(file_path, "rb") as f:
            st.download_button(
                label="⬇️ Download PDF",
                data=f,
                file_name="cyber_risk_report.pdf",
                mime="application/pdf"
            )

# 📊 CSV DOWNLOAD
with col2:
    # Convert dataframe to CSV format
    csv = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="📊 Download CSV",
        data=csv,
        file_name="scan_results.csv",
        mime="text/csv"
    )

# 🌐 JSON DOWNLOAD (API FORMAT)
with col3:
    # Convert dataframe to JSON format
    json_data = df.to_json(orient="records", indent=2)

    st.download_button(
        label="🌐 Download JSON",
        data=json_data,
        file_name="scan_results.json",
        mime="application/json"
    )