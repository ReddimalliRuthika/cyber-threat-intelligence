import streamlit as st

st.set_page_config(page_title="Home", layout="wide")

# 🏠 Title
st.title("🏠 Cyber Risk Assessment System")

st.markdown("""
## 👋 Welcome!

This project is a **Cyber Risk Assessment Dashboard**.

### 🔍 What it does:
- Scans websites/IPs using Nmap
- Detects open ports and services
- Uses VirusTotal for threat intelligence
- Calculates risk score
- Sends email alerts 🚨
- Stores scan history 📜
- Generates reports 📄

---

## 🚀 Start your scan now
""")

# 🔘 BUTTON TO GO TO DASHBOARD
if st.button("🚀 Go to Dashboard"):
    st.switch_page("pages/1_app.py")