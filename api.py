from fastapi import FastAPI
import sqlite3
import pandas as pd

# 🚀 Initialize FastAPI app
app = FastAPI(
    title="Cyber Risk API",
    version="1.0",
    description="API for Cyber Risk Dashboard"
)

# 🗄️ Database file name
DB_NAME = "cyber.db"

# ─────────────────────────────
# 📊 GET ALL RESULTS
# ─────────────────────────────
@app.get("/results")
def get_results():

    # 🔌 Connect to database
    conn = sqlite3.connect(DB_NAME)

    # 📥 Load all scan records into dataframe
    df = pd.read_sql("SELECT * FROM scans", conn)

    # 🔒 Close connection
    conn.close()

    # 📤 Return data as JSON
    return {
        "count": len(df),
        "data": df.to_dict(orient="records")
    }


# ─────────────────────────────
# 🔍 FILTER BY SEVERITY
# ─────────────────────────────
@app.get("/results/severity/{level}")
def get_by_severity(level: str):

    # 🔌 Connect to database
    conn = sqlite3.connect(DB_NAME)

    # 📥 Load data
    df = pd.read_sql("SELECT * FROM scans", conn)

    # 🔒 Close connection
    conn.close()

    # 🎯 Filter by severity (case-insensitive)
    df = df[df["severity"].str.lower() == level.lower()]

    # 📤 Return filtered results
    return {
        "count": len(df),
        "data": df.to_dict(orient="records")
    }


# ─────────────────────────────
# 🌐 FILTER BY IP
# ─────────────────────────────
@app.get("/results/ip/{ip}")
def get_by_ip(ip: str):

    # 🔌 Connect to database
    conn = sqlite3.connect(DB_NAME)

    # 📥 Load data
    df = pd.read_sql("SELECT * FROM scans", conn)

    # 🔒 Close connection
    conn.close()

    # 🎯 Filter records for specific IP
    df = df[df["ip"] == ip]

    # 📤 Return filtered results
    return {
        "count": len(df),
        "data": df.to_dict(orient="records")
    }


# ─────────────────────────────
# 🏠 ROOT ENDPOINT
# ─────────────────────────────
@app.get("/")
def home():

    # 📡 Simple status check API
    return {"status": "API running 🚀"}