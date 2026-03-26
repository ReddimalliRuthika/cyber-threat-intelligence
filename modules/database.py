import sqlite3
import pandas as pd

# 🗄️ Database file name
DB_NAME = "cyber.db"

# ─────────────────────────────
# 💾 SAVE SCAN DATA TO DATABASE
# ─────────────────────────────
def save_scan(df):

    # 🔌 Connect to SQLite database
    conn = sqlite3.connect(DB_NAME)

    # ✅ Create table if it does not exist
    conn.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        target TEXT,
        ip TEXT,
        port INTEGER,
        service TEXT,
        malicious INTEGER,
        suspicious INTEGER,
        exposure_score REAL,
        threat_score REAL,
        risk_score REAL,
        severity TEXT,
        scan_time TEXT
    )
    """)

    # 📥 Insert dataframe into database table
    df.to_sql("scans", conn, if_exists="append", index=False)

    # 💾 Save changes and close connection
    conn.commit()
    conn.close()


# ─────────────────────────────
# 📜 LOAD SCAN HISTORY
# ─────────────────────────────
def load_history():

    # 🔌 Connect to database
    conn = sqlite3.connect(DB_NAME)

    try:
        # 📊 Read all scan records into dataframe
        df = pd.read_sql("SELECT * FROM scans", conn)

    except:
        # ⚠️ If table doesn't exist or error occurs
        df = pd.DataFrame()

    # 🔒 Close connection
    conn.close()

    # 📤 Return dataframe
    return df