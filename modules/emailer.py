import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv

# 🔐 Load environment variables (email credentials)
load_dotenv()

# 📧 Sender email and password from .env
SENDER = os.getenv("EMAIL_SENDER")
PASSWORD = os.getenv("EMAIL_PASSWORD")


def send_alert_email(df, receiver_email):

    # ❌ If user didn't enter email
    if not receiver_email:
        return "no_email"

    # 🔍 Filter only High and Critical risks
    alerts = df[df["severity"].isin(["High", "Critical"])]

    # ❌ If no risky ports found
    if alerts.empty:
        return "no_risk"

    # 📄 Initialize email content details
    details = ""

    # 🔁 Loop through each risky row
    for _, row in alerts.iterrows():

        service = str(row["service"]).lower()
        ip = row["ip"]
        target = row.get("target", "Unknown")

        # ✅ Provide simple explanation for each service
        if service == "telnet":
            reason = "No encryption → attackers can read data"
        elif service == "ftp":
            reason = "Transfers data in plain text"
        elif service == "rdp":
            reason = "Remote access → brute-force risk"
        elif service == "ssh":
            reason = "Needs strong password protection"
        elif service == "http":
            reason = "Not secure (use HTTPS)"
        else:
            reason = "Service may be exposed"

        # 📌 Add formatted details to email body
        details += f"""
🔴 Target: {target}
   IP: {ip}
   Service: {service.upper()}
   Severity: {row['severity']}
   Cause: {reason}
"""

    # 📧 EMAIL BODY CONTENT
    body = f"""
🚨 CYBER RISK ALERT 🚨

High / Critical vulnerabilities detected.

━━━━━━━━━━━━━━━━━━━━━━
{details}
━━━━━━━━━━━━━━━━━━━━━━

👉 Recommended Actions:
- Close unused ports
- Use secure protocols (HTTPS)
- Set strong passwords
- Enable firewall

Stay safe 🔐
"""

    # 📩 Create email message
    msg = MIMEText(body)
    msg["Subject"] = "🚨 Cyber Risk Alert"
    msg["From"] = SENDER
    msg["To"] = receiver_email

    try:
        # 🔐 Connect to Gmail SMTP server (secure SSL)
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)

        # 🔑 Login using sender credentials
        server.login(SENDER, PASSWORD)

        # 📤 Send email
        server.sendmail(SENDER, receiver_email, msg.as_string())

        # 🔒 Close connection
        server.quit()

        return "sent"

    except Exception as e:
        # ❌ Print error if email fails
        print("Email Error:", e)
        return "failed"