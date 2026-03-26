import subprocess
import xml.etree.ElementTree as ET
import requests
import os

# 📁 Folder to store scan results (XML files)
SCAN_DIR = "scan_results"

# 📂 Create folder if it does not exist
os.makedirs(SCAN_DIR, exist_ok=True)


# ─────────────────────────────
# 🚀 RUN NMAP SCAN
# ─────────────────────────────
def run_nmap_scan(target):

    # 📄 Create XML file path for this target
    file = os.path.join(SCAN_DIR, f"{target}.xml")

    # 🛰️ Run Nmap scan (service detection + XML output)
    subprocess.run(
        ["nmap", "-Pn", "-sV", "-oX", file, target],
        stdout=subprocess.DEVNULL,   # Hide output
        stderr=subprocess.DEVNULL
    )

    # 📤 Return XML file path
    return file


# ─────────────────────────────
# 📊 PARSE NMAP XML
# ─────────────────────────────
def parse_nmap_xml(file):

    data = []

    # ❌ If file does not exist → return empty
    if not os.path.exists(file):
        return data

    try:
        # 📄 Load XML file
        root = ET.parse(file).getroot()

        # 🔍 Loop through each host
        for host in root.findall("host"):

            addr = host.find("address")
            if addr is None:
                continue

            # 🌐 Extract IP address
            ip = addr.get("addr", "unknown")

            # 🔓 Loop through ports
            for port in host.findall(".//port"):

                state = port.find("state")

                # ❌ Skip closed ports
                if state is None or state.get("state") != "open":
                    continue

                svc = port.find("service")

                # 📌 Add parsed data
                data.append({
                    "ip": ip,
                    "port": int(port.get("portid", 0)),
                    "service": svc.get("name", "unknown") if svc is not None else "unknown"
                })

    except Exception as e:
        # ❌ Handle XML parsing error
        print("XML Parse Error:", e)

    # 📤 Return parsed data list
    return data


# ─────────────────────────────
# 🌐 VIRUSTOTAL CHECK
# ─────────────────────────────
def check_virustotal(ip, key):

    # ❌ If no API key → return safe default
    if not key:
        return {"malicious": 0, "suspicious": 0}

    try:
        # 🌐 Call VirusTotal API
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=10
        )

        # ❌ If API fails → return default
        if response.status_code != 200:
            return {"malicious": 0, "suspicious": 0}

        # 📄 Convert response to JSON
        data = response.json()

        # 📊 Extract analysis statistics
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        # 📌 Return malicious & suspicious counts
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }

    except Exception as e:
        # ❌ Handle API error
        print("VT Error:", e)
        return {"malicious": 0, "suspicious": 0}