def enrich_dataframe(df, vt_data):

    # 🧪 Add VirusTotal threat data to dataframe
    df["malicious"] = df["ip"].map(lambda ip: vt_data[ip]["malicious"])
    df["suspicious"] = df["ip"].map(lambda ip: vt_data[ip]["suspicious"])

    # 📊 Function to assign exposure score based on service type
    def exposure(service):
        if service in ["telnet", "ftp", "rdp"]:
            return 8   # High exposure services
        elif service in ["ssh", "http"]:
            return 5   # Medium exposure services
        return 2       # Low exposure services

    # 📈 Apply exposure scoring
    df["exposure_score"] = df["service"].apply(exposure)

    # ⚠️ Calculate threat score using VirusTotal data
    df["threat_score"] = df["malicious"] * 2 + df["suspicious"]

    # 🧠 Final risk score calculation (weighted formula)
    df["risk_score"] = df["exposure_score"] * 0.6 + df["threat_score"] * 0.4

    # 🚨 Function to classify severity based on risk score
    def severity(score):
        if score >= 7:
            return "Critical"
        elif score >= 5:
            return "High"
        elif score >= 3:
            return "Medium"
        return "Low"

    # 🏷️ Assign severity labels
    df["severity"] = df["risk_score"].apply(severity)

    # 📤 Return enriched dataframe
    return df