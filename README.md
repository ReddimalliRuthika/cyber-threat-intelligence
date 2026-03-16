# cyber-threat-intelligence
# Web Vulnerability Scanner Dashboard

## Assignment 3  
**Web Application Vulnerability Scanning, Risk Evaluation & Alert System**

This project implements a web vulnerability scanner that detects security issues in websites, evaluates their risk level, visualizes the results using a dashboard, and sends email alerts when high-severity vulnerabilities are found.

---

## Features

### Vulnerability Scanner
The scanner checks target websites for common security weaknesses such as:

- Missing HTTPS
- Missing security headers (X-Frame-Options, Content-Security-Policy, X-Content-Type-Options)
- Forms without action attributes
- Directory listing enabled
- Server header exposure
- Website unreachable detection

Each vulnerability is assigned a severity level: **Critical, High, Medium, or Low**.

---

## Risk Evaluation

Each vulnerability contributes to a risk score:

| Severity | Score |
|--------|--------|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 2 |

The system calculates the total risk score for each scanned website.

---

## Dashboard

A **Streamlit dashboard** is used to visualize the scan results.  
The dashboard includes:

- Vulnerability results table
- Severity distribution chart
- Vulnerability type chart
- Severity histogram
- Vulnerabilities per website chart
- Risk score per target

These charts help quickly understand the security status of the scanned websites.

---

## Email Alert System

When **High or Critical vulnerabilities** are detected, the system automatically sends an **HTML email alert** containing:

- Target website
- Vulnerability details
- Severity level
- Recommended action

Lower severity issues do not trigger alerts.

---

## Technologies Used

- Python
- Requests
- BeautifulSoup
- Pandas
- Plotly
- Streamlit
- SMTP Email
- Google Colab

---

## Project Files

web_vulnerability_scanner_dashboard.ipynb
dashboard.py
scan_results.csv
README.md


---

   
