from fpdf import FPDF
import pandas as pd

def generate_pdf(df, filename="scan_report.pdf"):

    # 📄 Create PDF object
    pdf = FPDF()

    # 🔄 Enable auto page break
    pdf.set_auto_page_break(auto=True, margin=10)

    # ➕ Add new page
    pdf.add_page()

    # 🔤 Set font style and size
    pdf.set_font("Arial", size=12)

    # 🏷️ Title of the report
    pdf.cell(200, 10, txt="Cyber Risk Assessment Report", ln=True, align="C")

    pdf.ln(5)  # Add space

    # 📊 SUMMARY SECTION
    pdf.cell(200, 10, txt=f"Total Hosts: {df['ip'].nunique()}", ln=True)
    pdf.cell(200, 10, txt=f"Total Ports: {len(df)}", ln=True)
    pdf.cell(200, 10, txt=f"High Risks: {(df['severity']=='High').sum()}", ln=True)
    pdf.cell(200, 10, txt=f"Critical Risks: {(df['severity']=='Critical').sum()}", ln=True)

    pdf.ln(10)  # Space before table

    # 📋 TABLE HEADER
    pdf.cell(40, 10, "IP", 1)
    pdf.cell(20, 10, "Port", 1)
    pdf.cell(40, 10, "Service", 1)
    pdf.cell(30, 10, "Severity", 1)
    pdf.cell(30, 10, "Risk", 1)
    pdf.ln()

    # 📊 TABLE DATA (loop through each row)
    for _, row in df.iterrows():

        # Add each column value to PDF table
        pdf.cell(40, 10, str(row["ip"]), 1)
        pdf.cell(20, 10, str(row["port"]), 1)
        pdf.cell(40, 10, str(row["service"]), 1)
        pdf.cell(30, 10, str(row["severity"]), 1)
        pdf.cell(30, 10, str(round(row["risk_score"], 2)), 1)

        pdf.ln()  # Move to next line

    # 💾 Save PDF file
    pdf.output(filename)

    # 📤 Return file path
    return filename