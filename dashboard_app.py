"""
A dashboard for visualizing results from CVEye tools:
- CVEye-Hunter (Local Recon)
- CVEye (Vulnerability Scanner)
- Vendor-Risk-Analyzer
- Compliance_Companion

Features: 
- Upload & scan parsing
- CVE filtering, grouping, and risk breakdowns
- Recon and secrets detection
- Vendor risk reporting
- Compliance tracking with pass/fail summaries
- Exportable PDF reports
- Historical scan tracking and CVE diffing
- Multi-vendor comparisons and tagging support

"""

import streamlit as st
import pandas as pd
import json
import plotly.express as px
import os
from datetime import datetime
from fpdf import FPDF
import matplotlib.pyplot as plt
import seaborn as sns
import io
from collections import Counter

# --- Utility Functions ---

HISTORY_DIR = "scan_history"
os.makedirs(HISTORY_DIR, exist_ok=True)


def load_json(uploaded_file):
    """Load JSON file and return data as a dictionary."""
    try:
        return json.load(uploaded_file)
    except Exception as e:
        st.error(f"Error loading file: {e}")
        return {}


def save_pdf_report(data, password=None):
    """Generate a PDF report from data dictionary and optionally encrypt it using a user-defined or default password."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="CVEye Dashboard Report", ln=True, align='C')
    pdf.ln(10)
    for key, value in data.items():
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(200, 10, txt=key, ln=True)
        pdf.set_font("Arial", '', 9)
        if isinstance(value, list):
            for item in value[:30]:
                pdf.multi_cell(0, 5, txt=str(item))
        else:
            pdf.multi_cell(0, 5, txt=str(value))
        pdf.ln(5)
    filename = f"cveye_dashboard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    # Optional: Use PyPDF2 for encryption if sensitive
    try:
        from PyPDF2 import PdfReader, PdfWriter
        reader = PdfReader(filename)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        if password:
            writer.encrypt(password)
        else:
            writer.encrypt("changeme123")  # Default fallback password  # Replace or prompt for secure password
        with open(filename, 'wb') as f_out:
            writer.write(f_out)
    except Exception as e:
        st.warning(f"PDF encryption skipped: {e}")
    pdf.output(filename)
    return filename


import shutil
from zipfile import ZipFile
from datetime import timedelta

def save_scan_to_history(scan_data, vendor="unknown"):
    """Save scan data to history with timestamp and vendor label."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{HISTORY_DIR}/scan_{vendor}_{ts}.json"

    # Auto-delete or archive old scans (>30 days)
    cutoff = datetime.now() - timedelta(days=30)
    for file in os.listdir(HISTORY_DIR):
        try:
            path = os.path.join(HISTORY_DIR, file)
            if os.path.isfile(path):
                file_time = datetime.fromtimestamp(os.path.getmtime(path))
                if file_time < cutoff:
                    zip_path = os.path.join(HISTORY_DIR, "archived_scans.zip")
                    with ZipFile(zip_path, 'a') as zipf:
                        zipf.write(path, arcname=os.path.basename(path))
                    os.remove(path)
        except Exception as e:
            print(f"Archive error: {file}: {e}")
    with open(filename, 'w') as f:
        json.dump(scan_data, f, indent=2)
    return filename


def load_archived_scans():
    """Load all archived scan files from zip."""
    archive_path = os.path.join(HISTORY_DIR, "archived_scans.zip")
    if not os.path.exists(archive_path):
        return []
    archived = []
    with ZipFile(archive_path, 'r') as zipf:
        for name in zipf.namelist():
            if name.endswith(".json"):
                with zipf.open(name) as jf:
                    try:
                        data = json.load(jf)
                        parts = name.replace("scan_", "").replace(".json", "").split("_")
                        data['vendor'] = parts[0]
                        data['timestamp'] = "_".join(parts[1:])
                        data['archived'] = True
                        archived.append(data)
                    except:
                        continue
    return archived

def load_all_history():
    """Load all past scan files from history directory."""
    files = sorted(os.listdir(HISTORY_DIR))[-10:]
    history = []
    for f in files:
        try:
            with open(os.path.join(HISTORY_DIR, f)) as jf:
                data = json.load(jf)
                name_split = f.replace("scan_", "").replace(".json", "").split("_")
                data['vendor'] = name_split[0]
                data['timestamp'] = "_".join(name_split[1:])
                history.append(data)
        except:
            continue
    return history


def compare_cve_sets(current_cves, historical_cves):
    """Return added and removed CVEs compared to previous scan."""
    current_ids = {c.get("cve_id", str(c)) for c in current_cves}
    historical_ids = {c.get("cve_id", str(c)) for c in historical_cves}
    added = current_ids - historical_ids
    removed = historical_ids - current_ids
    return list(added), list(removed)

# --- Sidebar ---

# Load config from external JSON
CONFIG_PATH = "config.json"
DEFAULT_AUTH = {"admin": "secret"}
try:
    with open(CONFIG_PATH) as cfg:
        CONFIG = json.load(cfg)
except:
    CONFIG = {"auth": DEFAULT_AUTH}

auth_user = st.sidebar.text_input("Username")
auth_pass = st.sidebar.text_input("Password", type="password")
if auth_user not in CONFIG.get("auth", {}) or CONFIG["auth"][auth_user] != auth_pass:
    st.error("Unauthorized. Please enter valid credentials.")
    st.stop()
auth_pass = st.sidebar.text_input("Password", type="password")
if auth_user != "admin" or auth_pass != "secret":
    st.error("Unauthorized. Please enter valid credentials.")
    st.stop()
import smtplib
from email.message import EmailMessage
import subprocess
tag_options = ["web", "internal", "external", "production", "dev", "staging", "network", "api"]
st.sidebar.title("CVEye Dashboard")
st.sidebar.markdown("Upload scan output JSON files from CVEye tools.")
vendor_name = st.sidebar.text_input("Vendor or Client Tag", value="default")
selected_tags = st.sidebar.multiselect("Optional Tags/Categories", tag_options)
pdf_password = st.sidebar.text_input("PDF Password (optional)", type="password")
report_name = st.sidebar.text_input("Optional Report Name/Context", value="")
uploaded_file = st.sidebar.file_uploader("Choose a .json file", type=["json"])

# --- Main App ---

def trigger_scan_command():
    """Trigger a CLI-based scan script and return parsed results as a dictionary."""
    result_file = "latest_scan.json"
    try:
        subprocess.run(["python3", "cveye_cli_scan.py", "-o", result_file], check=True)
        with open(result_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Scan trigger failed: {e}")
        return {}

def send_email_report(recipient, attachment_path):
    """Send an email with a PDF report as an attachment using the local SMTP server."""
    try:
        msg = EmailMessage()
        msg['Subject'] = 'CVEye Dashboard Report'
        msg['From'] = 'cveye@yourdomain.com'
        msg['To'] = recipient
        msg.set_content('Attached is the requested CVEye scan report.')

        with open(attachment_path, 'rb') as f:
            msg.add_attachment(f.read(), maintype='application', subtype='pdf', filename=os.path.basename(attachment_path))

        with smtplib.SMTP(smtp_server, smtp_port) as s:
            s.starttls()
            s.login(smtp_user, smtp_password)
            s.send_message(msg)
        st.success(f"Email sent to {recipient}")
    except Exception as e:
        st.error(f"Failed to send email: {e}")
st.title("CVEye Security Dashboard")

if uploaded_file:
    data = load_json(uploaded_file)

    if data:
        data["tags"] = selected_tags
        if report_name:
            data['report_name'] = report_name
        save_scan_to_history(data, vendor_name)
        st.success(f"Scan results for '{vendor_name}' loaded and saved to history.")

        st.header("Summary")
        if "summary" in data:
            st.json(data["summary"], expanded=False)
        else:
            st.caption("No pre-built summary available. Showing top-level keys.")
            st.json({k: type(v).__name__ for k, v in data.items()})
        if "report_name" in data:
            st.markdown(f"Report Name: {data['report_name']}")
        if "tags" in data:
            st.markdown(f"Tags: {' ,'.join(data['tags'])}")

        if "cves" in data:
            # Optional CVE API enrichment
            if st.checkbox("Enrich CVEs using public API (Vulners/NVD)"):
                from urllib.request import urlopen
                st.info("Looking up CVE metadata, this may take a moment...")
                enriched = []
                for cve in data["cves"][:100]:  # Limit to 20 for performance
                    cve_id = cve.get("cve_id")
                    if cve_id:
                        try:
                            with urlopen(f"https://cve.circl.lu/api/cve/{cve_id}") as response:
                                extra = json.loads(response.read().decode())
                                enriched.append({"cve_id": cve_id, "cvss": extra.get("cvss"), "summary": extra.get("summary")})
                        except:
                            continue
                if enriched:
                    st.subheader("Enriched CVE Metadata")
                    st.dataframe(pd.DataFrame(enriched))
            st.header("📊 CVE Drill-Down & Visualization")
            # Drill-down: CVSS and metadata preview
            meta_df = pd.DataFrame(data["cves"])
            if "cvss" in meta_df.columns:
                st.subheader("CVE Metadata Snapshot")
                st.dataframe(meta_df[["cve_id", "severity", "cvss", "description"]].head(10))

            # Radar chart: CVE category metrics
            if "severity" in meta_df.columns:
                sev_counts = meta_df["severity"].value_counts().to_dict()
                sev_keys = list(sev_counts.keys())
                sev_vals = list(sev_counts.values())
                radar_fig = px.line_polar(r=sev_vals, theta=sev_keys, line_close=True, title="CVE Severity Radar Chart")
                radar_fig.update_traces(fill='toself')
                st.plotly_chart(radar_fig)

            # Risk heatmap: severity x service
            if "severity" in meta_df.columns and "service" in meta_df.columns:
                heatmap_df = meta_df.groupby(["service", "severity"]).size().reset_index(name="count")
                heatmap_pivot = heatmap_df.pivot(index="service", columns="severity", values="count").fillna(0)
                st.subheader("Service vs Severity Heatmap")
                fig3, ax3 = plt.subplots(figsize=(8, 4))
                sns.heatmap(heatmap_pivot, annot=True, fmt=".0f", cmap="Reds", ax=ax3)
                st.pyplot(fig3)
            st.header("CVE Results")
            cves_df = pd.DataFrame(data["cves"])

            severities = cves_df["severity"].unique()
            selected_sev = st.multiselect("Filter by severity", severities, default=list(severities))
            filtered_df = cves_df[cves_df["severity"].isin(selected_sev)]

            keyword = st.text_input("Search by keyword")
            if keyword:
                filtered_df = filtered_df[filtered_df.apply(lambda row: row.astype(str).str.contains(keyword, case=False).any(), axis=1)]

            group_by = st.selectbox("Group by", ["None", "port", "service", "ip"])
            if group_by != "None" and group_by in filtered_df.columns:
                grouped = filtered_df.groupby(group_by).size().reset_index(name='count')
                st.subheader(f"Grouped by {group_by}")
                st.dataframe(grouped)

            st.dataframe(filtered_df, use_container_width=True)

            st.subheader("Severity Breakdown")
            fig = px.histogram(filtered_df, x="severity", color="severity", title="CVEs by Severity")
            st.plotly_chart(fig)

        if "compliance_controls" in data:
            st.header("Compliance Controls")
            comp_df = pd.DataFrame(data["compliance_controls"])
            st.dataframe(comp_df)

            passed = comp_df[comp_df['status'] == 'pass'].shape[0]
            failed = comp_df[comp_df['status'] == 'fail'].shape[0]
            st.metric("Passed √", passed)
            st.metric("Failed x", failed)
            st.metric("Total Controls", len(comp_df))

            fig2, ax = plt.subplots()
            sns.countplot(x='status', data=comp_df, ax=ax)
            ax.set_title("Compliance Control Status")
            st.pyplot(fig2)

        if "shell_secrets" in data:
            st.header("Recon - Local Secrets & History")
            st.subheader("Shell Secrets")
            st.write(data["shell_secrets"])

        if "regex_env_secrets" in data:
            st.subheader("Env Secrets")
            st.write(data["regex_env_secrets"])

        if "writable_binaries_in_PATH" in data:
            st.subheader("Writable Binaries in PATH")
            st.write(data["writable_binaries_in_PATH"])

        if "vendor_score" in data:
            st.header("Vendor Risk Report")
            st.metric("Vendor Score", data["vendor_score"])
            st.write("Risk breakdown:")
            st.json(data.get("vendor_breakdown", {}))

        st.header("Export Report")
        email_recipient = st.text_input("Email Report To (optional)")
smtp_server = st.text_input("SMTP Server", value="smtp.example.com")
smtp_port = st.number_input("SMTP Port", value=587)
smtp_user = st.text_input("SMTP Username")
smtp_password = st.text_input("SMTP Password", type="password")
        if st.button("Generate PDF Report"):
            report_path = save_pdf_report(data, password=pdf_password)
            with open(report_path, "rb") as f:
                st.download_button("Download PDF", f, file_name=report_path)
            if email_recipient:
                send_email_report(email_recipient, report_path)

        st.header("Historical Comparison and Diffs")
        history = load_all_history() + load_archived_scans()
        if history:
            hist_df = pd.DataFrame([{"timestamp": d['timestamp'], "vendor": d['vendor'],
                                     "cves": len(d.get('cves', [])),
                                     "controls": len(d.get('compliance_controls', []))} for d in history])
            fig_hist = px.line(hist_df, x="timestamp", y="cves", color="vendor", markers=True, title="📉 CVE Severity Trend Over Time")
            fig_hist.update_traces(line=dict(shape="spline"))
            st.plotly_chart(fig_hist)
            if 'tags' in history[0]:
                tag_set = sorted(set(tag for entry in history for tag in entry.get('tags', [])))
                tag_filter = st.multiselect("Filter by tag", tag_set, default=tag_set)
                history = [entry for entry in history if any(tag in entry.get('tags', []) for tag in tag_filter)]
                hist_df = pd.DataFrame([{"timestamp": d['timestamp'], "vendor": d['vendor'], "tags": ','.join(d.get('tags', [])), "cves": len(d.get('cves', [])), "controls": len(d.get('compliance_controls', []))} for d in history])
            st.dataframe(hist_df)

            prev_scan = next((h for h in reversed(history[:-1]) if h['vendor'] == vendor_name), None)
            if prev_scan:
                added, removed = compare_cve_sets(data.get("cves", []), prev_scan.get("cves", []))
                st.subheader("Scan Diff vs Previous")
                st.write(f"! New CVEs: {added}")
                st.write(f"- Removed CVEs: {removed}")

else:
    if st.button("Trigger Live Scan"):
        st.warning("Triggering CLI scan...")
        live_data = trigger_scan_command()
        if live_data:
            uploaded_file = io.StringIO(json.dumps(live_data))
            st.experimental_rerun()
    st.info("Please upload a CVEye-compatible scan output (.json) file to begin.")
