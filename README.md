# CVEye Security Suite

This is an integrated open-source toolkit designed to help cybersecurity professionals identify local risks, weak configurations, and CVEs across systems. 

Tools Included:
- CVEye-Hunter: Local recon assistant
- CVEye: Vulnerability scanner with CVE detection
- Vendor-Risk-Analyzer: Third-party risk visibility (Shodan, HIBP, etc.)
- Compliance_Companion: Control compliance checker
- CVEye Dashboard: Streamlit-based GUI for visualization, drilldown, and export
- cveye_cli_scan.py: Real scanner backend for automated and GUI-triggered assessments

---

## Features

- CVE detection via banner matching and port scan
- Local recon: environment secrets, SSH audit, open ports, startup checks
- Compliance control logic and weak user password checks
- Banner grabbing with customizable port range
- CVE enrichment, grouping, filtering, and drilldown
- Secure PDF export with encryption
- Historical scan comparison, tagging, and auto-archival
- GUI dashboard (Streamlit) with charts and timelines
- Real-time CLI scan trigger with result upload
- Multi-user login with roles
- Auto-email delivery via SMTP
- Token-authenticated scan uploads
- Logging and quiet/verbose CLI support

---

## ⚙ Getting Started

### Requirements

- Python 3.7+
- Run:
```bash
pip install -r requirements.txt
```

Required packages:
`streamlit`, `plotly`, `pandas`, `fpdf`, `matplotlib`, `seaborn`, `psutil`, `PyPDF2`, `requests`

---

## CVEye Dashboard

To launch the GUI dashboard:
```bash
streamlit run dashboard_app.py
```

It supports:
- JSON upload from any CVEye tool
- CVE filtering, enrichment, risk drill-down
- Compliance summaries
- Radar, heatmap, and timeline visuals
- Report export (PDF + password)
- Email delivery via SMTP
- Scan comparison & archive

---

## Configuration

Create a `config.json` file:

```json
{
  "auth": {
    "admin": "changeme123",
    "analyst": "readonly2025"
  },
  "smtp": {
    "server": "smtp.example.com",
    "port": 587,
    "username": "you@example.com",
    "password": "your_smtp_password"
  }
}
```

---

## CLI Scanner (`cveye_cli_scan.py`)

Run standalone:
```bash
python cveye_cli_scan.py -o scan.json
```

With optional features:
```bash
python cveye_cli_scan.py \\
  -o scan.json \\
  --ports 21,22,80,443,3306,8080 \\
  --token YOUR_DASHBOARD_TOKEN \\
  --quiet
```

- `--ports`: Customize banner grabbing
- `--token`: Send scan to dashboard endpoint
- `--quiet`: Suppress console output (for automation)

---

## Report & Archive Management

- Reports saved in `scan_history/` with timestamp
- After 30 days, scans are zipped into `archived_scans.zip`
- Archived scans are still visible and comparable in the dashboard

---

## Auth & Upload

- CLI uploads use token-based auth (via `--token`)
- Dashboard logins use `config.json` roles
- PDF export supports optional password encryption

