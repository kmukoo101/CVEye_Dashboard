# CVEye Dashboard

This is a streamlit app for analyzing, visualizing, and comparing scan data from the CVEye suite of tools:

- CVEye-Hunter: Local recon assistant
- CVEye: Port and CVE vulnerability scanner
- Vendor-Risk-Analyzer: Reputation and exposure assessment
- Compliance_Companion: Security control compliance tool

This tool provides a centralized way to upload and review scan results, track historical security trends, compare scan diffs, and export encrypted reports.

---

## Features

- Upload and parse scan results from CVEye JSON files
- CVE drill-down with filtering, keyword search, grouping, and CVSS metadata
- Radar charts, heatmaps, and CVE severity trend animations
- Enrichment via CIRCL API (optional, toggle-based)
- Compliance summary with control pass/fail metrics
- Tag scans by category (e.g., production, internal, API)
- Save reports with context names
- Automatic archival of old scans after 30 days
- Password-protected PDF report export
- Secure email delivery of reports via SMTP
- Real-time scan triggering (CLI integration)
- Role-based authentication (admin, analyst, etc.)
- Load archived scans and compare to current ones

---

## Getting Started

### Prerequisites

- Python 3.7+
- Run:  
  ```
  pip install -r requirements.txt
  ```

Dependencies include:
- `streamlit`
- `plotly`
- `pandas`
- `fpdf`
- `matplotlib`
- `seaborn`
- `PyPDF2`

---

## Usage

### 1. Start Dashboard

```bash
streamlit run dashboard_app.py
```

### 2. Login

Use credentials defined in `config.json`.

---

## Configuration

Create a file named `config.json` in your root directory.

```json
{
  "auth": {
    "admin": "changeme123",
    "analyst": "readonly2025",
    "auditor": "complianceCheck"
  },
  "smtp": {
    "server": "smtp.yourmail.com",
    "port": 587,
    "username": "you@example.com",
    "password": "your_smtp_password"
  }
}
```

- Add or edit users in the `"auth"` block.
- Update SMTP settings to enable email delivery.
- If `config.json` is missing, a default single-user login (`admin:secret`) is applied.

---

## Exported Reports

- Reports are saved as PDFs, encrypted with a password if provided.
- Old scans (30+ days) are automatically moved into a ZIP archive.
- You can re-load archived scans and compare them with the latest scan.

---

## Optional CLI Integration

To enable live scan triggering, ensure `cveye_cli_scan.py` exists in the same directory. The dashboard can invoke this script with:

```bash
python3 cveye_cli_scan.py -o latest_scan.json
```

The output/results file is automatically loaded and parsed.

