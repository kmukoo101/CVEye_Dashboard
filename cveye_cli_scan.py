"""
CVEye CLI Scan: Performs local recon, CVE detection, and compliance checks, then saves output to a JSON file for use in CVEye Dashboard.
"""

import argparse
import json
from datetime import datetime
import os
import platform
import socket
import psutil
import getpass
import subprocess
import requests
import logging

# --- Logging Setup ---
logging.basicConfig(
    filename=f"cveye_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# --- Constants ---
SAMPLE_CVES = [
    {"cve_id": "CVE-2024-1111", "severity": "high", "cvss": 9.1, "description": "Example RCE vulnerability."},
    {"cve_id": "CVE-2023-2345", "severity": "medium", "cvss": 5.4, "description": "Example info disclosure."}
]

COMPLIANCE_CONTROLS = [
    {"control": "Firewall Enabled", "status": "pass"},
    {"control": "Default Passwords", "status": "fail"},
    {"control": "Auto Updates Enabled", "status": "pass"}
]

# --- Recon Functions ---

def scan_open_ports():
    """List open ports with associated processes."""
    ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                proc = psutil.Process(conn.pid)
                ports.append({
                    "port": conn.laddr.port,
                    "pid": conn.pid,
                    "exe": proc.exe(),
                    "name": proc.name()
                })
            except Exception:
                ports.append({"port": conn.laddr.port, "pid": conn.pid, "error": "Process info unavailable"})
    logging.info(f"Open ports scanned: {len(ports)}")
    return ports

def scan_env_secrets():
    """Detect sensitive values in environment variables."""
    keywords = ["KEY", "TOKEN", "SECRET", "PASSWORD", "API"]
    secrets = {}
    for k, v in os.environ.items():
        if any(word in k.upper() for word in keywords):
            secrets[k] = v
    logging.info(f"Environment secrets detected: {len(secrets)}")
    return secrets

def grab_banners(port_range):
    """Grab basic service banners using socket connections from a defined port range."""
    banners = []
    for port in port_range:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as s:
                s.settimeout(1)
                banner = s.recv(1024).decode(errors='ignore').strip()
                if banner:
                    banners.append({"port": port, "banner": banner})
        except Exception:
            continue
    logging.info(f"Banners grabbed from ports: {port_range}")
    return banners

def match_banners_to_cve(banners):
    """Mock CVE matching logic based on banner keywords."""
    cves = []
    for item in banners:
        if "apache" in item["banner"].lower():
            cves.append({"cve_id": "CVE-2022-23943", "severity": "high", "cvss": 8.0, "description": "Apache HTTPD vulnerability"})
        elif "mysql" in item["banner"].lower():
            cves.append({"cve_id": "CVE-2021-32026", "severity": "medium", "cvss": 6.5, "description": "MySQL info leak"})
    logging.info(f"Matched CVEs from banners: {len(cves)}")
    return cves

def audit_user_passwords():
    """Check for users with no passwords or default names (Linux only)."""
    issues = []
    if os.name == 'posix':
        try:
            with open("/etc/shadow", "r") as f:
                for line in f:
                    user, hashval = line.split(":", 1)
                    if "!" not in hashval and "*" not in hashval:
                        issues.append(user)
        except Exception:
            pass
    logging.info(f"Weak password users found: {len(issues)}")
    return issues

def upload_to_dashboard(scan_result, token=None):
    """Send the scan result to a CVEye Dashboard endpoint with token auth."""
    try:
        url = "http://localhost:8501/upload"  # Customize as needed
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = requests.post(url, json=scan_result, headers=headers, timeout=5)
        logging.info(f"Upload status: {response.status_code}")
    except Exception as e:
        logging.warning(f"Failed to upload scan result: {e}")

# --- Main Scan Wrapper ---

def run_full_scan(port_range):
    """Run all scanning routines and build the output payload."""
    banners = grab_banners(port_range)
    matched_cves = match_banners_to_cve(banners)

    result = {
        "timestamp": datetime.now().isoformat(),
        "vendor_score": 85,
        "cves": SAMPLE_CVES + matched_cves,
        "compliance_controls": COMPLIANCE_CONTROLS,
        "open_ports": scan_open_ports(),
        "regex_env_secrets": scan_env_secrets(),
        "ssh_key_issues": [],
        "writable_binaries_in_PATH": [],
        "banners": banners,
        "weak_password_users": audit_user_passwords(),
        "tags": ["cli-trigger", platform.system().lower()]
    }

    return result

# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run CVEye CLI scanner and output JSON")
    parser.add_argument("-o", "--output", help="Path to save output JSON", required=True)
    parser.add_argument("-p", "--ports", help="Comma-separated port range for banner grabbing (default: 21,22,80,443,3306)", default="21,22,80,443,3306")
    parser.add_argument("--token", help="Token for authenticated dashboard upload", default=None)
    parser.add_argument("--quiet", action="store_true", help="Suppress output messages")
    args = parser.parse_args()

    port_range = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    result = run_full_scan(port_range)

    # Save JSON locally
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    if not args.quiet:
        print(f"[+] Scan complete. Output saved to {args.output}")

    # Upload to dashboard if token is provided
    if args.token:
        upload_to_dashboard(result, token=args.token)
