#!/usr/bin/env python3
"""
Web App Vulnerability Scanner
==============================
A mid-level security scanning tool that checks a target web application
for common misconfigurations:
    - Missing/weak HTTP security headers
    - SSL/TLS certificate issues
    - Open ports (common service ports)
    - Exposed sensitive files/paths (robots.txt, .git, .env, admin panels)

Produces a scored risk report (console + PDF).

ETHICAL USE NOTICE:
Only scan applications you own or are explicitly authorized to test
(e.g. DVWA, testphp.vulnweb.com, or your own local test server).
Scanning systems without permission may be illegal.

Usage:
    python main.py --url https://example.com
    python main.py --url http://testphp.vulnweb.com --report
"""

import argparse
import sys
from urllib.parse import urlparse

from modules import headers_check, ssl_check, port_scan, path_check, scorer
from modules.report_generator import generate_pdf_report


BANNER = r"""
 __      __      _         _____
 \ \    / /     | |       / ____|
  \ \  / /_ _ ___| |_ __ _| (___   ___ __ _ _ __
   \ \/ / _` / __| __/ _` |\___ \ / __/ _` | '_ \
    \  / (_| \__ \ || (_| |____) | (_| (_| | | | |
     \/ \__,_|___/\__\__,_|_____/ \___\__,_|_| |_|

        Web App Vulnerability Scanner (Educational)
"""


def validate_url(url: str) -> str:
    """Ensure the URL has a scheme; default to http:// if missing."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
    return url


def run_scan(target_url: str):
    print(BANNER)
    print(f"[*] Target: {target_url}")
    print(f"[*] Starting scan...\n")

    results = {}

    print("[1/4] Checking HTTP security headers...")
    results["headers"] = headers_check.check_headers(target_url)

    print("[2/4] Checking SSL/TLS certificate...")
    results["ssl"] = ssl_check.check_ssl(target_url)

    print("[3/4] Scanning common ports...")
    results["ports"] = port_scan.scan_common_ports(target_url)

    print("[4/4] Checking for exposed sensitive paths...")
    results["paths"] = path_check.check_sensitive_paths(target_url)

    print("\n[*] Scan complete. Calculating risk score...\n")
    score_summary = scorer.calculate_score(results)

    scorer.print_report(target_url, results, score_summary)

    return results, score_summary


def main():
    parser = argparse.ArgumentParser(
        description="Educational web application vulnerability scanner."
    )
    parser.add_argument(
        "--url", required=True, help="Target URL (e.g. https://example.com)"
    )
    parser.add_argument(
        "--report", action="store_true", help="Generate a PDF report after scanning"
    )
    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        help="Confirm you are authorized to scan this target",
    )
    args = parser.parse_args()

    if not args.i_have_permission:
        print(
            "\n[!] You must confirm authorization to scan this target.\n"
            "    Re-run with --i-have-permission if you own this system\n"
            "    or have explicit permission (e.g. DVWA, your own test app).\n"
        )
        sys.exit(1)

    target_url = validate_url(args.url)
    results, score_summary = run_scan(target_url)

    if args.report:
        pdf_path = generate_pdf_report(target_url, results, score_summary)
        print(f"\n[+] PDF report saved to: {pdf_path}")


if __name__ == "__main__":
    main()
