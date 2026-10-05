#!/usr/bin/env python3

import argparse
import sys
from urllib.parse import urlparse

from modules import headers_check, path_check, port_scan, scorer, ssl_check
from modules.report_generator import generate_pdf_report


BANNER = r"""
 __      __      _         _____
 \ \    / /     | |       / ____|
  \ \  / /_ _ ___| |_ __ _| (___   ___ __ _ _ __
   \ \/ / _` / __| __/ _` |\___ \ / __/ _` | '_ \
    \  / (_| \__ \ || (_| |____) | (_| (_| | | | |
     \/ \__,_|___/\__\__,_|_____/ \___\__,_|_| |_|

        Web App Vulnerability Scanner
"""


def validate_url(url: str) -> str:
    """Return a normalized HTTP(S) URL or raise a useful validation error."""
    value = url.strip()
    if not value:
        raise ValueError("The target URL cannot be empty.")

    parsed = urlparse(value if "://" in value else f"http://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("The target must be a valid HTTP or HTTPS URL.")

    return parsed.geturl().rstrip("/")


def run_scan(target_url: str):
    print(BANNER)
    print(f"[*] Target: {target_url}")
    print("[*] Starting scan...\n")

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

    try:
        target_url = validate_url(args.url)
    except ValueError as error:
        parser.error(str(error))

    results, score_summary = run_scan(target_url)

    if args.report:
        pdf_path = generate_pdf_report(target_url, results, score_summary)
        print(f"\n[+] PDF report saved to: {pdf_path}")


if __name__ == "__main__":
    main()
