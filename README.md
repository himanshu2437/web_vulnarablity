# Web Application Vulnerability Scanner

A small Python command-line tool for authorized security checks against web
applications. It looks for common configuration problems and produces a
human-readable console summary, with an optional PDF report.

## ⚠️ Ethical Use

**Only scan applications you own or have explicit permission to test.**
Scanning systems without authorization can be illegal under laws like
the IT Act (India) or similar computer misuse laws elsewhere.

Safe practice targets:
- `http://testphp.vulnweb.com` (Acunetix's public test site)
- [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web App) — run locally
- Your own local dev server

## What It Checks

| Module | What it does |
|---|---|
| **Headers** | Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| **SSL/TLS** | Validates certificate expiry, issuer, and protocol strength |
| **Ports** | TCP connect scan on common ports (FTP, SSH, DB ports, etc.) |
| **Paths** | Checks for exposed sensitive files (`.git/config`, `.env`, backups, etc.) |
| **Scorer** | Combines all findings into a weighted 0–100 risk score + letter grade |

## Project Structure

```
vuln_scanner/
├── main.py                    # CLI entry point
├── requirements.txt
├── modules/
│   ├── headers_check.py       # Security header analysis
│   ├── ssl_check.py           # SSL/TLS certificate analysis
│   ├── port_scan.py           # Common port scanning
│   ├── path_check.py          # Sensitive file/path exposure
│   ├── scorer.py              # Risk scoring + console report
│   └── report_generator.py    # PDF report generation (ReportLab)
└── reports/                   # Generated PDF reports land here
```

## Installation

```bash
pip install -r requirements.txt
```

Python 3.9 or newer is recommended.

## Usage

```bash
# Basic scan (console output only)
python main.py --url http://testphp.vulnweb.com --i-have-permission

# Scan + generate PDF report
python main.py --url http://testphp.vulnweb.com --i-have-permission --report
```

The `--i-have-permission` flag is a deliberate safeguard — the tool
refuses to run without it, forcing the user to consciously confirm
authorization before scanning any target.

The scanner makes network requests and opens TCP connections. Use it only
against systems you own or have written permission to assess. The port and
path checks run concurrently to keep scans reasonably quick.

## How the Scoring Works

Every scan starts at 100 points. Points are deducted per finding based
on severity:

- **High** severity (missing CSP/HSTS, expired SSL, exposed `.env`, risky open ports like FTP/RDP): **-15 to -20**
- **Medium** severity (missing X-Frame-Options, exposed admin panel): **-8**
- **Low** severity (missing Referrer-Policy, robots.txt exposure): **-3**

Final grade: A (90+) · B (75+) · C (60+) · D (40+) · F (below 40)

## Possible Extensions

- Add authenticated scanning (login + session cookie support)
- Integrate `python-nmap` for deeper port/service fingerprinting
- Add XSS/SQLi payload testing against DVWA (safe, isolated lab only)
- Web dashboard (Flask) instead of CLI
- Scan history stored in SQLite to track risk score over time

## Why This Project (for HOD/viva)

This tool mirrors real-world tasks in a SOC/AppSec workflow:
reconnaissance (open ports, exposed paths), configuration auditing
(headers, SSL), and reporting (scored, prioritized findings) — the
same lifecycle used by tools like Nessus, Nikto, and OWASP ZAP, just
built from first principles to demonstrate understanding rather than
just running an existing scanner.
