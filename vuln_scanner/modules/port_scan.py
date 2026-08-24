"""
port_scan.py
============
Performs a lightweight TCP connect scan against a fixed list of
commonly-exposed ports. This is intentionally simple (no raw sockets/
SYN scanning) so it runs without elevated privileges — good enough
for a semester project and safe for authorized educational targets.

For deeper scans, this could later shell out to Nmap using the
python-nmap library.
"""

import socket
from urllib.parse import urlparse

# Port : (service name, why it matters if open/unexpected)
COMMON_PORTS = {
    21: ("FTP", "Often unencrypted; credentials can be sniffed."),
    22: ("SSH", "Should be firewalled or key-only if internet-facing."),
    23: ("Telnet", "Unencrypted remote access — high risk if open."),
    25: ("SMTP", "Can be abused for spam relay if misconfigured."),
    80: ("HTTP", "Expected for web apps; check if HTTPS redirect exists."),
    443: ("HTTPS", "Expected for secure web apps."),
    3306: ("MySQL", "Database port; should not be internet-facing."),
    3389: ("RDP", "Remote desktop; frequent brute-force target."),
    5432: ("PostgreSQL", "Database port; should not be internet-facing."),
    8080: ("HTTP-Alt", "Often used for admin panels/proxies."),
    8443: ("HTTPS-Alt", "Often used for admin panels."),
}


def scan_common_ports(url: str, timeout: float = 1.5) -> dict:
    """
    Attempts a TCP connection to each port in COMMON_PORTS.

    Returns a dict with 'open', 'closed', and 'host'.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname

    result = {"host": hostname, "open": [], "closed": [], "error": None}

    if not hostname:
        result["error"] = "Could not parse hostname from URL."
        return result

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
        return result

    for port, (service, note) in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            outcome = sock.connect_ex((resolved_ip, port))
            if outcome == 0:
                result["open"].append({"port": port, "service": service, "note": note})
            else:
                result["closed"].append(port)
        except socket.error:
            result["closed"].append(port)
        finally:
            sock.close()

    return result
