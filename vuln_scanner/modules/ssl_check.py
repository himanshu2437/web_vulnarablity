"""
ssl_check.py
============
Checks the SSL/TLS certificate of a target host: validity, expiry date,
and whether a weak/outdated protocol is in use.
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def check_ssl(url: str, timeout: int = 8) -> dict:
    """
    Connects to the target host on port 443 and inspects its certificate.

    Returns a dict describing certificate validity, expiry, issuer,
    and any detected issues.
    """
    result = {
        "has_ssl": False,
        "valid": False,
        "expires": None,
        "days_until_expiry": None,
        "issuer": None,
        "protocol": None,
        "issues": [],
        "error": None,
    }

    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme != "https":
        result["issues"].append(
            "Site is not served over HTTPS (using plain HTTP)."
        )
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["protocol"] = ssock.version()
                result["has_ssl"] = True

                # Parse expiry date
                expiry_str = cert.get("notAfter")
                if expiry_str:
                    expiry_date = datetime.strptime(
                        expiry_str, "%b %d %H:%M:%S %Y %Z"
                    )
                    result["expires"] = expiry_date.strftime("%Y-%m-%d")
                    days_left = (expiry_date - datetime.utcnow()).days
                    result["days_until_expiry"] = days_left

                    if days_left < 0:
                        result["issues"].append("Certificate has EXPIRED.")
                    elif days_left < 30:
                        result["issues"].append(
                            f"Certificate expires soon ({days_left} days)."
                        )
                    else:
                        result["valid"] = True

                # Issuer info
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName", "Unknown")

                # Weak protocol check
                weak_protocols = ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]
                if result["protocol"] in weak_protocols:
                    result["issues"].append(
                        f"Weak/outdated protocol in use: {result['protocol']}"
                    )

    except ssl.SSLCertVerificationError as e:
        result["issues"].append(f"Certificate verification failed: {e}")
    except socket.timeout:
        result["error"] = "Connection to port 443 timed out."
    except (socket.gaierror, ConnectionRefusedError) as e:
        result["error"] = f"Could not connect on port 443: {e}"
    except Exception as e:
        result["error"] = f"Unexpected SSL error: {e}"

    return result
