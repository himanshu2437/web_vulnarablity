import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def check_ssl(url: str, timeout: int = 8) -> dict:
    """Connect to HTTPS and inspect the negotiated protocol and certificate."""
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
        result["issues"].append("Site is not served over HTTPS (using plain HTTP).")
        return result

    if not hostname:
        result["error"] = "Could not parse hostname from URL."
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["protocol"] = ssock.version()
                result["has_ssl"] = True

                
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

               
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName", "Unknown")

                
                weak_protocols = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
                if result["protocol"] in weak_protocols:
                    result["issues"].append(
                        f"Weak/outdated protocol in use: {result['protocol']}"
                    )

    except ssl.SSLCertVerificationError as error:
        result["issues"].append(f"Certificate verification failed: {error}")
    except socket.timeout:
        result["error"] = "Connection to port 443 timed out."
    except (socket.gaierror, ConnectionRefusedError) as error:
        result["error"] = f"Could not connect on port 443: {error}"
    except OSError as error:
        result["error"] = f"Could not inspect SSL/TLS: {error}"

    return result
