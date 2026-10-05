from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from urllib.parse import urlparse


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
    """Attempt TCP connections to the common ports for the target host."""
    parsed = urlparse(url)
    hostname = parsed.hostname

    result = {"host": hostname, "open": [], "closed": [], "error": None}

    if not hostname:
        result["error"] = "Could not parse hostname from URL."
        return result

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror as error:
        result["error"] = f"DNS resolution failed: {error}"
        return result

    def check_port(port):
        service, note = COMMON_PORTS[port]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            return port, sock.connect_ex((resolved_ip, port)) == 0
        except OSError:
            return port, False
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        futures = [executor.submit(check_port, port) for port in COMMON_PORTS]
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service, note = COMMON_PORTS[port]
                result["open"].append(
                    {"port": port, "service": service, "note": note}
                )
            else:
                result["closed"].append(port)

    result["open"].sort(key=lambda item: item["port"])
    result["closed"].sort()
    return result
