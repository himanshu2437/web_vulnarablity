"""
headers_check.py
=================
Checks a target web app's HTTP response for the presence of common
security-related headers. Missing headers are common misconfigurations
that can expose apps to clickjacking, XSS, MIME-sniffing attacks, etc.
"""

import requests

# Each header maps to: (why it matters, severity if missing)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Helps prevent XSS by restricting sources of scripts/styles.",
        "high",
    ),
    "Strict-Transport-Security": (
        "Forces browsers to use HTTPS, preventing downgrade attacks.",
        "high",
    ),
    "X-Frame-Options": (
        "Prevents clickjacking by blocking the page from being framed.",
        "medium",
    ),
    "X-Content-Type-Options": (
        "Prevents MIME-sniffing attacks (should be 'nosniff').",
        "medium",
    ),
    "Referrer-Policy": (
        "Controls how much referrer info is leaked on navigation.",
        "low",
    ),
    "Permissions-Policy": (
        "Restricts which browser features/APIs the page can use.",
        "low",
    ),
}


def check_headers(url: str, timeout: int = 8) -> dict:
    """
    Sends a GET request to the target and checks which security
    headers are present or missing.

    Returns a dict with 'present', 'missing', and 'error' (if any).
    """
    result = {"present": [], "missing": [], "error": None, "raw_headers": {}}

    try:
        response = requests.get(url, timeout=timeout, verify=True)
        result["raw_headers"] = dict(response.headers)

        for header, (description, severity) in SECURITY_HEADERS.items():
            if header in response.headers:
                result["present"].append(
                    {"header": header, "value": response.headers[header]}
                )
            else:
                result["missing"].append(
                    {
                        "header": header,
                        "description": description,
                        "severity": severity,
                    }
                )

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error while connecting: {e}"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out."
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {e}"

    return result
