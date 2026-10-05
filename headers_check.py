import requests


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
    """Check the target response for recommended browser security headers."""
    result = {"present": [], "missing": [], "error": None, "raw_headers": {}}

    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=True,
            headers={"User-Agent": "VulnScanner/1.0 (authorized security audit)"},
        )
        result["raw_headers"] = dict(response.headers)

        for header, (description, severity) in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            if value is not None:
                result["present"].append(
                    {"header": header, "value": value}
                )
            else:
                result["missing"].append(
                    {
                        "header": header,
                        "description": description,
                        "severity": severity,
                    }
                )

    except requests.exceptions.SSLError as error:
        result["error"] = f"SSL error while connecting: {error}"
    except requests.exceptions.ConnectionError as error:
        result["error"] = f"Connection error: {error}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out."
    except requests.exceptions.RequestException as error:
        result["error"] = f"Request failed: {error}"

    return result
