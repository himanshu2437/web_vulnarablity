"""
path_check.py
=============
Checks for commonly-exposed sensitive files and paths on a target
web app — things that should never be publicly accessible but often
are due to misconfiguration (e.g. leftover .git folders, .env files
with secrets, default admin panels).
"""

import requests

# Path : (why it's a risk, severity)
SENSITIVE_PATHS = {
    "/.git/config": ("Exposes source repo config; can leak full source history.", "high"),
    "/.env": ("Often contains API keys, DB passwords, secrets.", "high"),
    "/wp-config.php.bak": ("Backup files can leak DB credentials.", "high"),
    "/admin": ("Default admin panel; should be restricted/renamed.", "medium"),
    "/phpinfo.php": ("Leaks detailed server configuration info.", "medium"),
    "/robots.txt": ("Can reveal hidden paths the site wants unindexed.", "low"),
    "/.well-known/security.txt": ("Not a risk — good practice if present.", "info"),
    "/backup.zip": ("Common name for exposed full-site backups.", "high"),
    "/.htaccess": ("Can leak server rewrite rules/config if readable.", "medium"),
}


def check_sensitive_paths(base_url: str, timeout: int = 6) -> dict:
    """
    Requests each path relative to base_url and records which ones
    return a 200 OK (i.e. are exposed).

    Returns a dict with 'exposed' and 'not_found'.
    """
    result = {"exposed": [], "not_found": [], "error": None}

    base_url = base_url.rstrip("/")

    for path, (description, severity) in SENSITIVE_PATHS.items():
        full_url = base_url + path
        try:
            response = requests.get(full_url, timeout=timeout, allow_redirects=False)
            if response.status_code == 200:
                result["exposed"].append(
                    {
                        "path": path,
                        "url": full_url,
                        "description": description,
                        "severity": severity,
                        "status_code": response.status_code,
                    }
                )
            else:
                result["not_found"].append(path)
        except requests.exceptions.RequestException:
            result["not_found"].append(path)

    return result
