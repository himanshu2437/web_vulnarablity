from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


USER_AGENT = "VulnScanner/1.0 (authorized security audit)"
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
    """Check common sensitive paths concurrently and record successful responses."""
    result = {"exposed": [], "not_found": [], "error": None}
    base_url = base_url.rstrip("/")

    def check_path(item):
        path, (description, severity) = item
        full_url = f"{base_url}{path}"
        try:
            response = requests.get(
                full_url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            )
            if response.status_code == 200:
                return {
                    "path": path,
                    "url": full_url,
                    "description": description,
                    "severity": severity,
                    "status_code": response.status_code,
                }, None
        except requests.exceptions.RequestException:
            pass
        return None, path

    with ThreadPoolExecutor(max_workers=min(8, len(SENSITIVE_PATHS))) as executor:
        futures = [
            executor.submit(check_path, item) for item in SENSITIVE_PATHS.items()
        ]
        for future in as_completed(futures):
            exposed, not_found = future.result()
            if exposed:
                result["exposed"].append(exposed)
            else:
                result["not_found"].append(not_found)

    result["exposed"].sort(key=lambda item: item["path"])
    result["not_found"].sort()

    return result
