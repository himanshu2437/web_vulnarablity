SEVERITY_WEIGHTS = {
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def calculate_score(results: dict) -> dict:
    """Calculate a bounded risk score from the findings returned by each check."""
    score = 100
    deductions = []

    for missing in results.get("headers", {}).get("missing", []):
        penalty = SEVERITY_WEIGHTS.get(missing["severity"], 5)
        score -= penalty
        deductions.append(
            f"Missing header '{missing['header']}' (-{penalty}, {missing['severity']})"
        )


    ssl_result = results.get("ssl", {})
    if not ssl_result.get("has_ssl"):
        score -= 20
        deductions.append("No HTTPS/SSL in use (-20, high)")
    for issue in ssl_result.get("issues", []):
        score -= 10
        deductions.append(f"SSL issue: {issue} (-10, high)")

    
    risky_ports = {21, 23, 3306, 3389, 5432}
    for open_port in results.get("ports", {}).get("open", []):
        if open_port["port"] in risky_ports:
            score -= 10
            deductions.append(
                f"Risky port open: {open_port['port']} ({open_port['service']}) (-10, high)"
            )
        else:
            score -= 2
            deductions.append(
                f"Port open: {open_port['port']} ({open_port['service']}) (-2, info)"
            )

   
    for exposed in results.get("paths", {}).get("exposed", []):
        penalty = SEVERITY_WEIGHTS.get(exposed["severity"], 5)
        if penalty > 0:
            score -= penalty
            deductions.append(
                f"Exposed path '{exposed['path']}' (-{penalty}, {exposed['severity']})"
            )

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade, "deductions": deductions}


def print_report(url: str, results: dict, score_summary: dict):
    """Print a concise, human-readable scan summary."""
    print("=" * 60)
    print(f" VULNERABILITY SCAN REPORT")
    print("=" * 60)
    print(f"Target       : {url}")
    print(f"Risk Score   : {score_summary['score']} / 100")
    print(f"Risk Grade   : {score_summary['grade']}")
    print("=" * 60)

    print("\n--- HTTP Security Headers ---")
    if results["headers"].get("error"):
        print(f"  Error: {results['headers']['error']}")
    else:
        for h in results["headers"]["present"]:
            print(f"  [OK]      {h['header']}")
        for h in results["headers"]["missing"]:
            print(f"  [MISSING] {h['header']} ({h['severity']}) - {h['description']}")

    print("\n--- SSL/TLS Certificate ---")
    ssl_r = results["ssl"]
    if ssl_r.get("error"):
        print(f"  Error: {ssl_r['error']}")
    elif not ssl_r.get("has_ssl"):
        print("  [WARNING] Site not served over HTTPS.")
    else:
        print(f"  Protocol     : {ssl_r['protocol']}")
        print(f"  Issuer       : {ssl_r['issuer']}")
        print(f"  Expires      : {ssl_r['expires']} ({ssl_r['days_until_expiry']} days left)")
        for issue in ssl_r["issues"]:
            print(f"  [ISSUE]      {issue}")

    print("\n--- Open Ports ---")
    if results["ports"].get("error"):
        print(f"  Error: {results['ports']['error']}")
    elif not results["ports"]["open"]:
        print("  No common ports found open.")
    else:
        for p in results["ports"]["open"]:
            print(f"  [OPEN] {p['port']} ({p['service']}) - {p['note']}")

    print("\n--- Exposed Sensitive Paths ---")
    if not results["paths"]["exposed"]:
        print("  No sensitive paths exposed from the checklist.")
    else:
        for p in results["paths"]["exposed"]:
            print(f"  [EXPOSED] {p['path']} ({p['severity']}) - {p['description']}")

    print("\n--- Score Breakdown ---")
    for d in score_summary["deductions"]:
        print(f"  {d}")
    if not score_summary["deductions"]:
        print("  No deductions — clean scan!")

    print("\n" + "=" * 60)
