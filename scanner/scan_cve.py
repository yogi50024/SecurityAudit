"""
CVE Vulnerability Scanner

Checks system packages and dependencies against public CVE databases for known vulnerabilities.
"""

import requests

def scan_cve(packages):
    """
    Checks a list of packages against a public CVE API.
    Returns: list of vulnerable packages with CVE info.
    """
    results = []
    cve_api = "https://cve.circl.lu/api/search/"
    for pkg in packages:
        try:
            resp = requests.get(cve_api + pkg)
            data = resp.json()
            if data and "results" in data and data["results"]:
                for vuln in data["results"]:
                    results.append({
                        "package": pkg,
                        "cve": vuln.get("id"),
                        "summary": vuln.get("summary"),
                        "published": vuln.get("Published"),
                    })
        except Exception:
            continue
    return results
