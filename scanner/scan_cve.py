"""
CVE Vulnerability Scanner

Checks system packages and dependencies against public CVE databases for known vulnerabilities.
"""

"""
Unified CVE Scanner via OSV API with Caching

Uses OSV batch API to query vulnerabilities for collected packages.
Caches results in .osv_cache.json (can be changed as needed).
"""

import requests
import math
import json
import os
import hashlib

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
CACHE_FILE = ".osv_cache.json"

def _cvss_severity(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

def _get_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

def _cache_key(pkg):
    return hashlib.sha256(f"{pkg['ecosystem']}|{pkg['name'].lower()}|{pkg['version']}".encode()).hexdigest()

def scan_cve(packages, batch_size=90, timeout=30):
    vulns = []
    if not packages:
        return vulns

    cache = _get_cache()
    queries = []
    batch_map = []
    for p in packages:
        if not all(k in p for k in ("name", "version", "ecosystem")):
            continue
        key = _cache_key(p)
        if key in cache:
            for v in cache[key]:
                vulns.append(v)
        else:
            queries.append({
                "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                "version": p["version"]
            })
            batch_map.append((key, p))

    if not queries:
        return vulns

    total_batches = math.ceil(len(queries) / batch_size)
    for i in range(total_batches):
        batch = queries[i*batch_size:(i+1)*batch_size]
        batch_keys = batch_map[i*batch_size:(i+1)*batch_size]
        try:
            resp = requests.post(OSV_BATCH_URL, json={"queries": batch}, timeout=timeout)
            if resp.status_code != 200:
                continue
            data = resp.json()
            results = data.get("results", [])
            for idx, result in enumerate(results):
                pkg_query = batch[idx]
                pkg_meta = batch_keys[idx][1]
                key = batch_keys[idx][0]
                these_vulns = result.get("vulns") or []
                entry_list = []
                for v in these_vulns:
                    severity_entries = v.get("severity", [])
                    cvss_score = None
                    for sev in severity_entries:
                        try:
                            cvss_score = float(sev.get("score"))
                            break
                        except Exception:
                            continue
                    entry = {
                        "package": pkg_meta["name"],
                        "version": pkg_meta["version"],
                        "ecosystem": pkg_meta["ecosystem"],
                        "vuln_id": v.get("id"),
                        "summary": v.get("summary"),
                        "aliases": v.get("aliases") or [],
                        "severity": severity_entries,
                        "cvss_score": cvss_score,
                        "cvss_severity": _cvss_severity(cvss_score)
                    }
                    entry_list.append(entry)
                vulns += entry_list
                cache[key] = entry_list
        except Exception:
            continue
    _save_cache(cache)
    return vulns
