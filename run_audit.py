import os
import json
import time
import logging
from datetime import datetime

from scanner.scan_do_droplets import scan_do_droplets
from scanner.scan_do_firewalls import scan_do_firewalls
from scanner.dependency_inventory import collect_all_dependencies
from scanner.scan_cve import scan_cve
from scanner.scan_ports import scan_ports
from scanner.ssh_scan import ssh_scan
from scanner.scan_firewall import scan_firewall
from scanner.scan_malware import scan_malware
from reports.report_generator import generate_report

def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def classify_severity(entry):
    # CVEs
    sev = entry.get("cvss_severity")
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev
    # Generic findings
    text = json.dumps(entry).lower()
    if any(k in text for k in ["cve-", "overly permissive", "public ip exposed", "malware", "inactive"]):
        return "HIGH"
    if any(k in text for k in ["no backups", "no tags"]):
        return "MEDIUM"
    return "LOW"

def summarize(report):
    counters = {"total_findings": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}}
    for section in ("droplets", "firewalls", "dependencies", "cves", "malware", "port_scans", "ssh_scans"):
        for f in report.get(section, []):
            sev = classify_severity(f)
            f["severity"] = sev
            counters["by_severity"][sev] += 1
            counters["total_findings"] += 1
    # Local firewall
    lf = report.get("local_firewall")
    if lf:
        sev = classify_severity(lf)
        lf["severity"] = sev
        counters["by_severity"][sev] += 1
        counters["total_findings"] += 1
    report["summary"] = counters
    return report

def main():
    configure_logging()
    start = time.time()
    report_file = os.getenv("REPORT_FILE", "report.json")
    html_report_file = os.getenv("HTML_REPORT_FILE", "report.html")
    errors = []
    fail_severity = os.getenv("FAIL_SEVERITY", "HIGH")  # Can be LOW, MEDIUM, HIGH, CRITICAL

    # 1. DigitalOcean droplet scan
    try:
        droplet_findings = scan_do_droplets()
    except Exception as e:
        logging.error(f"Droplet scan failed: {e}")
        droplet_findings = []
        errors.append(f"droplet_scan: {e}")

    # 2. DigitalOcean firewall scan
    try:
        firewall_findings = scan_do_firewalls()
    except Exception as e:
        logging.error(f"Firewall scan failed: {e}")
        firewall_findings = []
        errors.append(f"firewall_scan: {e}")

    # 3. Dependency inventory (OS + Python + Node + RPM)
    try:
        deps = collect_all_dependencies()
        logging.info(f"Collected {len(deps)} packages across all ecosystems.")
    except Exception as e:
        logging.error(f"Dependency inventory failed: {e}")
        deps = []
        errors.append(f"dependency_inventory: {e}")

    # 4. CVE scan across all packages
    try:
        cve_findings = scan_cve(deps)
        logging.info(f"CVE scan returned {len(cve_findings)} vulnerability records.")
    except Exception as e:
        logging.error(f"CVE scan failed: {e}")
        cve_findings = []
        errors.append(f"cve_scan: {e}")

    # 5. Malware scan
    try:
        malware_results = scan_malware(".")
        logging.info(f"Malware scan found {len(malware_results)} issues.")
    except Exception as e:
        logging.error(f"Malware scan failed: {e}")
        malware_results = []
        errors.append(f"malware_scan: {e}")

    # 6. Port scan (for all droplet public IPs)
    port_results = []
    try:
        droplet_ips = [d.get("ip_address") for d in droplet_findings if d.get("ip_address")]
        for ip in droplet_ips:
            open_ports = scan_ports(ip)
            port_results.append({"ip": ip, "open_ports": open_ports})
    except Exception as e:
        logging.error(f"Port scan failed: {e}")
        errors.append(f"port_scan: {e}")

    # 7. SSH scan for each droplet
    ssh_results = []
    try:
        ssh_user = os.getenv("DO_SSH_USER", "root")
        ssh_key = os.getenv("DO_SSH_KEY_PATH") or os.path.expanduser("~/.ssh/id_rsa")
        for ip in droplet_ips:
            result = ssh_scan(ip, user=ssh_user, key_path=ssh_key)
            ssh_results.append({"ip": ip, "result": result})
    except Exception as e:
        logging.error(f"SSH scan failed: {e}")
        errors.append(f"ssh_scan: {e}")

    # 8. Local firewall scan
    try:
        local_firewall_result = scan_firewall()
    except Exception as e:
        logging.error(f"Local firewall scan failed: {e}")
        local_firewall_result = {"error": str(e)}
        errors.append(f"local_firewall_scan: {e}")

    # Assemble report
    report = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "tool": "security-audit-mvp",
            "duration_seconds": round(time.time() - start, 2),
        },
        "droplets": droplet_findings,
        "firewalls": firewall_findings,
        "dependencies": deps,
        "cves": cve_findings,
        "malware": malware_results,
        "port_scans": port_results,
        "ssh_scans": ssh_results,
        "local_firewall": local_firewall_result,
        "errors": errors
    }

    summarize(report)
    logging.info(f"Writing report to {report_file} and {html_report_file}")
    generate_report(report, output=report_file, html_output=html_report_file)
    logging.info("Summary: " + json.dumps(report["summary"], indent=2))

    # Severity fail threshold
    sev_count = report["summary"]["by_severity"].get(fail_severity.upper(), 0)
    if sev_count > 0:
        logging.error(f"{sev_count} findings at or above severity {fail_severity.upper()}. Failing with code 10.")
        exit(10)
    logging.info("Done.")

if __name__ == "__main__":
    main()
