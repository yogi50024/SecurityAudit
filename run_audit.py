# Main audit runner
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
from reports.email_reports import send_email_report

def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def classify_severity(entry):
    sev = entry.get("cvss_severity")
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev
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
    fail_severity = os.getenv("FAIL_SEVERITY", "HIGH")

    try:
        droplet_findings = scan_do_droplets()
    except Exception as e:
        logging.error(f"Droplet scan failed: {e}")
        droplet_findings = []
        errors.append(f"droplet_scan: {e}")

    try:
        firewall_findings = scan_do_firewalls()
    except Exception as e:
        logging.error(f"Firewall scan failed: {e}")
        firewall_findings = []
        errors.append(f"firewall_scan: {e}")

    try:
        deps = collect_all_dependencies()
        logging.info(f"Collected {len(deps)} packages across all ecosystems.")
    except Exception as e:
        logging.error(f"Dependency inventory failed: {e}")
        deps = []

    try:
        cve_findings = scan_cve(deps)
    except Exception as e:
        logging.error(f"CVE scan failed: {e}")
        cve_findings = []
        errors.append(f"cve_scan: {e}")

    try:
        malware_findings = scan_malware()
    except Exception as e:
        logging.error(f"Malware scan failed: {e}")
        malware_findings = []
        errors.append(f"malware_scan: {e}")

    try:
        port_findings = scan_ports("127.0.0.1")
    except Exception as e:
        logging.error(f"Port scan failed: {e}")
        port_findings = []
        errors.append(f"port_scan: {e}")

    try:
        ssh_findings = ssh_scan("127.0.0.1")
    except Exception as e:
        logging.error(f"SSH scan failed: {e}")
        ssh_findings = []
        errors.append(f"ssh_scan: {e}")

    try:
        local_firewall = scan_firewall()
    except Exception as e:
        logging.error(f"Local firewall scan failed: {e}")
        local_firewall = {}
        errors.append(f"local_firewall: {e}")

    report = {
        "droplets": droplet_findings,
        "firewalls": firewall_findings,
        "dependencies": deps,
        "cves": cve_findings,
        "malware": malware_findings,
        "port_scans": port_findings,
        "ssh_scans": ssh_findings,
        "local_firewall": local_firewall,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "duration_seconds": round(time.time() - start, 2),
            "errors": errors,
        }
    }

    report = summarize(report)
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    generate_report(report, html_report_file)
    send_email_report(html_report_file)
    logging.info(f"Report generated: {report_file}, HTML: {html_report_file}")

    fail_threshold = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(fail_severity)
    for sev, count in report["summary"]["by_severity"].items():
        if ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(sev) <= fail_threshold and count > 0:
            logging.error(f"Findings of severity {sev} found! Failing the audit.")
            exit(10)
    logging.info("Audit complete. No findings above fail threshold.")

if __name__ == "__main__":
    main()
