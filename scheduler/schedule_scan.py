"""
Scan Scheduler

Schedules regular scans using the `schedule` library.
"""

import schedule
import time
from scanner.scan_do_droplets import scan_do_droplets
from scanner.scan_do_firewalls import scan_do_firewalls
from reports.report_generator import generate_report

def run_all_scans():
    droplet_findings = scan_do_droplets()
    fw_findings = scan_do_firewalls()
    findings = {
        "droplets": droplet_findings,
        "firewalls": fw_findings,
    }
    generate_report(findings)

schedule.every().day.at("03:00").do(run_all_scans)

if __name__ == "__main__":
    print("Starting the scan scheduler...")
    while True:
        schedule.run_pending()
        time.sleep(60)
