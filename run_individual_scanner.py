import json
import os

# Scanner modules
from scanner.scan_do_droplets import scan_do_droplets
from scanner.scan_do_firewalls import scan_do_firewalls
from scanner.dependency_inventory import collect_all_dependencies
from scanner.scan_cve import scan_cve
from scanner.scan_ports import scan_ports
from scanner.ssh_scan import ssh_scan
from scanner.scan_firewall import scan_firewall
from scanner.scan_malware import scan_malware

def save_report(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Report saved to {filename}")

def run_scanner(scanner_func, *args, **kwargs):
    try:
        result = scanner_func(*args, **kwargs)
        return result
    except Exception as e:
        print(f"[ERROR] {scanner_func.__name__} failed: {e}")
        return {"error": str(e)}

def main():
    os.makedirs("reports", exist_ok=True)

    # Droplets
    droplets_report = run_scanner(scan_do_droplets)
    save_report(droplets_report, "reports/droplets_report.json")

    # Firewalls
    firewalls_report = run_scanner(scan_do_firewalls)
    save_report(firewalls_report, "reports/firewalls_report.json")

    # Dependencies
    deps_report = run_scanner(collect_all_dependencies)
    save_report(deps_report, "reports/dependencies_report.json")

    # CVEs (requires dependency inventory)
    cves_report = run_scanner(scan_cve, deps_report)
    save_report(cves_report, "reports/cves_report.json")

    # Malware
    malware_report = run_scanner(scan_malware)
    save_report(malware_report, "reports/malware_report.json")

    # Port scan (local)
    ports_report = run_scanner(scan_ports, "127.0.0.1")
    save_report(ports_report, "reports/ports_report.json")

    # SSH scan (local)
    ssh_report = run_scanner(ssh_scan, "127.0.0.1")
    save_report(ssh_report, "reports/ssh_report.json")

    # Local firewall
    firewall_report = run_scanner(scan_firewall)
    save_report(firewall_report, "reports/local_firewall_report.json")

    print("All individual scanner reports generated in the 'reports/' directory.")

if __name__ == "__main__":
    main()
