"""
Local Firewall Scanner

Checks the local firewall configuration (e.g., UFW or iptables) on a droplet for common misconfigurations.
"""

import subprocess

def scan_firewall():
    """
    Scans for local firewall status and open rules.
    Returns: dict with status and rules.
    """
    findings = {}
    try:
        # Check if UFW is installed and enabled
        ufw_status = subprocess.check_output(["sudo", "ufw", "status"], stderr=subprocess.STDOUT).decode()
        findings["ufw_status"] = ufw_status
        if "inactive" in ufw_status:
            findings["issue"] = "UFW firewall is inactive"
    except Exception:
        # If UFW not present, try iptables
        try:
            iptables = subprocess.check_output(["sudo", "iptables", "-L"], stderr=subprocess.STDOUT).decode()
            findings["iptables_rules"] = iptables
            if "ACCEPT" in iptables and "DROP" not in iptables:
                findings["issue"] = "iptables may be overly permissive (ACCEPT everywhere)"
        except Exception as e:
            findings["error"] = f"Could not check firewall: {e}"
    return findings
