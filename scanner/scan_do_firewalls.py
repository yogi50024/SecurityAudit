"""
DigitalOcean Firewall Scanner

Checks firewall rules for overly permissive configurations or missing attachments.
"""

from .do_client import get_firewall_rules

def scan_do_firewalls():
    firewalls = get_firewall_rules()
    findings = []
    for fw in firewalls:
        if not fw.droplet_ids:
            findings.append({
                "firewall_id": fw.id,
                "issue": "Firewall not attached to any droplet",
            })
        for rule in fw.inbound_rules:
            if rule['sources'].get('addresses') == ['0.0.0.0/0']:
                findings.append({
                    "firewall_id": fw.id,
                    "issue": f"Overly permissive inbound rule: {rule}",
                })
    return findings
