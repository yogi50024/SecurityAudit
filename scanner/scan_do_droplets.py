"""
Droplet Security Scanner

Analyzes droplet configuration for common security issues (public IP exposure, missing backups, lack of tags).
"""

from .do_client import get_droplet_info

def scan_do_droplets():
    droplets = get_droplet_info()
    findings = []
    for droplet in droplets:
        if not droplet.tags:
            findings.append({
                "droplet_id": droplet.id,
                "issue": "No tags set",
            })
        if not droplet.backups:
            findings.append({
                "droplet_id": droplet.id,
                "issue": "No backups enabled",
            })
        if droplet.ip_address:
            findings.append({
                "droplet_id": droplet.id,
                "issue": f"Public IP exposed: {droplet.ip_address}",
            })
    return findings
