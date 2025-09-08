import json
import os

def generate_report(findings, output="report.json", html_output="report.html"):
    # JSON
    with open(output, "w") as f:
        json.dump(findings, f, indent=2)
    # HTML
    html = generate_html_report(findings)
    with open(html_output, "w") as f:
        f.write(html)
    return output, html_output

def generate_html_report(findings):
    def section(title, items):
        if not items:
            return f"<h2>{title}</h2><p>None found.</p>"
        html = f"<h2>{title}</h2><table border='1'><tr>{''.join(f'<th>{k}</th>' for k in items[0].keys())}</tr>"
        for item in items:
            html += "<tr>" + "".join(f"<td>{str(item.get(k,'')).replace('<','&lt;').replace('>','&gt;')}</td>" for k in items[0].keys()) + "</tr>"
        html += "</table>"
        return html

    html = "<html><head><title>Security Audit Report</title></head><body>"
    html += f"<h1>Security Audit Report</h1><pre>{findings.get('summary','')}</pre>"
    html += f"<h3>Metadata</h3><pre>{findings.get('metadata','')}</pre>"

    html += section("DigitalOcean Droplets", findings.get("droplets", []))
    html += section("DigitalOcean Firewalls", findings.get("firewalls", []))
    html += section("Dependencies", findings.get("dependencies", []))
    html += section("CVEs", findings.get("cves", []))
    html += section("Malware Findings", findings.get("malware", []))
    html += section("Port Scans", findings.get("port_scans", []))
    html += section("SSH Scans", findings.get("ssh_scans", []))
    html += section("Local Firewall", [findings.get("local_firewall")] if findings.get("local_firewall") else [])
    html += "</body></html>"
    return html
