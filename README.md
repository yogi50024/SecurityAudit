# Security Auditing & Vulnerability Scanning MVP

## DigitalOcean Integration

### Prerequisites
- Set your DigitalOcean API token as an environment variable:
  ```
  export DIGITALOCEAN_TOKEN=your_token_here
  ```
- (Optional) Add your SSH key to droplets for deeper scans.
- Place your SSH private key at `~/.ssh/id_rsa` or set path with `DO_SSH_KEY_PATH`.
- Set SSH user as `DO_SSH_USER` (default is `root`).
- Ensure your SSH key is authorized on all droplets you wish to scan.
## Features
 DigitalOcean Droplet & Firewall scan
- Full dependency inventory (Debian, RPM, Python, Node)
- Unified CVE scan (OSV API, cached)
- SSH remote scan, Port scan, malware scan, local firewall scan
- Severity filtering & fail threshold (set FAIL_SEVERITY env var)
- HTML and JSON report generation
- Dashboard displays HTML report

## Usage

```bash
export DIGITALOCEAN_TOKEN=your_token
export FAIL_SEVERITY=HIGH  # or CRITICAL/MEDIUM/LOW
python run_audit.py
python dashboard/app.py  # then visit http://127.0.0.1:5000/

## Directory Structure and modules
security-audit-mvp/
│
├── scanner/
│   ├── __init__.py
│   ├── scan_dependencies.py		 #Scans application directories for dependency files (requirements.txt, package.json) and checks for outdated packages.
│   ├── scan_ports.py				     #Checks for open and potentially vulnerable ports on a droplet.
│   ├── scan_firewall.py		  	 #Checks the local firewall configuration (e.g., UFW or iptables) on a droplet for common misconfigurations.
│   ├── scan_cve.py					     #Checks system packages and dependencies against public CVE databases for known vulnerabilities.
│   ├── scan_malware.py			   	 #Scans files and directories for suspicious patterns and malware signatures using regex rules.
│   ├── do_client.py             # DigitalOcean API client - Handles communication with the DigitalOcean API to fetch information about droplets, firewalls, and other resources.
│   ├── scan_do_firewalls.py     # Checks firewall rules for overly permissive configurations or missing attachments.
│   ├── scan_do_droplets.py      # Analyzes droplet configuration for common security issues (public IP exposure, missing backups, lack of tags).
│   └── ssh_scan.py              # Connects via SSH to each droplet to perform deeper scans, such as package updates, local firewalls, and suspicious processes.
│
├── reports/
│   ├── report_generator.py			 #Aggregates scanner findings and produces JSON or HTML reports with severity and remediation guidance.
│   └── email_alerts.py				   #Sends security report summaries to configured recipients using SMTP.
│
├── scheduler/
│   └── schedule_scans.py			   #Schedules regular scans using the `schedule` library.
│
├── ci_cd/
│   └── pipeline_hook.py		   	 #Runs scans automatically during code deployment or integration.
│
├── dashboard/
│   ├── app.py						       #Displays the latest scan report and findings on a web dashboard.
│   ├── auth.py
│   └── templates/
│       ├── dashboard.html
│       └── login.html
│
├── tests/
│   ├── test_scanners.py
│   └── test_signatures.py
│
├── requirements.txt                 
├── README.md                      

