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
- Fetch and scan all DigitalOcean Droplets and Firewalls via API
- SSH into droplets and run local scans
- Scan application repos and files
- Scheduled scans, reporting, CI/CD integration, dashboard

## Usage
- Run scheduled scans: `python scheduler/schedule_scans.py`
- Integrate with CI/CD: call `python ci_cd/pipeline_hook.py`
- View dashboard: `python dashboard/app.py`
- Run tests: `python -m unittest discover tests`
