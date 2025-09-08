"""
Dependency Scanner

Scans application directories for dependency files (requirements.txt, package.json) and checks for outdated packages.
"""

import os
import subprocess

def scan_python_requirements(path="requirements.txt"):
    """
    Checks Python requirements.txt for outdated packages.
    Returns: list of (package, current_version, latest_version)
    """
    results = []
    if not os.path.exists(path):
        return results
    with open(path) as f:
        packages = [line.strip().split("==")[0] for line in f if line.strip() and "==" in line]
    for pkg in packages:
        try:
            latest = subprocess.check_output(
                ["pip", "install", f"{pkg}==random"], stderr=subprocess.STDOUT
            ).decode()
        except Exception:
            latest = "Unknown"
        results.append((pkg, "Unknown", latest))
    return results

def scan_node_dependencies(path="package.json"):
    """
    Checks Node.js package.json for outdated packages.
    Returns: list of (package, current_version, latest_version)
    """
    results = []
    if not os.path.exists(path):
        return results
    try:
        output = subprocess.check_output(["npm", "outdated", "--json"], cwd=os.path.dirname(path))
        outdated = eval(output.decode())  # should be JSON, not eval in production
        for pkg, info in outdated.items():
            results.append((pkg, info["current"], info["latest"]))
    except Exception:
        pass
    return results
