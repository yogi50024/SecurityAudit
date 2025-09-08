"""
Dependency Inventory Collector

Collects installed packages across:
- OS-level (Debian via dpkg, RPM via rpm -qa)
- Python (pip freeze)
- Node.js (npm ls --prod --json)

Returned format:
{
    "name": <package>,
    "version": <version>,
    "ecosystem": <OSV ecosystem>,
    "source": "os|python|node"
}
"""

import subprocess
import json
import shutil

def _run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    except Exception:
        return ""

def collect_debian_packages():
    pkgs = []
    if shutil.which("dpkg-query"):
        out = _run_cmd(["dpkg-query", "-W", "-f", "${Package} ${Version}\\n"])
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                pkgs.append({
                    "name": parts[0],
                    "version": parts[1],
                    "ecosystem": "Debian",
                    "source": "os"
                })
    return pkgs

def collect_rpm_packages():
    pkgs = []
    if shutil.which("rpm"):
        out = _run_cmd(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"])
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                pkgs.append({
                    "name": parts[0],
                    "version": parts[1],
                    "ecosystem": "RPM",
                    "source": "os"
                })
    return pkgs

def collect_python_packages():
    pkgs = []
    if shutil.which("pip"):
        out = _run_cmd(["pip", "freeze"])
        for line in out.splitlines():
            if "==" in line:
                name, version = line.strip().split("==", 1)
                pkgs.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "source": "python"
                })
    return pkgs

def collect_node_packages():
    pkgs = []
    if shutil.which("npm"):
        raw = _run_cmd(["npm", "ls", "--prod", "--json", "--depth=9999"])
        if raw:
            try:
                data = json.loads(raw)
                dependencies = data.get("dependencies", {})
                def walk(deps):
                    for name, meta in deps.items():
                        version = meta.get("version")
                        if version:
                            pkgs.append({
                                "name": name,
                                "version": version,
                                "ecosystem": "npm",
                                "source": "node"
                            })
                        child = meta.get("dependencies")
                        if isinstance(child, dict):
                            walk(child)
                walk(dependencies)
            except Exception:
                pass
    return pkgs

def collect_all_dependencies():
    pkgs = []
    seen = set()
    for collector in (collect_debian_packages, collect_rpm_packages, collect_python_packages, collect_node_packages):
        subset = collector()
        for pkg in subset:
            key = (pkg["ecosystem"], pkg["name"].lower(), pkg["version"])
            if key not in seen:
                seen.add(key)
                pkgs.append(pkg)
    return pkgs
