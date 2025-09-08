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
import pkg_resources
import subprocess
import json

def collect_python_deps():
    return [{"name": dist.project_name, "version": dist.version, "ecosystem": "PyPI"}
            for dist in pkg_resources.working_set]

def collect_node_deps():
    try:
        output = subprocess.check_output(["npm", "ls", "--json"], text=True)
        data = json.loads(output)
        deps = []
        def walk(node):
            for k, v in (node.get("dependencies") or {}).items():
                deps.append({"name": k, "version": v.get("version", ""), "ecosystem": "npm"})
                walk(v)
        walk(data)
        return deps
    except Exception:
        return []

def collect_os_deps():
    try:
        output = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], text=True)
        return [{"name": line.split("\t")[0], "version": line.split("\t")[1], "ecosystem": "Debian"}
                for line in output.strip().split("\n") if "\t" in line]
    except Exception:
        return []

def collect_all_dependencies():
    results = []
    results += collect_python_deps()
    results += collect_node_deps()
    results += collect_os_deps()
    return results
