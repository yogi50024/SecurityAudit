"""
CI/CD Pipeline Security Hook

Runs scans automatically during code deployment or integration.
"""

from scanner.scan_dependencies import scan_python_requirements, scan_node_dependencies
from scanner.scan_cve import scan_cve
from reports.report_generator import generate_report

def pipeline_scan():
    py_findings = scan_python_requirements()
    node_findings = scan_node_dependencies()
    cve_findings = scan_cve([pkg for pkg,_,_ in py_findings+node_findings])
    findings = {
        "dependencies": py_findings + node_findings,
        "cves": cve_findings,
    }
    generate_report(findings, output="pipeline_report.json")

if __name__ == "__main__":
    pipeline_scan()
