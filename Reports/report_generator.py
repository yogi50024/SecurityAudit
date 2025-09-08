"""
Report Generator

Aggregates scanner findings and produces JSON or HTML reports with severity and remediation guidance.
"""

import json

def generate_report(findings, output="report.json"):
    """
    Saves findings as a JSON report.
    """
    with open(output, "w") as f:
        json.dump(findings, f, indent=2)
    return output
