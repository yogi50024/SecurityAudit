"""
Flask Dashboard App

Displays the latest scan report and findings on a web dashboard.
"""

from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

@app.route("/")
def home():
    report_file = "report.json"
    findings = {}
    if os.path.exists(report_file):
        with open(report_file) as f:
            findings = json.load(f)
    return render_template("dashboard.html", findings=findings)

@app.route("/api/findings")
def api_findings():
    report_file = "report.json"
    findings = {}
    if os.path.exists(report_file):
        with open(report_file) as f:
            findings = json.load(f)
    return jsonify(findings)

if __name__ == "__main__":
    app.run(debug=True)
