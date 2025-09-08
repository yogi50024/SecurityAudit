from flask import Flask, render_template, send_from_directory
import os

app = Flask(__name__)

@app.route("/")
def dashboard():
    # Parse summary and metadata from report.json for top section
    try:
        import json
        with open("report.json") as f:
            findings = json.load(f)
            summary = findings.get("summary", {})
            metadata = findings.get("metadata", {})
    except Exception:
        summary = {}
        metadata = {}
    return render_template("report.html", summary=summary, metadata=metadata)

@app.route("/static/report.html")
def serve_html_report():
    return send_from_directory(os.getcwd(), "report.html")

if __name__ == "__main__":
    app.run(debug=True)
