from flask import Flask, render_template, request, jsonify
from models.detector import DataLeakDetector
import os, json
from datetime import datetime

app = Flask(__name__)
detector = DataLeakDetector()

alert_log = []

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan/text", methods=["POST"])
def scan_text():
    data = request.json
    text = data.get("text", "")
    result = detector.scan_text(text)
    if result["findings"]:
        alert_log.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": "Text Input",
            "risk": result["risk_level"],
            "findings": result["findings"]
        })
    return jsonify(result)

@app.route("/scan/file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    content = file.read().decode("utf-8", errors="ignore")
    result = detector.scan_text(content)
    result["filename"] = file.filename
    if result["findings"]:
        alert_log.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": f"File: {file.filename}",
            "risk": result["risk_level"],
            "findings": result["findings"]
        })
    return jsonify(result)

@app.route("/alerts")
def get_alerts():
    return jsonify(alert_log[-20:])

@app.route("/stats")
def get_stats():
    total = len(alert_log)
    high = sum(1 for a in alert_log if a["risk"] == "HIGH")
    medium = sum(1 for a in alert_log if a["risk"] == "MEDIUM")
    low = sum(1 for a in alert_log if a["risk"] == "LOW")
    return jsonify({"total": total, "high": high, "medium": medium, "low": low})

if __name__ == "__main__":
    app.run(debug=True)
