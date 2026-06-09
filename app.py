from flask import Flask, request, jsonify, render_template_string
import requests
import base64
import time
import os

# ── CONFIG ─────────────────────────────────────
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_URL = "https://www.virustotal.com/api/v3"
# ───────────────────────────────────────────────

app = Flask(__name__)

# Load HTML template with fallback
try:
    HTML = open(os.path.join(os.path.dirname(__file__), "index.html")).read()
except FileNotFoundError:
    HTML = "<h1>Error: index.html not found</h1>"

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def get_report(url):
    headers = {"x-apikey": API_KEY}
    r = requests.get(f"{VT_URL}/urls/{encode_url(url)}", headers=headers)
    if r.status_code == 200:
        return r.json()
    return None

def submit_and_wait(url):
    headers = {"x-apikey": API_KEY}
    requests.post(f"{VT_URL}/urls", headers=headers, data={"url": url})
    for _ in range(10):
        time.sleep(3)
        report = get_report(url)
        if report:
            status = report.get("data", {}).get("attributes", {}).get("status")
            if status == "completed" or status is None:
                return report
    return get_report(url)

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan():
    # Validate API key is set
    if not API_KEY:
        return jsonify({"error": "API key not configured. Set VIRUSTOTAL_API_KEY environment variable."}), 500
    
    data = request.get_json()
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Try cached report first, then submit fresh
    report = get_report(url)
    if not report:
        report = submit_and_wait(url)
    
    if not report:
        return jsonify({"error": "Could not retrieve report. Check your API key and internet connection."}), 500
    
    attrs = report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    
    if malicious == 0 and suspicious == 0:
        verdict = "safe"
    elif malicious <= 2 or suspicious <= 3:
        verdict = "suspicious"
    else:
        verdict = "dangerous"
    
    engines = attrs.get("last_analysis_results", {})
    flagged = [
        name for name, res in engines.items()
        if res.get("category") in ("malicious", "suspicious")
    ]
    
    return jsonify({
        "url": url,
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total": total,
        "flagged": flagged[:8],
        "flagged_total": len(flagged),
    })

if __name__ == "__main__":
    print("\n  Lidacorp Scam Checker — running at http://localhost:5000\n")
    app.run(debug=True, port=5000)
