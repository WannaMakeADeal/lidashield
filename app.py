import os
import hashlib
import time
import requests
from flask import Flask, request, jsonify, render_template_string, send_from_directory

app = Flask(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY,
    "Accept": "application/json"
}


def submit_url(url):
    """Submit URL to VirusTotal for scanning."""
    resp = requests.post(
        f"{VT_BASE}/urls",
        headers=HEADERS,
        data={"url": url},
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()


def get_url_report(url):
    """Get existing report for a URL using its ID."""
    url_id = hashlib.sha256(url.encode()).hexdigest()
    resp = requests.get(
        f"{VT_BASE}/urls/{url_id}",
        headers=HEADERS,
        timeout=10
    )
    return resp


def scan_url(url):
    """Full scan flow: submit then retrieve report."""
    # First try to get existing report
    report_resp = get_url_report(url)

    if report_resp.status_code == 404:
        # Not in VT database — submit it
        submit_resp = submit_url(url)
        analysis_id = submit_resp.get("data", {}).get("id", "")

        # Wait a moment then try to get results
        time.sleep(3)
        report_resp = get_url_report(url)

    if report_resp.status_code != 200:
        return None

    return report_resp.json()


def parse_results(data):
    """Parse VT response into clean result dict."""
    if not data:
        return {"error": "No data returned from VirusTotal."}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    # Determine verdict
    if malicious >= 3:
        verdict = "DANGEROUS"
        verdict_class = "danger"
        message = "This link is flagged as malicious by multiple security engines. Do NOT proceed."
    elif malicious >= 1 or suspicious >= 3:
        verdict = "SUSPICIOUS"
        verdict_class = "warning"
        message = "This link raised flags with some security engines. Proceed with extreme caution."
    elif suspicious >= 1:
        verdict = "CAUTION"
        verdict_class = "caution"
        message = "Minor concerns detected. Be careful before proceeding."
    else:
        verdict = "SAFE"
        verdict_class = "safe"
        message = "No threats detected by security engines."

    # Get flagging engines
    engines = attrs.get("last_analysis_results", {})
    flagged_by = [
        name for name, result in engines.items()
        if result.get("category") in ("malicious", "suspicious")
    ]

    return {
        "verdict": verdict,
        "verdict_class": verdict_class,
        "message": message,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "flagged_by": flagged_by[:10],  # cap at 10
        "url": attrs.get("url", ""),
        "scan_date": attrs.get("last_analysis_date", ""),
    }


@app.route("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r") as f:
        return f.read()


@app.route("/scan", methods=["POST"])
def scan():
    body = request.get_json()
    if not body or not body.get("url"):
        return jsonify({"error": "No URL provided."}), 400

    url = body["url"].strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not VT_API_KEY:
        return jsonify({"error": "VirusTotal API key not configured."}), 500

    try:
        data = scan_url(url)
        result = parse_results(data)
        return jsonify(result)
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Try again."}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error: {str(e)}"}), 502
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
