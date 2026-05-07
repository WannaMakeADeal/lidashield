import os
import base64
import time
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY", "")
GSB_API_KEY = os.environ.get("GSB_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"

def vt_url_id(url):
    """VirusTotal v3 uses base64url (no padding) as the URL identifier."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

def vt_get_report(url):
    url_id = vt_url_id(url)
    return requests.get(
        f"{VT_BASE}/urls/{url_id}",
        headers={"x-apikey": VT_API_KEY},
        timeout=10
    )

def vt_submit(url):
    resp = requests.post(
        f"{VT_BASE}/urls",
        headers={"x-apikey": VT_API_KEY},
        data={"url": url},
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()

def scan_with_virustotal(url):
    report = vt_get_report(url)
    if report.status_code == 404:
        vt_submit(url)
        time.sleep(4)
        report = vt_get_report(url)
    if report.status_code != 200:
        return None
    data  = report.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected
    engines    = attrs.get("last_analysis_results", {})
    flagged    = [n for n, r in engines.items()
                  if r.get("category") in ("malicious", "suspicious")]
    return {
        "source": "virustotal",
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless,   "undetected": undetected,
        "total": total,         "flagged_by": flagged[:10],
        "url": attrs.get("url", url),
    }

def scan_with_gsb(url):
    if not GSB_API_KEY:
        return None
    payload = {
        "client": {"clientId": "lidashield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    resp = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
        json=payload, timeout=10
    )
    if resp.status_code != 200:
        return None
    data    = resp.json()
    matches = data.get("matches", [])
    return {
        "source": "google_safe_browsing",
        "flagged": len(matches) > 0,
        "threat_types": list({m.get("threatType","") for m in matches})
    }

def build_verdict(vt, gsb, url):
    malicious   = vt["malicious"]  if vt else 0
    suspicious  = vt["suspicious"] if vt else 0
    gsb_flagged = gsb["flagged"]   if gsb else False
    if malicious >= 3 or gsb_flagged:
        verdict, verdict_class = "DANGEROUS", "danger"
        message = "This link is flagged as malicious. Do NOT proceed."
    elif malicious >= 1 or suspicious >= 3:
        verdict, verdict_class = "SUSPICIOUS", "warning"
        message = "This link raised flags with security engines. Proceed with extreme caution."
    elif suspicious >= 1:
        verdict, verdict_class = "CAUTION", "caution"
        message = "Minor concerns detected. Be careful before proceeding."
    else:
        verdict, verdict_class = "SAFE", "safe"
        message = "No threats detected by security engines."
    result = {
        "verdict": verdict, "verdict_class": verdict_class, "message": message,
        "url": vt["url"] if vt else url,
        "malicious": malicious, "suspicious": suspicious,
        "harmless":  vt["harmless"]   if vt else 0,
        "undetected": vt["undetected"] if vt else 0,
        "total":     vt["total"]      if vt else 0,
        "flagged_by": vt["flagged_by"] if vt else [],
    }
    if gsb:
        result["gsb_flagged"]      = gsb["flagged"]
        result["gsb_threat_types"] = gsb["threat_types"]
    return result

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
    if not VT_API_KEY and not GSB_API_KEY:
        return jsonify({"error": "No API keys configured."}), 500
    try:
        vt_result  = scan_with_virustotal(url) if VT_API_KEY  else None
        gsb_result = scan_with_gsb(url)        if GSB_API_KEY else None
        if vt_result is None and gsb_result is None:
            return jsonify({"error": "No data returned from security engines."}), 502
        return jsonify(build_verdict(vt_result, gsb_result, url))
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
