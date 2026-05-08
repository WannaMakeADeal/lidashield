import os
import re
import base64
import time
import hashlib
import requests
from datetime import datetime, date
from collections import defaultdict
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── API Keys ──────────────────────────────────────────────────────────────────
GSB_API_KEY     = os.environ.get("GSB_API_KEY", "")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")

# ── Rate Limiting (in-memory, resets on redeploy — fine for now) ──────────────
DAILY_FREE_LIMIT = 10
scan_counts = defaultdict(lambda: {"count": 0, "date": str(date.today())})

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def check_rate_limit(ip):
    today = str(date.today())
    if scan_counts[ip]["date"] != today:
        scan_counts[ip] = {"count": 0, "date": today}
    if scan_counts[ip]["count"] >= DAILY_FREE_LIMIT:
        return False
    scan_counts[ip]["count"] += 1
    return True

def scans_remaining(ip):
    today = str(date.today())
    if scan_counts[ip]["date"] != today:
        return DAILY_FREE_LIMIT
    return max(0, DAILY_FREE_LIMIT - scan_counts[ip]["count"])

# ── Input Validation ──────────────────────────────────────────────────────────
URL_REGEX = re.compile(
    r'^(https?://)?([\w\-]+\.)+[\w\-]{2,}(/[\w\-./?%&=]*)?$', re.IGNORECASE
)

def validate_url(raw):
    raw = raw.strip()
    if not raw:
        return None, "Please enter a URL."
    if len(raw) > 2000:
        return None, "URL is too long."
    # Strip protocol for validation
    check = raw
    if check.startswith(("http://", "https://")):
        check = check.split("://", 1)[1]
    if "." not in check:
        return None, f'"{raw}" doesn\'t look like a valid URL. Try including a domain like .com or .sg'
    url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
    return url, None

# ── Google Safe Browsing ──────────────────────────────────────────────────────
def scan_gsb(url):
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
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload, timeout=8
        )
        if r.status_code != 200:
            return None
        matches = r.json().get("matches", [])
        return {
            "source": "Google Safe Browsing",
            "flagged": len(matches) > 0,
            "threat_types": list({m.get("threatType","") for m in matches})
        }
    except Exception:
        return None

# ── URLScan.io ────────────────────────────────────────────────────────────────
def scan_urlscan(url):
    if not URLSCAN_API_KEY:
        return None
    try:
        # Submit scan
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"},
            json={"url": url, "visibility": "unlisted"},
            timeout=8
        )
        if submit.status_code not in (200, 201):
            return None
        scan_uuid = submit.json().get("uuid")
        if not scan_uuid:
            return None
        # Wait for result
        time.sleep(6)
        result = requests.get(
            f"https://urlscan.io/api/v1/result/{scan_uuid}/",
            timeout=10
        )
        if result.status_code != 200:
            return None
        data     = result.json()
        verdicts = data.get("verdicts", {}).get("overall", {})
        return {
            "source":      "URLScan.io",
            "malicious":   verdicts.get("malicious", False),
            "score":       verdicts.get("score", 0),
            "tags":        verdicts.get("tags", []),
            "brands":      data.get("verdicts", {}).get("urlscan", {}).get("brands", []),
            "screenshot":  data.get("task", {}).get("screenshotURL", ""),
        }
    except Exception:
        return None

# ── PhishTank ─────────────────────────────────────────────────────────────────
def scan_phishtank(url):
    try:
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": base64.b64encode(url.encode()).decode(),
                "format": "json",
                "app_key": ""   # works without key, just slower
            },
            headers={"User-Agent": "LidaShield/1.0"},
            timeout=8
        )
        if r.status_code != 200:
            return None
        data   = r.json().get("results", {})
        in_db  = data.get("in_database", False)
        valid  = data.get("valid", False)
        return {
            "source":   "PhishTank",
            "flagged":  in_db and valid,
            "in_db":    in_db,
        }
    except Exception:
        return None

# ── Verdict Builder ───────────────────────────────────────────────────────────
def build_verdict(url, gsb, urlscan, phishtank):
    danger_signals = []
    warning_signals = []
    engines_checked = []

    if gsb:
        engines_checked.append("Google Safe Browsing")
        if gsb["flagged"]:
            danger_signals.append(f"Google flagged as: {', '.join(gsb['threat_types'])}")

    if phishtank:
        engines_checked.append("PhishTank")
        if phishtank["flagged"]:
            danger_signals.append("Known phishing URL (PhishTank)")

    if urlscan:
        engines_checked.append("URLScan.io")
        if urlscan["malicious"]:
            danger_signals.append(f"URLScan flagged malicious (score: {urlscan['score']})")
        elif urlscan["score"] and urlscan["score"] > 50:
            warning_signals.append(f"URLScan suspicious (score: {urlscan['score']})")

    if not engines_checked:
        return {"error": "No scanning engines available right now. Try again shortly."}

    if danger_signals:
        verdict, verdict_class = "DANGEROUS", "danger"
        message = "This link is flagged as dangerous. Do NOT proceed."
    elif warning_signals:
        verdict, verdict_class = "SUSPICIOUS", "warning"
        message = "This link raised concerns with security engines. Proceed with extreme caution."
    else:
        verdict, verdict_class = "SAFE", "safe"
        message = "No threats detected by security engines."

    result = {
        "verdict":          verdict,
        "verdict_class":    verdict_class,
        "message":          message,
        "url":              url,
        "engines_checked":  engines_checked,
        "danger_signals":   danger_signals,
        "warning_signals":  warning_signals,
    }

    if urlscan and urlscan.get("screenshot"):
        result["screenshot"] = urlscan["screenshot"]

    return result

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r") as f:
        return f.read()

@app.route("/scan", methods=["POST"])
def scan():
    ip = get_client_ip()

    if not check_rate_limit(ip):
        return jsonify({
            "error": f"You've used all {DAILY_FREE_LIMIT} free scans for today. Upgrade to Shield for unlimited scans.",
            "rate_limited": True,
            "scans_remaining": 0
        }), 429

    body = request.get_json()
    if not body or not body.get("url"):
        return jsonify({"error": "No URL provided."}), 400

    url, err = validate_url(body["url"])
    if err:
        return jsonify({"error": err}), 400

    gsb      = scan_gsb(url)
    phish    = scan_phishtank(url)
    urlsc    = scan_urlscan(url) if URLSCAN_API_KEY else None

    result = build_verdict(url, gsb, urlsc, phish)
    result["scans_remaining"] = scans_remaining(ip)

    if "error" in result:
        return jsonify(result), 502

    return jsonify(result)

@app.route("/remaining", methods=["GET"])
def remaining():
    ip = get_client_ip()
    return jsonify({"scans_remaining": scans_remaining(ip), "limit": DAILY_FREE_LIMIT})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
