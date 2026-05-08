import os
import base64
import requests
from datetime import date
from collections import defaultdict
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── API Keys ──────────────────────────────────────────────────────────────────
GSB_API_KEY = os.environ.get("GSB_API_KEY", "")

# ── Rate Limiting ─────────────────────────────────────────────────────────────
DAILY_FREE_LIMIT = 10
scan_counts = defaultdict(lambda: {"count": 0, "date": str(date.today())})


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


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


# ── URL Validation ────────────────────────────────────────────────────────────
def validate_url(raw):
    if not raw:
        return None, "Please enter a URL."

    raw = raw.strip()

    if len(raw) > 2000:
        return None, "URL is too long."

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if not parsed.netloc or "." not in parsed.netloc:
        return None, "That does not look like a valid website URL."

    return raw, None


# ── Google Safe Browsing ──────────────────────────────────────────────────────
def scan_google_safe_browsing(url):
    if not GSB_API_KEY:
        return None

    payload = {
        "client": {
            "clientId": "lidashield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload,
            timeout=4
        )

        if response.status_code != 200:
            print("[Google Safe Browsing] Status:", response.status_code)
            print("[Google Safe Browsing] Body:", response.text[:300])
            return None

        data = response.json()
        matches = data.get("matches", [])

        return {
            "source": "Google Safe Browsing",
            "available": True,
            "flagged": len(matches) > 0,
            "threat_types": list({
                match.get("threatType", "UNKNOWN")
                for match in matches
            })
        }

    except Exception as error:
        print("[Google Safe Browsing] Error:", str(error))
        return None


# ── PhishTank ─────────────────────────────────────────────────────────────────
def scan_phishtank(url):
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": base64.b64encode(url.encode()).decode(),
                "format": "json",
                "app_key": ""
            },
            headers={
                "User-Agent": "LidaShield/1.0"
            },
            timeout=4
        )

        if response.status_code != 200:
            print("[PhishTank] Status:", response.status_code)
            print("[PhishTank] Body:", response.text[:300])
            return None

        data = response.json()
        results = data.get("results", {})

        in_database = bool(results.get("in_database", False))
        valid = bool(results.get("valid", False))

        return {
            "source": "PhishTank",
            "available": True,
            "flagged": in_database and valid,
            "in_database": in_database,
            "valid": valid
        }

    except Exception as error:
        print("[PhishTank] Error:", str(error))
        return None


# ── Verdict Builder ───────────────────────────────────────────────────────────
def build_verdict(url, gsb_result, phishtank_result):
    engines_checked = []
    danger_signals = []

    if gsb_result:
        engines_checked.append("Google Safe Browsing")

        if gsb_result.get("flagged"):
            threat_types = gsb_result.get("threat_types", [])

            if threat_types:
                danger_signals.append(
                    "Google Safe Browsing flagged this URL as: "
                    + ", ".join(threat_types)
                )
            else:
                danger_signals.append(
                    "Google Safe Browsing flagged this URL."
                )

    if phishtank_result:
        engines_checked.append("PhishTank")

        if phishtank_result.get("flagged"):
            danger_signals.append(
                "PhishTank identifies this as a verified phishing URL."
            )

    if not engines_checked:
        return {
            "error": "No scan engines are available right now. Please try again later."
        }

    if danger_signals:
        verdict = "DANGEROUS"
        verdict_class = "danger"
        message = "This link is listed by a trusted threat database. Do NOT proceed."
    else:
        verdict = "NOT FLAGGED"
        verdict_class = "safe"
        message = "This link was not found in the connected threat databases."

    return {
        "verdict": verdict,
        "verdict_class": verdict_class,
        "message": message,
        "url": url,
        "engines_checked": engines_checked,
        "danger_signals": danger_signals,
        "warning_signals": [],
        "note": "LidaShield checks trusted threat databases. A 'Not Flagged' result does not guarantee that a website is 100% safe."
    }


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    file_path = os.path.join(os.path.dirname(__file__), "index.html")

    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


@app.route("/scan", methods=["POST"])
def scan():
    ip = get_client_ip()

    if not check_rate_limit(ip):
        return jsonify({
            "error": f"You've used all {DAILY_FREE_LIMIT} free scans for today.",
            "rate_limited": True,
            "scans_remaining": 0
        }), 429

    body = request.get_json(silent=True)

    if not body or not body.get("url"):
        return jsonify({
            "error": "No URL provided.",
            "scans_remaining": scans_remaining(ip)
        }), 400

    url, error = validate_url(body.get("url"))

    if error:
        return jsonify({
            "error": error,
            "scans_remaining": scans_remaining(ip)
        }), 400

    gsb_result = scan_google_safe_browsing(url)
    phishtank_result = scan_phishtank(url)

    result = build_verdict(url, gsb_result, phishtank_result)
    result["scans_remaining"] = scans_remaining(ip)

    if "error" in result:
        return jsonify(result), 502

    return jsonify(result)


@app.route("/remaining", methods=["GET"])
def remaining():
    ip = get_client_ip()

    return jsonify({
        "scans_remaining": scans_remaining(ip),
        "limit": DAILY_FREE_LIMIT
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "LidaShield"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
