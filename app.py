import os
import sqlite3
import requests
from datetime import date, datetime
from collections import defaultdict
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── API Keys ──────────────────────────────────────────────────────────────────
GSB_API_KEY = os.environ.get("GSB_API_KEY", "")

# ── Settings ──────────────────────────────────────────────────────────────────
DAILY_FREE_LIMIT = 10
DATABASE_FILE = "lidashield.db"

scan_counts = defaultdict(lambda: {"count": 0, "date": str(date.today())})


# ── Database ──────────────────────────────────────────────────────────────────
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            category TEXT,
            description TEXT,
            reporter_ip TEXT,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scam_reports_normalized_url
        ON scam_reports (normalized_url)
    """)

    conn.commit()
    conn.close()


init_database()


# ── Helpers ───────────────────────────────────────────────────────────────────
def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def normalize_url(raw_url):
    if not raw_url:
        return ""

    raw_url = raw_url.strip()

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    if netloc.startswith("www."):
        netloc = netloc[4:]

    path = parsed.path.rstrip("/")

    return f"{scheme}://{netloc}{path}"


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


# ── LidaShield Report Database Check ──────────────────────────────────────────
def check_lidashield_reports(url):
    normalized = normalize_url(url)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) AS report_count
        FROM scam_reports
        WHERE normalized_url = ?
    """, (normalized,))

    row = cursor.fetchone()
    report_count = row["report_count"] if row else 0

    cursor.execute("""
        SELECT category, description, created_at
        FROM scam_reports
        WHERE normalized_url = ?
        ORDER BY created_at DESC
        LIMIT 5
    """, (normalized,))

    recent_reports = cursor.fetchall()
    conn.close()

    return {
        "source": "LidaShield Reports",
        "flagged": report_count > 0,
        "report_count": report_count,
        "recent_reports": [
            {
                "category": report["category"],
                "description": report["description"],
                "created_at": report["created_at"]
            }
            for report in recent_reports
        ]
    }


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
            "threatEntries": [{"url": url}]
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

        matches = response.json().get("matches", [])

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


# ── Verdict Builder ───────────────────────────────────────────────────────────
def build_verdict(url, lidashield_reports, gsb_result):
    engines_checked = []
    danger_signals = []

    if lidashield_reports:
        engines_checked.append("LidaShield Reports")

        if lidashield_reports.get("flagged"):
            count = lidashield_reports.get("report_count", 0)
            danger_signals.append(
                f"This URL has been reported {count} time(s) in the LidaShield scam database."
            )

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
                danger_signals.append("Google Safe Browsing flagged this URL.")

    if not engines_checked:
        return {
            "error": "No scan engines are available right now. Please add GSB_API_KEY or try again later."
        }

    if danger_signals:
        verdict = "DANGEROUS"
        verdict_class = "danger"
        message = "This link has been flagged by Google Safe Browsing or the LidaShield report database. Do NOT proceed."
    else:
        verdict = "NOT FLAGGED"
        verdict_class = "safe"
        message = "This link was not found in Google Safe Browsing or LidaShield reports."

    return {
        "verdict": verdict,
        "verdict_class": verdict_class,
        "message": message,
        "url": url,
        "engines_checked": engines_checked,
        "danger_signals": danger_signals,
        "warning_signals": [],
        "report_count": lidashield_reports.get("report_count", 0) if lidashield_reports else 0,
        "recent_reports": lidashield_reports.get("recent_reports", []) if lidashield_reports else [],
        "note": "LidaShield checks Google Safe Browsing and user-submitted scam reports. A 'Not Flagged' result does not guarantee that a website is 100% safe."
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

    lidashield_reports = check_lidashield_reports(url)
    gsb_result = scan_google_safe_browsing(url)

    result = build_verdict(
        url,
        lidashield_reports,
        gsb_result
    )

    result["scans_remaining"] = scans_remaining(ip)

    if "error" in result:
        return jsonify(result), 502

    return jsonify(result)


@app.route("/report", methods=["POST"])
def report():
    body = request.get_json(silent=True)
    ip = get_client_ip()

    if not body:
        return jsonify({
            "error": "No report data provided."
        }), 400

    raw_url = body.get("url", "")
    category = body.get("category", "Unknown").strip()
    description = body.get("description", "").strip()

    url, error = validate_url(raw_url)

    if error:
        return jsonify({
            "error": error
        }), 400

    if len(description) > 1000:
        return jsonify({
            "error": "Description is too long. Keep it under 1000 characters."
        }), 400

    normalized = normalize_url(url)
    created_at = datetime.utcnow().isoformat() + "Z"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scam_reports (
            url,
            normalized_url,
            category,
            description,
            reporter_ip,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        url,
        normalized,
        category,
        description,
        ip,
        created_at
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Scam report submitted successfully.",
        "url": url
    })


@app.route("/remaining", methods=["GET"])
def remaining():
    ip = get_client_ip()

    return jsonify({
        "scans_remaining": scans_remaining(ip),
        "limit": DAILY_FREE_LIMIT
    })


@app.route("/stats", methods=["GET"])
def stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total_reports FROM scam_reports")
    row = cursor.fetchone()

    conn.close()

    return jsonify({
        "total_reports": row["total_reports"] if row else 0
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
