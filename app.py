from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
import psycopg
from psycopg.rows import dict_row
import requests
import base64
import os
import time
from urllib.parse import urlparse, urlunparse
from datetime import date
import stripe

# ============================================================
# LidaShield v1
# Flask + Postgres + Google OAuth + Stripe + Own Scam Database
# ============================================================

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# -----------------------------
# Environment variables
# -----------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_SHIELD = os.environ.get("STRIPE_PRICE_SHIELD", "")
STRIPE_PRICE_PRO = os.environ.get("STRIPE_PRICE_PRO", "")

APP_URL = os.environ.get("APP_URL", "http://localhost:5000").rstrip("/")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-key")

app.secret_key = FLASK_SECRET_KEY
@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return error

    app.logger.exception("Unhandled server error")
    return jsonify({
        "error": "Server error",
        "details": str(error)
    }), 500

VT_URL = "https://www.virustotal.com/api/v3"

stripe.api_key = STRIPE_SECRET_KEY

PLAN_LIMITS = {
    "free": 50,
    "shield": 500,
    "pro": 1000000
}

# -----------------------------
# Google OAuth
# -----------------------------
oauth = OAuth(app)

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

# -----------------------------
# Load HTML
# -----------------------------
try:
    HTML = open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8").read()
except FileNotFoundError:
    HTML = "<h1>LidaShield error: index.html not found</h1>"

_db_ready = False


# ============================================================
# Database helpers
# ============================================================

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured in Render Environment Variables.")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def ensure_db():
    global _db_ready

    if _db_ready:
        return

    if not DATABASE_URL:
        return

    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        google_id TEXT UNIQUE,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        avatar_url TEXT,
        plan TEXT DEFAULT 'free',
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scam_urls (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        normalized_url TEXT UNIQUE NOT NULL,
        verdict TEXT NOT NULL,
        source TEXT DEFAULT 'lidashield',
        notes TEXT,
        malicious INT DEFAULT 0,
        suspicious INT DEFAULT 0,
        harmless INT DEFAULT 0,
        undetected INT DEFAULT 0,
        report_count INT DEFAULT 1,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scan_history (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        url TEXT NOT NULL,
        normalized_url TEXT,
        verdict TEXT,
        source TEXT,
        malicious INT DEFAULT 0,
        suspicious INT DEFAULT 0,
        harmless INT DEFAULT 0,
        undetected INT DEFAULT 0,
        scanned_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scam_reports (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        url TEXT,
        normalized_url TEXT,
        message TEXT,
        category TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS usage_limits (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        scan_date DATE DEFAULT CURRENT_DATE,
        scans_used INT DEFAULT 0,
        UNIQUE(user_id, scan_date)
    );
    """

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)

    _db_ready = True


@app.before_request
def before_request():
    ensure_db()


# ============================================================
# Utility helpers
# ============================================================

def normalize_url(raw_url):
    if not raw_url:
        raise ValueError("No URL provided.")

    raw_url = raw_url.strip()

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if not parsed.netloc:
        raise ValueError("Invalid URL.")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    path = parsed.path or ""
    if path != "/":
        path = path.rstrip("/")

    normalized = urlunparse((
        scheme,
        netloc,
        path,
        "",
        parsed.query,
        ""
    ))

    return normalized


def encode_url_for_virustotal(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def get_current_user():
    user_id = session.get("user_id")

    if not user_id or not DATABASE_URL:
        return None

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                return cur.fetchone()
    except Exception:
        return None


def get_plan_limit(plan):
    return PLAN_LIMITS.get(plan or "free", PLAN_LIMITS["free"])


def increment_usage_and_check_lock(user):
    """
    The user can still see the main verdict after the free limit.
    Details become locked after limit.
    """

    if not user:
        today = str(date.today())

        if session.get("anon_scan_date") != today:
            session["anon_scan_date"] = today
            session["anon_scans_used"] = 0

        session["anon_scans_used"] = session.get("anon_scans_used", 0) + 1
        scans_used = session["anon_scans_used"]
        scan_limit = 25

        return {
            "locked": scans_used > scan_limit,
            "scans_used": scans_used,
            "scan_limit": scan_limit,
            "plan": "guest"
        }

    plan = user.get("plan", "free")
    scan_limit = get_plan_limit(plan)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO usage_limits (user_id, scan_date, scans_used)
                VALUES (%s, CURRENT_DATE, 1)
                ON CONFLICT (user_id, scan_date)
                DO UPDATE SET scans_used = usage_limits.scans_used + 1
                RETURNING scans_used
                """,
                (user["id"],)
            )
            row = cur.fetchone()

    scans_used = row["scans_used"]

    return {
        "locked": scans_used > scan_limit and plan != "pro",
        "scans_used": scans_used,
        "scan_limit": scan_limit,
        "plan": plan
    }


def calculate_verdict(malicious, suspicious):
    if malicious == 0 and suspicious == 0:
        return "safe"

    if malicious <= 2 and suspicious <= 3:
        return "suspicious"

    return "dangerous"


def calculate_score(malicious, suspicious):
    score = malicious * 25 + suspicious * 10
    return min(100, score)


# ============================================================
# Legacy external-scan helpers (currently disabled)
# ============================================================

def vt_get_report(url):
    if not VIRUSTOTAL_API_KEY:
        return None

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(
        f"{VT_URL}/urls/{encode_url_for_virustotal(url)}",
        headers=headers,
        timeout=20
    )

    if response.status_code == 200:
        return response.json()

    return None


def vt_submit_and_wait(url):
    if not VIRUSTOTAL_API_KEY:
        return None

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        requests.post(
            f"{VT_URL}/urls",
            headers=headers,
            data={"url": url},
            timeout=20
        )
    except Exception:
        return None

    for _ in range(8):
        time.sleep(2)
        report = vt_get_report(url)
        if report:
            return report

    return vt_get_report(url)


def parse_vt_report(report):
    attrs = report.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    verdict = calculate_verdict(malicious, suspicious)
    score = calculate_score(malicious, suspicious)

    engines = attrs.get("last_analysis_results", {})
    flagged = [
        name for name, res in engines.items()
        if res.get("category") in ("malicious", "suspicious")
    ]

    return {
        "verdict": verdict,
        "score": score,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "flagged": flagged[:10],
        "flagged_total": len(flagged),
        "source": "external_intelligence"
    }


# ============================================================
# Own database helpers
# ============================================================

def lookup_own_database(normalized_url):
    if not DATABASE_URL:
        return None

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM scam_urls
                WHERE normalized_url = %s
                LIMIT 1
                """,
                (normalized_url,)
            )
            return cur.fetchone()


def save_scan_history(user_id, url, normalized_url, result):
    if not DATABASE_URL:
        return

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_history
                (user_id, url, normalized_url, verdict, source, malicious, suspicious, harmless, undetected)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    url,
                    normalized_url,
                    result.get("verdict"),
                    result.get("source"),
                    result.get("malicious", 0),
                    result.get("suspicious", 0),
                    result.get("harmless", 0),
                    result.get("undetected", 0),
                )
            )


def save_to_own_database(url, normalized_url, result):
    """
    This saves dangerous/suspicious VT results into LidaShield's own database.
    Over time this becomes your own dataset.
    """

    if not DATABASE_URL:
        return

    verdict = result.get("verdict")

    if verdict not in ("suspicious", "dangerous"):
        return

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scam_urls
                (url, normalized_url, verdict, source, malicious, suspicious, harmless, undetected, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (normalized_url)
                DO UPDATE SET
                    verdict = EXCLUDED.verdict,
                    source = EXCLUDED.source,
                    malicious = EXCLUDED.malicious,
                    suspicious = EXCLUDED.suspicious,
                    harmless = EXCLUDED.harmless,
                    undetected = EXCLUDED.undetected,
                    updated_at = NOW()
                """,
                (
                    url,
                    normalized_url,
                    verdict,
                    "external_cache",
                    result.get("malicious", 0),
                    result.get("suspicious", 0),
                    result.get("harmless", 0),
                    result.get("undetected", 0),
                    "Automatically cached by LidaShield from external scan result."
                )
            )


# ============================================================
# Page routes
# ============================================================

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/health")
def health():
    return jsonify({
        "ok": True,
        "app": "LidaShield",
        "database": bool(DATABASE_URL),
        "external_scanning": False,
        "google_oauth": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "stripe": bool(STRIPE_SECRET_KEY)
    })


# ============================================================
# Auth routes
# ============================================================

@app.route("/login")
def login():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google OAuth is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render.", 500

    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    token = oauth.google.authorize_access_token()
    userinfo = token.get("userinfo")

    if not userinfo:
        userinfo = oauth.google.userinfo()

    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name", "")
    avatar_url = userinfo.get("picture", "")

    if not google_id or not email:
        return "Could not get Google account details.", 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (google_id, email, name, avatar_url)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (email)
                DO UPDATE SET
                    google_id = EXCLUDED.google_id,
                    name = EXCLUDED.name,
                    avatar_url = EXCLUDED.avatar_url
                RETURNING *
                """,
                (google_id, email, name, avatar_url)
            )
            user = cur.fetchone()

    session["user_id"] = user["id"]
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/api/me")
def api_me():
    user = get_current_user()

    if not user:
        return jsonify({
            "authenticated": False,
            "user": None
        })

    return jsonify({
        "authenticated": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user.get("name"),
            "avatar_url": user.get("avatar_url"),
            "plan": user.get("plan", "free")
        }
    })


# ============================================================
# Scan API
# ============================================================

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "No URL provided."}), 400

    try:
        normalized_url = normalize_url(raw_url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    user = get_current_user()
    usage = increment_usage_and_check_lock(user)

    # 1. Check LidaShield own database first
    known = lookup_own_database(normalized_url)

    if known:
        result = {
            "url": raw_url,
            "normalized_url": normalized_url,
            "verdict": known["verdict"],
            "score": calculate_score(known.get("malicious", 0), known.get("suspicious", 0)),
            "malicious": known.get("malicious", 0),
            "suspicious": known.get("suspicious", 0),
            "harmless": known.get("harmless", 0),
            "undetected": known.get("undetected", 0),
            "flagged": [],
            "flagged_total": 0,
            "source": known.get("source", "lidashield"),
            "known_by_lidashield": True,
            "message": "This link was found in the LidaShield database."
        }

        save_scan_history(user["id"] if user else None, raw_url, normalized_url, result)

        return jsonify({
            **result,
            **usage
        })

    # 2. If not found, do NOT use VirusTotal or any external scanner.
    # Unknown means: not verified in LidaShield yet.
    result = {
        "url": raw_url,
        "normalized_url": normalized_url,
        "verdict": "unknown",
        "score": 35,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "flagged": [],
        "flagged_total": 0,
        "source": "lidashield_unverified",
        "known_by_lidashield": False,
        "message": "This link is not yet in the verified LidaShield database. It has not been marked suspicious. Use Report this link if you want it reviewed."
    }

    save_scan_history(user["id"] if user else None, raw_url, normalized_url, result)

    return jsonify({
        **result,
        **usage
    })


# ============================================================
# User scan history
# ============================================================

@app.route("/api/history")
def api_history():
    user = get_current_user()

    if not user:
        return jsonify({"history": []})

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT url, verdict, source, scanned_at
                FROM scan_history
                WHERE user_id = %s
                ORDER BY scanned_at DESC
                LIMIT 12
                """,
                (user["id"],)
            )
            rows = cur.fetchall()

    return jsonify({"history": rows})


# ============================================================
# Scam report API
# ============================================================

@app.route("/report", methods=["POST"])
def report_scam():
    """
    User reports are saved as pending evidence only.
    They do NOT automatically mark a URL as suspicious.

    This prevents trolls from poisoning the LidaShield database.
    A reported URL should only move into scam_urls after trusted review
    or after strong evidence from verified sources.
    """
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()
    message = (data.get("message") or "User reported this link from the LidaShield scanner.").strip()
    category = (data.get("category") or "url").strip() or "url"

    user = get_current_user()

    normalized_url = None
    if raw_url:
        try:
            normalized_url = normalize_url(raw_url)
        except ValueError:
            normalized_url = None

    if not raw_url and not message:
        return jsonify({"error": "Please provide a URL or message to report."}), 400

    if not DATABASE_URL:
        return jsonify({"error": "Database is not configured."}), 500

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scam_reports
                (user_id, url, normalized_url, message, category, status)
                VALUES (%s, %s, %s, %s, %s, 'pending')
                RETURNING id
                """,
                (
                    user["id"] if user else None,
                    raw_url,
                    normalized_url,
                    message,
                    category
                )
            )
            report_row = cur.fetchone()

    return jsonify({
        "ok": True,
        "status": "pending",
        "report_id": report_row["id"] if report_row else None,
        "message": "Report received. It is now pending review and will not affect the public verdict until verified."
    })


# ============================================================
# Stripe checkout
# ============================================================

@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Please sign in with Google first."}), 401

    if not STRIPE_SECRET_KEY:
        return jsonify({"error": "Stripe is not configured yet."}), 500

    data = request.get_json(silent=True) or {}
    plan = data.get("plan", "").lower().strip()

    if plan == "shield":
        price_id = STRIPE_PRICE_SHIELD
    elif plan == "pro":
        price_id = STRIPE_PRICE_PRO
    else:
        return jsonify({"error": "Invalid plan."}), 400

    if not price_id:
        return jsonify({"error": f"Stripe price ID for {plan} is missing."}), 500

    customer_id = user.get("stripe_customer_id")

    if not customer_id:
        customer = stripe.Customer.create(
            email=user["email"],
            name=user.get("name") or user["email"],
            metadata={"user_id": str(user["id"])}
        )
        customer_id = customer.id

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET stripe_customer_id = %s WHERE id = %s",
                    (customer_id, user["id"])
                )

    checkout = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{APP_URL}/?billing=success",
        cancel_url=f"{APP_URL}/?billing=cancelled",
        metadata={
            "user_id": str(user["id"]),
            "plan": plan
        }
    )

    return jsonify({"url": checkout.url})


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({"ok": True, "message": "Webhook secret not configured."})

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    event_type = event["type"]
    obj = event["data"]["object"]

    if event_type == "checkout.session.completed":
        user_id = obj.get("metadata", {}).get("user_id")
        plan = obj.get("metadata", {}).get("plan", "shield")
        subscription_id = obj.get("subscription")

        if user_id and plan in ("shield", "pro"):
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE users
                        SET plan = %s, stripe_subscription_id = %s
                        WHERE id = %s
                        """,
                        (plan, subscription_id, user_id)
                    )

    if event_type == "customer.subscription.deleted":
        customer_id = obj.get("customer")

        if customer_id:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE users
                        SET plan = 'free', stripe_subscription_id = NULL
                        WHERE stripe_customer_id = %s
                        """,
                        (customer_id,)
                    )

    return jsonify({"ok": True})


# ============================================================
# Run locally
# ============================================================

if __name__ == "__main__":
    print("\nLidaShield running locally at http://localhost:5000\n")
    app.run(debug=True, port=5000)
