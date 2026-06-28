from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
from psycopg.rows import dict_row
from urllib.parse import urlparse, urlunparse
from datetime import date
import psycopg
import requests
import base64
import csv
import hashlib
import html
import io
import json
import os
import re
import stripe
import time

# ============================================================
# LidaShield AI Scam Analyst Core
# Flask + Postgres + Google OAuth + Stripe + Database-backed scam intelligence
# Complete replacement file for Render: gunicorn app:app
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
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "")

app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=APP_URL.startswith("https://"),
    MAX_CONTENT_LENGTH=256 * 1024,
)

VT_URL = "https://www.virustotal.com/api/v3"
stripe.api_key = STRIPE_SECRET_KEY

PLAN_LIMITS = {
    "guest": 3,
    "free": 50,
    "shield": 500,
    "pro": 1000000,
}

RATE_LIMIT_RULES = {
    "/scan": (40, 60),
    "/check-message": (30, 60),
    "/report": (10, 60),
    "/api/feedback": (10, 60),
    "/create-checkout-session": (8, 60),
    "/billing/portal": (12, 60),
}
_RATE_LIMIT_BUCKETS = {}
_db_ready = False

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
# Load homepage HTML
# -----------------------------
try:
    HTML = open(os.path.join(os.path.dirname(__file__), "index.html"), encoding="utf-8").read()
except FileNotFoundError:
    HTML = "<h1>LidaShield error: index.html not found</h1>"

# ============================================================
# Error handling + security
# ============================================================

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    code = 500
    if isinstance(error, HTTPException):
        code = error.code or 500
        name = error.name
        details = error.description
    else:
        name = "Server error"
        details = str(error)
    app.logger.exception("Unhandled server error")
    return jsonify({
        "error": name,
        "details": details,
        "type": type(error).__name__,
        "path": request.path,
    }), code


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit_key():
    user_id = session.get("user_id")
    if user_id:
        return f"user:{user_id}:{request.path}"
    return f"ip:{get_client_ip()}:{request.path}"


def check_rate_limit():
    rule = RATE_LIMIT_RULES.get(request.path)
    if not rule:
        return None
    max_hits, window_seconds = rule
    now = time.time()
    key = rate_limit_key()
    hits = _RATE_LIMIT_BUCKETS.get(key, [])
    hits = [t for t in hits if now - t < window_seconds]
    if len(hits) >= max_hits:
        retry_after = int(window_seconds - (now - hits[0])) if hits else window_seconds
        response = jsonify({
            "error": "Too many requests.",
            "details": f"Please wait {max(1, retry_after)} seconds before trying again.",
            "retry_after": max(1, retry_after),
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(max(1, retry_after))
        return response
    hits.append(now)
    _RATE_LIMIT_BUCKETS[key] = hits
    if len(_RATE_LIMIT_BUCKETS) > 5000:
        cutoff = now - 3600
        for old_key in list(_RATE_LIMIT_BUCKETS.keys()):
            _RATE_LIMIT_BUCKETS[old_key] = [t for t in _RATE_LIMIT_BUCKETS[old_key] if t > cutoff]
            if not _RATE_LIMIT_BUCKETS[old_key]:
                _RATE_LIMIT_BUCKETS.pop(old_key, None)
    return None


def is_same_origin_post_allowed():
    if request.method != "POST":
        return True
    if request.path == "/stripe/webhook":
        return True
    protected = (
        "/scan", "/check-message", "/report", "/api/feedback",
        "/create-checkout-session", "/billing/portal",
    )
    if not (request.path in protected or request.path.startswith("/admin/api/")):
        return True
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    allowed_hosts = {request.host, "lidashield.com", "www.lidashield.com"}
    if origin:
        return urlparse(origin).netloc in allowed_hosts
    if referer:
        return urlparse(referer).netloc in allowed_hosts
    return False


@app.before_request
def before_request():
    if request.host == "lidashield.com" and APP_URL.startswith("https://"):
        return redirect("https://www.lidashield.com" + request.full_path.rstrip("?"), code=301)
    limited = check_rate_limit()
    if limited:
        return limited
    if not is_same_origin_post_allowed():
        return jsonify({"error": "Blocked cross-origin request."}), 403
    ensure_db()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
    if request.path.startswith(("/dashboard", "/admin")):
        response.headers.setdefault("Cache-Control", "no-store")
    return response

# ============================================================
# Database helpers
# ============================================================

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured in Render Environment Variables.")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def ensure_column(cur, table, column, ddl):
    cur.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        LIMIT 1
        """,
        (table, column),
    )
    if not cur.fetchone():
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def ensure_db():
    global _db_ready
    if _db_ready or not DATABASE_URL:
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

    CREATE TABLE IF NOT EXISTS message_checks (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        message TEXT NOT NULL,
        verdict TEXT,
        score INT DEFAULT 0,
        reasons TEXT,
        extracted_urls TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS intelligence_events (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        report_id INT REFERENCES scam_reports(id) ON DELETE SET NULL,
        url TEXT,
        normalized_url TEXT,
        domain TEXT,
        email TEXT,
        phone TEXT,
        message_hash TEXT,
        source TEXT DEFAULT 'lidashield',
        evidence_type TEXT DEFAULT 'community_report',
        confidence_score INT DEFAULT 0,
        reason TEXT,
        status TEXT DEFAULT 'watchlist',
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS feedback_requests (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        request_type TEXT DEFAULT 'feedback',
        email TEXT,
        subject TEXT,
        url TEXT,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'new',
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS analyst_observations (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        input_type TEXT DEFAULT 'message',
        input_text TEXT,
        verdict TEXT,
        score INT DEFAULT 0,
        extracted_indicators TEXT,
        evidence_json TEXT,
        analyst_summary TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_scam_urls_normalized_url ON scam_urls(normalized_url);
    CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id);
    CREATE INDEX IF NOT EXISTS idx_message_checks_user_id ON message_checks(user_id);
    CREATE INDEX IF NOT EXISTS idx_intelligence_domain ON intelligence_events(domain);
    CREATE INDEX IF NOT EXISTS idx_intelligence_normalized_url ON intelligence_events(normalized_url);
    CREATE INDEX IF NOT EXISTS idx_analyst_observations_user_id ON analyst_observations(user_id);
    """

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)

            # Safe migrations for older LidaShield databases.
            ensure_column(cur, "users", "stripe_customer_id", "TEXT")
            ensure_column(cur, "users", "stripe_subscription_id", "TEXT")
            ensure_column(cur, "scam_urls", "source", "TEXT DEFAULT 'lidashield'")
            ensure_column(cur, "scam_urls", "notes", "TEXT")
            ensure_column(cur, "scam_urls", "malicious", "INT DEFAULT 0")
            ensure_column(cur, "scam_urls", "suspicious", "INT DEFAULT 0")
            ensure_column(cur, "scam_urls", "harmless", "INT DEFAULT 0")
            ensure_column(cur, "scam_urls", "undetected", "INT DEFAULT 0")
            ensure_column(cur, "scam_urls", "report_count", "INT DEFAULT 1")
            ensure_column(cur, "scam_urls", "updated_at", "TIMESTAMP DEFAULT NOW()")
            ensure_column(cur, "scan_history", "source", "TEXT")
            ensure_column(cur, "scan_history", "malicious", "INT DEFAULT 0")
            ensure_column(cur, "scan_history", "suspicious", "INT DEFAULT 0")
            ensure_column(cur, "scan_history", "harmless", "INT DEFAULT 0")
            ensure_column(cur, "scan_history", "undetected", "INT DEFAULT 0")
            ensure_column(cur, "scam_reports", "status", "TEXT DEFAULT 'pending'")
            ensure_column(cur, "intelligence_events", "email", "TEXT")
            ensure_column(cur, "intelligence_events", "phone", "TEXT")
            ensure_column(cur, "message_checks", "reasons", "TEXT")
            ensure_column(cur, "message_checks", "extracted_urls", "TEXT")

            # Beta seed so the requested DBS test returns genuine database-backed evidence.
            cur.execute(
                """
                INSERT INTO scam_urls
                (url, normalized_url, verdict, source, notes, malicious, suspicious, harmless, undetected, report_count)
                VALUES
                (%s, %s, 'dangerous', 'lidashield_test_seed', %s, 4, 5, 0, 0, 1)
                ON CONFLICT (normalized_url) DO UPDATE SET
                    verdict = EXCLUDED.verdict,
                    source = EXCLUDED.source,
                    notes = EXCLUDED.notes,
                    malicious = EXCLUDED.malicious,
                    suspicious = EXCLUDED.suspicious,
                    harmless = EXCLUDED.harmless,
                    undetected = EXCLUDED.undetected,
                    updated_at = NOW()
                """,
                (
                    "https://dbs-login-verify-account-security.xyz",
                    "https://dbs-login-verify-account-security.xyz",
                    "Seeded beta indicator: fake DBS OTP/login phishing-style domain for AI Scam Analyst testing.",
                ),
            )
        conn.commit()
    _db_ready = True

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
    netloc = parsed.netloc.lower().strip()
    path = parsed.path or ""
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def extract_domain(raw_url):
    try:
        parsed = urlparse(normalize_url(raw_url))
        return parsed.netloc.lower().split("@").pop().split(":")[0]
    except Exception:
        return ""


def encode_url_for_virustotal(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def message_hash(text):
    return hashlib.sha256((text or "").strip().lower().encode()).hexdigest()


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


def is_admin(user=None):
    user = user or get_current_user()
    if not user:
        return False
    emails = {e.strip().lower() for e in ADMIN_EMAILS.split(",") if e.strip()}
    return bool(user.get("email") and user["email"].lower() in emails)


def get_plan_limit(plan):
    return PLAN_LIMITS.get((plan or "free").lower(), PLAN_LIMITS["free"])


def increment_usage_and_check_lock(user):
    if not user:
        today = str(date.today())
        if session.get("anon_scan_date") != today:
            session["anon_scan_date"] = today
            session["anon_scans_used"] = 0
        session["anon_scans_used"] = session.get("anon_scans_used", 0) + 1
        used = session["anon_scans_used"]
        limit = PLAN_LIMITS["guest"]
        return {"locked": used > limit, "scans_used": used, "scan_limit": limit, "plan": "guest"}

    plan = (user.get("plan") or "free").lower()
    limit = get_plan_limit(plan)
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
                (user["id"],),
            )
            row = cur.fetchone()
        conn.commit()
    used = row["scans_used"]
    return {"locked": used > limit and plan != "pro", "scans_used": used, "scan_limit": limit, "plan": plan}


def calculate_verdict(malicious, suspicious):
    malicious = malicious or 0
    suspicious = suspicious or 0
    if malicious == 0 and suspicious == 0:
        return "safe"
    if malicious <= 2 and suspicious <= 3:
        return "suspicious"
    return "dangerous"


def calculate_score(malicious, suspicious):
    return min(100, int((malicious or 0) * 25 + (suspicious or 0) * 10))

# ============================================================
# Indicator extraction + AI scam analyst
# ============================================================

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?:(?:\+65|65)\s?)?[689]\d{3}\s?\d{4}")

BRANDS = [
    "DBS", "POSB", "OCBC", "UOB", "PayNow", "PayLah", "Singpass", "CPF", "IRAS",
    "Amazon", "Apple", "Google", "Microsoft", "Meta", "Facebook", "Instagram", "WhatsApp",
    "Shopee", "Lazada", "Carousell", "DHL", "SingPost", "Netflix", "Telegram",
]

SIGNAL_RULES = [
    ("otp_request", r"\b(otp|one[-\s]?time password|verification code|2fa|pin)\b", 24, "Requests OTP or verification code."),
    ("login_or_verify", r"\b(login|log in|verify|verification|authenticate|confirm|update your account)\b", 16, "Asks user to login, verify, or update account."),
    ("account_threat", r"\b(suspended|blocked|locked|disabled|restricted|terminated|frozen)\b", 24, "Threatens account suspension or restriction."),
    ("urgency", r"\b(urgent|immediately|within 24 hours|24 hours|today|final warning|last chance|expire|expires)\b", 16, "Creates urgency or time pressure."),
    ("money_or_reward", r"\b(refund|prize|reward|voucher|claim|payment|transfer|fee|fine|tax|parcel)\b", 12, "Mentions payment, reward, fine, tax, or parcel pressure."),
    ("shortened_or_odd_domain", r"\b(bit\.ly|tinyurl|t\.co|goo\.gl|\.xyz|\.top|\.click|\.shop|\.icu|\.monster)\b", 18, "Uses a risky, shortened, or unusual domain pattern."),
    ("credential_harvest", r"\b(password|credentials|bank account|card number|cvv|security code)\b", 18, "Asks for sensitive credentials or banking data."),
]


def extract_indicators(text):
    text = text or ""
    urls = []
    domains = []
    for match in URL_RE.findall(text):
        cleaned = match.strip().rstrip(".,;:!?)]")
        if cleaned.startswith("www."):
            cleaned = "https://" + cleaned
        try:
            normalized = normalize_url(cleaned)
            if normalized not in urls:
                urls.append(normalized)
            domain = extract_domain(normalized)
            if domain and domain not in domains:
                domains.append(domain)
        except Exception:
            pass

    emails = sorted(set(EMAIL_RE.findall(text)))
    phones = sorted(set(re.sub(r"\s+", "", p) for p in PHONE_RE.findall(text)))
    lower = text.lower()
    brands = [b for b in BRANDS if b.lower() in lower]

    signals = []
    behaviour_score = 0
    for code, pattern, points, reason in SIGNAL_RULES:
        if re.search(pattern, text, re.I):
            signals.append({"code": code, "points": points, "reason": reason})
            behaviour_score += points

    # Extra brand impersonation signal if brand + external URL are present.
    if brands and urls:
        for domain in domains:
            domain_l = domain.lower()
            brand_in_domain = any(b.lower().replace(" ", "") in domain_l for b in brands)
            if not brand_in_domain or any(tld in domain_l for tld in [".xyz", ".top", ".click", ".shop", ".icu"]):
                signals.append({
                    "code": "brand_impersonation_with_link",
                    "points": 22,
                    "reason": "Mentions a trusted brand and sends the user to an external or unusual domain.",
                })
                behaviour_score += 22
                break

    return {
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "phones": phones,
        "brands": brands,
        "signals": signals,
        "behaviour_score": min(100, behaviour_score),
    }


def lookup_own_database(normalized_url):
    if not DATABASE_URL:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scam_urls WHERE normalized_url = %s LIMIT 1", (normalized_url,))
            return cur.fetchone()


def lookup_domain_database(domain):
    if not DATABASE_URL or not domain:
        return []
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM scam_urls
                WHERE lower(normalized_url) LIKE %s
                ORDER BY updated_at DESC
                LIMIT 10
                """,
                (f"%{domain.lower()}%",),
            )
            return cur.fetchall() or []


def lookup_intelligence_graph(indicators):
    if not DATABASE_URL:
        return []
    urls = indicators.get("urls", [])
    domains = indicators.get("domains", [])
    emails = indicators.get("emails", [])
    phones = indicators.get("phones", [])
    hits = []
    with get_db() as conn:
        with conn.cursor() as cur:
            if urls:
                cur.execute(
                    "SELECT * FROM intelligence_events WHERE normalized_url = ANY(%s) ORDER BY created_at DESC LIMIT 15",
                    (urls,),
                )
                hits.extend(cur.fetchall() or [])
            if domains:
                cur.execute(
                    "SELECT * FROM intelligence_events WHERE domain = ANY(%s) ORDER BY created_at DESC LIMIT 15",
                    (domains,),
                )
                hits.extend(cur.fetchall() or [])
            if emails:
                cur.execute(
                    "SELECT * FROM intelligence_events WHERE email = ANY(%s) ORDER BY created_at DESC LIMIT 15",
                    (emails,),
                )
                hits.extend(cur.fetchall() or [])
            if phones:
                cur.execute(
                    "SELECT * FROM intelligence_events WHERE phone = ANY(%s) ORDER BY created_at DESC LIMIT 15",
                    (phones,),
                )
                hits.extend(cur.fetchall() or [])
    seen = set()
    unique = []
    for hit in hits:
        key = hit.get("id")
        if key not in seen:
            seen.add(key)
            unique.append(hit)
    return unique[:25]


def db_hit_to_evidence(row, indicator_type="url"):
    return {
        "source": row.get("source", "lidashield_database"),
        "indicator_type": indicator_type,
        "url": row.get("url"),
        "normalized_url": row.get("normalized_url"),
        "verdict": row.get("verdict"),
        "malicious": row.get("malicious", 0),
        "suspicious": row.get("suspicious", 0),
        "report_count": row.get("report_count", 0),
        "notes": row.get("notes"),
    }


def intelligence_hit_to_evidence(row):
    return {
        "source": row.get("source", "lidashield_intelligence_graph"),
        "indicator_type": row.get("evidence_type", "intelligence_event"),
        "url": row.get("url"),
        "normalized_url": row.get("normalized_url"),
        "domain": row.get("domain"),
        "email": row.get("email"),
        "phone": row.get("phone"),
        "confidence_score": row.get("confidence_score", 0),
        "reason": row.get("reason"),
        "status": row.get("status"),
    }


def analyse_message_with_database(message):
    indicators = extract_indicators(message)
    db_hits = []

    for url in indicators["urls"]:
        hit = lookup_own_database(url)
        if hit:
            db_hits.append(db_hit_to_evidence(hit, "url"))

    if not db_hits:
        for domain in indicators["domains"]:
            for hit in lookup_domain_database(domain):
                db_hits.append(db_hit_to_evidence(hit, "domain"))

    graph_hits_raw = lookup_intelligence_graph(indicators)
    graph_hits = [intelligence_hit_to_evidence(h) for h in graph_hits_raw]

    behaviour_score = indicators["behaviour_score"]
    score = min(70, behaviour_score)
    verdict = "unknown"
    evidence_strength = "behaviour_only"

    if db_hits:
        evidence_strength = "database_backed"
        max_db_score = 0
        for hit in db_hits:
            v = (hit.get("verdict") or "").lower()
            if v == "dangerous":
                max_db_score = max(max_db_score, 95)
            elif v == "suspicious":
                max_db_score = max(max_db_score, 82)
            elif v == "safe":
                max_db_score = max(max_db_score, 25)
            else:
                max_db_score = max(max_db_score, 60)
        score = max(score, max_db_score)
    elif graph_hits:
        evidence_strength = "intelligence_graph_backed"
        max_graph = max([int(h.get("confidence_score") or 0) for h in graph_hits] + [0])
        score = max(score, min(92, max_graph + 15))

    if score >= 85:
        verdict = "dangerous"
    elif score >= 45:
        verdict = "suspicious"
    elif score <= 20 and not indicators["urls"] and not indicators["signals"]:
        verdict = "low-risk"
    else:
        verdict = "unknown"

    reasons = []
    if db_hits:
        reasons.append(f"Matched {len(db_hits)} indicator(s) in LidaShield's scam database.")
    if graph_hits:
        reasons.append(f"Matched {len(graph_hits)} intelligence graph event(s).")
    for s in indicators["signals"][:6]:
        reasons.append(s["reason"])
    if not reasons:
        reasons.append("No strong scam indicators were found in LidaShield's database or signal layer.")

    if db_hits:
        summary = "Database-backed evidence found. Treat this message as high risk and do not click the link."
    elif graph_hits:
        summary = "LidaShield intelligence graph evidence found. Treat this message as suspicious."
    elif verdict in ("dangerous", "suspicious"):
        summary = "No prior database match, but the message contains strong scam behaviour signals."
    else:
        summary = "No database match and no strong scam signals found. Stay cautious if personal information is requested."

    return {
        "verdict": verdict,
        "score": int(score),
        "analysis_mode": "database_backed_ai_scam_analyst_core",
        "evidence_strength": evidence_strength,
        "database_hits": db_hits,
        "intelligence_graph_hits": graph_hits,
        "indicators": indicators,
        "reasons": reasons,
        "analyst_summary": summary,
    }


def save_message_check(user_id, message, analysis):
    if not DATABASE_URL:
        return None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO message_checks (user_id, message, verdict, score, reasons, extracted_urls)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    user_id,
                    message,
                    analysis.get("verdict"),
                    analysis.get("score", 0),
                    json.dumps(analysis.get("reasons", [])),
                    json.dumps(analysis.get("indicators", {}).get("urls", [])),
                ),
            )
            row = cur.fetchone()
            cur.execute(
                """
                INSERT INTO analyst_observations
                (user_id, input_type, input_text, verdict, score, extracted_indicators, evidence_json, analyst_summary)
                VALUES (%s, 'message', %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    message,
                    analysis.get("verdict"),
                    analysis.get("score", 0),
                    json.dumps(analysis.get("indicators", {})),
                    json.dumps({
                        "database_hits": analysis.get("database_hits", []),
                        "intelligence_graph_hits": analysis.get("intelligence_graph_hits", []),
                        "evidence_strength": analysis.get("evidence_strength"),
                    }),
                    analysis.get("analyst_summary"),
                ),
            )
        conn.commit()
    return row.get("id") if row else None

# ============================================================
# VirusTotal helpers
# ============================================================

def vt_get_report(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"{VT_URL}/urls/{encode_url_for_virustotal(url)}", headers=headers, timeout=20)
    if response.status_code == 200:
        return response.json()
    return None


def vt_submit_and_wait(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        requests.post(f"{VT_URL}/urls", headers=headers, data={"url": url}, timeout=20)
    except Exception:
        return None
    for _ in range(4):
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
    engines = attrs.get("last_analysis_results", {})
    flagged = [name for name, res in engines.items() if res.get("category") in ("malicious", "suspicious")]
    return {
        "verdict": calculate_verdict(malicious, suspicious),
        "score": calculate_score(malicious, suspicious),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "flagged": flagged[:10],
        "flagged_total": len(flagged),
        "source": "virustotal",
    }


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
                ),
            )
        conn.commit()


def save_to_own_database(url, normalized_url, result):
    if not DATABASE_URL:
        return
    if result.get("verdict") not in ("suspicious", "dangerous"):
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scam_urls
                (url, normalized_url, verdict, source, malicious, suspicious, harmless, undetected, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (normalized_url) DO UPDATE SET
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
                    result.get("verdict"),
                    "virustotal_cache",
                    result.get("malicious", 0),
                    result.get("suspicious", 0),
                    result.get("harmless", 0),
                    result.get("undetected", 0),
                    "Automatically cached from external scan result.",
                ),
            )
        conn.commit()

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
        "app": "LidaShield AI Scam Analyst Core",
        "database": bool(DATABASE_URL),
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "google_oauth": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "stripe": bool(STRIPE_SECRET_KEY),
    })


@app.route("/privacy")
def privacy():
    return render_template_string(SIMPLE_PAGE, title="Privacy Policy", body="LidaShield stores user-submitted URLs, scam reports, message-check metadata, and account information needed to provide scam intelligence services. Do not submit passwords, OTPs, or private banking information. Data may be used to improve LidaShield's scam database and intelligence graph.")


@app.route("/terms")
def terms():
    return render_template_string(SIMPLE_PAGE, title="Terms of Service", body="LidaShield provides risk analysis and scam intelligence for safety awareness. Verdicts are informational and not a guarantee. Users remain responsible for verifying messages, links, and transactions before acting.")

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
    userinfo = token.get("userinfo") or oauth.google.userinfo()
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
                ON CONFLICT (email) DO UPDATE SET
                    google_id = EXCLUDED.google_id,
                    name = EXCLUDED.name,
                    avatar_url = EXCLUDED.avatar_url
                RETURNING *
                """,
                (google_id, email, name, avatar_url),
            )
            user = cur.fetchone()
        conn.commit()
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
        return jsonify({"authenticated": False, "user": None})
    return jsonify({
        "authenticated": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user.get("name"),
            "avatar_url": user.get("avatar_url"),
            "plan": user.get("plan", "free"),
            "is_admin": is_admin(user),
        },
    })

# ============================================================
# Scanner API
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
            "source": known.get("source", "lidashield_database"),
            "known_by_lidashield": True,
            "intelligence_warning": "This link was already found in the LidaShield scam database.",
            "message": "Database-backed verdict from LidaShield.",
        }
        save_scan_history(user["id"] if user else None, raw_url, normalized_url, result)
        return jsonify({**result, **usage})

    graph_hits = lookup_intelligence_graph({"urls": [normalized_url], "domains": [extract_domain(normalized_url)], "emails": [], "phones": []})
    if graph_hits:
        result = {
            "url": raw_url,
            "normalized_url": normalized_url,
            "verdict": "suspicious",
            "score": min(90, max([int(h.get("confidence_score") or 0) for h in graph_hits] + [65])),
            "malicious": 0,
            "suspicious": len(graph_hits),
            "harmless": 0,
            "undetected": 0,
            "flagged": [],
            "flagged_total": len(graph_hits),
            "source": "lidashield_intelligence_graph",
            "known_by_lidashield": True,
            "intelligence_warning": "Related intelligence events were found for this URL/domain.",
            "message": "Intelligence graph-backed warning from LidaShield.",
        }
        save_scan_history(user["id"] if user else None, raw_url, normalized_url, result)
        return jsonify({**result, **usage})

    report = vt_get_report(normalized_url)
    if not report:
        report = vt_submit_and_wait(normalized_url)
    if report:
        result = parse_vt_report(report)
        result.update({
            "url": raw_url,
            "normalized_url": normalized_url,
            "known_by_lidashield": False,
            "message": "External scan completed and suspicious results may be cached into LidaShield.",
        })
        save_to_own_database(raw_url, normalized_url, result)
    else:
        result = {
            "url": raw_url,
            "normalized_url": normalized_url,
            "verdict": "unknown",
            "score": 0,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "flagged": [],
            "flagged_total": 0,
            "source": "lidashield_database_only",
            "known_by_lidashield": False,
            "message": "No LidaShield database hit. External scanning is not configured or did not return a result.",
        }
    save_scan_history(user["id"] if user else None, raw_url, normalized_url, result)
    return jsonify({**result, **usage})


@app.route("/check-message", methods=["POST"])
def check_message():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or data.get("text") or "").strip()
    if not message:
        return jsonify({"error": "No message provided."}), 400
    if len(message) > 5000:
        return jsonify({"error": "Message is too long. Keep it under 5000 characters."}), 400

    user = get_current_user()
    analysis = analyse_message_with_database(message)
    check_id = save_message_check(user["id"] if user else None, message, analysis)
    analysis["check_id"] = check_id
    return jsonify(analysis)

# ============================================================
# Reports + feedback
# ============================================================

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()
    message = (data.get("message") or "").strip()
    category = (data.get("category") or "user_report").strip()[:80]
    if not raw_url and not message:
        return jsonify({"error": "Submit a URL or message."}), 400

    normalized_url = None
    domain = None
    if raw_url:
        try:
            normalized_url = normalize_url(raw_url)
            domain = extract_domain(normalized_url)
        except Exception:
            normalized_url = None

    indicators = extract_indicators(message) if message else {"urls": [], "domains": [], "emails": [], "phones": []}
    if not normalized_url and indicators.get("urls"):
        normalized_url = indicators["urls"][0]
        domain = extract_domain(normalized_url)
    if not domain and indicators.get("domains"):
        domain = indicators["domains"][0]

    user = get_current_user()
    status = "pending"
    confidence = 45
    if normalized_url or indicators.get("phones") or indicators.get("emails"):
        status = "watchlist"
        confidence = 70

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scam_reports (user_id, url, normalized_url, message, category, status)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (user["id"] if user else None, raw_url or None, normalized_url, message or None, category, status),
            )
            report_row = cur.fetchone()
            report_id = report_row["id"]

            cur.execute(
                """
                INSERT INTO intelligence_events
                (user_id, report_id, url, normalized_url, domain, email, phone, message_hash, source, evidence_type, confidence_score, reason, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'user_report', 'community_report', %s, %s, %s)
                """,
                (
                    user["id"] if user else None,
                    report_id,
                    raw_url or None,
                    normalized_url,
                    domain,
                    indicators.get("emails", [None])[0] if indicators.get("emails") else None,
                    indicators.get("phones", [None])[0] if indicators.get("phones") else None,
                    message_hash(message) if message else None,
                    confidence,
                    f"User report category: {category}",
                    status,
                ),
            )

            if normalized_url:
                cur.execute(
                    """
                    INSERT INTO scam_urls
                    (url, normalized_url, verdict, source, notes, malicious, suspicious, harmless, undetected, report_count)
                    VALUES (%s, %s, 'suspicious', 'user_report', %s, 0, 3, 0, 0, 1)
                    ON CONFLICT (normalized_url) DO UPDATE SET
                        report_count = scam_urls.report_count + 1,
                        suspicious = GREATEST(scam_urls.suspicious, 3),
                        verdict = CASE
                            WHEN scam_urls.report_count + 1 >= 3 THEN 'dangerous'
                            ELSE scam_urls.verdict
                        END,
                        updated_at = NOW()
                    """,
                    (raw_url or normalized_url, normalized_url, f"Community report: {category}"),
                )
        conn.commit()

    return jsonify({"ok": True, "report_id": report_id, "status": status, "message": "Report saved into LidaShield intelligence."})


@app.route("/api/feedback", methods=["POST"])
def feedback():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "No feedback message provided."}), 400
    user = get_current_user()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO feedback_requests (user_id, request_type, email, subject, url, message)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    user["id"] if user else None,
                    (data.get("request_type") or "feedback")[:80],
                    (data.get("email") or "")[:200],
                    (data.get("subject") or "")[:200],
                    (data.get("url") or "")[:500],
                    message[:5000],
                ),
            )
            row = cur.fetchone()
        conn.commit()
    return jsonify({"ok": True, "feedback_id": row["id"]})

# ============================================================
# Dashboard
# ============================================================

@app.route("/dashboard")
def dashboard():
    if not get_current_user():
        return redirect("/")
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/dashboard")
def api_dashboard():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Login required."}), 401
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(SUM(scans_used),0) AS total FROM usage_limits WHERE user_id=%s AND scan_date=CURRENT_DATE", (user["id"],))
            today = cur.fetchone()["total"]
            cur.execute("SELECT COUNT(*) AS total FROM scan_history WHERE user_id=%s", (user["id"],))
            total_scans = cur.fetchone()["total"]
            cur.execute("SELECT COUNT(*) AS total FROM message_checks WHERE user_id=%s", (user["id"],))
            message_total = cur.fetchone()["total"]
            cur.execute("SELECT COUNT(*) AS total FROM scam_urls")
            db_total = cur.fetchone()["total"]
            cur.execute("SELECT url, verdict, source, scanned_at FROM scan_history WHERE user_id=%s ORDER BY scanned_at DESC LIMIT 8", (user["id"],))
            scans = cur.fetchall() or []
            cur.execute("SELECT message, verdict, score, created_at FROM message_checks WHERE user_id=%s ORDER BY created_at DESC LIMIT 8", (user["id"],))
            messages = cur.fetchall() or []
            cur.execute("SELECT status, COUNT(*) AS total FROM scam_reports WHERE user_id=%s GROUP BY status ORDER BY status", (user["id"],))
            reports = cur.fetchall() or []
    return jsonify({
        "user": {"email": user["email"], "name": user.get("name"), "avatar_url": user.get("avatar_url"), "plan": user.get("plan", "free")},
        "usage": {"scans_used_today": today, "scan_limit": get_plan_limit(user.get("plan", "free"))},
        "total_scans": total_scans,
        "message_checks": {"total": message_total, "recent": messages},
        "database": {"total_indicators": db_total},
        "recent_scans": scans,
        "reports": {"by_status": reports},
        "admin": {"is_admin": is_admin(user)},
    })

# ============================================================
# Stripe billing
# ============================================================

@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Please login first."}), 401
    if not STRIPE_SECRET_KEY:
        return jsonify({"error": "Stripe is not configured."}), 500
    data = request.get_json(silent=True) or {}
    plan = (data.get("plan") or "shield").lower()
    if plan not in ("shield", "pro"):
        return jsonify({"error": "Invalid plan."}), 400
    price_id = STRIPE_PRICE_SHIELD if plan == "shield" else STRIPE_PRICE_PRO
    if not price_id:
        return jsonify({"error": f"Stripe price ID for {plan} is not configured."}), 500

    customer_id = user.get("stripe_customer_id")
    if not customer_id:
        customer = stripe.Customer.create(email=user["email"], name=user.get("name") or user["email"])
        customer_id = customer.id
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET stripe_customer_id=%s WHERE id=%s", (customer_id, user["id"]))
            conn.commit()

    checkout = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{APP_URL}/dashboard?checkout=success",
        cancel_url=f"{APP_URL}/?checkout=cancelled",
        metadata={"user_id": str(user["id"]), "plan": plan},
    )
    return jsonify({"url": checkout.url})


@app.route("/billing/portal", methods=["POST"])
def billing_portal():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Please login first."}), 401
    customer_id = user.get("stripe_customer_id")
    if not STRIPE_SECRET_KEY or not customer_id:
        return jsonify({"error": "Billing portal is not available yet."}), 400
    portal = stripe.billing_portal.Session.create(customer=customer_id, return_url=f"{APP_URL}/dashboard")
    return jsonify({"url": portal.url})


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET) if STRIPE_WEBHOOK_SECRET else json.loads(payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    event_type = event.get("type")
    obj = event.get("data", {}).get("object", {})
    if event_type == "checkout.session.completed":
        user_id = obj.get("metadata", {}).get("user_id")
        plan = obj.get("metadata", {}).get("plan", "shield")
        subscription_id = obj.get("subscription")
        customer_id = obj.get("customer")
        if user_id:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET plan=%s, stripe_customer_id=%s, stripe_subscription_id=%s WHERE id=%s",
                        (plan, customer_id, subscription_id, int(user_id)),
                    )
                conn.commit()
    elif event_type in ("customer.subscription.deleted", "customer.subscription.paused"):
        customer_id = obj.get("customer")
        if customer_id:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET plan='free' WHERE stripe_customer_id=%s", (customer_id,))
                conn.commit()
    return jsonify({"received": True})

# ============================================================
# Admin intelligence console
# ============================================================

def admin_required():
    user = get_current_user()
    if not user:
        return None, (redirect("/login"), 302)
    if not is_admin(user):
        return user, ("Admin access required.", 403)
    return user, None


@app.route("/admin/reports")
def admin_reports():
    user, error = admin_required()
    if error:
        return error
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scam_reports ORDER BY created_at DESC LIMIT 100")
            reports = cur.fetchall() or []
    rows = "".join(
        f"<tr><td>{r['id']}</td><td>{html.escape(str(r.get('url') or ''))}</td><td>{html.escape(str(r.get('category') or ''))}</td><td>{html.escape(str(r.get('status') or ''))}</td><td>{html.escape(str(r.get('created_at') or ''))}</td></tr>"
        for r in reports
    )
    return render_template_string(ADMIN_TABLE_HTML, title="User Reports", rows=rows, headers="<th>ID</th><th>URL</th><th>Category</th><th>Status</th><th>Created</th>")


@app.route("/admin/database-stats")
def admin_database_stats():
    user, error = admin_required()
    if error:
        return error
    with get_db() as conn:
        with conn.cursor() as cur:
            stats = {}
            for table in ["users", "scam_urls", "scan_history", "scam_reports", "message_checks", "intelligence_events", "feedback_requests", "analyst_observations"]:
                cur.execute(f"SELECT COUNT(*) AS total FROM {table}")
                stats[table] = cur.fetchone()["total"]
    body = "".join(f"<p><b>{html.escape(k)}</b>: {v}</p>" for k, v in stats.items())
    return render_template_string(SIMPLE_PAGE, title="Database Stats", body=body)


@app.route("/admin/intelligence")
def admin_intelligence():
    user, error = admin_required()
    if error:
        return error
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM intelligence_events ORDER BY created_at DESC LIMIT 100")
            events = cur.fetchall() or []
    rows = "".join(
        f"<tr><td>{e['id']}</td><td>{html.escape(str(e.get('domain') or ''))}</td><td>{html.escape(str(e.get('normalized_url') or ''))}</td><td>{e.get('confidence_score') or 0}</td><td>{html.escape(str(e.get('status') or ''))}</td></tr>"
        for e in events
    )
    return render_template_string(ADMIN_TABLE_HTML, title="Intelligence Graph", rows=rows, headers="<th>ID</th><th>Domain</th><th>URL</th><th>Confidence</th><th>Status</th>")


@app.route("/admin/export/scam-urls.csv")
def admin_export_scam_urls():
    user, error = admin_required()
    if error:
        return error
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "url", "normalized_url", "verdict", "source", "malicious", "suspicious", "report_count", "updated_at"])
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, url, normalized_url, verdict, source, malicious, suspicious, report_count, updated_at FROM scam_urls ORDER BY updated_at DESC")
            for row in cur.fetchall() or []:
                writer.writerow([row.get(k) for k in ["id", "url", "normalized_url", "verdict", "source", "malicious", "suspicious", "report_count", "updated_at"]])
    return app.response_class(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=scam-urls.csv"})

# ============================================================
# Small templates
# ============================================================

SIMPLE_PAGE = """
<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{{ title }} — LidaShield</title>
<style>body{font-family:Inter,Arial,sans-serif;background:#03030a;color:#f4efe6;line-height:1.7;padding:40px;max-width:900px;margin:auto}a{color:#ffd27a}.card{border:1px solid rgba(240,168,48,.25);border-radius:20px;padding:26px;background:rgba(255,255,255,.05)}</style></head>
<body><p><a href='/'>← Back to LidaShield</a></p><div class='card'><h1>{{ title }}</h1><p>{{ body|safe }}</p></div></body></html>
"""

DASHBOARD_HTML = """
<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>LidaShield Dashboard</title>
<style>body{font-family:Inter,Arial,sans-serif;background:#03030a;color:#f4efe6;padding:34px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}.card{border:1px solid rgba(240,168,48,.22);border-radius:22px;padding:22px;background:rgba(255,255,255,.05)}a,button{color:#080805;background:#ffd27a;border:0;border-radius:12px;padding:10px 14px;text-decoration:none;font-weight:700}small{color:#8c8376}.item{border-top:1px solid rgba(255,255,255,.08);padding:10px 0;color:#ccc}</style></head>
<body><p><a href='/'>Scanner</a> <a href='/logout'>Logout</a></p><h1>LidaShield Dashboard</h1><div id='root'>Loading...</div>
<script>
function e(s){return String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
fetch('/api/dashboard').then(r=>r.json()).then(d=>{
 if(d.error){root.innerHTML='<p>'+e(d.error)+'</p>';return}
 const scans=(d.recent_scans||[]).map(x=>`<div class='item'>${e(x.url)} <b>${e(x.verdict)}</b></div>`).join('')||'<div class=item>No scans yet</div>';
 const msgs=(d.message_checks.recent||[]).map(x=>`<div class='item'>${e((x.message||'').slice(0,90))} <b>${e(x.verdict)} ${x.score||0}</b></div>`).join('')||'<div class=item>No message checks yet</div>';
 root.innerHTML=`<p>${e(d.user.email)} · ${e(d.user.plan)}</p><div class=grid><div class=card><h2>${d.usage.scans_used_today}</h2><small>Scans today</small></div><div class=card><h2>${d.usage.scan_limit}</h2><small>Daily limit</small></div><div class=card><h2>${d.total_scans}</h2><small>Total scans</small></div><div class=card><h2>${d.message_checks.total}</h2><small>Message checks</small></div><div class=card><h2>${d.database.total_indicators}</h2><small>Database indicators</small></div></div><div class=grid style='margin-top:18px'><div class=card><h2>Recent scans</h2>${scans}</div><div class=card><h2>Recent message checks</h2>${msgs}</div></div>`
})
</script></body></html>
"""

ADMIN_TABLE_HTML = """
<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{{ title }} — LidaShield</title>
<style>body{font-family:Inter,Arial,sans-serif;background:#03030a;color:#f4efe6;padding:34px}a{color:#ffd27a}table{width:100%;border-collapse:collapse;background:rgba(255,255,255,.04)}th,td{border:1px solid rgba(240,168,48,.18);padding:10px;text-align:left;font-size:13px}th{color:#ffd27a}</style></head>
<body><p><a href='/dashboard'>Dashboard</a> · <a href='/admin/database-stats'>Stats</a> · <a href='/admin/intelligence'>Intelligence</a></p><h1>{{ title }}</h1><table><thead><tr>{{ headers|safe }}</tr></thead><tbody>{{ rows|safe }}</tbody></table></body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
