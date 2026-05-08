# =============================================================================
# LidaShield v2.0 — Own Threat Intelligence Engine
# PART 1 / 50
# Core imports, Flask setup, configuration, database foundation, and base helpers.
# =============================================================================
#
# Build rule:
# - This app.py is meant to be compiled part by part.
# - Part 1 starts the file.
# - Part 2 onward will be pasted BELOW this file, in order.
# - Do not paste old app.py code above this.
#
# External scanners removed:
# - No Google Safe Browsing
# - No VirusTotal
# - No PhishTank
# - No URLScan
#
# LidaShield is now database-first:
# - verified threats
# - reports
# - scan history
# - domain intelligence
# - phone intelligence
# - message intelligence
# - email intelligence
# - business audit requests
# - admin verification
#
# =============================================================================


# =============================================================================
# Standard Library Imports
# =============================================================================

import os
import re
import json
import math
import time
import sqlite3
import hashlib
import secrets
import string
from datetime import date, datetime
from collections import defaultdict, Counter
from urllib.parse import urlparse, unquote


# =============================================================================
# Third-Party Imports
# =============================================================================

from flask import Flask, request, jsonify


# =============================================================================
# Flask App Setup
# =============================================================================

app = Flask(__name__)


# =============================================================================
# Global Configuration
# =============================================================================

APP_NAME = "LidaShield"
APP_VERSION = "2.0-part-1"
ENGINE_NAME = "LidaShield Own Threat Intelligence Engine"

DATABASE_FILE = os.environ.get("DATABASE_FILE", "lidashield.db")

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-this-admin-token")

DEFAULT_PLAN = "free"

FREE_DAILY_SCAN_LIMIT = 10
PLUS_DAILY_SCAN_LIMIT = 300
PRO_DAILY_SCAN_LIMIT = 5000

MAX_URL_LENGTH = 2000
MAX_REPORT_DESCRIPTION_LENGTH = 1000
MAX_MESSAGE_LENGTH = 5000
MAX_EMAIL_BODY_LENGTH = 10000

REGION_DEFAULT = "Singapore/SEA"

scan_counts = defaultdict(lambda: {
    "count": 0,
    "date": str(date.today())
})


# =============================================================================
# Base Time Helpers
# =============================================================================

def now_utc():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def today_string():
    return str(date.today())


def unix_time():
    return int(time.time())


# =============================================================================
# Base JSON Helpers
# =============================================================================

def safe_json(value):
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "[]"


def parse_json(value, fallback=None):
    if fallback is None:
        fallback = []

    try:
        return json.loads(value or "")
    except Exception:
        return fallback


def jsonify_success(data=None):
    if data is None:
        data = {}

    payload = {
        "success": True
    }

    payload.update(data)

    return jsonify(payload)


def jsonify_error(message, status_code=400, extra=None):
    if extra is None:
        extra = {}

    payload = {
        "success": False,
        "error": message
    }

    payload.update(extra)

    return jsonify(payload), status_code


# =============================================================================
# Base Hash / Token Helpers
# =============================================================================

def hash_text(value):
    if value is None:
        value = ""

    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def short_hash(value, length=12):
    return hash_text(value)[:length]


def generate_token(length=32):
    alphabet = string.ascii_letters + string.digits

    return "".join(secrets.choice(alphabet) for _ in range(length))


# =============================================================================
# Base Numeric Helpers
# =============================================================================

def clamp(value, minimum, maximum):
    return max(minimum, min(maximum, value))


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


# =============================================================================
# Request Helpers
# =============================================================================

def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


def get_request_json():
    return request.get_json(silent=True) or {}


def get_admin_token_from_request():
    return (
        request.headers.get("X-Admin-Token")
        or request.args.get("token")
        or ""
    )


def require_admin():
    return get_admin_token_from_request() == ADMIN_TOKEN


# =============================================================================
# Rate Limit Helpers
# =============================================================================

def get_plan_limit(plan):
    plan = (plan or DEFAULT_PLAN).lower().strip()

    if plan == "pro":
        return PRO_DAILY_SCAN_LIMIT

    if plan == "plus":
        return PLUS_DAILY_SCAN_LIMIT

    return FREE_DAILY_SCAN_LIMIT


def check_rate_limit(ip, plan=DEFAULT_PLAN):
    today = today_string()
    limit = get_plan_limit(plan)

    if scan_counts[ip]["date"] != today:
        scan_counts[ip] = {
            "count": 0,
            "date": today
        }

    if scan_counts[ip]["count"] >= limit:
        return False, limit

    scan_counts[ip]["count"] += 1

    return True, limit


def scans_remaining(ip, plan=DEFAULT_PLAN):
    today = today_string()
    limit = get_plan_limit(plan)

    if scan_counts[ip]["date"] != today:
        return limit

    return max(0, limit - scan_counts[ip]["count"])


# =============================================================================
# Database Connection Helpers
# =============================================================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return [row["name"] for row in cursor.fetchall()]


def add_column_if_missing(cursor, table_name, column_name, column_sql):
    columns = table_columns(cursor, table_name)

    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


# =============================================================================
# Database Initialization
# =============================================================================

def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    # -------------------------------------------------------------------------
    # users
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            plan TEXT NOT NULL DEFAULT 'free',
            created_at TEXT NOT NULL
        )
    """)

    # -------------------------------------------------------------------------
    # scan_history
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL DEFAULT 'url',
            input_value TEXT NOT NULL,
            normalized_value TEXT,
            domain TEXT,
            verdict TEXT NOT NULL,
            verdict_class TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            confidence INTEGER DEFAULT 0,
            message TEXT,
            sources_checked TEXT,
            danger_signals TEXT,
            warning_signals TEXT,
            info_signals TEXT,
            feature_snapshot TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # -------------------------------------------------------------------------
    # scam_reports
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            domain TEXT,
            category TEXT,
            description TEXT,
            reporter_ip TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            reviewed_at TEXT
        )
    """)

    # -------------------------------------------------------------------------
    # verified_threats
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verified_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            normalized_value TEXT NOT NULL UNIQUE,
            domain TEXT,
            category TEXT,
            region TEXT DEFAULT 'Singapore/SEA',
            source TEXT DEFAULT 'lidashield_admin',
            confidence INTEGER DEFAULT 100,
            notes TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # -------------------------------------------------------------------------
    # domain_intel
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'unknown',
            category TEXT,
            region TEXT DEFAULT 'Singapore/SEA',
            report_count INTEGER DEFAULT 0,
            verified_threat_count INTEGER DEFAULT 0,
            scan_count INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            notes TEXT
        )
    """)

    # -------------------------------------------------------------------------
    # phone_reports
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS phone_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            normalized_phone TEXT NOT NULL,
            category TEXT,
            description TEXT,
            reporter_ip TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            reviewed_at TEXT
        )
    """)

    # -------------------------------------------------------------------------
    # message_reports
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_text TEXT NOT NULL,
            message_hash TEXT NOT NULL,
            extracted_urls TEXT,
            extracted_phone_numbers TEXT,
            category TEXT,
            reporter_ip TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            reviewed_at TEXT
        )
    """)

    # -------------------------------------------------------------------------
    # email_reports
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT,
            sender_domain TEXT,
            subject TEXT,
            body_hash TEXT,
            extracted_urls TEXT,
            category TEXT,
            reporter_ip TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            reviewed_at TEXT
        )
    """)

    # -------------------------------------------------------------------------
    # business_audit_requests
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS business_audit_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_name TEXT NOT NULL,
            website TEXT NOT NULL,
            normalized_url TEXT,
            domain TEXT,
            email TEXT NOT NULL,
            industry TEXT,
            concerns TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            created_at TEXT NOT NULL
        )
    """)

    # -------------------------------------------------------------------------
    # intelligence_events
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intelligence_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            indicator_type TEXT,
            indicator_value TEXT,
            normalized_value TEXT,
            domain TEXT,
            category TEXT,
            source TEXT,
            confidence INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            raw_data TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # -------------------------------------------------------------------------
    # api_keys
    # -------------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_email TEXT NOT NULL,
            api_key_hash TEXT NOT NULL UNIQUE,
            plan TEXT NOT NULL DEFAULT 'free',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    # -------------------------------------------------------------------------
    # compatibility migrations
    # -------------------------------------------------------------------------
    add_column_if_missing(cursor, "scam_reports", "domain", "domain TEXT")
    add_column_if_missing(cursor, "scam_reports", "status", "status TEXT NOT NULL DEFAULT 'pending'")
    add_column_if_missing(cursor, "scam_reports", "reviewed_at", "reviewed_at TEXT")

    add_column_if_missing(cursor, "scan_history", "risk_score", "risk_score INTEGER DEFAULT 0")
    add_column_if_missing(cursor, "scan_history", "confidence", "confidence INTEGER DEFAULT 0")
    add_column_if_missing(cursor, "scan_history", "info_signals", "info_signals TEXT")
    add_column_if_missing(cursor, "scan_history", "feature_snapshot", "feature_snapshot TEXT")

    add_column_if_missing(cursor, "domain_intel", "risk_score", "risk_score INTEGER DEFAULT 0")

    # -------------------------------------------------------------------------
    # indexes
    # -------------------------------------------------------------------------
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_type ON scan_history(scan_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_normalized ON scan_history(normalized_value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_domain ON scan_history(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON scam_reports(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_normalized ON scam_reports(normalized_url)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_domain ON scam_reports(domain)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_type ON verified_threats(indicator_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_normalized ON verified_threats(normalized_value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_domain ON verified_threats(domain)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_intel_domain ON domain_intel(domain)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_phone_reports_number ON phone_reports(normalized_phone)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_phone_reports_status ON phone_reports(status)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_message_hash ON message_reports(message_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_message_status ON message_reports(status)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_sender_domain ON email_reports(sender_domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_status ON email_reports(status)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON intelligence_events(event_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_normalized ON intelligence_events(normalized_value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON intelligence_events(status)")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_key_hash ON api_keys(api_key_hash)")

    conn.commit()
    conn.close()


init_database()


# =============================================================================
# URL / Domain Normalization
# =============================================================================

def validate_url(raw):
    if not raw:
        return None, "Please enter a URL."

    raw = str(raw).strip()

    if len(raw) > MAX_URL_LENGTH:
        return None, "URL is too long."

    if " " in raw:
        return None, "URL should not contain spaces."

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if not parsed.netloc:
        return None, "That does not look like a valid website URL."

    if "." not in parsed.netloc:
        return None, "That does not look like a valid domain."

    return raw, None


def normalize_domain(domain):
    domain = str(domain or "").strip().lower()

    if domain.startswith("http://") or domain.startswith("https://"):
        domain = get_domain(domain)

    if "@" in domain:
        domain = domain.split("@")[-1]

    if ":" in domain:
        domain = domain.split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    domain = domain.strip(".")

    return domain


def get_domain(url):
    try:
        url = str(url or "").strip()

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)

        return normalize_domain(parsed.netloc)
    except Exception:
        return ""


def normalize_url(raw_url):
    if not raw_url:
        return ""

    raw_url = str(raw_url).strip()

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    scheme = parsed.scheme.lower()
    domain = normalize_domain(parsed.netloc)
    path = parsed.path.rstrip("/")

    return f"{scheme}://{domain}{path}"


def split_domain_parts(domain):
    domain = normalize_domain(domain)

    if not domain:
        return []

    return [part for part in domain.split(".") if part]


def get_tld(domain):
    parts = split_domain_parts(domain)

    if not parts:
        return ""

    return parts[-1]


def get_sld(domain):
    parts = split_domain_parts(domain)

    if len(parts) < 2:
        return ""

    return parts[-2]


def is_ip_address(domain):
    domain = normalize_domain(domain)

    if not domain:
        return False

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if not re.match(pattern, domain):
        return False

    try:
        parts = [int(part) for part in domain.split(".")]
        return all(0 <= part <= 255 for part in parts)
    except Exception:
        return False


def shannon_entropy(text):
    text = str(text or "")

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


# =============================================================================
# Phone / Text Extraction Helpers
# =============================================================================

def normalize_phone(phone):
    phone = str(phone or "").strip()

    keep_plus = phone.startswith("+")
    digits = re.sub(r"\D", "", phone)

    if keep_plus:
        return "+" + digits

    return digits


def extract_urls_from_text(text):
    text = str(text or "")

    pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)"

    matches = re.findall(pattern, text)

    cleaned = []

    for item in matches:
        item = item.strip(".,;:!?()[]{}<>\"'")

        if "." in item and item not in cleaned:
            cleaned.append(item)

    return cleaned


def extract_phone_numbers_from_text(text):
    text = str(text or "")

    pattern = r"(?:\+?\d[\d\s().-]{6,}\d)"

    matches = re.findall(pattern, text)

    cleaned = []

    for item in matches:
        normalized = normalize_phone(item)

        if len(normalized.replace("+", "")) >= 7 and normalized not in cleaned:
            cleaned.append(normalized)

    return cleaned


def extract_sender_domain(sender_email):
    sender_email = str(sender_email or "").strip().lower()

    if "@" not in sender_email:
        return ""

    return normalize_domain(sender_email.split("@")[-1])


# =============================================================================
# Indicator Normalization
# =============================================================================

def normalize_indicator(indicator_type, value):
    indicator_type = str(indicator_type or "").lower().strip()

    if indicator_type == "url":
        return normalize_url(value)

    if indicator_type == "domain":
        return normalize_domain(value)

    if indicator_type == "phone":
        return normalize_phone(value)

    if indicator_type == "message":
        return hash_text(value)

    if indicator_type == "email":
        return str(value or "").strip().lower()

    return str(value or "").strip().lower()


# =============================================================================
# Database Query Helpers
# =============================================================================

def find_verified_threat(indicator_type, value):
    normalized = normalize_indicator(indicator_type, value)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM verified_threats
        WHERE indicator_type = ?
        AND normalized_value = ?
        LIMIT 1
    """, (
        indicator_type,
        normalized
    ))

    row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    return dict(row)


def find_url_or_domain_threat(url):
    normalized_url = normalize_url(url)
    domain = get_domain(url)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM verified_threats
        WHERE normalized_value = ?
        OR normalized_value = ?
        OR domain = ?
        ORDER BY confidence DESC
        LIMIT 1
    """, (
        normalized_url,
        domain,
        domain
    ))

    row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    return dict(row)


def count_pending_url_reports(url):
    normalized_url = normalize_url(url)
    domain = get_domain(url)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) AS count
        FROM scam_reports
        WHERE status = 'pending'
        AND (
            normalized_url = ?
            OR domain = ?
        )
    """, (
        normalized_url,
        domain
    ))

    row = cursor.fetchone()

    conn.close()

    return row["count"] if row else 0


def count_verified_url_reports(url):
    normalized_url = normalize_url(url)
    domain = get_domain(url)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) AS count
        FROM scam_reports
        WHERE status = 'verified'
        AND (
            normalized_url = ?
            OR domain = ?
        )
    """, (
        normalized_url,
        domain
    ))

    row = cursor.fetchone()

    conn.close()

    return row["count"] if row else 0


# =============================================================================
# Database Write Helpers
# =============================================================================

def save_scan(
    scan_type,
    input_value,
    normalized_value,
    domain,
    verdict,
    verdict_class,
    risk_score,
    confidence,
    message,
    sources_checked,
    danger_signals,
    warning_signals,
    info_signals,
    feature_snapshot,
    ip
):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (
            scan_type,
            input_value,
            normalized_value,
            domain,
            verdict,
            verdict_class,
            risk_score,
            confidence,
            message,
            sources_checked,
            danger_signals,
            warning_signals,
            info_signals,
            feature_snapshot,
            ip_address,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_type,
        input_value,
        normalized_value,
        domain,
        verdict,
        verdict_class,
        risk_score,
        confidence,
        message,
        safe_json(sources_checked),
        safe_json(danger_signals),
        safe_json(warning_signals),
        safe_json(info_signals),
        safe_json(feature_snapshot),
        ip,
        now_utc()
    ))

    conn.commit()
    conn.close()


def upsert_domain_intel(
    domain,
    category=None,
    verified=False,
    scanned=False,
    risk_score=None,
    notes=None
):
    domain = normalize_domain(domain)

    if not domain:
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM domain_intel WHERE domain = ?", (domain,))

    existing = cursor.fetchone()
    current_time = now_utc()

    if existing:
        report_count = existing["report_count"] or 0
        verified_count = existing["verified_threat_count"] or 0
        scan_count = existing["scan_count"] or 0
        existing_risk = existing["risk_score"] or 0

        if verified:
            verified_count += 1
            status = "verified_threat"
        else:
            status = existing["status"] or "unknown"

        if scanned:
            scan_count += 1

        final_risk = existing_risk

        if risk_score is not None:
            final_risk = max(existing_risk, safe_int(risk_score, 0))

        cursor.execute("""
            UPDATE domain_intel
            SET status = ?,
                category = COALESCE(?, category),
                report_count = ?,
                verified_threat_count = ?,
                scan_count = ?,
                risk_score = ?,
                last_seen = ?,
                notes = COALESCE(?, notes)
            WHERE domain = ?
        """, (
            status,
            category,
            report_count,
            verified_count,
            scan_count,
            final_risk,
            current_time,
            notes,
            domain
        ))

    else:
        cursor.execute("""
            INSERT INTO domain_intel (
                domain,
                status,
                category,
                region,
                report_count,
                verified_threat_count,
                scan_count,
                risk_score,
                first_seen,
                last_seen,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            "verified_threat" if verified else "unknown",
            category,
            REGION_DEFAULT,
            0,
            1 if verified else 0,
            1 if scanned else 0,
            safe_int(risk_score, 0),
            current_time,
            current_time,
            notes
        ))

    conn.commit()
    conn.close()


def add_intelligence_event(
    event_type,
    indicator_type=None,
    indicator_value=None,
    normalized_value=None,
    domain=None,
    category=None,
    source=None,
    confidence=0,
    status="pending",
    raw_data=None
):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO intelligence_events (
            event_type,
            indicator_type,
            indicator_value,
            normalized_value,
            domain,
            category,
            source,
            confidence,
            status,
            raw_data,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        indicator_type,
        indicator_value,
        normalized_value,
        domain,
        category,
        source,
        safe_int(confidence, 0),
        status,
        safe_json(raw_data or {}),
        now_utc()
    ))

    conn.commit()
    conn.close()


# =============================================================================
# PART 1 END
# =============================================================================
# Next:
# PART 2 will be pasted BELOW this section.
# It will add:
# - advanced URL feature extraction
# - risk scoring engine
# - brand and scam signal lists
# - URL verdict builder foundation
# =============================================================================
# =============================================================================
# LidaShield v2.0 — Own Threat Intelligence Engine
# PART 2 / 50
# Advanced URL feature extraction, known signal lists, and URL risk scoring.
# =============================================================================


# =============================================================================
# High-Risk TLD Intelligence
# =============================================================================

HIGH_RISK_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "xyz",
    "quest",
    "cfd",
    "icu",
    "cyou",
    "cam",
    "monster",
    "buzz",
    "live",
    "shop",
    "store",
    "skin",
    "loan",
    "gq",
    "tk",
    "ml",
    "cf",
    "work",
    "rest",
    "fit",
    "mom",
    "surf",
    "space",
    "site",
    "online",
    "fun",
    "win",
    "bid",
    "men",
    "date",
    "review",
    "stream",
    "download",
    "country",
    "kim",
    "party",
    "trade",
    "racing",
    "accountants",
    "science"
}


# =============================================================================
# URL Shortener Intelligence
# =============================================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "s.id",
    "rb.gy",
    "lnkd.in",
    "bitly.com",
    "trib.al",
    "soo.gd",
    "tiny.cc",
    "clck.ru",
    "bc.vc",
    "adf.ly",
    "shorte.st",
    "qrco.de",
    "lnk.bio",
    "taplink.cc"
}


# =============================================================================
# Singapore / SEA Brand Intelligence
# =============================================================================

SENSITIVE_SG_BRANDS = {
    "dbs": [
        "dbs.com.sg"
    ],
    "posb": [
        "posb.com.sg",
        "dbs.com.sg"
    ],
    "ocbc": [
        "ocbc.com",
        "ocbc.com.sg"
    ],
    "uob": [
        "uob.com.sg"
    ],
    "singpass": [
        "singpass.gov.sg"
    ],
    "cpf": [
        "cpf.gov.sg"
    ],
    "iras": [
        "iras.gov.sg"
    ],
    "hdb": [
        "hdb.gov.sg"
    ],
    "mom": [
        "mom.gov.sg"
    ],
    "ica": [
        "ica.gov.sg"
    ],
    "moh": [
        "moh.gov.sg"
    ],
    "mfa": [
        "mfa.gov.sg"
    ],
    "gov": [
        "gov.sg"
    ],
    "shopee": [
        "shopee.sg",
        "shopee.com"
    ],
    "lazada": [
        "lazada.sg",
        "lazada.com"
    ],
    "grab": [
        "grab.com"
    ],
    "singtel": [
        "singtel.com"
    ],
    "starhub": [
        "starhub.com"
    ],
    "m1": [
        "m1.com.sg"
    ],
    "ninjavan": [
        "ninjavan.co"
    ],
    "jnt": [
        "jtexpress.sg"
    ],
    "dhl": [
        "dhl.com"
    ],
    "fedex": [
        "fedex.com"
    ],
    "paypal": [
        "paypal.com"
    ],
    "binance": [
        "binance.com"
    ],
    "coinbase": [
        "coinbase.com"
    ],
    "crypto": [],
    "telegram": [
        "telegram.org"
    ],
    "whatsapp": [
        "whatsapp.com"
    ],
    "facebook": [
        "facebook.com"
    ],
    "instagram": [
        "instagram.com"
    ],
    "google": [
        "google.com"
    ],
    "microsoft": [
        "microsoft.com"
    ],
    "apple": [
        "apple.com"
    ],
    "netflix": [
        "netflix.com"
    ],
    "amazon": [
        "amazon.com"
    ]
}


# =============================================================================
# Scam Context Word Intelligence
# =============================================================================

SCAM_CONTEXT_WORDS = {
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "password",
    "wallet",
    "reward",
    "bonus",
    "free",
    "gift",
    "claim",
    "urgent",
    "limited",
    "prize",
    "winner",
    "airdrop",
    "bank",
    "payment",
    "delivery",
    "parcel",
    "refund",
    "tax",
    "invoice",
    "loan",
    "job",
    "investment",
    "crypto",
    "whatsapp",
    "telegram",
    "otp",
    "unlock",
    "locked",
    "suspended",
    "restricted",
    "appeal",
    "support",
    "service",
    "customer",
    "helpdesk",
    "notice",
    "alert",
    "authenticate",
    "authentication",
    "reactivate",
    "redeem",
    "voucher",
    "cashback",
    "subsidy",
    "grant",
    "payout",
    "compensation",
    "fine",
    "penalty",
    "summon",
    "customs",
    "shipping",
    "tracking",
    "deposit",
    "withdraw",
    "transfer",
    "recover",
    "recovery"
}


# =============================================================================
# Suspicious File Extension Intelligence
# =============================================================================

SUSPICIOUS_FILE_EXTENSIONS = {
    ".apk",
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".msi",
    ".jar",
    ".ps1",
    ".iso",
    ".dmg",
    ".com",
    ".pif",
    ".hta",
    ".lnk",
    ".wsf",
    ".docm",
    ".xlsm",
    ".pptm"
}


# =============================================================================
# Suspicious URL Parameter Names
# =============================================================================

SUSPICIOUS_QUERY_KEYS = {
    "token",
    "auth",
    "session",
    "password",
    "pass",
    "otp",
    "code",
    "verify",
    "redirect",
    "url",
    "next",
    "return",
    "returnurl",
    "continue",
    "callback",
    "login",
    "account",
    "wallet",
    "payment"
}


# =============================================================================
# Official Domain Helpers
# =============================================================================

def domain_matches_official(domain, official_domain):
    domain = normalize_domain(domain)
    official_domain = normalize_domain(official_domain)

    if not domain or not official_domain:
        return False

    if domain == official_domain:
        return True

    if domain.endswith("." + official_domain):
        return True

    return False


def is_official_brand_domain(domain, brand):
    domain = normalize_domain(domain)
    brand = str(brand or "").lower().strip()

    official_domains = SENSITIVE_SG_BRANDS.get(brand, [])

    if not official_domains:
        return False

    for official_domain in official_domains:
        if domain_matches_official(domain, official_domain):
            return True

    return False


def detect_brand_mentions(domain, decoded_url):
    domain = normalize_domain(domain)
    decoded_url = str(decoded_url or "").lower()

    mentions = []
    impersonation_candidates = []

    for brand, official_domains in SENSITIVE_SG_BRANDS.items():
        brand_seen = False

        if brand in domain:
            brand_seen = True

        if brand in decoded_url:
            brand_seen = True

        if not brand_seen:
            continue

        mentions.append(brand)

        if not is_official_brand_domain(domain, brand):
            impersonation_candidates.append({
                "brand": brand,
                "official_domains": official_domains,
                "seen_domain": domain
            })

    return {
        "brand_mentions": sorted(set(mentions)),
        "brand_impersonation_candidates": impersonation_candidates
    }


# =============================================================================
# Query String Analysis
# =============================================================================

def parse_query_pairs(query):
    if not query:
        return []

    pairs = []

    for chunk in query.split("&"):
        if not chunk:
            continue

        if "=" in chunk:
            key, value = chunk.split("=", 1)
        else:
            key, value = chunk, ""

        pairs.append({
            "key": key.lower().strip(),
            "value": value.strip()
        })

    return pairs


def analyze_query_string(query):
    pairs = parse_query_pairs(query)

    suspicious_keys_found = []
    redirect_like_values = []
    long_values = []

    for pair in pairs:
        key = pair["key"]
        value = pair["value"]

        if key in SUSPICIOUS_QUERY_KEYS:
            suspicious_keys_found.append(key)

        lowered_value = value.lower()

        if "http://" in lowered_value or "https://" in lowered_value:
            redirect_like_values.append({
                "key": key,
                "value_preview": value[:120]
            })

        if len(value) >= 80:
            long_values.append({
                "key": key,
                "length": len(value)
            })

    return {
        "query_pair_count": len(pairs),
        "suspicious_query_keys": sorted(set(suspicious_keys_found)),
        "redirect_like_values": redirect_like_values,
        "long_query_values": long_values
    }


# =============================================================================
# Path Analysis
# =============================================================================

def analyze_path(path):
    path = str(path or "")

    lowered_path = path.lower()

    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    suspicious_extension = ""

    for extension in SUSPICIOUS_FILE_EXTENSIONS:
        if lowered_path.endswith(extension):
            suspicious_extension = extension
            break

    repeated_segment_count = 0

    if path_segments:
        counts = Counter(path_segments)

        for count in counts.values():
            if count >= 2:
                repeated_segment_count += 1

    return {
        "path_segment_count": len(path_segments),
        "path_segments": path_segments[:20],
        "suspicious_file_extension": suspicious_extension,
        "looks_like_file_download": bool(suspicious_extension),
        "repeated_segment_count": repeated_segment_count
    }


# =============================================================================
# Character Pattern Analysis
# =============================================================================

def analyze_character_patterns(url, domain):
    url = str(url or "")
    domain = normalize_domain(domain)

    letters_domain = sum(1 for char in domain if char.isalpha())
    digits_domain = sum(1 for char in domain if char.isdigit())
    hyphens_domain = domain.count("-")
    dots_domain = domain.count(".")

    digits_url = sum(1 for char in url if char.isdigit())
    special_url = sum(1 for char in url if not char.isalnum())

    domain_length = len(domain)
    url_length = len(url)

    digit_ratio_domain = 0.0

    if domain_length:
        digit_ratio_domain = round(digits_domain / domain_length, 3)

    digit_ratio_url = 0.0

    if url_length:
        digit_ratio_url = round(digits_url / url_length, 3)

    return {
        "letters_domain": letters_domain,
        "digits_domain": digits_domain,
        "hyphens_domain": hyphens_domain,
        "dots_domain": dots_domain,
        "digits_url": digits_url,
        "special_url": special_url,
        "domain_length": domain_length,
        "url_length": url_length,
        "digit_ratio_domain": digit_ratio_domain,
        "digit_ratio_url": digit_ratio_url,
        "entropy_domain": shannon_entropy(domain),
        "entropy_url": shannon_entropy(url)
    }


# =============================================================================
# Scam Context Analysis
# =============================================================================

def analyze_scam_context(decoded_url):
    decoded_url = str(decoded_url or "").lower()

    found_words = []

    for word in SCAM_CONTEXT_WORDS:
        if word in decoded_url:
            found_words.append(word)

    return {
        "scam_context_words": sorted(set(found_words)),
        "scam_context_word_count": len(set(found_words))
    }


# =============================================================================
# Advanced URL Feature Extraction
# =============================================================================

def extract_url_features(url):
    normalized_url = normalize_url(url)
    domain = get_domain(url)

    parsed = urlparse(
        url if str(url).startswith(("http://", "https://")) else "https://" + str(url)
    )

    decoded_url = unquote(str(url or ""))
    decoded_lower = decoded_url.lower()

    domain_parts = split_domain_parts(domain)
    tld = get_tld(domain)
    sld = get_sld(domain)

    path = parsed.path or ""
    query = parsed.query or ""

    path_analysis = analyze_path(path)
    query_analysis = analyze_query_string(query)
    char_analysis = analyze_character_patterns(url, domain)
    scam_context = analyze_scam_context(decoded_lower)
    brand_analysis = detect_brand_mentions(domain, decoded_lower)

    features = {
        "normalized_url": normalized_url,
        "domain": domain,
        "scheme": parsed.scheme.lower(),
        "path": path,
        "query": query,
        "tld": tld,
        "sld": sld,
        "domain_parts": domain_parts,
        "subdomain_count": max(0, len(domain_parts) - 2),
        "is_ip_address": is_ip_address(domain),
        "uses_http": parsed.scheme.lower() == "http",
        "uses_https": parsed.scheme.lower() == "https",
        "has_at_symbol": "@" in str(url),
        "has_encoded_chars": "%" in str(url),
        "has_punycode": "xn--" in domain,
        "has_many_subdomains": len(domain_parts) >= 4,
        "is_url_shortener": domain in URL_SHORTENERS,
        "high_risk_tld": tld in HIGH_RISK_TLDS,
        "decoded_url": decoded_url,
    }

    features.update(path_analysis)
    features.update(query_analysis)
    features.update(char_analysis)
    features.update(scam_context)
    features.update(brand_analysis)

    return features


# =============================================================================
# Signal Container Helpers
# =============================================================================

def make_signal(code, severity, message, points=0, meta=None):
    if meta is None:
        meta = {}

    return {
        "code": code,
        "severity": severity,
        "message": message,
        "points": points,
        "meta": meta
    }


def signals_to_messages(signals):
    return [
        signal.get("message", "")
        for signal in signals
        if signal.get("message")
    ]


def sum_signal_points(signals):
    total = 0

    for signal in signals:
        total += safe_int(signal.get("points", 0), 0)

    return total


# =============================================================================
# URL Risk Scoring Engine — Part 2
# =============================================================================

def score_url_features(features):
    danger_signals = []
    warning_signals = []
    info_signals = []

    # -------------------------------------------------------------------------
    # Hard structural risks
    # -------------------------------------------------------------------------

    if features.get("is_ip_address"):
        warning_signals.append(make_signal(
            code="url_uses_ip_address",
            severity="warning",
            message="The URL uses an IP address instead of a normal domain.",
            points=25
        ))

    if features.get("uses_http"):
        info_signals.append(make_signal(
            code="url_uses_http",
            severity="info",
            message="The URL uses HTTP instead of HTTPS.",
            points=8
        ))

    if features.get("has_at_symbol"):
        warning_signals.append(make_signal(
            code="url_has_at_symbol",
            severity="warning",
            message="The URL contains an @ symbol, which can hide the real destination.",
            points=25
        ))

    if features.get("has_punycode"):
        warning_signals.append(make_signal(
            code="url_has_punycode",
            severity="warning",
            message="The domain uses punycode, which can be used for lookalike domains.",
            points=20
        ))

    if features.get("has_encoded_chars"):
        info_signals.append(make_signal(
            code="url_has_encoded_chars",
            severity="info",
            message="The URL contains encoded characters.",
            points=5
        ))

    # -------------------------------------------------------------------------
    # Domain shape risks
    # -------------------------------------------------------------------------

    if features.get("is_url_shortener"):
        info_signals.append(make_signal(
            code="url_shortener",
            severity="info",
            message="This is a URL shortener. The final destination may be hidden.",
            points=12
        ))

    if features.get("high_risk_tld"):
        info_signals.append(make_signal(
            code="high_risk_tld",
            severity="info",
            message=f"The domain uses a frequently abused TLD: .{features.get('tld')}",
            points=10
        ))

    if features.get("has_many_subdomains"):
        info_signals.append(make_signal(
            code="many_subdomains",
            severity="info",
            message="The domain has many subdomains.",
            points=8,
            meta={
                "subdomain_count": features.get("subdomain_count")
            }
        ))

    if features.get("hyphens_domain", 0) >= 3:
        info_signals.append(make_signal(
            code="many_hyphens",
            severity="info",
            message="The domain contains many hyphens.",
            points=8,
            meta={
                "hyphens": features.get("hyphens_domain")
            }
        ))

    if features.get("domain_length", 0) >= 45:
        info_signals.append(make_signal(
            code="long_domain",
            severity="info",
            message="The domain is unusually long.",
            points=8,
            meta={
                "domain_length": features.get("domain_length")
            }
        ))

    if features.get("url_length", 0) >= 160:
        info_signals.append(make_signal(
            code="long_url",
            severity="info",
            message="The full URL is unusually long.",
            points=8,
            meta={
                "url_length": features.get("url_length")
            }
        ))

    if features.get("entropy_domain", 0) >= 4.2 and features.get("domain_length", 0) >= 18:
        info_signals.append(make_signal(
            code="high_domain_entropy",
            severity="info",
            message="The domain appears unusually random.",
            points=10,
            meta={
                "entropy_domain": features.get("entropy_domain")
            }
        ))

    if features.get("digit_ratio_domain", 0) >= 0.28 and features.get("domain_length", 0) >= 12:
        info_signals.append(make_signal(
            code="high_digit_ratio_domain",
            severity="info",
            message="The domain has an unusually high number of digits.",
            points=8,
            meta={
                "digit_ratio_domain": features.get("digit_ratio_domain")
            }
        ))

    # -------------------------------------------------------------------------
    # Scam context risks
    # -------------------------------------------------------------------------

    context_count = features.get("scam_context_word_count", 0)
    context_words = features.get("scam_context_words", [])

    if context_count >= 5:
        warning_signals.append(make_signal(
            code="many_scam_context_words",
            severity="warning",
            message="The URL contains many scam-context words: " + ", ".join(context_words[:10]),
            points=18,
            meta={
                "words": context_words
            }
        ))
    elif context_count >= 2:
        info_signals.append(make_signal(
            code="some_scam_context_words",
            severity="info",
            message="The URL contains scam-context words: " + ", ".join(context_words[:8]),
            points=8,
            meta={
                "words": context_words
            }
        ))

    # -------------------------------------------------------------------------
    # Brand impersonation risks
    # -------------------------------------------------------------------------

    impersonation_candidates = features.get("brand_impersonation_candidates", [])

    if impersonation_candidates:
        brands = sorted(set([
            item.get("brand")
            for item in impersonation_candidates
            if item.get("brand")
        ]))

        warning_signals.append(make_signal(
            code="possible_brand_impersonation",
            severity="warning",
            message="Possible brand impersonation signal involving: " + ", ".join(brands[:10]),
            points=35,
            meta={
                "candidates": impersonation_candidates
            }
        ))

    # -------------------------------------------------------------------------
    # File / download risks
    # -------------------------------------------------------------------------

    if features.get("looks_like_file_download"):
        warning_signals.append(make_signal(
            code="risky_file_extension",
            severity="warning",
            message=f"The URL appears to point to a risky file type: {features.get('suspicious_file_extension')}",
            points=20,
            meta={
                "extension": features.get("suspicious_file_extension")
            }
        ))

    # -------------------------------------------------------------------------
    # Query string risks
    # -------------------------------------------------------------------------

    suspicious_query_keys = features.get("suspicious_query_keys", [])
    redirect_like_values = features.get("redirect_like_values", [])
    long_query_values = features.get("long_query_values", [])

    if suspicious_query_keys:
        info_signals.append(make_signal(
            code="suspicious_query_keys",
            severity="info",
            message="The URL contains sensitive-looking query parameters: " + ", ".join(suspicious_query_keys[:10]),
            points=6,
            meta={
                "keys": suspicious_query_keys
            }
        ))

    if redirect_like_values:
        warning_signals.append(make_signal(
            code="query_contains_redirect_url",
            severity="warning",
            message="The URL contains another URL inside its query string.",
            points=15,
            meta={
                "redirect_like_values": redirect_like_values
            }
        ))

    if len(long_query_values) >= 2:
        info_signals.append(make_signal(
            code="multiple_long_query_values",
            severity="info",
            message="The URL contains multiple very long query values.",
            points=6,
            meta={
                "long_query_values": long_query_values
            }
        ))

    # -------------------------------------------------------------------------
    # Path risks
    # -------------------------------------------------------------------------

    if features.get("path_segment_count", 0) >= 8:
        info_signals.append(make_signal(
            code="many_path_segments",
            severity="info",
            message="The URL path has many segments.",
            points=5,
            meta={
                "path_segment_count": features.get("path_segment_count")
            }
        ))

    if features.get("repeated_segment_count", 0) >= 2:
        info_signals.append(make_signal(
            code="repeated_path_segments",
            severity="info",
            message="The URL path contains repeated segments.",
            points=5,
            meta={
                "repeated_segment_count": features.get("repeated_segment_count")
            }
        ))

    # -------------------------------------------------------------------------
    # Combined risk score
    # -------------------------------------------------------------------------

    raw_score = (
        sum_signal_points(danger_signals)
        + sum_signal_points(warning_signals)
        + sum_signal_points(info_signals)
    )

    risk_score = clamp(raw_score, 0, 100)

    if risk_score >= 80:
        confidence = 75
    elif risk_score >= 60:
        confidence = 60
    elif risk_score >= 40:
        confidence = 45
    elif risk_score >= 20:
        confidence = 30
    else:
        confidence = 15

    return {
        "risk_score": risk_score,
        "confidence": confidence,
        "danger_signals_structured": danger_signals,
        "warning_signals_structured": warning_signals,
        "info_signals_structured": info_signals,
        "danger_signals": signals_to_messages(danger_signals),
        "warning_signals": signals_to_messages(warning_signals),
        "info_signals": signals_to_messages(info_signals)
    }


# =============================================================================
# URL Verdict Builder
# =============================================================================

def build_url_verdict(url):
    sources_checked = [
        "LidaShield Verified Threat Database",
        "LidaShield URL Feature Engine",
        "LidaShield Report Intelligence"
    ]

    features = extract_url_features(url)
    score_result = score_url_features(features)

    risk_score = score_result["risk_score"]
    confidence = score_result["confidence"]

    danger_signals = list(score_result["danger_signals"])
    warning_signals = list(score_result["warning_signals"])
    info_signals = list(score_result["info_signals"])

    matched_threat = find_url_or_domain_threat(url)

    if matched_threat:
        risk_score = 100
        confidence = max(confidence, safe_int(matched_threat.get("confidence"), 100))

        danger_signals.append(
            "Matched verified LidaShield threat database: "
            + str(matched_threat.get("category") or "Unknown threat")
        )

    verified_report_count = count_verified_url_reports(url)
    pending_report_count = count_pending_url_reports(url)

    if verified_report_count > 0:
        risk_score = max(risk_score, 90)
        confidence = max(confidence, 90)

        danger_signals.append(
            f"This URL/domain has {verified_report_count} verified user report(s)."
        )

    if pending_report_count >= 3:
        risk_score = max(risk_score, 65)
        confidence = max(confidence, 55)

        warning_signals.append(
            f"This URL/domain has {pending_report_count} pending report(s). Not verified yet."
        )

    elif pending_report_count > 0:
        risk_score = max(risk_score, 35)

        info_signals.append(
            f"This URL/domain has {pending_report_count} pending report(s). Not verified yet."
        )

    if danger_signals:
        verdict = "DANGEROUS"
        verdict_class = "danger"
        message = "This link matches verified LidaShield threat intelligence or strong danger signals."
    elif risk_score >= 70:
        verdict = "SUSPICIOUS"
        verdict_class = "warning"
        message = "This link has a high LidaShield risk score."
    elif risk_score >= 40:
        verdict = "CAUTION"
        verdict_class = "warning"
        message = "This link has suspicious signals. Check carefully before trusting it."
    else:
        verdict = "NOT FLAGGED"
        verdict_class = "safe"
        message = "This link was not found in LidaShield verified threats and has low detected risk signals."

    return {
        "verdict": verdict,
        "verdict_class": verdict_class,
        "risk_score": risk_score,
        "confidence": confidence,
        "message": message,
        "url": url,
        "normalized_url": features["normalized_url"],
        "domain": features["domain"],
        "engines_checked": sources_checked,
        "sources_checked": sources_checked,
        "danger_signals": danger_signals,
        "warning_signals": warning_signals,
        "info_signals": info_signals,
        "pending_report_count": pending_report_count,
        "verified_report_count": verified_report_count,
        "matched_threat": matched_threat,
        "features": features,
        "note": "LidaShield uses its own database and signal engine. Not Flagged does not guarantee safety."
    }


# =============================================================================
# PART 2 END
# =============================================================================
# Next:
# PART 3 will add:
# - public routes
# - /scan route
# - /report route
# - /stats route
# - /health route
# - /remaining route
# - /api/check-url route
# =============================================================================
# =============================================================================
# LidaShield v2.0 — Own Threat Intelligence Engine
# PART 3 / 50
# Public routes, scan route, report route, stats route, health route, API route.
# =============================================================================


# =============================================================================
# Public Frontend Route
# =============================================================================

@app.route("/")
def index():
    file_path = os.path.join(os.path.dirname(__file__), "index.html")

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>LidaShield</title>
            <style>
                body {
                    background: #050505;
                    color: #f5c542;
                    font-family: Arial, sans-serif;
                    padding: 40px;
                }
                .box {
                    max-width: 720px;
                    margin: auto;
                    border: 1px solid rgba(245,197,66,0.3);
                    border-radius: 20px;
                    padding: 30px;
                    background: #111;
                }
                code {
                    color: #fff;
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h1>LidaShield Backend Online</h1>
                <p>Your backend is running, but <code>index.html</code> was not found.</p>
                <p>Put <code>index.html</code> in the same folder as <code>app.py</code>.</p>
            </div>
        </body>
        </html>
        """


# =============================================================================
# Scan Route
# =============================================================================

@app.route("/scan", methods=["POST"])
def scan():
    ip = get_client_ip()
    allowed, limit = check_rate_limit(ip, plan=DEFAULT_PLAN)

    if not allowed:
        return jsonify_error(
            message=f"You've used all {limit} free scans for today.",
            status_code=429,
            extra={
                "rate_limited": True,
                "scans_remaining": 0
            }
        )

    body = get_request_json()

    if not body or not body.get("url"):
        return jsonify_error(
            message="No URL provided.",
            status_code=400,
            extra={
                "scans_remaining": scans_remaining(ip)
            }
        )

    raw_url = body.get("url")
    url, error = validate_url(raw_url)

    if error:
        return jsonify_error(
            message=error,
            status_code=400,
            extra={
                "scans_remaining": scans_remaining(ip)
            }
        )

    result = build_url_verdict(url)
    result["scans_remaining"] = scans_remaining(ip)

    save_scan(
        scan_type="url",
        input_value=raw_url,
        normalized_value=result["normalized_url"],
        domain=result["domain"],
        verdict=result["verdict"],
        verdict_class=result["verdict_class"],
        risk_score=result["risk_score"],
        confidence=result["confidence"],
        message=result["message"],
        sources_checked=result["sources_checked"],
        danger_signals=result["danger_signals"],
        warning_signals=result["warning_signals"],
        info_signals=result["info_signals"],
        feature_snapshot=result["features"],
        ip=ip
    )

    upsert_domain_intel(
        domain=result["domain"],
        scanned=True,
        risk_score=result["risk_score"]
    )

    add_intelligence_event(
        event_type="url_scan",
        indicator_type="url",
        indicator_value=url,
        normalized_value=result["normalized_url"],
        domain=result["domain"],
        category=result["verdict"],
        source="public_scan",
        confidence=result["confidence"],
        status="recorded",
        raw_data={
            "risk_score": result["risk_score"],
            "verdict": result["verdict"],
            "danger_signals": result["danger_signals"],
            "warning_signals": result["warning_signals"],
            "info_signals": result["info_signals"]
        }
    )

    return jsonify(result)


# =============================================================================
# Scam Report Route
# =============================================================================

@app.route("/report", methods=["POST"])
def report():
    body = get_request_json()
    ip = get_client_ip()

    if not body:
        return jsonify_error(
            message="No report data provided.",
            status_code=400
        )

    raw_url = body.get("url", "")
    category = str(body.get("category", "Unknown")).strip()
    description = str(body.get("description", "")).strip()

    url, error = validate_url(raw_url)

    if error:
        return jsonify_error(
            message=error,
            status_code=400
        )

    if len(description) > MAX_REPORT_DESCRIPTION_LENGTH:
        return jsonify_error(
            message=f"Description is too long. Keep it under {MAX_REPORT_DESCRIPTION_LENGTH} characters.",
            status_code=400
        )

    normalized_url = normalize_url(url)
    domain = get_domain(url)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scam_reports (
            url,
            normalized_url,
            domain,
            category,
            description,
            reporter_ip,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
    """, (
        url,
        normalized_url,
        domain,
        category,
        description,
        ip,
        now_utc()
    ))

    report_id = cursor.lastrowid

    conn.commit()
    conn.close()

    upsert_domain_intel(
        domain=domain,
        category=category,
        scanned=False,
        verified=False,
        risk_score=None,
        notes=description
    )

    add_intelligence_event(
        event_type="user_scam_report",
        indicator_type="url",
        indicator_value=url,
        normalized_value=normalized_url,
        domain=domain,
        category=category,
        source="user_report",
        confidence=25,
        status="pending",
        raw_data={
            "report_id": report_id,
            "description": description,
            "reporter_ip_hash": short_hash(ip)
        }
    )

    return jsonify_success({
        "message": "Scam report submitted. It is pending review.",
        "report_id": report_id,
        "url": url,
        "normalized_url": normalized_url,
        "domain": domain,
        "status": "pending"
    })


# =============================================================================
# Remaining Scan Count Route
# =============================================================================

@app.route("/remaining", methods=["GET"])
def remaining():
    ip = get_client_ip()

    return jsonify({
        "scans_remaining": scans_remaining(ip),
        "limit": FREE_DAILY_SCAN_LIMIT,
        "plan": DEFAULT_PLAN
    })


# =============================================================================
# Stats Route
# =============================================================================

@app.route("/stats", methods=["GET"])
def stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM scan_history")
    total_scans = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scam_reports")
    total_reports = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scam_reports WHERE status = 'pending'")
    pending_reports = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scam_reports WHERE status = 'verified'")
    verified_reports = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM scam_reports WHERE status = 'rejected'")
    rejected_reports = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM verified_threats")
    verified_threats = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM domain_intel")
    domains_tracked = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM phone_reports")
    phone_reports = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM message_reports")
    message_reports = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM email_reports")
    email_reports = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM business_audit_requests")
    business_audit_requests = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM intelligence_events")
    intelligence_events = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT verdict, COUNT(*) AS count
        FROM scan_history
        GROUP BY verdict
        ORDER BY count DESC
    """)
    verdict_breakdown = [
        {
            "verdict": row["verdict"],
            "count": row["count"]
        }
        for row in cursor.fetchall()
    ]

    cursor.execute("""
        SELECT domain, scan_count, report_count, verified_threat_count, risk_score
        FROM domain_intel
        ORDER BY scan_count DESC, report_count DESC
        LIMIT 10
    """)
    top_domains = [
        {
            "domain": row["domain"],
            "scan_count": row["scan_count"],
            "report_count": row["report_count"],
            "verified_threat_count": row["verified_threat_count"],
            "risk_score": row["risk_score"]
        }
        for row in cursor.fetchall()
    ]

    conn.close()

    return jsonify({
        "total_scans": total_scans,
        "total_reports": total_reports,
        "pending_reports": pending_reports,
        "verified_reports": verified_reports,
        "rejected_reports": rejected_reports,
        "verified_threats": verified_threats,
        "domains_tracked": domains_tracked,
        "phone_reports": phone_reports,
        "message_reports": message_reports,
        "email_reports": email_reports,
        "business_audit_requests": business_audit_requests,
        "intelligence_events": intelligence_events,
        "verdict_breakdown": verdict_breakdown,
        "top_domains": top_domains,
        "engine": ENGINE_NAME,
        "external_scanners": [],
        "version": APP_VERSION
    })


# =============================================================================
# Health Route
# =============================================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": APP_NAME,
        "engine": ENGINE_NAME,
        "database": DATABASE_FILE,
        "external_scanners": [],
        "version": APP_VERSION,
        "time": now_utc()
    })


# =============================================================================
# API Check URL Route
# =============================================================================

@app.route("/api/check-url", methods=["POST"])
def api_check_url():
    body = get_request_json()

    if not body or not body.get("url"):
        return jsonify_error(
            message="No URL provided.",
            status_code=400
        )

    raw_url = body.get("url")
    url, error = validate_url(raw_url)

    if error:
        return jsonify_error(
            message=error,
            status_code=400
        )

    result = build_url_verdict(url)

    return jsonify(result)


# =============================================================================
# Public Domain Lookup Route
# =============================================================================

@app.route("/domain/<path:domain>", methods=["GET"])
def public_domain_lookup(domain):
    domain = normalize_domain(domain)

    if not domain:
        return jsonify_error(
            message="Invalid domain.",
            status_code=400
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM domain_intel
        WHERE domain = ?
        LIMIT 1
    """, (domain,))
    intel = cursor.fetchone()

    cursor.execute("""
        SELECT indicator_type, indicator_value, category, region, confidence, source, created_at
        FROM verified_threats
        WHERE domain = ?
        OR normalized_value = ?
        ORDER BY created_at DESC
        LIMIT 25
    """, (
        domain,
        domain
    ))
    threats = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT id, category, status, created_at
        FROM scam_reports
        WHERE domain = ?
        ORDER BY created_at DESC
        LIMIT 25
    """, (domain,))
    reports = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "domain": domain,
        "intel": dict(intel) if intel else None,
        "verified_threats": threats,
        "reports": reports
    })


# =============================================================================
# Public Recent Threats Route
# =============================================================================

@app.route("/public-threats", methods=["GET"])
def public_threats():
    limit = safe_int(request.args.get("limit", 50), 50)
    limit = clamp(limit, 1, 100)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            indicator_type,
            indicator_value,
            domain,
            category,
            region,
            confidence,
            source,
            created_at
        FROM verified_threats
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    threats = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "count": len(threats),
        "threats": threats
    })


# =============================================================================
# Basic Admin: Add Verified Threat
# =============================================================================

@app.route("/admin/add-threat", methods=["POST"])
def admin_add_threat():
    if not require_admin():
        return jsonify_error(
            message="Unauthorized.",
            status_code=401
        )

    body = get_request_json()

    if not body:
        return jsonify_error(
            message="No threat data provided.",
            status_code=400
        )

    indicator_type = str(body.get("indicator_type", "url")).strip().lower()
    indicator_value = str(body.get("indicator_value", "")).strip()
    category = str(body.get("category", "Unknown")).strip()
    region = str(body.get("region", REGION_DEFAULT)).strip()
    source = str(body.get("source", "admin_manual")).strip()
    confidence = clamp(safe_int(body.get("confidence", 100), 100), 0, 100)
    notes = str(body.get("notes", "")).strip()

    allowed_types = {
        "url",
        "domain",
        "phone",
        "message",
        "email"
    }

    if indicator_type not in allowed_types:
        return jsonify_error(
            message="Invalid indicator_type.",
            status_code=400,
            extra={
                "allowed_types": sorted(list(allowed_types))
            }
        )

    if not indicator_value:
        return jsonify_error(
            message="indicator_value is required.",
            status_code=400
        )

    normalized_value = normalize_indicator(indicator_type, indicator_value)
    domain = ""

    if indicator_type == "url":
        checked_url, error = validate_url(indicator_value)

        if error:
            return jsonify_error(
                message=error,
                status_code=400
            )

        indicator_value = checked_url
        normalized_value = normalize_url(checked_url)
        domain = get_domain(checked_url)

    elif indicator_type == "domain":
        domain = normalize_domain(indicator_value)
        indicator_value = domain
        normalized_value = domain

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO verified_threats (
            indicator_type,
            indicator_value,
            normalized_value,
            domain,
            category,
            region,
            source,
            confidence,
            notes,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        indicator_type,
        indicator_value,
        normalized_value,
        domain,
        category,
        region,
        source,
        confidence,
        notes,
        now_utc()
    ))

    inserted = cursor.rowcount

    conn.commit()
    conn.close()

    if domain:
        upsert_domain_intel(
            domain=domain,
            category=category,
            verified=True,
            scanned=False,
            risk_score=100,
            notes=notes
        )

    add_intelligence_event(
        event_type="admin_added_verified_threat",
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        normalized_value=normalized_value,
        domain=domain,
        category=category,
        source=source,
        confidence=confidence,
        status="verified",
        raw_data={
            "notes": notes,
            "inserted": bool(inserted)
        }
    )

    return jsonify_success({
        "message": "Verified threat added." if inserted else "Threat already exists.",
        "inserted": bool(inserted),
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "normalized_value": normalized_value,
        "domain": domain,
        "category": category,
        "confidence": confidence
    })


# =============================================================================
# Basic Admin: Pending Reports
# =============================================================================

@app.route("/admin/pending", methods=["GET"])
def admin_pending():
    if not require_admin():
        return jsonify_error(
            message="Unauthorized.",
            status_code=401
        )

    limit = safe_int(request.args.get("limit", 100), 100)
    limit = clamp(limit, 1, 200)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scam_reports
        WHERE status = 'pending'
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    pending_reports = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return jsonify({
        "count": len(pending_reports),
        "pending_scam_reports": pending_reports
    })


# =============================================================================
# Basic Admin: Approve Report
# =============================================================================

@app.route("/admin/approve-report", methods=["POST"])
def admin_approve_report():
    if not require_admin():
        return jsonify_error(
            message="Unauthorized.",
            status_code=401
        )

    body = get_request_json()

    report_id = body.get("report_id")

    if not report_id:
        return jsonify_error(
            message="report_id is required.",
            status_code=400
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scam_reports
        WHERE id = ?
        AND status = 'pending'
    """, (report_id,))

    report_row = cursor.fetchone()

    if not report_row:
        conn.close()
        return jsonify_error(
            message="Report not found or already reviewed.",
            status_code=404
        )

    reviewed_at = now_utc()

    cursor.execute("""
        UPDATE scam_reports
        SET status = 'verified',
            reviewed_at = ?
        WHERE id = ?
    """, (
        reviewed_at,
        report_id
    ))

    cursor.execute("""
        INSERT OR IGNORE INTO verified_threats (
            indicator_type,
            indicator_value,
            normalized_value,
            domain,
            category,
            region,
            source,
            confidence,
            notes,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "url",
        report_row["url"],
        report_row["normalized_url"],
        report_row["domain"],
        report_row["category"] or "User Reported Scam",
        REGION_DEFAULT,
        "admin_verified_user_report",
        100,
        report_row["description"] or "",
        reviewed_at
    ))

    cursor.execute("""
        INSERT OR IGNORE INTO verified_threats (
            indicator_type,
            indicator_value,
            normalized_value,
            domain,
            category,
            region,
            source,
            confidence,
            notes,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "domain",
        report_row["domain"],
        report_row["domain"],
        report_row["domain"],
        report_row["category"] or "User Reported Scam",
        REGION_DEFAULT,
        "admin_verified_user_report",
        100,
        report_row["description"] or "",
        reviewed_at
    ))

    conn.commit()
    conn.close()

    upsert_domain_intel(
        domain=report_row["domain"],
        category=report_row["category"],
        verified=True,
        scanned=False,
        risk_score=100,
        notes=report_row["description"]
    )

    add_intelligence_event(
        event_type="admin_approved_report",
        indicator_type="url",
        indicator_value=report_row["url"],
        normalized_value=report_row["normalized_url"],
        domain=report_row["domain"],
        category=report_row["category"],
        source="admin_review",
        confidence=100,
        status="verified",
        raw_data={
            "report_id": report_id
        }
    )

    return jsonify_success({
        "message": "Report approved and added to verified threats.",
        "report_id": report_id,
        "domain": report_row["domain"]
    })


# =============================================================================
# Basic Admin: Reject Report
# =============================================================================

@app.route("/admin/reject-report", methods=["POST"])
def admin_reject_report():
    if not require_admin():
        return jsonify_error(
            message="Unauthorized.",
            status_code=401
        )

    body = get_request_json()
    report_id = body.get("report_id")

    if not report_id:
        return jsonify_error(
            message="report_id is required.",
            status_code=400
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE scam_reports
        SET status = 'rejected',
            reviewed_at = ?
        WHERE id = ?
    """, (
        now_utc(),
        report_id
    ))

    updated = cursor.rowcount

    conn.commit()
    conn.close()

    if not updated:
        return jsonify_error(
            message="Report not found.",
            status_code=404
        )

    add_intelligence_event(
        event_type="admin_rejected_report",
        indicator_type="url",
        indicator_value=str(report_id),
        normalized_value=str(report_id),
        domain=None,
        category=None,
        source="admin_review",
        confidence=100,
        status="rejected",
        raw_data={
            "report_id": report_id
        }
    )

    return jsonify_success({
        "message": "Report rejected.",
        "report_id": report_id
    })


# =============================================================================
# App Runner
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )


# =============================================================================
# PART 3 END
# =============================================================================
# Next:
# PART 4 will add:
# - deeper domain reputation engine
# - lexical similarity checks
# - brand typosquatting detection
# - Levenshtein distance
# - homoglyph / lookalike character logic
# =============================================================================
