import os
import sqlite3
import hashlib
from datetime import date, datetime
from functools import wraps
from flask import Flask, request, jsonify, session, redirect

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

DB_PATH = os.environ.get("DB_PATH", "lidashield.db")

PLAN_LIMITS = {
    "free": 10,
    "plus": 100,
    "pro": 500,
}

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").lower().strip()


# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'free',
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS usage_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        feature TEXT NOT NULL,
        used_on TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS link_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        normalized_url TEXT UNIQUE NOT NULL,
        original_url TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        source TEXT NOT NULL DEFAULT 'user_report',
        report_count INTEGER NOT NULL DEFAULT 1,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS phone_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone_number TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        source TEXT NOT NULL DEFAULT 'user_report',
        report_count INTEGER NOT NULL DEFAULT 1,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS message_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_hash TEXT UNIQUE NOT NULL,
        message_text TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        source TEXT NOT NULL DEFAULT 'user_report',
        report_count INTEGER NOT NULL DEFAULT 1,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS email_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_hash TEXT UNIQUE NOT NULL,
        email_text TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        source TEXT NOT NULL DEFAULT 'user_report',
        report_count INTEGER NOT NULL DEFAULT 1,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS business_audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        business_name TEXT NOT NULL,
        website TEXT NOT NULL,
        contact_email TEXT,
        status TEXT NOT NULL DEFAULT 'requested',
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


def now():
    return datetime.utcnow().isoformat()


def normalize_url(raw):
    raw = (raw or "").strip().lower()
    raw = raw.replace("http://", "").replace("https://", "")
    raw = raw.split("#")[0].strip("/")
    return raw


def hash_text(text):
    return hashlib.sha256((text or "").strip().lower().encode()).hexdigest()


init_db()


# ─────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Please log in first."}), 401
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user["is_admin"]:
            return jsonify({"error": "Admin access required."}), 403
        return fn(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────
# Usage limits
# ─────────────────────────────────────────────

def check_usage_limit(user_id, feature):
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        conn.close()
        return False, 0, "User not found."

    plan = user["plan"]
    limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])

    today = str(date.today())

    used = conn.execute("""
        SELECT COUNT(*) AS count
        FROM usage_logs
        WHERE user_id = ? AND feature = ? AND used_on = ?
    """, (user_id, feature, today)).fetchone()["count"]

    if used >= limit:
        conn.close()
        return False, 0, f"You have used all {limit} daily {feature} checks for your {plan.title()} plan."

    conn.execute("""
        INSERT INTO usage_logs (user_id, feature, used_on, created_at)
        VALUES (?, ?, ?, ?)
    """, (user_id, feature, today, now()))

    conn.commit()
    conn.close()

    return True, limit - used - 1, None


# ─────────────────────────────────────────────
# Verdict builder — no heuristics
# ─────────────────────────────────────────────

def verdict_from_status(status, report_count=0):
    if status == "confirmed_scam":
        return {
            "verdict": "DANGEROUS",
            "verdict_class": "danger",
            "message": "This item exists in the LidaShield confirmed scam database. Do not proceed."
        }

    if status == "confirmed_safe":
        return {
            "verdict": "KNOWN SAFE",
            "verdict_class": "safe",
            "message": "This item has been reviewed and marked safe in the LidaShield database."
        }

    if status == "pending":
        return {
            "verdict": "REPORTED",
            "verdict_class": "warning",
            "message": f"This item has been reported {report_count} time(s), but has not been admin-confirmed yet."
        }

    return {
        "verdict": "UNKNOWN",
        "verdict_class": "unknown",
        "message": "LidaShield has no confirmed record for this item yet."
    }


# ─────────────────────────────────────────────
# Page
# ─────────────────────────────────────────────

@app.route("/")
def home():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r", encoding="utf-8") as f:
        return f.read()


# ─────────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    email = (data.get("email") or "").lower().strip()
    password = data.get("password") or ""

    if not email or "@" not in email:
        return jsonify({"error": "Enter a valid email."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    is_admin = 1 if ADMIN_EMAIL and email == ADMIN_EMAIL else 0

    try:
        conn = db()
        conn.execute("""
            INSERT INTO users (email, password_hash, plan, is_admin, created_at)
            VALUES (?, ?, 'free', ?, ?)
        """, (email, generate_password_hash(password), is_admin, now()))
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        session["user_id"] = user["id"]

        return jsonify({
            "message": "Account created.",
            "user": {
                "email": user["email"],
                "plan": user["plan"],
                "is_admin": bool(user["is_admin"])
            }
        })

    except sqlite3.IntegrityError:
        return jsonify({"error": "This email is already registered."}), 409


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").lower().strip()
    password = data.get("password") or ""

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401

    session["user_id"] = user["id"]

    return jsonify({
        "message": "Logged in.",
        "user": {
            "email": user["email"],
            "plan": user["plan"],
            "is_admin": bool(user["is_admin"])
        }
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out."})


@app.route("/api/me")
def me():
    user = current_user()

    if not user:
        return jsonify({"logged_in": False})

    return jsonify({
        "logged_in": True,
        "user": {
            "email": user["email"],
            "plan": user["plan"],
            "is_admin": bool(user["is_admin"])
        }
    })


# ─────────────────────────────────────────────
# Feature 1: Link checker
# ─────────────────────────────────────────────

@app.route("/api/check/link", methods=["POST"])
@require_login
def check_link():
    user = current_user()
    allowed, remaining, error = check_usage_limit(user["id"], "link")

    if not allowed:
        return jsonify({
            "error": error,
            "rate_limited": True,
            "remaining": 0
        }), 429

    data = request.get_json() or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Enter a link."}), 400

    normalized = normalize_url(url)

    conn = db()
    record = conn.execute("""
        SELECT * FROM link_records
        WHERE normalized_url = ?
    """, (normalized,)).fetchone()
    conn.close()

    if record:
        verdict = verdict_from_status(record["status"], record["report_count"])
        verdict.update({
            "type": "link",
            "input": url,
            "normalized": normalized,
            "source": "LidaShield database",
            "report_count": record["report_count"],
            "remaining": remaining
        })
        return jsonify(verdict)

    verdict = verdict_from_status("unknown")
    verdict.update({
        "type": "link",
        "input": url,
        "normalized": normalized,
        "source": "LidaShield database",
        "report_count": 0,
        "remaining": remaining
    })
    return jsonify(verdict)


@app.route("/api/report/link", methods=["POST"])
@require_login
def report_link():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    notes = data.get("notes", "").strip()

    if not url:
        return jsonify({"error": "Enter a link to report."}), 400

    normalized = normalize_url(url)

    conn = db()
    existing = conn.execute("""
        SELECT * FROM link_records
        WHERE normalized_url = ?
    """, (normalized,)).fetchone()

    if existing:
        conn.execute("""
            UPDATE link_records
            SET report_count = report_count + 1,
                notes = COALESCE(notes, '') || ?,
                updated_at = ?
            WHERE normalized_url = ?
        """, (f"\nUser report: {notes}", now(), normalized))
    else:
        conn.execute("""
            INSERT INTO link_records
            (normalized_url, original_url, status, source, report_count, notes, created_at, updated_at)
            VALUES (?, ?, 'pending', 'user_report', 1, ?, ?, ?)
        """, (normalized, url, notes, now(), now()))

    conn.commit()
    conn.close()

    return jsonify({"message": "Report submitted. Admin review needed before it becomes confirmed."})


# ─────────────────────────────────────────────
# Feature 2: Phone checker
# ─────────────────────────────────────────────

@app.route("/api/check/phone", methods=["POST"])
@require_login
def check_phone():
    user = current_user()
    allowed, remaining, error = check_usage_limit(user["id"], "phone")

    if not allowed:
        return jsonify({"error": error, "rate_limited": True, "remaining": 0}), 429

    data = request.get_json() or {}
    phone = data.get("phone", "").strip()

    if not phone:
        return jsonify({"error": "Enter a phone number."}), 400

    conn = db()
    record = conn.execute("""
        SELECT * FROM phone_records
        WHERE phone_number = ?
    """, (phone,)).fetchone()
    conn.close()

    if record:
        verdict = verdict_from_status(record["status"], record["report_count"])
    else:
        verdict = verdict_from_status("unknown")

    verdict.update({
        "type": "phone",
        "input": phone,
        "source": "LidaShield database",
        "remaining": remaining
    })

    return jsonify(verdict)


# ─────────────────────────────────────────────
# Feature 3: Message checker
# ─────────────────────────────────────────────

@app.route("/api/check/message", methods=["POST"])
@require_login
def check_message():
    user = current_user()
    allowed, remaining, error = check_usage_limit(user["id"], "message")

    if not allowed:
        return jsonify({"error": error, "rate_limited": True, "remaining": 0}), 429

    data = request.get_json() or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"error": "Paste a message."}), 400

    message_hash = hash_text(message)

    conn = db()
    record = conn.execute("""
        SELECT * FROM message_records
        WHERE message_hash = ?
    """, (message_hash,)).fetchone()
    conn.close()

    if record:
        verdict = verdict_from_status(record["status"], record["report_count"])
    else:
        verdict = verdict_from_status("unknown")

    verdict.update({
        "type": "message",
        "source": "LidaShield database",
        "remaining": remaining
    })

    return jsonify(verdict)


# ─────────────────────────────────────────────
# Feature 4: Email checker
# ─────────────────────────────────────────────

@app.route("/api/check/email", methods=["POST"])
@require_login
def check_email():
    user = current_user()
    allowed, remaining, error = check_usage_limit(user["id"], "email")

    if not allowed:
        return jsonify({"error": error, "rate_limited": True, "remaining": 0}), 429

    data = request.get_json() or {}
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "Paste email content."}), 400

    email_hash = hash_text(email_text)

    conn = db()
    record = conn.execute("""
        SELECT * FROM email_records
        WHERE email_hash = ?
    """, (email_hash,)).fetchone()
    conn.close()

    if record:
        verdict = verdict_from_status(record["status"], record["report_count"])
    else:
        verdict = verdict_from_status("unknown")

    verdict.update({
        "type": "email",
        "source": "LidaShield database",
        "remaining": remaining
    })

    return jsonify(verdict)


# ─────────────────────────────────────────────
# Feature 5: Business audit request
# ─────────────────────────────────────────────

@app.route("/api/business-audit", methods=["POST"])
@require_login
def business_audit():
    user = current_user()
    allowed, remaining, error = check_usage_limit(user["id"], "business_audit")

    if not allowed:
        return jsonify({"error": error, "rate_limited": True, "remaining": 0}), 429

    data = request.get_json() or {}

    business_name = data.get("business_name", "").strip()
    website = data.get("website", "").strip()
    contact_email = data.get("contact_email", "").strip()

    if not business_name or not website:
        return jsonify({"error": "Business name and website are required."}), 400

    conn = db()
    conn.execute("""
        INSERT INTO business_audits
        (user_id, business_name, website, contact_email, status, created_at)
        VALUES (?, ?, ?, ?, 'requested', ?)
    """, (user["id"], business_name, website, contact_email, now()))
    conn.commit()
    conn.close()

    return jsonify({
        "message": "Business audit request received.",
        "remaining": remaining
    })


# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────

@app.route("/api/dashboard")
@require_login
def dashboard():
    user = current_user()
    conn = db()

    today = str(date.today())

    usage = conn.execute("""
        SELECT feature, COUNT(*) AS count
        FROM usage_logs
        WHERE user_id = ? AND used_on = ?
        GROUP BY feature
    """, (user["id"], today)).fetchall()

    reports = conn.execute("""
        SELECT COUNT(*) AS count
        FROM link_records
    """).fetchone()["count"]

    confirmed = conn.execute("""
        SELECT COUNT(*) AS count
        FROM link_records
        WHERE status = 'confirmed_scam'
    """).fetchone()["count"]

    conn.close()

    limit = PLAN_LIMITS.get(user["plan"], PLAN_LIMITS["free"])

    return jsonify({
        "user": {
            "email": user["email"],
            "plan": user["plan"],
            "daily_limit": limit,
            "is_admin": bool(user["is_admin"])
        },
        "usage_today": [dict(row) for row in usage],
        "database": {
            "total_link_records": reports,
            "confirmed_scam_links": confirmed
        }
    })


# ─────────────────────────────────────────────
# Admin
# ─────────────────────────────────────────────

@app.route("/api/admin/links")
@require_admin
def admin_links():
    conn = db()
    rows = conn.execute("""
        SELECT *
        FROM link_records
        ORDER BY updated_at DESC
        LIMIT 100
    """).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/admin/link/<int:record_id>", methods=["POST"])
@require_admin
def admin_update_link(record_id):
    data = request.get_json() or {}
    status = data.get("status")

    allowed_statuses = ["pending", "confirmed_scam", "confirmed_safe", "rejected"]

    if status not in allowed_statuses:
        return jsonify({"error": "Invalid status."}), 400

    notes = data.get("notes", "")

    conn = db()
    conn.execute("""
        UPDATE link_records
        SET status = ?, notes = COALESCE(notes, '') || ?, updated_at = ?
        WHERE id = ?
    """, (status, f"\nAdmin note: {notes}", now(), record_id))
    conn.commit()
    conn.close()

    return jsonify({"message": "Record updated."})


@app.route("/api/admin/stats")
@require_admin
def admin_stats():
    conn = db()

    users = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    links = conn.execute("SELECT COUNT(*) AS count FROM link_records").fetchone()["count"]
    pending = conn.execute("SELECT COUNT(*) AS count FROM link_records WHERE status = 'pending'").fetchone()["count"]
    confirmed = conn.execute("SELECT COUNT(*) AS count FROM link_records WHERE status = 'confirmed_scam'").fetchone()["count"]
    audits = conn.execute("SELECT COUNT(*) AS count FROM business_audits").fetchone()["count"]

    conn.close()

    return jsonify({
        "users": users,
        "link_records": links,
        "pending_links": pending,
        "confirmed_scam_links": confirmed,
        "business_audits": audits
    })


# ─────────────────────────────────────────────
# Temporary plan upgrade route
# Later replace with Stripe/real payments.
# ─────────────────────────────────────────────

@app.route("/api/dev/set-plan", methods=["POST"])
@require_login
def dev_set_plan():
    data = request.get_json() or {}
    plan = data.get("plan", "").lower().strip()

    if plan not in PLAN_LIMITS:
        return jsonify({"error": "Invalid plan."}), 400

    user = current_user()

    conn = db()
    conn.execute("UPDATE users SET plan = ? WHERE id = ?", (plan, user["id"]))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Plan changed to {plan}."})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
