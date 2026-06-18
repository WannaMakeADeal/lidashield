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
import csv
import io
import re
import json

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
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "")

app.secret_key = FLASK_SECRET_KEY
@app.errorhandler(Exception)
def handle_unexpected_error(error):
    code = 500

    if isinstance(error, HTTPException):
        code = error.code or 500
        details = error.description
        name = error.name
    else:
        details = str(error)
        name = "Server error"

    app.logger.exception("Unhandled server error")

    return jsonify({
        "error": name,
        "details": details,
        "type": type(error).__name__,
        "path": request.path
    }), code

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


# -----------------------------
# Dashboard HTML
# -----------------------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LidaShield Dashboard</title>
<link rel="icon" type="image/png" href="/static/lidashield-icon.png">
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500&family=DM+Mono:wght@300;400;500&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#03030a;
  --card:rgba(255,255,255,.045);
  --card2:rgba(255,255,255,.075);
  --gold:#f0a830;
  --gold2:#ffd27a;
  --text:#f4efe6;
  --muted:#8c8376;
  --border:rgba(240,168,48,.18);
  --green:#54d483;
  --red:#ff5c68;
  --blue:#78a6ff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  min-height:100vh;
  background:
    radial-gradient(circle at 20% 20%, rgba(240,168,48,.08), transparent 26%),
    radial-gradient(circle at 80% 10%, rgba(255,255,255,.05), transparent 20%),
    var(--bg);
  color:var(--text);
  font-family:Inter,system-ui,sans-serif;
}
body::before{
  content:"";
  position:fixed;
  inset:0;
  background-image:
    linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px);
  background-size:42px 42px;
  pointer-events:none;
}
.page{position:relative;z-index:1}
.nav{
  height:86px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding:0 44px;
  border-bottom:1px solid var(--border);
  background:rgba(3,3,10,.72);
  backdrop-filter:blur(22px);
}
.brand{
  display:flex;
  align-items:center;
  gap:14px;
  color:var(--text);
  text-decoration:none;
}
.logo{width:46px;height:46px;object-fit:contain;filter:drop-shadow(0 0 18px rgba(240,168,48,.28))}
.brand-name{
  font-family:Cormorant Garamond,serif;
  font-size:28px;
  color:var(--gold2);
  letter-spacing:.04em;
}
.brand-sub{
  font-family:DM Mono,monospace;
  font-size:10px;
  letter-spacing:.18em;
  color:var(--muted);
  text-transform:uppercase;
}
.nav-actions{display:flex;gap:12px;align-items:center}
.btn{
  border:1px solid var(--border);
  background:rgba(255,255,255,.04);
  color:var(--text);
  padding:12px 16px;
  border-radius:14px;
  font-family:DM Mono,monospace;
  font-size:11px;
  letter-spacing:.12em;
  text-transform:uppercase;
  text-decoration:none;
  cursor:pointer;
}
.btn.gold{
  background:linear-gradient(135deg,var(--gold),var(--gold2));
  color:#080805;
  border-color:var(--gold);
  font-weight:700;
}
.wrap{
  width:min(1180px,100%);
  margin:0 auto;
  padding:56px 24px 90px;
}
.hero{
  display:flex;
  align-items:flex-end;
  justify-content:space-between;
  gap:24px;
  margin-bottom:28px;
}
.kicker{
  color:var(--gold);
  font-family:DM Mono,monospace;
  letter-spacing:.18em;
  font-size:12px;
  text-transform:uppercase;
  margin-bottom:14px;
}
h1{
  font-family:Cormorant Garamond,serif;
  font-size:clamp(46px,6vw,82px);
  line-height:.92;
  font-weight:400;
}
.hero-copy{
  margin-top:18px;
  max-width:640px;
  color:var(--muted);
  line-height:1.8;
  font-size:14px;
}
.profile-card{
  min-width:280px;
  border:1px solid var(--border);
  background:rgba(255,255,255,.045);
  border-radius:24px;
  padding:22px;
}
.profile-row{display:flex;gap:14px;align-items:center}
.avatar{width:46px;height:46px;border-radius:50%;background:var(--gold)}
.profile-name{font-weight:700}
.profile-email{color:var(--muted);font-size:12px;margin-top:4px}
.plan{
  display:inline-flex;
  margin-top:16px;
  padding:7px 11px;
  border:1px solid rgba(240,168,48,.32);
  border-radius:999px;
  color:var(--gold2);
  font-family:DM Mono,monospace;
  text-transform:uppercase;
  font-size:11px;
}
.grid{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:16px;
  margin-top:28px;
}
.card{
  border:1px solid rgba(255,255,255,.08);
  background:rgba(255,255,255,.045);
  border-radius:24px;
  padding:24px;
}
.card:hover{
  border-color:rgba(240,168,48,.26);
  background:rgba(255,255,255,.07);
}
.num{
  font-family:Cormorant Garamond,serif;
  font-size:44px;
  line-height:1;
}
.label{
  margin-top:9px;
  color:var(--muted);
  font-family:DM Mono,monospace;
  letter-spacing:.12em;
  text-transform:uppercase;
  font-size:11px;
}
.two{
  display:grid;
  grid-template-columns:1.2fr .8fr;
  gap:18px;
  margin-top:18px;
}
.section-title{
  font-family:Cormorant Garamond,serif;
  font-size:32px;
  font-weight:500;
  margin-bottom:18px;
}
.list{display:flex;flex-direction:column;gap:12px}
.item{
  display:flex;
  justify-content:space-between;
  gap:14px;
  padding:14px 0;
  border-bottom:1px solid rgba(255,255,255,.07);
  color:var(--muted);
  font-size:13px;
}
.item:last-child{border-bottom:0}
.item-main{
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}
.badge{
  font-family:DM Mono,monospace;
  font-size:10px;
  letter-spacing:.12em;
  text-transform:uppercase;
}
.safe{color:var(--green)}
.dangerous{color:var(--red)}
.suspicious{color:var(--gold)}
.unknown{color:var(--blue)}
.actions{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:14px;
  margin-top:18px;
}
.action{
  border:1px solid var(--border);
  border-radius:22px;
  padding:22px;
  background:rgba(240,168,48,.055);
}
.action h3{font-size:17px;margin-bottom:10px}
.action p{font-size:13px;line-height:1.7;color:var(--muted);margin-bottom:16px}
.error{color:#ff9ca4}
.checkout-overlay{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(3,3,10,.72);backdrop-filter:blur(18px);z-index:999}
.checkout-overlay.show{display:flex}
.checkout-card{width:min(420px,90%);border:1px solid rgba(240,168,48,.28);background:linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.035));border-radius:26px;padding:34px;text-align:center;box-shadow:0 30px 90px rgba(0,0,0,.55)}
.checkout-card h3{font-family:Cormorant Garamond,serif;font-size:34px;font-weight:500;margin-bottom:10px}
.checkout-card p{color:var(--muted);font-size:13px;line-height:1.7}
.checkout-spinner{width:30px;height:30px;margin:0 auto 18px;border-radius:50%;border:3px solid rgba(240,168,48,.18);border-top-color:var(--gold);animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:900px){
  .nav{padding:0 18px}
  .hero{flex-direction:column;align-items:stretch}
  .grid{grid-template-columns:repeat(2,1fr)}
  .two{grid-template-columns:1fr}
  .actions{grid-template-columns:1fr}
}
@media(max-width:520px){
  .grid{grid-template-columns:1fr}
  .brand-sub{display:none}
}
</style>
</head>
<body>
<div id="checkoutOverlay" class="checkout-overlay">
  <div class="checkout-card">
    <div class="checkout-spinner"></div>
    <h3>Preparing checkout</h3>
    <p>LidaShield is opening Stripe's secure payment page. This can take a moment in sandbox mode.</p>
  </div>
</div>

<div class="page">
  <nav class="nav">
    <a class="brand" href="/">
      <img class="logo" src="/static/lidashield-icon.png" alt="LidaShield logo">
      <div>
        <div class="brand-name">LidaShield</div>
        <div class="brand-sub">Scam Intelligence</div>
      </div>
    </a>
    <div class="nav-actions">
      <a class="btn" href="/">Scanner</a>
      <a class="btn" href="/logout">Logout</a>
    </div>
  </nav>

  <main class="wrap">
    <section class="hero">
      <div>
        <div class="kicker">Account Dashboard</div>
        <h1>Your protection<br>command centre.</h1>
        <p class="hero-copy">
          Track your scans, reports, plan usage, and LidaShield's growing scam intelligence database.
        </p>
      </div>

      <div class="profile-card">
        <div class="profile-row">
          <img id="avatar" class="avatar" alt="">
          <div>
            <div id="profileName" class="profile-name">Loading...</div>
            <div id="profileEmail" class="profile-email"></div>
          </div>
        </div>
        <div id="profilePlan" class="plan">free</div>
      </div>
    </section>

    <section class="grid">
      <div class="card">
        <div id="scansToday" class="num">0</div>
        <div class="label">Scans today</div>
      </div>
      <div class="card">
        <div id="scanLimit" class="num">0</div>
        <div class="label">Daily limit</div>
      </div>
      <div class="card">
        <div id="totalScans" class="num">0</div>
        <div class="label">Total scans</div>
      </div>
      <div class="card">
        <div id="messageChecks" class="num">0</div>
        <div class="label">Message checks</div>
      </div>
      <div class="card">
        <div id="dbTotal" class="num">0</div>
        <div class="label">Database indicators</div>
      </div>
    </section>

    <section class="actions">
      <div class="action">
        <h3>Scan a link</h3>
        <p>Check a suspicious WhatsApp, SMS, email, or social media link.</p>
        <a class="btn gold" href="/">Open scanner</a>
      </div>
      <div class="action">
        <h3>Check a message</h3>
        <p>Analyze a suspicious SMS or WhatsApp message using LidaShield's zero-cost signal engine.</p>
        <a class="btn gold" href="/#message-checker">Open message checker</a>
      </div>
      <div class="action">
        <h3>Upgrade protection</h3>
        <p>Unlock more scans, saved history, and early access to SMS checking.</p>
        <button class="btn gold" onclick="upgrade('shield')">Upgrade Shield</button>
      </div>
      <div class="action">
        <h3>Admin intelligence</h3>
        <p>Admin-only database tools for feed import and intelligence growth.</p>
        <a class="btn" href="/admin/database-stats">Database stats</a>
      </div>
    </section>

    <section class="two">
      <div class="card">
        <div class="section-title">Recent scans</div>
        <div id="recentScans" class="list">
          <div class="item"><span class="item-main">Loading...</span></div>
        </div>
      </div>

      <div class="card">
        <div class="section-title">Recent message checks</div>
        <div id="recentMessages" class="list">
          <div class="item"><span class="item-main">Loading...</span></div>
        </div>
      </div>

      <div class="card">
        <div class="section-title">Your reports</div>
        <div id="reportStats" class="list">
          <div class="item"><span class="item-main">Loading...</span></div>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
const $ = (id) => document.getElementById(id);

function escapeHtml(str){
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadDashboard(){
  try{
    const res = await fetch("/api/dashboard");
    const data = await res.json();

    if(!res.ok){
      throw new Error(data.error || "Dashboard failed.");
    }

    $("profileName").textContent = data.user.name || data.user.email;
    $("profileEmail").textContent = data.user.email;
    $("profilePlan").textContent = data.user.plan || "free";

    if(data.user.avatar_url){
      $("avatar").src = data.user.avatar_url;
    }

    $("scansToday").textContent = data.usage.scans_used_today || 0;
    $("scanLimit").textContent = data.usage.scan_limit || 0;
    $("totalScans").textContent = data.total_scans || 0;
    $("messageChecks").textContent = data.message_checks?.total || 0;
    $("dbTotal").textContent = data.database.total_indicators || 0;

    const scans = data.recent_scans || [];
    if(scans.length === 0){
      $("recentScans").innerHTML = `<div class="item"><span class="item-main">No scans yet.</span><span class="badge unknown">empty</span></div>`;
    }else{
      $("recentScans").innerHTML = scans.map(scan => {
        const verdict = scan.verdict || "unknown";
        return `
          <div class="item">
            <span class="item-main">${escapeHtml(scan.url)}</span>
            <span class="badge ${escapeHtml(verdict)}">${escapeHtml(verdict)}</span>
          </div>
        `;
      }).join("");
    }

    const messages = data.message_checks?.recent || [];
    if(messages.length === 0){
      $("recentMessages").innerHTML = `<div class="item"><span class="item-main">No message checks yet.</span><span class="badge unknown">empty</span></div>`;
    }else{
      $("recentMessages").innerHTML = messages.map(item => {
        const verdict = item.verdict || "unknown";
        const preview = (item.message || "").slice(0, 90);
        return `
          <div class="item">
            <span class="item-main">${escapeHtml(preview)}${(item.message || "").length > 90 ? "..." : ""}</span>
            <span class="badge ${escapeHtml(verdict)}">${escapeHtml(verdict)} ${item.score ?? 0}</span>
          </div>
        `;
      }).join("");
    }

    const reports = data.reports.by_status || [];
    if(reports.length === 0){
      $("reportStats").innerHTML = `<div class="item"><span class="item-main">No reports submitted yet.</span><span class="badge unknown">empty</span></div>`;
    }else{
      $("reportStats").innerHTML = reports.map(row => {
        return `
          <div class="item">
            <span class="item-main">${escapeHtml(row.status)}</span>
            <span class="badge suspicious">${row.count}</span>
          </div>
        `;
      }).join("");
    }
  }catch(e){
    document.body.innerHTML = `<pre class="error">${escapeHtml(e.message || "Dashboard failed.")}</pre>`;
  }
}

async function upgrade(plan){
  const overlay = $("checkoutOverlay");

  try{
    if(overlay){
      overlay.classList.add("show");
    }

    document.querySelectorAll("button, .btn").forEach(el => {
      if(el.textContent.toLowerCase().includes("upgrade")){
        el.dataset.originalText = el.textContent;
        el.textContent = "Preparing checkout...";
        el.disabled = true;
      }
    });

    const res = await fetch("/create-checkout-session", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({plan})
    });

    const data = await res.json();

    if(!res.ok){
      throw new Error(data.error || "Could not start checkout.");
    }

    window.location.href = data.url;
  }catch(e){
    if(overlay){
      overlay.classList.remove("show");
    }

    document.querySelectorAll("button, .btn").forEach(el => {
      if(el.dataset.originalText){
        el.textContent = el.dataset.originalText;
        el.disabled = false;
      }
    });

    alert(e.message || "Stripe checkout is not ready yet.");
  }
}

loadDashboard();
</script>
</body>
</html>
"""

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
    """

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)

    _db_ready = True


@app.before_request
def before_request():
    # Professional canonical-domain fix:
    # keep sessions, Google login, dashboard, and scanner on one domain.
    # Without this, lidashield.com and www.lidashield.com can behave like separate sites.
    if request.host == "lidashield.com":
        target = "https://www.lidashield.com" + request.full_path
        if target.endswith("?"):
            target = target[:-1]
        return redirect(target, code=301)

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


def admin_email_set():
    return {
        email.strip().lower()
        for email in ADMIN_EMAILS.split(",")
        if email.strip()
    }


def is_admin(user=None):
    if user is None:
        user = get_current_user()

    if not user:
        return False

    allowed = admin_email_set()
    email = (user.get("email") or "").lower()

    return bool(email and email in allowed)


def require_admin():
    user = get_current_user()

    if not user:
        session["next_url"] = request.full_path if request.query_string else request.path
        return None, redirect(url_for("login"))

    if not ADMIN_EMAILS:
        return None, (
            jsonify({
                "error": "ADMIN_EMAILS is not configured in Render.",
                "fix": "Add ADMIN_EMAILS with your Google account email, then redeploy."
            }),
            500
        )

    if not is_admin(user):
        return None, (
            jsonify({
                "error": "Forbidden.",
                "details": "Your signed-in Google email is not listed in ADMIN_EMAILS."
            }),
            403
        )

    return user, None


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

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/"):
        session["next_url"] = next_url

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
    next_url = session.pop("next_url", "/dashboard")
    return redirect(next_url)


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
# Dashboard routes
# ============================================================

@app.route("/dashboard")
def dashboard():
    user = get_current_user()

    if not user:
        session["next_url"] = "/dashboard"
        return redirect(url_for("login"))

    return render_template_string(DASHBOARD_HTML)


@app.route("/api/dashboard")
def api_dashboard():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Please sign in first."}), 401

    plan = user.get("plan", "free")
    scan_limit = get_plan_limit(plan)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT scans_used
                FROM usage_limits
                WHERE user_id = %s AND scan_date = CURRENT_DATE
                """,
                (user["id"],)
            )
            usage_row = cur.fetchone()
            scans_used_today = usage_row["scans_used"] if usage_row else 0

            cur.execute(
                """
                SELECT COUNT(*) AS count
                FROM scan_history
                WHERE user_id = %s
                """,
                (user["id"],)
            )
            total_scans = cur.fetchone()["count"]

            cur.execute(
                """
                SELECT url, verdict, source, scanned_at
                FROM scan_history
                WHERE user_id = %s
                ORDER BY scanned_at DESC
                LIMIT 10
                """,
                (user["id"],)
            )
            recent_scans = cur.fetchall()

            cur.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM scam_reports
                WHERE user_id = %s
                GROUP BY status
                ORDER BY count DESC
                """,
                (user["id"],)
            )
            reports_by_status = cur.fetchall()

            cur.execute(
                """
                SELECT COUNT(*) AS count
                FROM message_checks
                WHERE user_id = %s
                """,
                (user["id"],)
            )
            total_message_checks = cur.fetchone()["count"]

            cur.execute(
                """
                SELECT message, verdict, score, created_at
                FROM message_checks
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 8
                """,
                (user["id"],)
            )
            recent_message_checks = cur.fetchall()

            cur.execute("SELECT COUNT(*) AS count FROM scam_urls")
            total_indicators = cur.fetchone()["count"]

            cur.execute(
                """
                SELECT source, COUNT(*) AS count
                FROM scam_urls
                GROUP BY source
                ORDER BY count DESC
                """
            )
            indicators_by_source = cur.fetchall()

    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user.get("name"),
            "avatar_url": user.get("avatar_url"),
            "plan": plan
        },
        "usage": {
            "scans_used_today": scans_used_today,
            "scan_limit": scan_limit
        },
        "total_scans": total_scans,
        "recent_scans": recent_scans,
        "message_checks": {
            "total": total_message_checks,
            "recent": recent_message_checks
        },
        "reports": {
            "by_status": reports_by_status
        },
        "database": {
            "total_indicators": total_indicators,
            "by_source": indicators_by_source
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
        "score": 0,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "flagged": [],
        "flagged_total": 0,
        "source": "lidashield_unverified",
        "known_by_lidashield": False,
        "message": "No verified scam evidence was found in LidaShield yet. This does not prove the link is safe; it only means LidaShield has not verified it as suspicious."
    }

    save_scan_history(user["id"] if user else None, raw_url, normalized_url, result)

    return jsonify({
        **result,
        **usage
    })



# ============================================================
# SMS / WhatsApp scam message checker
# ============================================================

URL_PATTERN = re.compile(r"""
    (?:(?:https?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)
""", re.VERBOSE)

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "s.id", "shorturl.at", "lnkd.in"
}

BANK_GOV_TERMS = [
    "dbs", "posb", "ocbc", "uob", "maybank", "bank", "singpass", "cpf", "iras",
    "mom", "ica", "gov.sg", "police", "singapore customs", "lta", "hdb"
]

URGENCY_TERMS = [
    "urgent", "immediately", "within 24 hours", "limited time", "final warning",
    "account suspended", "account locked", "verify now", "act now", "failure to",
    "last chance", "blocked", "restricted"
]

CREDENTIAL_TERMS = [
    "otp", "one time password", "password", "pin", "cvv", "login", "verify your account",
    "authentication", "security code", "2fa", "passcode", "credentials"
]

MONEY_TERMS = [
    "prize", "winner", "claim", "refund", "investment", "crypto", "usdt", "bitcoin",
    "transfer", "fee", "loan", "grant", "parcel fee", "delivery fee", "compensation"
]


def extract_urls_from_text(text):
    found = []
    for match in URL_PATTERN.findall(text or ""):
        cleaned = match.strip().rstrip(".,);!?'\"")
        if "." in cleaned and cleaned not in found:
            found.append(cleaned)
    return found[:10]


def domain_from_url(raw_url):
    try:
        normalized = normalize_url(raw_url)
        return urlparse(normalized).netloc.lower()
    except Exception:
        return ""


def contains_any(text, terms):
    text_lower = (text or "").lower()
    return [term for term in terms if term in text_lower]


def analyze_scam_message(message):
    text = message.strip()
    text_lower = text.lower()
    extracted_urls = extract_urls_from_text(text)

    score = 0
    reasons = []
    database_hits = []

    if extracted_urls:
        score += 10
        reasons.append("Message contains one or more links.")

    urgency_hits = contains_any(text_lower, URGENCY_TERMS)
    if urgency_hits:
        score += 18
        reasons.append("Uses urgency or pressure language.")

    credential_hits = contains_any(text_lower, CREDENTIAL_TERMS)
    if credential_hits:
        score += 28
        reasons.append("Mentions login details, OTP, password, PIN, or account verification.")

    bank_gov_hits = contains_any(text_lower, BANK_GOV_TERMS)
    if bank_gov_hits:
        score += 18
        reasons.append("Mentions a bank, government service, or official institution.")

    money_hits = contains_any(text_lower, MONEY_TERMS)
    if money_hits:
        score += 18
        reasons.append("Mentions money, refunds, prizes, fees, loans, parcels, crypto, or transfers.")

    for url in extracted_urls:
        domain = domain_from_url(url)
        if domain in SHORTENER_DOMAINS:
            score += 18
            reasons.append(f"Uses a shortened link: {domain}.")

        try:
            normalized = normalize_url(url)
            known = lookup_own_database(normalized)
            if known:
                hit = {
                    "url": url,
                    "normalized_url": normalized,
                    "verdict": known.get("verdict"),
                    "source": known.get("source"),
                    "notes": known.get("notes")
                }
                database_hits.append(hit)

                if known.get("verdict") == "dangerous":
                    score += 70
                    reasons.append(f"Link found in LidaShield verified threat database: {domain or url}.")
                elif known.get("verdict") == "suspicious":
                    score += 45
                    reasons.append(f"Link found as suspicious in LidaShield database: {domain or url}.")
        except Exception:
            pass

    if extracted_urls and len(text) < 90 and score < 35:
        score += 10
        reasons.append("Short message with a link, which is common in phishing attempts.")

    score = min(100, score)

    if score >= 75:
        verdict = "dangerous"
    elif score >= 45:
        verdict = "suspicious"
    elif score > 0:
        verdict = "unknown"
    else:
        verdict = "safe"
        reasons.append("No major scam signals were detected by LidaShield's zero-cost rules.")

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons[:8],
        "extracted_urls": extracted_urls,
        "database_hits": database_hits,
        "signal_count": max(0, len(reasons))
    }


def save_message_check(user_id, message, analysis):
    if not DATABASE_URL:
        return

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO message_checks
                (user_id, message, verdict, score, reasons, extracted_urls)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    message,
                    analysis.get("verdict"),
                    analysis.get("score", 0),
                    json.dumps(analysis.get("reasons", [])),
                    json.dumps(analysis.get("extracted_urls", [])),
                )
            )


@app.route("/check-message", methods=["POST"])
def check_message():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "Paste an SMS, WhatsApp message, or email text first."}), 400

    if len(message) > 5000:
        return jsonify({"error": "Message is too long. Keep it under 5000 characters."}), 400

    user = get_current_user()
    analysis = analyze_scam_message(message)
    save_message_check(user["id"] if user else None, message, analysis)

    return jsonify({
        "ok": True,
        "message": message,
        **analysis
    })


# ============================================================
# Admin feed import
# ============================================================

def upsert_scam_indicator(cur, url, verdict, source, notes, malicious=0, suspicious=0, harmless=0, undetected=0):
    normalized_url = normalize_url(url)

    cur.execute(
        """
        INSERT INTO scam_urls
        (url, normalized_url, verdict, source, notes, malicious, suspicious, harmless, undetected, report_count)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1)
        ON CONFLICT (normalized_url)
        DO UPDATE SET
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
            url,
            normalized_url,
            verdict,
            source,
            notes,
            malicious,
            suspicious,
            harmless,
            undetected,
        )
    )


def import_urlhaus(cur, limit):
    """
    Imports recent malware URLs from URLhaus.
    Source format is CSV with comment lines starting with #.
    """
    feed_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    response = requests.get(feed_url, timeout=30)
    response.raise_for_status()

    imported = 0
    skipped = 0

    csv_text = "\n".join(
        line for line in response.text.splitlines()
        if line and not line.startswith("#")
    )

    reader = csv.reader(io.StringIO(csv_text))

    for row in reader:
        if imported >= limit:
            break

        try:
            # Expected row layout:
            # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            if len(row) < 3:
                skipped += 1
                continue

            url = row[2].strip().strip('"')

            if not url:
                skipped += 1
                continue

            upsert_scam_indicator(
                cur,
                url=url,
                verdict="dangerous",
                source="urlhaus",
                notes="Imported from URLhaus recent malware URL feed.",
                malicious=4,
                suspicious=0,
                harmless=0,
                undetected=0,
            )
            imported += 1

        except Exception:
            skipped += 1

    return {"source": "urlhaus", "imported": imported, "skipped": skipped}


def import_openphish(cur, limit):
    """
    Imports phishing URLs from the OpenPhish community feed.
    The community feed is a plain text list of URLs.
    """
    feed_url = "https://openphish.com/feed.txt"
    response = requests.get(feed_url, timeout=30)
    response.raise_for_status()

    imported = 0
    skipped = 0

    for line in response.text.splitlines():
        if imported >= limit:
            break

        url = line.strip()

        if not url or url.startswith("#"):
            continue

        try:
            upsert_scam_indicator(
                cur,
                url=url,
                verdict="dangerous",
                source="openphish",
                notes="Imported from OpenPhish phishing feed.",
                malicious=2,
                suspicious=4,
                harmless=0,
                undetected=0,
            )
            imported += 1

        except Exception:
            skipped += 1

    return {"source": "openphish", "imported": imported, "skipped": skipped}


@app.route("/admin/import-feeds")
def admin_import_feeds():
    """
    Admin-only route for importing free threat feeds into LidaShield.

    Security model:
    - User must sign in with Google.
    - User's email must be listed in ADMIN_EMAILS in Render.

    Safer usage:
    /admin/import-feeds?source=openphish&limit=50
    /admin/import-feeds?source=urlhaus&limit=50
    /admin/import-feeds?source=all&limit=50
    """

    try:
        admin_user, admin_error = require_admin()
        if admin_error:
            return admin_error

        source = (request.args.get("source") or "openphish").lower().strip()

        try:
            limit = int(request.args.get("limit", "50"))
        except ValueError:
            limit = 50

        limit = max(1, min(limit, 500))

        if source not in ("openphish", "urlhaus", "all"):
            return jsonify({
                "error": "Invalid source.",
                "allowed_sources": ["openphish", "urlhaus", "all"]
            }), 400

        if not DATABASE_URL:
            return jsonify({"error": "Database is not configured."}), 500

        results = []

        # Use autocommit so one bad URL/row cannot poison the whole transaction.
        conn = get_db()
        conn.autocommit = True

        try:
            with conn.cursor() as cur:
                if source in ("openphish", "all"):
                    try:
                        results.append(import_openphish(cur, limit))
                    except Exception as e:
                        app.logger.exception("OpenPhish import failed")
                        results.append({
                            "source": "openphish",
                            "error": str(e),
                            "type": type(e).__name__
                        })

                if source in ("urlhaus", "all"):
                    try:
                        results.append(import_urlhaus(cur, limit))
                    except Exception as e:
                        app.logger.exception("URLhaus import failed")
                        results.append({
                            "source": "urlhaus",
                            "error": str(e),
                            "type": type(e).__name__
                        })
        finally:
            conn.close()

        return jsonify({
            "ok": True,
            "message": "Feed import completed.",
            "admin": admin_user.get("email"),
            "source_requested": source,
            "limit_per_source": limit,
            "results": results
        })

    except Exception as e:
        app.logger.exception("Admin import route failed")
        return jsonify({
            "error": "Admin import failed",
            "details": str(e),
            "type": type(e).__name__,
            "fix_hint": "Try /admin/import-test-record first. Then try /admin/import-feeds?source=openphish&limit=10."
        }), 500


@app.route("/admin/import-test-record")
def admin_import_test_record():
    """
    Inserts one test dangerous URL into LidaShield's own database.
    This verifies that admin auth and Supabase writes work before using live feeds.
    """

    try:
        admin_user, admin_error = require_admin()
        if admin_error:
            return admin_error

        if not DATABASE_URL:
            return jsonify({"error": "Database is not configured."}), 500

        test_url = "https://lidashield-admin-test-dangerous.example"

        conn = get_db()
        conn.autocommit = True

        try:
            with conn.cursor() as cur:
                upsert_scam_indicator(
                    cur,
                    url=test_url,
                    verdict="dangerous",
                    source="admin_test",
                    notes="Admin test record inserted to verify LidaShield database writes.",
                    malicious=4,
                    suspicious=0,
                    harmless=0,
                    undetected=0,
                )
        finally:
            conn.close()

        return jsonify({
            "ok": True,
            "message": "Admin test record inserted.",
            "admin": admin_user.get("email"),
            "test_url": test_url,
            "next_step": "Scan this test_url on LidaShield. It should show Dangerous from the LidaShield database."
        })

    except Exception as e:
        app.logger.exception("Admin test record import failed")
        return jsonify({
            "error": "Admin test record import failed",
            "details": str(e),
            "type": type(e).__name__
        }), 500


@app.route("/admin/database-stats")
def admin_database_stats():
    """
    Admin route for checking database size.
    Requires Google sign-in and ADMIN_EMAILS match.
    """

    try:
        admin_user, admin_error = require_admin()
        if admin_error:
            return admin_error

        if not DATABASE_URL:
            return jsonify({"error": "Database is not configured."}), 500

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS count FROM scam_urls")
                total = cur.fetchone()["count"]

                cur.execute(
                    """
                    SELECT source, COUNT(*) AS count
                    FROM scam_urls
                    GROUP BY source
                    ORDER BY count DESC
                    """
                )
                by_source = cur.fetchall()

                cur.execute(
                    """
                    SELECT verdict, COUNT(*) AS count
                    FROM scam_urls
                    GROUP BY verdict
                    ORDER BY count DESC
                    """
                )
                by_verdict = cur.fetchall()

        return jsonify({
            "ok": True,
            "admin": admin_user.get("email"),
            "total_indicators": total,
            "by_source": by_source,
            "by_verdict": by_verdict
        })

    except Exception as e:
        app.logger.exception("Admin database stats failed")
        return jsonify({
            "error": "Admin database stats failed",
            "details": str(e),
            "type": type(e).__name__
        }), 500


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
        success_url=f"{APP_URL}/dashboard?billing=success",
        cancel_url=f"{APP_URL}/dashboard?billing=cancelled",
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
