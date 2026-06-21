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
import hashlib
import html

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
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=APP_URL.startswith("https://"),
    MAX_CONTENT_LENGTH=128 * 1024
)

# Lightweight in-memory abuse controls. This is enough for beta; later move to Redis/Cloudflare for scale.
_RATE_LIMIT_BUCKETS = {}
RATE_LIMIT_RULES = {
    "/scan": (40, 60),
    "/report": (8, 60),
    "/check-message": (25, 60),
    "/create-checkout-session": (8, 60),
    "/billing/portal": (12, 60),
    "/api/feedback": (8, 60),
}

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
        <p>Analyze a suspicious SMS or WhatsApp message using LidaShield's scam-signal engine.</p>
        <a class="btn gold" href="/#message-checker">Open message checker</a>
      </div>
      <div class="action">
        <h3>Upgrade protection</h3>
        <p>Unlock full explanations, saved history, and higher scan limits.</p>
        <button class="btn gold" onclick="upgrade('shield')">Upgrade Shield</button>
      </div>
      <div id="billingAction" class="action" style="display:none;">
        <h3>Manage subscription</h3>
        <p>Open Stripe's secure billing portal to update, cancel, or manage your plan.</p>
        <button class="btn" onclick="manageBilling()">Manage billing</button>
      </div>
      <div id="adminAction" class="action" style="display:none;">
        <h3>Admin intelligence</h3>
        <p>Admin-only database tools for report review and intelligence growth.</p>
        <a class="btn gold" href="/admin/reports">Review reports</a>
        <a class="btn" href="/admin/database-stats" style="margin-left:8px;">Database stats</a>
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

    const currentPlan = (data.user.plan || "free").toLowerCase();
    document.querySelectorAll("button").forEach(btn => {
      const txt = btn.textContent.toLowerCase();
      if(currentPlan === "shield" && txt.includes("upgrade shield")){
        btn.textContent = "Current plan";
        btn.disabled = true;
      }
      if(currentPlan === "pro" && txt.includes("upgrade")){
        btn.textContent = "Current plan";
        btn.disabled = true;
      }
    });

    if(data.user.avatar_url){
      $("avatar").src = data.user.avatar_url;
    }

    if($("adminAction") && data.admin && data.admin.is_admin){
      $("adminAction").style.display = "block";
    }

    if($("billingAction") && (currentPlan === "shield" || currentPlan === "pro")){
      $("billingAction").style.display = "block";
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

function resetCheckoutState(){
  const overlay = $("checkoutOverlay");

  if(overlay){
    overlay.classList.remove("show");
  }

  document.querySelectorAll("button, .btn").forEach(el => {
    if(el.dataset.originalText){
      el.textContent = el.dataset.originalText;
      el.disabled = false;
      delete el.dataset.originalText;
    }
  });
}

window.addEventListener("pageshow", resetCheckoutState);
window.addEventListener("focus", resetCheckoutState);
document.addEventListener("visibilitychange", () => {
  if(!document.hidden){
    resetCheckoutState();
  }
});

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


async function manageBilling(){
  const overlay = $("checkoutOverlay");

  try{
    if(overlay){
      overlay.classList.add("show");
      const title = overlay.querySelector("h3");
      const copy = overlay.querySelector("p");
      if(title){ title.textContent = "Opening billing portal"; }
      if(copy){ copy.textContent = "LidaShield is opening Stripe's secure subscription management page."; }
    }

    document.querySelectorAll("button, .btn").forEach(el => {
      if(el.textContent.toLowerCase().includes("manage billing")){
        el.dataset.originalText = el.textContent;
        el.textContent = "Opening billing...";
        el.disabled = true;
      }
    });

    const res = await fetch("/billing/portal", {
      method:"POST",
      headers:{"Content-Type":"application/json"}
    });

    const data = await res.json();

    if(!res.ok){
      throw new Error(data.error || "Could not open billing portal.");
    }

    window.location.href = data.url;
  }catch(e){
    resetCheckoutState();
    alert(e.message || "Billing portal is not ready yet.");
  }
}

loadDashboard();
</script>
</body>
</html>
"""

_db_ready = False



# ============================================================
# Security helpers
# ============================================================

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
            "retry_after": max(1, retry_after)
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(max(1, retry_after))
        return response

    hits.append(now)
    _RATE_LIMIT_BUCKETS[key] = hits

    # Small cleanup to prevent unbounded memory growth in long-running workers.
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

    # Stripe cannot send browser Origin headers; webhook has its own signature verification.
    if request.path == "/stripe/webhook":
        return True

    protected_paths = (
        "/scan",
        "/report",
        "/check-message",
        "/create-checkout-session",
        "/billing/portal",
        "/api/feedback",
    )

    if not (request.path in protected_paths or request.path.startswith("/admin/api/")):
        return True

    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")

    expected_host = request.host
    allowed_hosts = {expected_host, "www.lidashield.com", "lidashield.com"}

    if origin:
        parsed = urlparse(origin)
        return parsed.netloc in allowed_hosts

    if referer:
        parsed = urlparse(referer)
        return parsed.netloc in allowed_hosts

    # Same-origin fetch usually sends Origin for POST. If neither exists, block protected browser APIs.
    return False


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
    response.headers.setdefault("Cache-Control", "no-store" if request.path.startswith(("/dashboard", "/admin")) else "public, max-age=300")
    return response


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

    CREATE TABLE IF NOT EXISTS intelligence_events (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        report_id INT REFERENCES scam_reports(id) ON DELETE SET NULL,
        url TEXT,
        normalized_url TEXT,
        domain TEXT,
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

    CREAT
