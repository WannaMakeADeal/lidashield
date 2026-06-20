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
    """

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)
            cur.execute("ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP")
            cur.execute("ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS reviewed_by INT REFERENCES users(id) ON DELETE SET NULL")
            cur.execute("ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS review_notes TEXT")
            cur.execute("ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS triage_score INT DEFAULT 0")
            cur.execute("ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS triage_status TEXT DEFAULT 'watchlist'")
            cur.execute("ALTER TABLE scam_reports ADD COLUMN IF NOT EXISTS triage_reasons TEXT")
            cur.execute("ALTER TABLE intelligence_events ADD COLUMN IF NOT EXISTS entity_key TEXT")
            cur.execute("ALTER TABLE intelligence_events ADD COLUMN IF NOT EXISTS duplicate_count INT DEFAULT 1")
            cur.execute("ALTER TABLE intelligence_events ADD COLUMN IF NOT EXISTS signal_source_count INT DEFAULT 1")
            cur.execute("ALTER TABLE intelligence_events ADD COLUMN IF NOT EXISTS resolution TEXT")
            cur.execute("ALTER TABLE intelligence_events ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW()")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_intelligence_events_status ON intelligence_events(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_intelligence_events_normalized_url ON intelligence_events(normalized_url)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_intelligence_events_domain ON intelligence_events(domain)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_intelligence_events_entity_key ON intelligence_events(entity_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scam_reports_triage_status ON scam_reports(triage_status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scam_reports_normalized_url ON scam_reports(normalized_url)")

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

    if not is_same_origin_post_allowed():
        return jsonify({"error": "Blocked cross-site request.", "details": "Request origin did not match LidaShield."}), 403

    limited = check_rate_limit()
    if limited:
        return limited

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


def extract_domain(normalized_url):
    try:
        parsed = urlparse(normalized_url if normalized_url.startswith(("http://", "https://")) else "https://" + normalized_url)
        return (parsed.netloc or "").lower().replace("www.", "", 1)
    except Exception:
        return ""


def is_ip_address(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""))


def triage_report_signal(raw_url="", message="", user_id=None):
    """LidaShield Intelligence Engine v2: score, dedupe, and auto-sort reports."""

    raw_url = (raw_url or "").strip()
    message = (message or "").strip()
    score = 0
    reasons = []
    normalized_url = None
    domain = ""
    duplicate_count = 0
    distinct_reporters = 0
    existing_intel_events = 0
    resolution = "needs_more_evidence"

    if raw_url:
        try:
            normalized_url = normalize_url(raw_url)
            domain = extract_domain(normalized_url)
        except ValueError:
            return {"score": 5, "status": "auto_rejected", "reasons": ["Invalid URL format"], "normalized_url": None, "domain": "", "duplicate_count": 1, "distinct_reporters": 0, "resolution": "invalid_url"}

    if domain:
        reserved_domains = (".example", ".test", ".invalid", ".localhost")
        if domain.endswith(reserved_domains) or domain in ("example.com", "example.org", "example.net"):
            return {"score": 0, "status": "auto_rejected", "reasons": ["Reserved/test domain detected; not treated as real threat intelligence"], "normalized_url": normalized_url, "domain": domain, "duplicate_count": 1, "distinct_reporters": 0, "resolution": "test_or_reserved_domain"}

    if normalized_url and DATABASE_URL:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT verdict, source FROM scam_urls WHERE normalized_url = %s LIMIT 1", (normalized_url,))
                    existing = cur.fetchone()
                    if existing and existing.get("verdict") == "dangerous":
                        score += 90
                        resolution = "verified_database_match"
                        reasons.append(f"Already verified as dangerous in LidaShield database via {existing.get('source') or 'database'}")

                    cur.execute(
                        """
                        SELECT COUNT(*) AS total_reports,
                               COUNT(DISTINCT COALESCE(user_id, -id)) AS distinct_reporters
                        FROM scam_reports
                        WHERE normalized_url = %s
                        """,
                        (normalized_url,)
                    )
                    rep = cur.fetchone() or {}
                    duplicate_count = int(rep.get("total_reports") or 0)
                    distinct_reporters = int(rep.get("distinct_reporters") or 0)

                    cur.execute("SELECT COUNT(*) AS total_events FROM intelligence_events WHERE normalized_url = %s", (normalized_url,))
                    ev = cur.fetchone() or {}
                    existing_intel_events = int(ev.get("total_events") or 0)

                    if duplicate_count >= 1:
                        score += min(18, duplicate_count * 4)
                        reasons.append(f"Duplicate report history: {duplicate_count} previous report(s) for this URL")
                    if distinct_reporters >= 2:
                        score += min(24, distinct_reporters * 8)
                        reasons.append(f"Multiple independent reporters: {distinct_reporters}")
                    if existing_intel_events >= 1:
                        score += min(10, existing_intel_events * 3)
                        reasons.append(f"Existing intelligence events for this URL: {existing_intel_events}")
        except Exception:
            reasons.append("Database evidence lookup unavailable during triage")

    combined = f"{raw_url} {message}".lower()
    high_risk_terms = ["otp", "password", "login", "verify", "verification", "account suspended", "suspended", "bank", "wallet", "paypal", "paynow", "singpass", "dbs", "ocbc", "uob", "refund", "prize", "claim", "parcel", "delivery", "urgent", "within 24", "click", "security alert", "confirm your account"]
    hits = [term for term in high_risk_terms if term in combined]
    if hits:
        score += min(35, 8 * len(hits))
        reasons.append("Suspicious scam-language signals: " + ", ".join(hits[:6]))

    if domain:
        if is_ip_address(domain):
            score += 20
            reasons.append("URL uses raw IP address instead of normal domain")
        if domain.startswith("xn--"):
            score += 25
            reasons.append("Domain uses punycode, which can be used for impersonation")
        if domain.count("-") >= 3:
            score += 12
            reasons.append("Domain contains many hyphens")
        suspicious_tlds = (".xyz", ".top", ".click", ".cyou", ".quest", ".mom", ".rest", ".sbs")
        if domain.endswith(suspicious_tlds):
            score += 12
            reasons.append("Domain uses a high-risk low-trust TLD pattern")
        brand_terms = ["dbs", "ocbc", "uob", "singpass", "paypal", "google", "microsoft", "apple"]
        official_domains = ["dbs.com", "ocbc.com", "uob.com.sg", "paypal.com", "google.com", "microsoft.com", "apple.com"]
        if any(b in domain for b in brand_terms) and not any(domain.endswith(good) for good in official_domains):
            score += 25
            reasons.append("Domain appears to contain a trusted brand name but is not an official domain")

    if raw_url and len(raw_url) > 120:
        score += 10
        reasons.append("URL is unusually long")

    score = max(0, min(100, score))

    if score >= 90:
        status = "verified" if resolution == "verified_database_match" else "high_risk"
    elif score >= 65:
        status = "high_risk"
    elif score >= 25:
        status = "watchlist"
    else:
        status = "low_signal"

    if status == "high_risk" and resolution == "needs_more_evidence":
        resolution = "auto_triaged_high_risk"
    elif status == "watchlist" and resolution == "needs_more_evidence":
        resolution = "watchlist"
    elif status == "low_signal" and resolution == "needs_more_evidence":
        resolution = "low_signal"

    if not reasons:
        reasons.append("No strong automated evidence found yet")

    return {"score": score, "status": status, "reasons": reasons, "normalized_url": normalized_url, "domain": domain, "duplicate_count": duplicate_count + 1 if normalized_url else 1, "distinct_reporters": distinct_reporters, "existing_intel_events": existing_intel_events, "resolution": resolution}


def insert_intelligence_event(cur, user_id=None, report_id=None, raw_url=None, message=None, triage=None, source="community_report", evidence_type="community_report"):
    triage = triage or triage_report_signal(raw_url, message, user_id=user_id)
    normalized_url = triage.get("normalized_url")
    domain = triage.get("domain") or (extract_domain(normalized_url) if normalized_url else "")
    message_hash = hashlib.sha256((message or "").encode("utf-8")).hexdigest() if message else None
    reason = "; ".join(triage.get("reasons") or [])
    entity_key = normalized_url or (f"message:{message_hash}" if message_hash else None)

    cur.execute(
        """
        INSERT INTO intelligence_events
        (user_id, report_id, url, normalized_url, domain, message_hash, source, evidence_type,
         confidence_score, reason, status, entity_key, duplicate_count, signal_source_count, resolution, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        RETURNING id
        """,
        (user_id, report_id, raw_url, normalized_url, domain, message_hash, source, evidence_type,
         triage.get("score", 0), reason, triage.get("status", "watchlist"), entity_key,
         triage.get("duplicate_count", 1), max(1, triage.get("distinct_reporters", 0) or 1),
         triage.get("resolution", "needs_more_evidence"))
    )
    return cur.fetchone()


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


def lookup_intelligence_layer(normalized_url):
    """
    Reads LidaShield's intelligence layer for scanner warnings.
    This does NOT mark a link as verified dangerous. It only returns unverified intelligence.
    """
    if not DATABASE_URL:
        return None

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = '4000ms'")
                cur.execute(
                    """
                    SELECT COUNT(*) AS event_count,
                           MAX(COALESCE(confidence_score, 0)) AS max_score
                    FROM intelligence_events
                    WHERE normalized_url = %s
                    """,
                    (normalized_url,)
                )
                ev = cur.fetchone() or {}

                cur.execute(
                    """
                    SELECT COUNT(*) AS report_count,
                           MAX(COALESCE(triage_score, 0)) AS max_report_score
                    FROM scam_reports
                    WHERE normalized_url = %s
                    """,
                    (normalized_url,)
                )
                rep = cur.fetchone() or {}

                cur.execute(
                    """
                    SELECT reason, status, confidence_score
                    FROM intelligence_events
                    WHERE normalized_url = %s
                    ORDER BY confidence_score DESC, created_at DESC
                    LIMIT 1
                    """,
                    (normalized_url,)
                )
                top_event = cur.fetchone()

                cur.execute(
                    """
                    SELECT triage_reasons, triage_status, triage_score
                    FROM scam_reports
                    WHERE normalized_url = %s
                    ORDER BY triage_score DESC, created_at DESC
                    LIMIT 1
                    """,
                    (normalized_url,)
                )
                top_report = cur.fetchone()

        event_count = int(ev.get("event_count") or 0)
        report_count = int(rep.get("report_count") or 0)
        max_score = max(int(ev.get("max_score") or 0), int(rep.get("max_report_score") or 0))

        if event_count == 0 and report_count == 0:
            return None

        reasons = []
        if top_event and top_event.get("reason"):
            reasons.extend([x.strip() for x in str(top_event.get("reason")).split(";") if x.strip()])
        if top_report and top_report.get("triage_reasons"):
            try:
                parsed = json.loads(top_report.get("triage_reasons"))
                if isinstance(parsed, list):
                    reasons.extend([str(x) for x in parsed])
            except Exception:
                reasons.append(str(top_report.get("triage_reasons")))

        # Deduplicate while preserving order.
        seen = set()
        unique_reasons = []
        for reason in reasons:
            key = reason.lower()
            if key not in seen:
                seen.add(key)
                unique_reasons.append(reason)

        if max_score >= 65:
            return {
                "verdict": "suspicious",
                "score": max_score,
                "source": "lidashield_intelligence",
                "event_count": event_count,
                "report_count": report_count,
                "reasons": unique_reasons[:8],
                "message": "LidaShield found unverified high-risk intelligence for this link. This is not a verified dangerous verdict yet, but you should treat it with caution."
            }

        # Only show watchlist intelligence when there is a real risk signal.
        # Duplicate reports with 0 score should not make a normal site look watchlisted.
        if max_score >= 25:
            return {
                "verdict": "unknown",
                "score": max_score,
                "source": "lidashield_watchlist",
                "event_count": event_count,
                "report_count": report_count,
                "reasons": unique_reasons[:8],
                "message": "LidaShield has watchlist intelligence for this link, but not enough verified evidence to mark it as suspicious yet."
            }

        return None

    except Exception as e:
        app.logger.exception("Intelligence lookup failed")
        return None


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
        "admin": {
            "is_admin": is_admin(user)
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

    # 2. Check LidaShield intelligence layer.
    # This is not the verified scam database. It is an unverified warning layer.
    intelligence = lookup_intelligence_layer(normalized_url)

    if intelligence and intelligence.get("verdict") == "suspicious":
        result = {
            "url": raw_url,
            "normalized_url": normalized_url,
            "verdict": "suspicious",
            "score": intelligence.get("score", 0),
            "malicious": 0,
            "suspicious": 1,
            "harmless": 0,
            "undetected": 0,
            "flagged": intelligence.get("reasons", [])[:8],
            "flagged_total": len(intelligence.get("reasons", [])),
            "source": "lidashield_intelligence",
            "known_by_lidashield": False,
            "intelligence_warning": True,
            "intelligence_event_count": intelligence.get("event_count", 0),
            "report_count": intelligence.get("report_count", 0),
            "message": intelligence.get("message")
        }

        save_scan_history(user["id"] if user else None, raw_url, normalized_url, result)

        return jsonify({
            **result,
            **usage
        })

    if intelligence and intelligence.get("source") == "lidashield_watchlist":
        watchlist_message = intelligence.get("message") or "LidaShield has watchlist intelligence for this link, but not enough evidence to warn strongly yet."
    else:
        watchlist_message = "No verified scam evidence was found in LidaShield yet. This does not prove the link is safe; it only means LidaShield has not verified it as suspicious."

    # 3. If not found, do NOT use VirusTotal or any external scanner.
    # Unknown means: not verified in LidaShield yet.
    result = {
        "url": raw_url,
        "normalized_url": normalized_url,
        "verdict": "unknown",
        "score": intelligence.get("score", 0) if intelligence else 0,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "flagged": intelligence.get("reasons", [])[:5] if intelligence else [],
        "flagged_total": len(intelligence.get("reasons", [])) if intelligence else 0,
        "source": "lidashield_watchlist" if intelligence else "lidashield_unverified",
        "known_by_lidashield": False,
        "intelligence_warning": bool(intelligence),
        "message": watchlist_message
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

    plan = user.get("plan", "free") if user else "guest"
    paid_plan = plan in ("shield", "pro")

    # Free/guest users get a useful verdict, but full reasoning is a Shield feature.
    # This gives the paid plan real value without weakening the free tool.
    if not paid_plan:
        full_reason_count = len(analysis.get("reasons", []))
        analysis["full_reason_count"] = full_reason_count
        analysis["reasons"] = analysis.get("reasons", [])[:2]
        analysis["advanced_locked"] = full_reason_count > len(analysis["reasons"])
        analysis["locked_message"] = "Upgrade to Shield to unlock the full scam explanation, all detected signals, and saved protection history."
    else:
        analysis["full_reason_count"] = len(analysis.get("reasons", []))
        analysis["advanced_locked"] = False
        analysis["locked_message"] = ""

    return jsonify({
        "ok": True,
        "message": message,
        "plan": plan,
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




@app.route("/admin/api/intelligence-summary")
def admin_api_intelligence_summary():
    admin_user, admin_error = require_admin()
    if admin_error:
        return admin_error

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = '5000ms'")
                cur.execute("SELECT status, COUNT(*) AS count FROM intelligence_events GROUP BY status ORDER BY count DESC")
                by_status = cur.fetchall()
                cur.execute("SELECT evidence_type, COUNT(*) AS count FROM intelligence_events GROUP BY evidence_type ORDER BY count DESC")
                by_type = cur.fetchall()
                cur.execute(
                    """
                    SELECT id, url, domain, evidence_type, confidence_score, status, reason, created_at::text AS created_at
                    FROM intelligence_events
                    ORDER BY created_at DESC
                    LIMIT 20
                    """
                )
                recent = cur.fetchall()

        return jsonify({"ok": True, "by_status": by_status, "by_type": by_type, "recent": recent})
    except Exception as e:
        app.logger.exception("Intelligence summary failed")
        return jsonify({"ok": False, "error": "Intelligence summary failed", "details": str(e), "type": type(e).__name__}), 500


@app.route('/admin/reports')
def admin_reports_page():
    '''Server-rendered admin intelligence page. No fetch spinner for main data.'''

    admin_user, admin_error = require_admin()
    if admin_error:
        return admin_error

    def e(value):
        return html.escape(str(value if value is not None else ''))

    report_counts = []
    event_counts = []
    reports = []
    events = []
    risky_domains = []
    duplicate_urls = []
    db_error = None

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = '5000ms'")

                cur.execute('''
                    SELECT COALESCE(status, 'pending') AS status, COUNT(*) AS count
                    FROM scam_reports
                    GROUP BY COALESCE(status, 'pending')
                    ORDER BY count DESC, status ASC
                ''')
                report_counts = cur.fetchall()

                cur.execute('''
                    SELECT COALESCE(status, 'watchlist') AS status, COUNT(*) AS count
                    FROM intelligence_events
                    GROUP BY COALESCE(status, 'watchlist')
                    ORDER BY count DESC, status ASC
                ''')
                event_counts = cur.fetchall()

                cur.execute('''
                    SELECT domain, COUNT(*) AS event_count,
                           MAX(COALESCE(confidence_score, 0)) AS max_score,
                           ROUND(AVG(COALESCE(confidence_score, 0))::numeric, 1) AS avg_score
                    FROM intelligence_events
                    WHERE domain IS NOT NULL AND domain <> ''
                    GROUP BY domain
                    ORDER BY max_score DESC, event_count DESC
                    LIMIT 12
                ''')
                risky_domains = cur.fetchall()

                cur.execute('''
                    SELECT normalized_url, COUNT(*) AS report_count,
                           MAX(COALESCE(triage_score, 0)) AS max_score
                    FROM scam_reports
                    WHERE normalized_url IS NOT NULL
                    GROUP BY normalized_url
                    HAVING COUNT(*) > 1
                    ORDER BY report_count DESC, max_score DESC
                    LIMIT 12
                ''')
                duplicate_urls = cur.fetchall()

                cur.execute('''
                    SELECT r.id, r.url, r.normalized_url, r.message, r.category,
                           COALESCE(r.status, 'pending') AS status,
                           COALESCE(r.triage_score, 0) AS triage_score,
                           COALESCE(r.triage_status, 'watchlist') AS triage_status,
                           r.triage_reasons,
                           r.created_at::text AS created_at,
                           u.email AS reporter_email,
                           COUNT(*) OVER (PARTITION BY r.normalized_url) AS duplicate_reports
                    FROM scam_reports r
                    LEFT JOIN users u ON u.id = r.user_id
                    ORDER BY r.created_at DESC
                    LIMIT 30
                ''')
                reports = cur.fetchall()

                cur.execute('''
                    SELECT id, url, domain, evidence_type,
                           COALESCE(confidence_score, 0) AS confidence_score,
                           COALESCE(status, 'watchlist') AS status,
                           COALESCE(duplicate_count, 1) AS duplicate_count,
                           COALESCE(resolution, 'needs_more_evidence') AS resolution,
                           reason,
                           created_at::text AS created_at
                    FROM intelligence_events
                    ORDER BY created_at DESC
                    LIMIT 30
                ''')
                events = cur.fetchall()

    except Exception as ex:
        app.logger.exception('Server-rendered admin reports page failed')
        db_error = f'{type(ex).__name__}: {ex}'

    def status_class(status):
        s = (status or '').lower()
        if s in ('verified', 'approved'):
            return 'good'
        if s in ('high_risk', 'pending', 'watchlist'):
            return 'warn'
        if s in ('rejected', 'auto_rejected', 'low_signal'):
            return 'bad'
        return 'neutral'

    def count_cards(rows):
        if not rows:
            return '<div class="empty-mini">No data yet.</div>'
        return ''.join(f'''<div class="stat-card"><div class="stat-number">{e(row.get('count', 0))}</div><div class="stat-label">{e((row.get('status') or 'unknown').replace('_', ' '))}</div></div>''' for row in rows)

    def domain_rows(rows):
        if not rows:
            return '<div class="empty">No domain intelligence yet.</div>'
        return ''.join(f'''<div class="mini-row"><span>{e(row.get('domain'))}</span><b>{e(row.get('max_score'))}/100</b><small>{e(row.get('event_count'))} event(s)</small></div>''' for row in rows)

    def duplicate_rows(rows):
        if not rows:
            return '<div class="empty">No duplicate URL clusters yet.</div>'
        return ''.join(f'''<div class="mini-row"><span>{e(row.get('normalized_url'))}</span><b>{e(row.get('report_count'))} reports</b><small>max {e(row.get('max_score'))}/100</small></div>''' for row in rows)

    def report_rows(rows):
        if not rows:
            return '<div class="empty">No reports yet. When users report links, they will appear here automatically.</div>'
        out = []
        for r in rows:
            url = r.get('url') or r.get('normalized_url') or 'Message-only report'
            score = int(r.get('triage_score') or 0)
            triage_status = r.get('triage_status') or 'watchlist'
            cls = status_class(triage_status)
            reasons = r.get('triage_reasons') or 'No triage signals saved.'
            reporter = r.get('reporter_email') or 'unknown user'
            dup = int(r.get('duplicate_reports') or 1)
            out.append(f'''
              <div class="item">
                <div class="item-top"><div class="url">{e(url)}</div><span class="badge {cls}">{e(triage_status.replace('_', ' '))} · {score}/100</span></div>
                <div class="meta">Report #{e(r.get('id'))} · Status: {e(r.get('status'))} · Duplicates: {dup} · Category: {e(r.get('category') or 'url')} · {e(r.get('created_at') or '')}</div>
                <div class="meta">Reporter: {e(reporter)}</div>
                <div class="message">{e(r.get('message') or 'No message provided.')}</div>
                <div class="signals"><b>Signals:</b> {e(reasons)}</div>
              </div>
            ''')
        return ''.join(out)

    def event_rows(rows):
        if not rows:
            return '<div class="empty">No intelligence events yet.</div>'
        out = []
        for ev in rows:
            url = ev.get('url') or 'No URL'
            score = int(ev.get('confidence_score') or 0)
            status = ev.get('status') or 'watchlist'
            cls = status_class(status)
            dup = int(ev.get('duplicate_count') or 1)
            out.append(f'''
              <div class="item compact">
                <div class="item-top"><div class="url">{e(url)}</div><span class="badge {cls}">{e(status.replace('_', ' '))} · {score}/100</span></div>
                <div class="meta">Domain: {e(ev.get('domain') or 'unknown')} · Type: {e(ev.get('evidence_type') or 'event')} · Duplicates: {dup} · Resolution: {e(ev.get('resolution') or 'needs_more_evidence')} · {e(ev.get('created_at') or '')}</div>
                <div class="signals">{e(ev.get('reason') or 'No reason saved.')}</div>
              </div>
            ''')
        return ''.join(out)

    db_error_html = ''
    if db_error:
        db_error_html = f'''<div class="error-box"><b>Admin database query failed.</b><br>{e(db_error)}<br><br>This page is server-rendered, so it shows the real problem instead of loading forever.</div>'''

    return f'''
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>LidaShield Intelligence Admin</title>
<style>
:root{{--bg:#050816;--panel:#0b1024;--text:#f8fafc;--muted:#9fb0ca;--gold:#facc15;--line:rgba(255,255,255,.11);--red:#fb7185;--green:#86efac}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at top,#111827 0,#050816 48%,#020617 100%);color:var(--text);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;padding:28px}}.wrap{{max-width:1180px;margin:0 auto}}.top{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:22px;flex-wrap:wrap}}.brand{{font-weight:950;font-size:28px;letter-spacing:-.03em}}.brand span{{color:var(--gold)}}.subtitle{{color:#bad3f5;line-height:1.55;font-size:15px;margin-top:6px;max-width:720px}}.nav{{display:flex;gap:10px;flex-wrap:wrap}}a,.btn{{color:inherit}}.btn{{border:1px solid var(--line);background:rgba(255,255,255,.06);padding:11px 15px;border-radius:14px;text-decoration:none;font-weight:900;display:inline-flex;align-items:center;justify-content:center}}.btn.gold{{background:linear-gradient(135deg,#fde047,#f59e0b);color:#111827;border:0}}.card{{background:linear-gradient(180deg,rgba(17,24,39,.9),rgba(15,23,42,.82));border:1px solid var(--line);border-radius:24px;padding:22px;box-shadow:0 20px 70px rgba(0,0,0,.35);margin-bottom:18px}}h2{{margin:0 0 12px;font-size:22px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:14px}}.two{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}@media(max-width:800px){{.two{{grid-template-columns:1fr}}}}.stat-card{{background:rgba(255,255,255,.045);border:1px solid var(--line);border-radius:18px;padding:16px}}.stat-number{{font-size:32px;font-weight:950;font-family:Georgia,serif}}.stat-label{{color:var(--muted);text-transform:uppercase;letter-spacing:.12em;font-size:12px;margin-top:5px}}.item{{border:1px solid var(--line);background:rgba(255,255,255,.04);border-radius:18px;padding:16px;margin:12px 0}}.item.compact{{padding:14px}}.item-top{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap}}.url{{font-weight:950;word-break:break-all;line-height:1.35}}.meta{{color:var(--muted);font-size:13px;line-height:1.6;margin-top:6px}}.message{{color:#dbeafe;background:rgba(255,255,255,.035);border:1px solid var(--line);border-radius:14px;padding:10px;margin-top:10px;line-height:1.6}}.signals{{color:#cbd5e1;font-size:14px;line-height:1.6;margin-top:10px}}.badge{{display:inline-flex;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:950;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}}.badge.good{{background:rgba(34,197,94,.13);color:var(--green);border:1px solid rgba(34,197,94,.3)}}.badge.warn{{background:rgba(250,204,21,.13);color:#fde047;border:1px solid rgba(250,204,21,.3)}}.badge.bad{{background:rgba(244,63,94,.13);color:var(--red);border:1px solid rgba(244,63,94,.3)}}.badge.neutral{{background:rgba(148,163,184,.13);color:#cbd5e1;border:1px solid rgba(148,163,184,.25)}}.empty,.empty-mini{{color:var(--muted);text-align:center;padding:20px}}.error-box{{border:1px solid rgba(251,113,133,.35);background:rgba(251,113,133,.1);color:#fecdd3;border-radius:18px;padding:16px;margin-bottom:18px;line-height:1.6}}.note{{border:1px solid rgba(250,204,21,.25);background:rgba(250,204,21,.08);color:#fde68a;border-radius:18px;padding:14px;line-height:1.6;margin-bottom:18px}}.mini-row{{display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:center;border-bottom:1px solid var(--line);padding:12px 0;color:#dbeafe}}.mini-row:last-child{{border-bottom:0}}.mini-row span{{word-break:break-all}}.mini-row small{{color:var(--muted)}}
</style></head><body><div class="wrap"><div class="top"><div><div class="brand">Lida<span>Shield</span> Intelligence</div><div class="subtitle">Server-rendered intelligence console. Auto-triage now detects duplicate reports, clusters risky domains, and filters obvious junk before anything enters the verified scam database.</div></div><div class="nav"><a class="btn" href="/dashboard">Dashboard</a><a class="btn" href="/admin/database-stats">Database stats</a><a class="btn gold" href="/admin/reports">Refresh</a></div></div>{db_error_html}<div class="note"><b>Batch 24 active:</b> duplicate reports now become a signal, not a manual headache. High-risk reports are intelligence leads; only verified evidence should affect public verdicts.</div><div class="card"><h2>Report status</h2><div class="subtitle">Latest user-submitted reports by review status.</div><div class="grid">{count_cards(report_counts)}</div></div><div class="card"><h2>Intelligence event status</h2><div class="subtitle">Evidence events generated from reports, scans, and threat intelligence.</div><div class="grid">{count_cards(event_counts)}</div></div><div class="two"><div class="card"><h2>Top risky domains</h2><div class="subtitle">Domains ranked by current intelligence confidence.</div>{domain_rows(risky_domains)}</div><div class="card"><h2>Duplicate URL clusters</h2><div class="subtitle">Repeated reports are grouped here instead of becoming endless manual work.</div>{duplicate_rows(duplicate_urls)}</div></div><div class="card"><h2>Latest triaged reports</h2><div class="subtitle">These reports are auto-scored. High scores are important signals, not automatic truth.</div>{report_rows(reports)}</div><div class="card"><h2>Latest intelligence events</h2><div class="subtitle">This is the real LidaShield data engine layer.</div>{event_rows(events)}</div></div></body></html>'''


@app.route("/admin/api/reports-count")
def admin_api_reports_count():
    admin_user, admin_error = require_admin()
    if admin_error:
        return admin_error

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM scam_reports
                GROUP BY status
                ORDER BY status
                """
            )
            rows = cur.fetchall()

    return jsonify({"ok": True, "counts": rows})


@app.route("/admin/api/reports")
def admin_api_reports():
    admin_user, admin_error = require_admin()
    if admin_error:
        return admin_error

    status = (request.args.get("status") or "pending").lower().strip()
    if status not in ("pending", "approved", "rejected"):
        return jsonify({"error": "Invalid status."}), 400

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Prevent a stuck admin query from making the page load forever.
                cur.execute("SET LOCAL statement_timeout = '5000ms'")
                cur.execute(
                    """
                    SELECT r.id, r.url, r.normalized_url, r.message, r.category, r.status,
                           r.triage_score, r.triage_status, r.triage_reasons,
                           r.created_at::text AS created_at, r.reviewed_at::text AS reviewed_at,
                           r.review_notes, u.email AS reporter_email
                    FROM scam_reports r
                    LEFT JOIN users u ON u.id = r.user_id
                    WHERE r.status = %s
                    ORDER BY r.created_at DESC
                    LIMIT 100
                    """,
                    (status,)
                )
                reports = cur.fetchall()

        return jsonify({"ok": True, "status": status, "reports": reports})

    except Exception as e:
        app.logger.exception("Admin reports API failed")
        return jsonify({
            "ok": False,
            "error": "Admin reports API failed.",
            "details": str(e),
            "type": type(e).__name__
        }), 500


@app.route("/admin/api/reports/<int:report_id>/approve", methods=["POST"])
def admin_api_approve_report(report_id):
    admin_user, admin_error = require_admin()
    if admin_error:
        return admin_error

    data = request.get_json(silent=True) or {}
    notes = (data.get("notes") or "Approved by LidaShield admin review.").strip()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scam_reports WHERE id = %s FOR UPDATE", (report_id,))
            report = cur.fetchone()

            if not report:
                return jsonify({"error": "Report not found."}), 404

            if report.get("status") != "pending":
                return jsonify({"error": "Only pending reports can be approved."}), 400

            raw_url = report.get("url") or report.get("normalized_url")
            if not raw_url:
                return jsonify({"error": "This report has no URL, so it cannot be inserted into scam_urls yet. Reject it or review manually."}), 400

            try:
                normalized_url = normalize_url(raw_url)
            except ValueError:
                return jsonify({"error": "Report URL is invalid and cannot be approved into scam_urls."}), 400

            admin_notes = f"User report #{report_id} approved by admin. {notes}"
            if report.get("message"):
                admin_notes += f" User message: {report.get('message')[:300]}"

            upsert_scam_indicator(
                cur,
                url=raw_url,
                verdict="dangerous",
                source="user_report_reviewed",
                notes=admin_notes,
                malicious=2,
                suspicious=4,
                harmless=0,
                undetected=0,
            )

            cur.execute(
                """
                UPDATE scam_reports
                SET status = 'approved', reviewed_at = NOW(), reviewed_by = %s, review_notes = %s,
                    normalized_url = COALESCE(normalized_url, %s)
                WHERE id = %s
                """,
                (admin_user["id"], notes, normalized_url, report_id)
            )

    return jsonify({"ok": True, "message": "Report approved and added to scam_urls."})


@app.route("/admin/api/reports/<int:report_id>/reject", methods=["POST"])
def admin_api_reject_report(report_id):
    admin_user, admin_error = require_admin()
    if admin_error:
        return admin_error

    data = request.get_json(silent=True) or {}
    notes = (data.get("notes") or "Rejected by LidaShield admin review.").strip()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scam_reports WHERE id = %s FOR UPDATE", (report_id,))
            report = cur.fetchone()

            if not report:
                return jsonify({"error": "Report not found."}), 404

            if report.get("status") != "pending":
                return jsonify({"error": "Only pending reports can be rejected."}), 400

            cur.execute(
                """
                UPDATE scam_reports
                SET status = 'rejected', reviewed_at = NOW(), reviewed_by = %s, review_notes = %s
                WHERE id = %s
                """,
                (admin_user["id"], notes, report_id)
            )

    return jsonify({"ok": True, "message": "Report rejected. It was not added to scam_urls."})


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

    triage = triage_report_signal(raw_url, message, user_id=user["id"] if user else None)
    normalized_url = triage.get("normalized_url")

    if not raw_url and not message:
        return jsonify({"error": "Please provide a URL or message to report."}), 400

    if not DATABASE_URL:
        return jsonify({"error": "Database is not configured."}), 500

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scam_reports
                (user_id, url, normalized_url, message, category, status, triage_score, triage_status, triage_reasons)
                VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s, %s)
                RETURNING id
                """,
                (
                    user["id"] if user else None,
                    raw_url,
                    normalized_url,
                    message,
                    category,
                    triage.get("score", 0),
                    triage.get("status", "watchlist"),
                    json.dumps(triage.get("reasons", []))
                )
            )
            report_row = cur.fetchone()

            if report_row:
                insert_intelligence_event(
                    cur,
                    user_id=user["id"] if user else None,
                    report_id=report_row["id"],
                    raw_url=raw_url,
                    message=message,
                    triage=triage,
                    source="community_report",
                    evidence_type="community_report"
                )

    return jsonify({
        "ok": True,
        "status": "pending",
        "report_id": report_row["id"] if report_row else None,
        "message": "Report received. LidaShield has triaged it automatically and it will not affect the public verdict until verified.",
        "triage": {
            "score": triage.get("score", 0),
            "status": triage.get("status", "watchlist"),
            "reasons": triage.get("reasons", [])[:5],
            "duplicate_count": triage.get("duplicate_count", 1),
            "resolution": triage.get("resolution", "needs_more_evidence")
        }
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

    current_plan = (user.get("plan") or "free").lower().strip()

    if current_plan == plan:
        return jsonify({"error": f"You are already on the {plan.title()} plan."}), 400

    if current_plan == "pro":
        return jsonify({"error": "You are already on Pro, the highest plan."}), 400

    # Paid users should use the billing portal to change plans.
    # This prevents creating two active Stripe subscriptions for one user.
    if current_plan in ("shield", "pro") and user.get("stripe_subscription_id"):
        return jsonify({
            "error": "You already have an active subscription. Use Manage billing to change plans."
        }), 400

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
        success_url=f"{APP_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{APP_URL}/dashboard?billing=cancelled",
        metadata={
            "user_id": str(user["id"]),
            "plan": plan
        }
    )

    return jsonify({"url": checkout.url})


@app.route("/billing/portal", methods=["POST"])
def billing_portal():
    """
    Opens Stripe Customer Portal so paid users can manage/cancel subscriptions.
    This is needed before real customers because SaaS users expect self-service billing.
    """

    user = get_current_user()

    if not user:
        return jsonify({"error": "Please sign in first."}), 401

    if not STRIPE_SECRET_KEY:
        return jsonify({"error": "Stripe is not configured yet."}), 500

    customer_id = user.get("stripe_customer_id")

    if not customer_id:
        return jsonify({
            "error": "No Stripe customer found for this account yet. Upgrade first, then billing management will become available."
        }), 400

    try:
        portal = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=f"{APP_URL}/dashboard"
        )

        return jsonify({"url": portal.url})

    except Exception as e:
        app.logger.exception("Billing portal failed")
        return jsonify({
            "error": "Could not open Stripe billing portal.",
            "details": str(e)
        }), 500


@app.route("/billing/success")
def billing_success():
    """
    Stripe success return route.
    This verifies the Checkout Session and updates the user's plan immediately,
    even before the webhook arrives. The webhook remains the long-term source
    of truth, but this prevents the dashboard from staying FREE after payment.
    """

    user = get_current_user()

    if not user:
        session["next_url"] = "/dashboard?billing=success"
        return redirect(url_for("login"))

    session_id = request.args.get("session_id", "").strip()

    if not session_id or not STRIPE_SECRET_KEY:
        return redirect("/dashboard?billing=success")

    try:
        checkout = stripe.checkout.Session.retrieve(session_id)
        metadata = checkout.get("metadata") or {}
        plan = (metadata.get("plan") or "shield").lower().strip()
        checkout_user_id = metadata.get("user_id")

        if str(checkout_user_id) != str(user["id"]):
            app.logger.warning("Checkout session user mismatch")
            return redirect("/dashboard?billing=user_mismatch")

        if plan not in ("shield", "pro"):
            return redirect("/dashboard?billing=invalid_plan")

        payment_status = checkout.get("payment_status")
        subscription_id = checkout.get("subscription")
        customer_id = checkout.get("customer")

        if payment_status in ("paid", "no_payment_required"):
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE users
                        SET plan = %s,
                            stripe_customer_id = COALESCE(%s, stripe_customer_id),
                            stripe_subscription_id = COALESCE(%s, stripe_subscription_id)
                        WHERE id = %s
                        """,
                        (plan, customer_id, subscription_id, user["id"])
                    )

            return redirect("/dashboard?billing=success")

        return redirect("/dashboard?billing=not_paid")

    except Exception as e:
        app.logger.exception("Billing success verification failed")
        return redirect("/dashboard?billing=verify_failed")


def plan_from_subscription_object(subscription_obj):
    """Return shield/pro from a Stripe subscription object's price IDs."""

    try:
        items = subscription_obj.get("items", {}).get("data", [])
    except Exception:
        items = []

    price_ids = []

    for item in items:
        price = item.get("price") or {}
        price_id = price.get("id")
        if price_id:
            price_ids.append(price_id)

    if STRIPE_PRICE_PRO and STRIPE_PRICE_PRO in price_ids:
        return "pro"

    if STRIPE_PRICE_SHIELD and STRIPE_PRICE_SHIELD in price_ids:
        return "shield"

    return None


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
        customer_id = obj.get("customer")

        if user_id and plan in ("shield", "pro"):
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE users
                        SET plan = %s,
                            stripe_customer_id = COALESCE(%s, stripe_customer_id),
                            stripe_subscription_id = COALESCE(%s, stripe_subscription_id)
                        WHERE id = %s
                        """,
                        (plan, customer_id, subscription_id, user_id)
                    )

    if event_type in ("customer.subscription.created", "customer.subscription.updated"):
        customer_id = obj.get("customer")
        subscription_id = obj.get("id")
        status = obj.get("status")
        plan = plan_from_subscription_object(obj)

        if customer_id and subscription_id and plan and status in ("active", "trialing"):
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE users
                        SET plan = %s, stripe_subscription_id = %s
                        WHERE stripe_customer_id = %s
                          AND (stripe_subscription_id = %s OR stripe_subscription_id IS NULL)
                        """,
                        (plan, subscription_id, customer_id, subscription_id)
                    )

    if event_type == "customer.subscription.deleted":
        customer_id = obj.get("customer")
        subscription_id = obj.get("id")

        # Only downgrade the user if the deleted subscription is the one
        # currently stored on their account. This prevents an old Shield
        # cancellation from wiping a newer Pro subscription.
        if customer_id and subscription_id:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE users
                        SET plan = 'free', stripe_subscription_id = NULL
                        WHERE stripe_customer_id = %s
                          AND stripe_subscription_id = %s
                        """,
                        (customer_id, subscription_id)
                    )

    return jsonify({"ok": True})



# ============================================================
# Legal / trust pages
# ============================================================

LEGAL_UPDATED = "20 June 2026"
LEGAL_CONTACT = os.environ.get("LEGAL_CONTACT_EMAIL", "support@lidashield.com")

LEGAL_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ title }} · LidaShield</title>
  <style>
    :root{--bg:#05060d;--panel:#111217;--text:#f7f3ec;--muted:#a8a19a;--gold:#f6bd48;--line:rgba(246,189,72,.18)}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#17120a 0,#05060d 45%,#03040a 100%);color:var(--text);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.7}.wrap{max-width:900px;margin:0 auto;padding:42px 22px 80px}.top{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:32px}.brand{font-family:Georgia,serif;font-size:28px;color:var(--gold);text-decoration:none}.nav{display:flex;gap:10px;flex-wrap:wrap}.btn{border:1px solid var(--line);border-radius:999px;padding:10px 14px;color:var(--text);text-decoration:none;background:rgba(255,255,255,.04);font-weight:800}.card{border:1px solid var(--line);border-radius:28px;padding:30px;background:rgba(255,255,255,.045);box-shadow:0 30px 90px rgba(0,0,0,.35)}h1{font-family:Georgia,serif;font-size:46px;font-weight:400;margin:0 0 6px}h2{margin-top:30px;color:var(--gold);font-size:20px}.muted{color:var(--muted)}p,li{color:#ddd7cd}ul{padding-left:22px}.notice{border:1px solid rgba(246,189,72,.25);background:rgba(246,189,72,.08);border-radius:18px;padding:14px 16px;margin:20px 0;color:#f6e8c8}.footer{margin-top:28px;color:var(--muted);font-size:13px}code{color:#ffd98a}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <a class="brand" href="/">LidaShield</a>
      <div class="nav">
        <a class="btn" href="/">Scanner</a>
        <a class="btn" href="/privacy">Privacy</a>
        <a class="btn" href="/terms">Terms</a>
        <a class="btn" href="/disclaimer">Disclaimer</a>
      </div>
    </div>
    <div class="card">
      <h1>{{ title }}</h1>
      <div class="muted">Last updated: {{ updated }}</div>
      {{ body|safe }}
      <div class="footer">Contact: {{ contact }} · This page is a plain-language starter policy and should be reviewed properly before full public launch.</div>
    </div>
  </div>
</body>
</html>
"""


def render_legal_page(title, body):
    return render_template_string(
        LEGAL_TEMPLATE,
        title=title,
        body=body,
        updated=LEGAL_UPDATED,
        contact=LEGAL_CONTACT
    )


@app.route("/privacy")
def privacy_page():
    body = """
    <div class="notice"><b>Plain-language summary:</b> LidaShield collects only what is needed to run scam checks, accounts, reports, subscriptions, and security monitoring.</div>

    <h2>1. Information we collect</h2>
    <ul>
      <li>Account information from Google sign-in, such as your email address, name, and profile image.</li>
      <li>Links, messages, and reports you submit to LidaShield for scam analysis.</li>
      <li>Scan history, message-check history, report status, usage limits, and intelligence signals generated by the system.</li>
      <li>Billing-related identifiers from Stripe, such as customer and subscription IDs. Payment card details are handled by Stripe, not stored by LidaShield.</li>
      <li>Basic technical information needed for security, abuse prevention, and service operation.</li>
    </ul>

    <h2>2. How we use information</h2>
    <ul>
      <li>To check links and messages for scam signals.</li>
      <li>To build LidaShield's scam intelligence database and watchlist systems.</li>
      <li>To provide account dashboards, plan limits, scan history, and subscription features.</li>
      <li>To prevent spam, fake reports, abuse, and attempts to poison the database.</li>
      <li>To improve LidaShield's safety, reliability, and detection quality.</li>
    </ul>

    <h2>3. Scam reports and intelligence</h2>
    <p>User reports may be stored as intelligence events. A report does not automatically prove that a link is dangerous. LidaShield uses scoring, duplicate detection, trusted data, and admin controls to reduce false positives.</p>

    <h2>4. Sharing</h2>
    <p>We do not sell personal information. We may use trusted service providers such as Google sign-in, Stripe billing, hosting, database, and security infrastructure to operate the service.</p>

    <h2>5. Data retention</h2>
    <p>LidaShield keeps scan, report, and intelligence data for as long as needed to operate, protect users, prevent abuse, and improve scam detection. You may contact us to request deletion or correction of account-related information.</p>

    <h2>6. Security</h2>
    <p>We use environment variables for secrets, account authentication, admin-only controls, and payment verification. No online service can guarantee perfect security, but LidaShield is designed to reduce risk and improve over time.</p>

    <h2>7. Contact</h2>
    <p>For privacy requests, contact <code>support@lidashield.com</code> or the official contact address published by LidaShield.</p>
    """
    return render_legal_page("Privacy Policy", body)


@app.route("/terms")
def terms_page():
    body = """
    <div class="notice"><b>Plain-language summary:</b> Use LidaShield responsibly. It provides scam intelligence, not a guarantee that every link is safe or dangerous.</div>

    <h2>1. Acceptance</h2>
    <p>By using LidaShield, you agree to these Terms. If you do not agree, do not use the service.</p>

    <h2>2. Service purpose</h2>
    <p>LidaShield provides scam-link checks, message checks, user reporting, watchlist intelligence, and account-based protection tools. Results are informational and may change as new evidence is collected.</p>

    <h2>3. Accounts</h2>
    <p>You are responsible for activity on your account. Do not use another person's account or attempt to bypass plan limits, admin controls, or security systems.</p>

    <h2>4. Prohibited use</h2>
    <ul>
      <li>Do not submit fake reports to manipulate verdicts.</li>
      <li>Do not attack, scrape, overload, reverse-engineer, or abuse the service.</li>
      <li>Do not use LidaShield to harass, defame, or falsely accuse legitimate websites.</li>
      <li>Do not attempt to access admin tools, private data, or systems without permission.</li>
    </ul>

    <h2>5. Billing</h2>
    <p>Paid subscriptions are processed through Stripe. Plan features, prices, and limits may change as LidaShield develops. You may manage or cancel subscriptions through the billing portal where available.</p>

    <h2>6. No guarantee</h2>
    <p>LidaShield may miss threats or flag suspicious signals incorrectly. You should still use judgment, verify with official sources, and contact your bank, platform, or authorities when needed.</p>

    <h2>7. Limitation of liability</h2>
    <p>To the fullest extent allowed, LidaShield is provided as-is and is not liable for losses caused by reliance on scan results, missed scams, false positives, outages, or third-party services.</p>

    <h2>8. Changes</h2>
    <p>We may update these Terms as the product evolves. Continued use means you accept the updated Terms.</p>
    """
    return render_legal_page("Terms of Service", body)


@app.route("/disclaimer")
def disclaimer_page():
    body = """
    <div class="notice"><b>Important:</b> LidaShield is a scam intelligence tool. It is not a law-enforcement agency, bank, legal adviser, or guaranteed security product.</div>

    <h2>1. Verdict meanings</h2>
    <ul>
      <li><b>Dangerous:</b> the link appears in LidaShield's verified scam database or trusted threat intelligence.</li>
      <li><b>Suspicious:</b> LidaShield has unverified high-risk intelligence or strong scam signals.</li>
      <li><b>Unknown:</b> LidaShield has not verified the link as suspicious. This does not prove the link is safe.</li>
      <li><b>Low risk:</b> no major signals were found in the current check, but this is not a safety guarantee.</li>
    </ul>

    <h2>2. Unverified intelligence</h2>
    <p>Unverified intelligence can include user reports, duplicate reports, suspicious domain patterns, and message signals. These are warnings, not final proof.</p>

    <h2>3. What users should do</h2>
    <ul>
      <li>Do not enter passwords, OTPs, banking credentials, or Singpass details into suspicious links.</li>
      <li>Verify directly with the official website, app, bank, or organisation.</li>
      <li>If money or account access is involved, contact the relevant official support channel immediately.</li>
    </ul>

    <h2>4. No complete protection</h2>
    <p>No scanner can detect every scam. Scammers change domains, wording, and tactics quickly. LidaShield reduces risk, but users must remain careful.</p>
    """
    return render_legal_page("Disclaimer", body)


# ============================================================
# Run locally
# ============================================================

if __name__ == "__main__":
    print("\nLidaShield running locally at http://localhost:5000\n")
    app.run(debug=True, port=5000)
