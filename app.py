import os
import hashlib
import re
from datetime import date
from urllib.parse import urlparse

import psycopg2
import psycopg2.extras
import stripe
from authlib.integrations.flask_client import OAuth
from flask import (Flask, jsonify, redirect, render_template,
                   request, session, url_for)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')

DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL.startswith('postgres://'):          # Render gives postgres:// but psycopg2 needs postgresql://
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_PRICE_SHIELD = os.environ.get('STRIPE_PRICE_SHIELD', '')
STRIPE_PRICE_PRO    = os.environ.get('STRIPE_PRICE_PRO', '')

PRICE_IDS = {'shield': STRIPE_PRICE_SHIELD, 'pro': STRIPE_PRICE_PRO}

# ---------------------------------------------------------------------------
# Tier limits  (feature_key: scans/day)
# ---------------------------------------------------------------------------
DAILY_LIMITS = {
    'free':   {'url_check': 10, 'sms_scan': 5,   'email_check': 3,   'password_check': 5,   'report_submit': 3},
    'shield': {'url_check': 500,'sms_scan': 500,  'email_check': 500, 'password_check': 500, 'report_submit': 50},
    'pro':    {'url_check': 0,  'sms_scan': 0,    'email_check': 0,   'password_check': 0,   'report_submit': 0},
    # 0 = unlimited
}

TIER_FEATURES = {
    'free':   ['url_check', 'sms_scan', 'email_check', 'password_check', 'report_submit'],
    'shield': ['url_check', 'sms_scan', 'email_check', 'password_check', 'report_submit',
               'qr_scan', 'domain_check', 'ip_check', 'bulk_scan', 'history', 'alerts'],
    'pro':    ['url_check', 'sms_scan', 'email_check', 'password_check', 'report_submit',
               'qr_scan', 'domain_check', 'ip_check', 'bulk_scan', 'history', 'alerts',
               'file_scan', 'api_access', 'pdf_export'],
}

# ---------------------------------------------------------------------------
# OAuth
# ---------------------------------------------------------------------------
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID', ''),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', ''),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db():
    return psycopg2.connect(DATABASE_URL)


def get_user():
    uid = session.get('user_id')
    if not uid:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE id = %s', (uid,))
    user = cur.fetchone()
    conn.close()
    return user


def is_admin(user):
    if not user:
        return False
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT 1 FROM admins WHERE user_id = %s', (user['id'],))
    result = cur.fetchone()
    conn.close()
    return result is not None

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
def check_rate_limit(user, feature):
    """Returns (allowed: bool, remaining: int, limit: int)."""
    tier  = user['tier'] if user else 'free'
    limit = DAILY_LIMITS[tier].get(feature, 10)
    today = date.today()

    conn = get_db()
    cur  = conn.cursor()

    if user:
        cur.execute(
            'SELECT count FROM scan_usage WHERE user_id=%s AND feature=%s AND scan_date=%s',
            (user['id'], feature, today)
        )
    else:
        cur.execute(
            'SELECT count FROM scan_usage WHERE ip_address=%s AND feature=%s AND scan_date=%s',
            (request.remote_addr, feature, today)
        )

    row     = cur.fetchone()
    current = row[0] if row else 0

    if limit != 0 and current >= limit:
        conn.close()
        return False, 0, limit

    # Increment
    if row:
        if user:
            cur.execute(
                'UPDATE scan_usage SET count=count+1 WHERE user_id=%s AND feature=%s AND scan_date=%s',
                (user['id'], feature, today)
            )
        else:
            cur.execute(
                'UPDATE scan_usage SET count=count+1 WHERE ip_address=%s AND feature=%s AND scan_date=%s',
                (request.remote_addr, feature, today)
            )
    else:
        if user:
            cur.execute(
                'INSERT INTO scan_usage(user_id,feature,scan_date,count) VALUES(%s,%s,%s,1)',
                (user['id'], feature, today)
            )
        else:
            cur.execute(
                'INSERT INTO scan_usage(ip_address,feature,scan_date,count) VALUES(%s,%s,%s,1)',
                (request.remote_addr, feature, today)
            )

    conn.commit()
    conn.close()
    remaining = (limit - current - 1) if limit != 0 else 999999
    return True, remaining, limit

# ---------------------------------------------------------------------------
# Threat lookup — strict DB only, zero heuristics
# ---------------------------------------------------------------------------
URL_RE = re.compile(
    r'(?:https?://|www\.)[^\s<>"\']+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?'
)


def normalize_url(raw: str) -> str:
    raw = raw.strip().lower()
    if not raw.startswith(('http://', 'https://')):
        raw = 'http://' + raw
    p = urlparse(raw)
    path = p.path.rstrip('/')
    return (p.netloc + path).lstrip('/')


def url_hash(normalised: str) -> str:
    return hashlib.sha256(normalised.encode()).hexdigest()


def lookup_url(raw: str):
    """
    Strict DB lookup. Returns threat row dict or None.
    No heuristics — ever.
    """
    norm   = normalize_url(raw)
    uhash  = url_hash(norm)
    domain = urlparse('http://' + norm).netloc

    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Exact URL hash first
    cur.execute('SELECT * FROM threats WHERE url_hash=%s LIMIT 1', (uhash,))
    row = cur.fetchone()

    # Fall back to domain match
    if not row and domain:
        cur.execute('SELECT * FROM threats WHERE domain=%s LIMIT 1', (domain,))
        row = cur.fetchone()

    conn.close()
    return dict(row) if row else None


def save_history(user, feature, value, result, threat_type=None):
    if not user:
        return
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        'INSERT INTO scan_history(user_id,feature,input_value,result,threat_type) VALUES(%s,%s,%s,%s,%s)',
        (user['id'], feature, value[:500] if value else None, result, threat_type)
    )
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/auth/callback')
def auth_callback():
    token    = google.authorize_access_token()
    userinfo = token['userinfo']

    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        INSERT INTO users(google_id, email, name, avatar_url)
        VALUES(%s,%s,%s,%s)
        ON CONFLICT(google_id) DO UPDATE
            SET name=EXCLUDED.name, avatar_url=EXCLUDED.avatar_url
        RETURNING id
    """, (userinfo['sub'], userinfo['email'], userinfo['name'], userinfo.get('picture', '')))
    row = cur.fetchone()
    conn.commit()
    conn.close()

    session['user_id'] = row['id']
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    user = get_user()
    return render_template('index.html', user=user)


@app.route('/dashboard')
def dashboard():
    user = get_user()
    if not user:
        return redirect(url_for('login'))

    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute(
        'SELECT * FROM scan_history WHERE user_id=%s ORDER BY created_at DESC LIMIT 50',
        (user['id'],)
    )
    history = cur.fetchall()

    cur.execute(
        'SELECT feature, count FROM scan_usage WHERE user_id=%s AND scan_date=%s',
        (user['id'], date.today())
    )
    usage = {r['feature']: r['count'] for r in cur.fetchall()}
    conn.close()

    limits = DAILY_LIMITS[user['tier']]
    features = TIER_FEATURES[user['tier']]
    return render_template('dashboard.html',
                           user=user, history=history,
                           usage=usage, limits=limits, features=features,
                           admin=is_admin(user))


@app.route('/admin')
def admin():
    user = get_user()
    if not user or not is_admin(user):
        return redirect('/')

    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute('SELECT COUNT(*) as n FROM users')
    total_users = cur.fetchone()['n']

    cur.execute('SELECT COUNT(*) as n FROM threats')
    total_threats = cur.fetchone()['n']

    cur.execute("SELECT COUNT(*) as n FROM scam_reports WHERE status='pending'")
    pending = cur.fetchone()['n']

    cur.execute("""
        SELECT u.id, u.email, u.name, u.tier, u.created_at,
               COUNT(sh.id) AS total_scans
        FROM users u
        LEFT JOIN scan_history sh ON sh.user_id = u.id
        GROUP BY u.id
        ORDER BY total_scans DESC
        LIMIT 30
    """)
    users = cur.fetchall()

    cur.execute("""
        SELECT sr.*, u.email AS reporter_email
        FROM scam_reports sr
        LEFT JOIN users u ON u.id = sr.user_id
        WHERE sr.status='pending'
        ORDER BY sr.created_at DESC
        LIMIT 50
    """)
    reports = cur.fetchall()

    cur.execute("""
        SELECT source, COUNT(*) as n FROM threats GROUP BY source ORDER BY n DESC
    """)
    threat_sources = cur.fetchall()

    conn.close()
    return render_template('admin.html',
                           user=user,
                           total_users=total_users,
                           total_threats=total_threats,
                           pending=pending,
                           users=users,
                           reports=reports,
                           threat_sources=threat_sources)

# ---------------------------------------------------------------------------
# Feature API — Feature 1: URL check
# ---------------------------------------------------------------------------
@app.route('/api/check-url', methods=['POST'])
def api_check_url():
    user = get_user()
    data = request.get_json(silent=True) or {}
    raw  = data.get('url', '').strip()
    if not raw:
        return jsonify({'error': 'URL required'}), 400

    allowed, remaining, limit = check_rate_limit(user, 'url_check')
    if not allowed:
        return jsonify({'error': 'Daily limit reached', 'upgrade': True, 'limit': limit}), 429

    threat = lookup_url(raw)
    if threat:
        save_history(user, 'url_check', raw, 'threat', threat['threat_type'])
        return jsonify({
            'result': 'threat',
            'threat_type': threat['threat_type'],
            'source': threat['source'],
            'remaining': remaining,
        })

    save_history(user, 'url_check', raw, 'not_found')
    return jsonify({'result': 'not_found', 'remaining': remaining})

# ---------------------------------------------------------------------------
# Feature 2: SMS / text scanner
# ---------------------------------------------------------------------------
@app.route('/api/check-sms', methods=['POST'])
def api_check_sms():
    user = get_user()
    data = request.get_json(silent=True) or {}
    text = data.get('text', '').strip()
    if not text:
        return jsonify({'error': 'Text required'}), 400

    allowed, remaining, limit = check_rate_limit(user, 'sms_scan')
    if not allowed:
        return jsonify({'error': 'Daily limit reached', 'upgrade': True}), 429

    urls_found = URL_RE.findall(text)
    threats    = []
    for u in set(urls_found):
        t = lookup_url(u)
        if t:
            threats.append({'url': u, 'threat_type': t['threat_type'], 'source': t['source']})

    result = 'threat' if threats else 'not_found'
    save_history(user, 'sms_scan', text[:200], result)
    return jsonify({'result': result, 'threats': threats, 'remaining': remaining})

# ---------------------------------------------------------------------------
# Feature 3: Phishing email checker
# ---------------------------------------------------------------------------
@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    user = get_user()
    data = request.get_json(silent=True) or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Email content required'}), 400

    allowed, remaining, limit = check_rate_limit(user, 'email_check')
    if not allowed:
        return jsonify({'error': 'Daily limit reached', 'upgrade': True}), 429

    urls_found = URL_RE.findall(content)
    threats    = []
    for u in set(urls_found):
        t = lookup_url(u)
        if t:
            threats.append({'url': u, 'threat_type': t['threat_type'], 'source': t['source']})

    result = 'threat' if threats else 'not_found'
    save_history(user, 'email_check', content[:200], result)
    return jsonify({'result': result, 'threats': threats, 'remaining': remaining})

# ---------------------------------------------------------------------------
# Feature 4: Password breach checker (local DB, k-anonymity style)
# Client sends SHA-1 hex of password; we never store the plaintext.
# ---------------------------------------------------------------------------
@app.route('/api/check-password', methods=['POST'])
def api_check_password():
    user = get_user()
    data = request.get_json(silent=True) or {}
    sha1 = data.get('hash', '').strip().upper()

    if len(sha1) != 40 or not all(c in '0123456789ABCDEF' for c in sha1):
        return jsonify({'error': 'Valid SHA-1 hash required (40 hex chars)'}), 400

    allowed, remaining, limit = check_rate_limit(user, 'password_check')
    if not allowed:
        return jsonify({'error': 'Daily limit reached', 'upgrade': True}), 429

    prefix = sha1[:5]
    suffix = sha1[5:]

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        'SELECT breach_count FROM pwned_passwords WHERE hash_prefix=%s AND hash_suffix=%s',
        (prefix, suffix)
    )
    row = cur.fetchone()
    conn.close()

    if row:
        save_history(user, 'password_check', '[password_hash]', 'threat', 'breached')
        return jsonify({'result': 'breached', 'count': row[0], 'remaining': remaining})

    save_history(user, 'password_check', '[password_hash]', 'not_found')
    return jsonify({'result': 'not_found', 'remaining': remaining})

# ---------------------------------------------------------------------------
# Feature 5: Scam report database
# ---------------------------------------------------------------------------
@app.route('/api/reports', methods=['GET'])
def api_reports_get():
    conn = get_db()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT sr.id, sr.report_type, sr.value, sr.description,
               sr.upvotes, sr.created_at, u.name AS reporter
        FROM scam_reports sr
        LEFT JOIN users u ON u.id = sr.user_id
        WHERE sr.status = 'verified'
        ORDER BY sr.created_at DESC
        LIMIT 100
    """)
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        if r.get('created_at'):
            r['created_at'] = r['created_at'].isoformat()
    conn.close()
    return jsonify(rows)


@app.route('/api/reports', methods=['POST'])
def api_reports_post():
    user = get_user()
    if not user:
        return jsonify({'error': 'Login required'}), 401

    allowed, _, _ = check_rate_limit(user, 'report_submit')
    if not allowed:
        return jsonify({'error': 'Daily limit reached', 'upgrade': True}), 429

    data = request.get_json(silent=True) or {}
    rtype = data.get('type', '').strip()
    value = data.get('value', '').strip()
    desc  = data.get('description', '').strip()

    if rtype not in ('url', 'phone', 'email', 'sms') or not value:
        return jsonify({'error': 'Invalid report'}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        'INSERT INTO scam_reports(user_id,report_type,value,description) VALUES(%s,%s,%s,%s)',
        (user['id'], rtype, value, desc)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ---------------------------------------------------------------------------
# Admin actions
# ---------------------------------------------------------------------------
def require_admin():
    user = get_user()
    if not user or not is_admin(user):
        return None, jsonify({'error': 'Forbidden'}), 403
    return user, None, None


@app.route('/admin/reports/<int:rid>/verify', methods=['POST'])
def admin_verify(rid):
    user = get_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "UPDATE scam_reports SET status='verified' WHERE id=%s RETURNING report_type, value",
        (rid,)
    )
    row = cur.fetchone()
    if row and row[0] == 'url':
        norm  = normalize_url(row[1])
        uhash = url_hash(norm)
        dom   = urlparse('http://' + norm).netloc
        cur.execute("""
            INSERT INTO threats(url,url_hash,domain,threat_type,source)
            VALUES(%s,%s,%s,'scam','user_report')
            ON CONFLICT(url_hash) DO NOTHING
        """, (row[1], uhash, dom))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/admin/reports/<int:rid>/reject', methods=['POST'])
def admin_reject(rid):
    user = get_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("UPDATE scam_reports SET status='rejected' WHERE id=%s", (rid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/admin/users/<int:uid>/tier', methods=['POST'])
def admin_set_tier(uid):
    user = get_user()
    if not user or not is_admin(user):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(silent=True) or {}
    tier = data.get('tier', 'free')
    if tier not in ('free', 'shield', 'pro'):
        return jsonify({'error': 'Invalid tier'}), 400

    conn = get_db()
    cur  = conn.cursor()
    cur.execute('UPDATE users SET tier=%s WHERE id=%s', (tier, uid))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ---------------------------------------------------------------------------
# Stripe
# ---------------------------------------------------------------------------
@app.route('/stripe/create-checkout', methods=['POST'])
def stripe_checkout():
    user = get_user()
    if not user:
        return jsonify({'error': 'Login required'}), 401

    data = request.get_json(silent=True) or {}
    tier = data.get('tier')
    if tier not in PRICE_IDS or not PRICE_IDS[tier]:
        return jsonify({'error': 'Invalid tier'}), 400

    # Get or create Stripe customer
    cid = user['stripe_customer_id']
    if not cid:
        customer = stripe.Customer.create(email=user['email'], name=user['name'])
        cid = customer.id
        conn = get_db()
        cur  = conn.cursor()
        cur.execute('UPDATE users SET stripe_customer_id=%s WHERE id=%s', (cid, user['id']))
        conn.commit()
        conn.close()

    session_obj = stripe.checkout.Session.create(
        customer=cid,
        mode='subscription',
        line_items=[{'price': PRICE_IDS[tier], 'quantity': 1}],
        success_url=request.host_url + 'stripe/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=request.host_url,
    )
    return jsonify({'url': session_obj.url})


@app.route('/stripe/success')
def stripe_success():
    user = get_user()
    return render_template('stripe_success.html', user=user)


@app.route('/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload    = request.get_data()
    sig_header = request.headers.get('Stripe-Signature', '')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return '', 400

    etype = event['type']

    if etype in ('customer.subscription.created', 'customer.subscription.updated'):
        sub     = event['data']['object']
        cid     = sub['customer']
        status  = sub['status']
        price   = sub['items']['data'][0]['price']['id']
        tier    = next((t for t, p in PRICE_IDS.items() if p == price), 'free')
        if status != 'active':
            tier = 'free'
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            'UPDATE users SET tier=%s, stripe_subscription_id=%s WHERE stripe_customer_id=%s',
            (tier, sub['id'], cid)
        )
        conn.commit()
        conn.close()

    elif etype == 'customer.subscription.deleted':
        cid = event['data']['object']['customer']
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "UPDATE users SET tier='free', stripe_subscription_id=NULL WHERE stripe_customer_id=%s",
            (cid,)
        )
        conn.commit()
        conn.close()

    return '', 200

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
