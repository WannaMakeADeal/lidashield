import os
import re
import time
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta

import requests
from flask import Flask, jsonify, render_template, request

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')

VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

# ---------------------------------------------------------------------------
# Simple in-memory rate limiting (10 scans/day per IP)
# ---------------------------------------------------------------------------
_scan_counts = defaultdict(lambda: {'count': 0, 'reset': datetime.utcnow() + timedelta(days=1)})

def check_rate_limit(ip):
    record = _scan_counts[ip]
    if datetime.utcnow() > record['reset']:
        record['count'] = 0
        record['reset'] = datetime.utcnow() + timedelta(days=1)
    if record['count'] >= 10:
        return False, 0
    record['count'] += 1
    remaining = 10 - record['count']
    return True, remaining

# ---------------------------------------------------------------------------
# VirusTotal helper
# ---------------------------------------------------------------------------
def check_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {'error': 'VirusTotal API key not configured'}

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    # Submit URL for analysis
    resp = requests.post(
        'https://www.virustotal.com/api/v3/urls',
        headers=headers,
        data={'url': url},
        timeout=15
    )
    if resp.status_code != 200:
        return {'error': f'VirusTotal submission failed ({resp.status_code})'}

    analysis_id = resp.json().get('data', {}).get('id', '')
    if not analysis_id:
        return {'error': 'No analysis ID returned'}

    # Poll for result (up to 15s)
    for _ in range(5):
        time.sleep(3)
        result_resp = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers=headers,
            timeout=15
        )
        if result_resp.status_code != 200:
            continue
        data = result_resp.json().get('data', {})
        status = data.get('attributes', {}).get('status', '')
        if status == 'completed':
            stats = data.get('attributes', {}).get('stats', {})
            return {
                'malicious':  stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless':   stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'status':     'completed'
            }

    return {'error': 'Analysis timed out — try again in a moment'}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html', user=None)


@app.route('/api/check-url', methods=['POST'])
def api_check_url():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        return jsonify({'error': 'Daily limit of 10 scans reached. Try again tomorrow.', 'upgrade': True}), 429

    data = request.get_json(silent=True) or {}
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL required'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    vt = check_virustotal(url)
    if 'error' in vt:
        return jsonify({'error': vt['error']}), 500

    malicious  = vt['malicious']
    suspicious = vt['suspicious']

    if malicious > 0:
        result = 'threat'
        threat_type = 'malicious'
    elif suspicious > 0:
        result = 'suspicious'
        threat_type = 'suspicious'
    else:
        result = 'safe'
        threat_type = None

    return jsonify({
        'result':      result,
        'threat_type': threat_type,
        'malicious':   malicious,
        'suspicious':  suspicious,
        'harmless':    vt['harmless'],
        'undetected':  vt['undetected'],
        'remaining':   remaining,
    })


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
