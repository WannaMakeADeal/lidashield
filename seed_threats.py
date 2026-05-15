"""
LidaShield — Threat DB Seeder
Imports threat data from free public feeds into your own PostgreSQL.
No API keys needed.

Usage:
    python seed_threats.py            # import all feeds
    python seed_threats.py --phishtank
    python seed_threats.py --urlhaus
    python seed_threats.py --openphish

Run this once to seed, then set a cron job (Render Cron Job, free) to run daily.
"""

import argparse
import csv
import hashlib
import io
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

import psycopg2
import requests

DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)


def get_db():
    return psycopg2.connect(DATABASE_URL)


def normalize_url(raw: str) -> str:
    raw = raw.strip().lower()
    if not raw.startswith(('http://', 'https://')):
        raw = 'http://' + raw
    p    = urlparse(raw)
    path = p.path.rstrip('/')
    return (p.netloc + path).lstrip('/')


def url_hash(norm: str) -> str:
    return hashlib.sha256(norm.encode()).hexdigest()


def bulk_insert(rows: list[tuple], source: str, total_before: int) -> int:
    """
    rows = [(url, domain, threat_type), ...]
    Returns number of new rows inserted.
    """
    if not rows:
        return 0

    conn = get_db()
    cur  = conn.cursor()
    inserted = 0

    BATCH = 500
    for i in range(0, len(rows), BATCH):
        batch = rows[i:i + BATCH]
        values = []
        for url, domain, ttype in batch:
            norm  = normalize_url(url)
            uhash = url_hash(norm)
            values.append((url, uhash, domain, ttype, source))

        args = ','.join(
            cur.mogrify('(%s,%s,%s,%s,%s)', v).decode() for v in values
        )
        cur.execute(f"""
            INSERT INTO threats(url,url_hash,domain,threat_type,source)
            VALUES {args}
            ON CONFLICT(url_hash) DO UPDATE SET last_seen=NOW()
        """)
        inserted += cur.rowcount
        conn.commit()
        print(f'  [{source}] {min(i+BATCH, len(rows))}/{len(rows)} processed', end='\r')

    conn.close()
    print()
    return inserted


# ---------------------------------------------------------------------------
# PhishTank  (free, no API key — just set a User-Agent)
# ---------------------------------------------------------------------------
def seed_phishtank():
    print('\n[PhishTank] Downloading feed...')
    url = 'https://data.phishtank.com/data/online-valid.json'
    try:
        r = requests.get(url, headers={'User-Agent': 'LidaShield/1.0 (security research)'}, timeout=120)
        r.raise_for_status()
    except Exception as e:
        print(f'  ERROR: {e}')
        return

    data = r.json()
    print(f'  {len(data)} entries downloaded.')

    rows = []
    for entry in data:
        target_url = entry.get('url', '').strip()
        if not target_url:
            continue
        domain = urlparse(target_url).netloc.lower()
        rows.append((target_url, domain, 'phishing'))

    n = bulk_insert(rows, 'phishtank', 0)
    print(f'  Done — {len(rows)} entries processed.')


# ---------------------------------------------------------------------------
# URLhaus  (Abuse.ch — completely free, no signup)
# ---------------------------------------------------------------------------
def seed_urlhaus():
    print('\n[URLhaus] Downloading feed...')
    url = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
    try:
        r = requests.get(url, timeout=120)
        r.raise_for_status()
    except Exception as e:
        print(f'  ERROR: {e}')
        return

    lines = r.text.splitlines()
    # Strip comment lines
    data_lines = [l for l in lines if not l.startswith('#') and l.strip()]
    print(f'  {len(data_lines)} entries downloaded.')

    rows = []
    reader = csv.reader(data_lines)
    for row in reader:
        # Format: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) < 6:
            continue
        target_url = row[2].strip().strip('"')
        threat_tag = row[5].strip().strip('"').lower()
        if not target_url:
            continue
        domain = urlparse(target_url).netloc.lower()
        ttype  = 'malware' if 'malware' in threat_tag else 'phishing' if 'phish' in threat_tag else 'malware'
        rows.append((target_url, domain, ttype))

    n = bulk_insert(rows, 'urlhaus', 0)
    print(f'  Done — {len(rows)} entries processed.')


# ---------------------------------------------------------------------------
# OpenPhish  (free tier — plain text URL list)
# ---------------------------------------------------------------------------
def seed_openphish():
    print('\n[OpenPhish] Downloading feed...')
    url = 'https://openphish.com/feed.txt'
    try:
        r = requests.get(url, headers={'User-Agent': 'LidaShield/1.0'}, timeout=60)
        r.raise_for_status()
    except Exception as e:
        print(f'  ERROR: {e}')
        return

    lines = [l.strip() for l in r.text.splitlines() if l.strip()]
    print(f'  {len(lines)} entries downloaded.')

    rows = []
    for target_url in lines:
        domain = urlparse(target_url).netloc.lower()
        rows.append((target_url, domain, 'phishing'))

    n = bulk_insert(rows, 'openphish', 0)
    print(f'  Done — {len(rows)} entries processed.')


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
def print_stats():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute('SELECT source, COUNT(*) FROM threats GROUP BY source ORDER BY COUNT(*) DESC')
    rows = cur.fetchall()
    cur.execute('SELECT COUNT(*) FROM threats')
    total = cur.fetchone()[0]
    conn.close()

    print(f'\n{"─"*40}')
    print(f'  Threat DB total: {total:,}')
    for source, count in rows:
        print(f'  {source:<15} {count:>8,}')
    print(f'{"─"*40}\n')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LidaShield threat DB seeder')
    parser.add_argument('--phishtank',  action='store_true')
    parser.add_argument('--urlhaus',    action='store_true')
    parser.add_argument('--openphish',  action='store_true')
    args = parser.parse_args()

    run_all = not any([args.phishtank, args.urlhaus, args.openphish])

    print('LidaShield Threat Seeder')
    print(f'Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    if run_all or args.phishtank:
        seed_phishtank()
    if run_all or args.urlhaus:
        seed_urlhaus()
    if run_all or args.openphish:
        seed_openphish()

    print_stats()
    print('Done.')
