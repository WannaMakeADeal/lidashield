import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None
    dict_row = None

SYSTEM = "You are Lida, the LidaShield scam-intelligence AI. Be evidence-backed and cautious."

URL_RE = re.compile(r"https?://[^\s)>'\"]+", re.I)
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
PHONE_RE = re.compile(r"(?:(?:\+?65|0065)[\s-]?)?[689]\d{3}[\s-]?\d{4}")

SUSPICIOUS_WORDS = ["otp", "login", "verify", "suspend", "locked", "refund", "prize", "urgent", "paynow", "singpass", "dbs", "ocbc", "uob"]


def load_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


def simple_verdict(text: str, score: Optional[int] = None, status: Optional[str] = None) -> str:
    t = (text or "").lower()
    if status in {"verified", "dangerous", "malicious"}:
        return "Dangerous"
    if score is not None and score >= 80:
        return "Suspicious"
    if score is not None and score >= 50:
        return "Suspicious"
    hits = sum(1 for w in SUSPICIOUS_WORDS if w in t)
    if "otp" in t and ("login" in t or "password" in t or "bank" in t):
        return "Dangerous"
    if URL_RE.search(text or "") and hits >= 2:
        return "Suspicious"
    if hits >= 4:
        return "Suspicious"
    return "Unknown"


def build_answer(text: str, evidence: Optional[str] = None, score: Optional[int] = None, status: Optional[str] = None) -> str:
    urls = URL_RE.findall(text or "")
    emails = EMAIL_RE.findall(text or "")
    phones = PHONE_RE.findall(text or "")
    verdict = simple_verdict(text, score, status)
    confidence = score if score is not None else ({"Dangerous": 95, "Suspicious": 80, "Unknown": 10}.get(verdict, 30))

    bullets: List[str] = []
    for url in urls[:5]:
        bullets.append(f"URL indicator found: {url}")
    for email in emails[:3]:
        bullets.append(f"Email indicator found: {email}")
    for phone in phones[:3]:
        bullets.append(f"Phone indicator found: {phone}")

    lower = (text or "").lower()
    for w in SUSPICIOUS_WORDS:
        if w in lower:
            bullets.append(f"Message contains scam-relevant term: {w}")
    if evidence:
        bullets.append(f"LidaShield evidence: {evidence[:500]}")
    if not bullets:
        bullets.append("No strong scam indicator was found in the text alone.")

    action = "Do not click links or share OTP/passwords. Verify through the official app/site directly." if verdict in {"Suspicious", "Dangerous"} else "No scam evidence found from this text alone. Stay cautious if links, payments, OTPs, or login requests appear later."

    return "Verdict: {verdict}\nConfidence: {confidence}\nEvidence:\n- {evidence}\nRecommended action:\n- {action}".format(
        verdict=verdict,
        confidence=max(0, min(100, int(confidence))),
        evidence="\n- ".join(dict.fromkeys(bullets)),
        action=action,
    )


def sft_row(user_text: str, answer: str) -> Dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Analyze this scam message or indicator evidence:\n{user_text}"},
            {"role": "assistant", "content": answer},
        ]
    }


def from_db(database_url: str) -> Iterable[Dict[str, Any]]:
    if psycopg is None:
        raise RuntimeError("psycopg is not installed. Run: pip install -r requirements-lida-train.txt")
    with psycopg.connect(database_url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            # Try flexible table names because LidaShield evolved fast.
            queries = [
                ("scam_reports", "SELECT * FROM scam_reports ORDER BY id DESC LIMIT 1000"),
                ("intelligence_events", "SELECT * FROM intelligence_events ORDER BY id DESC LIMIT 1000"),
                ("analyst_observations", "SELECT * FROM analyst_observations ORDER BY id DESC LIMIT 1000"),
                ("feedback", "SELECT * FROM feedback ORDER BY id DESC LIMIT 1000"),
                ("user_feedback", "SELECT * FROM user_feedback ORDER BY id DESC LIMIT 1000"),
            ]
            for table, sql in queries:
                try:
                    cur.execute(sql)
                    rows = cur.fetchall()
                except Exception as e:
                    conn.rollback()
                    print(f"Skipping {table}: {e}")
                    continue
                for r in rows:
                    text_parts = []
                    for key in ["message", "text", "url", "domain", "subject", "details", "reason", "verdict", "status", "signals", "triage_reasons"]:
                        val = r.get(key)
                        if val:
                            text_parts.append(f"{key}: {val}")
                    if not text_parts:
                        continue
                    text = "\n".join(text_parts)
                    score = None
                    for key in ["score", "risk_score", "triage_score", "confidence_score"]:
                        if r.get(key) is not None:
                            try:
                                score = int(r.get(key))
                                break
                            except Exception:
                                pass
                    status = str(r.get("status") or r.get("verdict") or "")
                    answer = build_answer(text, evidence=f"source_table={table}; status={status}", score=score, status=status)
                    yield sft_row(text, answer)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="data/lida_sft.jsonl")
    p.add_argument("--sample-only", action="store_true")
    p.add_argument("--sample", default="sample_lida_sft.jsonl")
    args = p.parse_args()

    out = Path(args.out)
    rows: List[Dict[str, Any]] = []

    sample_path = Path(args.sample)
    if sample_path.exists():
        rows.extend(load_jsonl(sample_path))

    if not args.sample_only:
        db = os.getenv("DATABASE_URL")
        if db:
            rows.extend(from_db(db))
        else:
            print("DATABASE_URL not set. Using sample data only.")

    # Dedupe by user message content.
    seen = set()
    unique = []
    for row in rows:
        try:
            key = row["messages"][1]["content"][:1000]
        except Exception:
            key = json.dumps(row, sort_keys=True)[:1000]
        if key not in seen:
            seen.add(key)
            unique.append(row)

    n = write_jsonl(out, unique)
    print(f"Wrote {n} examples to {out}")


if __name__ == "__main__":
    main()
