"""
shared.py — Utilities used across multiple lab modules.

Contents:
  - Prompt model (FastAPI request body)
  - parse_body()  — safely parse JSON or plain-text prompt
  - redact_pii()  — regex-based PII scrubber (used by LLM06, LLM07)
  - make_embedding() / cosine_sim() — tiny deterministic embeddings (LLM04)
  - detect_sql_injection() — SQL injection pattern check (LLM07)
  - is_internal_url()     — SSRF host check (LLM04, LLM07)
"""

import re
import math
import json
import time
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class Prompt(BaseModel):
    """Single text field sent by the API gateway to every lab endpoint."""
    text: str


# ---------------------------------------------------------------------------
# Body parsing
# ---------------------------------------------------------------------------

def parse_body(prompt: Prompt) -> dict:
    """
    Try to decode prompt.text as JSON.
    Fall back to {"query": text} if it is plain text.
    This lets every endpoint accept both JSON payloads and raw strings.
    """
    try:
        return json.loads(prompt.text)
    except Exception:
        return {"query": prompt.text}


# ---------------------------------------------------------------------------
# PII redaction  (LLM06, LLM07)
# ---------------------------------------------------------------------------

_PII_PATTERNS = [
    (r'\b\d{3}-\d{2}-\d{4}\b',                                         '[SSN REDACTED]'),
    (r'\b\d{4}-\d{4}-\d{4}-\d{4}\b',                                   '[CARD REDACTED]'),
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',         '[EMAIL REDACTED]'),
    (r'\b[A-Z]+-(?:API-KEY|OVERRIDE-TOKEN|TOKEN)-[A-Za-z0-9]+\b',      '[TOKEN REDACTED]'),
    (r'(?i)password:\s*\S+',                                            '[PASSWORD REDACTED]'),
    (r'http://internal-[^\s]+',                                         '[INTERNAL URL REDACTED]'),
]

def redact_pii(text: str) -> str:
    """Remove SSNs, credit cards, emails, API tokens, passwords from text."""
    for pattern, replacement in _PII_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


# ---------------------------------------------------------------------------
# Deterministic mini-embeddings  (LLM04)
# ---------------------------------------------------------------------------

def make_embedding(text: str) -> list:
    """
    8-dimensional character-frequency embedding.
    Not a real neural embedding — just enough to demonstrate
    semantic-similarity retrieval for the LLM04 lab.
    """
    t = text.lower()
    vec = [0.0] * 8
    for i, ch in enumerate(t):
        vec[i % 8] += ord(ch) / 1000.0
    magnitude = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / magnitude for v in vec]


def cosine_sim(a: list, b: list) -> float:
    """Cosine similarity between two vectors."""
    dot  = sum(x * y for x, y in zip(a, b))
    ma   = math.sqrt(sum(x * x for x in a)) or 1.0
    mb   = math.sqrt(sum(x * x for x in b)) or 1.0
    return dot / (ma * mb)


def retrieve(query: str, db: list, top_k: int = 3, access_level: str = None) -> list:
    """
    Return top-k documents from db ordered by cosine similarity to query.
    If access_level is given, only documents whose access_level is 'all'
    or matches access_level are considered.
    """
    q_emb = make_embedding(query)
    scored = []
    for doc in db:
        if access_level and doc.get("access_level") not in ("all", access_level):
            continue
        sim = cosine_sim(q_emb, make_embedding(doc["content"]))
        scored.append((sim, doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [doc for _, doc in scored[:top_k]]


# ---------------------------------------------------------------------------
# SQL injection detection  (LLM07)
# ---------------------------------------------------------------------------

_SQL_INJECTION_PATTERNS = [
    (r"OR\s+1\s*=\s*1",               "OR 1=1 tautology"),
    (r";\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)", "destructive statement chaining"),
    (r"--\s*$",                        "comment-based injection"),
    (r"UNION\s+SELECT",               "UNION-based extraction"),
    (r"'\s*OR\s*'",                   "string-based OR injection"),
    (r"xp_cmdshell",                  "stored procedure injection"),
]

def detect_sql_injection(text: str) -> tuple:
    """Returns (is_injected: bool, technique: str | None)."""
    for pattern, label in _SQL_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True, label
    return False, None


# ---------------------------------------------------------------------------
# SSRF / internal URL detection  (LLM04, LLM07)
# ---------------------------------------------------------------------------

_BLOCKED_HOSTS = [
    "localhost", "127.0.0.1", "192.168.", "10.", "172.16.",
    "169.254.", "file:", "::1",
]

def is_internal_url(url: str) -> tuple:
    """
    Returns (is_internal: bool, reason: str | None).
    Blocks private IP ranges, loopback, link-local, and file:// scheme.
    Only HTTPS is permitted for web-searcher plugin.
    """
    for host in _BLOCKED_HOSTS:
        if host in url.lower():
            return True, f"URL targets internal/private host: '{host}'"
    if not url.lower().startswith("https://"):
        scheme = url.split(":")[0]
        return True, f"Only HTTPS allowed; URL uses disallowed scheme: '{scheme}'"
    return False, None


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
