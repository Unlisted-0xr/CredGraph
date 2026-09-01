from __future__ import annotations
import re
from dataclasses import dataclass
from math import log2

@dataclass(frozen=True, slots=True)
class Detection:
    detector: str
    secret_type: str
    value: str
    confidence: float
    context: str
    line: int
    start: int
    end: int

# High-signal vendor formats plus a deliberately conservative generic assignment detector.
PATTERNS = (
    ("aws_access_key", "aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.99),
    ("aws_temp_access_key", "aws_access_key", re.compile(r"\bASIA[0-9A-Z]{16}\b"), 0.96),
    ("github_token", "github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"), 0.99),
    ("gitlab_token", "gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"), 0.99),
    ("slack_token", "slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), 0.98),
    ("stripe_secret", "stripe_secret_key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,255}\b"), 0.99),
    ("sendgrid_key", "sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), 0.98),
    ("private_key", "private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----(?s:.*?)-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 0.995),
    ("jwt", "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.90),
)

ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key|client[_-]?secret)
    \b\s*[:=]\s*["']([^"']{8,512})["']
    """
)

PLACEHOLDERS = {
    "changeme","change_me","your_token","your-token","your_api_key",
    "example","example_token","example-token","dummy","dummy_token",
    "test","test_token","replace_me","replace-this","xxxxxxxx",
}

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum((n / len(s)) * log2(n / len(s)) for n in counts.values())

def _context(text: str, start: int, end: int, radius: int = 120) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0: line_end = len(text)
    raw = text[line_start:line_end].replace("\x00", " ")
    rel_s = start - line_start
    rel_e = end - line_start
    return raw[:rel_s] + "[SECRET_REDACTED]" + raw[rel_e:]

def detect(text: str) -> list[Detection]:
    hits: list[Detection] = []
    seen: set[tuple[str,int,int]] = set()
    seen_values: set[str] = set()

    for detector, secret_type, pattern, base in PATTERNS:
        for m in pattern.finditer(text):
            key = (detector, m.start(), m.end())
            if key in seen: continue
            seen.add(key)
            value = m.group(0)
            seen_values.add(value)
            conf = base
            if secret_type == "jwt" and shannon_entropy(value) < 3.2:
                conf -= 0.15
            line = text.count("\n", 0, m.start()) + 1
            hits.append(Detection(detector, secret_type, value, max(0.0,min(1.0,conf)),
                                  _context(text,m.start(),m.end()), line, m.start(), m.end()))

    for m in ASSIGNMENT.finditer(text):
        key_name, value = m.group(1), m.group(2)
        if value.strip().lower() in PLACEHOLDERS:
            continue
        if value in seen_values:
            continue
        seen_values.add(value)
        entropy = shannon_entropy(value)
        # Short/low-entropy assignment values are intentionally down-ranked.
        conf = 0.50 + min(0.35, max(0.0, entropy - 3.0) * 0.09)
        if len(value) >= 20: conf += 0.04
        line = text.count("\n", 0, m.start()) + 1
        hits.append(Detection("assignment", key_name.lower().replace("-","_"), value,
                              min(conf,0.94), _context(text,m.start(),m.end()), line, m.start(), m.end()))
    return hits
