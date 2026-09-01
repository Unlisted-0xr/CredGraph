from __future__ import annotations
import hashlib, hmac, os

def normalize_secret(value: str) -> str:
    return value.strip().replace("\r\n", "\n").replace("\r", "\n")

def fingerprint_secret(value: str, salt: bytes | None = None) -> str:
    normalized = normalize_secret(value).encode("utf-8", "surrogatepass")
    key = salt or os.environ.get("CREDGRAPH_FINGERPRINT_KEY", "credgraph-dev-key").encode()
    return hmac.new(key, normalized, hashlib.sha256).hexdigest()

def redact_preview(value: str, keep: int = 4) -> str:
    value = value.strip()
    if len(value) <= keep * 2:
        return "[REDACTED]"
    return f"{value[:keep]}…{value[-keep:]}"

def stable_id(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]
