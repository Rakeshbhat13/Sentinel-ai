"""Exfiltration Interceptor — validates outbound requests.

Checks (in order): canary leak, domain allowlist/denylist, secrets & PII
in the payload, markdown-image exfil patterns, and session taint state.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, unquote_plus

from app.canary import check_canary_leak
from app.models import Verdict

# ── Domain lists ──────────────────────────────────────────────────────────────

ALLOWED_DOMAINS: set[str] = {
    "api.openai.com", "generativelanguage.googleapis.com",
    "api.anthropic.com", "api.github.com",
    "google.com", "www.google.com",
    "amazon.com", "www.amazon.com",
    "localhost", "127.0.0.1",
}

DENIED_DOMAINS: set[str] = {
    "evil.com", "attacker.com", "malicious.example",
}

# ── Sensitive data patterns ───────────────────────────────────────────────────

_SECRETS_RE = re.compile(
    r"(eyJ[A-Za-z0-9_-]{10,})"                    # JWT tokens
    r"|(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)"  # Email addresses
    r"|(sk-[A-Za-z0-9]{20,})"                      # OpenAI-style API keys
    r"|(sk-proj-[A-Za-z0-9]{20,})"                 # Project API keys
    r"|(api[_-]?key\s*[:=]\s*\S{10,})"             # Generic API keys
    r"|(Bearer\s+\S{20,})"                         # Bearer tokens
    r"|(session[_-]?id\s*[:=]\s*\S{8,})"           # Session IDs
    r"|(\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b)",  # Credit card numbers
    re.I,
)

# Long base64 blobs (potential encoded exfiltration)
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

# Markdown image exfiltration: ![...](https://host/?data=...)
_MD_EXFIL_RE = re.compile(
    r"!\[.*?\]\(https?://[^)]*\?(.*?(data|token|key|session|cookie|secret)[^)]*)\)",
    re.I,
)


def _extract_host(url: str) -> str:
    """Extract hostname from a URL, handling edge cases."""
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def check_egress_request(
    session: dict,
    destination: str,
    method: str,
    headers: dict,
    body: str,
) -> tuple[Verdict, str]:
    """Validate an outbound request. Returns (verdict, reason)."""

    # Combine all text for scanning
    all_text = " ".join([
        destination,
        unquote_plus(destination),
        str(headers),
        body,
        unquote_plus(body) if body else "",
    ])

    # ── 1. Canary leak check (deterministic HIJACK) ──
    canary = session.get("canary", {})
    if canary:
        leaked_field = check_canary_leak(canary, all_text)
        if leaked_field:
            return Verdict.BLOCK, f"HIJACK: Canary token '{leaked_field}' detected in outbound request."

    # ── 2. Domain denylist ──
    host = _extract_host(destination)
    if host in DENIED_DOMAINS:
        return Verdict.BLOCK, f"Destination '{host}' is on the deny list."

    # ── 3. Secrets / PII in payload ──
    secrets_match = _SECRETS_RE.search(body)
    if secrets_match:
        snippet = secrets_match.group()[:40]
        if host not in ALLOWED_DOMAINS:
            return Verdict.BLOCK, f"Payload contains suspected secret ('{snippet}…') sent to non-allowlisted domain '{host}'."
        # Allowed domain but still flag it
        # (don't block — the agent might legitimately be calling an API)

    # ── 4. Long base64 blobs ──
    if _LONG_B64_RE.search(body):
        if host not in ALLOWED_DOMAINS:
            return Verdict.BLOCK, f"Large base64 blob in payload sent to non-allowlisted domain '{host}'."

    # ── 5. Markdown image exfil ──
    if _MD_EXFIL_RE.search(all_text):
        return Verdict.BLOCK, "Markdown image exfiltration pattern detected."

    # ── 6. Tainted session + non-allowlisted domain ──
    if session.get("tainted") and host and host not in ALLOWED_DOMAINS:
        return Verdict.CONFIRM, (
            f"Session is tainted (reason: {session.get('taint_reason', 'unknown')}). "
            f"Outbound request to non-allowlisted domain '{host}' requires confirmation."
        )

    # ── 7. Unknown domain (not allow-listed, not deny-listed) ──
    if host and host not in ALLOWED_DOMAINS:
        return Verdict.CONFIRM, f"Destination '{host}' is not in the allowlist."

    return Verdict.ALLOW, "Egress check passed."
