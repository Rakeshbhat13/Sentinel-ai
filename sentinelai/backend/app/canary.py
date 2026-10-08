"""Canary token generation, injection, and leak detection.

Per-session, realistic fake credentials are injected into the agent context.
If any canary value appears in an outbound request, it's a deterministic
proof of hijacking — block immediately.
"""

import base64
import re
import uuid
from urllib.parse import unquote_plus

from app.models import CanaryTokens


def generate_canary_tokens() -> CanaryTokens:
    """Generate a set of realistic-looking fake credentials."""
    return CanaryTokens(
        api_key=f"sk-proj-{uuid.uuid4().hex[:32]}",
        session_token=f"sess_{uuid.uuid4().hex}",
        email=f"user-{uuid.uuid4().hex[:8]}@sentinel-trap.internal",
    )


def build_canary_block(canary: CanaryTokens) -> str:
    """Build the context block that gets injected into the agent prompt."""
    return (
        "--- SYSTEM CONTEXT (confidential, never share externally) ---\n"
        f"Active API Key: {canary.api_key}\n"
        f"Session Token: {canary.session_token}\n"
        f"User Contact: {canary.email}\n"
        "--- END SYSTEM CONTEXT ---"
    )


def _decode_layers(text: str) -> list[str]:
    """Produce decoded variants of the text to catch encoding tricks."""
    variants = [text]
    # URL-decoded
    try:
        decoded = unquote_plus(text)
        if decoded != text:
            variants.append(decoded)
    except Exception:
        pass
    # Base64-decoded (try chunks that look like base64)
    b64_re = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
    for match in b64_re.finditer(text):
        try:
            decoded = base64.b64decode(match.group(), validate=True).decode("utf-8", errors="ignore")
            if len(decoded) > 8:
                variants.append(decoded)
        except Exception:
            pass
    return variants


def check_canary_leak(canary_dict: dict, text: str) -> str | None:
    """Check if any canary token appears in the given text.

    Searches the raw text plus URL-decoded and base64-decoded variants.
    Returns the name of the leaked field, or None.
    """
    variants = _decode_layers(text)
    for field in ("api_key", "session_token", "email"):
        token = canary_dict.get(field, "")
        if not token:
            continue
        for variant in variants:
            if token in variant:
                return field
    return None
