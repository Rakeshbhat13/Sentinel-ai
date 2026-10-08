"""Task-alignment check — validates agent actions against the user's goal.

Uses the pluggable LLM judge for semantic analysis, with a heuristic
fallback when no LLM key is configured.
"""

from __future__ import annotations

import logging
import os
import re
from urllib.parse import urlparse

log = logging.getLogger("sentinelai.alignment")

# Domains commonly associated with legitimate agent tasks
_SAFE_DOMAINS = {
    "google.com", "www.google.com",
    "amazon.com", "www.amazon.com",
    "github.com", "api.github.com",
    "stackoverflow.com",
    "wikipedia.org", "en.wikipedia.org",
}

# Tool names that involve outbound data transfer
_DATA_TOOLS = {"send_email", "post_request", "submit_form", "upload_file",
               "http_post", "http_put", "send_message", "webhook"}


def _heuristic_alignment(
    goal: str, tool_name: str, arguments: dict, target_domain: str,
) -> tuple[bool, float, list[str]]:
    """Simple heuristic check when no LLM is available."""
    reasons: list[str] = []
    confidence = 0.7

    # Parse target domain
    domain = target_domain
    if domain and not domain.startswith("http"):
        domain = f"https://{domain}"
    try:
        host = urlparse(domain).hostname or ""
    except Exception:
        host = ""

    # Rule 1: data-sending tool to unknown domain
    if tool_name.lower() in _DATA_TOOLS and host and host not in _SAFE_DOMAINS:
        reasons.append(f"Tool '{tool_name}' sends data to unknown domain '{host}'.")
        return False, 0.8, reasons

    # Rule 2: goal keywords vs target domain mismatch
    goal_lower = goal.lower()
    if host:
        # Check if domain is related to goal keywords
        goal_words = set(re.findall(r"\w{4,}", goal_lower))
        domain_parts = set(host.replace(".", " ").split())
        if not goal_words & domain_parts and host not in _SAFE_DOMAINS:
            if tool_name.lower() in _DATA_TOOLS:
                reasons.append(
                    f"Goal '{goal[:60]}' does not mention domain '{host}', "
                    f"but tool '{tool_name}' would send data there."
                )
                return False, 0.7, reasons

    # Rule 3: sensitive argument values
    args_str = str(arguments).lower()
    if any(kw in args_str for kw in ["password", "secret", "api_key", "token", "credit_card"]):
        reasons.append("Arguments contain sensitive-looking data.")
        confidence = 0.6
        if tool_name.lower() in _DATA_TOOLS:
            return False, 0.85, reasons

    return True, confidence, reasons


async def check_alignment(
    goal: str, tool_name: str, arguments: dict, target_domain: str,
) -> tuple[bool, float, list[str]]:
    """Check whether a proposed agent action is aligned with the user's goal.

    Returns (aligned: bool, confidence: float, reasons: list[str]).
    """
    # Try LLM judge first if available
    key = os.getenv("GEMINI_API_KEY", "")
    if key:
        try:
            return await _llm_alignment(key, goal, tool_name, arguments, target_domain)
        except Exception as e:
            log.warning("LLM alignment check failed, falling back to heuristic: %s", e)

    return _heuristic_alignment(goal, tool_name, arguments, target_domain)


async def _llm_alignment(
    api_key: str, goal: str, tool_name: str, arguments: dict, target_domain: str,
) -> tuple[bool, float, list[str]]:
    """Ask Gemini whether the action is aligned with the goal."""
    import json
    from google import genai

    client = genai.Client(api_key=api_key)
    prompt = (
        "You are a strict security validator. Given a user's goal and a proposed "
        "agent action, determine if the action is aligned with the goal.\n\n"
        f"User Goal: {goal}\n"
        f"Proposed Action: tool={tool_name}, args={json.dumps(arguments)}, domain={target_domain}\n\n"
        'Respond ONLY with JSON: {"aligned": true/false, "confidence": 0.0-1.0, "reason": "..."}'
    )
    response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
    raw = response.text.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
    result = json.loads(raw)
    return (
        bool(result.get("aligned", True)),
        float(result.get("confidence", 0.5)),
        [result.get("reason", "")],
    )
