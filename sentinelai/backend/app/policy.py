"""Policy / verdict engine — combines signals into a final decision.

Verdicts: allow | sanitize | confirm | block
"""

from __future__ import annotations

from app.models import Finding, FirewallMatch, Verdict


def compute_verdict(
    findings: list[Finding],
    firewall_matches: list[FirewallMatch],
    session: dict,
) -> tuple[Verdict, float]:
    """Compute a scan verdict from sniffer findings and firewall matches.

    Returns (verdict, risk_score).
    """
    if not findings and not firewall_matches:
        return Verdict.ALLOW, 0.0

    # Aggregate risk: max of all individual risks
    risks = [f.risk for f in findings] + [m.severity for m in firewall_matches]
    max_risk = max(risks, default=0.0)

    # Check for deterministic block conditions
    block_labels = {"exfiltration", "stealth-command", "code-exec", "markdown-exfil"}
    for m in firewall_matches:
        if m.label in block_labels and m.severity >= 0.85:
            return Verdict.BLOCK, max(max_risk, 0.90)

    # Tainted session escalates everything
    if session.get("tainted"):
        if max_risk >= 0.5:
            return Verdict.BLOCK, max_risk
        if max_risk >= 0.3:
            return Verdict.CONFIRM, max_risk

    # Standard thresholds
    if max_risk >= 0.80:
        return Verdict.BLOCK, max_risk
    if max_risk >= 0.50:
        return Verdict.SANITIZE, max_risk
    if max_risk >= 0.30:
        return Verdict.CONFIRM, max_risk

    return Verdict.ALLOW, max_risk


def compute_action_verdict(
    aligned: bool,
    confidence: float,
    session: dict,
) -> tuple[Verdict, float]:
    """Compute a verdict for a proposed agent action.

    Returns (verdict, risk_score).
    """
    if aligned and confidence >= 0.7:
        return Verdict.ALLOW, 1.0 - confidence

    risk = 1.0 - confidence

    # Tainted session + misaligned = block
    if session.get("tainted") and not aligned:
        return Verdict.BLOCK, max(risk, 0.80)

    if not aligned:
        if confidence < 0.3:
            return Verdict.BLOCK, risk
        return Verdict.CONFIRM, risk

    # Aligned but low confidence
    return Verdict.CONFIRM, risk
