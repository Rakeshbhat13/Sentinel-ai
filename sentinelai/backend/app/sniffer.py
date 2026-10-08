"""Invisible DOM Sniffer — detects hidden text payloads in page snapshots.

Analyses DOM nodes with their computed styles and bounding boxes to find text
that is present in the agent-readable DOM (textContent) but invisible to a
human user. Each detected payload is returned as a Finding with the hiding
technique identified.
"""

from __future__ import annotations

import re

from app.models import BoundingBox, ComputedStyles, DOMNode, Finding

# Minimum text length to consider as a payload (skip tiny fragments)
_MIN_PAYLOAD_LEN = 10


# ── Style-based detection ────────────────────────────────────────────────────

def _parse_px(val: str) -> float:
    """Extract numeric value from a CSS pixel string like '16px' or '0'."""
    m = re.match(r"(-?[\d.]+)", val)
    return float(m.group(1)) if m else 0.0


def _parse_rgb(val: str) -> tuple[int, int, int] | None:
    """Parse 'rgb(r,g,b)' or 'rgba(r,g,b,a)' to (r,g,b). Returns None if
    the value is transparent or unparseable."""
    m = re.match(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\s*\)", val)
    if not m:
        return None
    # If alpha is present and 0, the background is transparent
    if m.group(4) is not None and float(m.group(4)) == 0:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _contrast_ratio(c1: tuple[int, int, int], c2: tuple[int, int, int]) -> float:
    """Relative luminance contrast ratio per WCAG 2.0."""
    def lum(c: tuple[int, int, int]) -> float:
        srgb = [v / 255.0 for v in c]
        linear = [(v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4) for v in srgb]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    l1 = lum(c1)
    l2 = lum(c2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def _detect_hiding_technique(cs: ComputedStyles, bbox: BoundingBox) -> str | None:
    """Return the hiding technique name if the element is invisible, else None."""
    # display: none
    if cs.display == "none":
        return "display:none"

    # visibility: hidden
    if cs.visibility == "hidden":
        return "visibility:hidden"

    # opacity: 0
    try:
        if float(cs.opacity) == 0:
            return "opacity:0"
    except ValueError:
        pass

    # font-size: 0
    if _parse_px(cs.font_size) == 0:
        return "font-size:0"

    # Zero or tiny bounding box
    if bbox.width <= 1 or bbox.height <= 1:
        return "zero-pixel-box"

    # Off-screen positioning
    if cs.position in ("absolute", "fixed"):
        left = _parse_px(cs.left)
        top = _parse_px(cs.top)
        if left < -5000 or top < -5000:
            return "off-screen"

    # Clip / clip-path hiding
    if cs.clip not in ("auto", "none", ""):
        if "rect(0" in cs.clip or "inset(50%)" in cs.clip_path:
            return "clip-hidden"
    if cs.clip_path not in ("none", ""):
        if "inset(50%)" in cs.clip_path or "circle(0" in cs.clip_path:
            return "clip-path-hidden"

    # aria-hidden
    if cs.aria_hidden:
        return "aria-hidden"

    # Color camouflage: text blends into background
    fg = _parse_rgb(cs.color)
    bg = _parse_rgb(cs.background_color)
    if fg and bg:
        ratio = _contrast_ratio(fg, bg)
        if ratio < 1.1:  # Nearly identical
            return "color-camouflage"

    # Overflow hidden with tiny container (text exists but is clipped)
    if cs.overflow == "hidden":
        if bbox.width < 5 or bbox.height < 5:
            return "overflow-clip"

    return None


def _risk_for_technique(technique: str) -> float:
    """Assign a base risk score based on the hiding technique."""
    high = {"display:none", "visibility:hidden", "opacity:0", "font-size:0",
            "zero-pixel-box", "off-screen", "clip-hidden", "clip-path-hidden",
            "overflow-clip"}
    if technique in high:
        return 0.85
    if technique == "color-camouflage":
        return 0.90
    if technique == "aria-hidden":
        return 0.70
    if technique in ("html-comment", "alt-attr", "title-attr", "css-pseudo"):
        return 0.60
    return 0.50


# ── Main entry point ─────────────────────────────────────────────────────────

def sniff_dom(
    nodes: list[DOMNode],
    visible_text: str,
    html_comments: list[str] | None = None,
    css_pseudo_content: list[dict] | None = None,
) -> list[Finding]:
    """Analyse a set of DOM nodes and supplementary data for hidden payloads.

    Returns a list of Findings, one per detected hidden element.
    """
    findings: list[Finding] = []

    for node in nodes:
        # ── Alt / title attribute payloads ──
        for attr_name, attr_val in [("alt-attr", node.alt), ("title-attr", node.title_attr)]:
            val = (attr_val or "").strip()
            if len(val) >= _MIN_PAYLOAD_LEN and val not in visible_text:
                findings.append(Finding(
                    selector=node.selector,
                    technique=attr_name,
                    extracted_text=val[:2000],
                    risk=_risk_for_technique(attr_name),
                ))

        # ── Visibility delta: textContent has text the human can't see ──
        tc = (node.text_content or "").strip()
        it = (node.inner_text or "").strip()

        if not tc:
            continue

        technique = _detect_hiding_technique(node.computed_styles, node.bounding_box)

        if technique:
            # The entire textContent is hidden
            hidden_text = tc
        elif len(tc) > len(it) + _MIN_PAYLOAD_LEN:
            # Partial delta: some text is visible, some is not
            hidden_text = tc.replace(it, "", 1).strip() if it else tc
            technique = "visibility-delta"
        else:
            hidden_text = ""

        if hidden_text and len(hidden_text) >= _MIN_PAYLOAD_LEN:
            findings.append(Finding(
                selector=node.selector,
                technique=technique,
                extracted_text=hidden_text[:2000],
                risk=_risk_for_technique(technique),
            ))

    # ── HTML comments ──
    for i, comment in enumerate(html_comments or []):
        comment = comment.strip()
        if len(comment) >= _MIN_PAYLOAD_LEN:
            findings.append(Finding(
                selector=f"<!--comment[{i}]-->",
                technique="html-comment",
                extracted_text=comment[:2000],
                risk=_risk_for_technique("html-comment"),
            ))

    # ── CSS pseudo-element content (::before / ::after) ──
    for i, pseudo in enumerate(css_pseudo_content or []):
        content = (pseudo.get("content") or "").strip().strip('"').strip("'")
        if len(content) >= _MIN_PAYLOAD_LEN and content not in visible_text:
            findings.append(Finding(
                selector=pseudo.get("selector", f"::pseudo[{i}]"),
                technique="css-pseudo",
                extracted_text=content[:2000],
                risk=_risk_for_technique("css-pseudo"),
            ))

    return findings
