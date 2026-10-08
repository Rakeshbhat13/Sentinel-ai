# SentinelAI — Progress Log

## Stage 1: Backend Skeleton ✅
- Created full FastAPI app with 6 endpoints: `/v1/health`, `/v1/session`, `/v1/scan`, `/v1/action`, `/v1/egress`, `/v1/trail/{session_id}`
- All Pydantic models defined in `models.py`
- Session store with Redis fallback to in-memory dict
- SQLite audit DB initialization with indexes
- CORS enabled for dashboard integration

## Stage 2: Normalizer + Sniffer + extractor.js ✅
- `normalizer.py`: NFKC normalization, zero-width/BiDi stripping, Cyrillic/Greek homoglyph folding, inline base64 decode
- `sniffer.py`: Detects 12+ hiding techniques (display:none, visibility:hidden, opacity:0, font-size:0, zero-pixel box, off-screen, clip/clip-path, aria-hidden, color camouflage, overflow clip, alt/title attrs, HTML comments, CSS pseudo-content). Uses WCAG contrast ratio for color-camouflage detection.
- `extractor.js`: Browser-side script for Playwright/extension that collects DOM nodes with getComputedStyle, getBoundingClientRect, HTML comments, and CSS pseudo-content
- Tests written for normalizer (6) and sniffer (12)

## Stage 3: Egress + Canary + Policy ✅
- `canary.py`: Per-session fake credential generation (API key, session token, email), context block builder, leak detection with URL/base64 decoding layers
- `egress.py`: 7-check pipeline (canary leak → domain denylist → secrets/PII → base64 blobs → markdown exfil → taint state → unknown domain)
- `policy.py`: Verdict engine combining findings and firewall matches with taint escalation
- Tests: canary (5), egress (5), policy (4)

## Stage 4: Firewall + Alignment ✅
- `firewall.py`: 28 regex patterns (prompt-override, persona-hijack, system-override/extraction, stealth, exfiltration, code-exec, XSS, markdown-exfil, chained attacks, Hindi/Kannada). Pluggable LLM judge (abstract + Mock + Gemini). Ambiguity-band escalation.
- `alignment.py`: Heuristic fallback (domain mismatch, data-sending tool, sensitive args) + optional Gemini LLM check
- `audit.py`: SQLite-backed event log with chain_id attribution
- Tests: firewall (9)

## Stage 5: All endpoints wired ✅
- All routes connected: session → scan → action → egress → trail
- Lazy imports avoid circular dependencies
- Session taint propagation on hidden content detection and canary leaks

## Current: Stage 6 — Demo pages + mock agent
- TODO

## Pending
- Stage 7: Dashboard (React + Vite + Tailwind)
- Stage 8: Evaluation script + README
