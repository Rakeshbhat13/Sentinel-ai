# 🛡️ SentinelAI — Autonomous Security Shield

> **Digital Safety & Cybersecurity Hackathon 2026**  
> Protecting AI Browser Agents & Users from Indirect Prompt Injections, Invisible DOM Payloads, and Unauthorized Exfiltration.

---

## 🎯 The Problem

Modern AI browser agents (such as Claude Computer Use, Browser-Use, MultiOn, and Devin) read webpage text via `textContent` or full DOM dumps. 

Attackers exploit this blind spot by placing **indirect prompt injections** inside invisible DOM elements:
- **Zero-pixel containers** (`width: 0; height: 0; overflow: hidden`)
- **Color camouflage** (white text on white background with 1:1 contrast ratio)
- **Off-screen negative coordinates** (`left: -9999px`)
- **Accessibility bypasses** (`aria-hidden="true"`)
- **Hidden HTML comments & CSS pseudo-content**
- **Image alt attributes & homoglyphs** (Cyrillic, BiDi direction overrides)

Human users see a normal product review or flight confirmation, but the AI agent silently executes the malicious payload—exfiltrating session cookies, user credentials, and API tokens to attacker servers.

---

## 💡 The SentinelAI Solution

**SentinelAI** acts as an autonomous, multi-layered security shield situated between the untrusted web and the AI browser agent:

1. **Invisible DOM Sniffer**: Computes the **visibility delta** between what a human sees (`innerText`) and what the agent parses (`textContent`). Analyzes layout dimensions, CSS styles, and WCAG contrast ratios to strip hidden payloads before they reach agent context.
2. **Semantic Intent Firewall**: Inspects parsed text with a two-tier defense: 28 sub-millisecond regex heuristic rules + pluggable LLM Judge (with mock fallback or Gemini) to trap behavioral overrides, persona hijacks, and exfiltration directives.
3. **Canary Tripwires & Egress Interceptor**: Injects ephemeral, cryptographically unique honeypot credentials into session prompts. If any outbound network request contains a canary token or hits an untrusted domain, the egress proxy blocks it instantly.
4. **Session Taint Isolation & Immutable Audit Log**: Escalates security posture if suspicious nodes are detected, and records every event into an indexed SQLite audit database with forensic chain attribution.

---

## 🏗️ Architecture

```
                                  [ Untrusted Webpage ]
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     ▼                                             ▼
            [ Human Display ]                             [ Raw DOM Nodes ]
           (Rendered innerText)                       (textContent, CSS styles)
                     │                                             │
                     └──────────────────────┬──────────────────────┘
                                            │
                                            ▼
                           ┌─────────────────────────────────┐
                           │   1. Invisible DOM Sniffer      │
                           │   - Visibility Delta            │
                           │   - WCAG Contrast Check         │
                           │   - 12+ Hiding Techniques       │
                           │   - Homoglyph & BiDi Fold       │
                           └────────────────┬────────────────┘
                                            │
                                            ▼
                           ┌─────────────────────────────────┐
                           │   2. Semantic Intent Firewall   │
                           │   - 28 Heuristic Rules          │
                           │   - Ambiguity Escalation Band   │
                           │   - Pluggable LLM Judge         │
                           └────────────────┬────────────────┘
                                            │
                                            ▼
                           ┌─────────────────────────────────┐
                           │   3. Verdict & Policy Engine    │
                           │   - ALLOW | SANITIZE            │
                           │   - CONFIRM | BLOCK             │
                           └────────────────┬────────────────┘
                                            │ (Sanitized Content)
                                            ▼
                                   [ AI Browser Agent ]
                                            │
                                            ▼ Outbound Actions
                           ┌─────────────────────────────────┐
                           │   4. Egress Proxy & Canaries    │
                           │   - Canary Leak Detection       │
                           │   - Domain Whitelist / Denylist │
                           │   - PII & Secret Filters        │
                           └────────────────┬────────────────┘
                                            │
                                            ▼
                               [ SQLite Forensic Audit Log ]
```

---

## 📊 Benchmark & Evaluation Results

Tested on a benchmark corpus of **28 attack variants** across all 12+ hiding techniques, obfuscations, and multilingual variants against **26 clean, benign web pages** (`eval/run_eval.py`):

| Metric | Result | Benchmark Target | Status |
| :--- | :---: | :---: | :---: |
| **Detection Rate (Recall / TPR)** | **100.00%** | > 95% | 🏆 Perfect |
| **False Positive Rate (FPR)** | **0.00%** | < 2% | 🏆 Zero FP |
| **Precision** | **100.00%** | > 95% | 🏆 Perfect |
| **F1 Score** | **1.0000** | > 0.95 | 🏆 Perfect |
| **Latency (p50 Median)** | **0.13 ms** | < 10 ms | ⚡ Real-Time |
| **Latency (p95)** | **0.40 ms** | < 25 ms | ⚡ Real-Time |
| **Latency (p99)** | **0.57 ms** | < 50 ms | ⚡ Real-Time |

*Full raw evaluation breakdown stored in `eval/results.json`.*

---

## 🚀 Quickstart & How to Run

SentinelAI is structured to run simply with three single-line commands:

### 1. Start the Backend API

```bash
# From sentinelai/backend directory:
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
- Exposes API endpoints at `http://localhost:8000`:
  - `GET  /v1/health`
  - `POST /v1/session`
  - `POST /v1/scan`
  - `POST /v1/action`
  - `POST /v1/egress`
  - `GET  /v1/trail/{session_id}`
- Works out-of-the-box without Redis or external keys (in-memory + SQLite fallback).

### 2. Start the Frontend Dashboard

```bash
# From sentinelai/dashboard directory:
npm install
npm run dev
```
- Open `http://localhost:5173` in your browser.
- Explore the interactive **Visibility Delta Diff View**, **Intent Firewall Inspector**, **Canary Sandbox**, and **Immutable Audit Trail**.

### 3. Run the End-to-End Demo

```bash
# From the repository root:
python sentinelai/demo/run_demo.py
```
- Automatically executes:
  1. **Unprotected Agent**: Simulates an agent falling victim to indirect prompt injection and leaking session tokens.
  2. **Shielded Agent**: Demonstrates SentinelAI neutralizing 6 attack vectors and trapping egress exfiltration.
  3. **Benign Pages**: Verifies 0% false positive pass-through on clean content.

---

## 🧪 Running the Test Suite & Benchmark

### Run Core Pytest Suite (41 tests)
```bash
pytest sentinelai/backend/tests/test_core.py -v
```

### Run Benchmark Evaluation (54 samples)
```bash
python sentinelai/eval/run_eval.py
```

---

## 📂 Repository Layout

```
sentinelai/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI endpoints, CORS, lifespan, session store
│   │   ├── models.py          # Pydantic schemas (DOMNode, Finding, Verdict, etc.)
│   │   ├── normalizer.py      # NFKC, zero-width strip, homoglyph folding, b64 decode
│   │   ├── sniffer.py         # Invisible DOM Sniffer (12+ hiding vectors, WCAG contrast)
│   │   ├── firewall.py        # Semantic Intent Firewall (28 regex heuristics + LLM judge)
│   │   ├── canary.py          # Canary credential generation & leak tripwires
│   │   ├── alignment.py       # Task-intent alignment validation
│   │   ├── egress.py          # Egress proxy filter & exfiltration interceptor
│   │   ├── policy.py          # Verdict decision engine (allow | sanitize | confirm | block)
│   │   └── audit.py           # SQLite forensic event log
│   ├── tests/
│   │   └── test_core.py       # 41 unit & integration tests
│   └── requirements.txt
├── dashboard/                 # React + Vite + Tailwind CSS cybersecurity dashboard
│   ├── src/
│   │   ├── App.jsx            # Diff view, Threat stream, Canary sandbox, Audit trail
│   │   └── index.css          # Cyber-dark theme styles & Tailwind v4
│   └── package.json
├── demo/
│   ├── attack_pages/          # 6 static attack scenarios (zero-pixel, camo, off-screen, etc.)
│   ├── clean_pages/           # 3 clean benign pages
│   ├── mock_agent.py          # Browser agent loop (Unprotected vs Shielded)
│   ├── run_demo.py            # Automated end-to-end demo runner
│   └── extractor.js           # Browser-side DOM scanner script
├── eval/
│   ├── run_eval.py            # 54-sample evaluation script
│   └── results.json           # Benchmark output metrics
└── PROGRESS.md                # Development stage tracker
```

---

## 🔒 Security & Code Quality

SentinelAI enforces strict security standards via GitHub Actions:
- **SAST scanning**: Semgrep + Bandit + CodeQL catch injection flaws, crypto misuse, logic bugs
- **Type safety**: mypy in strict mode
- **Code quality**: pylint (>8.5), black formatting
- **Dependency audit**: pip-audit + npm audit
- **Secrets detection**: TruffleHog prevents credential leaks

All checks must pass before merge.

---

## 🛡️ License

MIT License • Built for the Digital Safety & Cybersecurity Hackathon 2026.
