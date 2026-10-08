"""SentinelAI — FastAPI application entry point.

Wires up all modules, manages session state (Redis or in-memory fallback),
and exposes the full API surface.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import (
    ActionRequest, ActionResponse,
    EgressRequest, EgressResponse,
    HealthResponse,
    ScanRequest, ScanResponse,
    SessionCreate, SessionResponse,
    TrailResponse, Verdict,
)

load_dotenv()

VERSION = "0.1.0"
DB_PATH = Path(os.getenv("SQLITE_PATH", "sentinelai.db"))

log = logging.getLogger("sentinelai")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
)

# ── State ─────────────────────────────────────────────────────────────────────

_sessions: dict[str, dict] = {}
_redis = None
_db: sqlite3.Connection | None = None


def _init_redis():
    global _redis
    url = os.getenv("REDIS_URL")
    if not url:
        log.info("REDIS_URL not set — using in-memory session store.")
        return
    try:
        import redis as _redis_lib
        _redis = _redis_lib.Redis.from_url(url, decode_responses=True)
        _redis.ping()
        log.info("Redis connected: %s", url)
    except Exception as e:
        log.warning("Redis unavailable (%s) — using in-memory session store.", e)
        _redis = None


def _init_db():
    global _db
    try:
        _db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _db.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                chain_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}'
            )
        """)
        _db.execute("CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id)")
        _db.execute("CREATE INDEX IF NOT EXISTS idx_audit_chain ON audit_events(chain_id)")
        _db.commit()
        log.info("SQLite audit DB ready: %s", DB_PATH)

        # Wire the DB into the audit module
        from app.audit import init_db
        init_db(_db)
    except Exception as e:
        log.error("SQLite init failed: %s", e)
        _db = None


# ── Session store ─────────────────────────────────────────────────────────────

def store_session(session_id: str, data: dict):
    if _redis:
        _redis.set(f"session:{session_id}", json.dumps(data, default=str), ex=7200)
    else:
        _sessions[session_id] = data


def get_session(session_id: str) -> dict | None:
    if _redis:
        raw = _redis.get(f"session:{session_id}")
        return json.loads(raw) if raw else None
    return _sessions.get(session_id)


def update_session(session_id: str, updates: dict):
    data = get_session(session_id)
    if data:
        data.update(updates)
        store_session(session_id, data)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    _init_redis()
    _init_db()
    yield
    if _db:
        _db.close()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="SentinelAI", version=VERSION, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/v1/health", response_model=HealthResponse)
async def health():
    redis_status = "unavailable"
    if _redis:
        try:
            _redis.ping()
            redis_status = "connected"
        except Exception:
            redis_status = "error"

    return HealthResponse(
        status="ok",
        version=VERSION,
        redis=redis_status,
        sqlite="connected" if _db else "unavailable",
        llm_judge="available" if os.getenv("GEMINI_API_KEY") else "unavailable (mock fallback)",
    )


# ── Session ───────────────────────────────────────────────────────────────────

@app.post("/v1/session", response_model=SessionResponse)
async def create_session(req: SessionCreate):
    from app.canary import build_canary_block, generate_canary_tokens

    sid = uuid.uuid4().hex[:16]
    canary = generate_canary_tokens()
    now = datetime.now(timezone.utc)

    store_session(sid, {
        "session_id": sid,
        "goal": req.goal,
        "canary": canary.model_dump(),
        "tainted": False,
        "taint_reason": "",
        "created_at": now.isoformat(),
    })

    log.info("SESSION created: %s  goal='%s'", sid, req.goal[:80])
    return SessionResponse(
        session_id=sid,
        canary_block=build_canary_block(canary),
        created_at=now,
    )


# ── Scan ──────────────────────────────────────────────────────────────────────

@app.post("/v1/scan", response_model=ScanResponse)
async def scan_page(req: ScanRequest):
    session = get_session(req.session_id)
    if not session:
        raise HTTPException(404, "Session not found.")

    from app.audit import log_event
    from app.firewall import analyze_intent
    from app.normalizer import normalize_text
    from app.policy import compute_verdict
    from app.sniffer import sniff_dom

    chain_id = uuid.uuid4().hex[:12]

    # Step 1: Sniff hidden elements
    findings = sniff_dom(req.nodes, req.visible_text, req.html_comments, req.css_pseudo_content)
    for f in findings:
        f.chain_id = chain_id

    # Step 2: Normalize and run firewall on hidden text
    all_firewall_matches = []
    for finding in findings:
        clean = normalize_text(finding.extracted_text)
        matches = await analyze_intent(clean)
        all_firewall_matches.extend(matches)

    # Step 3: Compute verdict
    verdict, risk_score = compute_verdict(findings, all_firewall_matches, session)

    # Step 4: Taint session if hidden content is risky
    if findings and risk_score > 0.3:
        update_session(req.session_id, {
            "tainted": True,
            "taint_reason": f"Hidden content detected on {req.url}",
        })

    # Step 5: Audit log
    await log_event(
        session_id=req.session_id, chain_id=chain_id, event_type="scan",
        details={
            "url": req.url,
            "findings_count": len(findings),
            "firewall_matches": len(all_firewall_matches),
            "verdict": verdict.value,
            "risk_score": risk_score,
        },
    )

    log.info("SCAN  %s  risk=%.2f  verdict=%s  findings=%d  url=%s",
             "🛡️" if verdict == Verdict.ALLOW else "🚨",
             risk_score, verdict.value, len(findings), req.url)

    return ScanResponse(
        verdict=verdict,
        risk_score=risk_score,
        findings=findings,
        firewall_matches=all_firewall_matches,
        sanitized_text=req.visible_text,
        chain_id=chain_id,
    )


# ── Action Check ──────────────────────────────────────────────────────────────

@app.post("/v1/action", response_model=ActionResponse)
async def check_action(req: ActionRequest):
    session = get_session(req.session_id)
    if not session:
        raise HTTPException(404, "Session not found.")

    from app.alignment import check_alignment
    from app.audit import log_event
    from app.policy import compute_action_verdict

    chain_id = uuid.uuid4().hex[:12]

    aligned, confidence, reasons = await check_alignment(
        goal=session["goal"],
        tool_name=req.tool_name,
        arguments=req.arguments,
        target_domain=req.target_domain,
    )

    verdict, risk_score = compute_action_verdict(aligned, confidence, session)

    await log_event(
        session_id=req.session_id, chain_id=chain_id, event_type="action_check",
        details={
            "tool_name": req.tool_name, "target_domain": req.target_domain,
            "aligned": aligned, "confidence": confidence, "verdict": verdict.value,
        },
    )

    log.info("ACTION  %s  aligned=%s  verdict=%s  tool=%s  domain=%s",
             "✅" if verdict == Verdict.ALLOW else "⚠️",
             aligned, verdict.value, req.tool_name, req.target_domain)

    return ActionResponse(verdict=verdict, risk_score=risk_score, reasons=reasons, chain_id=chain_id)


# ── Egress ────────────────────────────────────────────────────────────────────

@app.post("/v1/egress", response_model=EgressResponse)
async def check_egress(req: EgressRequest):
    session = get_session(req.session_id)
    if not session:
        raise HTTPException(404, "Session not found.")

    from app.audit import log_event
    from app.egress import check_egress_request

    chain_id = uuid.uuid4().hex[:12]

    verdict, reason = check_egress_request(
        session=session,
        destination=req.destination,
        method=req.method,
        headers=req.headers,
        body=req.body,
    )

    # If canary was leaked, mark session as compromised
    if "HIJACK" in reason:
        update_session(req.session_id, {
            "tainted": True,
            "taint_reason": reason,
        })

    await log_event(
        session_id=req.session_id, chain_id=chain_id, event_type="egress_check",
        details={"destination": req.destination, "method": req.method,
                 "verdict": verdict.value, "reason": reason},
    )

    log.info("EGRESS  %s  verdict=%s  dest=%s",
             "✅" if verdict == Verdict.ALLOW else "🚫", verdict.value, req.destination)

    return EgressResponse(verdict=verdict, reason=reason, chain_id=chain_id)


# ── Trail ─────────────────────────────────────────────────────────────────────

@app.get("/v1/trail/{session_id}", response_model=TrailResponse)
async def get_trail(session_id: str):
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found.")

    from app.audit import get_events
    return TrailResponse(
        session_id=session_id,
        events=get_events(session_id),
        tainted=session.get("tainted", False),
    )


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
