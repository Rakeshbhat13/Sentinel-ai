"""SentinelAI — Pydantic schemas for all API contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class Verdict(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    CONFIRM = "confirm"
    BLOCK = "block"


class EventType(str, Enum):
    SCAN = "scan"
    FINDING = "finding"
    FIREWALL = "firewall"
    CANARY_HIT = "canary_hit"
    EGRESS_CHECK = "egress_check"
    ACTION_CHECK = "action_check"
    VERDICT = "verdict"


# ── Session ───────────────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    """Create a new agent session with a declared goal."""
    goal: str = Field(..., min_length=1, description="The user's original goal for the agent.")


class CanaryTokens(BaseModel):
    """Fake credentials injected into agent context as tripwires."""
    api_key: str
    session_token: str
    email: str


class SessionResponse(BaseModel):
    """Returned when a session is created."""
    session_id: str
    canary_block: str = Field(..., description="Context block to inject into the agent prompt.")
    created_at: datetime


# ── DOM / Scanning ────────────────────────────────────────────────────────────

class BoundingBox(BaseModel):
    x: float = 0.0
    y: float = 0.0
    width: float = 0.0
    height: float = 0.0


class ComputedStyles(BaseModel):
    opacity: str = "1"
    font_size: str = "16px"
    color: str = "rgb(0, 0, 0)"
    background_color: str = "rgba(0, 0, 0, 0)"
    display: str = "block"
    visibility: str = "visible"
    position: str = "static"
    left: str = "auto"
    top: str = "auto"
    width: str = "auto"
    height: str = "auto"
    clip: str = "auto"
    clip_path: str = "none"
    z_index: str = "auto"
    overflow: str = "visible"
    aria_hidden: bool = False


class DOMNode(BaseModel):
    """A single DOM element with its computed styles and text content."""
    selector: str = ""
    tag: str = "div"
    text_content: str = ""
    inner_text: str = ""
    alt: str = ""
    title_attr: str = ""
    computed_styles: ComputedStyles = Field(default_factory=ComputedStyles)
    bounding_box: BoundingBox = Field(default_factory=BoundingBox)


class ScanRequest(BaseModel):
    """Full page snapshot for analysis."""
    session_id: str
    url: str
    nodes: list[DOMNode] = []
    visible_text: str = ""
    html_comments: list[str] = []
    css_pseudo_content: list[dict] = []


class Finding(BaseModel):
    """A single detected hidden element / payload."""
    selector: str
    technique: str
    extracted_text: str
    risk: float = Field(ge=0.0, le=1.0)
    chain_id: str = ""


class FirewallMatch(BaseModel):
    """A regex or LLM match from the intent firewall."""
    label: str
    severity: float
    matched_text: str
    start: int = 0
    end: int = 0
    source: str = "heuristic"


class ScanResponse(BaseModel):
    verdict: Verdict
    risk_score: float = Field(ge=0.0, le=1.0)
    findings: list[Finding] = []
    firewall_matches: list[FirewallMatch] = []
    sanitized_text: str = ""
    chain_id: str = ""


# ── Action Check ──────────────────────────────────────────────────────────────

class ActionRequest(BaseModel):
    """A proposed agent action to validate for task alignment."""
    session_id: str
    tool_name: str
    arguments: dict = {}
    target_domain: str = ""


class ActionResponse(BaseModel):
    verdict: Verdict
    risk_score: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = []
    chain_id: str = ""


# ── Egress ────────────────────────────────────────────────────────────────────

class EgressRequest(BaseModel):
    """An outbound network request to validate before sending."""
    session_id: str
    destination: str
    method: str = "GET"
    headers: dict = {}
    body: str = ""


class EgressResponse(BaseModel):
    verdict: Verdict
    reason: str = ""
    chain_id: str = ""


# ── Audit Trail ───────────────────────────────────────────────────────────────

class AuditEvent(BaseModel):
    id: str
    chain_id: str
    session_id: str
    event_type: EventType
    timestamp: datetime
    details: dict = {}


class TrailResponse(BaseModel):
    session_id: str
    events: list[AuditEvent] = []
    tainted: bool = False


# ── Health ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    redis: str = "unavailable"
    sqlite: str = "unavailable"
    llm_judge: str = "unavailable"
