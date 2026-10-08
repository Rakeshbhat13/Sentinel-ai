"""Audit trail — SQLite-backed event log with attribution chain tracking.

Every event shares a chain_id linking:
  hidden element → payload → attempted action → verdict
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone

from app.models import AuditEvent, EventType

log = logging.getLogger("sentinelai.audit")

_db: sqlite3.Connection | None = None


def init_db(db: sqlite3.Connection):
    """Store the DB connection for use by audit functions."""
    global _db
    _db = db


async def log_event(
    session_id: str,
    chain_id: str,
    event_type: str,
    details: dict,
) -> str:
    """Log an audit event. Returns the event ID."""
    event_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()

    if _db:
        try:
            _db.execute(
                "INSERT INTO audit_events (id, chain_id, session_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, chain_id, session_id, event_type, now, json.dumps(details)),
            )
            _db.commit()
        except Exception as e:
            log.error("Failed to log audit event: %s", e)
    else:
        log.warning("No DB connection — audit event %s not persisted.", event_id)

    return event_id


def get_events(session_id: str) -> list[AuditEvent]:
    """Retrieve all events for a session, ordered by timestamp."""
    if not _db:
        return []

    try:
        cursor = _db.execute(
            "SELECT id, chain_id, session_id, event_type, timestamp, details "
            "FROM audit_events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        rows = cursor.fetchall()
        events = []
        for row in rows:
            events.append(AuditEvent(
                id=row[0],
                chain_id=row[1],
                session_id=row[2],
                event_type=EventType(row[3]),
                timestamp=datetime.fromisoformat(row[4]),
                details=json.loads(row[5]) if row[5] else {},
            ))
        return events
    except Exception as e:
        log.error("Failed to retrieve audit events: %s", e)
        return []
