"""
persistence.py
Atomic disk persistence for assessment sessions.

Each session is stored as sessions/<session_id>.json.
Writes are atomic (write-to-tmp then rename) to avoid corruption on crash.
Credentials are NEVER written to disk — only audit results, AI data, and manual findings.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

SESSIONS_DIR = Path(__file__).parent.parent / "sessions"


def save(session) -> None:
    """Serialize session state to disk. Safe to call from background threads."""
    SESSIONS_DIR.mkdir(exist_ok=True)
    data = {
        "session_id":       session.session_id,
        "state":            session.state,
        "created_at":       session.created_at.isoformat(),
        "updated_at":       datetime.now(timezone.utc).isoformat(),
        "error_message":    session.error_message,
        "device_context":   session.device_context,
        "raw_results":      session.raw_results,
        "enriched_data":    session.enriched_data,
        "manual_findings":  session.manual_findings,
        "report_data":      session.report_data,
        "audit_log":        session.audit_log[-200:],  # cap to avoid huge files
        "total_manual":     session.total_manual,
        "completed_manual": session.completed_manual,
        "ai_model":         session.ai_model,
        "ai_base_url":      session.ai_base_url,
        "frameworks":       session.frameworks,
        "vendor":           session.vendor,
        # ai_api_key intentionally excluded — treat like a credential
    }
    path = SESSIONS_DIR / f"{session.session_id}.json"
    tmp  = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.rename(path)


def load_all() -> list[dict]:
    """Load all saved sessions. Returns raw dicts; caller reconstructs objects."""
    if not SESSIONS_DIR.exists():
        return []
    result = []
    for path in SESSIONS_DIR.glob("*.json"):
        try:
            result.append(json.loads(path.read_text()))
        except Exception:
            pass
    return result


def delete(session_id: str) -> None:
    """Remove a session's file from disk."""
    (SESSIONS_DIR / f"{session_id}.json").unlink(missing_ok=True)
