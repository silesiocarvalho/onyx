"""
main.py — FastAPI Application
API Gateway, WebSocket hub, REST endpoints.

Endpoints:
  POST   /api/sessions                      Create session + store credentials
  GET    /api/sessions/{id}                 Session summary + state
  POST   /api/sessions/{id}/audit/start     Start audit (async)
  GET    /api/sessions/{id}/workbench       Manual check list with guidance
  POST   /api/sessions/{id}/manual/{cid}    Submit / update a manual finding
  GET    /api/sessions/{id}/report          Current full report JSON
  POST   /api/sessions/{id}/report/finalize Run final AI pass + freeze report
  GET    /api/sessions/{id}/export/{fmt}    Download CSV / Excel / PDF
  DELETE /api/sessions/{id}                 Purge session + credentials
  WS     /ws/{id}                           Real-time progress stream
"""

import asyncio
import io
import json
import os
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import (FastAPI, HTTPException, WebSocket,
                     WebSocketDisconnect, BackgroundTasks)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
import ipaddress

# Local modules
from backend.credential_vault  import vault
from backend.session_manager   import sessions, AssessmentSession, SessionState
from backend.audit_runner      import launch_audit
from backend.persistence       import save as persist, load_all as load_sessions, delete as persist_delete

# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, session_id: str, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.setdefault(session_id, []).append(ws)

    async def disconnect(self, session_id: str, ws: WebSocket):
        async with self._lock:
            conns = self._connections.get(session_id, [])
            if ws in conns:
                conns.remove(ws)

    async def broadcast(self, session_id: str, message: str):
        """Send to all WebSocket clients watching this session."""
        async with self._lock:
            targets = list(self._connections.get(session_id, []))
        dead = []
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(session_id, ws)


ws_manager = ConnectionManager()


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.loop = asyncio.get_running_loop()

    # Restore sessions from disk
    _resumable = (SessionState.MANUAL_REVIEW, SessionState.COMPLETE)
    _crashed   = (SessionState.AUDITING, SessionState.AI_ANALYSIS, SessionState.FINALIZING)
    restored   = 0
    for data in load_sessions():
        try:
            session = AssessmentSession.from_dict(data)
            if session.state in _crashed:
                session.state = SessionState.ERROR
                session.error_message = (
                    "Server restarted during an active operation. "
                    "Create a new session to re-run the audit."
                )
                persist(session)
            with sessions._lock:
                sessions._sessions[session.session_id] = session
            restored += 1
        except Exception:
            pass
    if restored:
        print(f"  [✓] Restored {restored} session(s) from disk.", flush=True)

    yield


def _read_version() -> str:
    import re
    from pathlib import Path
    try:
        text = (Path(__file__).parent.parent / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"

app = FastAPI(title="FW AI Audit", version=_read_version(), lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'frontend')
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class StartSessionRequest(BaseModel):
    ip:           str = Field(..., description="Firewall IP address")
    username:     str = Field(..., min_length=1)
    password:     str = Field(..., min_length=1)
    api_key:      str = Field(default="", description="CP Management API key (optional)")
    organization: str = Field(default="")
    device_role:  str = Field(default="Perimeter Firewall")
    industry:     str = Field(default="General")
    assessor_name: str = Field(default="")
    # AI provider config
    ai_model:    str = Field(default="", description="LiteLLM model string e.g. claude-sonnet-4-6, gpt-4o, ollama/llama3")
    ai_api_key:  str = Field(default="", description="AI provider API key (leave empty to use server env var)")
    ai_base_url: str = Field(default="", description="Base URL for local/custom AI endpoints e.g. http://localhost:11434")
    # Security compliance
    frameworks: list[str] = Field(default=[], description="Compliance frameworks: nist_csf, iso_27001, pci_dss, mitre_attack")
    # Firewall vendor
    vendor: str = Field(default="checkpoint", description="checkpoint | palo_alto")
    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            # Allow hostnames too
            if not v.strip():
                raise ValueError("IP/hostname required")
        return v.strip()


class ManualFindingRequest(BaseModel):
    status:   str = Field(..., description="PASS | FAIL | NA")
    evidence: str = Field(default="", description="What the assessor observed")
    notes:    str = Field(default="")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        if v not in ("PASS", "FAIL", "NA"):
            raise ValueError("status must be PASS, FAIL, or NA")
        return v


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    index = os.path.join(FRONTEND_DIR, "index.html")
    with open(index) as f:
        return HTMLResponse(content=f.read())


@app.post("/api/sessions", status_code=201)
async def create_session(req: StartSessionRequest):
    """
    Phase 0/1 — Create session and securely store credentials.
    Returns session_id. The anthropic key is stored but NOT returned.
    """
    session = sessions.create()
    sid = session.session_id

    # Store all secrets in the vault
    vault.create_session(sid)
    vault.store_credentials(sid, req.ip, req.username, req.password, req.api_key)

    # Store non-secret context in the session
    _VENDOR_BENCHMARKS = {
        "checkpoint": "FW AI Audit Security Assessment",
        "palo_alto":  "CIS Palo Alto Firewall Benchmark",
    }
    session.vendor           = req.vendor
    session.device_context = {
        "target_ip":    req.ip,
        "organization": req.organization,
        "device_role":  req.device_role,
        "industry":     req.industry,
        "assessor_name": req.assessor_name,
        "vendor":        req.vendor,
        "benchmark":     _VENDOR_BENCHMARKS.get(req.vendor, "FW AI Audit Security Assessment"),
        "assessment_date": datetime.now(timezone.utc).isoformat(),
    }

    # Store AI provider config (api_key stored in session — not in vault since it's not a firewall credential)
    session.ai_model    = req.ai_model.strip()
    session.ai_api_key  = req.ai_api_key.strip()
    session.ai_base_url = req.ai_base_url.strip()

    # Security compliance frameworks
    session.frameworks = req.frameworks
    session.device_context["frameworks"] = req.frameworks

    session.log("Session created. Credentials stored in encrypted vault.")
    persist(session)

    return {"session_id": sid, "state": session.state}


@app.get("/api/sessions")
async def list_sessions():
    """Return all active sessions sorted by most recently updated."""
    all_sessions = sessions.list_sessions()
    resumable = [s for s in all_sessions if s["state"] != "CREATED"]
    resumable.sort(key=lambda s: s["updated_at"], reverse=True)
    return {"sessions": resumable}


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    session = _get_or_404(session_id)
    return session.get_summary()


@app.post("/api/sessions/{session_id}/audit/start")
async def start_audit(session_id: str):
    """
    Phase 2 — Start the async audit pipeline.
    Returns immediately; progress streams via WebSocket /ws/{session_id}.
    """
    session = _get_or_404(session_id)

    if session.state not in (SessionState.CREATED, SessionState.ERROR):
        raise HTTPException(400, f"Audit cannot start from state: {session.state}")

    if not vault.has_session(session_id):
        raise HTTPException(400, "Session credentials not found. Create a new session.")

    loop = app.state.loop

    async def emit_to_ws(msg: str):
        await ws_manager.broadcast(session_id, msg)

    # Launch background thread
    launch_audit(
        session_id=session_id,
        emit_sync=emit_to_ws,
        loop=loop,
    )

    return {"status": "started", "message": "Audit running. Connect to WebSocket for progress."}


class RetryAIRequest(BaseModel):
    ai_model:    str = Field(default="")
    ai_api_key:  str = Field(default="")
    ai_base_url: str = Field(default="")


@app.post("/api/sessions/{session_id}/ai/rerun")
async def rerun_ai(session_id: str, req: RetryAIRequest):
    """
    Re-run the AI enrichment pass on a session that has raw audit results
    but failed during AI analysis (ERROR state). Does not re-run SSH checks.
    """
    session = _get_or_404(session_id)

    if not session.raw_results:
        raise HTTPException(400, "No audit data found. Run the full audit first.")

    # Update AI config if provided
    if req.ai_model:    session.ai_model    = req.ai_model.strip()
    if req.ai_api_key:  session.ai_api_key  = req.ai_api_key.strip()
    if req.ai_base_url: session.ai_base_url = req.ai_base_url.strip()

    session.transition(SessionState.AI_ANALYSIS, "Re-running AI enrichment...")
    persist(session)

    loop = app.state.loop

    async def emit_to_ws(msg: str):
        await ws_manager.broadcast(session_id, msg)

    def _run_ai_only():
        from tools.ai_analyzer import AIConfig, run_analysis
        import json as _json

        def emit(msg):
            try:
                asyncio.run_coroutine_threadsafe(emit_to_ws(msg), loop)
            except Exception:
                pass

        try:
            ai_cfg = AIConfig(
                model    = session.ai_model    or os.environ.get("AI_MODEL", "claude-sonnet-4-6"),
                api_key  = session.ai_api_key  or None,
                base_url = session.ai_base_url or None,
            )
            counts = {}
            for r in session.raw_results:
                counts[r["status"]] = counts.get(r["status"], 0) + 1

            stats = {**counts, "total": len(session.raw_results)}
            ctx   = session.device_context

            emit(_json.dumps({"event": "phase_change", "phase": "ai_analysis",
                              "message": f"Re-running AI analysis ({ai_cfg.model})..."}))

            result = run_analysis(session.raw_results, ctx, stats, ai_config=ai_cfg)

            enriched_data = {
                "meta": {
                    "benchmark":      "FW AI Audit Security Assessment",
                    "target":         ctx.get("target_ip", ""),
                    "generated":      datetime.now(timezone.utc).isoformat() + "Z",
                    "ai_model":       ai_cfg.model,
                    "device_context": ctx,
                },
                "summary":       stats,
                "narrative":     result["narrative"],
                "attack_chains": result["attack_chains"],
                "results":       result["results"],
            }
            session.enriched_data = enriched_data
            session.report_data   = enriched_data
            session.total_manual  = sum(1 for r in result["results"] if r["status"] == "MANUAL")
            session.transition(SessionState.MANUAL_REVIEW,
                               "AI re-analysis complete. Manual review phase started.")
            persist(session)
            emit(_json.dumps({"event": "phase_change", "phase": "manual_review",
                              "pct": 90, "message": "Ready for manual review.",
                              "manual_count": session.total_manual}))
        except Exception as e:
            session.set_error(f"AI re-run failed: {e}")
            persist(session)
            emit(_json.dumps({"event": "error", "message": str(e)}))

    import threading
    threading.Thread(target=_run_ai_only, daemon=True).start()

    return {"status": "started", "message": "AI re-analysis running. Connect to WebSocket for progress."}


@app.get("/api/sessions/{session_id}/workbench")
async def get_workbench(session_id: str):
    """Phase 3 — Return manual checks with guidance and current state."""
    session = _get_or_404(session_id)
    if session.state not in (SessionState.MANUAL_REVIEW, SessionState.FINALIZING, SessionState.COMPLETE):
        raise HTTPException(400, f"Workbench not available in state: {session.state}")
    return {
        "items":              session.get_manual_workbench(),
        "total":              session.total_manual,
        "completed":          session.completed_manual,
        "completion_pct":     round(session.completed_manual / max(session.total_manual, 1) * 100),
        "is_finalizable":     session.is_report_finalizable,
    }


@app.post("/api/sessions/{session_id}/manual/{control_id}")
async def submit_manual_finding(session_id: str, control_id: str,
                                req: ManualFindingRequest):
    """
    Phase 3 — Submit or update a manual finding.
    Triggers partial re-reasoning and broadcasts updated stats.
    """
    session = _get_or_404(session_id)
    if session.state != SessionState.MANUAL_REVIEW:
        raise HTTPException(400, f"Manual findings not accepted in state: {session.state}")

    # Validate control exists and is MANUAL
    workbench = session.get_manual_workbench()
    known_ids = {item["control_id"] for item in workbench}
    if control_id not in known_ids:
        raise HTTPException(404, f"Control {control_id} is not a manual check")

    session.update_manual_finding(control_id, req.status, req.evidence, req.notes)
    session.log(f"Manual finding updated: {control_id} → {req.status}")
    persist(session)

    # Broadcast the update
    stats = session.get_summary()["stats"]
    await ws_manager.broadcast(session_id, json.dumps({
        "event":       "manual_update",
        "control_id":  control_id,
        "status":      req.status,
        "completed":   session.completed_manual,
        "total":       session.total_manual,
        "completion_pct": round(session.completed_manual / max(session.total_manual, 1) * 100),
        "is_finalizable": session.is_report_finalizable,
        "stats":       stats,
    }))

    return {
        "control_id":     control_id,
        "status":         req.status,
        "completed":      session.completed_manual,
        "total":          session.total_manual,
        "is_finalizable": session.is_report_finalizable,
    }


@app.get("/api/sessions/{session_id}/report")
async def get_report(session_id: str):
    """Return current report data (enriched + manual overrides merged)."""
    session = _get_or_404(session_id)
    if not session.report_data:
        raise HTTPException(400, "Report not yet generated. Run audit first.")
    return _merge_manual_into_report(session)


@app.post("/api/sessions/{session_id}/report/finalize")
async def finalize_report(session_id: str):
    """
    Phase 4/5 — Run final AI reasoning pass on complete dataset,
    freeze the report, transition to COMPLETE.
    """
    session = _get_or_404(session_id)

    if not session.is_report_finalizable:
        pending = session.total_manual - session.completed_manual
        raise HTTPException(400,
            f"Cannot finalize: {pending} manual checks still pending. "
            "Mark all checks as PASS, FAIL, or N/A before finalizing.")

    session.transition(SessionState.FINALIZING, "Finalizing report...")

    # Merge manual findings into report
    merged = _merge_manual_into_report(session)

    # Run final AI narrative with complete dataset
    try:
        from tools.ai_analyzer import AIConfig, analyze_attack_chains, generate_narrative

        ai_cfg = AIConfig(
            model    = session.ai_model    or os.environ.get("AI_MODEL", "claude-sonnet-4-6"),
            api_key  = session.ai_api_key  or None,
            base_url = session.ai_base_url or None,
        )

        findings = merged.get("results", [])
        ctx      = session.device_context

        # Recompute stats with manual findings included
        final_counts = {"PASS": 0, "FAIL": 0, "MANUAL": 0, "SKIPPED": 0, "ERROR": 0, "NA": 0}
        for r in findings:
            final_counts[r.get("status", "ERROR")] = final_counts.get(r.get("status", "ERROR"), 0) + 1

        total  = sum(v for k, v in final_counts.items() if k != "NA")
        passes = final_counts["PASS"]
        final_stats = {**final_counts, "total": total,
                       "score": round(passes / total * 100, 1) if total else 0}

        # Fresh attack chain + narrative with complete picture (manual checks resolved)
        chains    = await asyncio.get_event_loop().run_in_executor(
            None, analyze_attack_chains, ai_cfg, findings, ctx)
        narrative = await asyncio.get_event_loop().run_in_executor(
            None, generate_narrative, ai_cfg, findings, chains, ctx, final_stats)

        merged["narrative"]     = narrative
        merged["attack_chains"] = chains
        merged["summary"]       = final_stats
        merged["meta"]["finalized_at"] = datetime.now(timezone.utc).isoformat() + "Z"
        merged["meta"]["ai_model"]     = ai_cfg.model

    except Exception as e:
        session.log(f"Final AI pass error (using existing narrative): {e}", level="warn")
        merged["meta"]["finalized_at"] = datetime.now(timezone.utc).isoformat() + "Z"

    session.report_data = merged
    session.transition(SessionState.COMPLETE, "Assessment complete. Report finalized.")
    persist(session)

    await ws_manager.broadcast(session_id, json.dumps({
        "event":   "report_finalized",
        "message": "Report finalized. Ready to export.",
        "summary": merged.get("summary", {}),
    }))

    return {"status": "complete", "message": "Report finalized. Use /export/{fmt} to download."}


@app.get("/api/sessions/{session_id}/export/consulting")
async def export_consulting_report(session_id: str):
    """Export a client-facing consulting Word report following template_1.txt structure."""
    session = _get_or_404(session_id)

    if not session.report_data:
        raise HTTPException(400, "No report to export. Run audit first.")

    data = _merge_manual_into_report(session)

    from tools.report_generator import generate_consulting_docx

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    org      = session.device_context.get("organization", "assessment").replace(" ", "_")
    filename = f"consulting_report_{org}_{ts}.docx"
    media    = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    with tempfile.TemporaryDirectory() as tmpdir:
        path = generate_consulting_docx(data, os.path.join(tmpdir, filename))
        with open(path, "rb") as f:
            content = f.read()

    return StreamingResponse(
        io.BytesIO(content),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/sessions/{session_id}/export/{fmt}")
async def export_report(session_id: str, fmt: str):
    """Phase 6 — Export report as PDF, Excel, or CSV."""
    session = _get_or_404(session_id)

    if fmt not in ("pdf", "excel", "csv", "docx"):
        raise HTTPException(400, "fmt must be pdf, excel, csv, or docx")

    if not session.report_data:
        raise HTTPException(400, "No report to export. Run audit first.")

    data = _merge_manual_into_report(session)

    from tools.report_generator import generate_pdf, generate_excel, generate_csv, generate_docx

    ts         = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    org        = session.device_context.get("organization", "assessment").replace(" ", "_")
    base_name  = f"cis_report_{org}_{ts}"

    with tempfile.TemporaryDirectory() as tmpdir:
        base = os.path.join(tmpdir, base_name)

        if fmt == "pdf":
            path      = generate_pdf(data, base + ".pdf")
            media     = "application/pdf"
            ext       = ".pdf"
        elif fmt == "excel":
            path      = generate_excel(data, base + ".xlsx")
            media     = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ext       = ".xlsx"
        elif fmt == "docx":
            path      = generate_docx(data, base + ".docx")
            media     = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ext       = ".docx"
        else:
            path      = generate_csv(data, base + ".csv")
            media     = "text/csv"
            ext       = ".csv"

        with open(path, "rb") as f:
            content = f.read()

    return StreamingResponse(
        io.BytesIO(content),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{base_name}{ext}"'},
    )


@app.get("/api/compliance/frameworks")
async def list_compliance_frameworks():
    """Return available security compliance frameworks."""
    from tools.compliance_mappings import FRAMEWORKS
    return {"frameworks": list(FRAMEWORKS.values())}


@app.get("/api/ai/groq-models")
async def list_groq_models(api_key: str = ""):
    """
    Fetch available models from the Groq API.
    Returns a list of LiteLLM-formatted model strings (groq/<id>).
    """
    import httpx
    key = api_key or os.environ.get("GROQ_API_KEY", "")
    if not key:
        raise HTTPException(400, "Groq API key required. Enter it in the AI API Key field or set GROQ_API_KEY.")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {key}"},
            )
        resp.raise_for_status()
        data   = resp.json()
        # Exclude audio/guard models not suited for text generation
        _skip = ("whisper", "guard", "safeguard", "orpheus", "allam")
        models = sorted([
            {"name": m["id"],
             "litellm": f"groq/{m['id']}" if not m["id"].startswith("groq/") else m["id"]}
            for m in data.get("data", [])
            if m.get("object") == "model"
            and not any(s in m["id"].lower() for s in _skip)
        ], key=lambda x: x["name"])
        return {"models": models}
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, f"Groq API error: {e.response.text[:200]}")
    except httpx.RequestError as e:
        raise HTTPException(503, f"Cannot reach Groq API: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/ai/anthropic-models")
async def list_anthropic_models(api_key: str = ""):
    """
    Fetch available models from the Anthropic API.
    Returns a list of LiteLLM-formatted model strings.
    """
    import httpx
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise HTTPException(400, "Anthropic API key required.")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            )
        resp.raise_for_status()
        data = resp.json()
        _skip = ("moderation", "embedding")
        models = sorted([
            {"name": m.get("display_name", m["id"]),
             "litellm": m["id"]}
            for m in data.get("data", [])
            if not any(s in m["id"].lower() for s in _skip)
        ], key=lambda x: x["litellm"], reverse=True)
        return {"models": models}
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, f"Anthropic API error: {e.response.text[:200]}")
    except httpx.RequestError as e:
        raise HTTPException(503, f"Cannot reach Anthropic API: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/ai/ollama-models")
async def list_ollama_models(base_url: str = "http://localhost:11434"):
    """
    Fetch available models from a local Ollama instance.
    Returns a list of LiteLLM-formatted model strings (ollama/<name>).
    """
    import urllib.request
    import urllib.error
    url = base_url.rstrip("/") + "/api/tags"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        models = [
            {"name": m["name"], "litellm": f"ollama/{m['name']}"}
            for m in data.get("models", [])
        ]
        return {"models": models, "base_url": base_url}
    except urllib.error.URLError as e:
        raise HTTPException(503, f"Cannot reach Ollama at {url}: {e.reason}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.delete("/api/sessions/{session_id}")
async def destroy_session(session_id: str):
    """Purge session, credentials, and report data from memory and disk."""
    session = sessions.get(session_id)
    if session:
        sessions.destroy(session_id)
    vault.destroy_session(session_id)
    persist_delete(session_id)
    return {"status": "destroyed"}


@app.delete("/api/sessions")
async def destroy_all_sessions():
    """Purge all sessions, credentials, and persisted data."""
    all_ids = [s["session_id"] for s in sessions.list_sessions()]
    for sid in all_ids:
        sessions.destroy(sid)
        vault.destroy_session(sid)
        persist_delete(sid)
    return {"status": "destroyed", "count": len(all_ids)}


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    session = sessions.get(session_id)
    if not session:
        await websocket.close(code=4004)
        return

    await ws_manager.connect(session_id, websocket)
    try:
        # Send current state immediately on connect
        await websocket.send_text(json.dumps({
            "event":   "connected",
            "summary": session.get_summary(),
            "log":     session.audit_log[-20:],
        }))
        # Keep alive
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if msg == "ping":
                    await websocket.send_text(json.dumps({"event": "pong"}))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(session_id, websocket)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_or_404(session_id: str) -> AssessmentSession:
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    return session


def _merge_manual_into_report(session: AssessmentSession) -> dict:
    """Return report data with manual findings merged in."""
    import copy
    data = copy.deepcopy(session.report_data)
    if not data:
        return {}

    for r in data.get("results", []):
        cid = r.get("control_id", "")
        if cid in session.manual_findings:
            mf = session.manual_findings[cid]
            r["status"]          = mf["status"] if mf["status"] != "NA" else "SKIPPED"
            r["manual_evidence"] = mf.get("evidence", "")
            r["manual_notes"]    = mf.get("notes", "")
            r["manual_updated"]  = mf.get("updated_at", "")

    # Inject selected compliance frameworks so report_generator can annotate
    data.setdefault("meta", {})["frameworks"] = session.frameworks

    return data
