"""
audit_runner.py
Runs the full audit pipeline in a background thread.
Emits structured progress events via an asyncio queue
that the WebSocket handler broadcasts to the browser.

Vendor dispatch:
  checkpoint  → GaiaClishSession + CISAudit + CP Management API
  palo_alto   → PANOSSession + PANOSAudit (SSH only)
"""

import asyncio
import json
import os
import threading
import traceback
from datetime import datetime, timezone
from typing import Callable

from backend.session_manager import AssessmentSession, SessionState, sessions
from backend.credential_vault import vault
from backend.persistence import save as persist


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------
def _event(event_type: str, **kwargs) -> str:
    return json.dumps({"event": event_type, "ts": datetime.now(timezone.utc).isoformat(), **kwargs})


# ---------------------------------------------------------------------------
# Instrumented SSH session that emits per-command progress
# ---------------------------------------------------------------------------
class InstrumentedSSH:
    """
    Wraps any SSH session (GaiaClishSession or PANOSSession) and emits a
    progress event for each command run. Requires host, run(), close().
    """
    def __init__(self, real_session, emit: Callable, check_counter: list):
        self._ssh     = real_session
        self._emit    = emit
        self._counter = check_counter  # mutable list [current, total]

    @property
    def host(self) -> str:
        return self._ssh.host

    def run(self, command: str) -> str:
        result = self._ssh.run(command)
        self._counter[0] += 1
        pct = min(int(self._counter[0] / max(self._counter[1], 1) * 60), 60)
        self._emit(_event("progress",
                          phase="audit",
                          pct=pct,
                          message=f"Running: {command[:50]}"))
        return result

    def close(self):
        self._ssh.close()


# ---------------------------------------------------------------------------
# Evidence capture helper — PAN-OS only, called after audit.run_all()
# ---------------------------------------------------------------------------
def _attach_evidence(results: list, creds: dict, emit) -> None:
    """
    Run Playwright browser captures against the PAN-OS web UI and attach
    base64-encoded PNG screenshots to matching result dicts.

    Runs evidence_capture.py in a subprocess so that sync_playwright() gets its
    own process main thread — it conflicts with uvicorn's asyncio event loop
    when called inline from a background threading.Thread.
    """
    import json as _json
    import os
    import subprocess
    import sys

    emit(_event("progress", phase="audit", pct=61,
                message="Capturing browser evidence screenshots..."))

    try:
        from tools.evidence_capture import EVIDENCE_CHECKS
    except Exception as e:
        emit(_event("progress", phase="audit", pct=62,
                    message=f"Evidence capture skipped: import failed ({e})."))
        return

    username = creds.get("username", "")
    password = creds.get("password", "")
    if not (username and password):
        emit(_event("progress", phase="audit", pct=62,
                    message="Evidence capture skipped: no username/password in credentials."))
        return

    try:
        # Deduplicated list of methods needed for this result set (insertion order)
        needed = list(dict.fromkeys(
            EVIDENCE_CHECKS[r["control_id"]]
            for r in results
            if r.get("control_id") in EVIDENCE_CHECKS
        ))
        if not needed:
            return

        payload = _json.dumps({
            "host":     creds["ip"],
            "username": username,
            "password": password,
            "methods":  needed,
        })

        # Project root is one level above backend/
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Use the project's own venv Python — sys.executable may be a different venv
        # (e.g. when the server was started via `uv run` from a parent directory).
        venv_python = os.path.join(project_root, ".venv", "bin", "python")
        if not os.path.isfile(venv_python):
            venv_python = sys.executable  # fallback if venv layout differs
        proc = subprocess.run(
            [venv_python, "-m", "tools.evidence_capture"],
            input=payload,
            capture_output=True,
            timeout=180,
            text=True,
            cwd=project_root,
        )

        if proc.returncode != 0 or not proc.stdout.strip():
            err = (proc.stderr or "no output").strip()
            emit(_event("progress", phase="audit", pct=62,
                        message=f"Evidence capture failed (exit {proc.returncode}): {err[:200]}"))
            return

        captures: dict = _json.loads(proc.stdout)
        if captures.get("error"):
            emit(_event("progress", phase="audit", pct=62,
                        message=f"Evidence capture: {captures['error']} — screenshots skipped."))
            return

        for result in results:
            method = EVIDENCE_CHECKS.get(result.get("control_id", ""))
            if method and captures.get(method):
                result["evidence_image"] = captures[method]

        captured = sum(1 for v in captures.values() if v)
        emit(_event("progress", phase="audit", pct=62,
                    message=f"Evidence screenshots: {captured}/{len(needed)} pages captured."))

    except subprocess.TimeoutExpired:
        emit(_event("progress", phase="audit", pct=62,
                    message="Evidence capture timed out (180s) — screenshots skipped."))
    except Exception as e:
        emit(_event("progress", phase="audit", pct=62,
                    message=f"Evidence capture failed ({type(e).__name__}: {e}) — continuing without screenshots."))


# ---------------------------------------------------------------------------
# Main runner — called from background thread
# ---------------------------------------------------------------------------
def run_audit_pipeline(session_id: str,
                       emit_sync: Callable[[str], None],
                       loop: asyncio.AbstractEventLoop) -> None:
    """
    Full pipeline:
      1. SSH audit  (vendor-dispatched: checkpoint or palo_alto)
      2. AI enrichment (ai_analyzer.py)
    """

    def emit(msg: str):
        try:
            asyncio.run_coroutine_threadsafe(emit_sync(msg), loop)
        except Exception:
            pass

    session: AssessmentSession = sessions.get(session_id)
    if not session:
        return

    try:
        # ----------------------------------------------------------------
        # Phase 1 — SSH Audit (vendor-dispatched)
        # ----------------------------------------------------------------
        session.transition(SessionState.AUDITING, "Starting SSH audit...")
        emit(_event("phase_change", phase="auditing",
                    message="Connecting to firewall via SSH..."))

        creds  = vault.get_credentials(session_id)
        vendor = session.device_context.get("vendor", "checkpoint")

        mgmt_client  = None   # CP Management API client (checkpoint only)
        total_checks = 61     # default (Check Point)
        benchmark    = "FW AI Audit Security Assessment"

        # ---- Palo Alto PAN-OS ----
        if vendor == "palo_alto":
            from tools.panos_audit import PANOSSession, PANOSXMLAPISession, PANOSAudit

            transport = None

            # Try XML API first (primary)
            api_key = creds.get("api_key", "")
            try:
                xml_session = PANOSXMLAPISession(creds["ip"])
                xml_session.connect(
                    api_key  = api_key or None,
                    username = creds["username"] if not api_key else None,
                    password = creds["password"] if not api_key else None,
                )
                transport = xml_session
                emit(_event("progress", phase="audit", pct=5,
                            message="XML API connected. Starting PAN-OS checks..."))
            except Exception as xml_err:
                emit(_event("progress", phase="audit", pct=4,
                            message=f"XML API unavailable ({xml_err}). Falling back to SSH..."))

            # Fall back to SSH
            if transport is None:
                ssh_real = PANOSSession(creds["ip"])
                try:
                    ssh_real.connect(username=creds["username"], password=creds["password"])
                except Exception as e:
                    raise ConnectionError(f"SSH connection failed: {e}")
                transport = ssh_real
                emit(_event("progress", phase="audit", pct=5,
                            message="SSH connected. Starting PAN-OS checks..."))

            total_checks = PANOSAudit.TOTAL_CHECKS
            benchmark    = PANOSAudit.BENCHMARK
            counter = [0, total_checks * 4]
            instr   = InstrumentedSSH(transport, emit, counter)
            audit   = PANOSAudit(ssh_session=instr)

        # ---- Check Point Gaia ----
        else:
            from tools.audit_tool import GaiaClishSession, CISAudit
            from cpapi import APIClient, APIClientArgs

            ssh_real = GaiaClishSession(creds["ip"])
            try:
                ssh_real.connect(username=creds["username"], password=creds["password"])
            except Exception as e:
                raise ConnectionError(f"SSH connection failed: {e}")

            emit(_event("progress", phase="audit", pct=5,
                        message="SSH connected. Starting checks..."))

            # Connect to CP Management API (optional — falls back gracefully)
            try:
                client_args = APIClientArgs(server=creds["ip"], port=443,
                                            unsafe=True, unsafe_auto_accept=True)
                mgmt_client = APIClient(client_args)
                mgmt_client.check_fingerprint = lambda: True
                api_key = creds.get("api_key", "")
                if api_key:
                    login_res = mgmt_client.login_with_api_key(api_key, read_only=True)
                else:
                    login_res = mgmt_client.login(creds["username"], creds["password"],
                                                  read_only=True)
                if login_res.success:
                    emit(_event("progress", phase="audit", pct=6,
                                message="Management API connected. §3 checks will be automated."))
                else:
                    emit(_event("progress", phase="audit", pct=6,
                                message=f"Management API login failed ({login_res.error_message}). §3 checks will be manual."))
                    mgmt_client = None
            except Exception as e:
                emit(_event("progress", phase="audit", pct=6,
                            message=f"Management API unavailable ({e}). §3 checks will be manual."))
                mgmt_client = None

            total_checks = 75  # 61 CIS + 14 additive: NAT/RQ/CERT/LOG + IAM-1/2/3 + ARCH-1
            counter      = [0, total_checks]
            instr        = InstrumentedSSH(ssh_real, emit, counter)
            audit        = CISAudit(ssh_session=instr, mgmt_client=mgmt_client)

        # ---- Common: instrument _add() for per-check events ----
        original_add = audit._add
        check_num    = [0]

        def instrumented_add(result):
            original_add(result)
            check_num[0] += 1
            pct = min(5 + int(check_num[0] / max(total_checks, 1) * 55), 60)
            status_label = {"PASS": "✅", "FAIL": "❌",
                            "MANUAL": "⚠️", "SKIPPED": "⏭️"}.get(result["status"], "?")
            emit(_event("check_result",
                        pct=pct,
                        finding=result,
                        message=f"{status_label} [{result['control_id']}] {result['description'][:60]}"))
            session.log(f"{result['status']} — {result['control_id']}: {result['description']}")

        audit._add = instrumented_add
        audit.run_all(level_filter="all")

        # Evidence capture — PAN-OS only, opt-in, best-effort, never blocks audit
        if vendor == "palo_alto":
            _attach_evidence(audit.results, creds, emit)

        instr.close()
        if mgmt_client:
            try:
                mgmt_client.api_call("logout")
            except Exception:
                pass

        session.raw_results  = audit.results
        session.total_manual = sum(1 for r in audit.results if r["status"] == "MANUAL")

        # Backfill detected version into device_context for the consulting report
        ver_result = next((r for r in audit.results if r.get("control_id") == "VER-1"), None)
        if ver_result and ver_result.get("notes"):
            session.device_context["version"] = ver_result["notes"]

        persist(session)

        counts = {}
        for r in audit.results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1

        emit(_event("audit_complete",
                    pct=60,
                    message="Audit complete. Starting AI analysis...",
                    summary=counts))

        # ----------------------------------------------------------------
        # Phase 2 — AI Enrichment
        # ----------------------------------------------------------------
        session.transition(SessionState.AI_ANALYSIS, "AI analysis started")
        emit(_event("phase_change", phase="ai_analysis",
                    message="Pass 1 of 3: Enriching findings with risk intelligence..."))

        from tools.ai_analyzer import AIConfig, run_analysis

        ctx    = session.device_context
        ai_cfg = AIConfig(
            model    = session.ai_model    or os.environ.get("AI_MODEL", "claude-sonnet-4-6"),
            api_key  = session.ai_api_key  or None,
            base_url = session.ai_base_url or None,
        )

        stats = {
            "PASS":    counts.get("PASS", 0),
            "FAIL":    counts.get("FAIL", 0),
            "MANUAL":  counts.get("MANUAL", 0),
            "SKIPPED": counts.get("SKIPPED", 0),
            "ERROR":   counts.get("ERROR", 0),
            "total":   len(audit.results),
        }

        emit(_event("progress", phase="ai_analysis", pct=65,
                    message=f"AI analysis starting ({ai_cfg.model})..."))

        ai_result = run_analysis(
            findings       = audit.results,
            device_context = ctx,
            stats          = stats,
            ai_config      = ai_cfg,
        )

        enriched  = ai_result["results"]
        chains    = ai_result["attack_chains"]
        narrative = ai_result["narrative"]

        enriched_data = {
            "meta": {
                "benchmark":          benchmark,
                "target":             creds["ip"],
                "generated":          datetime.now(timezone.utc).isoformat() + "Z",
                "ai_model":           ai_cfg.model,
                "device_context":     ctx,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            },
            "summary":       stats,
            "narrative":     narrative,
            "attack_chains": chains,
            "results":       enriched,
        }

        session.enriched_data = enriched_data
        session.report_data   = enriched_data
        session.transition(SessionState.MANUAL_REVIEW,
                           "Automated audit complete. Manual review phase started.")
        persist(session)

        emit(_event("phase_change",
                    phase="manual_review",
                    pct=90,
                    message="Ready for manual review.",
                    manual_count=session.total_manual,
                    summary=stats,
                    narrative=narrative,
                    attack_chains=chains))

    except ConnectionError as e:
        session.set_error(str(e))
        persist(session)
        emit(_event("error", message=str(e)))

    except Exception as e:
        tb = traceback.format_exc()
        session.set_error(f"{e}")
        persist(session)
        emit(_event("error", message=str(e), detail=tb[:500]))


def launch_audit(session_id: str,
                 emit_sync: Callable,
                 loop: asyncio.AbstractEventLoop) -> None:
    """Start audit in a daemon background thread."""
    t = threading.Thread(
        target=run_audit_pipeline,
        args=(session_id, emit_sync, loop),
        daemon=True,
        name=f"audit-{session_id[:8]}",
    )
    t.start()
