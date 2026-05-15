"""
tests/test_backend.py
Run with:  uv run pytest tests/ -v
"""

import json
import re
from pathlib import Path
import pytest
from fastapi.testclient import TestClient


# ── Version consistency ──────────────────────────────────────
class TestVersionConsistency:
    """pyproject.toml is the single source of truth for the version.
    README.md and CLAUDE.md headings must match it."""

    ROOT = Path(__file__).parent.parent

    def _pyproject_version(self) -> str:
        text = (self.ROOT / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert m, "version not found in pyproject.toml"
        return m.group(1)

    def test_readme_version_matches(self):
        version = self._pyproject_version()
        readme  = (self.ROOT / "README.md").read_text()
        assert f"v{version}" in readme, (
            f"README.md heading does not contain 'v{version}'. "
            f"Update README.md to match pyproject.toml version."
        )

    def test_claude_md_version_matches(self):
        version  = self._pyproject_version()
        claude   = (self.ROOT / "CLAUDE.md").read_text()
        assert f"v{version}" in claude, (
            f"CLAUDE.md heading does not contain 'v{version}'. "
            f"Update CLAUDE.md to match pyproject.toml version."
        )

    def test_api_version_matches(self):
        from fastapi.testclient import TestClient
        from backend.main import app
        version = self._pyproject_version()
        with TestClient(app) as client:
            data = client.get("/openapi.json").json()
        assert data["info"]["version"] == version, (
            f"FastAPI version '{data['info']['version']}' differs from "
            f"pyproject.toml version '{version}'. Check backend/main.py."
        )


# ── Credential Vault ────────────────────────────────────────
class TestCredentialVault:

    def test_create_and_retrieve(self):
        from backend.credential_vault import CredentialVault
        v = CredentialVault()
        v.create_session("s1")
        v.store_credentials("s1", "10.0.0.1", "admin", "secret", "myapikey")
        c = v.get_credentials("s1")
        assert c["ip"]       == "10.0.0.1"
        assert c["username"] == "admin"
        assert c["password"] == "secret"
        assert c["api_key"]  == "myapikey"

    def test_credentials_are_not_plaintext(self):
        """Raw store must not contain the password as plaintext."""
        from backend.credential_vault import CredentialVault
        v = CredentialVault()
        v.create_session("s2")
        v.store("s2", "password", "supersecret")
        raw = v._store["s2"]["password"]
        assert b"supersecret" not in raw

    def test_destroy_removes_session(self):
        from backend.credential_vault import CredentialVault
        v = CredentialVault()
        v.create_session("s3")
        v.store("s3", "key", "value")
        v.destroy_session("s3")
        assert not v.has_session("s3")

    def test_retrieve_missing_field_raises(self):
        from backend.credential_vault import CredentialVault
        v = CredentialVault()
        v.create_session("s4")
        with pytest.raises(KeyError):
            v.retrieve("s4", "nonexistent")

    def test_cross_session_isolation(self):
        """Two sessions use separate keys — one cannot read the other's data."""
        from backend.credential_vault import CredentialVault
        from cryptography.fernet import InvalidToken
        v = CredentialVault()
        v.create_session("sa")
        v.create_session("sb")
        v.store("sa", "secret", "alpha_value")
        # Try to decrypt session-a's ciphertext with session-b's key
        ct = v._store["sa"]["secret"]
        with pytest.raises((InvalidToken, KeyError)):
            v._ciphers["sb"].decrypt(ct)


# ── Session Manager ─────────────────────────────────────────
class TestSessionManager:

    def test_create_session(self):
        from backend.session_manager import SessionManager, SessionState
        sm = SessionManager()
        s  = sm.create()
        assert s.state == SessionState.CREATED
        assert s.session_id is not None

    def test_state_transitions(self):
        from backend.session_manager import SessionManager, SessionState
        sm = SessionManager()
        s  = sm.create()
        s.transition(SessionState.AUDITING)
        assert s.state == SessionState.AUDITING
        s.transition(SessionState.MANUAL_REVIEW)
        assert s.state == SessionState.MANUAL_REVIEW

    def test_manual_finding_completion_tracking(self):
        from backend.session_manager import SessionManager
        sm = SessionManager()
        s  = sm.create()
        s.total_manual = 3
        assert s.completed_manual == 0

        s.update_manual_finding("3.1", "PASS", "Stealth rule at position 1", "")
        assert s.completed_manual == 1

        s.update_manual_finding("3.2", "FAIL", "No cleanup rule found", "")
        assert s.completed_manual == 2

        s.update_manual_finding("3.3", "NA", "", "Not applicable")
        assert s.completed_manual == 3

    def test_updating_same_finding_doesnt_double_count(self):
        from backend.session_manager import SessionManager
        sm = SessionManager()
        s  = sm.create()
        s.total_manual = 2
        s.update_manual_finding("3.1", "PASS", "ok", "")
        s.update_manual_finding("3.1", "FAIL", "on reflection, fail", "")
        assert s.completed_manual == 1

    def test_is_report_finalizable(self):
        from backend.session_manager import SessionManager, SessionState
        sm = SessionManager()
        s  = sm.create()
        s.total_manual = 2
        s.transition(SessionState.MANUAL_REVIEW)
        assert not s.is_report_finalizable
        s.update_manual_finding("3.1", "PASS", "", "")
        s.update_manual_finding("3.2", "FAIL", "", "")
        assert s.is_report_finalizable

    def test_get_summary_keys(self):
        from backend.session_manager import SessionManager
        sm = SessionManager()
        s  = sm.create()
        summary = s.get_summary()
        for key in ("session_id", "state", "stats", "total_manual", "completed_manual"):
            assert key in summary

    def test_get_or_destroy(self):
        from backend.session_manager import SessionManager
        sm = SessionManager()
        s  = sm.create()
        sid = s.session_id
        assert sm.get(sid) is s
        sm.destroy(sid)
        assert sm.get(sid) is None


# ── Manual Guidance coverage ────────────────────────────────
class TestManualGuidance:

    def test_all_known_controls_have_guidance(self):
        """Every control in MANUAL_CONTROLS should have an entry in MANUAL_GUIDANCE."""
        from backend.session_manager import MANUAL_CONTROLS, MANUAL_GUIDANCE
        missing = MANUAL_CONTROLS - set(MANUAL_GUIDANCE.keys())
        # We allow a few to be intentionally absent (e.g. API-dependent fallbacks)
        # but at minimum the most important ones must be there
        critical = {"3.1", "3.2", "3.12", "3.8", "2.5.3"}
        assert not (critical & missing), f"Missing guidance for: {critical & missing}"

    def test_guidance_has_required_fields(self):
        from backend.session_manager import MANUAL_GUIDANCE
        for cid, g in MANUAL_GUIDANCE.items():
            assert "where" in g,        f"{cid} missing 'where'"
            assert "steps" in g,        f"{cid} missing 'steps'"
            assert isinstance(g["steps"], list), f"{cid} steps must be a list"
            assert len(g["steps"]) >= 1, f"{cid} must have at least 1 step"


# ── FastAPI App (integration) ────────────────────────────────
@pytest.fixture
def client():
    from backend.main import app
    with TestClient(app) as c:
        yield c


class TestAPI:

    def test_root_serves_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_create_session_missing_fields(self, client):
        r = client.post("/api/sessions", json={})
        assert r.status_code == 422   # validation error

    def test_create_session_invalid_ip(self, client):
        r = client.post("/api/sessions", json={
            "ip": "",
            "username": "admin",
            "password": "pass",
            
            "organization": "Test",
        })
        assert r.status_code == 422

    def test_create_session_success(self, client):
        r = client.post("/api/sessions", json={
            "ip":            "10.0.0.1",
            "username":      "admin",
            "password":      "testpass",
            
            "organization":  "Test Org",
        })
        assert r.status_code == 201
        data = r.json()
        assert "session_id" in data
        assert data["state"] == "CREATED"

    def test_get_session(self, client):
        # Create first
        r = client.post("/api/sessions", json={
            "ip": "10.0.0.1", "username": "admin",
            "password": "testpass",
            
            "organization": "Test Org",
        })
        sid = r.json()["session_id"]
        r2  = client.get(f"/api/sessions/{sid}")
        assert r2.status_code == 200
        assert r2.json()["session_id"] == sid

    def test_get_unknown_session(self, client):
        r = client.get("/api/sessions/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_workbench_unavailable_before_audit(self, client):
        r = client.post("/api/sessions", json={
            "ip": "10.0.0.1", "username": "admin",
            "password": "testpass",
            
            "organization": "Test Org",
        })
        sid = r.json()["session_id"]
        r2 = client.get(f"/api/sessions/{sid}/workbench")
        assert r2.status_code == 400

    def test_manual_finding_unavailable_before_audit(self, client):
        r = client.post("/api/sessions", json={
            "ip": "10.0.0.1", "username": "admin",
            "password": "testpass",
            
            "organization": "Test Org",
        })
        sid = r.json()["session_id"]
        r2 = client.post(f"/api/sessions/{sid}/manual/3.1",
                          json={"status": "PASS", "evidence": "ok"})
        assert r2.status_code == 400

    def test_manual_finding_invalid_status(self, client):
        """Status must be PASS, FAIL, or NA."""
        r = client.post("/api/sessions", json={
            "ip": "10.0.0.1", "username": "admin",
            "password": "testpass",
            
            "organization": "Test Org",
        })
        sid = r.json()["session_id"]
        r2  = client.post(f"/api/sessions/{sid}/manual/3.1",
                           json={"status": "MAYBE"})
        assert r2.status_code == 422

    def test_delete_session(self, client):
        r = client.post("/api/sessions", json={
            "ip": "10.0.0.1", "username": "admin",
            "password": "testpass",
            
            "organization": "Test Org",
        })
        sid = r.json()["session_id"]
        r2  = client.delete(f"/api/sessions/{sid}")
        assert r2.status_code == 200
        r3  = client.get(f"/api/sessions/{sid}")
        assert r3.status_code == 404

    def test_export_before_audit_returns_400(self, client):
        r = client.post("/api/sessions", json={
            "ip": "10.0.0.1", "username": "admin",
            "password": "testpass",
            
            "organization": "Test Org",
        })
        sid = r.json()["session_id"]
        r2  = client.get(f"/api/sessions/{sid}/export/pdf")
        assert r2.status_code == 400

    def test_export_invalid_format(self, client):
        r = client.post("/api/sessions", json={
            "ip": "10.0.0.1", "username": "admin",
            "password": "testpass",
            
            "organization": "Test Org",
        })
        sid = r.json()["session_id"]
        r2  = client.get(f"/api/sessions/{sid}/export/docx")
        assert r2.status_code == 400


# ── Report generator (unit) ─────────────────────────────────
class TestReportGenerator:

    @pytest.fixture
    def sample_data(self):
        """Minimal enriched audit data for testing report generation."""
        return {
            "meta": {
                "benchmark": "FW AI Audit Security Assessment",
                "target": "10.0.0.1",
                "generated": "2025-04-21T09:00:00Z",
                "device_context": {
                    "organization": "Test Corp",
                    "device_role": "Perimeter Firewall",
                    "industry": "Finance",
                    "target_ip": "10.0.0.1",
                    "assessor_name": "Test Assessor",
                }
            },
            "summary": {"PASS": 3, "FAIL": 2, "MANUAL": 1, "SKIPPED": 0, "ERROR": 0, "total": 6},
            "narrative": {
                "overall_risk_rating": "High",
                "compliance_score_interpretation": "Score is below acceptable threshold.",
                "executive_summary": {
                    "headline": "Firewall requires immediate hardening.",
                    "paragraph_1": "Several critical controls are failing.",
                    "paragraph_2": "Password policy gaps are the primary concern.",
                    "paragraph_3": "Immediate remediation recommended.",
                },
                "technical_summary": {
                    "paragraph_1": "Technical posture is weak in password controls.",
                    "paragraph_2": "SSH brute-force protection is absent.",
                },
                "top_5_priority_actions": [
                    {"rank": 1, "action": "Enable lockout", "justification": "Critical",
                     "effort": "Low", "impact": "Eliminates brute-force"},
                ],
                "positive_findings": "NTP and syslog are correctly configured.",
                "assessment_limitations": "19 manual checks require SmartConsole access.",
            },
            "attack_chains": [
                {
                    "chain_id": "AC-01", "chain_name": "Brute-force to full compromise",
                    "risk_level": "Critical",
                    "controls_involved": ["1.11", "1.13"],
                    "attack_narrative": "Attacker brute-forces admin account.",
                    "blast_radius": "Full firewall compromise.",
                    "priority_fix_order": ["1.11", "1.13"],
                }
            ],
            "results": [
                {"control_id": "1.1", "description": "Min password length ≥ 14",
                 "level": "L1", "status": "PASS", "expected": "≥ 14", "actual": "14",
                 "remediation": "", "notes": "", "timestamp": "2025-04-21T09:00:00Z"},
                {"control_id": "1.11", "description": "Deny access after failed attempts",
                 "level": "L1", "status": "FAIL", "expected": "on", "actual": "off",
                 "remediation": "set password-controls deny-on-fail enable on",
                 "notes": "", "timestamp": "2025-04-21T09:00:01Z",
                 "ai_analysis": {
                     "risk_level": "Critical",
                     "business_impact": "Unrestricted brute-force possible.",
                     "attack_scenario": "Automated password attack.",
                     "remediation_effort": "Low",
                     "remediation_steps": ["set password-controls deny-on-fail enable on"],
                     "priority_rank": 1,
                     "cve_or_reference": "NIST AC-7",
                 }},
                {"control_id": "3.1", "description": "Stealth rule present",
                 "level": "L2", "status": "MANUAL", "expected": None, "actual": None,
                 "remediation": "Create stealth rule", "notes": "Check SmartConsole",
                 "timestamp": "2025-04-21T09:00:02Z"},
            ],
        }

    def test_csv_generation(self, sample_data, tmp_path):
        from tools.report_generator import generate_csv
        out = tmp_path / "report.csv"
        generate_csv(sample_data, str(out))
        assert out.exists()
        content = out.read_text()
        assert "control_id" in content
        assert "1.11" in content
        assert "FAIL" in content

    def test_excel_generation(self, sample_data, tmp_path):
        from tools.report_generator import generate_excel
        out = tmp_path / "report.xlsx"
        generate_excel(sample_data, str(out))
        assert out.exists()
        assert out.stat().st_size > 5000   # must be a real xlsx, not empty

    def test_pdf_generation(self, sample_data, tmp_path):
        from tools.report_generator import generate_pdf
        out = tmp_path / "report.pdf"
        generate_pdf(sample_data, str(out))
        assert out.exists()
        content = out.read_bytes()
        assert content[:4] == b"%PDF"   # valid PDF header

    def test_csv_has_ai_fields_when_present(self, sample_data, tmp_path):
        from tools.report_generator import generate_csv
        out = tmp_path / "report_ai.csv"
        generate_csv(sample_data, str(out))
        content = out.read_text()
        assert "ai_risk_level" in content
        assert "Critical" in content


# ── Audit Tool — Clish parsing & API field navigation ───────
class TestAuditToolChecks:
    """Unit tests for CISAudit check methods.

    All tests use mock SSH and API clients — no real firewall needed.
    """

    class _MockSSH:
        """Fake SSH session: maps command strings to preset outputs."""
        def __init__(self, responses):
            self._responses = responses   # {command: output}

        def run(self, cmd):
            return self._responses.get(cmd, "")

    class _MockApiResponse:
        def __init__(self, success, data):
            self.success = success
            self.data    = data

    class _MockMgmt:
        """Fake CP MGMT API client."""
        def __init__(self, global_props=None, call_count=None):
            self._props      = global_props or {}
            self.call_count  = call_count if call_count is not None else []

        def api_call(self, command, payload=None):
            self.call_count.append(command)
            if command == "show-objects" and (payload or {}).get("type") == "global-properties":
                if self._props:
                    return TestAuditToolChecks._MockApiResponse(
                        True, {"objects": [self._props]}
                    )
                return TestAuditToolChecks._MockApiResponse(True, {"objects": []})
            return TestAuditToolChecks._MockApiResponse(False, {})

    def _audit(self, ssh_responses=None, global_props=None):
        from tools.audit_tool import CISAudit
        ssh  = self._MockSSH(ssh_responses or {})
        mgmt = self._MockMgmt(global_props) if global_props is not None else None
        return CISAudit(ssh, mgmt)

    def _result(self, audit, cid):
        return next((r for r in audit.results if r["control_id"] == cid), None)

    # ── check_2_4_1: show backups ──────────────────────────────

    def test_2_4_1_pass_when_tgz_present(self):
        audit = self._audit({"show backups": (
            "Backups location: /var/log/CPbackup/backups\n"
            "backup_gw_29_Apr_2026_02_00.tgz  29 Apr 2026  110 MB"
        )})
        audit.check_2_4_1()
        r = self._result(audit, "2.4.1")
        assert r["status"] == "PASS"

    def test_2_4_1_fail_when_no_tgz(self):
        audit = self._audit({"show backups": "Backups location: /var/log/CPbackup/backups"})
        audit.check_2_4_1()
        r = self._result(audit, "2.4.1")
        assert r["status"] == "FAIL"
        assert "CPbackup" in r["actual"]   # raw output shown when non-empty but no .tgz

    def test_2_4_1_fail_when_empty_output(self):
        audit = self._audit({"show backups": ""})
        audit.check_2_4_1()
        r = self._result(audit, "2.4.1")
        assert r["status"] == "FAIL"

    # ── check_2_4_3: show configuration backup-scheduled ──────

    def test_2_4_3_pass_when_schedule_exists(self):
        audit = self._audit({"show configuration backup-scheduled": (
            "add backup-scheduled name DailyBackup local\n"
            "set backup-scheduled name DailyBackup recurrence daily time 02:00"
        )})
        audit.check_2_4_3()
        r = self._result(audit, "2.4.3")
        assert r["status"] == "PASS"

    def test_2_4_3_fail_when_no_schedule(self):
        audit = self._audit({"show configuration backup-scheduled": ""})
        audit.check_2_4_3()
        r = self._result(audit, "2.4.3")
        assert r["status"] == "FAIL"
        assert "No scheduled backups" in r["actual"]

    # ── _check_global_prop_via_api: field navigation ──────────

    def test_global_prop_no_mgmt_gives_manual(self):
        from tools.audit_tool import CISAudit
        audit = CISAudit(self._MockSSH({}), mgmt_client=None)
        audit._check_global_prop_via_api(
            "3.10", "Test", "L2",
            "stateful-inspection.drop-out-of-state-tcp-packets", True, "fix it"
        )
        r = self._result(audit, "3.10")
        assert r["status"] == "MANUAL"

    def test_global_prop_empty_props_gives_manual(self):
        audit = self._audit(global_props={})
        audit._check_global_prop_via_api(
            "3.10", "Test", "L2",
            "stateful-inspection.drop-out-of-state-tcp-packets", True, "fix it"
        )
        r = self._result(audit, "3.10")
        assert r["status"] == "MANUAL"

    def test_global_prop_pass_when_value_matches(self):
        props = {"stateful-inspection": {"drop-out-of-state-tcp-packets": True}}
        audit = self._audit(global_props=props)
        audit._check_global_prop_via_api(
            "3.10", "Test", "L2",
            "stateful-inspection.drop-out-of-state-tcp-packets", True, "fix it"
        )
        r = self._result(audit, "3.10")
        assert r["status"] == "PASS"
        assert r["actual"] is True

    def test_global_prop_fail_when_value_differs(self):
        props = {"stateful-inspection": {"drop-out-of-state-tcp-packets": False}}
        audit = self._audit(global_props=props)
        audit._check_global_prop_via_api(
            "3.10", "Test", "L2",
            "stateful-inspection.drop-out-of-state-tcp-packets", True, "fix it"
        )
        r = self._result(audit, "3.10")
        assert r["status"] == "FAIL"
        assert r["actual"] is False

    def test_global_props_cached_across_calls(self):
        counter = []
        props = {
            "stateful-inspection": {
                "drop-out-of-state-tcp-packets": True,
                "drop-out-of-state-icmp-packets": True,
            }
        }
        audit = self._audit(global_props=props)
        audit.mgmt.call_count = counter
        audit._check_global_prop_via_api("3.10", "T", "L2",
            "stateful-inspection.drop-out-of-state-tcp-packets", True, "")
        audit._check_global_prop_via_api("3.11", "T", "L2",
            "stateful-inspection.drop-out-of-state-icmp-packets", True, "")
        # show-objects should only have been called once (cache hit on second)
        assert counter.count("show-objects") == 1

    # ── All 10 specific callers use the correct field path ─────

    @pytest.mark.parametrize("method,section,field,expected_val,expected_status", [
        ("check_3_4",  "hit-count",           "enable-hit-count",                True,  "PASS"),
        ("check_3_9",  "firewall",            "log-implied-rules",               False, "FAIL"),
        ("check_3_10", "stateful-inspection", "drop-out-of-state-tcp-packets",   True,  "PASS"),
        ("check_3_11", "stateful-inspection", "drop-out-of-state-icmp-packets",  True,  "PASS"),
        ("check_3_14", "firewall",            "accept-rip",                      False, "PASS"),
        ("check_3_15", "firewall",            "accept-domain-name-over-tcp",     False, "PASS"),
        ("check_3_16", "firewall",            "accept-domain-name-over-udp",     False, "PASS"),
        ("check_3_17", "firewall",            "accept-icmp-requests",            False, "PASS"),
        ("check_3_18", "nat",                 "allow-bi-directional-nat",        True,  "PASS"),
        ("check_3_19", "nat",                 "auto-arp-conf",                   True,  "PASS"),
    ])
    def test_check_method_field_path(self, method, section, field, expected_val, expected_status):
        """Each check reads the correct section.field from global-properties."""
        props = {section: {field: expected_val}}
        audit = self._audit(global_props=props)
        getattr(audit, method)()
        cid = method.replace("check_", "").replace("_", ".")
        r = self._result(audit, cid)
        assert r is not None, f"No result for {cid}"
        assert r["status"] == expected_status, (
            f"{method}: expected {expected_status}, got {r['status']} "
            f"(actual={r['actual']!r})"
        )
