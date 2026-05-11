"""
session_manager.py
Assessment session state machine + in-memory MEMORY store.

States:
  CREATED → AUDITING → AI_ANALYSIS → MANUAL_REVIEW → FINALIZING → COMPLETE
                     ↘ ERROR (from any state)

MEMORY stores:
  - Device context (role, industry, org)
  - Raw audit results
  - Enriched audit results
  - Manual finding updates
  - Current report data
  - Completion tracking
"""

import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class SessionState(str, Enum):
    CREATED       = "CREATED"
    AUDITING      = "AUDITING"
    AI_ANALYSIS   = "AI_ANALYSIS"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    FINALIZING    = "FINALIZING"
    COMPLETE      = "COMPLETE"
    ERROR         = "ERROR"


# Controls that require manual verification
MANUAL_CONTROLS = {
    "2.1.4", "2.1.5", "2.5.3",
    "3.1",  "3.2",  "3.3",  "3.5",  "3.6",  "3.7",
    "3.8",  "3.12", "3.13", "3.20",
    # API-dependent ones that fall back to MANUAL
    "3.4",  "3.9",  "3.10", "3.11",
    "3.14", "3.15", "3.16", "3.17", "3.18", "3.19",
    "2.4.1", "2.4.3", "2.3.2",
}

MANUAL_GUIDANCE = {
    "2.1.4": {
        "where": "Gaia Clish",
        "steps": ["Run: show config-state", "Look for 'Saved' status"],
        "pass_criteria": "Output shows configuration is saved",
        "fail_criteria": "Output shows unsaved changes",
    },
    "2.1.5": {
        "where": "Gaia Clish",
        "steps": ["Run: show interfaces all", "Identify interfaces with no traffic or purpose"],
        "pass_criteria": "All active interfaces are justified; unused ones are disabled (state off)",
        "fail_criteria": "Interfaces with state 'on' that serve no documented purpose",
    },
    "2.5.3": {
        "where": "Expert Mode / File System",
        "steps": ["Check $FWDIR/conf/fwauthd.conf", "Port 259 should be commented out", "Port 900 should have ssl:defaultCert"],
        "pass_criteria": "Port 259 disabled, port 900 SSL-only",
        "fail_criteria": "Port 259 active (plain HTTP client auth)",
    },
    "3.1": {
        "where": "SmartConsole → Security Policies → Access Control",
        "steps": ["Open the rulebase", "Check if Rule #1 drops all traffic destined to the gateway itself", "Source: Any, Destination: <This Gateway>, Service: Any, Action: Drop"],
        "pass_criteria": "Stealth rule is Rule #1 or #2 (before any Allow rules)",
        "fail_criteria": "No stealth rule exists, or it appears below permit rules",
    },
    "3.2": {
        "where": "SmartConsole → Security Policies → Access Control",
        "steps": ["Scroll to the last rule in the rulebase", "Verify it drops all traffic: Source: Any, Dest: Any, Service: Any, Action: Drop"],
        "pass_criteria": "Last rule is a catch-all Drop with logging enabled",
        "fail_criteria": "No cleanup rule, or last rule is not a Drop",
    },
    "3.3": {
        "where": "SmartConsole → Security Policies → Access Control",
        "steps": ["Verify that rules are organized into named sections", "Each section should have a descriptive title (e.g. 'Management Access', 'Internet Outbound')"],
        "pass_criteria": "Rules are organized into labelled sections",
        "fail_criteria": "All rules in one flat list with no sections",
    },
    "3.5": {
        "where": "SmartConsole → Security Policies → Access Control",
        "steps": ["Review all Allow/Accept rules", "Check the Destination column for 'Any'"],
        "pass_criteria": "No Allow rule has 'Any' in the Destination field",
        "fail_criteria": "One or more Allow rules have Destination = Any",
    },
    "3.6": {
        "where": "SmartConsole → Security Policies → Access Control",
        "steps": ["Review all Allow/Accept rules", "Check the Source column for 'Any'"],
        "pass_criteria": "No Allow rule has 'Any' in the Source field",
        "fail_criteria": "One or more Allow rules have Source = Any",
    },
    "3.7": {
        "where": "SmartConsole → Security Policies → Access Control",
        "steps": ["Review all Allow/Accept rules", "Check the Service/Application column for 'Any'"],
        "pass_criteria": "No Allow rule has 'Any' in the Services field",
        "fail_criteria": "One or more Allow rules have Service = Any",
    },
    "3.8": {
        "where": "SmartConsole → Security Policies → Access Control",
        "steps": ["Review every rule in the rulebase", "Check the Track column", "All rules should have Track set to 'Log' at minimum"],
        "pass_criteria": "Every rule has logging enabled (Track = Log or detailed)",
        "fail_criteria": "Any rule has Track = None",
    },
    "3.12": {
        "where": "SmartConsole → Gateway Object → Network Management",
        "steps": ["Open the Gateway/Cluster object", "Go to Network Management tab", "For each interface, click Edit", "Check Anti-Spoofing setting under General tab"],
        "pass_criteria": "All interfaces have Anti-Spoofing = Prevent with correct topology",
        "fail_criteria": "Any interface has Anti-Spoofing = Detect or disabled",
    },
    "3.13": {
        "where": "SmartConsole → Gateway Object → Logs",
        "steps": ["Open Gateway object", "Go to Logs tab", "Check Local Storage section", "Verify disk space alert threshold is configured"],
        "pass_criteria": "Disk space alert is configured with a threshold (e.g. 20%)",
        "fail_criteria": "No disk space alert configured",
    },
    "3.20": {
        "where": "SmartConsole → Manage & Settings → Blades → Firewall → Advanced Settings",
        "steps": ["Go to Global Properties", "Navigate to Log and Alert", "Check Track Options section", "Verify logging is enabled for relevant categories"],
        "pass_criteria": "Log and Alert Track Options are configured for VPN, Admin notifications, and connection events",
        "fail_criteria": "Track Options set to None for most categories",
    },
    "3.4": {
        "where": "SmartConsole → Manage & Settings → Blades → Firewall",
        "steps": ["Open Global Properties", "Navigate to Firewall section", "Verify 'Enable Hit Count' is checked"],
        "pass_criteria": "Hit Count is enabled",
        "fail_criteria": "Hit Count is disabled",
    },
    "3.9": {
        "where": "SmartConsole → Global Properties → Firewall",
        "steps": ["Open Global Properties", "Find 'Log Implied Rules' option", "Verify it is enabled"],
        "pass_criteria": "Log Implied Rules is enabled",
        "fail_criteria": "Log Implied Rules is disabled",
    },
    "3.10": {
        "where": "SmartConsole → Global Properties → Stateful Inspection",
        "steps": ["Open Global Properties", "Navigate to Stateful Inspection", "Verify 'Drop out of state TCP packets' is checked"],
        "pass_criteria": "Drop out of state TCP is enabled",
        "fail_criteria": "Drop out of state TCP is disabled",
    },
    "3.11": {
        "where": "SmartConsole → Global Properties → Stateful Inspection",
        "steps": ["Open Global Properties", "Navigate to Stateful Inspection", "Verify 'Drop out of state ICMP packets' is checked"],
        "pass_criteria": "Drop out of state ICMP is enabled",
        "fail_criteria": "Drop out of state ICMP is disabled",
    },
    "3.14": {
        "where": "SmartConsole → Global Properties → Firewall → Implied Rules",
        "steps": ["Open Global Properties", "Navigate to implied rules section", "Verify 'Accept RIP' is unchecked"],
        "pass_criteria": "Accept RIP is disabled",
        "fail_criteria": "Accept RIP is enabled",
    },
    "3.15": {
        "where": "SmartConsole → Global Properties → Firewall → Implied Rules",
        "steps": ["Open Global Properties", "Verify 'Accept Domain Name over TCP (Zone Transfer)' is unchecked"],
        "pass_criteria": "Accept DNS TCP is disabled",
        "fail_criteria": "Accept DNS TCP is enabled",
    },
    "3.16": {
        "where": "SmartConsole → Global Properties → Firewall → Implied Rules",
        "steps": ["Open Global Properties", "Verify 'Accept Domain Name over UDP (Queries)' is unchecked"],
        "pass_criteria": "Accept DNS UDP is disabled",
        "fail_criteria": "Accept DNS UDP is enabled",
    },
    "3.17": {
        "where": "SmartConsole → Global Properties → Firewall → Implied Rules",
        "steps": ["Open Global Properties", "Verify 'Accept ICMP Requests' is unchecked"],
        "pass_criteria": "Accept ICMP is disabled",
        "fail_criteria": "Accept ICMP is enabled",
    },
    "3.18": {
        "where": "SmartConsole → Global Properties → NAT",
        "steps": ["Open Global Properties", "Navigate to NAT section", "Verify 'Allow bi-directional NAT' is checked"],
        "pass_criteria": "Bi-directional NAT is enabled",
        "fail_criteria": "Bi-directional NAT is disabled",
    },
    "3.19": {
        "where": "SmartConsole → Global Properties → NAT",
        "steps": ["Open Global Properties", "Verify 'Automatic ARP Configuration' is checked"],
        "pass_criteria": "Automatic ARP Configuration is enabled",
        "fail_criteria": "Automatic ARP Configuration is disabled",
    },
    "2.4.1": {
        "where": "Gaia Portal or Clish",
        "steps": ["Run: show backup last-successful (if available)", "Or check Gaia Portal → Maintenance → System Backup"],
        "pass_criteria": "A system backup has been created and is recent (within policy window)",
        "fail_criteria": "No backup exists or last backup is older than policy allows",
    },
    "2.4.3": {
        "where": "Gaia Portal → Maintenance → System Backup",
        "steps": ["Log into Gaia Portal", "Navigate to Maintenance → System Backup", "Check if a scheduled backup is configured"],
        "pass_criteria": "Scheduled backup is configured with a recurring schedule",
        "fail_criteria": "No scheduled backup configured",
    },
    "2.3.2": {
        "where": "Gaia Clish",
        "steps": ["Run: show timezone", "Verify the timezone matches the organization's policy"],
        "pass_criteria": "Timezone is set to the correct organizational timezone",
        "fail_criteria": "Timezone is UTC or incorrect for the organization's location",
    },
}


class AssessmentSession:
    """All state for one assessment."""

    def __init__(self, session_id: str):
        self.session_id    = session_id
        self.state         = SessionState.CREATED
        self.created_at    = datetime.now(timezone.utc)
        self.updated_at    = datetime.now(timezone.utc)
        self.error_message: Optional[str] = None

        # Device context (set at form submission, never contains credentials)
        self.device_context: dict = {}

        # AI provider config (model, api_key, base_url — stored per-session)
        self.ai_model:    str = ""
        self.ai_api_key:  str = ""
        self.ai_base_url: str = ""

        # Raw audit results (from audit_tool.py)
        self.raw_results: list = []

        # Enriched results (from ai_analyzer.py)
        self.enriched_data: dict = {}

        # Manual findings: control_id → {status, evidence, notes, updated_at}
        self.manual_findings: dict = {}

        # Report data (updated after each manual input)
        self.report_data: dict = {}

        # Progress tracking
        self.progress_pct: int = 0
        self.progress_message: str = ""
        self.audit_log: list = []  # list of {ts, message, level}

        # Security compliance frameworks selected for this assessment
        self.frameworks: list = []

        # Firewall vendor: "checkpoint" | "palo_alto"
        self.vendor: str = "checkpoint"

        # Completion tracking
        self.total_manual = 0
        self.completed_manual = 0

        self._lock = threading.Lock()

    def log(self, message: str, level: str = "info"):
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.audit_log.append({"ts": ts, "message": message, "level": level})
            self.updated_at = datetime.now(timezone.utc)

    def transition(self, new_state: SessionState, message: str = ""):
        with self._lock:
            self.state       = new_state
            self.updated_at  = datetime.now(timezone.utc)
            if message:
                self.audit_log.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "message": message,
                    "level": "phase",
                })

    def set_error(self, message: str):
        with self._lock:
            self.state         = SessionState.ERROR
            self.error_message = message
            self.updated_at    = datetime.now(timezone.utc)

    def get_summary(self) -> dict:
        with self._lock:
            stats = self._compute_stats()
            return {
                "session_id":        self.session_id,
                "state":             self.state,
                "created_at":        self.created_at.isoformat(),
                "updated_at":        self.updated_at.isoformat(),
                "device_context":    self.device_context,
                "progress_pct":      self.progress_pct,
                "progress_message":  self.progress_message,
                "error_message":     self.error_message,
                "frameworks":        self.frameworks,
                "vendor":            self.vendor,
                "stats":             stats,
                "total_manual":      self.total_manual,
                "completed_manual":  self.completed_manual,
                "manual_completion_pct": (
                    round(self.completed_manual / self.total_manual * 100)
                    if self.total_manual else 0
                ),
            }

    def _compute_stats(self) -> dict:
        """Compute PASS/FAIL/etc counts from current results."""
        results = self.enriched_data.get("results", self.raw_results)
        counts = {"PASS": 0, "FAIL": 0, "MANUAL": 0, "SKIPPED": 0, "ERROR": 0}
        for r in results:
            status = r.get("status", "ERROR")
            # Override with manual finding if available
            cid = r.get("control_id", "")
            if cid in self.manual_findings and self.manual_findings[cid].get("status"):
                status = self.manual_findings[cid]["status"]
            counts[status] = counts.get(status, 0) + 1
        total  = sum(counts.values())
        passes = counts["PASS"]
        return {
            **counts,
            "total": total,
            "score": round(passes / total * 100, 1) if total else 0,
        }

    def get_manual_workbench(self) -> list:
        """Return all manual checks with current state and guidance."""
        items = []
        results = self.enriched_data.get("results", self.raw_results)
        for r in results:
            if r.get("status") != "MANUAL":
                continue
            cid      = r["control_id"]
            finding  = self.manual_findings.get(cid, {})
            if self.vendor == "checkpoint":
                guidance = MANUAL_GUIDANCE.get(cid) or r.get("guidance", {})
            else:
                guidance = r.get("guidance", {})
            ai       = r.get("ai_analysis", {})
            items.append({
                "control_id":   cid,
                "description":  r["description"],
                "level":        r["level"],
                "notes":        r.get("notes", ""),
                "guidance":     guidance,
                "ai_risk":      ai.get("risk_level", "Unknown"),
                "ai_priority":  ai.get("priority_rank", 99),
                "current_status":  finding.get("status", "PENDING"),
                "evidence":        finding.get("evidence", ""),
                "assessor_notes":  finding.get("notes", ""),
                "updated_at":      finding.get("updated_at", ""),
                "is_complete":     finding.get("status") in ("PASS", "FAIL", "NA"),
            })
        # Sort by AI priority rank
        items.sort(key=lambda x: int(x["ai_priority"]) if str(x["ai_priority"]).isdigit() else 99)
        return items

    def update_manual_finding(self, control_id: str,
                               status: str, evidence: str, notes: str) -> bool:
        """Record a manual finding. Returns True if it's a new completion."""
        was_complete = self.manual_findings.get(control_id, {}).get("status") in ("PASS", "FAIL", "NA")
        with self._lock:
            self.manual_findings[control_id] = {
                "status":     status,
                "evidence":   evidence,
                "notes":      notes,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            is_complete = status in ("PASS", "FAIL", "NA")
            if is_complete and not was_complete:
                self.completed_manual = min(self.completed_manual + 1, self.total_manual)
            elif not is_complete and was_complete:
                self.completed_manual = max(self.completed_manual - 1, 0)
            self.updated_at = datetime.now(timezone.utc)
        return is_complete and not was_complete

    @classmethod
    def from_dict(cls, data: dict) -> "AssessmentSession":
        """Reconstruct a session from a persisted dict (no credentials restored)."""
        obj = cls(data["session_id"])
        obj.state            = SessionState(data["state"])
        obj.created_at       = datetime.fromisoformat(data["created_at"])
        obj.updated_at       = datetime.fromisoformat(data["updated_at"])
        obj.error_message    = data.get("error_message")
        obj.device_context   = data.get("device_context", {})
        obj.raw_results      = data.get("raw_results", [])
        obj.enriched_data    = data.get("enriched_data", {})
        obj.manual_findings  = data.get("manual_findings", {})
        obj.report_data      = data.get("report_data", {})
        obj.audit_log        = data.get("audit_log", [])
        obj.total_manual     = data.get("total_manual", 0)
        obj.completed_manual = data.get("completed_manual", 0)
        obj.ai_model         = data.get("ai_model", "")
        obj.ai_api_key       = data.get("ai_api_key", "")   # empty after reload (not persisted)
        obj.ai_base_url      = data.get("ai_base_url", "")
        obj.frameworks       = data.get("frameworks", [])
        obj.vendor           = data.get("vendor", "checkpoint")
        return obj

    @property
    def is_report_finalizable(self) -> bool:
        """True when all manual checks have a resolution."""
        return (self.total_manual > 0 and
                self.completed_manual >= self.total_manual and
                self.state == SessionState.MANUAL_REVIEW)


class SessionManager:
    """Thread-safe registry of all active sessions."""

    def __init__(self):
        self._sessions: dict[str, AssessmentSession] = {}
        self._lock     = threading.Lock()

    def create(self) -> AssessmentSession:
        sid = str(uuid.uuid4())
        session = AssessmentSession(sid)
        with self._lock:
            self._sessions[sid] = session
        return session

    def get(self, session_id: str) -> Optional[AssessmentSession]:
        return self._sessions.get(session_id)

    def destroy(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def list_sessions(self) -> list:
        return [s.get_summary() for s in self._sessions.values()]


# Global singleton
sessions = SessionManager()
