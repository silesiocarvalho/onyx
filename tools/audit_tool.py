#!/usr/bin/env python3
"""
FW AI Audit — Firewall Security Audit Engine
Targets: Check Point Gaia R82 Standalone
Author : Generated audit tool
Usage  : python audit_tool.py -m <ip> -u <user> -p <pass> [options]
"""

from __future__ import print_function

import argparse
import datetime
import getpass
import json
import os
import re
import sys
import time

# ---------------------------------------------------------------------------
# Optional imports – SSH (paramiko) and CP Management API SDK
# ---------------------------------------------------------------------------
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    from cpapi import APIClient, APIClientArgs
    HAS_CPAPI = True
except ImportError:
    HAS_CPAPI = False

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def colorize(text, color):
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text

# ---------------------------------------------------------------------------
# Result constants
# ---------------------------------------------------------------------------
PASS           = "PASS"
FAIL           = "FAIL"
MANUAL         = "MANUAL"
SKIPPED        = "SKIPPED"
ERROR          = "ERROR"
RECOMMENDATION = "RECOMMENDATION"

STATUS_ICON = {
    PASS:           colorize("✅ PASS",       GREEN),
    FAIL:           colorize("❌ FAIL",        RED),
    MANUAL:         colorize("⚠️  MANUAL",     YELLOW),
    SKIPPED:        colorize("⏭️  SKIPPED",     DIM),
    ERROR:          colorize("🔴 ERROR",        RED),
    RECOMMENDATION: colorize("💡 RECOMMEND",   YELLOW),
}

# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------
class GaiaClishSession:
    """Thin wrapper around a Paramiko SSH connection that runs Gaia Clish cmds."""

    PROMPT_RE = re.compile(r'[\w\-\.]+[>#]\s*$')
    TIMEOUT   = 15

    def __init__(self, host, port=22):
        if not HAS_PARAMIKO:
            raise RuntimeError("paramiko is required for SSH connectivity. "
                               "Install with: pip install paramiko --break-system-packages")
        self.host   = host
        self.port   = port
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.channel = None

    def connect(self, username, password=None, key_filename=None):
        kwargs = dict(hostname=self.host, port=self.port, username=username,
                      timeout=10, look_for_keys=False, allow_agent=False)
        if password:
            kwargs['password'] = password
        if key_filename:
            kwargs['key_filename'] = key_filename
        self.client.connect(**kwargs)
        self.channel = self.client.invoke_shell()
        self.channel.settimeout(self.TIMEOUT)
        self._drain()                   # eat login banner / prompt

    def _drain(self):
        """Read until we see a shell prompt."""
        buf = ""
        deadline = time.time() + self.TIMEOUT
        while time.time() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode('utf-8', errors='replace')
                buf += chunk
                if self.PROMPT_RE.search(buf.splitlines()[-1] if buf.splitlines() else ""):
                    break
            else:
                time.sleep(0.1)
        return buf

    def run(self, command):
        """Send a Clish command and return the output lines (stripped)."""
        self.channel.send(command + "\n")
        time.sleep(0.2)
        output = self._drain()
        # Remove the echoed command and trailing prompt
        lines = output.splitlines()
        result_lines = []
        skip_first = True
        for line in lines:
            stripped = line.strip()
            if skip_first and command.strip() in stripped:
                skip_first = False
                continue
            if self.PROMPT_RE.match(stripped):
                continue
            result_lines.append(stripped)
        return "\n".join(result_lines).strip()

    def close(self):
        if self.channel:
            self.channel.close()
        self.client.close()


# ---------------------------------------------------------------------------
# Audit result dataclass (plain dict for Python 2/3 compat)
# ---------------------------------------------------------------------------
def make_result(control_id, description, level, status,
                expected=None, actual=None, remediation="", notes=""):
    return {
        "control_id":   control_id,
        "description":  description,
        "level":        level,
        "status":       status,
        "expected":     expected,
        "actual":       actual,
        "remediation":  remediation,
        "notes":        notes,
        "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Core audit checks
# ---------------------------------------------------------------------------
class CISAudit:

    def __init__(self, ssh_session, mgmt_client=None):
        self.ssh     = ssh_session
        self.mgmt    = mgmt_client   # CP API client (optional)
        self.results = []
        self._global_props_cache = None  # lazily populated by _get_global_properties
        self._rulebase_cache     = None  # lazily populated by _get_rulebase
        self._gateway_cache      = None  # lazily populated by _get_gateway
        self._nat_cache          = None  # lazily populated by _get_nat_rulebase

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _cmd(self, command):
        try:
            return self.ssh.run(command)
        except Exception as e:
            return f"__ERROR__: {e}"

    def _extract_value(self, output, pattern):
        """Return first capture group from regex search, or None."""
        m = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    def _is_on(self, value):
        return str(value).lower() in ('on', 'true', 'yes', 'enabled', '1')

    def _numeric_le(self, value, threshold):
        try:
            return int(value) <= threshold
        except (TypeError, ValueError):
            return False

    def _numeric_ge(self, value, threshold):
        try:
            return int(value) >= threshold
        except (TypeError, ValueError):
            return False

    def _add(self, result):
        self.results.append(result)

    def _manual(self, control_id, description, level, notes="", remediation=""):
        self._add(make_result(control_id, description, level, MANUAL,
                               notes=notes, remediation=remediation))

    def _error(self, control_id, description, level, err):
        self._add(make_result(control_id, description, level, ERROR,
                               notes=str(err)))

    def _recommend(self, control_id, description, level, notes="", remediation=""):
        self._add(make_result(control_id, description, level, RECOMMENDATION,
                               notes=notes, remediation=remediation))

    # -----------------------------------------------------------------------
    # Section 1 – Password Policy
    # -----------------------------------------------------------------------
    def check_1_1(self):
        cid, desc, level = "1.1", "Ensure Minimum Password Length is set to 14 or higher", "L1"
        out = self._cmd("show password-controls min-password-length")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_ge(val, 14) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≥ 14", actual=val,
                               remediation="set password-controls min-password-length 14"))

    def check_1_2(self):
        cid, desc, level = "1.2", "Ensure Disallow Palindromes is selected", "L1"
        out = self._cmd("show password-controls palindrome-check")
        val = self._extract_value(out, r'(on|off|true|false)', ) or out
        status = PASS if self._is_on(val) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on", actual=val,
                               remediation="set password-controls palindrome-check on"))

    def check_1_3(self):
        cid, desc, level = "1.3", "Ensure Password Complexity is set to 3", "L1"
        out = self._cmd("show password-controls complexity")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if int(val) >= 3 else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≥ 3", actual=val,
                               remediation="set password-controls complexity 3"))

    def check_1_4_history_checking(self):
        cid, desc, level = "1.4a", "Ensure Check for Password Reuse is selected", "L1"
        out = self._cmd("show password-controls history-checking")
        val = self._extract_value(out, r'(on|off|true|false)') or out
        status = PASS if self._is_on(val) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on", actual=val,
                               remediation="set password-controls history-checking on"))

    def check_1_4_history_length(self):
        cid, desc, level = "1.4b", "Ensure History Length is set to 12 or more", "L1"
        out = self._cmd("show password-controls history-length")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_ge(val, 12) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≥ 12", actual=val,
                               remediation="set password-controls history-length 12"))

    def check_1_5(self):
        cid, desc, level = "1.5", "Ensure Password Expiration is set to 90 days or less", "L1"
        out = self._cmd("show password-controls password-expiration")
        # "never" or a number
        if 'never' in out.lower():
            status = FAIL
            val = "never"
        else:
            val = self._extract_value(out, r'(\d+)')
            if val is None:
                self._error(cid, desc, level, f"Unexpected output: {out}")
                return
            status = PASS if self._numeric_le(val, 90) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 90 days", actual=val,
                               remediation="set password-controls password-expiration 90"))

    def check_1_6(self):
        cid, desc, level = "1.6", "Ensure Warn users before password expiration is set to 7 days or less", "L1"
        out = self._cmd("show password-controls expiration-warning-days")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 7) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 7 days", actual=val,
                               remediation="set password-controls expiration-warning-days 7"))

    def check_1_7(self):
        cid, desc, level = "1.7", "Ensure Lockout users after password expiration is set to 1", "L1"
        out = self._cmd("show password-controls expiration-lockout-days")
        if 'never' in out.lower():
            status = FAIL
            val = "never"
        else:
            val = self._extract_value(out, r'(\d+)')
            if val is None:
                self._error(cid, desc, level, f"Unexpected output: {out}")
                return
            status = PASS if int(val) == 1 else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="1 day", actual=val,
                               remediation="set password-controls expiration-lockout-days 1"))

    def check_1_8(self):
        cid, desc, level = "1.8", "Ensure Deny access to unused accounts is selected", "L1"
        # Gaia OS
        out = self._cmd("show password-controls deny-on-nonuse enable")
        val = self._extract_value(out, r'(on|off|true|false)') or out.strip()
        gaia_ok = self._is_on(val)
        # SmartConsole
        sc_fail, sc_notes = False, ""
        if self.mgmt:
            try:
                stale, total = self._sc_stale_admins(30)
                sc_fail = len(stale) > 0
                sc_notes = (f"SmartConsole: {len(stale)}/{total} admin(s) inactive >30 days: {', '.join(stale[:3])}"
                            if sc_fail else f"SmartConsole: all {total} admin(s) have recent activity")
            except Exception as e:
                sc_notes = f"SmartConsole check failed: {e}"
        else:
            sc_notes = "SmartConsole accounts not checked — Management API not connected"
        status = PASS if (gaia_ok and not sc_fail) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="Gaia OS: on; SmartConsole: no admins inactive >30 days",
                               actual=f"Gaia OS deny-on-nonuse = {val}",
                               notes=sc_notes,
                               remediation="set password-controls deny-on-nonuse enable on. "
                                           "Review and disable unused SmartConsole admin accounts."))

    def check_1_9(self):
        cid, desc, level = "1.9", "Ensure Days of non-use before lock-out is set to 30 or less", "L1"
        out = self._cmd("show password-controls deny-on-nonuse allowed-days")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        sc_notes = ""
        if self.mgmt:
            try:
                stale, total = self._sc_stale_admins(30)
                sc_notes = (f"SmartConsole: {len(stale)}/{total} admin(s) inactive >30 days — "
                            "no equivalent inactivity lockout enforced for SmartConsole accounts"
                            if stale else f"SmartConsole: all {total} admin(s) active within 30 days")
            except Exception as e:
                sc_notes = f"SmartConsole check failed: {e}"
        else:
            sc_notes = "SmartConsole accounts not checked — Management API not connected"
        status = PASS if self._numeric_le(val, 30) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 30 days", actual=val, notes=sc_notes,
                               remediation="set password-controls deny-on-nonuse allowed-days 30"))

    def check_1_10(self):
        cid, desc, level = "1.10", "Ensure Force users to change password at first login", "L1"
        out = self._cmd("show password-controls force-change-when")
        gaia_ok = 'password' in out.lower()
        sc_notes = ""
        if self.mgmt:
            try:
                local, external = self._sc_auth_summary()
                sc_notes = (f"SmartConsole: {len(local)} admin(s) use local auth — "
                            f"verify force-password-change setting: {', '.join(a.split(' ')[0] for a in local[:3])}"
                            if local
                            else f"SmartConsole: all {len(external)} admin(s) use external auth — "
                                 "password policy managed by auth provider")
            except Exception as e:
                sc_notes = f"SmartConsole check failed: {e}"
        else:
            sc_notes = "SmartConsole accounts not checked — Management API not connected"
        status = PASS if gaia_ok else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="password", actual=out.strip(), notes=sc_notes,
                               remediation="set password-controls force-change-when password"))

    def check_1_11(self):
        cid, desc, level = "1.11", "Ensure Deny access after failed login attempts is selected", "L1"
        # Gaia OS
        out = self._cmd("show password-controls deny-on-fail enable")
        val = self._extract_value(out, r'(on|off|true|false)') or out.strip()
        gaia_ok = self._is_on(val)
        # SmartConsole
        sc_fail, sc_notes = False, ""
        if self.mgmt:
            try:
                local, external = self._sc_auth_summary()
                sc_fail = len(local) > 0
                sc_notes = (f"SmartConsole: {len(local)} admin(s) use local auth — "
                            f"no automated lockout enforced: {', '.join(a.split(' ')[0] for a in local[:3])}"
                            if sc_fail
                            else f"SmartConsole: all {len(external)} admin(s) use external auth "
                                 "(lockout enforced by provider)")
            except Exception as e:
                sc_notes = f"SmartConsole check failed: {e}"
        else:
            sc_notes = "SmartConsole accounts not checked — Management API not connected"
        status = PASS if (gaia_ok and not sc_fail) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="Gaia OS: on; SmartConsole: all admins use external auth",
                               actual=f"Gaia OS deny-on-fail = {val}",
                               notes=sc_notes,
                               remediation="set password-controls deny-on-fail enable on. "
                                           "Configure SmartConsole admins with RADIUS or TACACS+ authentication."))

    def check_1_12(self):
        cid, desc, level = "1.12", "Ensure Maximum number of failed attempts allowed is set to 5 or fewer", "L1"
        # Gaia OS
        out = self._cmd("show password-controls deny-on-fail failures-allowed")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        # SmartConsole
        sc_fail, sc_notes = False, ""
        if self.mgmt:
            try:
                local, external = self._sc_auth_summary()
                sc_fail = len(local) > 0
                sc_notes = (f"SmartConsole: {len(local)} admin(s) use local auth — "
                            f"max-failures threshold not enforced: {', '.join(a.split(' ')[0] for a in local[:3])}"
                            if sc_fail
                            else f"SmartConsole: all {len(external)} admin(s) use external auth")
            except Exception as e:
                sc_notes = f"SmartConsole check failed: {e}"
        else:
            sc_notes = "SmartConsole accounts not checked — Management API not connected"
        gaia_ok = self._numeric_le(val, 5)
        status = PASS if (gaia_ok and not sc_fail) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="Gaia OS: ≤5; SmartConsole: all admins use external auth",
                               actual=f"Gaia OS failures-allowed = {val}",
                               notes=sc_notes,
                               remediation="set password-controls deny-on-fail failures-allowed 5. "
                                           "Configure SmartConsole admins with RADIUS or TACACS+ authentication."))

    def check_1_13(self):
        cid, desc, level = "1.13", "Ensure Allow access again after time is set to 300 or more seconds", "L1"
        # Gaia OS
        out = self._cmd("show password-controls deny-on-fail allow-after")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        # SmartConsole
        sc_fail, sc_notes = False, ""
        if self.mgmt:
            try:
                local, external = self._sc_auth_summary()
                sc_fail = len(local) > 0
                sc_notes = (f"SmartConsole: {len(local)} admin(s) use local auth — "
                            f"re-enable delay not enforced: {', '.join(a.split(' ')[0] for a in local[:3])}"
                            if sc_fail
                            else f"SmartConsole: all {len(external)} admin(s) use external auth")
            except Exception as e:
                sc_notes = f"SmartConsole check failed: {e}"
        else:
            sc_notes = "SmartConsole accounts not checked — Management API not connected"
        gaia_ok = self._numeric_ge(val, 300)
        status = PASS if (gaia_ok and not sc_fail) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="Gaia OS: ≥300s; SmartConsole: all admins use external auth",
                               actual=f"Gaia OS allow-after = {val}",
                               notes=sc_notes,
                               remediation="set password-controls deny-on-fail allow-after 300. "
                                           "Configure SmartConsole admins with RADIUS or TACACS+ authentication."))

    # -----------------------------------------------------------------------
    # Section 2.1 – General Settings
    # -----------------------------------------------------------------------
    def check_2_1_1(self):
        cid, desc, level = "2.1.1", "Ensure 'Login Banner' is set", "L1"
        out = self._cmd("show configuration message")
        banner_on   = bool(re.search(r'set message banner on', out, re.IGNORECASE))
        has_content = bool(re.search(r'set message banner on.*msgvalue', out, re.IGNORECASE | re.DOTALL))
        if banner_on and has_content:
            status = PASS
        elif banner_on:
            status = FAIL
            out = "Banner on but no msgvalue configured"
        else:
            status = FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="message banner on + msgvalue set", actual=out[:120],
                               remediation='set message banner on msgvalue "Unauthorized access prohibited"'))

    def check_2_1_2(self):
        cid, desc, level = "2.1.2", "Ensure 'Message Of The Day (MOTD)' is set", "L1"
        out = self._cmd("show configuration message")
        motd_on     = bool(re.search(r'set message motd on', out, re.IGNORECASE))
        has_content = bool(re.search(r'set message motd on.*msgvalue', out, re.IGNORECASE | re.DOTALL))
        status = PASS if (motd_on and has_content) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="message motd on + msgvalue set", actual=out[:120],
                               remediation='set message motd on msgvalue "Unauthorized access prohibited"'))

    def check_2_1_3(self):
        cid, desc, level = "2.1.3", "Ensure Core Dump is enabled", "L1"
        out = self._cmd("show core-dump status")
        status = PASS if 'enable' in out.lower() else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="enabled", actual=out,
                               remediation="set core-dump enable"))

    def check_2_1_4(self):
        cid, desc, level = "2.1.4", "Ensure Config-state is saved", "L1"
        out = self._cmd("show config-state")
        saved = bool(re.search(r'\bsaved\b', out, re.IGNORECASE))
        status = PASS if saved else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="saved", actual=out.strip() or "no output",
                               remediation="save config"))

    def check_2_1_5(self):
        cid, desc, level = "2.1.5", "Ensure unused interfaces are disabled", "L1"
        out = self._cmd("show interfaces all")
        self._add(make_result(cid, desc, level, MANUAL,
                               actual=out[:300],
                               notes="Review output and disable unused interfaces.",
                               remediation="set interface <Interface_Number> state off"))

    def check_2_1_6(self):
        cid, desc, level = "2.1.6", "Ensure DNS server is configured", "L1"
        primary   = self._cmd("show dns primary")
        secondary = self._cmd("show dns secondary")
        p_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', primary)
        s_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', secondary)
        status = PASS if p_ip and s_ip else FAIL
        actual = f"primary={p_ip.group(1) if p_ip else 'NOT SET'}, secondary={s_ip.group(1) if s_ip else 'NOT SET'}"
        self._add(make_result(cid, desc, level, status,
                               expected="Primary and Secondary DNS set", actual=actual,
                               remediation="set dns primary <IP> ; set dns secondary <IP>"))

    def check_2_1_7(self):
        cid, desc, level = "2.1.7", "Ensure IPv6 is disabled if not used", "L1"
        out = self._cmd("show ipv6-state")
        val = self._extract_value(out, r'(on|off)') or out
        status = PASS if val.lower() == 'off' else MANUAL
        notes = "" if status == PASS else "IPv6 is enabled. Verify this is intentional."
        self._add(make_result(cid, desc, level, status,
                               expected="off (if not used)", actual=val,
                               remediation="set ipv6-state off",
                               notes=notes))

    def check_2_1_8(self):
        cid, desc, level = "2.1.8", "Ensure Host Name is set", "L1"
        out = self._cmd("show hostname")
        val = out.strip()
        status = PASS if val and val not in ('', 'localhost', 'gaia') else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="Non-default hostname", actual=val,
                               remediation="set hostname <descriptive-name>"))

    def check_2_1_9(self):
        cid, desc, level = "2.1.9", "Ensure Telnet is disabled", "L1"
        out = self._cmd("show net-access telnet")
        val = self._extract_value(out, r'(on|off)') or out
        status = PASS if val.lower() == 'off' else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="off", actual=val,
                               remediation="set net-access telnet off"))

    def check_2_1_10(self):
        cid, desc, level = "2.1.10", "Ensure DHCP is disabled", "L1"
        out = self._cmd("show dhcp server status")
        status = FAIL if re.search(r'enable', out, re.IGNORECASE) else PASS
        self._add(make_result(cid, desc, level, status,
                               expected="DHCP Server Disabled", actual=out,
                               remediation="set dhcp server disable"))

    # -----------------------------------------------------------------------
    # Section 2.2 – SNMP
    # -----------------------------------------------------------------------
    def check_2_2_1(self):
        cid, desc, level = "2.2.1", "Ensure SNMP agent is disabled (or v3-only)", "L1"
        out = self._cmd("show snmp agent")
        agent_off = bool(re.search(r'disabled', out, re.IGNORECASE))
        self._snmp_agent_off = agent_off   # used by dependent checks
        status = PASS if agent_off else MANUAL
        notes = "" if agent_off else "SNMP agent is ON. Ensure v3-only is configured (see 2.2.2)."
        self._add(make_result(cid, desc, level, status,
                               expected="disabled (or v3-only if required)", actual=out,
                               remediation="set snmp agent off",
                               notes=notes))

    def check_2_2_2(self):
        cid, desc, level = "2.2.2", "Ensure SNMP version is set to v3-Only", "L1"
        if getattr(self, '_snmp_agent_off', True):
            self._add(make_result(cid, desc, level, SKIPPED,
                                   notes="SNMP agent is disabled; v3-only not applicable."))
            return
        out = self._cmd("show snmp agent-version")
        status = PASS if 'v3' in out.lower() else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="v3-Only", actual=out,
                               remediation="set snmp agent-version v3-Only"))

    def check_2_2_3(self):
        cid, desc, level = "2.2.3", "Ensure SNMP traps are enabled", "L1"
        if getattr(self, '_snmp_agent_off', True):
            self._add(make_result(cid, desc, level, SKIPPED,
                                   notes="SNMP agent is disabled; traps not applicable."))
            return
        out = self._cmd("show snmp traps enabled-traps")
        required = ['authorizationError', 'coldStart', 'configurationChange',
                    'configurationSave', 'linkUpLinkDown', 'lowDiskSpace']
        missing = [t for t in required if t.lower() not in out.lower()]
        status = PASS if not missing else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="All 6 traps enabled", actual=out[:200],
                               notes=f"Missing traps: {missing}" if missing else "",
                               remediation="set snmp traps trap <trapName> enable"))

    def check_2_2_4(self):
        cid, desc, level = "2.2.4", "Ensure SNMP traps receivers is set", "L1"
        if getattr(self, '_snmp_agent_off', True):
            self._add(make_result(cid, desc, level, SKIPPED,
                                   notes="SNMP agent is disabled; trap receivers not applicable."))
            return
        out = self._cmd("show snmp traps receivers")
        has_receiver = bool(re.search(r'trap receiver', out, re.IGNORECASE))
        status = PASS if has_receiver else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="At least one trap receiver configured", actual=out,
                               remediation="add snmp traps receiver <IP> version v3"))

    # -----------------------------------------------------------------------
    # Section 2.3 – NTP
    # -----------------------------------------------------------------------
    def check_2_3_1(self):
        cid, desc, level = "2.3.1", "Ensure NTP is enabled with Primary and Secondary servers", "L1"
        active = self._cmd("show ntp active")
        servers = self._cmd("show ntp servers")
        ntp_on  = bool(re.search(r'\byes\b', active, re.IGNORECASE))
        has_pri = bool(re.search(r'primary', servers, re.IGNORECASE))
        has_sec = bool(re.search(r'secondary', servers, re.IGNORECASE))
        status  = PASS if (ntp_on and has_pri and has_sec) else FAIL
        actual  = f"active={active.strip()}, servers=\n{servers[:200]}"
        self._add(make_result(cid, desc, level, status,
                               expected="NTP active with primary+secondary servers",
                               actual=actual,
                               remediation="set ntp active on ; set ntp server primary <host> version 3 ; set ntp server secondary <host> version 3"))

    def check_2_3_2(self):
        cid, desc, level = "2.3.2", "Ensure timezone is properly configured", "L1"
        out = self._cmd("show timezone")
        status = PASS if out.strip() and 'UTC' in out.upper() or '/' in out else MANUAL
        self._add(make_result(cid, desc, level, MANUAL if '/' not in out else PASS,
                               expected="Organization-appropriate timezone",
                               actual=out,
                               notes="Verify timezone matches organizational policy.",
                               remediation="set timezone <Area> / <Region>"))

    # -----------------------------------------------------------------------
    # Section 2.4 – Backup
    # -----------------------------------------------------------------------
    def check_2_4_1(self):
        cid, desc, level = "2.4.1", "Ensure 'System Backup' is set", "L1"
        out = self._cmd("show backups")
        has_backup = bool(re.search(r'\.tgz', out, re.IGNORECASE))
        if not has_backup:
            self._add(make_result(cid, desc, level, FAIL,
                                   expected="At least one .tgz backup ≤ 90 days old",
                                   actual=out.strip() or "No backups found",
                                   remediation="add backup local"))
            return
        from datetime import date as _date
        dates = []
        for m in re.finditer(r'(\d{4})[_\-]?(\d{2})[_\-]?(\d{2})', out):
            try:
                dates.append(_date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
            except ValueError:
                pass
        if dates:
            most_recent = max(dates)
            age = (_date.today() - most_recent).days
            if age > 90:
                self._add(make_result(cid, desc, level, FAIL,
                                       expected="Most recent backup ≤ 90 days old",
                                       actual=out.strip()[:200],
                                       notes=f"Most recent backup is {age} days old — exceeds 90-day limit",
                                       remediation="add backup local"))
                return
            notes = f"Most recent backup is {age} days old"
        else:
            notes = "Backup present; unable to parse backup date — verify manually"
        self._add(make_result(cid, desc, level, PASS,
                               expected="At least one .tgz backup ≤ 90 days old",
                               actual=out.strip()[:200],
                               notes=notes,
                               remediation="add backup local"))

    def check_2_4_2(self):
        cid, desc, level = "2.4.2", "Ensure 'Snapshot' is set", "L1"
        out = self._cmd("show snapshots")
        has_snap = bool(re.search(r'restore points|snap', out, re.IGNORECASE))
        if not has_snap:
            self._add(make_result(cid, desc, level, FAIL,
                                   expected="At least one snapshot ≤ 90 days old",
                                   actual=out[:200],
                                   remediation="add snapshot <name>"))
            return
        from datetime import date as _date
        dates = []
        for m in re.finditer(r'(\d{4})[_\-]?(\d{2})[_\-]?(\d{2})', out):
            try:
                dates.append(_date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
            except ValueError:
                pass
        if dates:
            most_recent = max(dates)
            age = (_date.today() - most_recent).days
            if age > 90:
                self._add(make_result(cid, desc, level, FAIL,
                                       expected="Most recent snapshot ≤ 90 days old",
                                       actual=out[:200],
                                       notes=f"Most recent snapshot is {age} days old — exceeds 90-day limit",
                                       remediation="add snapshot <name>"))
                return
            notes = f"Most recent snapshot is {age} days old"
        else:
            notes = "Snapshot present; unable to parse snapshot date — verify manually"
        self._add(make_result(cid, desc, level, PASS,
                               expected="At least one snapshot ≤ 90 days old",
                               actual=out[:200],
                               notes=notes,
                               remediation="add snapshot <name>"))

    def check_2_4_3(self):
        cid, desc, level = "2.4.3", "Configuring Scheduled Backups", "L1"
        out = self._cmd("show configuration backup-scheduled")
        has_schedule = bool(out.strip())
        status = PASS if has_schedule else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="At least one scheduled backup configured",
                               actual=out.strip() or "No scheduled backups configured",
                               remediation="add backup-scheduled name <Name> local && set backup-scheduled name <Name> recurrence daily time 02:00"))

    # -----------------------------------------------------------------------
    # Section 2.5 – Authentication Settings
    # -----------------------------------------------------------------------
    def check_2_5_1(self):
        cid, desc, level = "2.5.1", "Ensure CLI session timeout is set to ≤ 10 minutes", "L1"
        out = self._cmd("show inactivity-timeout")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 10) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 10 minutes", actual=val,
                               remediation="set inactivity-timeout 10"))

    def check_2_5_2(self):
        cid, desc, level = "2.5.2", "Ensure Web session timeout is set to ≤ 10 minutes", "L1"
        out = self._cmd("show web session-timeout")
        val = self._extract_value(out, r'(\d+)')
        if val is None:
            self._error(cid, desc, level, f"Unexpected output: {out}")
            return
        status = PASS if self._numeric_le(val, 10) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="≤ 10 minutes", actual=val,
                               remediation="set web session-timeout 10"))

    def check_2_5_3(self):
        self._manual("2.5.3", "Ensure Client Authentication is secured (HTTPS)", "L1",
                     notes="Verify $FWDIR/conf/fwauthd.conf: port 259 should be commented out "
                           "and port 900 should have ssl:defaultCert.",
                     remediation="Edit $FWDIR/conf/fwauthd.conf in Expert mode.")

    def check_2_5_4(self):
        cid, desc, level = "2.5.4", "Ensure RADIUS or TACACS+ server is configured", "L1"
        tacacs = self._cmd("show aaa tacacs-servers state")
        radius = self._cmd("show aaa radius-servers list")
        tacacs_on  = bool(re.search(r'\bon\b', tacacs, re.IGNORECASE))
        radius_cfg = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', radius))
        status = PASS if (tacacs_on or radius_cfg) else FAIL
        actual = f"TACACS+ state: {tacacs.strip()[:60]} | RADIUS: {radius.strip()[:60]}"
        self._add(make_result(cid, desc, level, status,
                               expected="RADIUS or TACACS+ configured", actual=actual,
                               remediation="set aaa tacacs-servers state on ; add aaa tacacs-servers ..."))

    def check_2_5_5(self):
        cid, desc, level = "2.5.5", "Ensure allowed-client is restricted to necessary hosts", "L2"
        out = self._cmd("show allowed-client all")
        has_any = bool(re.search(r'\bany\b', out, re.IGNORECASE))
        no_output = not out.strip()
        if no_output:
            status = FAIL
            actual = "No output — command may have failed or no clients configured"
        elif has_any:
            status = FAIL
            actual = out[:200]
        else:
            status = PASS
            actual = out[:200]
        self._add(make_result(cid, desc, level, status,
                               expected="Specific management IPs only (no 'any')",
                               actual=actual,
                               remediation="delete allowed-client host any-host ; add allowed-client host ipv4-address <MGMT-IP>"))

    # -----------------------------------------------------------------------
    # Section 2.6 – Logging
    # -----------------------------------------------------------------------
    def check_2_6_1(self):
        cid, desc, level = "2.6.1", "Ensure mgmtauditlogs is set to on", "L1"
        out = self._cmd("show syslog mgmtauditlogs")
        status = PASS if 'enabled' in out.lower() or re.search(r'\bon\b', out, re.IGNORECASE) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="enabled/on", actual=out,
                               remediation="set syslog mgmtauditlogs on"))

    def check_2_6_2(self):
        cid, desc, level = "2.6.2", "Ensure auditlog is set to permanent", "L1"
        out = self._cmd("show syslog auditlog")
        status = PASS if 'permanent' in out.lower() else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="permanent", actual=out,
                               remediation="set syslog auditlog permanent"))

    def check_2_6_3(self):
        cid, desc, level = "2.6.3", "Ensure cplogs is set to on", "L1"
        out = self._cmd("show syslog cplogs")
        status = PASS if 'enabled' in out.lower() or re.search(r'\bon\b', out, re.IGNORECASE) else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="on/enabled", actual=out,
                               remediation="set syslog cplogs on"))

    # -----------------------------------------------------------------------
    # Section 3 – Firewall Secure Settings
    # (Many require SmartConsole access or manual verification)
    # -----------------------------------------------------------------------
    def check_3_1(self):
        cid, desc, level = "3.1", "Enable the Firewall Stealth Rule", "L2"
        rem = "Create a Drop rule in SmartConsole targeting the gateway object before any permissive rules."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = self._get_rulebase()
            gw_ip = self.ssh.host
            stealth = False
            for rule in rules:
                if not rule.get("enabled", True):
                    continue
                action = rule.get("action", {})
                if not self._is_drop(action):
                    continue
                dests = rule.get("destination", [])
                for d in dests:
                    ip = d.get("ipv4-address", "") if isinstance(d, dict) else ""
                    if ip == gw_ip or (not self._is_any(d) and len(dests) > 0):
                        stealth = True
                        break
                if stealth:
                    break
            status = PASS if stealth else FAIL
            self._add(make_result(cid, desc, level, status,
                                   expected="Drop rule targeting gateway before permissive rules",
                                   actual=f"Stealth rule {'found' if stealth else 'NOT found'}",
                                   remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_3_2(self):
        cid, desc, level = "3.2", "Configure a Default Drop/Cleanup Rule", "L2"
        rem = "Add a Drop rule with Any/Any/Any as the last rule in the rulebase."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = [r for r in self._get_rulebase() if r.get("enabled", True)]
            if not rules:
                self._manual(cid, desc, level, notes="No rules found.", remediation=rem)
                return
            last = rules[-1]
            action = last.get("action", {})
            is_drop    = self._is_drop(action)
            src_any    = all(self._is_any(o) for o in last.get("source", []))
            dst_any    = all(self._is_any(o) for o in last.get("destination", []))
            svc_any    = all(self._is_any(o) for o in last.get("service", []))
            status = PASS if (is_drop and src_any and dst_any and svc_any) else FAIL
            actual = (f"Last rule action={self._obj_name(action)}, "
                      f"src_any={src_any}, dst_any={dst_any}, svc_any={svc_any}")
            self._add(make_result(cid, desc, level, status,
                                   expected="Drop rule with Any/Any/Any as last rule",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_3_3(self):
        cid, desc, level = "3.3", "Use Checkpoint Sections and Titles", "L1"
        rem = "Organize rules into named sections in SmartConsole Access Control policy."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            layers_resp = self.mgmt.api_call("show-access-layers", {"details-level": "standard"})
            sections = []
            if layers_resp.success:
                for layer in layers_resp.data.get("access-layers", []):
                    resp = self.mgmt.api_call("show-access-rulebase", {
                        "name": layer["name"], "limit": 500, "details-level": "standard"})
                    if resp.success:
                        for item in resp.data.get("rulebase", []):
                            if isinstance(item, dict) and item.get("type") == "access-section":
                                sections.append(item.get("name", ""))
            generic = re.compile(r'^Rules?\s*\d', re.IGNORECASE)
            named = [s for s in sections if s and not generic.match(s)]
            if not sections:
                status, actual = FAIL, "No sections found in rulebase"
            elif named:
                status, actual = PASS, f"Sections: {', '.join(sections)}"
            else:
                status, actual = FAIL, f"Only generic sections found: {', '.join(sections)}"
            self._add(make_result(cid, desc, level, status,
                                   expected="Named sections organising rules",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    # ── CP API object helpers ────────────────────────────────────────────────

    ANY_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"

    @staticmethod
    def _obj_name(obj):
        """Return the name of a CP API object (handles full or UID-only format)."""
        if isinstance(obj, dict):
            return obj.get("name", "")
        return str(obj)

    @classmethod
    def _is_any(cls, obj):
        """True if obj is the special 'Any' object."""
        if isinstance(obj, dict):
            return obj.get("name") == "Any" or obj.get("uid") == cls.ANY_UID
        return obj == cls.ANY_UID

    @staticmethod
    def _is_accept(action):
        """True if the rule action is Accept."""
        name = action.get("name", "") if isinstance(action, dict) else ""
        return name.lower() == "accept"

    @staticmethod
    def _is_drop(action):
        """True if the rule action is Drop or Reject."""
        name = action.get("name", "") if isinstance(action, dict) else ""
        return name.lower() in ("drop", "reject", "inner layer")

    @staticmethod
    def _is_logged(track):
        """True if the track object indicates logging (Log, Alert, Account).

        The API returns track.type as either:
          - a dict  {"name": "Log", ...}  — when objects are expanded
          - a UID string                  — when type is a built-in reference
        A UID string means a track type IS configured; only empty/"none" means no logging.
        """
        if not isinstance(track, dict):
            return False
        t = track.get("type", {})
        if isinstance(t, dict):
            name = t.get("name", "").lower()
            return name in ("log", "alert", "account")
        # UID string reference — non-empty and not "none" means logging is set
        return isinstance(t, str) and t.lower() not in ("", "none")

    @staticmethod
    def _flatten_rules(rulebase_list):
        """Recursively flatten sections into a flat list of access-rule dicts."""
        rules = []
        for item in rulebase_list:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "access-rule":
                rules.append(item)
            elif item.get("type") == "access-section":
                rules.extend(CISAudit._flatten_rules(item.get("rulebase", [])))
        return rules

    @staticmethod
    def _flatten_nat_rules(rulebase_list):
        """Recursively flatten NAT sections into a flat list of nat-rule dicts."""
        rules = []
        for item in rulebase_list:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "nat-rule":
                rules.append(item)
            elif item.get("type") == "nat-section":
                rules.extend(CISAudit._flatten_nat_rules(item.get("rulebase", [])))
        return rules

    # ── Cached API fetchers ──────────────────────────────────────────────────

    def _get_global_properties(self):
        """Fetch and cache global-properties object via show-objects."""
        if self._global_props_cache is not None:
            return self._global_props_cache
        resp = self.mgmt.api_call("show-objects",
                                   {"type": "global-properties", "details-level": "full"})
        if resp.success and resp.data.get('objects'):
            self._global_props_cache = resp.data['objects'][0]
        else:
            self._global_props_cache = {}
        return self._global_props_cache

    def _get_rulebase(self):
        """Fetch and cache a flat list of all access rules from all layers."""
        if self._rulebase_cache is not None:
            return self._rulebase_cache
        try:
            layers_resp = self.mgmt.api_call("show-access-layers",
                                              {"details-level": "standard"})
            if not layers_resp.success:
                self._rulebase_cache = []
                return self._rulebase_cache

            all_rules = []
            for layer in layers_resp.data.get("access-layers", []):
                offset = 0
                while True:
                    resp = self.mgmt.api_call("show-access-rulebase", {
                        "name": layer["name"],
                        "offset": offset,
                        "limit": 500,
                        "details-level": "full",
                    })
                    if not resp.success:
                        break
                    all_rules.extend(resp.data.get("rulebase", []))
                    total = resp.data.get("total", 0)
                    offset += 500
                    if offset >= total:
                        break

            self._rulebase_cache = self._flatten_rules(all_rules)
        except Exception:
            self._rulebase_cache = []
        return self._rulebase_cache

    def _get_gateway(self):
        """Fetch and cache the gateway object matching the SSH target IP."""
        if self._gateway_cache is not None:
            return self._gateway_cache
        try:
            resp = self.mgmt.api_call("show-simple-gateways",
                                       {"details-level": "full"})
            if resp.success:
                target = self.ssh.host
                for gw in resp.data.get("objects", []):
                    if gw.get("ipv4-address") == target:
                        self._gateway_cache = gw
                        return self._gateway_cache
                gws = resp.data.get("objects", [])
                self._gateway_cache = gws[0] if gws else {}
            else:
                self._gateway_cache = {}
        except Exception:
            self._gateway_cache = {}
        return self._gateway_cache

    def _get_nat_rulebase(self):
        """Fetch and cache a flat list of all NAT rules."""
        if self._nat_cache is not None:
            return self._nat_cache
        try:
            pkg_name = None
            pkg_resp = self.mgmt.api_call("show-packages",
                                           {"details-level": "standard", "limit": 1})
            if pkg_resp.success and pkg_resp.data.get("packages"):
                pkg_name = pkg_resp.data["packages"][0].get("name")

            all_rules = []
            offset = 0
            while True:
                params = {"details-level": "full", "limit": 500, "offset": offset}
                if pkg_name:
                    params["package"] = pkg_name
                resp = self.mgmt.api_call("show-nat-rulebase", params)
                if not resp.success:
                    break
                all_rules.extend(resp.data.get("rulebase", []))
                total = resp.data.get("total", 0)
                offset += 500
                if offset >= total:
                    break
            self._nat_cache = self._flatten_nat_rules(all_rules)
        except Exception:
            self._nat_cache = []
        return self._nat_cache

    def _check_global_prop_via_api(self, cid, desc, level, api_field, expected_val, remediation):
        """Generic helper for Global Properties checks via CP MGMT API.

        api_field must be a dotted path: "section.field-name"
        e.g. "stateful-inspection.drop-out-of-state-tcp-packets"
             "firewall.log-implied-rules"
             "nat.allow-bi-directional-nat"
             "hit-count.enable-hit-count"
        """
        if not self.mgmt:
            self._manual(cid, desc, level,
                         notes="CP Management API not connected. Verify manually in SmartConsole.",
                         remediation=remediation)
            return None
        try:
            props = self._get_global_properties()
            if not props:
                self._manual(cid, desc, level,
                             notes="Unable to retrieve Global Properties.",
                             remediation=remediation)
                return None
            section, _, field = api_field.partition('.')
            actual = props.get(section, {}).get(field)
            status = PASS if actual == expected_val else FAIL
            self._add(make_result(cid, desc, level, status,
                                   expected=expected_val, actual=actual,
                                   remediation=remediation))
        except Exception as e:
            self._manual(cid, desc, level,
                         notes=f"API error: {e}",
                         remediation=remediation)

    def check_3_4(self):
        cid, desc, level = "3.4", "Ensure Hit Count is enabled for the rules", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'hit-count.enable-hit-count', True,
                                         "In SmartConsole > Global Properties > Hit Count: enable 'Enable Hit Count'")
        if not self.mgmt:
            return
        # If API not available, stay as manual
        existing = next((r for r in self.results if r['control_id'] == cid), None)
        if existing and existing['status'] == MANUAL:
            pass  # already added

    def _check_any_in_field(self, cid, desc, level, field, rem):
        """Generic helper for 3.5/3.6/3.7: check no Accept rule has Any in field."""
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = self._get_rulebase()
            enabled_accept = [r for r in rules
                              if r.get("enabled", True) and self._is_accept(r.get("action", {}))]
            # Exclude the cleanup rule (last rule where all fields are Any)
            non_cleanup = [r for r in enabled_accept
                           if not (all(self._is_any(o) for o in r.get("source", []))
                                   and all(self._is_any(o) for o in r.get("destination", []))
                                   and all(self._is_any(o) for o in r.get("service", [])))]
            offenders = [r for r in non_cleanup
                         if all(self._is_any(o) for o in r.get(field, []))]
            if offenders:
                ids = [str(r.get("rule-number", "?")) for r in offenders]
                status, actual = FAIL, f"Rules with Any in {field}: {', '.join(ids)}"
            else:
                status, actual = PASS, f"No Accept rules with Any in {field} (excluding cleanup)"
            self._add(make_result(cid, desc, level, status,
                                   expected=f"No Accept rule with Any in {field}",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_3_5(self):
        self._check_any_in_field("3.5", "Ensure no Allow Rule with Any in Destination", "L2",
                                  "destination",
                                  "Replace 'Any' in destination with specific network objects.")

    def check_3_6(self):
        self._check_any_in_field("3.6", "Ensure no Allow Rule with Any in Source", "L2",
                                  "source",
                                  "Replace 'Any' in source with specific network objects.")

    def check_3_7(self):
        self._check_any_in_field("3.7", "Ensure no Allow Rule with Any in Services", "L2",
                                  "service",
                                  "Replace 'Any' in services with specific service objects.")

    def check_3_8(self):
        cid, desc, level = "3.8", "Logging should be enabled for all Firewall Rules", "L2"
        rem = "Set Track field to 'Log' for all rules in SmartConsole."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = [r for r in self._get_rulebase() if r.get("enabled", True)]
            unlogged = [r for r in rules if not self._is_logged(r.get("track", {}))]
            if unlogged:
                ids = [str(r.get("rule-number", "?")) for r in unlogged]
                status = FAIL
                actual = f"Rules without logging: {', '.join(ids)}"
            else:
                status, actual = PASS, "All enabled rules have logging enabled"
            self._add(make_result(cid, desc, level, status,
                                   expected="All rules tracked with Log",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_3_9(self):
        cid, desc, level = "3.9", "Review and Log Implied Rules", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'firewall.log-implied-rules', True,
                                         "In SmartConsole > Global Properties > Firewall: enable 'Log Implied Rules'")
        # Fallback
        if not self.mgmt:
            pass

    def check_3_10(self):
        cid, desc, level = "3.10", "Ensure Drop Out of State TCP Packets is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'stateful-inspection.drop-out-of-state-tcp-packets', True,
                                         "SmartConsole > Global Properties > Stateful Inspection: enable Drop Out of State TCP Packets")

    def check_3_11(self):
        cid, desc, level = "3.11", "Ensure Drop Out of State ICMP Packets is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'stateful-inspection.drop-out-of-state-icmp-packets', True,
                                         "SmartConsole > Global Properties > Stateful Inspection: enable Drop Out of State ICMP Packets")

    def check_3_12(self):
        cid, desc, level = "3.12", "Ensure Anti-Spoofing is enabled (Prevent) on all interfaces", "L2"
        rem = "SmartConsole > Gateway > Network Management > each interface > enable Anti-Spoofing (Prevent)."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            gw = self._get_gateway()
            if not gw:
                self._manual(cid, desc, level,
                             notes="Gateway object not found via API.", remediation=rem)
                return
            ifaces = gw.get("interfaces", [])
            failing = [i.get("name", "?") for i in ifaces
                       if not i.get("anti-spoofing", False)]
            if failing:
                status = FAIL
                actual = f"Anti-spoofing disabled on: {', '.join(failing)}"
            else:
                status = PASS
                actual = f"Anti-spoofing enabled on all {len(ifaces)} interface(s)"
            self._add(make_result(cid, desc, level, status,
                                   expected="Anti-spoofing enabled on all interfaces",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_3_13(self):
        cid, desc, level = "3.13", "Ensure Disk Space Alert is set", "L1"
        rem = "SmartConsole > Gateway > Logs > Local Storage: enable disk space alert."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            gw = self._get_gateway()
            if not gw:
                self._manual(cid, desc, level,
                             notes="Gateway object not found via API.", remediation=rem)
                return
            logs = gw.get("logs-settings", {})
            alert_on = logs.get("alert-when-free-disk-space-below", False)
            threshold = logs.get("alert-when-free-disk-space-below-threshold", 0)
            status = PASS if alert_on else FAIL
            actual = (f"Alert enabled, threshold={threshold} MB" if alert_on
                      else "Disk space alert is disabled")
            self._add(make_result(cid, desc, level, status,
                                   expected="alert-when-free-disk-space-below=true",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_3_14(self):
        cid, desc, level = "3.14", "Ensure Accept RIP is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'firewall.accept-rip', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept RIP'")

    def check_3_15(self):
        cid, desc, level = "3.15", "Ensure Accept Domain Name over TCP (Zone Transfer) is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'firewall.accept-domain-name-over-tcp', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept Domain Name over TCP'")

    def check_3_16(self):
        cid, desc, level = "3.16", "Ensure Accept Domain Name over UDP (Queries) is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'firewall.accept-domain-name-over-udp', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept Domain Name over UDP'")

    def check_3_17(self):
        cid, desc, level = "3.17", "Ensure Accept ICMP Requests is not enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'firewall.accept-icmp-requests', False,
                                         "SmartConsole > Gateway > Firewall: uncheck 'Accept ICMP Requests'")

    def check_3_18(self):
        cid, desc, level = "3.18", "Ensure Allow bi-directional NAT is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'nat.allow-bi-directional-nat', True,
                                         "SmartConsole > Gateway > NAT: check 'Allow bi-directional NAT'")

    def check_3_19(self):
        cid, desc, level = "3.19", "Ensure Automatic ARP Configuration NAT is enabled", "L2"
        self._check_global_prop_via_api(cid, desc, level,
                                         'nat.auto-arp-conf', True,
                                         "SmartConsole > Gateway > NAT: check 'Automatic ARP Configuration'")

    def check_3_20(self):
        cid, desc, level = "3.20", "Ensure Logging is enabled for Track Options of Global Properties", "L1"
        rem = "SmartConsole > Global Properties > Log and Alert: set all Track Options to Log."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            props = self._get_global_properties()
            if not props:
                self._manual(cid, desc, level,
                             notes="Unable to retrieve Global Properties.", remediation=rem)
                return
            la = props.get("log-and-alert", {})
            # Key track options that should not be "none"
            checks = {
                "ip-options-drop":              la.get("ip-options-drop", "none"),
                "vpn-successful-key-exchange":  la.get("vpn-successful-key-exchange", "none"),
                "vpn-packet-handling-error":    la.get("vpn-packet-handling-error", "none"),
                "administrative-notifications": la.get("administrative-notifications", "none"),
            }
            failing = [k for k, v in checks.items() if str(v).lower() == "none"]
            if failing:
                status = FAIL
                actual = f"Track set to 'none' for: {', '.join(failing)}"
            else:
                status = PASS
                actual = f"All key track options configured: {checks}"
            self._add(make_result(cid, desc, level, status,
                                   expected="All track options set to Log or Alert (not none)",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    # -----------------------------------------------------------------------
    # NAT Rulebase Quality  (NAT-1 through NAT-3)
    # -----------------------------------------------------------------------
    def run_nat_audit(self):
        """NAT rulebase checks — appended after CIS checks. Skipped if no mgmt client."""
        _checks = [
            ("NAT-1", "Ensure no NAT rules have zero hit count"),
            ("NAT-2", "Ensure no Any-Any NAT rules exist"),
        ]
        if not self.mgmt:
            for cid, desc in _checks:
                self._add(make_result(cid, desc, "L2", SKIPPED,
                                       notes="Management API not connected — NAT audit skipped."))
            return

        try:
            nat_rules = self._get_nat_rulebase()
        except Exception as e:
            for cid, desc in _checks:
                self._error(cid, desc, "L2", f"Failed to fetch NAT rulebase: {e}")
            return

        enabled = [r for r in nat_rules if r.get("enabled", True)]

        # NAT-1: Zero hit count
        zero_hit = [
            str(r.get("rule-number", "?")) for r in enabled
            if r.get("hits") and
               r["hits"].get("level", "none") == "none" and
               not r["hits"].get("last-date")
        ]
        if not nat_rules:
            nat1_status, nat1_actual = SKIPPED, "No NAT rules found in rulebase"
        elif zero_hit:
            nat1_status = FAIL
            nat1_actual = f"NAT rules with zero hits: {', '.join(zero_hit)}"
        else:
            nat1_status = PASS
            nat1_actual = f"All {len(enabled)} enabled NAT rules have been triggered"
        self._add(make_result("NAT-1", "Ensure no NAT rules have zero hit count", "L2", nat1_status,
                               expected="All enabled NAT rules triggered at least once",
                               actual=nat1_actual,
                               remediation="Review and disable NAT rules with zero hits — they may be obsolete."))

        # NAT-2: Any-Any (original-source=Any AND original-destination=Any)
        any_any = [
            str(r.get("rule-number", "?")) for r in enabled
            if self._is_any(r.get("original-source", {})) and
               self._is_any(r.get("original-destination", {}))
        ]
        if any_any:
            nat2_status = FAIL
            nat2_actual = f"Any-Any NAT rules: {', '.join(any_any)}"
        else:
            nat2_status, nat2_actual = PASS, "No Any-Any NAT rules found"
        self._add(make_result("NAT-2", "Ensure no Any-Any NAT rules exist", "L2", nat2_status,
                               expected="All NAT rules specify explicit source or destination",
                               actual=nat2_actual,
                               remediation="Restrict NAT rules to specific source/destination objects."))


    # -----------------------------------------------------------------------
    # Rulebase Quality  (RQ-1 through RQ-4)
    # -----------------------------------------------------------------------
    def run_rulebase_quality_audit(self):
        """Rulebase quality checks — appended after CIS checks."""
        self.check_rq_1()
        self.check_rq_2()
        self.check_rq_3()
        self.check_rq_4()

    def check_rq_1(self):
        cid, desc, level = "RQ-1", "Ensure no shadow rules exist in the rulebase", "L2"
        rem = "Remove or reorder rules shadowed by a prior Allow-All rule in SmartConsole."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = [r for r in self._get_rulebase() if r.get("enabled", True)]
            shadowed = []
            for i, rule in enumerate(rules):
                if not self._is_accept(rule.get("action", {})):
                    continue
                for prior in rules[:i]:
                    if not self._is_accept(prior.get("action", {})):
                        continue
                    if (all(self._is_any(o) for o in prior.get("source", []))
                            and all(self._is_any(o) for o in prior.get("destination", []))
                            and all(self._is_any(o) for o in prior.get("service", []))):
                        shadowed.append(str(rule.get("rule-number", "?")))
                        break
            if shadowed:
                status = FAIL
                actual = f"Rules shadowed by prior Allow-Any: {', '.join(shadowed)}"
            else:
                status, actual = PASS, "No shadow rules detected"
            self._add(make_result(cid, desc, level, status,
                                   expected="No Accept rules unreachable due to a prior Allow-All",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_rq_2(self):
        cid, desc, level = "RQ-2", "Ensure no enabled rules have zero hit count", "L2"
        rem = "Review and disable or remove rules with zero hits — they may be obsolete."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = [r for r in self._get_rulebase() if r.get("enabled", True)]
            zero_hit = []
            has_hit_data = False
            for rule in rules:
                hits = rule.get("hits", {})
                if not hits:
                    continue
                has_hit_data = True
                if hits.get("level", "none") == "none" and not hits.get("last-date"):
                    zero_hit.append(str(rule.get("rule-number", "?")))
            if not has_hit_data:
                self._add(make_result(cid, desc, level, SKIPPED,
                                       notes="Hit count data unavailable — enable Hit Count (check 3.4)."))
                return
            if zero_hit:
                status = FAIL
                actual = f"Rules with zero hits: {', '.join(zero_hit[:20])}"
                if len(zero_hit) > 20:
                    actual += f" (+{len(zero_hit) - 20} more)"
            else:
                status = PASS
                actual = "All rules with hit count data have been triggered at least once"
            self._add(make_result(cid, desc, level, status,
                                   expected="All enabled rules triggered at least once",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_rq_3(self):
        cid, desc, level = "RQ-3", "Ensure no Any/Any/Any Allow rules exist", "L2"
        rem = "Replace Any objects with specific network and service objects in SmartConsole."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = [r for r in self._get_rulebase() if r.get("enabled", True)]
            offenders = [
                str(r.get("rule-number", "?")) for r in rules
                if self._is_accept(r.get("action", {}))
                and all(self._is_any(o) for o in r.get("source", []))
                and all(self._is_any(o) for o in r.get("destination", []))
                and all(self._is_any(o) for o in r.get("service", []))
            ]
            if offenders:
                status = FAIL
                actual = f"Any/Any/Any Allow rules: {', '.join(offenders)}"
            else:
                status, actual = PASS, "No Any/Any/Any Allow rules found"
            self._add(make_result(cid, desc, level, status,
                                   expected="No Allow rules with Any in source, destination, and service",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_rq_4(self):
        cid, desc, level = "RQ-4", "Ensure threat intelligence feed objects are used in deny rules", "L2"
        rem = ("Add deny rules referencing Check Point ThreatCloud IOC feeds "
               "or custom threat intelligence objects.")
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            rules = [r for r in self._get_rulebase() if r.get("enabled", True)]
            ti_re = re.compile(
                r'threat|feed|ioc|indicator|blocklist|blacklist|intelligence', re.IGNORECASE)
            found = []
            for rule in rules:
                if not self._is_drop(rule.get("action", {})):
                    continue
                for field in ("source", "destination", "service"):
                    for obj in rule.get(field, []):
                        name = self._obj_name(obj)
                        if ti_re.search(name):
                            found.append(f"rule {rule.get('rule-number', '?')}: {name}")
                            break
            if found:
                status = PASS
                actual = f"Threat intel objects in deny rules: {'; '.join(found[:5])}"
            else:
                status = FAIL
                actual = "No deny rules reference threat intelligence feed objects"
            self._add(make_result(cid, desc, level, status,
                                   expected="At least one deny rule references a threat intelligence feed",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    # -----------------------------------------------------------------------
    # Certificate Inventory  (CERT-1)
    # -----------------------------------------------------------------------
    def check_cert_1(self):
        cid, desc, level = "CERT-1", "Ensure no gateway certificates expire within 90 days", "L2"
        rem = "Renew expiring certificates in SmartConsole > Gateway > VPN > Certificates."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            resp = self.mgmt.api_call("show-simple-gateways", {"details-level": "full"})
            if not resp.success:
                self._manual(cid, desc, level,
                             notes="Unable to retrieve gateway objects.", remediation=rem)
                return

            now = datetime.datetime.utcnow()
            expiring = []
            expired_list = []
            no_cert_data = True

            for gw in resp.data.get("objects", []):
                gw_name = gw.get("name", "unknown")
                cert_lists = [
                    gw.get("vpn-settings", {}).get("certificates", []),
                    gw.get("certificates", []),
                ]
                for certs in cert_lists:
                    for cert in (certs or []):
                        no_cert_data = False
                        raw = (cert.get("valid-to") or cert.get("expiry")
                               or cert.get("valid-until") or "")
                        if not raw:
                            continue
                        expiry_dt = None
                        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                            try:
                                expiry_dt = datetime.datetime.strptime(raw[:len(fmt)], fmt)
                                break
                            except ValueError:
                                continue
                        if expiry_dt is None:
                            continue
                        days_left = (expiry_dt - now).days
                        label = cert.get("name", gw_name)
                        if days_left < 0:
                            expired_list.append(f"{label} (expired {-days_left}d ago)")
                        elif days_left <= 90:
                            expiring.append(f"{label} (expires in {days_left}d)")

            if no_cert_data:
                self._manual(cid, desc, level,
                             notes="No certificate expiry data accessible via API. "
                                   "Verify manually in SmartConsole > Gateway > VPN > Certificates.",
                             remediation=rem)
                return

            all_issues = expired_list + expiring
            if all_issues:
                status = FAIL
                actual = "; ".join(all_issues[:10])
            else:
                status, actual = PASS, "No gateway certificates expiring within 90 days"
            self._add(make_result(cid, desc, level, status,
                                   expected="No certificates expiring within 90 days",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    # -----------------------------------------------------------------------
    # Log Retention & SIEM  (LOG-1, LOG-2)
    # -----------------------------------------------------------------------
    def check_log_1(self):
        cid, desc, level = "LOG-1", "Ensure syslog is configured to forward logs to a SIEM", "L1"
        rem = "add syslog-server host <SIEM-IP> port 514 proto udp"
        out = self._cmd("show configuration syslog")
        # Look for a remote server entry
        has_server = bool(
            re.search(r'set syslog.*log-remote-address\s+\d{1,3}', out, re.IGNORECASE)
            or re.search(r'add syslog-server\s+host', out, re.IGNORECASE)
        )
        if not has_server:
            out2 = self._cmd("show syslog all")
            has_server = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', out2))
            if has_server:
                out = out2
        status = PASS if has_server else FAIL
        self._add(make_result(cid, desc, level, status,
                               expected="At least one external syslog/SIEM server configured",
                               actual=out[:200] if out.strip() else "No syslog configuration found",
                               remediation=rem))

    def check_log_2(self):
        cid, desc, level = "LOG-2", "Ensure log servers are defined and retention policy is configured", "L1"
        rem = ("In SmartConsole, configure log retention under "
               "Logs & Monitor > Logs > Log Retention Policy.")
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            resp = self.mgmt.api_call("show-objects",
                                       {"type": "CpmiLogServer", "details-level": "standard",
                                        "limit": 10})
            if resp.success and resp.data.get("objects"):
                names = [s.get("name", "?") for s in resp.data["objects"]]
                status = PASS
                actual = f"Log servers: {', '.join(names)}"
            else:
                # Fall back: check global-properties for log cleanup policy
                props = self._get_global_properties()
                la = props.get("log-and-alert", {})
                cleanup = (la.get("log-cleanup-by-delete-re-percent")
                           or la.get("log-cleanup-by-delete-oldest-files"))
                if cleanup is not None:
                    status = PASS
                    actual = f"Log cleanup policy configured: {cleanup}"
                else:
                    status = FAIL
                    actual = "No log servers or retention policy found via Management API"
            self._add(make_result(cid, desc, level, status,
                                   expected="Log servers defined with retention policy",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    # -----------------------------------------------------------------------
    # Identity & Access Management  (IAM-1 through IAM-3)
    # -----------------------------------------------------------------------
    def run_iam_audit(self):
        """Admin account and privilege review — requires Management API."""
        self.check_iam_1()
        self.check_iam_2()
        self.check_iam_3()

    def _get_administrators(self):
        """Fetch all administrator objects from the Management API."""
        admins = []
        offset = 0
        while True:
            resp = self.mgmt.api_call("show-administrators",
                                      {"details-level": "full", "limit": 100, "offset": offset})
            if not resp.success:
                break
            admins.extend(resp.data.get("administrators", []))
            total = resp.data.get("total", 0)
            offset += 100
            if offset >= total:
                break
        return admins

    @staticmethod
    def _is_superuser_profile(profile):
        name = (profile.get("name", "") if isinstance(profile, dict) else str(profile)).lower()
        return any(kw in name for kw in ("super", "read write all", "full"))

    def _sc_stale_admins(self, threshold_days):
        """Return (stale_list, total) for SmartConsole admins with no modification in threshold_days."""
        admins = self._get_administrators()
        now = datetime.datetime.utcnow()
        stale = []
        for a in admins:
            lm = a.get("last-modified", {})
            iso = (lm.get("iso-8601", "") if isinstance(lm, dict) else str(lm or ""))
            if not iso:
                continue
            try:
                ts = datetime.datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")
                if (now - ts).days > threshold_days:
                    stale.append(f"{a.get('name', '?')} ({(now - ts).days}d)")
            except ValueError:
                pass
        return stale, len(admins)

    def _sc_auth_summary(self):
        """Return (local_list, external_list) of SmartConsole admins by authentication method."""
        admins = self._get_administrators()
        local, external = [], []
        for a in admins:
            name = a.get("name", "?")
            method = str(a.get("authentication-method", "")).lower()
            if any(x in method for x in ("radius", "tacacs", "securid", "certificate")):
                external.append(f"{name} ({method})")
            else:
                local.append(f"{name} ({method or 'check point password'})")
        return local, external

    def check_iam_1(self):
        cid, desc, level = "IAM-1", "Ensure superuser privileges are restricted to a minimal set of accounts", "L2"
        rem = "In SmartConsole, restrict full superuser profiles to ≤ 2 dedicated admin accounts."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            admins = self._get_administrators()
            superusers = [a.get("name", "?") for a in admins
                          if self._is_superuser_profile(a.get("permissions-profile", {}))]
            if len(superusers) > 2:
                status = FAIL
                actual = f"{len(superusers)} superuser accounts: {', '.join(superusers)}"
            else:
                status = PASS
                actual = (f"{len(superusers)} superuser account(s): {', '.join(superusers)}"
                          if superusers else f"No superuser accounts (total admins: {len(admins)})")
            self._add(make_result(cid, desc, level, status,
                                   expected="≤ 2 accounts with full superuser privileges",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_iam_2(self):
        cid, desc, level = "IAM-2", "Ensure no admin accounts have been unmodified for more than 90 days", "L2"
        rem = "Review, update, or disable admin accounts that have not been touched in >90 days in SmartConsole."
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            admins = self._get_administrators()
            now = datetime.datetime.utcnow()
            stale = []
            for a in admins:
                lm = a.get("last-modified", {})
                iso = (lm.get("iso-8601", "") if isinstance(lm, dict) else str(lm))
                if not iso:
                    continue
                try:
                    ts = datetime.datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")
                    if (now - ts).days > 90:
                        stale.append(f"{a.get('name','?')} ({(now-ts).days}d)")
                except ValueError:
                    pass
            if stale:
                status = FAIL
                actual = f"Admin accounts unmodified >90 days: {', '.join(stale)}"
            else:
                status = PASS
                actual = f"All {len(admins)} admin account(s) modified within the last 90 days"
            self._add(make_result(cid, desc, level, status,
                                   expected="All admin accounts modified within 90 days",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    def check_iam_3(self):
        cid, desc, level = "IAM-3", "Ensure all admin accounts use multi-factor authentication", "L2"
        rem = ("Configure RADIUS or SecurID as the authentication method for all admin accounts "
               "in SmartConsole > Manage & Settings > Administrators.")
        if not self.mgmt:
            self._manual(cid, desc, level, remediation=rem); return
        try:
            admins = self._get_administrators()
            single_factor = {"check-point-password", "os-password", "undefined"}
            no_mfa = [a.get("name", "?") for a in admins
                      if a.get("authentication-method", "undefined").lower() in single_factor]
            if no_mfa:
                status = FAIL
                actual = f"Admin accounts without MFA: {', '.join(no_mfa)}"
            else:
                status = PASS
                actual = f"All {len(admins)} admin account(s) use a multi-factor authentication method"
            self._add(make_result(cid, desc, level, status,
                                   expected="All admin accounts use RADIUS, SecurID, or TACACS+ (MFA-capable)",
                                   actual=actual, remediation=rem))
        except Exception as e:
            self._manual(cid, desc, level, notes=f"API error: {e}", remediation=rem)

    # -----------------------------------------------------------------------
    # Architecture  (ARCH-1)
    # -----------------------------------------------------------------------
    def check_arch_1(self):
        cid, desc, level = "ARCH-1", "Ensure management interface is on a dedicated subnet separate from production", "L2"
        rem = ("Configure a dedicated out-of-band management interface (Mgmt VLAN or physical port) "
               "that is not reachable from production security zones.")

        # SSH: look for a dedicated management interface
        mgmt_out = self._cmd("show management interface")
        ifaces_out = self._cmd("show interfaces all")
        has_dedicated = bool(
            re.search(r'\bMgmt\b', mgmt_out, re.IGNORECASE)
            or re.search(r'interface\s+Mgmt\b', ifaces_out, re.IGNORECASE)
        )
        ssh_status = PASS if has_dedicated else FAIL
        ssh_actual = ("Dedicated Mgmt interface detected" if has_dedicated
                      else "No dedicated Mgmt interface found — management may share a production interface")

        # API: cross-check for Accept rules with Any destination (could reach management IP)
        if self.mgmt:
            try:
                mgmt_ip = self.ssh.host
                rules = self._get_rulebase()
                risky = [str(r.get("rule-number", "?")) for r in rules
                         if r.get("enabled", True)
                         and self._is_accept(r.get("action", {}))
                         and all(self._is_any(o) for o in r.get("destination", []))]
                if risky and not has_dedicated:
                    status = FAIL
                    actual = (f"{ssh_actual}. Accept rules with Any-dest that could reach {mgmt_ip}: "
                              f"rules {', '.join(risky[:5])}")
                elif risky:
                    status = MANUAL
                    actual = (f"{ssh_actual}. Accept Any-dest rules that could reach {mgmt_ip}: "
                              f"rules {', '.join(risky[:5])} — verify mgmt subnet is excluded")
                else:
                    status = ssh_status
                    actual = ssh_actual
            except Exception:
                status, actual = ssh_status, ssh_actual
        else:
            status, actual = ssh_status, ssh_actual

        self._add(make_result(cid, desc, level, status,
                               expected="Dedicated management interface on isolated subnet",
                               actual=actual, remediation=rem))

    # -----------------------------------------------------------------------
    # Governance & Architecture Recommendations  (GOV-1 … GOV-4)
    # -----------------------------------------------------------------------
    def check_gov_1(self):
        """Cluster/HA detection — RECOMMENDATION if standalone."""
        cid, desc, level = "GOV-1", "Firewall Deployment Architecture: Standalone vs. Distributed/Cluster", "L2"
        rem = ("Deploy in a distributed architecture with a dedicated Management Server "
               "and ClusterXL or VRRP for high availability. A standalone deployment "
               "creates a single point of failure for both management and enforcement.")
        out = self._cmd("show cluster members")
        has_cluster = bool(
            re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', out)
            or re.search(r'\b(Active|Standby|Down)\b', out, re.IGNORECASE)
        )
        if has_cluster:
            self._add(make_result(cid, desc, level, PASS,
                                   expected="Cluster or distributed deployment",
                                   actual="Cluster membership detected",
                                   remediation=rem))
        else:
            self._recommend(cid, desc, level,
                             notes="No cluster members detected. Gateway appears to be operating "
                                   "in standalone mode, creating a single point of failure.",
                             remediation=rem)

    def check_gov_2(self):
        """Always-on RECOMMENDATION: failover testing plan."""
        self._recommend(
            "GOV-2",
            "Absence of Documented Failover Testing Plan",
            "L2",
            notes="A periodic failover test plan cannot be verified automatically. "
                  "This is a governance control requiring documentation review.",
            remediation=("Establish and document a periodic failover testing procedure "
                         "(at minimum bi-annually). Cover: failover initiation, traffic "
                         "continuity, failback, and post-failover validation. Record results "
                         "in the change log."),
        )

    def check_gov_3(self):
        """Break-glass admin model — RECOMMENDATION if no named accounts beyond 'admin'."""
        cid, desc, level = "GOV-3", "Shared 'admin' Account — Break-Glass Model Not Enforced", "L2"
        rem = ("Reserve the built-in 'admin' account for emergency break-glass access only. "
               "Create individual named administrator accounts for day-to-day operations. "
               "Store the 'admin' credentials in a PAM vault with dual-authorisation controls "
               "and full audit trail on every use.")
        if not self.mgmt:
            self._recommend(cid, desc, level,
                             notes="Management API not connected — could not enumerate admin accounts. "
                                   "Verify manually that individual named accounts exist alongside 'admin'.",
                             remediation=rem)
            return
        try:
            admins = self._get_administrators()
            names  = [a.get("name", "?") for a in admins]
            generic = {"admin", "cpconfig", "monitor"}
            named   = [n for n in names if n.lower() not in generic]
            if not named:
                names_str = ', '.join(names) if names else 'none returned by API'
                self._recommend(cid, desc, level,
                                 notes=f"Admin accounts found: {names_str}. "
                                       "No individually named accounts detected. "
                                       "The built-in 'admin' account should be reserved as break-glass only.",
                                 remediation=rem)
            else:
                self._add(make_result(cid, desc, level, PASS,
                                       expected="Named individual accounts alongside break-glass 'admin'",
                                       actual=f"Named accounts: {', '.join(named)}",
                                       remediation=rem))
        except Exception as e:
            self._recommend(cid, desc, level,
                             notes=f"Could not enumerate admin accounts: {e}. Verify manually.",
                             remediation=rem)

    def check_gov_4(self):
        """Always-on RECOMMENDATION: CAB / change management governance."""
        self._recommend(
            "GOV-4",
            "Change Management and Governance — CAB Process",
            "L2",
            notes="Change management governance cannot be verified automatically. "
                  "This requires documentation review: change logs, approval records, "
                  "and CAB meeting minutes.",
            remediation=("Implement a formal Change Advisory Board (CAB) process for all firewall rule changes. "
                         "(1) Submit a change request with business justification and defined scope. "
                         "(2) Conduct peer review and risk assessment before approval. "
                         "(3) Schedule a defined change window with stakeholder notification. "
                         "(4) Document a tested rollback plan before execution. "
                         "(5) Perform post-change verification and record the outcome. "
                         "Integrate with an ITSM tool (ServiceNow, Jira Service Management, etc.) for a full audit trail."),
        )

    # -----------------------------------------------------------------------
    # Run all checks
    # -----------------------------------------------------------------------
    def run_all(self, level_filter="all"):
        """Execute all checks, filtered by level."""
        checks = [
            self.check_1_1,  self.check_1_2,  self.check_1_3,
            self.check_1_4_history_checking, self.check_1_4_history_length,
            self.check_1_5,  self.check_1_6,  self.check_1_7,
            self.check_1_8,  self.check_1_9,  self.check_1_10,
            self.check_1_11, self.check_1_12, self.check_1_13,
            self.check_2_1_1, self.check_2_1_2, self.check_2_1_3,
            self.check_2_1_4, self.check_2_1_5, self.check_2_1_6,
            self.check_2_1_7, self.check_2_1_8, self.check_2_1_9,
            self.check_2_1_10,
            self.check_2_2_1, self.check_2_2_2, self.check_2_2_3, self.check_2_2_4,
            self.check_2_3_1, self.check_2_3_2,
            self.check_2_4_1, self.check_2_4_2, self.check_2_4_3,
            self.check_2_5_1, self.check_2_5_2,
            self.check_2_5_4, self.check_2_5_5,
            self.check_2_6_1, self.check_2_6_2,
            self.check_3_1,  self.check_3_2,  self.check_3_3,  self.check_3_4,
            self.check_3_5,  self.check_3_6,  self.check_3_7,  self.check_3_8,
            self.check_3_10, self.check_3_11, self.check_3_12,
            self.check_3_13, self.check_3_14, self.check_3_15, self.check_3_16,
            self.check_3_17, self.check_3_18, self.check_3_19,
        ]
        for fn in checks:
            try:
                fn()
            except Exception as e:
                cid = fn.__name__.replace('check_', '').replace('_', '.')
                self._error(cid, fn.__name__, "?", str(e))

        # Additive policy-quality checks (CP Management API; gracefully skipped if unavailable)
        self.run_nat_audit()
        self.run_rulebase_quality_audit()
        self.run_iam_audit()

        # Governance & architecture recommendations (always run)
        self.check_gov_1()
        self.check_gov_2()
        self.check_gov_3()
        self.check_gov_4()

        # Apply level filter — always preserve RECOMMENDATION findings regardless of level
        if level_filter == "1":
            self.results = [r for r in self.results
                            if r['level'] in ('L1', '?') or r['status'] == RECOMMENDATION]
        elif level_filter == "2":
            self.results = [r for r in self.results
                            if r['level'] == 'L2' or r['status'] == RECOMMENDATION]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
SECTION_TITLES = {
    "1":    "Password Policy",
    "2.1":  "Device Setup – General Settings",
    "2.2":  "Device Setup – SNMP",
    "2.3":  "Device Setup – NTP",
    "2.4":  "Device Setup – Backup",
    "2.5":  "Device Setup – Authentication Settings",
    "2.6":  "Device Setup – Logging",
    "3":    "Firewall Secure Settings",
    "NAT":  "NAT Rulebase Quality",
    "RQ":   "Rulebase Quality",
    "CERT": "Certificate Inventory",
    "LOG":  "Log Retention & SIEM",
    "IAM":  "Identity & Access Management",
    "ARCH": "Architecture & Segmentation",
    "GOV":  "Governance & Architecture Recommendations",
}

def get_section(cid):
    for key in ['2.1', '2.2', '2.3', '2.4', '2.5', '2.6']:
        if cid.startswith(key):
            return key
    for key in ('NAT', 'RQ', 'CERT', 'LOG', 'IAM', 'ARCH', 'GOV'):
        if cid.startswith(key):
            return key
    return cid.split('.')[0]


def print_report(results, target):
    counts = {PASS: 0, FAIL: 0, MANUAL: 0, SKIPPED: 0, ERROR: 0}
    for r in results:
        counts[r['status']] = counts.get(r['status'], 0) + 1

    print()
    print(colorize("=" * 70, CYAN))
    print(colorize(f"  FW AI Audit — Security Audit Report", BOLD))
    print(colorize(f"  Target : {target}", BOLD))
    print(colorize(f"  Time   : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", BOLD))
    print(colorize("=" * 70, CYAN))

    current_section = None
    for r in results:
        sec = get_section(r['control_id'])
        if sec != current_section:
            current_section = sec
            title = SECTION_TITLES.get(sec, f"Section {sec}")
            print()
            print(colorize(f"  ── {title} ──", BOLD))
        icon = STATUS_ICON.get(r['status'], r['status'])
        line = f"  [{r['control_id']:6s}] {icon}  {r['description']}"
        print(line)
        if r['status'] == FAIL:
            print(colorize(f"           Expected : {r['expected']}", DIM))
            print(colorize(f"           Actual   : {str(r['actual'])[:80]}", RED))
            if r['remediation']:
                print(colorize(f"           Fix      : {r['remediation']}", YELLOW))
        elif r['status'] == MANUAL:
            if r['notes']:
                print(colorize(f"           Note     : {r['notes'][:100]}", YELLOW))
        elif r['status'] == ERROR:
            print(colorize(f"           Error    : {r['notes'][:80]}", RED))

    print()
    print(colorize("=" * 70, CYAN))
    total = len(results)
    pct   = round(counts[PASS] / total * 100, 1) if total else 0
    print(colorize(f"  SUMMARY  Total:{total}  "
                   f"Pass:{counts[PASS]}  Fail:{counts[FAIL]}  "
                   f"Manual:{counts[MANUAL]}  Skipped:{counts[SKIPPED]}  "
                   f"Error:{counts[ERROR]}  "
                   f"Score:{pct}%", BOLD))
    print(colorize("=" * 70, CYAN))
    print()


def write_json_report(results, target, output_file):
    report = {
        "meta": {
            "benchmark": "FW AI Audit Security Assessment",
            "target":    target,
            "generated": datetime.datetime.utcnow().isoformat() + "Z",
            "tool":      "cis_gaia_audit_tool",
        },
        "summary": {
            PASS:    sum(1 for r in results if r['status'] == PASS),
            FAIL:    sum(1 for r in results if r['status'] == FAIL),
            MANUAL:  sum(1 for r in results if r['status'] == MANUAL),
            SKIPPED: sum(1 for r in results if r['status'] == SKIPPED),
            ERROR:   sum(1 for r in results if r['status'] == ERROR),
            "total": len(results),
        },
        "results": results,
    }
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(colorize(f"  JSON report saved → {os.path.abspath(output_file)}", CYAN))


# ---------------------------------------------------------------------------
# Argument parsing (mirrors policyCleanUp.py style)
# ---------------------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="FW AI Audit — Firewall Security Audit Engine",
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('--management', '-m', default='127.0.0.1', metavar="",
                        help='Management server IP address or hostname. Default: 127.0.0.1')
    parser.add_argument('--port', default=22, type=int, metavar="",
                        help='SSH port. Default: 22')
    parser.add_argument('--api-port', default=443, type=int, metavar="",
                        help='Management API HTTPS port. Default: 443')
    parser.add_argument('--user', '-u', dest='username', metavar="",
                        help='Gaia/Management administrator username.')
    parser.add_argument('--password', '-p', metavar="",
                        help='Administrator password.')
    parser.add_argument('--api-key', metavar="",
                        help='Management API key (used for API checks, not SSH).')
    parser.add_argument('--level', choices=['1', '2', 'all'], default='all', metavar="",
                        help='{1|2|all}  CIS level filter. Default: all')
    parser.add_argument('--output-file', '-o', default=None, metavar="",
                        help='Output JSON report file. Default: cis_audit_<timestamp>.json')
    parser.add_argument('--no-api', action='store_true',
                        help='Skip Management API checks (SSH only).')
    parser.add_argument('--domain', '-d', metavar="",
                        help='Management domain (for MDS environments).')

    args = parser.parse_args()

    # Prompt for username if missing
    if args.api_key is None:
        if args.username is None:
            try:
                args.username = input("Username: ")
            except EOFError:
                args.username = "admin"
        if args.password is None:
            if sys.stdin.isatty():
                args.password = getpass.getpass("Password: ")
            else:
                args.password = input("Password: ")

    if args.output_file is None:
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        args.output_file = f"cis_audit_{ts}.json"

    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_arguments()
    target = args.management

    print(colorize(f"\n[*] CIS Gaia R82 Audit Tool", BOLD))
    print(colorize(f"[*] Target  : {target}:{args.port}", CYAN))
    print(colorize(f"[*] Level   : {args.level}", CYAN))
    print()

    # ------------------------------------------------------------------
    # 1. SSH / Gaia Clish connection
    # ------------------------------------------------------------------
    if not HAS_PARAMIKO:
        print(colorize("[!] paramiko not installed. Run: pip install paramiko --break-system-packages", RED))
        sys.exit(1)

    print(colorize("[*] Connecting via SSH...", CYAN))
    ssh = GaiaClishSession(target, port=args.port)
    try:
        ssh.connect(username=args.username, password=args.password)
        print(colorize("[✓] SSH connected.", GREEN))
    except Exception as e:
        print(colorize(f"[✗] SSH connection failed: {e}", RED))
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Optional Management API connection
    # ------------------------------------------------------------------
    mgmt_client = None
    if not args.no_api and HAS_CPAPI:
        print(colorize("[*] Connecting to Management API...", CYAN))
        try:
            client_args = APIClientArgs(server=target, port=args.api_port,
                                        unsafe=True, unsafe_auto_accept=True)
            mgmt_client = APIClient(client_args)
            mgmt_client.check_fingerprint = lambda: True
            if args.api_key:
                login_res = mgmt_client.login_with_api_key(args.api_key,
                                                            domain=args.domain,
                                                            read_only=True)
            else:
                login_res = mgmt_client.login(args.username, args.password,
                                              domain=args.domain, read_only=True)
            if login_res.success:
                print(colorize("[✓] Management API connected.", GREEN))
            else:
                print(colorize(f"[!] API login failed: {login_res.error_message}. API checks will be skipped.", YELLOW))
                mgmt_client = None
        except Exception as e:
            print(colorize(f"[!] API connection error: {e}. API checks will be skipped.", YELLOW))
            mgmt_client = None
    elif args.no_api:
        print(colorize("[*] Management API skipped (--no-api).", DIM))
    elif not HAS_CPAPI:
        print(colorize("[*] cp-mgmt-api-sdk not installed. API checks will be MANUAL.", YELLOW))

    # ------------------------------------------------------------------
    # 3. Run audit
    # ------------------------------------------------------------------
    print(colorize("[*] Running audit checks...\n", CYAN))
    audit = CISAudit(ssh_session=ssh, mgmt_client=mgmt_client)
    audit.run_all(level_filter=args.level)

    ssh.close()
    if mgmt_client:
        try:
            mgmt_client.api_call("logout")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 4. Report
    # ------------------------------------------------------------------
    print_report(audit.results, target)
    write_json_report(audit.results, target, args.output_file)


if __name__ == "__main__":
    main()
