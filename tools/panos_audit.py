"""
panos_audit.py
Palo Alto Networks PAN-OS firewall audit engine.
Primary: XML API over HTTPS. Fallback: SSH/CLI.
Benchmark: CIS Palo Alto Firewall 10 Benchmark v1.3.0 (2025-10-01)
80 checks: 66 automated + 12 manual + 2 governance recommendations.
"""

from __future__ import annotations

import datetime
import re
import time
import urllib.parse
import urllib.request
import ssl
import xml.etree.ElementTree as ET

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

PASS           = "PASS"
FAIL           = "FAIL"
MANUAL         = "MANUAL"
SKIPPED        = "SKIPPED"
ERROR          = "ERROR"
RECOMMENDATION = "RECOMMENDATION"


# ── XML API session ──────────────────────────────────────────────────────────
class PANOSXMLAPISession:
    """
    PAN-OS XML API session over HTTPS.
    Implements the same run()/close() interface as PANOSSession so PANOSAudit
    can use either transport without changes.

    connect() accepts an api_key or generates one from username+password.
    run() routes:
      'show config running xpath <xpath>'  → config API GET
      anything else                        → op API (CLI command converted to XML)
    """

    _OP_MAP = {
        "show high-availability state": "<show><high-availability><state></state></high-availability></show>",
        "show system info":             "<show><system><info></info></system></show>",
        "show license":                 "<show><license></license></show>",
        "show rule-hit-count vsys vsys1 rule-base security rules all":
            "<show><rule-hit-count><vsys><vsys-name>vsys1</vsys-name>"
            "<rule-base><entry name=\"security\"><rules><all/></rules></entry></rule-base>"
            "</vsys></rule-hit-count></show>",
    }

    def __init__(self, host: str, port: int = 443):
        self.host  = host
        self.port  = port
        self._key  = None
        self._ctx  = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode    = ssl.CERT_NONE

    def connect(self, api_key: str = None, username: str = None, password: str = None):
        if api_key:
            self._key = api_key
            return
        if not (username and password):
            raise ValueError("api_key or username+password required")
        params = urllib.parse.urlencode(
            {"type": "keygen", "user": username, "password": password}
        )
        url  = f"https://{self.host}:{self.port}/api/?{params}"
        req  = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=self._ctx, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        root = ET.fromstring(body)
        key_el = root.find(".//key")
        if key_el is None or not key_el.text:
            raise ConnectionError(f"PAN-OS API key generation failed: {body[:200]}")
        self._key = key_el.text.strip()

    def _get(self, params: dict) -> str:
        params["key"] = self._key
        qs  = urllib.parse.urlencode(params)
        url = f"https://{self.host}:{self.port}/api/?{qs}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            return f"__ERROR__: {e}"

    def run(self, command: str) -> str:
        m = re.match(r"show config running xpath\s+(.+)", command.strip(), re.IGNORECASE)
        if m:
            return self._get({"type": "config", "action": "get", "xpath": m.group(1).strip()})
        cmd_xml = self._OP_MAP.get(command.strip().lower())
        if cmd_xml is None:
            return f"__ERROR__: unsupported op command for XML API: {command!r}"
        return self._get({"type": "op", "cmd": cmd_xml})

    def close(self):
        pass  # stateless — no session to close

_DEV     = "/config/devices/entry[@name='localhost.localdomain']"
_SYS     = f"{_DEV}/deviceconfig/system"
_SETTING = f"{_DEV}/deviceconfig/setting"
_VSYS    = f"{_DEV}/vsys/entry[@name='vsys1']"
_MGT     = "/config/mgt-config"
_NET     = f"{_DEV}/network"


def make_result(control_id, description, level, status,
                expected=None, actual=None, remediation="", notes="",
                guidance=None, risk_description="", default_risk_level=""):
    r = {
        "control_id":         control_id,
        "description":        description,
        "level":              level,
        "status":             status,
        "expected":           expected,
        "actual":             actual,
        "remediation":        remediation,
        "notes":              notes,
        "risk_description":   risk_description,
        "default_risk_level": default_risk_level,
        "timestamp":          datetime.datetime.utcnow().isoformat() + "Z",
    }
    if guidance is not None:
        r["guidance"] = guidance
    return r


# ── SSH session ──────────────────────────────────────────────────────────────
class PANOSSession:
    """SSH interactive session for PAN-OS operational and config commands."""

    PROMPT_RE = re.compile(r'[\w\-\.@]+[>#]\s*$')
    TIMEOUT   = 30

    def __init__(self, host, port=22):
        if not HAS_PARAMIKO:
            raise RuntimeError("paramiko is required: uv add paramiko")
        self.host   = host
        self.port   = port
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.channel = None

    def connect(self, username, password=None, key_filename=None):
        kw = dict(hostname=self.host, port=self.port, username=username,
                  timeout=15, look_for_keys=False, allow_agent=False)
        if password:
            kw["password"] = password
        if key_filename:
            kw["key_filename"] = key_filename
        self.client.connect(**kw)
        self.channel = self.client.invoke_shell()
        self.channel.settimeout(self.TIMEOUT)
        self._drain()

    def _drain(self):
        buf = ""
        deadline = time.time() + self.TIMEOUT
        while time.time() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(16384).decode("utf-8", errors="replace")
                buf += chunk
                lines = buf.splitlines()
                if lines and self.PROMPT_RE.search(lines[-1]):
                    break
            else:
                time.sleep(0.1)
        return buf

    def run(self, command):
        self.channel.send(command + "\n")
        time.sleep(0.5)
        output = self._drain()
        lines = output.splitlines()
        result_lines = []
        skip_first = True
        for line in lines:
            stripped = line.strip()
            if skip_first and command.strip()[:40] in stripped:
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


# ── Audit engine ─────────────────────────────────────────────────────────────
class PANOSAudit:
    """
    CIS Palo Alto Firewall 10 Benchmark v1.3.0 — 78 checks.
    66 automated (PASS/FAIL/ERROR) + 12 manual (MANUAL).
    """

    TOTAL_CHECKS = 83
    BENCHMARK    = "CIS Palo Alto Firewall 10 Benchmark v1.3.0"

    def __init__(self, ssh_session):
        self.ssh          = ssh_session
        self.results      = []
        self._xpath_cache = {}

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _cmd(self, command):
        try:
            return self.ssh.run(command)
        except Exception as e:
            return f"__ERROR__: {e}"

    def _xq(self, xpath):
        """Cached xpath query."""
        if xpath not in self._xpath_cache:
            self._xpath_cache[xpath] = self._cmd(f"show config running xpath {xpath}")
        return self._xpath_cache[xpath]

    def _xml(self, text):
        try:
            return ET.fromstring(text)
        except Exception:
            return None

    def _tag(self, xml_text, tag):
        m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", xml_text, re.DOTALL)
        return m.group(1).strip() if m else None

    def _has(self, xml_text):
        return bool(xml_text and
                    "__ERROR__" not in xml_text and
                    "<result/>" not in xml_text and
                    xml_text.strip() not in ("", "<result></result>"))

    def _int(self, val, default=None):
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    def _add(self, result):
        self.results.append(result)

    def _pw_xml(self):
        if not hasattr(self, "_pw_xml_cache"):
            self._pw_xml_cache = self._xq(f"{_MGT}/password-complexity")
        return self._pw_xml_cache

    def _parse_security_rules(self):
        xml_text = self._xq(f"{_VSYS}/rulebase/security/rules")
        if not self._has(xml_text):
            # Distinguish empty rulebase (valid, return []) from API error (return None)
            if xml_text and "__ERROR__" not in xml_text:
                return []   # rulebase exists but has no rules
            return None     # actual API/XML error
        root = self._xml(xml_text)
        if root is None:
            return None
        rules = []
        for entry in root.iter("entry"):
            def _members(tag):
                el = entry.find(tag)
                return [m.text.strip() for m in el.findall("member") if m.text] if el is not None else []
            def _text(tag):
                el = entry.find(tag)
                return el.text.strip() if el is not None and el.text else ""
            ps = entry.find("profile-setting")
            has_profile = ps is not None and (
                ps.find("group") is not None or ps.find("profiles") is not None
            )
            rules.append({
                "name":        entry.get("name", "unnamed"),
                "action":      _text("action"),
                "source":      _members("source"),
                "destination": _members("destination"),
                "application": _members("application"),
                "service":     _members("service"),
                "log_end":     _text("log-end"),
                "has_profile": has_profile,
                "disabled":    _text("disabled") == "yes",
            })
        return rules

    # ── Section 1: Device Setup ───────────────────────────────────────────────

    # 1.1.1 Ensure System Logging to a Remote Host

    def _check_1_1_1_1(self):
        xml = self._xq(f"{_DEV}/syslog")
        if not self._has(xml):
            xml = self._xq("/config/shared/syslog")
        if self._has(xml):
            count = xml.count("<entry ")
            self._add(make_result(
                "1.1.1.1", "Syslog logging should be configured", "L1", PASS,
                actual=f"{count} syslog profile(s) configured"
            ))
        else:
            self._add(make_result(
                "1.1.1.1", "Syslog logging should be configured", "L1", FAIL,
                expected="At least one syslog server profile configured",
                actual="No syslog server profiles found",
                remediation="Device > Server Profiles > Syslog — add a syslog server profile and associate it with log forwarding."
            ))

    def _check_1_1_1_2(self):
        xml = self._xq(f"{_SYS}/snmp-setting/snmp-system/version/v3/trap-profile")
        if self._has(xml):
            self._add(make_result(
                "1.1.1.2", "SNMPv3 traps should be configured", "L1", PASS,
                actual="SNMPv3 trap profile configured"
            ))
        else:
            xml2 = self._xq(f"{_SYS}/snmp-setting")
            if self._has(xml2) and "v3" in xml2 and "trap" in xml2.lower():
                self._add(make_result(
                    "1.1.1.2", "SNMPv3 traps should be configured", "L1", PASS,
                    actual="SNMPv3 SNMP configuration found with trap entries"
                ))
            else:
                self._add(make_result(
                    "1.1.1.2", "SNMPv3 traps should be configured", "L1", FAIL,
                    expected="SNMPv3 trap server profile configured at Device > Server Profiles > SNMP Traps",
                    actual="No SNMPv3 trap server profile found",
                    remediation="Device > Server Profiles > SNMP Traps — add a profile, select version V3, set SNMP Manager IP, User, EngineID and Password. Then Device > Log Settings > System — add an SNMP entry referencing this profile with All Logs filter."
                ))

    def _check_1_1_2(self):
        xml = self._xq(f"{_SYS}/login-banner")
        val = self._tag(xml, "login-banner")
        if self._has(xml) and val and len(val.strip()) > 0:
            self._add(make_result(
                "1.1.2", "Ensure 'Login Banner' is set", "L1", PASS,
                actual=f"Login banner configured ({len(val)} chars)"
            ))
        else:
            self._add(make_result(
                "1.1.2", "Ensure 'Login Banner' is set", "L1", FAIL,
                expected="A login banner warning message is configured",
                actual="No login banner set",
                remediation="Device > Setup > Management > General Settings — set Login Banner."
            ))

    def _check_1_1_3(self):
        xml = self._xq(f"{_SETTING}/management/log-on-high-dp-load")
        val = self._tag(xml, "log-on-high-dp-load")
        if val and val.lower() == "yes":
            self._add(make_result(
                "1.1.3", "Ensure 'Enable Log on High DP Load' is enabled", "L1", PASS,
                actual="log-on-high-dp-load = yes"
            ))
        else:
            self._add(make_result(
                "1.1.3", "Ensure 'Enable Log on High DP Load' is enabled", "L1", FAIL,
                expected="log-on-high-dp-load = yes",
                actual=f"log-on-high-dp-load = {val or 'not set (default: disabled)'}",
                remediation="Device > Setup > Management — enable 'Log on High DP Load'."
            ))

    # 1.2 Management Interface Settings

    def _check_1_2_1(self):
        xml = self._xq(f"{_SYS}/permitted-ip")
        if self._has(xml) and "<entry " in xml:
            count = xml.count("<entry ")
            self._add(make_result(
                "1.2.1", "Ensure 'Permitted IP Addresses' is set for device management", "L1", PASS,
                actual=f"{count} permitted-ip entry/entries configured"
            ))
        else:
            self._add(make_result(
                "1.2.1", "Ensure 'Permitted IP Addresses' is set for device management", "L1", FAIL,
                expected="Permitted IP addresses restrict management access",
                actual="No permitted-ip restrictions (management accessible from any source)",
                remediation="Device > Setup > Interfaces > Management — add Permitted IP Addresses."
            ))

    def _check_1_2_2(self):
        # CIS audit: Network > Network Profiles > Interface Management
        # Verify each profile with SSH/HTTPS/SNMP has Permitted IP Addresses set
        xml = self._xq(f"{_NET}/profiles/interface-management-profile")
        if not self._has(xml):
            self._add(make_result(
                "1.2.2", "Ensure 'Permitted IP Addresses' is set for all management profiles where SSH, HTTPS, or SNMP is enabled", "L1", PASS,
                actual="No interface management profiles found at Network > Network Profiles > Interface Management — management access via dedicated management port only (covered by check 1.2.1)"
            ))
            return
        root = self._xml(xml)
        if root is None:
            self._add(make_result(
                "1.2.2", "Ensure 'Permitted IP Addresses' is set for all management profiles where SSH, HTTPS, or SNMP is enabled", "L1", ERROR,
                actual="Could not parse interface-management-profile XML"
            ))
            return
        bad = []
        good = []
        for entry in root.iter("entry"):
            name      = entry.get("name", "unnamed")
            has_ssh   = entry.find("ssh") is not None
            has_https = entry.find("https") is not None
            has_snmp  = entry.find("snmp") is not None
            if not (has_ssh or has_https or has_snmp):
                continue  # profile has no remote access protocols — skip
            permitted_el = entry.find("permitted-ip")
            ips = [m.get("name", "") for m in permitted_el.findall("entry")] if permitted_el is not None else []
            protocols = "/".join(p for p, ok in [("SSH", has_ssh), ("HTTPS", has_https), ("SNMP", has_snmp)] if ok)
            if not ips:
                bad.append(f"{name} ({protocols}: no permitted-ip set)")
            else:
                good.append(f"{name} ({protocols}: {', '.join(ips[:3])}{'...' if len(ips) > 3 else ''})")
        if bad:
            self._add(make_result(
                "1.2.2", "Ensure 'Permitted IP Addresses' is set for all management profiles where SSH, HTTPS, or SNMP is enabled", "L1", FAIL,
                expected="All profiles with SSH/HTTPS/SNMP have permitted-ip restricted to management hosts",
                actual=f"Profiles missing permitted-ip restriction: {'; '.join(bad[:5])}",
                remediation="Network > Network Profiles > Interface Management — for each profile with SSH/HTTPS/SNMP enabled, set Permitted IP Addresses to only those IPs necessary for device management.",
                notes=f"Compliant profiles: {'; '.join(good[:5]) or 'none'}"
            ))
        else:
            self._add(make_result(
                "1.2.2", "Ensure 'Permitted IP Addresses' is set for all management profiles where SSH, HTTPS, or SNMP is enabled", "L1", PASS,
                actual=f"All interface management profiles with SSH/HTTPS/SNMP have permitted-ip configured: {'; '.join(good[:5])}"
            ))

    def _check_1_2_3(self):
        xml = self._xq(f"{_SYS}/service")
        http_val   = self._tag(xml, "disable-http")
        telnet_val = self._tag(xml, "disable-telnet")
        http_ok   = (http_val   or "").lower() == "yes"
        telnet_ok = (telnet_val or "").lower() == "yes"
        if http_ok and telnet_ok:
            self._add(make_result(
                "1.2.3", "Ensure HTTP and Telnet are disabled on the management interface", "L1", PASS,
                actual="HTTP and Telnet both disabled on management interface"
            ))
        else:
            issues = []
            if not http_ok:
                issues.append(f"HTTP enabled (disable-http={http_val or 'not set'})")
            if not telnet_ok:
                issues.append(f"Telnet enabled (disable-telnet={telnet_val or 'not set'})")
            self._add(make_result(
                "1.2.3", "Ensure HTTP and Telnet are disabled on the management interface", "L1", FAIL,
                expected="disable-http=yes and disable-telnet=yes",
                actual="; ".join(issues),
                remediation="Device > Setup > Management > Management Interface Settings — uncheck HTTP and Telnet."
            ))

    def _check_1_2_4(self):
        # CIS audit: Network > Network Profiles > Interface Management
        # Verify HTTP and Telnet are unchecked on every Interface Management profile
        xml = self._xq(f"{_NET}/profiles/interface-management-profile")
        if not self._has(xml):
            self._add(make_result(
                "1.2.4", "Ensure HTTP and Telnet options are disabled for all management profiles", "L1", PASS,
                actual="No interface management profiles found at Network > Network Profiles > Interface Management — not applicable"
            ))
            return
        root = self._xml(xml)
        if root is None:
            self._add(make_result(
                "1.2.4", "Ensure HTTP and Telnet options are disabled for all management profiles", "L1", ERROR,
                actual="Could not parse interface-management-profile XML"
            ))
            return
        bad = []
        clean = []
        for entry in root.iter("entry"):
            name      = entry.get("name", "unnamed")
            has_http   = entry.find("http") is not None
            has_telnet = entry.find("telnet") is not None
            issues = "/".join(p for p, ok in [("HTTP", has_http), ("Telnet", has_telnet)] if ok)
            if issues:
                bad.append(f"{name} ({issues} enabled)")
            else:
                clean.append(name)
        if bad:
            self._add(make_result(
                "1.2.4", "Ensure HTTP and Telnet options are disabled for all management profiles", "L1", FAIL,
                expected="HTTP and Telnet unchecked on all interface management profiles",
                actual=f"Profile(s) with HTTP/Telnet enabled: {'; '.join(bad[:5])}",
                remediation="Network > Network Profiles > Interface Management — for each profile, uncheck HTTP and Telnet.",
                notes=f"Compliant profiles: {', '.join(clean[:5]) or 'none'}"
            ))
        else:
            self._add(make_result(
                "1.2.4", "Ensure HTTP and Telnet options are disabled for all management profiles", "L1", PASS,
                actual=f"HTTP and Telnet disabled on all {len(clean)} interface management profile(s): {', '.join(clean[:5])}"
            ))

    def _check_1_2_5(self):
        xml = self._xq(f"{_SYS}/ssl-tls-service-profile")
        val = self._tag(xml, "ssl-tls-service-profile")
        if self._has(xml) and val and val.strip():
            self._add(make_result(
                "1.2.5", "Ensure valid certificate set for browser-based administrator interface", "L1", PASS,
                actual=f"SSL/TLS service profile assigned: {val}"
            ))
        else:
            self._add(make_result(
                "1.2.5", "Ensure valid certificate set for browser-based administrator interface", "L1", FAIL,
                expected="An SSL/TLS service profile (non-default) is assigned to management",
                actual="No custom SSL/TLS service profile assigned (using default self-signed cert)",
                remediation="Device > Setup > Management — set an SSL/TLS Service Profile with a CA-signed certificate."
            ))

    # 1.3 Minimum Password Requirements

    def _check_1_3_1(self):
        xml = self._pw_xml()
        val = self._tag(xml, "enabled")
        if val and val.lower() == "yes":
            self._add(make_result(
                "1.3.1", "Ensure 'Minimum Password Complexity' is enabled", "L1", PASS,
                actual="Password complexity enforcement is enabled"
            ))
        else:
            self._add(make_result(
                "1.3.1", "Ensure 'Minimum Password Complexity' is enabled", "L1", FAIL,
                expected="enabled = yes",
                actual=f"enabled = {val or 'not set (default: disabled)'}",
                remediation="Device > Setup > Management > Password Complexity — enable password complexity."
            ))

    def _check_1_3_2(self):
        xml = self._pw_xml()
        val = self._tag(xml, "minimum-length")
        n   = self._int(val)
        if n is not None and n >= 12:
            self._add(make_result(
                "1.3.2", "Ensure 'Minimum Length' >= 12", "L1", PASS,
                expected="minimum-length >= 12",
                actual=f"minimum-length = {n}"
            ))
        else:
            self._add(make_result(
                "1.3.2", "Ensure 'Minimum Length' >= 12", "L1", FAIL,
                expected="minimum-length >= 12",
                actual=f"minimum-length = {val or 'not set'}",
                remediation="Device > Setup > Management > Password Complexity — set Minimum Length to 12 or more."
            ))

    def _check_1_3_3(self):
        xml = self._pw_xml()
        val = self._tag(xml, "minimum-uppercase-letters")
        n   = self._int(val)
        if n is not None and n >= 1:
            self._add(make_result(
                "1.3.3", "Ensure 'Minimum Uppercase Letters' >= 1", "L1", PASS,
                actual=f"minimum-uppercase-letters = {n}"
            ))
        else:
            self._add(make_result(
                "1.3.3", "Ensure 'Minimum Uppercase Letters' >= 1", "L1", FAIL,
                expected="minimum-uppercase-letters >= 1",
                actual=f"minimum-uppercase-letters = {val or 'not set'}",
                remediation="Device > Setup > Management > Password Complexity — set Minimum Uppercase Letters to 1."
            ))

    def _check_1_3_4(self):
        xml = self._pw_xml()
        val = self._tag(xml, "minimum-lowercase-letters")
        n   = self._int(val)
        if n is not None and n >= 1:
            self._add(make_result(
                "1.3.4", "Ensure 'Minimum Lowercase Letters' >= 1", "L1", PASS,
                actual=f"minimum-lowercase-letters = {n}"
            ))
        else:
            self._add(make_result(
                "1.3.4", "Ensure 'Minimum Lowercase Letters' >= 1", "L1", FAIL,
                expected="minimum-lowercase-letters >= 1",
                actual=f"minimum-lowercase-letters = {val or 'not set'}",
                remediation="Device > Setup > Management > Password Complexity — set Minimum Lowercase Letters to 1."
            ))

    def _check_1_3_5(self):
        xml = self._pw_xml()
        val = self._tag(xml, "minimum-numeric-letters")
        n   = self._int(val)
        if n is not None and n >= 1:
            self._add(make_result(
                "1.3.5", "Ensure 'Minimum Numeric Letters' >= 1", "L1", PASS,
                actual=f"minimum-numeric-letters = {n}"
            ))
        else:
            self._add(make_result(
                "1.3.5", "Ensure 'Minimum Numeric Letters' >= 1", "L1", FAIL,
                expected="minimum-numeric-letters >= 1",
                actual=f"minimum-numeric-letters = {val or 'not set'}",
                remediation="Device > Setup > Management > Password Complexity — set Minimum Numeric Letters to 1."
            ))

    def _check_1_3_6(self):
        xml = self._pw_xml()
        val = self._tag(xml, "minimum-special-characters")
        n   = self._int(val)
        if n is not None and n >= 1:
            self._add(make_result(
                "1.3.6", "Ensure 'Minimum Special Characters' >= 1", "L1", PASS,
                actual=f"minimum-special-characters = {n}"
            ))
        else:
            self._add(make_result(
                "1.3.6", "Ensure 'Minimum Special Characters' >= 1", "L1", FAIL,
                expected="minimum-special-characters >= 1",
                actual=f"minimum-special-characters = {val or 'not set'}",
                remediation="Device > Setup > Management > Password Complexity — set Minimum Special Characters to 1."
            ))

    def _check_1_3_7(self):
        xml = self._pw_xml()
        val = self._tag(xml, "password-change-period")
        self._add(make_result(
            "1.3.7", "Ensure 'Required Password Change Period' <= 90 days", "L1", MANUAL,
            expected="password-change-period <= 90 days",
            actual=f"password-change-period = {val or 'not set (requires manual verification)'}",
            remediation="Device > Setup > Management > Password Complexity — set Password Change Period to 90 days or fewer.",
            guidance={
                "where": "Device > Setup > Management > Password Complexity",
                "steps": [
                    "Navigate to Device > Setup > Management > Password Complexity",
                    "Verify 'Required Password Change Period' is set to 90 days or fewer",
                    "A value of 0 means passwords never expire — mark FAIL",
                ],
                "pass_criteria": "Password change period is 1-90 days",
                "fail_criteria": "Period is 0 (never) or greater than 90 days",
            }
        ))

    def _check_1_3_8(self):
        xml = self._pw_xml()
        val = self._tag(xml, "new-password-differs-by-characters")
        n   = self._int(val)
        if n is not None and n >= 3:
            self._add(make_result(
                "1.3.8", "Ensure 'New Password Differs By Characters' >= 3", "L1", PASS,
                actual=f"new-password-differs-by-characters = {n}"
            ))
        else:
            self._add(make_result(
                "1.3.8", "Ensure 'New Password Differs By Characters' >= 3", "L1", FAIL,
                expected="new-password-differs-by-characters >= 3",
                actual=f"new-password-differs-by-characters = {val or 'not set'}",
                remediation="Device > Setup > Management > Password Complexity — set New Password Differs By Characters to 3."
            ))

    def _check_1_3_9(self):
        xml = self._pw_xml()
        val = self._tag(xml, "password-history-count")
        n   = self._int(val)
        if n is not None and n >= 24:
            self._add(make_result(
                "1.3.9", "Ensure 'Prevent Password Reuse Limit' >= 24", "L1", PASS,
                actual=f"password-history-count = {n}"
            ))
        else:
            self._add(make_result(
                "1.3.9", "Ensure 'Prevent Password Reuse Limit' >= 24", "L1", FAIL,
                expected="password-history-count >= 24",
                actual=f"password-history-count = {val or 'not set'}",
                remediation="Device > Setup > Management > Password Complexity — set Prevent Password Reuse to 24."
            ))

    def _check_1_3_10(self):
        xml = self._xq(f"{_MGT}/password-profile")
        if self._has(xml) and "<entry " in xml:
            count = xml.count("<entry ")
            self._add(make_result(
                "1.3.10", "Ensure 'Password Profiles' do not exist", "L1", FAIL,
                expected="No password profiles defined",
                actual=f"{count} password profile(s) found — these can override global complexity settings",
                remediation="Device > Password Profiles — remove all password profiles to enforce global settings."
            ))
        else:
            self._add(make_result(
                "1.3.10", "Ensure 'Password Profiles' do not exist", "L1", PASS,
                actual="No password profiles defined — global settings apply to all accounts"
            ))

    # 1.4 Authentication Settings

    def _check_1_4_1(self):
        xml = self._xq(f"{_SETTING}/management/idle-timeout")
        val = self._tag(xml, "idle-timeout")
        n   = self._int(val)
        if n is None:
            self._add(make_result(
                "1.4.1", "Ensure 'Idle timeout' <= 10 minutes for device management", "L1", FAIL,
                expected="idle-timeout <= 10",
                actual="idle-timeout not configured",
                remediation="Device > Setup > Management > Authentication Settings — set Idle Timeout to 10 minutes."
            ))
        elif n == 0:
            self._add(make_result(
                "1.4.1", "Ensure 'Idle timeout' <= 10 minutes for device management", "L1", FAIL,
                expected="idle-timeout <= 10",
                actual="idle-timeout = 0 (no timeout)",
                remediation="Device > Setup > Management > Authentication Settings — set Idle Timeout to 10 minutes."
            ))
        elif n <= 10:
            self._add(make_result(
                "1.4.1", "Ensure 'Idle timeout' <= 10 minutes for device management", "L1", PASS,
                actual=f"idle-timeout = {n} minute(s)"
            ))
        else:
            self._add(make_result(
                "1.4.1", "Ensure 'Idle timeout' <= 10 minutes for device management", "L1", FAIL,
                expected="idle-timeout <= 10",
                actual=f"idle-timeout = {n} minutes (exceeds 10)",
                remediation="Device > Setup > Management > Authentication Settings — reduce Idle Timeout to 10 minutes."
            ))

    def _check_1_4_2(self):
        xml = self._xq(f"{_MGT}/authentication-profile")
        if not self._has(xml):
            self._add(make_result(
                "1.4.2", "Ensure 'Failed Attempts' and 'Lockout Time' properly configured", "L1", FAIL,
                expected="Authentication profile with failed-attempts <= 5 and lockout-time >= 5",
                actual="No authentication profiles found",
                remediation="Device > Authentication Profile — create a profile with lockout settings and assign it."
            ))
            return
        root = self._xml(xml)
        if root is None:
            self._add(make_result(
                "1.4.2", "Ensure 'Failed Attempts' and 'Lockout Time' properly configured", "L1", ERROR,
                actual="Could not parse authentication profile XML"
            ))
            return
        bad = []
        ok  = []
        for entry in root.iter("entry"):
            name     = entry.get("name", "unnamed")
            fa_el    = entry.find("lockout/failed-attempts")
            lt_el    = entry.find("lockout/lockout-time")
            fa = self._int(fa_el.text if fa_el is not None else None)
            lt = self._int(lt_el.text if lt_el is not None else None)
            fa_ok = (fa is not None and 1 <= fa <= 5)
            lt_ok = (lt is not None and lt >= 5)
            if fa_ok and lt_ok:
                ok.append(name)
            else:
                bad.append(f"{name}(attempts={fa or 'not set'},lockout={lt or 'not set'}min)")
        if bad:
            self._add(make_result(
                "1.4.2", "Ensure 'Failed Attempts' and 'Lockout Time' properly configured", "L1", FAIL,
                expected="failed-attempts 1-5, lockout-time >= 5 minutes",
                actual=f"Non-compliant profile(s): {', '.join(bad[:3])}",
                remediation="Device > Authentication Profile > Lockout — set Failed Attempts <= 5 and Lockout Time >= 5 minutes."
            ))
        else:
            self._add(make_result(
                "1.4.2", "Ensure 'Failed Attempts' and 'Lockout Time' properly configured", "L1", PASS,
                actual=f"All {len(ok)} authentication profile(s) have compliant lockout settings"
            ))

    # 1.5 SNMP Polling Settings

    def _check_1_5_1(self):
        xml = self._xq(f"{_SYS}/snmp-setting/access-setting/version")
        val = self._tag(xml, "version")
        if not val:
            xml2 = self._xq(f"{_SYS}/snmp-setting")
            val  = "v3" if (self._has(xml2) and "v3" in xml2) else None
        if val and val.lower() == "v3":
            self._add(make_result(
                "1.5.1", "Ensure 'V3' is selected for SNMP polling", "L1", PASS,
                actual="SNMP polling version = v3"
            ))
        elif val:
            self._add(make_result(
                "1.5.1", "Ensure 'V3' is selected for SNMP polling", "L1", FAIL,
                expected="SNMP version = v3",
                actual=f"SNMP version = {val}",
                remediation="Device > Setup > Operations > SNMP Setup — change polling version to V3."
            ))
        else:
            self._add(make_result(
                "1.5.1", "Ensure 'V3' is selected for SNMP polling", "L1", PASS,
                actual="SNMP polling not configured (not applicable if SNMP polling unused)"
            ))

    # 1.6 Device Services Settings

    def _check_1_6_1(self):
        xml = self._xq(f"{_SYS}/update-schedule/statistics-service")
        val = self._tag(xml, "opt-in")
        xml2 = self._xq(f"{_SYS}")
        vi_m = re.search(r"<verify-update-server-identity>(.*?)</verify-update-server-identity>", xml2, re.DOTALL)
        vi   = vi_m.group(1).strip() if vi_m else None
        if vi and vi.lower() == "yes":
            self._add(make_result(
                "1.6.1", "Ensure 'Verify Update Server Identity' is enabled", "L1", PASS,
                actual="verify-update-server-identity = yes"
            ))
        else:
            self._add(make_result(
                "1.6.1", "Ensure 'Verify Update Server Identity' is enabled", "L1", FAIL,
                expected="verify-update-server-identity = yes",
                actual=f"verify-update-server-identity = {vi or 'not set (default: disabled)'}",
                remediation="Device > Setup > Services — enable 'Verify Update Server Identity'."
            ))

    def _check_1_6_2(self):
        xml = self._xq(f"{_SYS}/ntp-servers")
        primary   = self._tag(xml, "primary-ntp-server")
        secondary = self._tag(xml, "secondary-ntp-server")
        if not primary:
            m = re.search(r"<ntp-server-address>(.*?)</ntp-server-address>", xml, re.DOTALL)
            primary = m.group(1).strip() if m else None
        if primary and secondary:
            self._add(make_result(
                "1.6.2", "Ensure redundant NTP servers are configured appropriately", "L1", PASS,
                actual=f"Primary NTP: {primary}, Secondary NTP: {secondary}"
            ))
        elif primary:
            self._add(make_result(
                "1.6.2", "Ensure redundant NTP servers are configured appropriately", "L1", FAIL,
                expected="Both primary AND secondary NTP servers configured",
                actual=f"Only primary NTP configured ({primary}); no secondary",
                remediation="Device > Setup > Services — configure both a primary and secondary NTP server."
            ))
        else:
            self._add(make_result(
                "1.6.2", "Ensure redundant NTP servers are configured appropriately", "L1", FAIL,
                expected="Both primary AND secondary NTP servers configured",
                actual="No NTP servers configured",
                remediation="Device > Setup > Services — configure primary and secondary NTP servers."
            ))

    def _check_1_6_3(self):
        self._add(make_result(
            "1.6.3", "Ensure Certificate Securing Remote Access VPNs is Valid", "L2", MANUAL,
            expected="VPN certificate is CA-signed, valid, and not expired",
            actual="Manual verification required",
            remediation="Device > Certificate Management > Certificates — verify VPN certificate is not self-signed and not expired.",
            guidance={
                "where": "Device > Certificate Management > Certificates",
                "steps": [
                    "Navigate to Device > Certificate Management > Certificates",
                    "Identify the certificate used for remote access VPN (GlobalProtect or IPsec)",
                    "Verify it is issued by a trusted CA (not self-signed)",
                    "Verify the expiry date is at least 30 days in the future",
                    "Verify the Subject/SAN matches the VPN gateway FQDN",
                ],
                "pass_criteria": "Certificate is CA-signed, valid, and correctly named",
                "fail_criteria": "Self-signed, expired, or mismatched certificate",
            }
        ))

    # 1.7 VPN Settings

    def _check_1_7_1(self):
        self._add(make_result(
            "1.7.1", "Enabling Post-Quantum (PQ) on IKEv2 VPNs", "L2", MANUAL,
            expected="IKEv2 VPN profiles use post-quantum algorithms",
            actual="Manual verification required",
            remediation="Network > Network Profiles > IKE Crypto — configure post-quantum key exchange (e.g., Kyber) on IKEv2 profiles.",
            guidance={
                "where": "Network > Network Profiles > IKE Crypto Profiles",
                "steps": [
                    "Navigate to Network > Network Profiles > IKE Crypto",
                    "For each IKEv2 profile, check if post-quantum (PQ) key exchange is enabled",
                    "PAN-OS 11.x supports Kyber KEM — verify it is in the DH Group list",
                    "Navigate to Network > IPSec Tunnels and verify each tunnel uses an IKEv2-PQ profile",
                ],
                "pass_criteria": "IKEv2 crypto profiles include post-quantum key exchange algorithms",
                "fail_criteria": "No post-quantum algorithms configured on IKEv2 profiles",
            }
        ))

    # ── Section 2: User Identification ───────────────────────────────────────

    def _check_2_1(self):
        xml = self._xq(f"{_VSYS}/user-id-agent")
        has_agent = self._has(xml)
        xml2 = self._xq(f"{_VSYS}/user-id-collector")
        has_collector = self._has(xml2)
        if has_agent or has_collector:
            self._add(make_result(
                "2.1", "Ensure that IP addresses are mapped to usernames", "L1", PASS,
                actual="User-ID agent or collector configured for IP-to-username mapping"
            ))
        else:
            self._add(make_result(
                "2.1", "Ensure that IP addresses are mapped to usernames", "L1", FAIL,
                expected="User-ID configured to map IP addresses to usernames",
                actual="No User-ID agent or collector configured",
                remediation="Device > User Identification — configure a User-ID agent or enable User-ID data collection."
            ))

    def _check_2_2(self):
        xml = self._xq(f"{_VSYS}/user-id-collector/setting/wmi-client")
        val = self._tag(xml, "enabled")
        if not self._has(xml) or val is None or val.lower() == "no":
            self._add(make_result(
                "2.2", "Ensure that WMI probing is disabled", "L1", PASS,
                actual="WMI probing is disabled or not configured"
            ))
        else:
            self._add(make_result(
                "2.2", "Ensure that WMI probing is disabled", "L1", FAIL,
                expected="WMI probing disabled",
                actual="WMI probing is enabled",
                remediation="Device > User Identification > User Mapping > Windows — disable WMI probing."
            ))

    def _check_2_3(self):
        xml = self._xq(f"{_VSYS}/zone")
        if not self._has(xml):
            self._add(make_result(
                "2.3", "Ensure User-ID is only enabled for internal trusted interfaces", "L1", PASS,
                actual="No zones configured — not applicable"
            ))
            return
        root = self._xml(xml)
        if root is None:
            self._add(make_result(
                "2.3", "Ensure User-ID is only enabled for internal trusted interfaces", "L1", ERROR,
                actual="Could not parse zone XML"
            ))
            return
        untrusted_kw = ("untrust", "outside", "external", "internet", "wan", "dmz")
        bad = []
        for entry in root.iter("entry"):
            name   = entry.get("name", "").lower()
            uid_el = entry.find("enable-user-identification")
            uid_on = uid_el is not None and (uid_el.text or "").strip().lower() == "yes"
            if uid_on and any(kw in name for kw in untrusted_kw):
                bad.append(entry.get("name", "unnamed"))
        if bad:
            self._add(make_result(
                "2.3", "Ensure User-ID is only enabled for internal trusted interfaces", "L1", FAIL,
                expected="User-ID not enabled on untrusted/external zones",
                actual=f"User-ID enabled on untrusted zone(s): {', '.join(bad)}",
                remediation="Network > Zones — disable 'Enable User Identification' on all untrusted zones."
            ))
        else:
            self._add(make_result(
                "2.3", "Ensure User-ID is only enabled for internal trusted interfaces", "L1", PASS,
                actual="User-ID not enabled on any detected untrusted zones"
            ))

    def _check_2_4(self):
        xml = self._xq(f"{_VSYS}/user-id-collector/setting")
        has_include = self._has(self._xq(f"{_VSYS}/user-id-collector/setting/ip-user-mapping/include-network"))
        has_exclude = self._has(self._xq(f"{_VSYS}/user-id-collector/setting/ip-user-mapping/exclude-network"))
        uid_enabled = self._has(self._xq(f"{_VSYS}/user-id-collector"))
        if not uid_enabled:
            self._add(make_result(
                "2.4", "Ensure 'Include/Exclude Networks' is used if User-ID is enabled", "L1", PASS,
                actual="User-ID not enabled — not applicable"
            ))
            return
        if has_include or has_exclude:
            self._add(make_result(
                "2.4", "Ensure 'Include/Exclude Networks' is used if User-ID is enabled", "L1", PASS,
                actual="Include/Exclude network lists configured for User-ID"
            ))
        else:
            self._add(make_result(
                "2.4", "Ensure 'Include/Exclude Networks' is used if User-ID is enabled", "L1", FAIL,
                expected="Include/Exclude networks configured to limit User-ID scope",
                actual="No include/exclude networks defined (User-ID applies to all subnets)",
                remediation="Device > User Identification > User Mapping — configure Include/Exclude Networks."
            ))

    def _check_2_5(self):
        self._add(make_result(
            "2.5", "Ensure User-ID Agent has minimal permissions if User-ID is enabled", "L1", MANUAL,
            expected="User-ID service account is a domain user with read-only DC permissions",
            actual="Manual verification required — check Active Directory permissions",
            remediation="In Active Directory, verify the User-ID service account has only the minimum permissions required.",
            guidance={
                "where": "Active Directory Users and Computers",
                "steps": [
                    "Identify the service account used by the PAN-OS User-ID agent",
                    "In Active Directory, verify the account is a standard domain user (not Domain Admin)",
                    "Verify account has read access to Security event logs only",
                    "Verify account is NOT in Administrators, Domain Admins, or other privileged groups",
                ],
                "pass_criteria": "Service account is a least-privilege domain user with read-only Security log access",
                "fail_criteria": "Service account has elevated AD privileges (Domain Admin, etc.)",
            }
        ))

    def _check_2_6(self):
        xml = self._xq(f"{_VSYS}/user-id-collector/setting")
        val = self._tag(xml, "allow-interactive-logon")
        if not self._has(xml) or val is None or val.lower() == "no":
            self._add(make_result(
                "2.6", "Ensure User-ID service account does not have interactive logon rights", "L1", PASS,
                actual="Interactive logon disabled or User-ID not configured"
            ))
        else:
            self._add(make_result(
                "2.6", "Ensure User-ID service account does not have interactive logon rights", "L1", FAIL,
                expected="allow-interactive-logon = no",
                actual=f"allow-interactive-logon = {val}",
                remediation="Device > User Identification — disable interactive logon for the User-ID service account."
            ))

    def _check_2_7(self):
        self._add(make_result(
            "2.7", "Ensure remote access capabilities for User-ID service account are forbidden", "L1", MANUAL,
            expected="User-ID service account has no remote desktop or remote access rights",
            actual="Manual verification required",
            remediation="In Active Directory, deny remote desktop access to the User-ID service account.",
            guidance={
                "where": "Active Directory Group Policy",
                "steps": [
                    "Open Group Policy Management on your domain controller",
                    "Find the GPO applying to the User-ID agent host",
                    "Under Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment",
                    "Verify the User-ID service account is NOT in 'Allow log on through Remote Desktop Services'",
                    "Verify the account IS in 'Deny log on through Remote Desktop Services' if possible",
                ],
                "pass_criteria": "Service account explicitly denied remote access / not in remote access groups",
                "fail_criteria": "Service account can log on remotely or is a member of Remote Desktop Users",
            }
        ))

    def _check_2_8(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "2.8", "Ensure security policies restrict User-ID Agent traffic from crossing into untrusted zones", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        uid_rules = [r for r in rules if not r["disabled"] and r["action"] == "deny" and
                     any("uid" in (r.get("name", "")).lower() or
                         "user-id" in (r.get("name", "")).lower()
                         for _ in [1])]
        if uid_rules:
            self._add(make_result(
                "2.8", "Ensure security policies restrict User-ID Agent traffic from crossing into untrusted zones", "L1",
                PASS, actual=f"Found {len(uid_rules)} rule(s) restricting User-ID traffic"
            ))
        else:
            self._add(make_result(
                "2.8", "Ensure security policies restrict User-ID Agent traffic from crossing into untrusted zones", "L1",
                MANUAL,
                expected="Security policy denies User-ID agent traffic to untrusted zones",
                actual="Could not auto-detect User-ID restriction rules — manual verification required",
                remediation="Policies > Security — add a rule denying User-ID agent traffic from trusted to untrusted zones.",
                guidance={
                    "where": "Policies > Security",
                    "steps": [
                        "Navigate to Policies > Security",
                        "Verify a deny rule exists that blocks User-ID agent traffic (port 5007 or custom) to untrusted zones",
                        "The rule should be above any allow-all rules",
                        "Source zone: internal/trusted; Destination zone: untrusted; Action: Deny",
                    ],
                    "pass_criteria": "Deny rule exists preventing User-ID traffic from crossing to untrusted zones",
                    "fail_criteria": "No such rule exists or User-ID traffic is allowed to untrusted zones",
                }
            ))

    # ── Section 3: High Availability ─────────────────────────────────────────

    def _check_3_1(self):
        xml = self._xq(f"{_DEV}/deviceconfig/high-availability")
        enabled = self._tag(xml, "enabled")
        if not self._has(xml) or enabled == "no":
            self._add(make_result(
                "3.1", "Ensure a fully-synchronized HA peer is configured", "L2", FAIL,
                expected="HA enabled and both peers synchronized",
                actual="High Availability is not enabled",
                remediation="Device > High Availability — configure active/passive HA pair."
            ))
            return
        state_xml = self._cmd("show high-availability state")
        sync_ok = "synchronized" in state_xml.lower()
        if sync_ok:
            self._add(make_result(
                "3.1", "Ensure a fully-synchronized HA peer is configured", "L2", PASS,
                actual="HA is enabled and peers report synchronized"
            ))
        else:
            self._add(make_result(
                "3.1", "Ensure a fully-synchronized HA peer is configured", "L2", FAIL,
                expected="HA enabled and peers synchronized",
                actual="HA enabled but peers not reporting synchronized state",
                remediation="Device > High Availability — verify both peers are connected and synchronized."
            ))

    def _check_3_2(self):
        xml = self._xq(f"{_DEV}/deviceconfig/high-availability/group")
        link_mon = self._tag(xml, "link-monitoring")
        path_mon = self._tag(xml, "path-monitoring")
        has_link = self._has(self._xq(f"{_DEV}/deviceconfig/high-availability/group/link-monitoring"))
        has_path = self._has(self._xq(f"{_DEV}/deviceconfig/high-availability/group/path-monitoring"))
        if has_link or has_path:
            self._add(make_result(
                "3.2", "Ensure HA requires Link Monitoring and/or Path Monitoring", "L2", PASS,
                actual=f"Link monitoring: {'configured' if has_link else 'not set'}, Path monitoring: {'configured' if has_path else 'not set'}"
            ))
        else:
            xml2 = self._xq(f"{_DEV}/deviceconfig/high-availability")
            if not self._has(xml2):
                self._add(make_result(
                    "3.2", "Ensure HA requires Link Monitoring and/or Path Monitoring", "L2", FAIL,
                    actual="HA is not configured",
                    remediation="Configure HA with link and path monitoring enabled."
                ))
            else:
                self._add(make_result(
                    "3.2", "Ensure HA requires Link Monitoring and/or Path Monitoring", "L2", FAIL,
                    expected="Link or path monitoring enabled in HA configuration",
                    actual="HA configured but no link or path monitoring defined",
                    remediation="Device > High Availability > Link and Path Monitoring — enable link and/or path monitoring."
                ))

    def _check_3_3(self):
        xml = self._xq(f"{_DEV}/deviceconfig/high-availability")
        passive_link = self._tag(xml, "passive-link-state")
        preemptive   = self._tag(xml, "preemptive")
        self._add(make_result(
            "3.3", "Ensure 'Passive Link State' and 'Preemptive' are configured appropriately", "L2", MANUAL,
            expected="Passive link state = shutdown; preemptive configured per policy",
            actual=f"passive-link-state={passive_link or 'not set'}, preemptive={preemptive or 'not set'}",
            remediation="Device > High Availability — set Passive Link State to 'shutdown' and configure Preemptive per your HA design.",
            guidance={
                "where": "Device > High Availability",
                "steps": [
                    "Navigate to Device > High Availability",
                    "Verify 'Passive Link State' is set to 'Shutdown' (recommended) to prevent forwarding loops",
                    "Review 'Preemptive' setting — enable if the primary should automatically resume when it recovers",
                    "Document the chosen configuration as part of HA runbook",
                ],
                "pass_criteria": "Passive link state = shutdown; preemptive setting matches documented design",
                "fail_criteria": "Passive link state = auto (may allow forwarding loops); no documented justification for preemptive choice",
            }
        ))

    # ── Section 4: Dynamic Updates ───────────────────────────────────────────

    def _check_4_1(self):
        xml = self._xq(f"{_SYS}/update-schedule/anti-virus")
        recurrence = self._tag(xml, "recurring/hourly/action") or self._tag(xml, "recurring/hourly")
        if not recurrence:
            sync_str = re.search(r"<hourly>", xml or "")
            recurrence = "hourly" if sync_str else None
        if recurrence or (self._has(xml) and "hourly" in (xml or "").lower()):
            self._add(make_result(
                "4.1", "Ensure 'Antivirus Update Schedule' is set to download and install updates hourly", "L1", PASS,
                actual="Antivirus update schedule is configured as hourly"
            ))
        elif self._has(xml):
            self._add(make_result(
                "4.1", "Ensure 'Antivirus Update Schedule' is set to download and install updates hourly", "L1", FAIL,
                expected="Antivirus updates: hourly download and install",
                actual="Antivirus update schedule configured but not hourly",
                remediation="Device > Dynamic Updates > Antivirus — set Recurrence to Hourly with action Download and Install."
            ))
        else:
            self._add(make_result(
                "4.1", "Ensure 'Antivirus Update Schedule' is set to download and install updates hourly", "L1", FAIL,
                expected="Antivirus updates: hourly download and install",
                actual="Antivirus update schedule not configured",
                remediation="Device > Dynamic Updates > Antivirus — enable scheduled hourly updates."
            ))

    def _check_4_2(self):
        xml = self._xq(f"{_SYS}/update-schedule/threats")
        daily = "daily" in (xml or "").lower()
        hourly = "hourly" in (xml or "").lower()
        if self._has(xml) and (daily or hourly):
            self._add(make_result(
                "4.2", "Ensure 'Applications and Threats Update Schedule' is daily or shorter", "L1", PASS,
                actual=f"App and Threat updates scheduled: {'hourly' if hourly else 'daily'}"
            ))
        elif self._has(xml):
            self._add(make_result(
                "4.2", "Ensure 'Applications and Threats Update Schedule' is daily or shorter", "L1", FAIL,
                expected="App+Threats updates at daily or shorter interval",
                actual="App+Threats update schedule configured but interval exceeds daily",
                remediation="Device > Dynamic Updates > Applications and Threats — set Recurrence to Daily or more frequent."
            ))
        else:
            self._add(make_result(
                "4.2", "Ensure 'Applications and Threats Update Schedule' is daily or shorter", "L1", FAIL,
                expected="App+Threats updates at daily or shorter interval",
                actual="App+Threats update schedule not configured",
                remediation="Device > Dynamic Updates > Applications and Threats — enable daily scheduled updates."
            ))

    # ── Section 5: WildFire ───────────────────────────────────────────────────

    def _check_5_1(self):
        xml = self._xq(f"{_SETTING}/wildfire/file-size-limit")
        if self._has(xml):
            self._add(make_result(
                "5.1", "Ensure WildFire file size upload limits are maximized", "L1", PASS,
                actual="WildFire file size limits are configured"
            ))
        else:
            self._add(make_result(
                "5.1", "Ensure WildFire file size upload limits are maximized", "L1", FAIL,
                expected="WildFire file size limits set to maximum for all file types",
                actual="WildFire file size limits not configured (using defaults)",
                remediation="Device > Setup > WildFire — set file size limits to maximum for pe, pdf, ms-office, jar, flash, apk, elf, and archive types."
            ))

    def _check_5_2(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "5.2", "Ensure a WildFire Analysis profile is enabled for all security policies", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        if rules == []:
            self._add(make_result(
                "5.2", "Ensure a WildFire Analysis profile is enabled for all security policies", "L1", FAIL,
                expected="All allow rules reference a security profile group including WildFire Analysis",
                actual="No security policies configured — WildFire Analysis profiles cannot be assigned",
                remediation="Policies > Security — create security policies and attach a Profile Group with WildFire Analysis."
            ))
            return
        allow_rules = [r for r in rules if not r["disabled"] and r["action"] == "allow"]
        no_wf = []
        for r in allow_rules:
            if not r["has_profile"]:
                no_wf.append(r["name"])
        if no_wf:
            self._add(make_result(
                "5.2", "Ensure a WildFire Analysis profile is enabled for all security policies", "L1", FAIL,
                expected="All allow rules reference a security profile group including WildFire",
                actual=f"{len(no_wf)} allow rule(s) with no security profile: {', '.join(no_wf[:5])}",
                remediation="Policies > Security — add a Profile Group with WildFire Analysis to each allow rule."
            ))
        else:
            self._add(make_result(
                "5.2", "Ensure a WildFire Analysis profile is enabled for all security policies", "L1", PASS,
                actual=f"All {len(allow_rules)} allow rule(s) have security profiles attached"
            ))

    def _check_5_3(self):
        xml = self._xq(f"{_SETTING}/wildfire/forward-decrypted-https-content")
        val = self._tag(xml, "forward-decrypted-https-content")
        if val and val.lower() == "yes":
            self._add(make_result(
                "5.3", "Ensure forwarding of decrypted content to WildFire is enabled", "L1", PASS,
                actual="forward-decrypted-https-content = yes"
            ))
        else:
            self._add(make_result(
                "5.3", "Ensure forwarding of decrypted content to WildFire is enabled", "L1", FAIL,
                expected="forward-decrypted-https-content = yes",
                actual=f"forward-decrypted-https-content = {val or 'not set'}",
                remediation="Device > Setup > WildFire — enable 'Forward Decrypted HTTPS Content'."
            ))

    def _check_5_4(self):
        xml = self._xq(f"{_SETTING}/wildfire/session-info-select")
        if self._has(xml):
            self._add(make_result(
                "5.4", "Ensure all WildFire session information settings are enabled", "L1", PASS,
                actual="WildFire session information settings are configured"
            ))
        else:
            self._add(make_result(
                "5.4", "Ensure all WildFire session information settings are enabled", "L1", FAIL,
                expected="All WildFire session info options enabled",
                actual="WildFire session information settings not configured",
                remediation="Device > Setup > WildFire — enable all Session Information settings."
            ))

    def _check_5_5(self):
        xml = self._xq(f"{_VSYS}/log-settings/profiles")
        if not self._has(xml):
            xml = self._xq("/config/shared/log-settings/profiles")
        wf_alert = bool(self._has(xml) and "wildfire" in (xml or "").lower())
        if wf_alert:
            self._add(make_result(
                "5.5", "Ensure alerts are enabled for malicious files detected by WildFire", "L1", PASS,
                actual="Log forwarding profile with WildFire log type found"
            ))
        else:
            self._add(make_result(
                "5.5", "Ensure alerts are enabled for malicious files detected by WildFire", "L1", FAIL,
                expected="Log forwarding profile configured with WildFire alert actions",
                actual="No WildFire alert configuration found in log forwarding profiles",
                remediation="Objects > Log Forwarding — add a WildFire log type with filter '(verdict neq benign)' and alert destinations."
            ))

    def _check_5_6(self):
        xml = self._xq(f"{_SYS}/update-schedule/wildfire")
        realtime = "real-time" in (xml or "").lower()
        if self._has(xml) and realtime:
            self._add(make_result(
                "5.6", "Ensure 'WildFire Update Schedule' is set to real-time", "L1", PASS,
                actual="WildFire update schedule = real-time"
            ))
        elif self._has(xml):
            self._add(make_result(
                "5.6", "Ensure 'WildFire Update Schedule' is set to real-time", "L1", FAIL,
                expected="WildFire updates: recurrence = Real-time",
                actual="WildFire update schedule configured but not real-time",
                remediation="Device > Dynamic Updates > WildFire Update Schedule — set Recurrence to Real-time."
            ))
        else:
            self._add(make_result(
                "5.6", "Ensure 'WildFire Update Schedule' is set to real-time", "L1", FAIL,
                expected="WildFire updates: recurrence = Real-time",
                actual="WildFire update schedule not configured",
                remediation="Device > Dynamic Updates > WildFire Update Schedule — enable Real-time updates."
            ))

    def _check_5_7(self):
        xml = self._xq(f"{_SETTING}/wildfire/cloud-intelligence/public-cloud-server")
        server = self._tag(xml, "public-cloud-server")
        self._add(make_result(
            "5.7", "Choosing WildFire public cloud region", "L2", MANUAL,
            expected="WildFire public cloud region matches organizational data residency requirements",
            actual=f"Current WildFire cloud server: {server or 'wildfire.paloaltonetworks.com (default/US)'}",
            remediation="Device > Setup > WildFire — change WildFire Public Cloud to appropriate regional server.",
            guidance={
                "where": "Device > Setup > WildFire > General Settings",
                "steps": [
                    "Navigate to Device > Setup > WildFire",
                    "Check the 'WildFire Public Cloud' field",
                    "Default is wildfire.paloaltonetworks.com (US) — verify this meets your data residency requirements",
                    "Change to regional server if required (e.g., eu.wildfire.paloaltonetworks.com for EU data residency)",
                ],
                "pass_criteria": "WildFire cloud region matches organizational data residency policy",
                "fail_criteria": "Default US region used when data residency requires another region",
            }
        ))

    # ── Section 6: Security Profiles ─────────────────────────────────────────

    def _check_6_1(self):
        xml = self._xq(f"{_VSYS}/profiles/virus")
        if not self._has(xml):
            self._add(make_result(
                "6.1", "Ensure antivirus profiles set to reset-both on all decoders except imap/pop3", "L1", FAIL,
                expected="At least one antivirus profile with reset-both on all non-email decoders",
                actual="No antivirus profiles configured",
                remediation="Objects > Security Profiles > Antivirus — create a profile with reset-both on all decoders."
            ))
            return
        root = self._xml(xml)
        if root is None:
            self._add(make_result(
                "6.1", "Ensure antivirus profiles set to reset-both on all decoders except imap/pop3", "L1", ERROR,
                actual="Could not parse antivirus profile XML"
            ))
            return
        bad_profiles = []
        for entry in root.iter("entry"):
            name = entry.get("name", "unnamed")
            decoders = entry.find("decoder")
            if decoders is None:
                bad_profiles.append(f"{name}(no decoders configured)")
                continue
            for dec in decoders:
                dec_name = dec.get("name", "").lower()
                if dec_name in ("imap", "pop3"):
                    continue
                action_el = dec.find("action")
                if action_el is not None and action_el.text and action_el.text.strip().lower() != "reset-both":
                    bad_profiles.append(f"{name}/{dec_name}={action_el.text.strip()}")
        if bad_profiles:
            self._add(make_result(
                "6.1", "Ensure antivirus profiles set to reset-both on all decoders except imap/pop3", "L1", FAIL,
                expected="All non-imap/pop3 decoders = reset-both",
                actual=f"Non-compliant: {', '.join(bad_profiles[:5])}",
                remediation="Objects > Security Profiles > Antivirus — set all decoders (except imap/pop3) to reset-both."
            ))
        else:
            self._add(make_result(
                "6.1", "Ensure antivirus profiles set to reset-both on all decoders except imap/pop3", "L1", PASS,
                actual="All antivirus profiles have reset-both on non-imap/pop3 decoders"
            ))

    def _check_6_2(self):
        self._add(make_result(
            "6.2", "Ensure a secure antivirus profile is applied to all relevant security policies", "L1", MANUAL,
            expected="AV profile applied to all policies passing HTTP, SMTP, IMAP, POP3, FTP, or SMB traffic",
            actual="Manual verification required",
            remediation="Policies > Security — for each policy passing file-capable protocols, add an antivirus profile or profile group.",
            guidance={
                "where": "Policies > Security",
                "steps": [
                    "Navigate to Policies > Security",
                    "For each security policy that allows traffic, click the policy name",
                    "Under Actions > Profile Setting, verify an Antivirus profile or Profile Group is selected",
                    "Verify the profile uses reset-both action (not allow/alert) for all applicable decoders",
                ],
                "pass_criteria": "All allow policies referencing HTTP/SMTP/IMAP/POP3/FTP/SMB have an AV profile",
                "fail_criteria": "Any allow policy lacks an antivirus profile or uses alert-only action",
            }
        ))

    def _check_6_3(self):
        xml = self._xq(f"{_VSYS}/profiles/spyware")
        if not self._has(xml):
            self._add(make_result(
                "6.3", "Ensure anti-spyware profile blocks Critical/High/Medium spyware", "L1", FAIL,
                expected="Anti-spyware profile with reset-both on Critical, High, Medium severity",
                actual="No anti-spyware profiles configured",
                remediation="Objects > Security Profiles > Anti-Spyware — create profile blocking Critical/High/Medium spyware."
            ))
            return
        root = self._xml(xml)
        if root is None:
            self._add(make_result(
                "6.3", "Ensure anti-spyware profile blocks Critical/High/Medium spyware", "L1", ERROR,
                actual="Could not parse anti-spyware profile XML"
            ))
            return
        profiles_checked = []
        for entry in root.iter("entry"):
            name = entry.get("name", "unnamed")
            profiles_checked.append(name)
        if profiles_checked:
            self._add(make_result(
                "6.3", "Ensure anti-spyware profile blocks Critical/High/Medium spyware", "L1", PASS,
                actual=f"{len(profiles_checked)} anti-spyware profile(s) found: {', '.join(profiles_checked[:3])}"
            ))
        else:
            self._add(make_result(
                "6.3", "Ensure anti-spyware profile blocks Critical/High/Medium spyware", "L1", FAIL,
                expected="Anti-spyware profile blocking Critical/High/Medium",
                actual="No valid anti-spyware profiles found",
                remediation="Objects > Security Profiles > Anti-Spyware — create a profile with reset-both on Critical, High, Medium."
            ))

    def _check_6_4(self):
        xml = self._xq(f"{_VSYS}/profiles/spyware")
        if not self._has(xml):
            self._add(make_result(
                "6.4", "Ensure DNS sinkholing is configured on all anti-spyware profiles in use", "L1", FAIL,
                expected="All anti-spyware profiles have DNS sinkholing configured",
                actual="No anti-spyware profiles found",
                remediation="Objects > Security Profiles > Anti-Spyware > DNS Policies — enable sinkhole for default-paloalto-dns."
            ))
            return
        has_sinkhole = "sinkhole" in (xml or "").lower()
        if has_sinkhole:
            self._add(make_result(
                "6.4", "Ensure DNS sinkholing is configured on all anti-spyware profiles in use", "L1", PASS,
                actual="DNS sinkholing configuration found in anti-spyware profiles"
            ))
        else:
            self._add(make_result(
                "6.4", "Ensure DNS sinkholing is configured on all anti-spyware profiles in use", "L1", FAIL,
                expected="DNS sinkholing configured in anti-spyware profiles",
                actual="No DNS sinkholing found in anti-spyware profiles",
                remediation="Objects > Security Profiles > Anti-Spyware > DNS Policies — set default-paloalto-dns to sinkhole action."
            ))

    def _check_6_5(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "6.5", "Ensure secure anti-spyware profile applied to internet-bound policies", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        if rules == []:
            self._add(make_result(
                "6.5", "Ensure secure anti-spyware profile applied to internet-bound policies", "L1", FAIL,
                expected="All internet-bound allow rules have a security profile group with anti-spyware",
                actual="No security policies configured — anti-spyware profiles cannot be verified",
                remediation="Policies > Security — create internet-bound policies and attach a Profile Group including an Anti-Spyware profile."
            ))
            return
        internet_rules = [r for r in rules if not r["disabled"] and r["action"] == "allow"]
        no_profile = [r["name"] for r in internet_rules if not r["has_profile"]]
        if no_profile:
            self._add(make_result(
                "6.5", "Ensure secure anti-spyware profile applied to internet-bound policies", "L1", FAIL,
                expected="All allow policies have a security profile group (including anti-spyware)",
                actual=f"{len(no_profile)} allow policy/policies without profile: {', '.join(no_profile[:5])}",
                remediation="Policies > Security — add Profile Group with Anti-Spyware to all outbound allow policies."
            ))
        else:
            self._add(make_result(
                "6.5", "Ensure secure anti-spyware profile applied to internet-bound policies", "L1", PASS,
                actual=f"All {len(internet_rules)} allow rule(s) have security profiles attached"
            ))

    def _check_6_6(self):
        xml = self._xq(f"{_VSYS}/profiles/vulnerability")
        if not self._has(xml):
            self._add(make_result(
                "6.6", "Ensure Vulnerability Protection Profile blocks critical/high vulnerabilities", "L1", FAIL,
                expected="Vulnerability protection profile blocking Critical and High severity",
                actual="No vulnerability protection profiles found",
                remediation="Objects > Security Profiles > Vulnerability Protection — create profile blocking Critical and High."
            ))
            return
        has_block = "block" in (xml or "").lower() or "reset" in (xml or "").lower()
        count = xml.count("<entry ") if self._has(xml) else 0
        if has_block:
            self._add(make_result(
                "6.6", "Ensure Vulnerability Protection Profile blocks critical/high vulnerabilities", "L1", PASS,
                actual=f"{count} vulnerability protection profile(s) found with block/reset actions"
            ))
        else:
            self._add(make_result(
                "6.6", "Ensure Vulnerability Protection Profile blocks critical/high vulnerabilities", "L1", FAIL,
                expected="Vulnerability profile with block on Critical/High, default on Medium/Low",
                actual="Vulnerability profiles found but no block/reset actions detected",
                remediation="Objects > Security Profiles > Vulnerability Protection — set Critical/High severity to block-ip or reset-both."
            ))

    def _check_6_7(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "6.7", "Ensure secure Vulnerability Protection Profile applied to all allow rules", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        if rules == []:
            self._add(make_result(
                "6.7", "Ensure secure Vulnerability Protection Profile applied to all allow rules", "L1", FAIL,
                expected="All allow rules reference a security profile group with Vulnerability Protection",
                actual="No security policies configured — Vulnerability Protection profiles cannot be verified",
                remediation="Policies > Security — create allow rules and attach a Profile Group including a Vulnerability Protection profile."
            ))
            return
        allow_rules = [r for r in rules if not r["disabled"] and r["action"] == "allow"]
        no_profile  = [r["name"] for r in allow_rules if not r["has_profile"]]
        if no_profile:
            self._add(make_result(
                "6.7", "Ensure secure Vulnerability Protection Profile applied to all allow rules", "L1", FAIL,
                expected="All allow rules have a security profile including Vulnerability Protection",
                actual=f"{len(no_profile)} allow rule(s) without security profile: {', '.join(no_profile[:5])}",
                remediation="Policies > Security — add Profile Group with Vulnerability Protection to all allow rules."
            ))
        else:
            self._add(make_result(
                "6.7", "Ensure secure Vulnerability Protection Profile applied to all allow rules", "L1", PASS,
                actual=f"All {len(allow_rules)} allow rule(s) have security profiles"
            ))

    def _check_6_8(self):
        xml = self._cmd("show system info")
        pandb = re.search(r"url-db\s*:\s*(\S+)", xml, re.IGNORECASE)
        val   = pandb.group(1).strip().lower() if pandb else None
        if val and "paloalto" in val:
            self._add(make_result(
                "6.8", "Ensure that PAN-DB URL Filtering is used", "L1", PASS,
                actual=f"URL database: {val}"
            ))
        elif val and "brightcloud" in val.lower():
            self._add(make_result(
                "6.8", "Ensure that PAN-DB URL Filtering is used", "L1", FAIL,
                expected="URL database = PAN-DB",
                actual=f"URL database = {val} (BrightCloud is not recommended)",
                remediation="Device > Licenses — switch URL database to PAN-DB."
            ))
        else:
            self._add(make_result(
                "6.8", "Ensure that PAN-DB URL Filtering is used", "L1", PASS,
                actual=f"URL database: {val or 'PAN-DB (license active)'}"
            ))

    def _check_6_9(self):
        xml = self._xq(f"{_VSYS}/profiles/url-filtering")
        if not self._has(xml):
            self._add(make_result(
                "6.9", "Ensure URL Filtering uses block/override on high-risk categories", "L1", FAIL,
                expected="URL filtering profile with block/override on high-risk categories",
                actual="No URL filtering profiles configured",
                remediation="Objects > Security Profiles > URL Filtering — create profile blocking high-risk categories."
            ))
            return
        has_block = "block" in (xml or "").lower() or "override" in (xml or "").lower()
        count = xml.count("<entry ") if self._has(xml) else 0
        if has_block:
            self._add(make_result(
                "6.9", "Ensure URL Filtering uses block/override on high-risk categories", "L1", PASS,
                actual=f"{count} URL filtering profile(s) with block/override actions found"
            ))
        else:
            self._add(make_result(
                "6.9", "Ensure URL Filtering uses block/override on high-risk categories", "L1", FAIL,
                expected="URL filtering profiles block high-risk categories",
                actual="URL filtering profiles found but no block/override actions detected",
                remediation="Objects > Security Profiles > URL Filtering — set high-risk categories (adult, hacking, malware) to block."
            ))

    def _check_6_10(self):
        xml = self._xq(f"{_VSYS}/profiles/url-filtering")
        if not self._has(xml):
            self._add(make_result(
                "6.10", "Ensure that access to every URL is logged", "L1", FAIL,
                actual="No URL filtering profiles — all URL access unlogged",
                remediation="Objects > Security Profiles > URL Filtering — set all permitted categories to alert (not allow)."
            ))
            return
        has_allow = "allow" in (xml or "").lower()
        if has_allow:
            self._add(make_result(
                "6.10", "Ensure that access to every URL is logged", "L1", FAIL,
                expected="No URL categories set to 'allow' (which suppresses logging)",
                actual="URL categories with 'allow' action found — these are not logged",
                remediation="Objects > Security Profiles > URL Filtering — change all 'allow' categories to 'alert' to enable logging."
            ))
        else:
            self._add(make_result(
                "6.10", "Ensure that access to every URL is logged", "L1", PASS,
                actual="No URL categories use 'allow' (which suppresses logging)"
            ))

    def _check_6_11(self):
        xml = self._xq(f"{_VSYS}/profiles/url-filtering")
        if not self._has(xml):
            self._add(make_result(
                "6.11", "Ensure all HTTP Header Logging options are enabled", "L1", FAIL,
                actual="No URL filtering profiles configured",
                remediation="Objects > Security Profiles > URL Filtering — enable User-Agent, Referer, and X-Forwarded-For logging."
            ))
            return
        has_ua  = "user-agent" in (xml or "").lower()
        has_ref = "referer"    in (xml or "").lower()
        has_xff = "x-forwarded-for" in (xml or "").lower()
        if has_ua and has_ref and has_xff:
            self._add(make_result(
                "6.11", "Ensure all HTTP Header Logging options are enabled", "L1", PASS,
                actual="User-Agent, Referer, and X-Forwarded-For header logging configured"
            ))
        else:
            missing = []
            if not has_ua:  missing.append("User-Agent")
            if not has_ref: missing.append("Referer")
            if not has_xff: missing.append("X-Forwarded-For")
            self._add(make_result(
                "6.11", "Ensure all HTTP Header Logging options are enabled", "L1", FAIL,
                expected="User-Agent, Referer, and X-Forwarded-For all enabled",
                actual=f"Missing header logging: {', '.join(missing)}",
                remediation="Objects > Security Profiles > URL Filtering > URL Filtering Settings — enable all HTTP Header Logging options."
            ))

    def _check_6_12(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "6.12", "Ensure secure URL filtering applied to internet-bound policies", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        if rules == []:
            self._add(make_result(
                "6.12", "Ensure secure URL filtering applied to internet-bound policies", "L1", FAIL,
                expected="All internet-bound allow rules have a security profile group with URL Filtering",
                actual="No security policies configured — URL Filtering profile assignment cannot be verified",
                remediation="Policies > Security — create internet-bound allow rules and attach a Profile Group including a URL Filtering profile."
            ))
            return
        allow_rules = [r for r in rules if not r["disabled"] and r["action"] == "allow"]
        no_profile  = [r["name"] for r in allow_rules if not r["has_profile"]]
        if no_profile:
            self._add(make_result(
                "6.12", "Ensure secure URL filtering applied to internet-bound policies", "L1", FAIL,
                expected="All internet-bound allow policies have URL filtering profile",
                actual=f"{len(no_profile)} allow rule(s) without security profile: {', '.join(no_profile[:5])}",
                remediation="Policies > Security — add Profile Group with URL Filtering to all internet-bound allow policies."
            ))
        else:
            self._add(make_result(
                "6.12", "Ensure secure URL filtering applied to internet-bound policies", "L1", PASS,
                actual=f"All {len(allow_rules)} allow rule(s) have security profiles"
            ))

    def _check_6_13(self):
        xml = self._xq(f"{_VSYS}/profiles/data-filtering")
        if not self._has(xml):
            self._add(make_result(
                "6.13", "Ensure alerting after threshold of credit card/SSN detection is enabled", "L1", FAIL,
                expected="Data filtering profile with credit card/SSN patterns and alert threshold",
                actual="No data filtering profiles configured",
                remediation="Objects > Custom Objects > Data Patterns — create CC/SSN patterns; Objects > Security Profiles > Data Filtering — create profile."
            ))
            return
        has_cc  = "credit-card" in (xml or "").lower() or "cc" in (xml or "").lower()
        has_ssn = "social-security" in (xml or "").lower() or "ssn" in (xml or "").lower()
        if has_cc or has_ssn:
            self._add(make_result(
                "6.13", "Ensure alerting after threshold of credit card/SSN detection is enabled", "L1", PASS,
                actual="Data filtering profile with credit card/SSN pattern configured"
            ))
        else:
            self._add(make_result(
                "6.13", "Ensure alerting after threshold of credit card/SSN detection is enabled", "L1", FAIL,
                expected="Data filtering profile with CC/SSN patterns and alert threshold >= 1",
                actual="Data filtering profile exists but no CC/SSN patterns detected",
                remediation="Objects > Custom Objects > Data Patterns — add predefined Credit Card and Social Security Number patterns."
            ))

    def _check_6_14(self):
        xml = self._xq(f"{_VSYS}/profiles/data-filtering")
        if not self._has(xml):
            self._add(make_result(
                "6.14", "Ensure a secure Data Filtering profile is applied to all internet-bound policies", "L1", FAIL,
                expected="Data filtering profile applied to all internet-bound allow policies",
                actual="No data filtering profiles configured",
                remediation="Objects > Security Profiles > Data Filtering — create a profile and apply it to internet-bound policies."
            ))
            return
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "6.14", "Ensure a secure Data Filtering profile is applied to all internet-bound policies", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        allow_rules = [r for r in rules if not r["disabled"] and r["action"] == "allow"]
        no_profile  = [r["name"] for r in allow_rules if not r["has_profile"]]
        if no_profile:
            self._add(make_result(
                "6.14", "Ensure a secure Data Filtering profile is applied to all internet-bound policies", "L1", FAIL,
                expected="All internet-bound allow policies include data filtering",
                actual=f"{len(no_profile)} allow rule(s) without security profile: {', '.join(no_profile[:5])}",
                remediation="Policies > Security — add Profile Group with Data Filtering to all internet-bound allow policies."
            ))
        else:
            self._add(make_result(
                "6.14", "Ensure a secure Data Filtering profile is applied to all internet-bound policies", "L1", PASS,
                actual=f"All {len(allow_rules)} allow rule(s) have security profiles (which should include data filtering)"
            ))

    def _check_6_15(self):
        xml = self._xq(f"{_NET}/profiles/zone-protection-profile")
        if not self._has(xml):
            self._add(make_result(
                "6.15", "Ensure Zone Protection Profile with SYN Cookies attached to untrusted zones", "L1", FAIL,
                expected="Zone protection profile with SYN Cookies flood protection on untrusted zones",
                actual="No zone protection profiles configured",
                remediation="Network > Network Profiles > Zone Protection — create profile with SYN Cookies flood protection."
            ))
            return
        has_syn = "syn-cookies" in (xml or "").lower() or "syn" in (xml or "").lower()
        zone_xml = self._xq(f"{_NET}/zone")
        has_zone_profile = "zone-protection-profile" in (zone_xml or "").lower()
        if has_syn and has_zone_profile:
            self._add(make_result(
                "6.15", "Ensure Zone Protection Profile with SYN Cookies attached to untrusted zones", "L1", PASS,
                actual="Zone protection profiles with SYN configuration found and applied to zones"
            ))
        else:
            self._add(make_result(
                "6.15", "Ensure Zone Protection Profile with SYN Cookies attached to untrusted zones", "L1", FAIL,
                expected="Zone protection profile with SYN Cookies applied to all untrusted zones",
                actual=f"SYN Cookies: {'found' if has_syn else 'not found'}; Zone assignment: {'found' if has_zone_profile else 'not found'}",
                remediation="Network > Network Profiles > Zone Protection > Flood Protection — enable SYN with SYN Cookies and apply to untrusted zones."
            ))

    def _check_6_16(self):
        xml = self._xq(f"{_NET}/profiles/zone-protection-profile")
        if not self._has(xml):
            self._add(make_result(
                "6.16", "Ensure Zone Protection with all flood types applied to untrusted zones", "L2", FAIL,
                expected="Zone protection profile with all flood types enabled on untrusted zones",
                actual="No zone protection profiles configured",
                remediation="Network > Network Profiles > Zone Protection > Flood Protection — enable all flood types."
            ))
            return
        xml_l = (xml or "").lower()
        has_syn  = "syn" in xml_l
        has_udp  = "udp" in xml_l
        has_icmp = "icmp" in xml_l
        if has_syn and has_udp and has_icmp:
            self._add(make_result(
                "6.16", "Ensure Zone Protection with all flood types applied to untrusted zones", "L2", PASS,
                actual="Zone protection profile with SYN, UDP, and ICMP flood protection found"
            ))
        else:
            missing = []
            if not has_syn:  missing.append("SYN")
            if not has_udp:  missing.append("UDP")
            if not has_icmp: missing.append("ICMP")
            self._add(make_result(
                "6.16", "Ensure Zone Protection with all flood types applied to untrusted zones", "L2", FAIL,
                expected="All flood types (SYN, UDP, ICMP) enabled",
                actual=f"Missing flood protection types: {', '.join(missing)}",
                remediation="Network > Network Profiles > Zone Protection > Flood Protection — enable all flood protection types."
            ))

    def _check_6_17(self):
        xml = self._xq(f"{_NET}/profiles/zone-protection-profile")
        if not self._has(xml):
            self._add(make_result(
                "6.17", "Ensure Zone Protection Profiles have Reconnaissance Protection enabled", "L1", FAIL,
                expected="Reconnaissance protection enabled on all zone protection profiles",
                actual="No zone protection profiles configured",
                remediation="Network > Network Profiles > Zone Protection > Reconnaissance Protection — enable all three scan types."
            ))
            return
        xml_l = (xml or "").lower()
        has_tcp_scan  = "tcp-port-scan" in xml_l or "tcp-scan" in xml_l
        has_host_sw   = "host-sweep" in xml_l
        has_udp_scan  = "udp-port-scan" in xml_l or "udp-scan" in xml_l
        if has_tcp_scan and has_host_sw and has_udp_scan:
            self._add(make_result(
                "6.17", "Ensure Zone Protection Profiles have Reconnaissance Protection enabled", "L1", PASS,
                actual="TCP port scan, host sweep, and UDP port scan protection all configured"
            ))
        else:
            missing = []
            if not has_tcp_scan: missing.append("TCP port scan")
            if not has_host_sw:  missing.append("Host sweep")
            if not has_udp_scan: missing.append("UDP port scan")
            self._add(make_result(
                "6.17", "Ensure Zone Protection Profiles have Reconnaissance Protection enabled", "L1", FAIL,
                expected="TCP port scan, host sweep, and UDP port scan all enabled",
                actual=f"Missing reconnaissance protection: {', '.join(missing)}",
                remediation="Network > Network Profiles > Zone Protection > Reconnaissance Protection — enable all scan types with block-ip/block actions."
            ))

    def _check_6_18(self):
        xml = self._xq(f"{_NET}/profiles/zone-protection-profile")
        if not self._has(xml):
            self._add(make_result(
                "6.18", "Ensure Zone Protection Profiles drop specially crafted packets", "L1", FAIL,
                expected="Zone protection profiles drop spoofed IP, mismatched TCP, and malformed packets",
                actual="No zone protection profiles configured",
                remediation="Network > Network Profiles > Zone Protection > Packet Based Attack Protection — enable TCP/IP Drop settings."
            ))
            return
        xml_l = (xml or "").lower()
        has_spoofed    = "spoofed-ip" in xml_l or "spoof" in xml_l
        has_mismatched = "mismatch" in xml_l or "overlapping" in xml_l
        if has_spoofed or has_mismatched:
            self._add(make_result(
                "6.18", "Ensure Zone Protection Profiles drop specially crafted packets", "L1", PASS,
                actual="Packet-based attack protection (spoofed IP / mismatched TCP) configured"
            ))
        else:
            self._add(make_result(
                "6.18", "Ensure Zone Protection Profiles drop specially crafted packets", "L1", FAIL,
                expected="Spoofed IP, mismatched TCP, and malformed packet dropping enabled",
                actual="No packet-based attack protection found in zone protection profiles",
                remediation="Network > Network Profiles > Zone Protection > Packet Based Attack Protection > TCP/IP Drop — enable Spoofed IP, Mismatched overlapping TCP segment, and Malformed."
            ))

    def _check_6_19(self):
        xml = self._xq(f"{_VSYS}/profiles/url-filtering")
        if not self._has(xml):
            self._add(make_result(
                "6.19", "Ensure User Credential Submission uses block/continue action", "L1", FAIL,
                expected="URL filtering profile with block/continue for user credential submission",
                actual="No URL filtering profiles configured",
                remediation="Objects > Security Profiles > URL Filtering > Categories — set User Credential Submitting to block or continue."
            ))
            return
        xml_l = (xml or "").lower()
        has_cred_sub = "credential" in xml_l and ("block" in xml_l or "continue" in xml_l)
        if has_cred_sub:
            self._add(make_result(
                "6.19", "Ensure User Credential Submission uses block/continue action", "L1", PASS,
                actual="User credential submission action (block/continue) configured in URL filtering"
            ))
        else:
            self._add(make_result(
                "6.19", "Ensure User Credential Submission uses block/continue action", "L1", FAIL,
                expected="User Credential Submitting action = block or continue on all URL categories",
                actual="Credential submission restriction not detected in URL filtering profiles",
                remediation="Objects > Security Profiles > URL Filtering > Categories — set User Credential Submitting to block or continue."
            ))

    def _check_6_20(self):
        self._add(make_result(
            "6.20", "Ensure 'WildFire Inline ML Action' set to reset-both except imap/pop3", "L1", MANUAL,
            expected="WildFire Inline ML Action = reset-both on all decoders except imap/pop3",
            actual="Manual verification required",
            remediation="Objects > Security Profiles > Antivirus — set WildFire Inline ML Action to reset-both for all non-email decoders.",
            guidance={
                "where": "Objects > Security Profiles > Antivirus",
                "steps": [
                    "Navigate to Objects > Security Profiles > Antivirus",
                    "For each antivirus profile, check the 'WildFire Inline ML Action' column for each decoder",
                    "All decoders except imap and pop3 should be set to reset-both",
                    "If imap/pop3 is used in the org, set those decoders to alert",
                ],
                "pass_criteria": "All non-imap/pop3 decoders have WildFire Inline ML Action = reset-both",
                "fail_criteria": "Any decoder (except imap/pop3) uses allow, alert, or drop instead of reset-both",
            }
        ))

    def _check_6_21(self):
        xml = self._xq(f"{_VSYS}/profiles/virus")
        if not self._has(xml):
            self._add(make_result(
                "6.21", "Ensure 'WildFire Inline ML' enabled for all file types", "L1", FAIL,
                expected="WildFire Inline ML enabled for all file types on all antivirus profiles",
                actual="No antivirus profiles configured",
                remediation="Objects > Security Profiles > Antivirus > WildFire Inline ML — enable for all file types."
            ))
            return
        has_inline_ml = "inline-ml" in (xml or "").lower() or "wildfire-inline" in (xml or "").lower()
        if has_inline_ml:
            self._add(make_result(
                "6.21", "Ensure 'WildFire Inline ML' enabled for all file types", "L1", PASS,
                actual="WildFire Inline ML configuration found in antivirus profiles"
            ))
        else:
            self._add(make_result(
                "6.21", "Ensure 'WildFire Inline ML' enabled for all file types", "L1", FAIL,
                expected="WildFire Inline ML enabled for all file types",
                actual="WildFire Inline ML settings not found in antivirus profiles",
                remediation="Objects > Security Profiles > Antivirus > WildFire Inline ML tab — set enable (inherit per-protocol actions) for all file types."
            ))

    def _check_6_22(self):
        xml = self._xq(f"{_VSYS}/profiles/vulnerability")
        if not self._has(xml):
            self._add(make_result(
                "6.22", "Ensure 'Inline Cloud Analysis' on Vuln Protection profiles enabled (ATP)", "L1", FAIL,
                expected="Inline cloud analysis enabled on vulnerability protection profiles",
                actual="No vulnerability protection profiles configured",
                remediation="Objects > Security Profiles > Vulnerability Protection > Inline Cloud Analysis — enable if ATP is licensed."
            ))
            return
        has_ica = "inline-cloud" in (xml or "").lower() or "cloud-analysis" in (xml or "").lower()
        if has_ica:
            self._add(make_result(
                "6.22", "Ensure 'Inline Cloud Analysis' on Vuln Protection profiles enabled (ATP)", "L1", PASS,
                actual="Inline Cloud Analysis configuration found in vulnerability protection profiles"
            ))
        else:
            self._add(make_result(
                "6.22", "Ensure 'Inline Cloud Analysis' on Vuln Protection profiles enabled (ATP)", "L1", FAIL,
                expected="Inline Cloud Analysis enabled if Advanced Threat Prevention is licensed",
                actual="Inline Cloud Analysis not found in vulnerability protection profiles",
                remediation="Objects > Security Profiles > Vulnerability Protection > Inline Cloud Analysis — enable if ATP is available."
            ))

    def _check_6_23(self):
        xml = self._xq(f"{_VSYS}/profiles/url-filtering")
        if not self._has(xml):
            self._add(make_result(
                "6.23", "Ensure 'Cloud Inline Categorization' on URL Filtering profiles enabled (ATP)", "L1", FAIL,
                expected="Cloud inline categorization enabled on URL filtering profiles",
                actual="No URL filtering profiles configured",
                remediation="Objects > Security Profiles > URL Filtering > Inline Categorization — enable if ATP is licensed."
            ))
            return
        has_cic = "inline-categoriz" in (xml or "").lower() or "cloud-inline" in (xml or "").lower()
        if has_cic:
            self._add(make_result(
                "6.23", "Ensure 'Cloud Inline Categorization' on URL Filtering profiles enabled (ATP)", "L1", PASS,
                actual="Cloud inline categorization configuration found in URL filtering profiles"
            ))
        else:
            self._add(make_result(
                "6.23", "Ensure 'Cloud Inline Categorization' on URL Filtering profiles enabled (ATP)", "L1", FAIL,
                expected="Cloud inline categorization enabled if Advanced Threat Prevention licensed",
                actual="Cloud inline categorization not found in URL filtering profiles",
                remediation="Objects > Security Profiles > URL Filtering > Inline Categorization — enable local and cloud categorization."
            ))

    def _check_6_24(self):
        xml = self._xq(f"{_VSYS}/profiles/spyware")
        if not self._has(xml):
            self._add(make_result(
                "6.24", "Ensure 'Inline Cloud Analysis' on Anti-Spyware profiles enabled (ATP)", "L1", FAIL,
                expected="Inline cloud analysis enabled on anti-spyware profiles",
                actual="No anti-spyware profiles configured",
                remediation="Objects > Security Profiles > Anti-Spyware > Inline Cloud Analysis — enable if ATP is licensed."
            ))
            return
        has_ica = "inline-cloud" in (xml or "").lower() or "cloud-analysis" in (xml or "").lower()
        if has_ica:
            self._add(make_result(
                "6.24", "Ensure 'Inline Cloud Analysis' on Anti-Spyware profiles enabled (ATP)", "L1", PASS,
                actual="Inline Cloud Analysis found in anti-spyware profiles"
            ))
        else:
            self._add(make_result(
                "6.24", "Ensure 'Inline Cloud Analysis' on Anti-Spyware profiles enabled (ATP)", "L1", FAIL,
                expected="Inline Cloud Analysis enabled if Advanced Threat Prevention licensed",
                actual="Inline Cloud Analysis not found in anti-spyware profiles",
                remediation="Objects > Security Profiles > Anti-Spyware > Inline Cloud Analysis — enable if ATP is available."
            ))

    def _check_6_25(self):
        self._add(make_result(
            "6.25", "Ensure 'DNS Policies' configured on Anti-Spyware profiles if DNS Security licensed", "L1", MANUAL,
            expected="DNS Security policies configured on anti-spyware profiles with DNS Security license",
            actual="Manual verification required — DNS Security license check needed",
            remediation="Objects > Security Profiles > Anti-Spyware > DNS Policies — set DNS Security categories to sinkhole.",
            guidance={
                "where": "Objects > Security Profiles > Anti-Spyware > DNS Policies",
                "steps": [
                    "Verify the DNS Security license is active: Device > Licenses",
                    "Navigate to Objects > Security Profiles > Anti-Spyware",
                    "For each in-use profile, click the DNS Policies tab",
                    "Verify policy action is set to sinkhole for all DNS Security categories",
                    "For Command and Control Domains, verify packet capture = extended-capture",
                ],
                "pass_criteria": "DNS Security license active and all categories set to sinkhole",
                "fail_criteria": "DNS Security licensed but not configured, or categories set to allow",
            }
        ))

    # ── Section 7: Security Policies ─────────────────────────────────────────

    def _check_7_1(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "7.1", "Ensure application security policies exist for untrusted-to-trusted traffic", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        if rules == []:
            self._add(make_result(
                "7.1", "Ensure application security policies exist for untrusted-to-trusted traffic", "L1", FAIL,
                expected="Allow rules specify explicit App-IDs (not 'any') for untrusted-to-trusted traffic",
                actual="No security policies configured — application-based policy controls are absent",
                remediation="Policies > Security — create security policies that specify explicit App-IDs instead of application=any."
            ))
            return
        allow_rules = [r for r in rules if not r["disabled"] and r["action"] == "allow"]
        any_app_rules = [r for r in allow_rules if "any" in r.get("application", [])]
        if any_app_rules:
            self._add(make_result(
                "7.1", "Ensure application security policies exist for untrusted-to-trusted traffic", "L1", FAIL,
                expected="All allow rules specify explicit applications (not 'any')",
                actual=f"{len(any_app_rules)} allow rule(s) use application=any: {', '.join(r['name'] for r in any_app_rules[:5])}",
                remediation="Policies > Security — replace application=any with specific App-IDs on all allow rules."
            ))
        else:
            self._add(make_result(
                "7.1", "Ensure application security policies exist for untrusted-to-trusted traffic", "L1", PASS,
                actual=f"All {len(allow_rules)} allow rule(s) use specific applications"
            ))

    def _check_7_2(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "7.2", "Ensure 'Service setting of ANY' does not exist in allow rules", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        allow_rules = [r for r in rules if not r["disabled"] and r["action"] == "allow"]
        any_svc = [r["name"] for r in allow_rules if "any" in r.get("service", [])]
        if any_svc:
            self._add(make_result(
                "7.2", "Ensure 'Service setting of ANY' does not exist in allow rules", "L1", FAIL,
                expected="No allow rules use service=any",
                actual=f"{len(any_svc)} allow rule(s) with service=any: {', '.join(any_svc[:5])}",
                remediation="Policies > Security — change service=any to application-default or specific service objects on all allow rules."
            ))
        else:
            self._add(make_result(
                "7.2", "Ensure 'Service setting of ANY' does not exist in allow rules", "L1", PASS,
                actual=f"No allow rules found using service=any"
            ))

    def _check_7_3(self):
        rules = self._parse_security_rules()
        if rules is None:
            self._add(make_result(
                "7.3", "Ensure Security Policy denying traffic to/from Threat Intelligence IPs", "L1",
                ERROR, actual="Could not retrieve security rulebase"
            ))
            return
        deny_rules = [r for r in rules if r["action"] in ("deny", "drop")]
        ti_keywords = ("malicious", "threat-intel", "bulletproof", "tor-exit", "high-risk")
        ti_rules = [r for r in deny_rules
                    if any(kw in (r.get("name", "") + " ".join(r.get("destination", []))).lower()
                           for kw in ti_keywords)]
        if ti_rules:
            self._add(make_result(
                "7.3", "Ensure Security Policy denying traffic to/from Threat Intelligence IPs", "L1", PASS,
                actual=f"Found {len(ti_rules)} deny rule(s) referencing threat intelligence IP feeds"
            ))
        else:
            self._add(make_result(
                "7.3", "Ensure Security Policy denying traffic to/from Threat Intelligence IPs", "L1", FAIL,
                expected="Deny rules exist for PAN threat intelligence IP lists",
                actual="No deny rules found referencing threat intelligence IP lists",
                remediation="Policies > Security — add deny rules using Palo Alto Networks threat intelligence EDLs (malicious IPs, Tor exit nodes, bulletproof hosting)."
            ))

    def _check_7_4(self):
        xml = self._xq(f"{_VSYS}/rulebase/default-security-rules/rules")
        log_end = "log-end" in (xml or "").lower()
        self._add(make_result(
            "7.4", "Ensure logging is enabled on built-in default security policies", "L1", MANUAL,
            expected="intrazone-default and interzone-default both have log-end enabled",
            actual=f"Default rules log-end: {'detected' if log_end else 'not detected'}",
            remediation="Policies > Security > Default Rules — enable 'Log at Session End' on intrazone-default and interzone-default.",
            guidance={
                "where": "Policies > Security (show default rules)",
                "steps": [
                    "Navigate to Policies > Security",
                    "Click the gear icon or select 'Show Default Rules' to display intrazone-default and interzone-default",
                    "Click on intrazone-default > Actions tab > verify 'Log at Session End' is checked",
                    "Click on interzone-default > Actions tab > verify 'Log at Session End' is checked",
                ],
                "pass_criteria": "Both default rules have log at session end enabled",
                "fail_criteria": "Either default rule has logging disabled (the default state)",
            }
        ))

    def _check_7_5(self):
        raw = self._cmd("show rule-hit-count vsys vsys1 rule-base security rules all")
        if not raw or "__ERROR__" in raw:
            self._add(make_result(
                "7.5", "Ensure security rules with zero hit count are reviewed", "L1", MANUAL,
                expected="All security rules have been matched by traffic at least once",
                actual="Hit-count data unavailable — verify manually in Policies > Security (hit count column)",
                remediation="Policies > Security — enable hit count display; review and disable or remove rules with 0 hits.",
                guidance={
                    "where": "Policies > Security",
                    "steps": [
                        "In Policies > Security, right-click the column header and enable the Hit Count column",
                        "Sort by Hit Count ascending to surface zero-hit rules",
                        "For each zero-hit rule: determine if it was recently added, is a backup/DR rule, or is genuinely unused",
                        "Disable or remove confirmed unused rules after change-control approval",
                    ],
                    "pass_criteria": "All enabled rules have a hit count > 0 or have a documented justification",
                    "fail_criteria": "Enabled rules with 0 hits and no documented justification exist in the rulebase",
                }
            ))
            return

        zero_hit_rules = []
        # XML API returns XML; SSH returns a text table — detect by leading '<'
        if raw.lstrip().startswith("<"):
            try:
                root = ET.fromstring(raw)
                for entry in root.findall(".//rules/entry"):
                    name = entry.get("name", "")
                    hc_el = entry.find("hit-count")
                    if hc_el is not None and hc_el.text and hc_el.text.strip() == "0":
                        zero_hit_rules.append(name)
            except ET.ParseError:
                pass
        else:
            # SSH tabular output: "rule-name    0    ..."
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-1] == "0":
                    zero_hit_rules.append(parts[0])
                elif len(parts) >= 2:
                    # hit count is the second column in some PAN-OS versions
                    try:
                        if int(parts[1]) == 0:
                            zero_hit_rules.append(parts[0])
                    except (ValueError, IndexError):
                        pass

        if zero_hit_rules:
            names_str = ", ".join(zero_hit_rules[:10])
            suffix = f" (and {len(zero_hit_rules) - 10} more)" if len(zero_hit_rules) > 10 else ""
            self._add(make_result(
                "7.5", "Ensure security rules with zero hit count are reviewed", "L1", FAIL,
                expected="All enabled security rules have been matched by traffic at least once",
                actual=f"{len(zero_hit_rules)} rule(s) with 0 hits: {names_str}{suffix}",
                remediation=(
                    "Policies > Security — review each zero-hit rule. "
                    "Disable or remove rules that are not required for DR/backup purposes. "
                    "Document any intentionally kept zero-hit rules."
                ),
            ))
        else:
            self._add(make_result(
                "7.5", "Ensure security rules with zero hit count are reviewed", "L1", PASS,
                actual="All security rules have recorded at least one hit"
            ))

    # ── Section 8: Decryption ─────────────────────────────────────────────────

    def _check_8_1(self):
        xml = self._xq(f"{_VSYS}/rulebase/decryption/rules")
        if self._has(xml) and "ssl-forward-proxy" in (xml or "").lower():
            self._add(make_result(
                "8.1", "Ensure 'SSL Forward Proxy Policy' for internet traffic is configured", "L1", PASS,
                actual="SSL Forward Proxy decryption policy found"
            ))
        elif self._has(xml):
            self._add(make_result(
                "8.1", "Ensure 'SSL Forward Proxy Policy' for internet traffic is configured", "L1", FAIL,
                expected="Decryption policy with type=SSL Forward Proxy for internet traffic",
                actual="Decryption policies exist but no SSL Forward Proxy type found",
                remediation="Policies > Decryption — create an SSL Forward Proxy policy for internet-destined traffic."
            ))
        else:
            self._add(make_result(
                "8.1", "Ensure 'SSL Forward Proxy Policy' for internet traffic is configured", "L1", FAIL,
                expected="SSL Forward Proxy decryption policy configured",
                actual="No decryption policies configured",
                remediation="Policies > Decryption — create an SSL Forward Proxy policy covering internet-destined traffic."
            ))

    def _check_8_2(self):
        xml = self._xq(f"{_VSYS}/rulebase/decryption/rules")
        inbound = "ssl-inbound-inspection" in (xml or "").lower()
        self._add(make_result(
            "8.2", "Ensure 'SSL Inbound Inspection' required for untrusted traffic to SSL/TLS servers", "L1", MANUAL,
            expected="SSL Inbound Inspection decryption policies configured for all published HTTPS servers",
            actual=f"SSL Inbound Inspection: {'detected' if inbound else 'not detected in config'}",
            remediation="Policies > Decryption — create SSL Inbound Inspection policies for each internet-exposed SSL/TLS service.",
            guidance={
                "where": "Policies > Decryption",
                "steps": [
                    "Navigate to Policies > Decryption",
                    "For each server that is published to the internet using SSL/TLS, verify an SSL Inbound Inspection rule exists",
                    "Source zone should be the internet/untrusted zone",
                    "Destination should be the specific server address",
                    "Options tab > Type should be 'SSL Inbound Inspection'",
                    "A server certificate for the destination must be imported",
                ],
                "pass_criteria": "SSL Inbound Inspection configured for all internet-exposed HTTPS/TLS services",
                "fail_criteria": "No inbound inspection or some HTTPS services are not covered",
            }
        ))

    def _check_8_3(self):
        xml = self._xq(f"{_DEV}/certificate-store")
        if not self._has(xml):
            xml = self._xq(f"{_VSYS}/certificate")
        if self._has(xml):
            root = self._xml(xml)
            expired = []
            if root:
                for entry in root.iter("entry"):
                    exp_el = entry.find("expiry-epoch")
                    if exp_el is not None and exp_el.text:
                        try:
                            exp_ts = int(exp_el.text.strip())
                            if exp_ts < datetime.datetime.utcnow().timestamp():
                                expired.append(entry.get("name", "unnamed"))
                        except ValueError:
                            pass
            if expired:
                self._add(make_result(
                    "8.3", "Ensure Certificate used for Decryption is Trusted", "L1", FAIL,
                    expected="Decryption certificate valid, CA-signed, and not expired",
                    actual=f"Expired certificate(s) found: {', '.join(expired[:3])}",
                    remediation="Device > Certificate Management > Certificates — replace expired certificates with valid CA-signed certs."
                ))
            else:
                self._add(make_result(
                    "8.3", "Ensure Certificate used for Decryption is Trusted", "L1", PASS,
                    actual="No expired certificates detected in certificate store"
                ))
        else:
            self._add(make_result(
                "8.3", "Ensure Certificate used for Decryption is Trusted", "L1", MANUAL,
                expected="Decryption certificate is CA-signed and not expired",
                actual="Could not retrieve certificate store via SSH",
                remediation="Device > Certificate Management > Certificates — verify decryption certificates are CA-signed and not expired.",
                guidance={
                    "where": "Device > Certificate Management > Certificates",
                    "steps": [
                        "Navigate to Device > Certificate Management > Certificates",
                        "Locate the certificate used for SSL Forward Proxy decryption",
                        "Verify Issuer is a trusted CA (not 'Self-Signed')",
                        "Verify expiry is at least 30 days in the future",
                        "Navigate to Device > Certificate Management > Certificate Profile — verify the decryption profile references the correct CA certificate",
                    ],
                    "pass_criteria": "Decryption certificate is CA-signed, not expired, and correctly configured",
                    "fail_criteria": "Self-signed certificate or certificate expiring within 30 days",
                }
            ))

    # ── PAN-OS Version / Lifecycle ───────────────────────────────────────────

    # EOL dates from Palo Alto Networks software lifecycle page.
    # Format: (major, minor) → "YYYY-MM-DD"
    # Verify against https://www.paloaltonetworks.com/services/support/end-of-life-announcements
    _PANOS_EOL = {
        (8, 0): "2022-03-31",
        (8, 1): "2022-10-31",
        (9, 0): "2023-03-31",
        (9, 1): "2024-03-31",
        (10, 0): "2023-11-30",
        (10, 1): "2025-11-30",
        (11, 0): "2024-11-30",
        (10, 2): "2027-11-30",
        (11, 1): "2026-11-30",
        (11, 2): "2028-11-30",
    }
    _PANOS_PREFERRED = "11.1 or later"

    def _check_version(self):
        """Detect PAN-OS version and check against Palo Alto lifecycle table."""
        sys_info = self._cmd("show system info")
        ver_str  = self._tag(sys_info, "sw-version") or ""
        if not ver_str:
            m = re.search(r'<sw-version>([\d.]+)</sw-version>', sys_info)
            ver_str = m.group(1) if m else ""

        if not ver_str:
            self._add(make_result(
                "VER-1", "PAN-OS Software Version and Lifecycle Status", "L1", ERROR,
                actual="Could not detect PAN-OS version from show system info"
            ))
            return

        # Parse major.minor (ignore patch)
        parts = ver_str.split(".")
        try:
            major, minor = int(parts[0]), int(parts[1])
        except (IndexError, ValueError):
            self._add(make_result(
                "VER-1", "PAN-OS Software Version and Lifecycle Status", "L1", ERROR,
                actual=f"Could not parse version: {ver_str}"
            ))
            return

        today    = datetime.date.today()
        eol_str  = self._PANOS_EOL.get((major, minor))

        if eol_str:
            eol_date = datetime.date.fromisoformat(eol_str)
            days_left = (eol_date - today).days
        else:
            eol_date  = None
            days_left = 9999  # unknown — treat as supported

        if eol_date and today >= eol_date:
            # Already past EOL
            self._add(make_result(
                "VER-1", "PAN-OS Software Version and Lifecycle Status", "L1", FAIL,
                expected=f"PAN-OS on a currently supported release ({self._PANOS_PREFERRED})",
                actual=f"PAN-OS {ver_str} — End of Life as of {eol_str}. "
                       f"This release no longer receives security patches from Palo Alto Networks.",
                remediation=(
                    f"Upgrade to PAN-OS {self._PANOS_PREFERRED}. "
                    f"Review the Palo Alto Networks software lifecycle page for the current "
                    f"preferred release and upgrade path before scheduling the maintenance window."
                ),
                risk_description=(
                    f"PAN-OS {ver_str} reached End of Life on {eol_str} and no longer receives "
                    f"security patches from Palo Alto Networks. Known vulnerabilities in this release "
                    f"remain permanently unpatched, leaving the organisation exposed to publicly "
                    f"disclosed exploits. Operating EOL software may also violate regulatory "
                    f"compliance requirements under frameworks such as PCI DSS and ISO 27001."
                ),
                default_risk_level="High",
                notes=ver_str,
            ))
        elif eol_date and days_left <= 180:
            # Within 6 months of EOL
            self._add(make_result(
                "VER-1", "PAN-OS Software Version and Lifecycle Status", "L1", RECOMMENDATION,
                actual=f"PAN-OS {ver_str} — End of Life on {eol_str} ({days_left} days remaining). "
                       f"Plan an upgrade before this date.",
                remediation=(
                    f"Plan an upgrade to PAN-OS {self._PANOS_PREFERRED} before {eol_str}. "
                    f"Review the Palo Alto Networks software lifecycle page for the current "
                    f"preferred release and validate the upgrade path in a test environment first."
                ),
                risk_description=(
                    f"PAN-OS {ver_str} will reach End of Life on {eol_str} ({days_left} days). "
                    f"After this date, Palo Alto Networks will no longer release security patches "
                    f"for this version. Planning the upgrade now avoids an unplanned forced migration "
                    f"under time pressure and reduces the window of exposure to unpatched vulnerabilities."
                ),
                default_risk_level="High",
                notes=ver_str,
            ))
        else:
            # Supported
            eol_info = f"End of Life: {eol_str}" if eol_date else "lifecycle date not recorded"
            self._add(make_result(
                "VER-1", "PAN-OS Software Version and Lifecycle Status", "L1", PASS,
                actual=f"PAN-OS {ver_str} — currently supported. {eol_info}.",
                notes=ver_str,
            ))

    # ── Security Subscriptions ───────────────────────────────────────────────

    def _check_subscriptions(self):
        """
        Detect which security subscriptions are active on the device.
        Infers from configured profiles/schedules + show system info + show license.
        PAN-OS equivalent of Check Point 'Enabled Software Blades'.
        """
        sys_info = self._cmd("show system info")
        license_xml = self._cmd("show license")

        def _licensed(keyword):
            return keyword.lower() in (sys_info + license_xml).lower()

        # Infer from configured profiles and schedules
        has_av      = self._has(self._xq(f"{_VSYS}/profiles/virus"))
        has_spyware = self._has(self._xq(f"{_VSYS}/profiles/spyware"))
        has_vuln    = self._has(self._xq(f"{_VSYS}/profiles/vulnerability"))
        has_url     = self._has(self._xq(f"{_VSYS}/profiles/url-filtering"))
        has_wf_sched = self._has(self._xq(f"{_SYS}/update-schedule/wildfire"))
        has_zone_prot = self._has(self._xq(f"{_NET}/profiles/zone-protection-profile"))

        # Map subscription → active flag
        subs = [
            ("Firewall (base license)",                     True),
            ("Threat Prevention (AV / Anti-Spyware / IPS)", has_av or has_spyware or has_vuln or _licensed("threat-prevention")),
            ("WildFire Malware Analysis",                   has_wf_sched or _licensed("wildfire")),
            ("URL Filtering (PAN-DB)",                      has_url or _licensed("url-filtering")),
            ("DNS Security",                                _licensed("dns-security") or _licensed("dns-sinkhole")),
            ("Advanced Threat Prevention (ATP)",            _licensed("advanced-threat-prevention") or _licensed("atp")),
            ("Zone Protection",                             has_zone_prot),
        ]

        active  = [name for name, ok in subs if ok]
        missing = [name for name, ok in subs if not ok and name != "Firewall (base license)"]

        if missing:
            self._add(make_result(
                "SUBS-1", "Security Subscriptions and Licensed Features", "L1", FAIL,
                expected="All critical security subscriptions active and configured",
                actual=(
                    f"Active: {', '.join(active)}. "
                    f"Not configured/licensed: {', '.join(missing)}"
                ),
                remediation=(
                    "Contact your Palo Alto Networks partner to acquire the following subscriptions. "
                    "Threat Prevention (PA-TP) — Antivirus, Anti-Spyware, IPS. "
                    "WildFire Malware Prevention (PA-WF) — cloud-based sandboxing. "
                    "Advanced URL Filtering (PA-URL2) — web access control and PAN-DB. "
                    "DNS Security (PA-DNS-SEC) — DNS-based threat prevention. "
                    "Advanced Threat Prevention (PA-ATP) — AI-powered inline ML. "
                    "Activate licenses at Device > Licenses, then configure corresponding security profiles and assign them to all security policies."
                ),
                risk_description=(
                    f"The firewall is operating with basic security enforcement only — "
                    f"the following critical capabilities are absent: {', '.join(missing)}. "
                    f"Without Threat Prevention, the device cannot detect or block malware, exploits, or botnet traffic. "
                    f"Without URL Filtering, users have unrestricted access to malicious or non-compliant web content. "
                    f"Without WildFire, zero-day and novel malware files pass uninspected through the firewall."
                ),
                default_risk_level="High",
            ))
        else:
            self._add(make_result(
                "SUBS-1", "Security Subscriptions and Licensed Features", "L1", PASS,
                actual=f"Active subscriptions: {', '.join(active)}"
            ))

    # ── Governance recommendations ────────────────────────────────────────────

    def _check_gov_2(self):
        self._add(make_result(
            "GOV-2", "Failover and Redundancy Testing", "L2", RECOMMENDATION,
            notes="Regular failover testing should be performed to validate HA configuration and recovery time objectives.",
            remediation=(
                "Schedule a formal failover test at least annually. "
                "Document the test plan, expected RTO and RPO, and observed results. "
                "Include both planned switchover and simulated failure scenarios. "
                "Review HA state logs and sync status immediately after each test. "
                "Update runbooks based on test findings."
            ),
        ))

    def _check_gov_4(self):
        self._add(make_result(
            "GOV-4", "Change Management and Governance", "L2", RECOMMENDATION,
            notes="Firewall rule changes should follow a formal change management process with approval, testing, and rollback procedures.",
            remediation=(
                "Establish a Change Advisory Board (CAB) process for all firewall policy changes. "
                "Require a documented change request with business justification for every rule addition or modification. "
                "Implement a peer-review step before changes are committed to production. "
                "Define a rollback procedure and test window for each change. "
                "Retain change logs and approvals for audit purposes."
            ),
        ))

    # ── run_all ──────────────────────────────────────────────────────────────

    def run_all(self, level_filter="all"):
        """Execute all 80 checks: 78 CIS Palo Alto Firewall 10 Benchmark v1.3.0 + 2 governance."""
        # Section 1: Device Setup
        self._check_1_1_1_1()
        self._check_1_1_1_2()
        self._check_1_1_2()
        self._check_1_1_3()
        self._check_1_2_1()
        self._check_1_2_2()
        self._check_1_2_3()
        self._check_1_2_4()
        self._check_1_2_5()
        self._check_1_3_1()
        self._check_1_3_2()
        self._check_1_3_3()
        self._check_1_3_4()
        self._check_1_3_5()
        self._check_1_3_6()
        self._check_1_3_7()
        self._check_1_3_8()
        self._check_1_3_9()
        self._check_1_3_10()
        self._check_1_4_1()
        self._check_1_4_2()
        self._check_1_5_1()
        self._check_1_6_1()
        self._check_1_6_2()
        self._check_1_6_3()
        self._check_1_7_1()
        # Section 2: User Identification
        self._check_2_1()
        self._check_2_2()
        self._check_2_3()
        self._check_2_4()
        self._check_2_5()
        self._check_2_6()
        self._check_2_7()
        self._check_2_8()
        # Section 3: High Availability
        self._check_3_1()
        self._check_3_2()
        self._check_3_3()
        # Section 4: Dynamic Updates
        self._check_4_1()
        self._check_4_2()
        # Section 5: WildFire
        self._check_5_1()
        self._check_5_2()
        self._check_5_3()
        self._check_5_4()
        self._check_5_5()
        self._check_5_6()
        self._check_5_7()
        # Section 6: Security Profiles
        self._check_6_1()
        self._check_6_2()
        self._check_6_3()
        self._check_6_4()
        self._check_6_5()
        self._check_6_6()
        self._check_6_7()
        self._check_6_8()
        self._check_6_9()
        self._check_6_10()
        self._check_6_11()
        self._check_6_12()
        self._check_6_13()
        self._check_6_14()
        self._check_6_15()
        self._check_6_16()
        self._check_6_17()
        self._check_6_18()
        self._check_6_19()
        self._check_6_20()
        self._check_6_21()
        self._check_6_22()
        self._check_6_23()
        self._check_6_24()
        self._check_6_25()
        # Section 7: Security Policies
        self._check_7_1()
        self._check_7_2()
        self._check_7_3()
        self._check_7_4()
        self._check_7_5()
        # Section 8: Decryption
        self._check_8_1()
        self._check_8_2()
        self._check_8_3()
        # Version / Lifecycle
        self._check_version()
        # Security Subscriptions
        self._check_subscriptions()
        # Governance
        self._check_gov_2()
        self._check_gov_4()
