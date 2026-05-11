"""
evidence_capture.py — Playwright-based browser evidence capture for PAN-OS.
Takes screenshots of key configuration pages to embed in consulting reports.
All captures are best-effort: failures log a warning and return None.
Credentials are used only for the browser session and are not persisted.

PAN-OS web UI notes (validated on PAN-OS 10.1.0):
- Uses ExtJS 3; detects headless Chrome unless AutomationControlled is disabled
- Submit button (id="submit") starts disabled; submit via Enter key on passwd field
- MOTD dialog appears after page init on a timer; closes via Ext.WindowMgr
- Top nav: <a class="x-pan-pageheader"> elements (DASHBOARD/ACC/MONITOR/…/DEVICE)
- Sub-nav: <a> tree items in the left sidebar after a top tab is clicked
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright, Page, Browser
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Maps control_id → capture method name (shared image per unique method)
EVIDENCE_CHECKS: dict[str, str] = {
    "VER-1":  "capture_version",
    "SUBS-1": "capture_licenses",
    "3.1":    "capture_ha_state",
    "3.2":    "capture_ha_state",
    "3.3":    "capture_ha_state",
    "4.1":    "capture_dynamic_updates",
    "4.2":    "capture_dynamic_updates",
    "6.1":    "capture_security_profiles",
    "6.2":    "capture_security_profiles",
    "6.3":    "capture_security_profiles",
    "6.4":    "capture_security_profiles",
    "6.5":    "capture_security_profiles",
    "6.6":    "capture_security_profiles",
    "6.7":    "capture_security_profiles",
    "6.15":   "capture_zones",
    "6.16":   "capture_zones",
    "6.17":   "capture_zones",
    "6.18":   "capture_zones",
}


class PANOSEvidenceCapture:
    """
    Headless Chromium session against the PAN-OS web UI (10.x/11.x).
    All capture methods return PNG bytes or None on failure.
    Call connect() before any capture; close() when done.
    """

    def __init__(self, host: str, username: str, password: str):
        self._host      = host
        self._username  = username
        self._password  = password
        self._pw        = None
        self._browser: Browser = None
        self._page:    Page    = None
        self._logged_in = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Launch headless Chromium and log in to the PAN-OS web UI."""
        if not HAS_PLAYWRIGHT:
            log.warning("Evidence capture: playwright not installed — skipping")
            return False
        try:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
            )
            ctx = self._browser.new_context(
                ignore_https_errors=True,
                user_agent=_USER_AGENT,
            )
            # Hide webdriver flag — ExtJS detects headless Chrome and refuses to render
            ctx.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            self._page = ctx.new_page()
            self._page.set_viewport_size({"width": 1440, "height": 900})
            self._page.set_default_timeout(15_000)

            self._page.goto(
                f"https://{self._host}", wait_until="domcontentloaded", timeout=20_000
            )

            # PAN-OS submit button starts disabled and is enabled via JS after input.
            # Dispatch change events on both fields, then press Enter to submit.
            self._page.fill('input[name="user"]', self._username)
            self._page.dispatch_event('input[name="user"]', "change")
            self._page.fill('input[name="passwd"]', self._password)
            self._page.dispatch_event('input[name="passwd"]', "change")
            self._page.press('input[name="passwd"]', "Enter")
            self._page.wait_for_load_state("networkidle", timeout=20_000)

            # PAN-OS shows a MOTD dialog on a timer after init; wait for its mask then
            # close all ExtJS windows so the UI is fully interactive.
            try:
                self._page.wait_for_selector(
                    ".ext-el-mask", state="visible", timeout=12_000
                )
            except Exception:
                pass  # no MOTD on this session — proceed
            self._page.evaluate("""(function(){
                if (typeof Ext !== 'undefined' && Ext.WindowMgr)
                    Ext.WindowMgr.each(function(w){ try { w.close(); } catch(e){} });
            })()""")
            self._page.wait_for_timeout(800)

            self._logged_in = True
            log.info("Evidence capture: logged in to %s", self._host)
            return True
        except Exception as exc:
            log.warning("Evidence capture: login failed for %s: %s", self._host, exc)
            self._logged_in = False
            return False

    def close(self) -> None:
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    # ── Navigation helpers ────────────────────────────────────────────────────

    def _nav(self, top_label: str, sub_label: str) -> bool:
        """
        Click the top-level PAN-OS tab (DEVICE/NETWORK/OBJECTS/…) then the
        sidebar tree item (Licenses/Software/Zones/…).
        Uses Playwright native clicks — masks are removed during connect().
        """
        try:
            self._page.locator("a.x-pan-pageheader", has_text=top_label).click(
                timeout=8_000
            )
            self._page.wait_for_timeout(2_000)
            self._page.locator("a", has_text=sub_label).first.click(timeout=8_000)
            self._page.wait_for_timeout(3_000)
            return True
        except Exception as exc:
            log.debug("Evidence capture: nav %s>%s failed: %s", top_label, sub_label, exc)
            return False

    def _screenshot(self) -> bytes | None:
        try:
            self._page.wait_for_timeout(1_000)
            return self._page.screenshot(full_page=False)
        except Exception as exc:
            log.debug("Evidence capture: screenshot failed: %s", exc)
            return None

    # ── Capture methods ───────────────────────────────────────────────────────

    def capture_version(self) -> bytes | None:
        """Device > Software — installed PAN-OS version."""
        try:
            return self._screenshot() if self._nav("DEVICE", "Software") else None
        except Exception as exc:
            log.warning("capture_version failed: %s", exc)
            return None

    def capture_licenses(self) -> bytes | None:
        """Device > Licenses — active subscription licenses."""
        try:
            return self._screenshot() if self._nav("DEVICE", "Licenses") else None
        except Exception as exc:
            log.warning("capture_licenses failed: %s", exc)
            return None

    def capture_ha_state(self) -> bytes | None:
        """Device > High Availability — HA peer and sync state."""
        try:
            return self._screenshot() if self._nav("DEVICE", "High Availability") else None
        except Exception as exc:
            log.warning("capture_ha_state failed: %s", exc)
            return None

    def capture_zones(self) -> bytes | None:
        """Network > Zones — security zone configuration."""
        try:
            return self._screenshot() if self._nav("NETWORK", "Zones") else None
        except Exception as exc:
            log.warning("capture_zones failed: %s", exc)
            return None

    def capture_security_profiles(self) -> bytes | None:
        """Objects > Security Profile Groups — profile group assignments."""
        try:
            return (
                self._screenshot()
                if self._nav("OBJECTS", "Security Profile Groups")
                else None
            )
        except Exception as exc:
            log.warning("capture_security_profiles failed: %s", exc)
            return None

    def capture_dynamic_updates(self) -> bytes | None:
        """Device > Dynamic Updates — update schedules and last-update timestamps."""
        try:
            return self._screenshot() if self._nav("DEVICE", "Dynamic Updates") else None
        except Exception as exc:
            log.warning("capture_dynamic_updates failed: %s", exc)
            return None
