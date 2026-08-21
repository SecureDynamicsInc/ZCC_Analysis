"""
Detector: Captive Portal errors.

Issue #4 in the user spec. Per the official Zscaler ZCC Traffic
Forwarding Troubleshooting Runbook (Captive Portal Error section),
ZCC handles captive portals by:

  1. Periodically probing ``http://gateway.<cloud>.net/zcc_conn_test``
     (or ``/generate_204``) and expecting an HTTP 204 response.
  2. If the response is anything else (200 with portal HTML, 302
     redirect, 4xx, timeout), ZCC concludes a captive portal is in
     the way and enters ``CAPTIVE_PORTAL_FAILOPEN`` state for the
     configured ``automaticCaptureDuration`` minutes.
  3. If the user doesn't authenticate to the captive portal in time,
     the state transitions to ``CAPTIVE_PORTAL_ERROR``.

The probing is done by ZCC's ZCPM (Zscaler Captive Portal Module),
which logs a clean lifecycle to ZSATunnel.log:

    ZCPM Using company configured URL. Host: [...], URI: [/zcc_conn_test]
    ZCPM Captive detection starting through URL: ...
    ZCPM detectCaptive: Connecting to url: ...
    ZCPM detectCaptive: Server: ...
    ZCPM detectCaptive: Response Status <CODE> Length: <N> ...
    ZCPM Captive portal {not detected | detected}.
    ZCPM sending captive detected notification to observers: {NOT_DETECTED | DETECTED}
    ZCPM observers finished processing notification

Healthy bundles emit ``Response Status 204``, ``Captive portal not
detected``, and ``NOT_DETECTED`` / ``DETECTING`` notifications.

This detector watches for:

  * ``CAPTIVE_PORTAL_ERROR`` proxy-state transitions (CRITICAL --
    user is stuck because they didn't auth in time)
  * ``CAPTIVE_PORTAL_FAILOPEN`` proxy-state transitions (WARNING --
    ZCC has detected a captive portal and is bypassing interception
    temporarily)
  * The ``DETECTED`` notification (CRITICAL -- a portal was actually
    seen)
  * The ``Captive portal detected.`` phrase (defensive duplicate)
  * Non-204 ``Response Status`` from the ZCPM probe -- watched at the
    DEBUG level since that's where it's logged
  * The user-facing tray string ``Captive Portal Detected``

CALIBRATION NOTE: None of the three real bundles available during
development contained a captive-portal failure. Detector grounded in
the runbook + healthy-bundle absence of failure shapes. Synthetic
test cases verify both the planted-failure paths and that the healthy
NOT_DETECTED / DETECTING / 204-response patterns don't false-fire.
"""

from __future__ import annotations

import re
from typing import List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# Canonical state transitions (same syntax as in tunnel detector).
_RE_STATE_CHANGE_CP = re.compile(
    r"Changing\s+(?P<svc>ZIA|ZPA)\s+state\s+from:\s*"
    r"(?P<from>\w+)\s+to\s+(?P<to>CAPTIVE_PORTAL_(?:ERROR|FAILOPEN))"
)

# ZCPM "DETECTED" notification -- the canonical "captive portal IS
# present" signal. Healthy bundles emit ``NOT_DETECTED`` or
# ``DETECTING`` only; ``DETECTED`` indicates the probe got a non-204
# response and ZCPM concluded a portal is in the way.
_RE_ZCPM_DETECTED = re.compile(
    r"ZCPM\s+sending\s+captive\s+detected\s+notification\s+to\s+"
    r"observers:\s*DETECTED\b"
)

# The user-facing tray string. Per the Errors documentation Connection Status
# table, this fires on the tray. Logs sometimes echo the tray status.
# Case-sensitive (capital P, capital D) -- this distinguishes the tray
# echo from the lowercase "captive portal detected state: <VAL>"
# informational log line which has VAL in {IDLE, DETECTING,
# NOT_DETECTED, FORCESTOP, DETECTED} and would otherwise false-fire.
_RE_TRAY_CAPTIVE_DETECTED = re.compile(
    r"Captive\s+Portal\s+Detected",
)

# Non-204 response from the ZCPM probe. Healthy bundles emit:
#     DBG ZCPM detectCaptive: Response Status 204 Length: 0 ...
# Failure: any code other than 204. Match the response-status line and
# extract the code; we'll filter to non-204 in feed().
_RE_ZCPM_RESPONSE_STATUS = re.compile(
    r"ZCPM\s+detectCaptive:\s*Response\s+Status\s+(?P<code>\d+)\b"
)


EVIDENCE_CAP = 10


# --- Detector ---------------------------------------------------------

@register
class CaptivePortalDetector(IssueDetector):
    id = "captive_portal"
    title = "Captive Portal errors"
    sop_file = "captive_portal.md"
    # Cross-suite: captive portal detection happens BEFORE either
    # suite's tunnel comes up. Affects both ZIA and ZPA enrollment.
    applies_to_suite = None

    def __init__(self) -> None:
        super().__init__()
        # state-transition records, separated by severity target
        self._state_error_records: List[LogLine] = []
        self._state_failopen_records: List[LogLine] = []

    # --- IssueDetector overrides ---------------------------------

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # 1. State transitions.
        m = _RE_STATE_CHANGE_CP.search(msg)
        if m:
            target = m.group("to")
            if target == "CAPTIVE_PORTAL_ERROR":
                self._state_error_records.append(record)
            else:  # CAPTIVE_PORTAL_FAILOPEN
                self._state_failopen_records.append(record)
            return

        # 2. ZCPM DETECTED notification.
        if _RE_ZCPM_DETECTED.search(msg):
            f = self._bucket(
                "ZCPM_PORTAL_DETECTED",
                Severity.CRITICAL,
                "Captive portal detected by ZCPM",
                "ZCC's Captive Portal Module (ZCPM) probed "
                "``gateway.<cloud>.net/zcc_conn_test`` (or "
                "``/generate_204``) and got a non-204 response, so "
                "concluded a captive portal is in the way. ZCC will "
                "enter CAPTIVE_PORTAL_FAILOPEN for the configured "
                "automaticCaptureDuration minutes (default 5) to let "
                "the user authenticate via browser. If the user "
                "doesn't auth in time, ZCC moves to "
                "CAPTIVE_PORTAL_ERROR.",
                sop_anchor="#zcpm-portal-detected",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 3. Tray-string echo. Case-sensitive match avoids the
        # lowercase "captive portal detected state: ..." informational
        # logging path.
        if _RE_TRAY_CAPTIVE_DETECTED.search(msg):
            f = self._bucket(
                "TRAY_CAPTIVE_PORTAL_DETECTED",
                Severity.WARNING,
                "Tray showed 'Captive Portal Detected'",
                "The user-facing tray Service Status displayed "
                "'Captive Portal Detected'. Per the Errors documentation, this "
                "means ZCC entered captive-portal-aware fail-open "
                "mode and is waiting for the user to authenticate.",
                sop_anchor="#tray-captive-portal-detected",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 5. Non-204 ZCPM response status.
        m = _RE_ZCPM_RESPONSE_STATUS.search(msg)
        if m:
            try:
                code = int(m.group("code"))
            except ValueError:
                return
            if code != 204:
                f = self._bucket(
                    f"ZCPM_PROBE_NON_204_{code}",
                    Severity.CRITICAL,
                    f"ZCPM probe returned HTTP {code} (expected 204)",
                    f"ZCC's captive-portal probe to "
                    f"``gateway.<cloud>.net/zcc_conn_test`` returned "
                    f"HTTP {code}. A 200 with HTML body usually means "
                    f"a portal is intercepting; 302/301 = redirect to "
                    f"login page; 4xx/5xx = the gateway itself is "
                    f"unreachable through the local network. Healthy "
                    f"value is exactly 204.",
                    sop_anchor="#zcpm-probe-non-204",
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)
            return

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        findings: List[Finding] = list(self._buckets.values())

        if self._state_error_records:
            f = Finding(
                code="CAPTIVE_PORTAL_ERROR_STATE",
                severity=Severity.CRITICAL,
                title=(
                    f"CAPTIVE_PORTAL_ERROR state entered "
                    f"({len(self._state_error_records)} time(s))"
                ),
                description=(
                    "ZCC's proxy state transitioned into "
                    "CAPTIVE_PORTAL_ERROR. Per the Errors documentation "
                    "Registry-Keys table: 'Captive portal has been "
                    "detected on the system and the open timeout has "
                    "expired.' The user did not authenticate to the "
                    "portal within the configured "
                    "automaticCaptureDuration window."
                ),
                sop_anchor="#captive-portal-error-state",
            )
            for rec in self._state_error_records[:EVIDENCE_CAP]:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        if self._state_failopen_records:
            f = Finding(
                code="CAPTIVE_PORTAL_FAILOPEN_STATE",
                severity=Severity.WARNING,
                title=(
                    f"CAPTIVE_PORTAL_FAILOPEN state entered "
                    f"({len(self._state_failopen_records)} time(s))"
                ),
                description=(
                    "Per the Errors documentation: 'ZCC has detected a captive "
                    "portal on the network and stopped traffic "
                    "interception for some time to allow captive "
                    "authentication.' This is a normal transient "
                    "state when joining hotel/airport/cafe Wi-Fi -- "
                    "WARNING rather than CRITICAL because traffic "
                    "still flows around ZCC during fail-open. "
                    "Becomes CRITICAL if it transitions to "
                    "CAPTIVE_PORTAL_ERROR (timeout expired)."
                ),
                sop_anchor="#captive-portal-failopen-state",
            )
            for rec in self._state_failopen_records[:EVIDENCE_CAP]:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        return findings
