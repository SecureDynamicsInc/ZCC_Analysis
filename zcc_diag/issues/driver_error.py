"""
Detector: Driver Error.

Per the official Zscaler ZCC Traffic Forwarding Troubleshooting Runbook
(Driver Error section), ZCC fails to load its kernel-mode
filter driver and the tray Service Status flips to "Driver Error".

Signatures live in ZSATray logs (NOT ZSATunnel logs):

    ERR LWF: Unable to load driver!
    ERR lwf: Initial driver check FAILED! LightWeightFilter not loaded! ZApp moves to DRIVER ERROR!

A separate signature lives in ``setupapi.dev.log`` (driver install
diagnostic) -- but that file isn't routinely shipped in ZCC support
bundles, so this detector matches only the ZSATray signatures.

CALIBRATION NOTE: None of the three real bundles available during
development contained a Driver Error. Detector grounded in the
runbook quotes + healthy-bundle absence of the failure shapes.
Synthetic tests verify both the planted-failure paths and that
healthy tray logs don't false-fire.

Distinct from other detectors:
  * The ``endpoint_fw_av`` detector watches ``lwfDriverRunning:false``
    in ZSATunnel status JSON. That's an INDIRECT symptom (the driver
    isn't running according to the periodic status poll) -- this
    detector watches the DIRECT failure signal at driver-load time.
  * The runbook treats "Driver Error" as a distinct tray status from
    "Endpoint FW/AV Error", with separate triage (Repair App vs
    AV/EDR allow-list).
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# Documented signatures from the runbook. Both have ERR-level prefix in
# Format A logs, but we don't level-gate because these phrases would
# only appear at error level anyway and the level field already
# distinguishes them.
_RE_LWF_UNABLE_TO_LOAD = re.compile(
    r"\bLWF:?\s*Unable to load driver",
    re.IGNORECASE,
)

_RE_LWF_INITIAL_CHECK_FAILED = re.compile(
    r"\blwf:?\s*Initial driver check FAILED",
    re.IGNORECASE,
)

# Backstop: the runbook also quotes the consequence phrase. Used as
# an additional finding source in case a ZCC version emits one without
# the other.
_RE_LIGHTWEIGHT_FILTER_NOT_LOADED = re.compile(
    r"LightWeightFilter not loaded",
    re.IGNORECASE,
)

# Tray Service Status echo of the canonical tray string.
_RE_TRAY_DRIVER_ERROR = re.compile(
    r"\bDriver Error\b",
)


EVIDENCE_CAP = 10


# --- Detector ---------------------------------------------------------

@register
class DriverErrorDetector(IssueDetector):
    id = "driver_error"
    title = "ZCC Driver Error"
    sop_file = "driver_error.md"
    # Cross-suite: LWF driver failure breaks BOTH ZIA and ZPA tunnels.
    # No suite-filter — gates only on OS (Windows-only here).
    applies_to_suite = None

    # Opt in to tray-log feeding. Tunnel-log feed() remains the default
    # no-op from the base class -- driver errors don't appear in
    # tunnel logs.
    wants_tray_logs = True
    # All current signatures match the Windows LWF kernel driver.
    # macOS kext / system-extension failures are handled separately in
    # ``driver_error_mac.py`` (not yet implemented).
    applies_to_os = ("windows",)

    # --- IssueDetector overrides ---------------------------------

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # 1. Direct LWF load failure.
        if _RE_LWF_UNABLE_TO_LOAD.search(msg):
            f = self._bucket(
                "LWF_UNABLE_TO_LOAD",
                Severity.CRITICAL,
                "LWF driver failed to load",
                "ZCC's tray reported ``LWF: Unable to load driver!``. "
                "The Lightweight Filter (LWF) is the kernel-mode "
                "component that intercepts traffic in modern ZCC. "
                "Per the ZCC Traffic Forwarding runbook, common "
                "causes: driver cache corruption "
                "(C:\\Windows\\System32\\DriverStore), missing "
                "registry entries for the ZCC driver service, "
                "endpoint protection blocking driver installation, "
                "or DriverStore corruption.",
                sop_anchor="#lwf-unable-to-load",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 2. Initial driver check failed at startup.
        if _RE_LWF_INITIAL_CHECK_FAILED.search(msg):
            f = self._bucket(
                "LWF_INITIAL_CHECK_FAILED",
                Severity.CRITICAL,
                "LWF driver check failed at startup",
                "ZCC's tray reported ``Initial driver check FAILED! "
                "LightWeightFilter not loaded! ZApp moves to DRIVER "
                "ERROR!`` This means ZCC started up, queried for "
                "the driver, and got a not-loaded response -- the "
                "tray transitioned to the Driver Error state "
                "immediately.",
                sop_anchor="#lwf-initial-check-failed",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 3. Backstop: LightWeightFilter not loaded phrase.
        if _RE_LIGHTWEIGHT_FILTER_NOT_LOADED.search(msg):
            f = self._bucket(
                "LIGHTWEIGHT_FILTER_NOT_LOADED",
                Severity.CRITICAL,
                "LightWeightFilter not loaded",
                "Backstop pattern -- ZCC logged that the "
                "LightWeightFilter is not loaded, outside the two "
                "canonical phrases. Triage same as "
                "LWF_UNABLE_TO_LOAD.",
                sop_anchor="#lightweightfilter-not-loaded",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 4. Tray-string echo. The tray Service Status flipping to
        # "Driver Error" is the user-facing signal.
        if _RE_TRAY_DRIVER_ERROR.search(msg):
            f = self._bucket(
                "TRAY_DRIVER_ERROR",
                Severity.WARNING,
                "Tray showed 'Driver Error'",
                "The user-facing tray Service Status displayed "
                "'Driver Error'. Per the Errors documentation, ZCC enters "
                "fail-open state in this condition (unless the app "
                "profile enables fail-close).",
                sop_anchor="#tray-driver-error",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
