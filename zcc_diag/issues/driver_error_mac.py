"""
Detector: macOS driver / system extension load failure.

What this catches
-----------------
On macOS, ZCC's data plane is implemented as a Network Extension /
content-filter system extension (modern Big Sur+) or, on older Macs,
a kernel extension (kext). When these fail to load or activate,
ZCC's tunnel can't intercept traffic and the tray shows a state
analogous to Windows' "Driver Error".

This is the macOS analog of ``driver_error.py`` (which catches
Windows LWF driver load failures).

Signal sources
--------------
The bundle's AppInfo.log plist carries a ``SystemExtensions`` block
with per-extension state. State strings to watch for:
  * "activated waiting for user" — sysext approved by app but
    pending user / MDM approval in System Settings.
  * "activated waiting for reboot" — needs a restart to take effect.
  * "deactivated" — was active, now off.
  * "could not be loaded" — kernel rejected the bundle.

The relevant bundle IDs are anything starting with
``com.zscaler.zscaler.`` (pktfilter, dnsproxy, contentfilter, etc).

Additionally, the ZSAService log emits errors when the daemon
tries to start a sysext that's not approved:

    ERR System extension ... is not approved by the user
    ERR Failed to activate system extension ...
    ERR Network Extension provider not running

We harvest both: the structured plist-state field AND the
log-line failure signals.

CALIBRATION NOTE
----------------
Same as fw_av_mac.py — no real Mac bundle in the development
corpus has fired these signals at scale. Grounded in:
  - Apple's documented sysctl OSSystemExtension states
  - Zscaler's macOS deployment guide (sysext approval flow)
  - The Mac-specific Tray status string "System Extension Error"
    that's the macOS equivalent of "Driver Error"

When a real failure bundle is captured, this detector should be
re-validated.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

_RE_SYSEXT_LOAD_FAIL = re.compile(
    r"System\s+extension.{0,80}(?:fail|error|could\s+not)|"
    r"Failed\s+to\s+activate\s+system\s+extension",
    re.IGNORECASE,
)

_RE_SYSEXT_NOT_APPROVED = re.compile(
    r"System\s+extension.{0,80}not\s+approved",
    re.IGNORECASE,
)

# Network Extension provider failures.
_RE_NE_FAIL = re.compile(
    r"Network\s+Extension\s+provider.{0,40}"
    r"(?:not\s+running|stopped|crashed|disconnected|fail)",
    re.IGNORECASE,
)

# Kernel extension load failure (older macOS).
_RE_KEXT_FAIL = re.compile(
    r"kext.{0,60}(?:failed\s+to\s+load|load\s+failed|rejected)|"
    r"OSKext.{0,40}(?:error|fail)|"
    r"kxld.{0,40}(?:error|fail)",
    re.IGNORECASE,
)

# The Tray's "Driver Error" / "System Extension Error" surface state.
_RE_TRAY_SYSEXT_STATE = re.compile(
    r"System\s+Extension\s+Error|"
    r"Driver\s+Error.{0,20}(?:macOS|Mac\s+OS)",
)


EVIDENCE_CAP = 15


# --- Detector ---------------------------------------------------------

@register
class MacDriverErrorDetector(IssueDetector):
    id = "driver_error_mac"
    title = "macOS system extension / kext load failure"
    sop_file = "driver_error.md"  # share SOP with Windows analog
    # Cross-suite: sysext / kext load failure breaks both ZIA and ZPA
    # tunnels equally. Gate is OS-only (macOS).
    applies_to_suite = None

    wants_tray_logs = True
    wants_extra_log_kinds = ("service", "upm", "upm_controller")
    applies_to_os = ("macos",)

    prematch_substrings = (
        "system extension",
        "System extension",
        "System Extension",
        "Network Extension",
        "kext",
        "OSKext",
        "kxld",
        "Driver Error",
    )

    def _scan(self, record: LogLine) -> None:
        msg = record.message

        if _RE_SYSEXT_LOAD_FAIL.search(msg):
            f = self._bucket(
                "MAC_SYSEXT_LOAD_FAIL",
                Severity.CRITICAL,
                "macOS system extension failed to load",
                "A Zscaler system extension failed to activate or "
                "load. Without it, ZCC cannot intercept Mac traffic. "
                "Triage: System Settings -> Privacy & Security -> "
                "scroll to bottom, look for 'System Extension was "
                "blocked' approval prompt; if absent, run "
                "`systemextensionsctl list` in Terminal to see the "
                "per-bundle state. Common causes: user hasn't "
                "approved, MDM hasn't pushed approval, OS upgrade "
                "invalidated the previous approval.",
                sop_anchor="#mac-sysext-load-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        if _RE_SYSEXT_NOT_APPROVED.search(msg):
            f = self._bucket(
                "MAC_SYSEXT_NOT_APPROVED",
                Severity.CRITICAL,
                "macOS system extension not approved",
                "ZCC's system extension is installed but not approved "
                "(user or MDM). ZCC will not intercept traffic until "
                "approval is granted. Push the approval via MDM with "
                "SystemExtensionPayload (TeamID PCBCQZJ7S7 for "
                "Zscaler), or guide the user through System Settings "
                "approval.",
                sop_anchor="#mac-sysext-not-approved",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        if _RE_NE_FAIL.search(msg):
            f = self._bucket(
                "MAC_NETWORK_EXTENSION_FAIL",
                Severity.CRITICAL,
                "macOS Network Extension provider not running",
                "ZCC's Network Extension provider stopped or never "
                "started. The tunnel is effectively non-functional. "
                "Check ``systemextensionsctl list`` for the "
                "com.zscaler.zscaler.pktfilter / .dnsproxy state. "
                "If activated but not running, restart the ZCC tray "
                "and check Console.app for crash logs of "
                "ZscalerNetworkExtension.",
                sop_anchor="#mac-ne-provider-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        if _RE_KEXT_FAIL.search(msg):
            f = self._bucket(
                "MAC_KEXT_LOAD_FAIL",
                Severity.CRITICAL,
                "macOS kernel extension load failure",
                "A kernel extension failed to load — relevant only on "
                "older macOS releases that still use kexts (pre-Big "
                "Sur). Modern Zscaler installs use system extensions "
                "instead. If this fires on macOS 12+, it's usually a "
                "leftover legacy kext that should be removed.",
                sop_anchor="#mac-kext-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        if _RE_TRAY_SYSEXT_STATE.search(msg):
            f = self._bucket(
                "MAC_TRAY_SYSEXT_ERROR_STATE",
                Severity.WARNING,
                "Mac tray reports System Extension Error",
                "The ZCC tray rendered the user-visible 'System "
                "Extension Error' state. Downstream symptom of any "
                "of the load / not-approved / NE-fail conditions "
                "above; cross-reference timestamps to find the "
                "originating cause.",
                sop_anchor="#mac-tray-sysext-error",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        self._scan(record)

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        self._scan(record)

    def feed_extra(self, record: LogLine, summary: BundleSummary,
                   kind: str) -> None:
        self._scan(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        # Also consult the parsed AppInfo.log SystemExtensions plist
        # state (already extracted into summary.sysext_states). If
        # any Zscaler bundle ID is not "activated enabled", fire a
        # cross-reference finding. Pure structured-data signal — no
        # regex needed.
        sysext_states = getattr(summary, "sysext_states", None) or []
        for ext in sysext_states:
            state = (ext.get("state") or "").lower()
            bid = (ext.get("bundle_id") or "").lower()
            if "com.zscaler" not in bid:
                continue
            if state == "activated enabled":
                continue  # healthy
            # Anything else (waiting for user, deactivated, terminated)
            # is a problem worth flagging.
            f = self._bucket(
                f"MAC_SYSEXT_STATE::{bid.replace('.', '_')}",
                Severity.WARNING if "waiting" in state else Severity.CRITICAL,
                f"Zscaler sysext '{ext.get('name', bid)}' state: {state}",
                f"Bundle ID {bid} reports state '{state}' in "
                f"AppInfo.log. Healthy is 'activated enabled'. "
                f"Any other state — 'activated waiting for user', "
                f"'activated waiting for reboot', 'terminated', "
                f"'deactivated' — means the extension is NOT "
                f"intercepting traffic. Cross-reference with the "
                f"sysext approval flow.",
                sop_anchor=None,
            )
            # No evidence LogLine — this came from structured plist
            # data, not a log scan. The title carries enough context.
        return list(self._buckets.values())
