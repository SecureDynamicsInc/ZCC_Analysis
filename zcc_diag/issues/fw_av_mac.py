"""
Detector: macOS firewall / AV / EDR interference with ZCC.

What this catches
-----------------
On macOS, ZCC's data plane goes through a Network Extension /
content-filter system extension, NOT a Windows-style LWF kernel
driver. The mechanisms that can block it are different:

  * pfctl rules — the macOS packet filter, similar to ipfw on older
    macOS. Tenants sometimes deploy pf rules via MDM that block ZCC
    tunnel destinations.
  * socketfilterfw (Application Layer Firewall) — Apple's
    application-level firewall. Can deny inbound to ZCC or its
    helper processes if not explicitly allowed.
  * Third-party endpoint security: CrowdStrike Falcon, SentinelOne,
    Carbon Black, Sophos — all install kexts or system extensions
    that can block ZCC connections.

This detector is the Mac analog of ``endpoint_fw_av`` (which catches
the Windows LWF / WFP / port-9000 health-check patterns).

Why a separate file (not extending endpoint_fw_av_mac.py)
---------------------------------------------------------
We already have ``endpoint_fw_av_mac.py`` which covers SOME Mac
signatures (NCSI-false-negative shape and a few others). This
detector adds the explicit pfctl / socketfilterfw / EDR-attribution
patterns that the README's "Known limitations" section calls out
as missing. Two separate detectors is fine — they bucket distinctly
in the UI under "macOS firewall / EDR / DNS-filter interference".

Signal sources
--------------
* Tunnel + Service logs: probe failures with "pf: rules" or
  "pfctl" in nearby context; "Application Layer Firewall" /
  "socketfilterfw" mentions.
* Service logs: connection failures with CrowdStrike / Falcon /
  SentinelOne / CarbonBlack / Sophos process names in the
  surrounding context, or system-extension activation failures
  citing those bundle IDs.
* AppInfo.log (Mac plist) — the apps_installed list often surfaces
  the EDR product directly. Used to attribute a connection failure
  to a specific 3rd-party.

CALIBRATION NOTE
----------------
No real Mac bundle in the development corpus has fired these
signals. Patterns are grounded in:
  - Apple's pf(8) / socketfilterfw(8) man-page output formats
  - Public documentation for CrowdStrike Falcon's connection-block
    error format
  - The "Known limitations" entry in README.md flagging this gap

When a real Mac-FW-interference bundle is captured, this detector's
patterns should be re-validated against it.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# pfctl / pf packet filter activity
_RE_PFCTL = re.compile(
    r"\bpfctl\b|\bpf:\s+(?:rules|state|block|deny)|"
    r"pf\.conf|pf\s+blocked",
    re.IGNORECASE,
)

# socketfilterfw — Apple's Application Layer Firewall
_RE_SOCKETFILTERFW = re.compile(
    r"\bsocketfilterfw\b|"
    r"Application Layer Firewall.{0,40}(?:block|deny|reject)",
    re.IGNORECASE,
)

# Bundle-ID denial of a Zscaler system extension. macOS logs the
# bundle ID when a sysext is blocked by user / mdm.
_RE_SYSEXT_DENIED = re.compile(
    r"system.extension.{0,80}(?:com\.zscaler\.zscaler\.\S+).{0,40}"
    r"(?:denied|rejected|blocked|disabled)",
    re.IGNORECASE,
)

# EDR products that commonly cause ZCC traffic blocks on Mac.
_EDR_VENDORS = [
    ("CrowdStrike Falcon", re.compile(
        r"\bfalcon\b|com\.crowdstrike\.|crowdstrike", re.IGNORECASE)),
    ("SentinelOne", re.compile(
        r"sentinelone|sentinel-?one|com\.sentinelone\.", re.IGNORECASE)),
    ("Carbon Black", re.compile(
        r"carbon\s*black|com\.carbonblack\.|cbdefense", re.IGNORECASE)),
    ("Sophos", re.compile(
        r"\bsophos\b|com\.sophos\.", re.IGNORECASE)),
    ("Bitdefender", re.compile(
        r"bitdefender|com\.bitdefender\.", re.IGNORECASE)),
    ("Trend Micro", re.compile(
        r"trend\s*micro|trendmicro", re.IGNORECASE)),
    ("McAfee", re.compile(
        r"\bmcafee\b|com\.mcafee\.", re.IGNORECASE)),
    ("Microsoft Defender", re.compile(
        r"microsoft\s*defender|wdavdaemon|com\.microsoft\.wdav",
        re.IGNORECASE)),
]

# Connection-blocked or denied phrases that indicate the failure
# came from a firewall / AV, not from the network.
_RE_BLOCKED = re.compile(
    r"\b(?:connection\s+(?:blocked|denied|refused\s+by\s+policy)|"
    r"blocked\s+by\s+(?:firewall|policy|edr|av)|"
    r"deny\s+rule|"
    r"socket\s+denied)\b",
    re.IGNORECASE,
)


EVIDENCE_CAP = 15


# --- Detector ---------------------------------------------------------

@register
class MacFwAvInterferenceDetector(IssueDetector):
    id = "fw_av_mac"
    title = "macOS firewall / AV / EDR interference"
    sop_file = "endpoint_fw_av.md"  # share with Windows analog
    # Cross-suite: pfctl / socketfilterfw / EDR interference breaks
    # both ZIA and ZPA tunnels equally.
    applies_to_suite = None

    # Walk tunnel + tray + service. Mac fw/edr logs scatter across
    # all three so we cast a wide net.
    wants_tray_logs = True
    wants_extra_log_kinds = ("service", "upm", "upm_controller")
    applies_to_os = ("macos",)

    prematch_substrings = (
        "pf",            # pfctl, pf:
        "socketfilter",
        "firewall",
        "Firewall",
        "denied",
        "blocked",
        "Falcon",
        "falcon",
        "sentinel",
        "SentinelOne",
        "carbonblack",
        "sophos",
        "Sophos",
        "system.extension",
    )

    def __init__(self) -> None:
        super().__init__()
        # Tracks which EDR vendors fired anywhere in the bundle so
        # we can attribute generic block lines to a specific product
        # at finalize() time.
        self._seen_vendors: List[str] = []

    def _scan(self, record: LogLine) -> None:
        msg = record.message

        # pfctl / pf packet-filter block
        if _RE_PFCTL.search(msg) and _RE_BLOCKED.search(msg):
            f = self._bucket(
                "MAC_PFCTL_BLOCK",
                Severity.CRITICAL,
                "macOS pf packet filter blocking ZCC",
                "A pfctl rule or pf state is blocking ZCC traffic. "
                "Check /etc/pf.conf and the MDM-deployed pf rules. "
                "Common culprit: corporate MDM pushing a pf rule "
                "that blocks 100.64.0.0/10 (the CGNAT range ZCC uses "
                "internally) or specific Zscaler infrastructure IPs.",
                sop_anchor="#mac-pfctl-block",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # socketfilterfw / Application Layer Firewall
        if _RE_SOCKETFILTERFW.search(msg):
            f = self._bucket(
                "MAC_SOCKETFILTERFW_BLOCK",
                Severity.WARNING,
                "macOS Application Layer Firewall denying ZCC",
                "Apple's socketfilterfw (Application Layer Firewall) "
                "denied a ZCC connection. The fix is to add ZCC's "
                "tunnel daemons to the ALF allow-list, either via "
                "System Settings -> Network -> Firewall Options or "
                "via MDM configuration profile.",
                sop_anchor="#mac-alf-block",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # System-extension denied
        if _RE_SYSEXT_DENIED.search(msg):
            f = self._bucket(
                "MAC_SYSEXT_DENIED",
                Severity.CRITICAL,
                "macOS system extension denied / not approved",
                "A Zscaler system extension was denied by the OS or "
                "by user/MDM policy. Without the sysext, ZCC cannot "
                "intercept traffic on Mac. Fix: System Settings -> "
                "Privacy & Security -> System Extensions -> approve "
                "Zscaler; or push the approval via MDM "
                "(SystemExtensionPayload).",
                sop_anchor="#mac-sysext-denied",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # EDR vendor attribution
        for name, pat in _EDR_VENDORS:
            if pat.search(msg):
                if name not in self._seen_vendors:
                    self._seen_vendors.append(name)
                # If this line ALSO has a block phrase, fire a finding
                # that explicitly names the EDR vendor.
                if _RE_BLOCKED.search(msg):
                    safe = re.sub(r"[^A-Za-z0-9_]", "_", name)
                    f = self._bucket(
                        f"MAC_EDR_BLOCK::{safe}",
                        Severity.CRITICAL,
                        f"{name} blocking ZCC traffic",
                        f"{name} appeared in a line that also "
                        f"indicates connection block/deny. Triage: "
                        f"open the {name} admin console, find the "
                        f"policy that blocked the ZCC process or "
                        f"destination, and either allow-list ZCC's "
                        f"tunnel daemon paths or whitelist Zscaler's "
                        f"infrastructure ranges.",
                        sop_anchor=None,
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
        # If we saw EDR vendors but no explicit block lines, fire an
        # INFO finding that just attributes the present vendor —
        # useful context for the engineer ("there's a SentinelOne
        # running on this machine, even if it didn't fire a block").
        for vendor in self._seen_vendors:
            safe = re.sub(r"[^A-Za-z0-9_]", "_", vendor)
            code = f"MAC_EDR_BLOCK::{safe}"
            if code not in self._buckets:
                presence_code = f"MAC_EDR_PRESENT::{safe}"
                if presence_code not in self._buckets:
                    f = self._bucket(
                        presence_code,
                        Severity.INFO,
                        f"{vendor} detected on this Mac",
                        f"{vendor} was mentioned in the logs but did "
                        f"not fire an explicit block in this bundle "
                        f"window. Listed here as context — if ZCC "
                        f"connectivity issues come up, {vendor}'s "
                        f"policy is a likely place to start.",
                        sop_anchor=None,
                    )
        return list(self._buckets.values())
