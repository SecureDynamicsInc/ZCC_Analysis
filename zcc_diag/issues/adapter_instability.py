"""
Detector: network adapter / NIC instability on the host.

Repeated adapter and gateway errors indicate that another network underlay may
be coexisting with ZCC -- usually
a VPN client, Hyper-V/WSL2/Docker virtual switch, or a docking
station that repeatedly adds and removes network adapters.

Why this matters: when adapters thrash, ZCC repeatedly re-discovers
the default gateway and re-applies its traffic-forwarding filters,
which produces a cascade of downstream symptoms (ZTUI bus failures,
LWF filter reconfiguration, DTLS-to-TLS fallback) that look like
unrelated problems but share one root cause.

Signature: count occurrences of each generic product marker. Fire on ANY of:
  - LUID alias failures  >= 30           (CRIT >= 100)
  - NP tunnel parse fails >= 3           (CRIT >= 10)
  - Gateway-change ERRs   >= 20          (CRIT >= 35)
  - WTS session fails     >= 5           (CRIT >= 20)

Even a single signal at the WARN threshold fires. CRIT only fires
when one signal independently crosses a high-volume bar.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Substring anchors for the multiplexer pre-filter.
_PREMATCH = (
    "ConvertInterfaceLuidToAlias",
    "Failed to parse NP tunnel",
    "Default Interface Gateway",
    "WTSQuerySessionInformation",
    "impersonateLoggedOnUser",
)


# Per-signal thresholds: (warn, crit)
_LUID_TH = (30, 100)
_NP_PARSE_TH = (3, 10)
_GW_TH = (20, 35)
_WTS_TH = (5, 20)


EVIDENCE_CAP = 12


@register
class AdapterInstabilityDetector(IssueDetector):
    id = "adapter_instability"
    title = "Network adapter / NIC instability"
    sop_file = "adapter_instability.md"
    # Cross-suite: NIC instability breaks both ZIA and ZPA tunnels.
    applies_to_suite = None
    prematch_substrings = _PREMATCH
    # Every signal in _PREMATCH is a Windows-only API name
    # (ConvertInterfaceLuidToAlias, WTSQuerySessionInformation,
    # impersonateLoggedOnUser, NP tunnel) -- this detector cannot
    # produce a meaningful result on macOS / Linux bundles.
    applies_to_os = ("windows",)

    def __init__(self) -> None:
        super().__init__()
        self._luid = 0
        self._np_parse = 0
        self._gw_change = 0
        self._wts = 0
        self._imp = 0
        # Sample evidence -- keep a few per signal so the finding shows
        # representative lines, not 100 of the same message.
        self._evidence_luid: List[LogLine] = []
        self._evidence_np: List[LogLine] = []
        self._evidence_gw: List[LogLine] = []
        self._evidence_wts: List[LogLine] = []

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        # NB: order matters -- check most specific first to avoid double-counting.
        if "ConvertInterfaceLuidToAlias Failed" in msg:
            self._luid += 1
            if len(self._evidence_luid) < 3:
                self._evidence_luid.append(record)
            return
        if "Failed to parse NP tunnel" in msg:
            self._np_parse += 1
            if len(self._evidence_np) < 3:
                self._evidence_np.append(record)
            return
        if "Default Interface Gateway is" in msg and record.level == "ERR":
            self._gw_change += 1
            if len(self._evidence_gw) < 3:
                self._evidence_gw.append(record)
            return
        if "WTSQuerySessionInformation failed" in msg:
            self._wts += 1
            if len(self._evidence_wts) < 3:
                self._evidence_wts.append(record)
            return
        if "impersonateLoggedOnUser failed" in msg:
            self._imp += 1
            return

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        # Decide severity. Any single signal hitting its CRIT threshold
        # gives us a CRITICAL finding. Otherwise if any signal crossed
        # WARN, we fire WARNING. Below all thresholds -> silent.
        signals = [
            ("LUID alias failures", self._luid, _LUID_TH),
            ("NP tunnel-ip parse fails", self._np_parse, _NP_PARSE_TH),
            ("gateway-change ERRs", self._gw_change, _GW_TH),
            ("WTS session lookup fails", self._wts, _WTS_TH),
        ]
        warn_hits = [s for s in signals if s[1] >= s[2][0]]
        crit_hits = [s for s in signals if s[1] >= s[2][1]]
        if not warn_hits:
            return []

        severity = Severity.CRITICAL if crit_hits else Severity.WARNING
        crossed = ", ".join(
            f"{name}={count}" for name, count, _ in warn_hits
        )

        # Title
        if crit_hits:
            crit_names = ", ".join(name for name, _, _ in crit_hits)
            title = (
                f"Network adapter instability (CRITICAL volume on "
                f"{crit_names})"
            )
        else:
            title = (
                f"Network adapter instability ({crossed})"
            )

        desc = (
            f"ZCC's host-adapter abstraction layer logged a large volume "
            f"of errors that indicate the machine's NICs are churning "
            f"(adapters being added / removed / having their LUID "
            f"reassigned). Counts in this bundle:\n\n"
            f"  ConvertInterfaceLuidToAlias failures:      {self._luid}\n"
            f"  'Failed to parse NP tunnel ip' events:     {self._np_parse}\n"
            f"  Default-Gateway-change ERR records:        {self._gw_change}\n"
            f"  WTSQuerySessionInformation failures:       {self._wts}\n"
            f"  impersonateLoggedOnUser failures:          {self._imp}\n\n"
            f"Thresholds crossed: {crossed}\n\n"
            f"Common causes (most -> least common):\n"
            f"  1. **3rd-party VPN client coexistence** (GlobalProtect, "
            f"Cisco AnyConnect, OpenVPN, NordVPN, ExpressVPN). When "
            f"the other VPN engages/disengages, it tears down and "
            f"re-creates virtual NICs. ZCC sees that as instability "
            f"and re-applies its filter chain each time.\n"
            f"  2. **Hyper-V / WSL2 / Docker Desktop** creating and "
            f"destroying virtual switches as containers / VMs start.\n"
            f"  3. **Docking-station / USB-Ethernet adapter** with a "
            f"flaky cable or driver.\n"
            f"  4. **Roaming between WiFi APs** in a dense-AP environment.\n\n"
            f"Why it matters: each adapter event causes ZCC to redo its "
            f"traffic-forwarding setup, which in turn produces a "
            f"cascade of secondary symptoms (ZTUI bus failures, LWF "
            f"reconfiguration, DTLS-to-TLS fallback) that look like "
            f"separate problems but are all downstream of this single "
            f"root cause.\n\n"
            f"Triage:\n"
            f"  - Check installed apps for a 3rd-party VPN client.\n"
            f"  - Run ``Get-WindowsOptionalFeature -Online`` and look "
            f"for Hyper-V / WSL feature flags.\n"
            f"  - Look in Device Manager for virtual / phantom adapters.\n"
            f"  - If a VPN client must coexist, configure ZCC's "
            f"VPN-trusted forwarding profile correctly so the two "
            f"don't fight."
        )

        f = Finding(
            code="ADAPTER_INSTABILITY",
            severity=severity,
            title=title,
            description=desc,
            sop_anchor="#adapter-instability",
        )
        # Attach the diverse evidence we collected
        for rec in (
            self._evidence_luid + self._evidence_np
            + self._evidence_gw + self._evidence_wts
        )[:EVIDENCE_CAP]:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        return [f]
