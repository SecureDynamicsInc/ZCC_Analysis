"""
Detector: rapid network transitions (dock/undock, wifi-eth swap).

What this catches
-----------------
Each time the user moves between networks — dock plug/unplug,
wifi-to-ethernet swap, VPN connect/disconnect, hotspot tether on/off
— ZCC has to re-evaluate its network context (Trusted / VPN /
Off-Trusted) and may re-auth. A few transitions per day is normal.
Many transitions in a short window suggests the customer is on a
flaky network OR has a docking station that's losing link
intermittently OR is moving between wifi APs.

Signal sources
--------------
  * ``sys_dns_changed`` events — every DNS server swap is a proxy
    for a network change.
  * ``Network change detected`` log lines (ZCC's own event for
    interface up/down).
  * Adapter link-state transitions in ZSAService.
  * Companion: the existing
    ``zcc_zpa_force_reauth_network_change_trigger`` ZEvent fires
    when ZPA re-auth is triggered by a network change. That's a
    consequence; THIS detector catches the cause.

Severity logic
--------------
  * 1-5 transitions across the bundle window: INFO (normal lifecycle).
  * 6-15: WARNING (the user is on something flaky).
  * 16+: CRITICAL (something is wrong — likely a flapping NIC or
    aggressively-reconnecting wifi).

Closely related to ``adapter_instability`` but distinct: that
detector watches NIC LUID alias churn (a Windows-specific
representation); THIS detector watches the higher-level "the network
changed" signal that applies to both platforms.

CALIBRATION NOTE
----------------
Synthetic Windows Scenario D has multiple sys_dns_changed events
(192.168.4.1 alternating, IPv6 / IPv4 swaps), and the same bundle
fires two zcc_zpa_force_reauth_network_change_trigger events —
that's the consistent picture: rapid network transitions causing
re-auth churn.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

_RE_SYS_DNS_CHANGED = re.compile(r"\bsys_dns_changed\b")
_RE_NETWORK_CHANGE = re.compile(
    r"Network\s+change\s+detected|"
    r"NetworkInterfaceChange|"
    r"network\s+(?:interface|adapter)\s+(?:up|down|connected|disconnected)",
    re.IGNORECASE,
)
_RE_LINK_STATE = re.compile(
    r"link\s+state.{0,20}(?:up|down|changed)|"
    r"interface\s+state\s+changed",
    re.IGNORECASE,
)


EVIDENCE_CAP = 25


# --- Detector ---------------------------------------------------------

@register
class NetworkTransitionsDetector(IssueDetector):
    id = "network_transitions"
    title = "Network transitions (dock/undock, wifi swap)"
    sop_file = ""
    # Cross-suite: network changes affect both ZIA and ZPA reconnect.
    applies_to_suite = None

    # Walk tunnel + service since network-change events scatter
    # between both kinds.
    wants_extra_log_kinds = ("service",)
    applies_to_os = None

    prematch_substrings = (
        "sys_dns_changed", "Network change", "network change",
        "NetworkInterface", "link state", "Link state",
    )

    def __init__(self) -> None:
        super().__init__()
        # Track all transition events. The severity decision happens
        # at finalize() time based on the total count + density.
        self._transitions: List[LogLine] = []

    def _scan(self, record: LogLine) -> None:
        msg = record.message
        if (
            _RE_SYS_DNS_CHANGED.search(msg)
            or _RE_NETWORK_CHANGE.search(msg)
            or _RE_LINK_STATE.search(msg)
        ):
            self._transitions.append(record)

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        self._scan(record)

    def feed_extra(self, record: LogLine, summary: BundleSummary,
                   kind: str) -> None:
        self._scan(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        n = len(self._transitions)
        if n == 0:
            return []

        # Compute the bundle window length to derive density.
        # Phase 58e-C3 (2026-07-08): the multiplexer feeds records
        # newest-first, so self._transitions[0] is the NEWEST timestamp
        # and self._transitions[-1] is the OLDEST. The previous code
        # computed (last - first) which was negative; max(neg, 0.01)
        # clamped to 36s and made every non-empty bundle escalate on
        # the rate calc. Sort explicitly so ordering is a property of
        # this function, not of upstream feed direction.
        if len(self._transitions) >= 2:
            ts_sorted = sorted(
                r.timestamp for r in self._transitions
            )
            first, last = ts_sorted[0], ts_sorted[-1]
            span_seconds = max((last - first).total_seconds(), 0.0)
            span_hours = span_seconds / 3600.0
            # Guard against sub-second bursts producing a zero span
            # that would make the rate infinite. If span < 60s, drop
            # to n-only severity (no rate escalation).
            if span_hours < (1.0 / 60.0):
                span_hours = 0.0
        else:
            span_hours = 0.0

        # Severity decision. Counts are TOTAL events; the per-hour
        # rate further escalates.
        if n >= 16 or (span_hours > 0 and n / span_hours >= 6):
            severity = Severity.CRITICAL
            severity_label = "very high"
        elif n >= 6 or (span_hours > 0 and n / span_hours >= 3):
            severity = Severity.WARNING
            severity_label = "elevated"
        else:
            severity = Severity.INFO
            severity_label = "normal"

        f = self._bucket(
            "NETWORK_TRANSITIONS",
            severity,
            f"{n} network transition(s) — {severity_label} cadence",
            f"Detected {n} network transition event(s) "
            f"(sys_dns_changed / network-change / link-state) "
            f"over {span_hours:.1f} hours. Each transition forces "
            f"ZCC to re-evaluate Trusted-Network status, re-bind "
            f"the tunnel, and may trigger ZPA re-auth (see "
            f"zcc_zpa_force_reauth_network_change_trigger). "
            f"Normal cadence on a laptop is 1-3 per day. Elevated "
            f"cadence indicates: flapping wifi/eth NIC, docking "
            f"station losing link, aggressively-reconnecting AP, "
            f"or a 3rd-party VPN connecting/disconnecting. "
            f"Cross-reference with the vpn_coexistence detector "
            f"if it also fires.",
            sop_anchor=None,
        )
        for rec in self._transitions[:EVIDENCE_CAP]:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        # The detector counts ALL transitions even though only
        # EVIDENCE_CAP get attached as evidence.
        f.count = n
        return [f]
