"""
Detector: SaaS app uses direct P2P data plane, blocked by ZIA.

Some SaaS apps surface as "connection to <SaaS> fails" but the
actual data plane is direct peer-to-peer between user devices --
not a server-bound flow. The user thinks "Zscaler is breaking
<SaaS>"; ZCC's tunnel logs show clean auth/control traffic to the
SaaS, but UDP/TCP attempts to public-internet peers fail.

Grounded by:
- an anonymized internal case (Example Tenant J JumpCloud Remote Assist,
  closed `ISSUE_FIXED`). observed from 2026-02-06 Zoom AI Summary:
  *"Patrick discovered that remote assistance connections were
  failing because ZIA needed to be disabled on both devices involved
  in the connection. He realized that the remote assistance was not
  connecting to JumpCloud servers but rather establishing a direct
  connection between the devices, which was being blocked by ZIA."*

Apps known to use direct P2P data planes (catalogue lives in
``_P2P_APPS``):
- JumpCloud Remote Assist
- Zoom screen share (when peer-to-peer mode is enabled)
- Microsoft Teams calls in some configurations
- BlueJeans Network meetings (legacy)
- Discord voice channels
- TeamViewer direct connect mode
- Apple Continuity / Universal Control
- Steam Remote Play

WARNING-level by design: the only ground truth that a user-action
P2P attempt happened is correlation with the application's own
logs, which aren't in the ZCC bundle. The detector can surface "ZCC
saw outbound UDP/TCP failures to public IPs in a window while ZCC
was otherwise healthy" and let the SOP teach the operator to ask
the user "what app were you using when it broke?"

Heuristic:
- A burst (>= 3) of outbound connection failures to public-internet
  IPs (NOT to Zscaler edges, NOT to RFC1918, NOT to known SaaS
  control planes).
- On non-standard ports (NOT 80/443/53/22 etc).
- While the tunnel state is otherwise UP (no SmeProxyState flap, no
  FIREWALL_BLOCK_ERROR transitions).

Detector is intentionally conservative -- false positives waste
operator triage time more than false negatives here.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Catalogue of apps that have a known P2P data plane. Used by the
# SOP to give the operator a list to compare against the user's
# reported app.
_P2P_APPS = (
    "JumpCloud Remote Assist",
    "Zoom screen share (P2P mode)",
    "Microsoft Teams calls (when DirectConnect is enabled)",
    "BlueJeans Network",
    "Discord voice",
    "TeamViewer direct-connect mode",
    "Apple Continuity / Universal Control",
    "Steam Remote Play",
    "Google Meet (rare P2P mode)",
    "Skype legacy (pre-cloud)",
)


# Ports that are almost always control-plane (HTTPS, HTTP, DNS, SSH
# etc.). UDP/TCP failures on these don't fit the P2P heuristic --
# they're standard traffic that's failing for other reasons.
_CONTROL_PLANE_PORTS = frozenset({
    80, 443, 53, 22, 25, 110, 143, 465, 587, 993, 995, 8080, 8443,
})

# Burst threshold -- we need at least this many independent
# connection failures to fire.
_BURST_THRESHOLD = 3


_RE_OUTBOUND_CONN_FAIL = re.compile(
    # We look for the shape:
    #   <action> ... DestIP=<ip>:<port> ... <fail-phrase>
    # ZCC logs vary, so we accept both ``DestIP=`` and bare ``->``
    # IP-port patterns.
    r"(?:DestIP=|->\s*)"
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::|;|/)?"
    r"(?P<port>\d{1,5})?"
    r"[^\n]{0,160}?"
    r"(?:connection\s+refused"
    r"|connection\s+reset"
    r"|connection\s+timed?\s*out"
    r"|connect(?:ion)?\s+failed"
    r"|cannot\s+connect"
    r"|unable\s+to\s+connect"
    r"|no\s+route\s+to\s+host"
    r"|host\s+unreachable)",
    re.IGNORECASE,
)

# State-machine transitions that imply the tunnel is broken --
# if any of these have fired, this detector should NOT, because
# the failures are explained by infrastructure.
_RE_TUNNEL_BROKEN = re.compile(
    r"FIREWALL_BLOCK_ERROR"
    r"|SERVER_DOWN_ERROR"
    r"|getSmeProxyState:LOCAL_PROXY_FORWARDING"
    r"|TUNNEL_NOT_ESTABLISHED",
)

# Networks we treat as "infrastructure / not public peer-to-peer".
# Failures into these IPs are infrastructure-level and don't fit the
# P2P shape this detector is hunting for. We do NOT use
# ``IPv4Address.is_private`` because as of Python 3.12.4 / 3.11.9 /
# 3.10.14 (CVE-2024-4032) it returns True for RFC 5737 documentation
# blocks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Those
# blocks are not real corporate addressing, so treating them as
# "internal" suppresses legitimate signal when synthetic test data or
# example documentation happens to leak into a real bundle.
_INTERNAL_V4_NETS = tuple(
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",   # CGNAT (ZCC health checks)
        "169.254.0.0/16",  # link-local
        "127.0.0.0/8",     # loopback
        "0.0.0.0/8",       # "this network"
        "224.0.0.0/4",     # multicast
        "240.0.0.0/4",     # reserved future-use
    )
)
_INTERNAL_V6_NETS = tuple(
    ipaddress.ip_network(n) for n in (
        "fc00::/7",        # ULA
        "fe80::/10",       # link-local
        "::1/128",         # loopback
        "ff00::/8",        # multicast
    )
)


def _is_zscaler_or_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # be conservative
    nets = _INTERNAL_V4_NETS if isinstance(addr, ipaddress.IPv4Address) else _INTERNAL_V6_NETS
    return any(addr in n for n in nets)


EVIDENCE_CAP = 10


@register
class P2pAppBlockedDetector(IssueDetector):
    id = "p2p_app_blocked"
    title = "Possible direct-P2P app blocked by ZIA"
    sop_file = "p2p_app_blocked.md"
    # ZIA-only: direct-peer P2P traffic is blocked by ZIA's
    # forwarding/firewall layer. ZPA doesn't intercept peer-to-peer
    # public-internet flows.
    applies_to_suite = ("zia",)

    def __init__(self) -> None:
        super().__init__()
        # Failure records: list of (record, ip, port)
        self._failures: List[Tuple[LogLine, str, Optional[int]]] = []
        # Have we seen evidence the tunnel itself is broken? If so,
        # don't fire this detector.
        self._tunnel_broken = False

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        if _RE_TUNNEL_BROKEN.search(msg):
            self._tunnel_broken = True
            return

        m = _RE_OUTBOUND_CONN_FAIL.search(msg)
        if not m:
            return

        ip = m.group("ip")
        port_str = m.group("port")
        port: Optional[int] = None
        try:
            if port_str is not None:
                port = int(port_str)
                if port < 1 or port > 65535:
                    port = None
        except ValueError:
            pass

        # Filter out: Zscaler edges, RFC1918, CGNAT, control-plane
        # ports.
        if _is_zscaler_or_internal(ip):
            return
        if port is not None and port in _CONTROL_PLANE_PORTS:
            return

        self._failures.append((record, ip, port))

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        if self._tunnel_broken:
            return []
        if len(self._failures) < _BURST_THRESHOLD:
            return []

        # Group by (ip, port) so a long-lived single failure to one
        # peer doesn't inflate the count.
        distinct_peers = set()
        for _, ip, port in self._failures:
            distinct_peers.add((ip, port))
        if len(distinct_peers) < _BURST_THRESHOLD:
            return []

        sample = "; ".join(
            f"{ip}{':' + str(port) if port else ''}"
            for ip, port in list(distinct_peers)[:5]
        )
        extra = ""
        if len(distinct_peers) > 5:
            extra = f" (+ {len(distinct_peers) - 5} more)"

        f = Finding(
            code="POSSIBLE_P2P_APP_BLOCKED_BY_ZIA",
            severity=Severity.WARNING,
            title=(
                f"{len(distinct_peers)} outbound failure(s) to public "
                f"IPs while tunnel is otherwise healthy"
            ),
            description=(
                f"ZCC's tunnel state appears healthy (no "
                f"FIREWALL_BLOCK_ERROR / SERVER_DOWN_ERROR / "
                f"LOCAL_PROXY_FORWARDING transitions), but "
                f"{len(distinct_peers)} distinct outbound connection "
                f"attempt(s) to public-internet IPs failed during "
                f"the bundle window. Failures are on non-standard "
                f"ports (not 80/443/53/etc), which fits the shape "
                f"of an application's direct peer-to-peer data "
                f"plane.\n\n"
                f"Peers seen: {sample}{extra}\n\n"
                f"This is the Example Tenant J JumpCloud case shape: ZIA "
                f"blocks the P2P leg of a SaaS app while the app's "
                f"own server traffic flows fine, so the customer "
                f"thinks 'Zscaler broke this SaaS' but the actual "
                f"breakage isn't visible in the SaaS's control "
                f"channel.\n\n"
                f"**Triage**: ask the user what app they were "
                f"using when the symptom appeared. Compare against "
                f"the known-P2P catalogue: "
                f"{', '.join(_P2P_APPS[:5])}... (full list in "
                f"the SOP).\n\n"
                f"If the app is in the catalogue, fix via ZIA app-"
                f"profile bypass for the app's UDP/TCP P2P range "
                f"(varies by vendor) AND disable ZIA on BOTH "
                f"endpoints during repro to confirm."
            ),
            sop_anchor="#possible-p2p-app-blocked",
        )
        # Attach the first few failure records as evidence.
        for rec, _, _ in self._failures[:EVIDENCE_CAP]:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        return [f]
