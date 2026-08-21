"""
Detector: DNS leak.

What this catches
-----------------
A DNS leak occurs when the ZCC tunnel is up but DNS queries for
tunneled domains are going to a non-Zscaler DNS resolver — typically
the local ISP's DNS or a public resolver (8.8.8.8, 1.1.1.1). The
result: queries that SHOULD be tunneled get resolved by an external
party (privacy leak + the resolved IPs may differ from what the
tunneled flow would have gotten, breaking session establishment).

Signal sources
--------------
Two complementary signal sources:

  1. ``sys_dns_changed`` ZEvent with metrics showing the active
     resolver. When the "new" resolver is a non-Zscaler IP AND the
     tunnel state is up, that's a configuration drift worth flagging.

  2. ZSAHelper / DNS resolution log lines explicitly noting that a
     query was sent to a non-Zscaler DNS server. ZCC's helper does
     not normally log this at INF — but when ``Detailed DNS logging``
     is enabled in the App Profile, the resolver chosen per query
     appears in the log.

Why this matters
----------------
ZCC normally captures DNS via its DNS proxy (Mac) or DNS interception
(Windows). A DNS leak typically means:
  * The user has a manually-configured DNS that ZCC's profile
    didn't override (e.g. they pasted 8.8.8.8 into their wifi
    settings and the App Profile's DNS-override flag is off).
  * A 3rd-party security tool (CrowdStrike DNS Filter, Cisco
    Umbrella) is intercepting DNS upstream of ZCC.
  * The bundle was captured pre-enrollment, where ZCC hadn't yet
    pushed its DNS interception config.

CALIBRATION NOTE
----------------
No real bundle in the development corpus has clearly fired this
signal. Patterns are grounded in Zscaler documentation about the
DNS-interception mechanism + the standard ``sys_dns_changed`` event
shape. When a real DNS-leak bundle is captured, refine the patterns
against it.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# sys_dns_changed event with new resolver IPs in metrics.
_RE_DNS_CHANGED = re.compile(
    r'sys_dns_changed\b.*?"new"\s*:\s*"(?P<new>[^"]+)"'
    r'(?:.*?"old"\s*:\s*"(?P<old>[^"]+)")?',
    re.IGNORECASE,
)

# Known public-DNS / common-leak-target IPs. NOT exhaustive — just the
# usual suspects. Customers can have legitimate reasons to use any of
# these (split-horizon DNS for some domains, etc.) so finding fires
# WARNING, not CRITICAL.
_PUBLIC_DNS_IPS = {
    "8.8.8.8", "8.8.4.4",          # Google
    "1.1.1.1", "1.0.0.1",          # Cloudflare
    "9.9.9.9", "149.112.112.112",  # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS / Cisco Umbrella
    "4.2.2.1", "4.2.2.2",          # Level 3 / Lumen
    "64.6.64.6",                    # Verisign
}

# Zscaler-side DNS interception IPs. When the resolver IS one of these,
# the system is correctly using ZCC's DNS path.
_ZSCALER_DNS_IPS = {
    "100.64.0.1", "100.64.0.2",
    # ZCC uses 100.64/10 CGNAT for tunnel-internal addressing.
}

# Explicit "DNS forwarded to <ip>" line. Some ZCC builds log this at
# DBG when detailed DNS logging is on.
_RE_DNS_FORWARDED = re.compile(
    r"DNS.{0,20}forwarded.{0,20}to.{0,20}(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)


EVIDENCE_CAP = 15


def _ip_is_public_dns(ip: str) -> bool:
    """Quick check whether an IP is one of the well-known public DNS
    resolvers. Comma-separated IP lists in 'new' field are split."""
    for part in re.split(r"[,\s]+", ip or ""):
        part = part.strip()
        if part in _PUBLIC_DNS_IPS:
            return True
    return False


def _ip_is_local_subnet(ip: str) -> bool:
    """Heuristic: 192.168.x.y / 10.x.y.z / 172.16-31.x.y. A DNS
    resolver on the local subnet is usually the home / corp router,
    NOT a leak — the user is just using their LAN DNS. We don't fire
    on these."""
    if not ip:
        return False
    first = re.split(r"[,\s]+", ip.strip())[0]
    if first.startswith("192.168."):
        return True
    if first.startswith("10."):
        return True
    if first.startswith("100.64.") or first.startswith("100.65."):
        return True  # CGNAT (Zscaler-internal range)
    m = re.match(r"172\.(\d+)\.", first)
    if m:
        try:
            second = int(m.group(1))
            if 16 <= second <= 31:
                return True
        except ValueError:
            pass
    return False


# --- Detector ---------------------------------------------------------

@register
class DnsLeakDetector(IssueDetector):
    id = "dns_leak"
    title = "DNS leak — queries bypassing ZCC interception"
    sop_file = ""
    # Cross-suite: both ZIA and ZPA intercept DNS the same way.
    applies_to_suite = None

    # Cross-platform — both ZIA and ZPA tunnels intercept DNS the
    # same way regardless of OS.
    applies_to_os = None
    prematch_substrings = ("sys_dns_changed", "DNS", "dns")

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # sys_dns_changed event
        m = _RE_DNS_CHANGED.search(msg)
        if m:
            new_ip = m.group("new") or ""
            if _ip_is_public_dns(new_ip):
                f = self._bucket(
                    "DNS_LEAK_PUBLIC_RESOLVER",
                    Severity.WARNING,
                    "DNS resolver pointed at a public DNS provider",
                    "The system DNS resolver is set to a well-known "
                    "public DNS (Google, Cloudflare, Quad9, etc). "
                    "Whether this is a leak depends on whether ZCC "
                    "is configured to intercept DNS. If the App "
                    "Profile has 'Enable DNS interception' OFF, "
                    "queries for tunneled domains will resolve at "
                    "the public DNS and bypass ZIA's DNS-based "
                    "policy enforcement. Verify the App Profile in "
                    "ZIA Admin Console -> Mobile Admin -> App "
                    "Profiles, and check whether the resolved IPs "
                    "match what Zscaler's PAC expects.",
                    sop_anchor=None,
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)

        # Explicit "forwarded to X" line
        m = _RE_DNS_FORWARDED.search(msg)
        if m:
            ip = m.group("ip")
            if (
                ip
                and not _ip_is_local_subnet(ip)
                and ip not in _ZSCALER_DNS_IPS
                and ip != ""
            ):
                # Only fire if the resolver is on the public internet
                # AND not a Zscaler-managed range.
                f = self._bucket(
                    "DNS_LEAK_QUERY_FORWARDED_EXTERNAL",
                    Severity.WARNING,
                    "DNS query forwarded to external resolver",
                    f"A DNS query was explicitly logged as forwarded "
                    f"to {ip}, which is not on the local subnet nor "
                    f"in Zscaler's known DNS interception ranges. "
                    f"If the affected query is for a tunneled "
                    f"domain, this is a confirmed leak. Engineers "
                    f"should: (1) verify the App Profile DNS-"
                    f"interception flag, (2) check whether a 3rd-"
                    f"party DNS filter (Umbrella, CrowdStrike DNS) "
                    f"is upstream of ZCC.",
                    sop_anchor=None,
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
