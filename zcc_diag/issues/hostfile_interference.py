"""
Detector: Hosts-file interference (GPO-pushed override bypassing ZPA/ZIA).

Customer machines often carry stale entries in the system hosts file
that map a hostname to a specific IP. When ZPA / ZIA expects to
intercept that hostname via tunnel, the OS-level override short-
circuits the resolution and traffic goes direct -- which usually
fails (the IP is reachable only through ZPA app segments) or
silently bypasses inspection.

Grounded by:
- an anonymized internal case (Example Tenant L "portal not working").
  Zoom AI summary observed: *"Jack's machine had an incorrect host
  file entry that was causing DNS requests to be sent directly to
  the IP address instead of through Zscaler."*
- a synthetic internal case (Example Tenant M). Resolution
  was *"reset host files on all affected computers to resolve
  internal site access issues."*

The hosts file is GPO-pushed in many Windows environments, so even
when the operator fixes a single machine the entry can come back
within 30 minutes when Group Policy re-pushes.

Signature: a non-comment hosts-file line that maps a customer-
identifiable hostname to a private or non-routable IP -- the
combination strongly implies this is an internal-app override that
should be flowing through ZPA instead. Public-internet IPs are
ignored (they're often legitimate split-DNS shortcuts).

This is a summary-only detector. No tunnel-log feeding needed --
``summary.hosts_file_entries`` is pre-populated by ``summary.py``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Set  # noqa: F401

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Standard hosts-file boilerplate that ships with Windows and macOS.
# We skip these so the detector doesn't fire on a healthy bundle.
_STANDARD_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    # Windows IPv6 entries
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
})

# Standard loopback / link-local / multicast IPs in default hosts
# files. Entries to these are always benign.
_STANDARD_IPS = frozenset({
    "127.0.0.1",
    "::1",
    "fe00::0",
    "ff00::0",
    "ff02::1",
    "ff02::2",
    "ff02::3",
    "0.0.0.0",
})


# Network blocks considered "private" for the purpose of this detector.
# We do NOT use ``ipaddress.IPv4Address.is_private`` because as of
# Python 3.12.4 / 3.11.9 / 3.10.14 (CVE-2024-4032) it returns True for
# the RFC 5737 documentation ranges (TEST-NET-1/2/3) and a handful of
# other IETF-reserved blocks. That broadening makes ``is_private`` no
# longer a reliable proxy for "RFC 1918 corporate addressing", which
# is the semantic this detector needs: a hosts-file entry pointing a
# corporate hostname at 203.0.113.42 (TEST-NET-3) is suspicious, NOT
# the same kind of finding as one pointing at 10.x.x.x.
_PRIVATE_V4_NETS = tuple(
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8",        # RFC 1918
        "172.16.0.0/12",     # RFC 1918
        "192.168.0.0/16",    # RFC 1918
        "100.64.0.0/10",     # RFC 6598 CGNAT
        "169.254.0.0/16",    # RFC 3927 link-local
        "127.0.0.0/8",       # loopback
    )
)
_PRIVATE_V6_NETS = tuple(
    ipaddress.ip_network(n) for n in (
        "fc00::/7",          # ULA
        "fe80::/10",         # link-local
        "::1/128",           # loopback
    )
)


def _is_private_ip(ip: str) -> bool:
    """Return True if ``ip`` is in an actual corporate / link-local /
    loopback range -- explicitly NOT including RFC 5737 TEST-NET or
    other IETF-reserved documentation blocks (see ``_PRIVATE_V4_NETS``
    docstring for the CVE-2024-4032 background). Tolerant of parse
    failures (returns False)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = _PRIVATE_V4_NETS if isinstance(addr, ipaddress.IPv4Address) else _PRIVATE_V6_NETS
    return any(addr in n for n in nets)


def _hostname_looks_internal(host: str) -> bool:
    """Heuristic: does this hostname look like an internal corporate
    host? We flag anything that's NOT a public TLD or a well-known
    consumer service. The detector errs on the side of surfacing
    overrides for operator review.
    """
    h = host.lower().strip(".")
    if not h or h in _STANDARD_HOSTNAMES:
        return False
    # Single-label names (no dot) are almost always internal.
    if "." not in h:
        return True
    # Common internal-only TLDs.
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".corp"):
        return True
    if h.endswith(".lan") or h.endswith(".intranet") or h.endswith(".home"):
        return True
    # Anything else with a dot we treat as potentially internal --
    # the detector can't easily distinguish public *.example.com
    # from internal *.corp.example.com. We'll fire WARN-level so the
    # operator reviews; the SOP guides them through validation.
    return True


EVIDENCE_CAP = 20


@register
class HostFileInterferenceDetector(IssueDetector):
    id = "hostfile_interference"
    title = "Hosts-file override may be bypassing ZPA/ZIA"
    sop_file = "hostfile_interference.md"
    # Cross-suite: hosts-file entries can intercept DNS resolution
    # before either ZIA's PAC or ZPA's app-segment match has a chance
    # to apply. Issue applies symmetrically to both suites.
    applies_to_suite = None

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        entries = summary.hosts_file_entries or []
        if not entries:
            return []

        # Bucket the overrides by IP-class for slightly different
        # severity calls. The Example Tenant L case mapped a private IP
        # to an internal hostname -- that's the strongest signal.
        # Public IPs paired with internal-looking hostnames usually
        # indicate split-DNS shortcuts and rate a WARN at most.
        private_overrides: List[Dict[str, str]] = []
        public_overrides: List[Dict[str, str]] = []
        for e in entries:
            ip = e.get("ip", "").strip()
            host = e.get("hostname", "").strip()
            if not ip or not host:
                continue
            # Skip default Windows / Mac boilerplate.
            if ip in _STANDARD_IPS or host.lower() in _STANDARD_HOSTNAMES:
                continue
            if not _hostname_looks_internal(host):
                continue
            if _is_private_ip(ip):
                private_overrides.append({"ip": ip, "hostname": host})
            else:
                public_overrides.append({"ip": ip, "hostname": host})

        findings: List[Finding] = []

        if private_overrides:
            sample = "; ".join(
                f"{e['hostname']} -> {e['ip']}"
                for e in private_overrides[:5]
            )
            extra = ""
            if len(private_overrides) > 5:
                extra = f" (+ {len(private_overrides) - 5} more)"
            findings.append(Finding(
                code="HOSTFILE_PRIVATE_OVERRIDE",
                severity=Severity.CRITICAL,
                title=(
                    f"{len(private_overrides)} hosts-file entry/ies "
                    f"mapping internal hostname to a private IP"
                ),
                description=(
                    f"The system hosts file contains {len(private_overrides)} "
                    f"entry/ies mapping an internal-looking hostname "
                    f"to a private (RFC1918 / link-local / CGNAT) IP. "
                    f"This bypasses ZPA at the OS resolver layer -- "
                    f"DNS for the host never gets to the tunnel, so "
                    f"ZPA can't intercept it. The traffic then goes "
                    f"direct to the IP, which usually fails because "
                    f"the IP is only reachable through ZPA's app "
                    f"segments.\n\n"
                    f"From the Example Tenant L case (observed): \"Jack's "
                    f"machine had an incorrect host file entry that "
                    f"was causing DNS requests to be sent directly "
                    f"to the IP address instead of through Zscaler.\"\n\n"
                    f"Entries: {sample}{extra}\n\n"
                    f"**IMPORTANT**: many enterprises push the hosts "
                    f"file via Group Policy. Removing the entry on "
                    f"the affected machine alone is NOT enough -- "
                    f"GPO will re-push it within 30 minutes. Identify "
                    f"the GPO that owns the file (gpresult / rsop.msc) "
                    f"and fix the policy source."
                ),
                sop_anchor="#hostfile-private-override",
            ))

        if public_overrides:
            sample = "; ".join(
                f"{e['hostname']} -> {e['ip']}"
                for e in public_overrides[:5]
            )
            extra = ""
            if len(public_overrides) > 5:
                extra = f" (+ {len(public_overrides) - 5} more)"
            findings.append(Finding(
                code="HOSTFILE_PUBLIC_OVERRIDE",
                severity=Severity.WARNING,
                title=(
                    f"{len(public_overrides)} hosts-file entry/ies "
                    f"mapping internal hostname to a public IP"
                ),
                description=(
                    f"The system hosts file contains {len(public_overrides)} "
                    f"entry/ies mapping a hostname to a public-internet "
                    f"IP. These can be legitimate split-DNS shortcuts "
                    f"(e.g. pinning a SaaS host to a specific edge "
                    f"IP), or stale entries from a migration. Review "
                    f"each in context.\n\n"
                    f"Entries: {sample}{extra}\n\n"
                    f"If any of these match a ZPA-managed app segment "
                    f"or a SaaS endpoint that should be flowing "
                    f"through ZIA, remove the override and verify "
                    f"resolution works via the tunnel."
                ),
                sop_anchor="#hostfile-public-override",
            ))

        return findings

    # Summary-only -- no tunnel-log feed.
    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        return
