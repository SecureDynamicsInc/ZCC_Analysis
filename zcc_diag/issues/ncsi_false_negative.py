"""
Detector: NCSI false-negative ("no internet" icon with working VPN).

Windows checks for internet connectivity by probing Microsoft's
Network Connectivity Status Indicator (NCSI) endpoints. When ZCC
intercepts those probes' SSL/HTTP responses, Windows interprets the
unexpected response as "no internet" and shows the yellow-triangle
icon — even though the VPN tunnel is up and other traffic flows
normally. Browsers, Outlook, Teams and other apps that consult
Windows' connectivity state then refuse to operate normally.

Grounded by:
- an anonymized internal case (Example Tenant O "Windows No Internet Issue").
  Zoom AI summary observed: *"Windows systems show 'no internet
  connection' warnings despite VPN connectivity being active...
  tools like Mimecast and Global Secure Access are affected by these
  false internet connection alerts, which occur when Windows checks
  for internet connectivity."*
- an anonymized internal case (Example Tenant O User F capture, same root
  cause). Mimecast IP range `216.145.216.0/24` SSL handshake was
  failing through ZIA's split-tunnel configuration.
- Same pattern likely behind an anonymized internal case (Internal Error on
  connection — Mac, different NCSI endpoint but same idea).

Signature: SSL handshake failure (or HTTP 200/204 with unexpected
body) against any host in the NCSI / connectivity-check catalogue.
Windows-only (NCSI is a Windows feature).

Distinct from other detectors:
- ``bypass_misconfiguration`` watches generic cert errors; this is
  narrower and Windows-specific.
- ``captive_portal`` looks for the runbook's
  ``gateway.<cloud>.net:443/generate_204`` probe pattern. That's the
  Zscaler-side connectivity check. NCSI is the OS-side check, and
  failures look identical to the user even though the fix is
  different.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Microsoft NCSI probe endpoints. The detector matches by exact host
# substring against captured Host=… lines.
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-connectivity-info-tooltip
_NCSI_HOSTS = (
    "www.msftncsi.com",
    "msftncsi.com",
    "dns.msftncsi.com",
    "www.msftconnecttest.com",  # Windows 10+ replacement
    "msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    # Google equivalent (Chrome / Edge sometimes probe these too)
    "clients3.google.com",
    "connectivitycheck.gstatic.com",
    # Apple's captive-portal probe — also fires on Windows via WSL or
    # via cross-platform apps
    "captive.apple.com",
)

# Mimecast IP range from the Example Tenant O case. These IPs sit upstream of
# the NCSI flow when a customer routes outbound through Mimecast's
# secure email gateway alongside ZIA. The Mimecast cert is what's
# actually failing the handshake when this pattern fires.
_MIMECAST_IPV4_PREFIXES = (
    "216.145.216.",  # Example Tenant O observed — primary Mimecast range
    "216.145.217.",
    "216.145.218.",
    "194.180.157.",
)

_RE_HOST_LINE = re.compile(
    r"\bHost=(?P<host>[A-Za-z0-9.\-]+)(?::\d+)?",
)
_RE_DEST_IP = re.compile(
    r"\bDestIP=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
_RE_SSL_FAIL = re.compile(
    r"Auth::Lib::certificateErroCallback:\s*Invalid certificate"
    r"|Certificate validation error"
    r"|SSL handshake (?:failure|failed|fail)"
    r"|TLS handshake (?:failure|failed|fail)"
    r"|ssl3_get_server_certificate.*?verify failed",
    re.IGNORECASE,
)


def _is_ncsi_host(host: str) -> Optional[str]:
    h = host.lower().rstrip(".")
    for d in _NCSI_HOSTS:
        if h == d:
            return d
        # Suffix tolerance for subdomain variants.
        if h.endswith("." + d):
            return d
    return None


def _is_mimecast_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _MIMECAST_IPV4_PREFIXES)


EVIDENCE_CAP = 10


@register
class NcsiFalseNegativeDetector(IssueDetector):
    id = "ncsi_false_negative"
    title = "Windows 'no internet' icon caused by NCSI probe SSL failure"
    sop_file = "ncsi_false_negative.md"
    # Cross-suite: NCSI is an OS-level Windows behaviour. Affects
    # ZIA-only, ZPA-only, and dual-enrolled bundles equally.
    applies_to_suite = None
    applies_to_os = ("windows",)

    def __init__(self) -> None:
        super().__init__()
        # Per-thread last-seen target (host or destination IP).
        self._thread_target: Dict[tuple, str] = {}
        self._thread_target_kind: Dict[tuple, str] = {}  # "ncsi" or "mimecast"

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        key = (record.pid, record.tid)

        # Capture host on every line that has one; remember if it's
        # an NCSI probe.
        m_host = _RE_HOST_LINE.search(msg)
        if m_host:
            ncsi = _is_ncsi_host(m_host.group("host"))
            if ncsi is not None:
                self._thread_target[key] = m_host.group("host")
                self._thread_target_kind[key] = "ncsi"

        # Capture dest IPs that fall in Mimecast ranges.
        m_dest = _RE_DEST_IP.search(msg)
        if m_dest and _is_mimecast_ip(m_dest.group("ip")):
            self._thread_target[key] = m_dest.group("ip")
            self._thread_target_kind[key] = "mimecast"

        if _RE_SSL_FAIL.search(msg):
            target = self._thread_target.get(key)
            if target is None:
                return
            kind = self._thread_target_kind.get(key)
            if kind == "ncsi":
                f = self._bucket(
                    "NCSI_PROBE_SSL_FAIL",
                    Severity.WARNING,
                    f"Windows NCSI probe ``{target}`` hit SSL inspection",
                    (
                        f"ZCC's SSL inspection caused a handshake / "
                        f"cert failure against ``{target}``, a "
                        f"Windows NCSI (Network Connectivity Status "
                        f"Indicator) probe endpoint. Windows uses "
                        f"these probes to decide whether to show the "
                        f"yellow-triangle 'no internet' icon. When "
                        f"the probe response is corrupted by SSL "
                        f"interception, Windows declares no "
                        f"connectivity -- even though the VPN tunnel "
                        f"is up and other traffic works.\n\n"
                        f"Apps that consult `IsNetworkAvailable()` "
                        f"(Outlook offline mode, Teams 'we can't "
                        f"connect', Edge dial errors, Mimecast "
                        f"Sync client) then refuse to operate "
                        f"normally.\n\n"
                        f"Fix: add the NCSI URL category to the "
                        f"customer's bypass list (or BLSSL if the "
                        f"customer is doing full SSL inspection). "
                        f"ZIA has a built-in 'Microsoft NCSI' URL "
                        f"category; using it is preferred to manual "
                        f"per-host entries."
                    ),
                    sop_anchor="#ncsi-probe-ssl-fail",
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)
            elif kind == "mimecast":
                f = self._bucket(
                    "MIMECAST_SSL_FAIL",
                    Severity.WARNING,
                    f"Mimecast endpoint ``{target}`` hit SSL inspection",
                    (
                        f"ZCC's SSL inspection caused a handshake "
                        f"failure against ``{target}``, which is in "
                        f"the Mimecast secure-email-gateway IP range. "
                        f"This was the observed root cause of the "
                        f"Example Tenant O 'Windows no internet' case (HubSpot "
                        f"an anonymized internal case) -- Mimecast's response "
                        f"got corrupted by SSL inspection, which "
                        f"cascaded into the NCSI false-negative.\n\n"
                        f"Fix: add Mimecast's IP range "
                        f"(`216.145.216.0/24` and adjacent ranges) "
                        f"to BLSSL bypass. Mimecast publishes the "
                        f"current IP list at "
                        f"https://community.mimecast.com -- use that "
                        f"as the source of truth."
                    ),
                    sop_anchor="#mimecast-ssl-fail",
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
