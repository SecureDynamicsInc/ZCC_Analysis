"""
Detector: Network Error.

Per the official Zscaler ZCC Traffic Forwarding Troubleshooting Runbook
(Network Error section), ZCC's keepalive requests to critical
auth/policy hosts (mobile.zscaler.net, login.<cloud>.net,
mobile.<cloud>.net) fail at the network layer and the tray Service
Status flips to "Network Connection Failed -8".

Signatures live in ZSATray / ZSATrayManager logs (NOT ZSATunnel).

CALIBRATION NOTES:
  1. The runbook quotes the older log format
     ``2022-... #NORMAL #ERROR : Error checking updates: {"error":-8,
     "errorMessage":"<reason>"}``. Real bundles use Format A (same as
     ZSATunnel) and embed the same JSON; we match the JSON content,
     not the format.
  2. The runbook's bare ``error:-8`` is too narrow -- doesn't appear in
     any of the three real bundles. Modern ZCC seems to use other
     codes for network errors. We match on the runbook's specific
     errorMessage CATEGORY phrases instead.
  3. Real bundles DO contain ``errorMessage`` with non-empty values
     that AREN'T network errors (``"Invalid user/password"`` is auth,
     ``"No ZCC update available"`` is informational, ``"Bad Gateway"``
     is from update-check responses). The detector deliberately matches
     ONLY the runbook's documented network-error phrases to avoid
     misclassifying these.

Five categories from the runbook:
  1. DNS failure          -- ``Host not found``
  2. Connection reset     -- ``Connection reset by peer``
  3. Missing route        -- ``Net Exception. No route to host``
  4. Network unreachable  -- ``Net Exception. Network is unreachable``
  5. SSL intercepted      -- ``Certificate validation error.
                              Unacceptable certificate``
                              (and the ``SSL Exception`` /
                              ``certificate verify failed`` variant)
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# Each pattern matches a specific runbook category. Anchored to be
# specific enough to avoid matching e.g. "Invalid user/password".

_RE_HOST_NOT_FOUND = re.compile(
    r'"errorMessage"\s*:\s*"Host not found',
    re.IGNORECASE,
)

_RE_CONN_RESET = re.compile(
    r'"errorMessage"\s*:\s*"Connection reset by peer',
    re.IGNORECASE,
)

_RE_NO_ROUTE = re.compile(
    r'"errorMessage"\s*:\s*"Net Exception\.\s*No route to host',
    re.IGNORECASE,
)

_RE_NET_UNREACHABLE = re.compile(
    r'"errorMessage"\s*:\s*"Net Exception\.\s*Network is unreachable',
    re.IGNORECASE,
)

# SSL interception -- the runbook quotes two variants. Match either.
_RE_CERT_VALIDATION = re.compile(
    r'"errorMessage"\s*:\s*"Certificate validation error',
    re.IGNORECASE,
)
_RE_SSL_EXCEPTION = re.compile(
    r'"errorMessage"\s*:\s*"SSL Exception',
    re.IGNORECASE,
)


EVIDENCE_CAP = 10


# --- Detector ---------------------------------------------------------

@register
class NetworkErrorDetector(IssueDetector):
    id = "network_error"
    title = "Network Error (-8)"
    sop_file = "network_error.md"
    # ZIA-only: the "Network Error -8" family is documented in the
    # ZIA Traffic Forwarding Troubleshooting Runbook. ZPA's equivalent
    # failures go through ZPN_ERR_* + BRK_MT_* paths instead.
    applies_to_suite = ("zia",)

    # Network Error signatures live in tray / tray_manager logs, not
    # tunnel logs. Opt in.
    wants_tray_logs = True
    # Every regex requires ``"errorMessage"`` as a literal anchor; this
    # cheap substring check filters out ~95% of tray records before any
    # regex pass runs.
    prematch_substrings = ('"errorMessage"',)

    # --- IssueDetector overrides ---------------------------------

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        if _RE_HOST_NOT_FOUND.search(msg):
            f = self._bucket(
                "NETERR_HOST_NOT_FOUND",
                Severity.CRITICAL,
                "Network Error: DNS resolution failure",
                "ZCC's tray reported ``errorMessage: Host not found`` "
                "from a keepalive to a critical Zscaler host. The "
                "client cannot resolve the hostname to an IP. Per "
                "the ZCC Traffic Forwarding runbook, the critical "
                "hosts being probed include ``mobile.zscaler.net``, "
                "``login.<cloud_name>.net``, and "
                "``mobile.<cloud_name>.net``.",
                sop_anchor="#neterr-host-not-found",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        if _RE_CONN_RESET.search(msg):
            f = self._bucket(
                "NETERR_CONNECTION_RESET",
                Severity.CRITICAL,
                "Network Error: connection reset by peer",
                "ZCC's tray reported ``errorMessage: Connection reset "
                "by peer`` from a keepalive. DNS resolved and the "
                "TCP handshake started, but a network device along "
                "the path forcibly closed the connection. Common "
                "culprits: TLS-inspecting proxies that drop unknown "
                "TLS handshakes, stateful firewalls timing out "
                "long-lived connections, or load balancers cycling "
                "backends.",
                sop_anchor="#neterr-connection-reset",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        if _RE_NO_ROUTE.search(msg):
            f = self._bucket(
                "NETERR_NO_ROUTE",
                Severity.CRITICAL,
                "Network Error: no route to host",
                "ZCC's tray reported ``errorMessage: Net Exception. "
                "No route to host`` from a keepalive. The OS "
                "routing table has no entry for reaching the "
                "Zscaler host. Likely causes: wrong default gateway, "
                "active VPN client capturing the route, or an IPv6 "
                "host being returned to a v4-only adapter.",
                sop_anchor="#neterr-no-route",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        if _RE_NET_UNREACHABLE.search(msg):
            f = self._bucket(
                "NETERR_NET_UNREACHABLE",
                Severity.CRITICAL,
                "Network Error: network is unreachable",
                "ZCC's tray reported ``errorMessage: Net Exception. "
                "Network is unreachable`` from a keepalive. The "
                "client has no network connectivity at all -- the "
                "adapter is down, no DHCP lease, or no link.",
                sop_anchor="#neterr-net-unreachable",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        if _RE_CERT_VALIDATION.search(msg):
            f = self._bucket(
                "NETERR_CERT_VALIDATION",
                Severity.CRITICAL,
                "Network Error: certificate validation error",
                "ZCC's tray reported ``errorMessage: Certificate "
                "validation error`` from a keepalive -- the TLS "
                "certificate presented by the Zscaler host failed "
                "validation. Per the runbook, this is the canonical "
                "signature of a TLS-inspecting proxy in the path "
                "(corporate firewall / web security gateway "
                "presenting its own cert). Cross-reference with the "
                "tunnel detector's SSL_INTERCEPTION_DETECTED finding "
                "if it also fired.",
                sop_anchor="#neterr-cert-validation",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        if _RE_SSL_EXCEPTION.search(msg):
            f = self._bucket(
                "NETERR_SSL_EXCEPTION",
                Severity.CRITICAL,
                "Network Error: SSL exception",
                "ZCC's tray reported ``errorMessage: SSL Exception`` "
                "from a keepalive -- the TLS handshake itself "
                "failed (often ``certificate verify failed``). Same "
                "root cause family as NETERR_CERT_VALIDATION: a "
                "TLS-inspecting proxy is most likely in the path.",
                sop_anchor="#neterr-ssl-exception",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
