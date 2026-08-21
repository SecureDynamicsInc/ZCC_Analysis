"""
Detector: high volume of ZPA data-plane connection resets while ZPA is
otherwise healthy.

Grounded by the Example Tenant E / Google Remote Desktop bundle
(2026-05-18-15-20-30) where 582 ``Zpn endConnection`` events fired
across 8 tunnel logs while ``getZpnProxyState:TUNNEL_FORWARDING
getZpnAuthState:AUTHENTICATED`` stayed healthy throughout. Existing
detectors miss this shape:

  * ``p2p_app_blocked`` needs ``DestIP=<ip>:<port>`` in the same log
    line as the failure. The Zpn endConnection lines only carry a
    socket-local ``tag id``, not the destination IP.
  * ``network_error`` is anchored on the ``errorMessage`` JSON token
    which is absent from Zpn endConnection lines.
  * ``zpa_mtunnel_reconnect_loop`` covers control-plane mtunnel
    reconnects, not data-plane individual connection resets.
  * ``tunnel_not_established`` needs a state transition. With ZPA
    AUTHENTICATED+FORWARDING throughout, no transition fires.

Signature shape (verbatim from the Example Tenant E bundle):
  ``ID=<n>, Zpn client onSocketReadable called. Others: [0]``
  ``ID=<n>, Exception in onSocketReadable tag id: <m> (Error: Connection reset by peer)``
  ``ID=<n>, Zpn endConnection called for tag id: <m> ShutdownMode: SHUTDOWN_BOTH``

We anchor on the second line (the actual reset exception). Threshold:

  * 0-99 resets:    no finding
  * 100-499 resets: WARN
  * 500+ resets:    CRITICAL

The detector suppresses itself if the bundle window also shows
upstream tunnel-state breakage: any record matching
``SmeProxyState`` transitions away from FORWARDING, mtunnel
reconnect attempts, or the ZPA-TUNNEL-DOWN_SERVER_DOWN_ERROR token.
We track that signal during ``feed()`` itself (a single regex) so
the detector is self-contained -- no cross-detector ordering or
multiplexer post-pass needed.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


_RE_ZPN_RESET = re.compile(
    r"Exception in onSocketReadable.*?Connection reset by peer",
    re.IGNORECASE,
)

# Markers that the broader ZPA tunnel is broken in this bundle. If we
# observe ANY of these during feed(), we know the resets we're counting
# are a downstream symptom and suppress the finding to avoid double-
# reporting against the upstream cause.
#
# IMPORTANT: only ZPA-context markers belong here. ``SmeProxyState``
# is ZIA tenant state (Service Edge / mobile API) — used to live in
# this regex and caused ZPA data-plane findings to be suppressed
# whenever the ZIA tunnel happened to flap, even if ZPA was healthy
# and resetting for its own reasons. Removed. The terminology rule:
# SME/ZEN = ZIA, broker/mtunnel/ZPN = ZPA.
#
# SERVER_DOWN_ERROR / FIREWALL_BLOCK_ERROR / TUNNEL_NOT_ESTABLISHED
# are suite-neutral codes — kept because if the underlying transport
# layer is broken, ZPA data-plane resets really are a downstream
# symptom and shouldn't be double-counted.
_RE_TUNNEL_BROKEN = re.compile(
    r"ZpnProxyState:TUNNEL_DOWN"
    r"|ZpnAuthState:(?:UNAUTHENTICATED|AUTH_REQUIRED)"
    r"|ZPA_MTUNNEL_RECONNECT"
    r"|mtunnel.*reconnect"
    r"|SERVER_DOWN_ERROR"
    r"|FIREWALL_BLOCK_ERROR"
    r"|TUNNEL_NOT_ESTABLISHED",
    re.IGNORECASE,
)


# Anchor substrings used by the multiplexer to short-circuit the
# detector before invoking feed(). Cheap ``in`` test over each
# log message. See ``issues/__init__.py`` and ``test_multiplexer.py``.
# We list anchors for BOTH the reset shape and the suppression shapes
# so feed() sees the suppression triggers as well as the resets.
# ``SmeProxyState`` removed: ZIA tenant state, not relevant to this
# ZPA detector. See the comment on ``_RE_TUNNEL_BROKEN`` above.
_PREMATCH = (
    "Connection reset",
    "onSocketReadable",
    "ZpnProxyState",
    "SERVER_DOWN_ERROR",
    "mtunnel",
    "TUNNEL_NOT_ESTABLISHED",
    "FIREWALL_BLOCK_ERROR",
)


_WARN_THRESHOLD = 100
_CRIT_THRESHOLD = 500


EVIDENCE_CAP = 10


@register
class ZpaDataPlaneResetsDetector(IssueDetector):
    id = "zpa_data_plane_resets"
    title = "ZPA data-plane connection resets"
    sop_file = "zpa_data_plane_resets.md"
    # ZPA-only: ZPA broker data-plane reset events.
    applies_to_suite = ("zpa",)
    prematch_substrings = _PREMATCH

    def __init__(self) -> None:
        super().__init__()
        self._count = 0
        self._evidence: List[LogLine] = []
        self._tunnel_broken = False

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        # Track upstream tunnel breakage so we can suppress in finalize.
        if _RE_TUNNEL_BROKEN.search(msg):
            self._tunnel_broken = True
            return
        if not _RE_ZPN_RESET.search(msg):
            return
        self._count += 1
        if len(self._evidence) < EVIDENCE_CAP:
            self._evidence.append(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        if self._count < _WARN_THRESHOLD:
            return []
        if self._tunnel_broken:
            # Upstream tunnel-state issue exists; the resets are a
            # downstream symptom. Suppress to avoid double-reporting.
            return []

        severity = Severity.CRITICAL if self._count >= _CRIT_THRESHOLD else Severity.WARNING
        sev_word = "CRITICAL" if severity == Severity.CRITICAL else "WARNING"

        f = Finding(
            code="ZPA_DATA_PLANE_RESETS",
            severity=severity,
            title=(
                f"{self._count} ZPA data-plane connection reset(s) while "
                f"ZPA tunnel state stayed healthy"
            ),
            description=(
                f"Saw {self._count} ``Exception in onSocketReadable ... "
                f"Connection reset by peer`` events in the tunnel logs. "
                f"These are individual ZPA data-plane connections "
                f"(``Zpn client``) terminated by the remote side, "
                f"distinct from tunnel-state flaps or mtunnel reconnects "
                f"(no such finding co-fired, otherwise this detector "
                f"would have suppressed itself).\n\n"
                f"Severity: {sev_word} ({self._count} >= "
                f"{_CRIT_THRESHOLD if severity == Severity.CRITICAL else _WARN_THRESHOLD}).\n\n"
                f"What this typically means: an application's connections "
                f"through ZPA are completing TLS handshake then getting "
                f"reset before useful exchange. Common upstream causes:\n"
                f"  * App Connector running out of session capacity (look "
                f"    at connector logs for ``Too many open files`` / "
                f"    ``EAGAIN``).\n"
                f"  * Server-side application closing the connection "
                f"    immediately after handshake (look for app-layer "
                f"    blocks: WAF rule, IP allowlist, source-IP anchor "
                f"    mismatch).\n"
                f"  * Path MTU issues fragmenting TLS records (look for "
                f"    ICMP frag-needed in customer firewall logs).\n"
                f"  * Customer firewall between the App Connector and the "
                f"    backend silently dropping the flow.\n\n"
                f"NOTE: the detector cannot name the affected destination "
                f"because the log line only carries a socket-local "
                f"``tag id``, not the destination IP. Cross-reference "
                f"with pcap (``--pcap``) if available to identify the "
                f"target IP/SNI."
            ),
            sop_anchor="#zpa-data-plane-resets",
        )
        for rec in self._evidence:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        return [f]
