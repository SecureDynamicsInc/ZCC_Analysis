"""
ZPA session correlator.

Why this exists
---------------
The toolkit already groups ZIA connections by their per-connection
``ID=<N>``. ZPA has the same need but a different identifier:
``TAG-ID=<N>`` / ``tag_id`` — the broker microtunnel ID. Each ZPA
session has a clear three-act story:

  Act 1 (setup)
    ``===> ID=X, ZPN Connection local:PORT->IP:443 App Name=NAME,
    DoubleEncrypt=0 TAG-ID=N``
    -> we learn the App Name, the local socket, the destination IP,
       and whether double-encryption is on.

  Act 2 (request_ack)
    ``{"zpn_mtunnel_request_ack":{"tag_id":N,"mtunnel_id":"...",
       "err_code":1,"allow_all_xport":0,"reauth_timeout_s":43200}}``
    -> broker accepted the request. err_code:1 = success.

  Act 3 (end)
    ``{"zpn_mtunnel_end":{"tag_id":N,"error":"BRK_MT_CLOSED_FROM_
       ASSISTANT","err_code":5027,"drop_data":0}}``
    -> mtunnel closed. The ``error`` field tells us the close reason.

What this module does
---------------------
Walks the in-memory ``LogIndex`` ONCE, groups every line referencing
a tag_id into a ``ZpaSession`` object. Cross-references the session's
``app_name`` against the ZPA app registry (from ``zpa_apps``) so the
Search-module drill-in shows whether the targeted app is configured
as bypass, deleted, double-encrypted, etc.

Why not extend the existing session_correlator?
-----------------------------------------------
The ZIA correlator's heuristics (PAC decision, SME selection, SNI on
TLS handshake) don't apply to ZPA — ZPA traffic doesn't traverse the
SME, doesn't have a PAC decision, and doesn't show SNI in the same
log shape. Separate module = simpler grouping logic and a clear
suite separation in the UI.

Public API
----------
    extract_zpa_sessions(log_index, app_registry=None) -> List[ZpaSession]
    sessions_summary_table(sessions) -> List[Dict[str, Any]]
    session_phase_lines(session) -> List[IndexedLine]   # for drill-in

The list is sorted by ``start_ts`` ascending so the engineer sees the
chronological story when scrolling.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------

# Setup line — the post-broker-approval `===>` connection-establishment
# line. ONLY appears for sessions where the broker accepted the request
# AND the client actually established a TCP/UDP connection. For
# setup-failed sessions (BRK_MT_SETUP_FAIL_*), this line never fires —
# use the outbound request line below (_RE_REQUEST) which is emitted
# regardless of broker outcome.
#
# The fields between App Name= and TAG-ID= (e.g. DoubleEncrypt=0) are
# optional in older builds; we make the gap lazy.
_RE_SETUP = re.compile(
    r"ID=(?P<conn_id>\d+),\s*"
    r"ZPN Connection\s+local:(?P<local_port>\d+)\s*"
    r"->\s*(?P<dest_ip>[\d.]+):(?P<dest_port>\d+)\s+"
    r"App Name=(?P<app>[^,]+),"
    # Phase 25.1 (2026-06-17) — middle was previously `[^T]*?` to avoid
    # backtracking, but combined with re.IGNORECASE the negated class
    # excludes lowercase 't' too. Real Zscaler logs put
    # "DoubleEncryp**t**=0" between the App Name and TAG-ID — that 't'
    # would terminate the negated-class match early and the whole
    # regex would fail. The Scenario Windows D bundle exposed this: every
    # `===>` storefront.corp-a.example line was being skipped, leaving
    # the ZPA tab empty even though the sessions were right there.
    # `.*?` (lazy any-char) works correctly under IGNORECASE.
    r"(?P<middle>.*?)"
    r"TAG-ID=(?P<tag>\d+)",
    re.IGNORECASE,
)

# DoubleEncrypt=0|1 in the middle of the setup line.
_RE_DOUBLE_ENCRYPT = re.compile(r"DoubleEncrypt=(\d)", re.IGNORECASE)

# Outbound `zpn_mtunnel_request` JSON — the CLIENT-side request to the
# broker. Carries every field we need to identify a session (app_name,
# original destination IP, server port, protocol). Crucially, this
# line fires for EVERY mtunnel attempt regardless of broker outcome,
# so it's the authoritative source of app_name for sessions that
# never reach the `===>` ZPN Connection line (broker setup-failures,
# rotated-out setup lines, IP-literal probes, etc.).
#
# Example from a real bundle (example-tenant-c-windows, 2026-04-14):
#   DBG Writing Mtunnel request: Size: 213 Data: { "zpn_mtunnel_request":
#   { "app_name": "as-dc1.corp-c.example", "app_type": "name",
#     "double_encrypt": 0, "ip_protocol": 17, "o_dip": "100.64.1.2",
#     "o_sport": 61835, "server_port": 389, "tag_id": 2 } }
#
# Added 2026-06-17 (Phase 11) to fix "(unknown)" app names in the ZPA
# session table for setup-failed sessions like
# BRK_MT_SETUP_FAIL_NO_POLICY_FOUND.
_RE_REQUEST = re.compile(
    r'"zpn_mtunnel_request"\s*:\s*\{'
    r'(?P<body>[^}]*)\}',
    re.IGNORECASE,
)

# Inner-field extractors for the request body. Run only after the
# outer match hits. Order-tolerant inside the JSON object.
_RE_REQ_APP_NAME = re.compile(r'"app_name"\s*:\s*"(?P<v>[^"]+)"')
_RE_REQ_O_DIP = re.compile(r'"o_dip"\s*:\s*"(?P<v>[^"]+)"')
_RE_REQ_SERVER_PORT = re.compile(r'"server_port"\s*:\s*(?P<v>\d+)')
_RE_REQ_IP_PROTOCOL = re.compile(r'"ip_protocol"\s*:\s*(?P<v>\d+)')
_RE_REQ_DOUBLE_ENC = re.compile(r'"double_encrypt"\s*:\s*1\b')
_RE_REQ_TAG_ID = re.compile(r'"tag_id"\s*:\s*(?P<v>\d+)')

# Phase 13 additions (2026-06-17): full session lifecycle capture.
# These extract the per-session signal that lives between request and
# end — broker setup latency, data-plane events, keep-alives, transport
# protocol, client-initiated close detection, and the gold-standard
# per-session byte stats from the disconnect line.

# DBG line that accompanies the INF ack and carries the broker setup
# latency as a float in seconds. Format:
#   "zpn_mtunnel_request_ack tag_id: N, mtunnel_id: ... Setup Time: F.FFFFFF seconds"
_RE_SETUP_TIME = re.compile(
    r"zpn_mtunnel_request_ack\s+tag_id:\s*(?P<tag>\d+)"
    r".*?Setup Time:\s*(?P<seconds>[\d.]+)\s*seconds",
    re.IGNORECASE,
)

# Reauth-timeout from the ack JSON. Stored alongside other ack fields.
_RE_ACK_REAUTH = re.compile(
    r'"reauth_timeout_s"\s*:\s*(?P<v>\d+)'
)

# Per-tag transport identification line:
#   "Zpn:N: client for tag_id: N = proto=N, handler=0xADDR Double encrypt: N"
# proto=6 → TCP, proto=17 → UDP (IANA protocol numbers).
_RE_CLIENT_PROTO = re.compile(
    r"client for tag_id:\s*(?P<tag>\d+)\s*=\s*proto=(?P<proto>\d+)",
    re.IGNORECASE,
)

# Data-plane traffic event:
#   "Zpn:N: Got data for tag_id: N"
# Counted per-session as an indicator of how active the session was.
_RE_GOT_DATA = re.compile(
    r"Got data for tag_id:\s*(?P<tag>\d+)",
    re.IGNORECASE,
)

# Keep-alive / timeout-handler ping per session:
#   "ZpnTimeoutHandler: Updating mtunnel entry tag_id: N, timeout: N (s), ..."
# Counted as an indicator the session was held open across the keep-
# alive interval. Also captures the timeout value (typically the same
# as reauth_timeout_s).
_RE_KEEPALIVE = re.compile(
    r"Updating mtunnel entry tag_id:\s*(?P<tag>\d+),\s*"
    r"timeout:\s*(?P<timeout>\d+)",
    re.IGNORECASE,
)

# Client-initiated close emission:
#   "Sending mtunnel end json: Size: N Data: { "zpn_mtunnel_end":
#    { "drop_data": N, "tag_id": N } } :isbrokerSwitch N"
# When this fires for a tag_id BEFORE we see the broker's end response,
# the close was client-initiated (graceful app-close). When the broker
# response comes first, the close was broker-initiated (broker reset /
# policy timeout / etc).
_RE_CLIENT_END = re.compile(
    r'Sending mtunnel end json[^{]*\{[^}]*"tag_id"\s*:\s*(?P<tag>\d+)'
    r'.*?:isbrokerSwitch\s+(?P<switch>\d+)',
    re.IGNORECASE,
)

# Connection-shutdown event with shutdown mode:
#   "ID=N, Zpn endConnection called for tag id: N ShutdownMode: SHUTDOWN_READ|SHUTDOWN_BOTH|..."
_RE_END_CONNECTION = re.compile(
    r"Zpn endConnection called for tag id:\s*(?P<tag>\d+)\s+"
    r"ShutdownMode:\s*(?P<mode>\S+)",
    re.IGNORECASE,
)

# The disconnect line with full per-session byte stats — the gold
# signal for "how much data actually flowed". Format:
#   "ID=N, Disconnecting Tag id: N from [::ffff:IP]:PORT for app_name: NAME,
#    stats=[Cl:(Rx:N,Tx:N) Sr:(Rx:N,Tx:N)]"
# Cl = client-side bytes (Rx from client, Tx to client)
# Sr = server-side bytes (Rx from server, Tx to server)
# In a clean session: Cl.Rx == Sr.Tx and Cl.Tx == Sr.Rx (no drops).
# When they diverge, data was dropped at one of the two pipes.
_RE_DISCONNECT_STATS = re.compile(
    r"Disconnecting Tag id:\s*(?P<tag>\d+)"
    r".*?stats=\[\s*Cl:\(Rx:(?P<cl_rx>\d+),Tx:(?P<cl_tx>\d+)\)"
    r"\s*Sr:\(Rx:(?P<sr_rx>\d+),Tx:(?P<sr_tx>\d+)\)\s*\]",
    re.IGNORECASE,
)

# Phase 24 (2026-06-17): runtime byte-flow tracking. Lets us populate
# per-session bytes even when the final disconnect-stats line is
# missing (session still open at log capture, line in a rotated-out
# file, etc). These fire on every chunked write/read so totals are
# accumulated across the session.
#
# Examples seen in real bundles:
#   DBG ID=N, Zpn client socket written bytes: 4416 Pending bytes: 0 tag id: M
#   DBG ID=N, Zpn Client socket read bytes: 19, tag id: M
#
# Naming is from the CLIENT's perspective:
#   "written" = client → server   (upload, would land in Cl.Rx → Sr.Tx)
#   "read"    = server → client   (download, would land in Sr.Rx → Cl.Tx)
_RE_RUNTIME_WRITE = re.compile(
    r"Zpn client socket written bytes:\s*(?P<bytes>\d+)"
    r".*?tag[ _]?id[: ]+(?P<tag>\d+)",
    re.IGNORECASE,
)
_RE_RUNTIME_READ = re.compile(
    r"Zpn Client socket read bytes:\s*(?P<bytes>\d+)"
    r".*?tag[ _]?id[: ]+(?P<tag>\d+)",
    re.IGNORECASE,
)

# Permissive tag-id pattern that also matches the unquoted lowercase
# form ZSATunnel uses in non-JSON lines: "tag id: 65572" / "TAG-ID=12".
# Used as the LAST-RESORT tag detection in the bare-tag fallback.
_RE_LOOSE_TAG_ID = re.compile(
    r"\btag[ _-]?id[: =]+(?P<tag>\d+)\b",
    re.IGNORECASE,
)

# Connection ID extraction from any tunnel line. ZSATunnel emits the
# per-connection numeric ID at the start of most session-related
# lines. When a line has an ID we've already seen attached to a
# session via the setup OR request line, we can attach it without
# needing tag_id. This catches lines like
#   "ID=1206691882, Successfully set SO_OOBINLINE socket option"
# that don't carry tag_id at all.
_RE_ID_REF = re.compile(
    r"\bID=(?P<id>\d+)\b"
)

# request_ack JSON. err_code:1 = success; other codes are setup
# failures we capture for context. mtunnel_id is the broker-assigned
# session ID — captured as a secondary correlation key for cross-
# log-file resolution. The optional `error` field appears on failed
# acks (e.g. BRK_MT_SETUP_FAIL_NO_POLICY_FOUND) and is captured so
# the UI can render the broker's rejection reason without needing a
# separate end record.
_RE_ACK = re.compile(
    r'\{"zpn_mtunnel_request_ack":\{"tag_id":(?P<tag>\d+),'
    r'(?:[^}]*?"mtunnel_id":"(?P<mtunnel>[^"]+)")?'
    r'(?:[^}]*?"error":"(?P<error>[^"]+)")?'
    r'.*?"err_code":(?P<code>\d+)'
)

# end JSON.
_RE_END = re.compile(
    r'\{"zpn_mtunnel_end":\{"tag_id":(?P<tag>\d+),'
    r'\s*"error":"(?P<error>[^"]+)"'
    r'.*?"err_code":(?P<code>\d+)'
    r'.*?"drop_data":(?P<drop>\d+)'
)

# Bare "tag_id" reference for general grep (used to attach loose
# data-plane lines to the session). Cheap pre-filter.
_RE_TAG_REF = re.compile(r'"tag_id"\s*:\s*(\d+)|TAG-ID=(\d+)')


# ---------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------

@dataclass
class ZpaSession:
    """One reconstructed ZPA microtunnel session, keyed on tag_id."""
    tag_id: str
    app_name: str = ""
    conn_id: Optional[str] = None
    local_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    double_encrypt: bool = False
    # IP protocol number from the request line. 6 = TCP, 17 = UDP.
    # Populated from the outbound zpn_mtunnel_request JSON.
    ip_protocol: Optional[int] = None

    setup_ts: Optional[datetime] = None
    # Time of the outbound zpn_mtunnel_request line — fires for every
    # session including those that fail at the broker. Distinct from
    # setup_ts (which is the `===>` ZPN Connection line and only fires
    # for sessions that reach connection establishment).
    request_ts: Optional[datetime] = None
    ack_ts: Optional[datetime] = None
    ack_err_code: Optional[int] = None   # 1 = success; others = failure code
    ack_error: str = ""                  # broker's rejection reason on failed acks
    # mtunnel_id is the broker-assigned session identifier from the ack
    # JSON. Captured as a secondary correlation key so sessions can be
    # cross-referenced across log files / log kinds when tag_id alone
    # is ambiguous. Empty string when no ack was seen (session may
    # have timed out before broker responded).
    mtunnel_id: str = ""
    # Broker setup latency in seconds — captured from the DBG ack line
    # "Setup Time: F.FFFFFF seconds". This is the round-trip time from
    # client request → broker accept, measured by the client. None
    # when no DBG ack was seen.
    setup_latency_s: Optional[float] = None
    # Reauth timeout in seconds from the ack JSON. Typically 604800
    # (7 days) for normal sessions; very short values indicate the
    # broker forced a near-immediate reauth.
    reauth_timeout_s: Optional[int] = None
    end_ts: Optional[datetime] = None
    end_error: str = ""                  # e.g. BRK_MT_CLOSED_FROM_ASSISTANT
    end_err_code: Optional[int] = None
    end_drop_data: Optional[int] = None
    # Whether the client sent the "mtunnel end" json BEFORE receiving
    # the broker's end response — i.e. the application closed first
    # vs the broker / server closing first. True = graceful app close;
    # False = broker / server reset.
    client_initiated_close: Optional[bool] = None
    # broker_switch flag from the "Sending mtunnel end json :isbrokerSwitch N"
    # line. True when the close was triggered by ZCC switching brokers
    # (e.g. failover), not by the application.
    broker_switch_close: Optional[bool] = None
    # Last shutdown mode observed for this session (SHUTDOWN_READ /
    # SHUTDOWN_WRITE / SHUTDOWN_BOTH). Hints at clean vs abrupt close.
    shutdown_mode: str = ""

    # Per-session data-flow stats from the disconnect line. Cl =
    # client-side, Sr = server-side. In a clean session Cl.Rx == Sr.Tx
    # and Cl.Tx == Sr.Rx; divergence indicates data dropped at one
    # pipe.
    bytes_client_rx: Optional[int] = None  # bytes received FROM client
    bytes_client_tx: Optional[int] = None  # bytes sent TO client
    bytes_server_rx: Optional[int] = None  # bytes received FROM server (= Cl.Tx ideally)
    bytes_server_tx: Optional[int] = None  # bytes sent TO server (= Cl.Rx ideally)

    # Activity counters across the session window.
    data_event_count: int = 0    # "Got data for tag_id: N" lines
    keepalive_count: int = 0     # "ZpnTimeoutHandler: Updating mtunnel entry tag_id: N" lines

    # Phase 24 (2026-06-17): runtime byte accumulators.
    # Summed from per-chunk events as the session ran:
    #   bytes_runtime_written — client → server  (uploads)
    #   bytes_runtime_read    — server → client  (downloads)
    # These give us a useful byte total even when the final disconnect
    # stats line (Cl:..., Sr:...) is missing from the bundle — common
    # for sessions still open at capture time, or whose disconnect
    # landed in a rotated-out log. When the disconnect line IS
    # captured, its values supersede the runtime sums (they're
    # authoritative; runtime can lose final pending-buffer flushes).
    bytes_runtime_written: int = 0
    bytes_runtime_read: int = 0
    # Per-direction event counts so the UI can show how many TCP/UDP
    # write+read chunks the session generated.
    runtime_write_events: int = 0
    runtime_read_events: int = 0

    # How app_name was resolved. Tracks transparency so the UI can show
    # the operator whether the app identity is solid (setup_line /
    # request) or inferred (mtunnel_xref / neighbor). Empty string for
    # sessions whose app_name remains unknown.
    #
    # Values:
    #   "setup_line"    — from `===> ID=X, ZPN Connection ... App Name=NAME`
    #                     (post-broker-approval; most authoritative)
    #   "request"       — from outbound zpn_mtunnel_request JSON
    #                     (every session has one; covers setup failures)
    #   "mtunnel_xref"  — back-filled by mtunnel_id match against another
    #                     session with a known app_name (rare; only when
    #                     the same mtunnel_id appears in multiple sessions
    #                     across log files)
    #   "neighbor"      — back-filled from an adjacent tag_id within the
    #                     same log file + 30s window (last-resort heuristic;
    #                     marked clearly so the operator can disbelieve it)
    app_name_source: str = ""

    # Cross-ref to the ZPA app registry (zpn_client_app catalog) if
    # the app_name matched a registry entry. Useful for the Search
    # drill-in: shows whether the app is BYPASSED, DELETED, etc.
    app_registry: Optional[Any] = None

    # All log lines (IndexedLine) referencing this tag_id, sorted by ts.
    lines: List[Any] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        """One-word outcome for the summary table.

        VALIDATION (2026-06-12, help.zscaler.com): BRK_MT_CLOSED_FROM_
        ASSISTANT is the documented NORMAL closure signal — the App
        Connector closed the M-Tunnel because the application server
        sent TCP FIN. So it maps to ``closed``, NOT ``broker_terminated``.
        Earlier versions of this module mis-classified it as
        broker_terminated; corrected per Zscaler's ZPA Session Status
        Codes documentation.

        Other end_error strings beginning with BRK_MT_CLOSED_FROM_* are
        surfaced as ``closed:<reason>`` so the engineer can see the
        underlying close code and look up its meaning in the docs.
        """
        if self.end_ts is None:
            if self.ack_ts is not None and self.ack_err_code == 1:
                return "open"  # established, no end seen — still active OR cut off by log rotation
            if self.ack_ts is not None:
                return "setup_failed"
            return "incomplete"
        # Normal closures (per Zscaler docs).
        if self.end_error == "BRK_MT_CLOSED_FROM_ASSISTANT":
            return "closed"
        # Other close reasons — surface the literal code so the
        # engineer can cross-reference against the ZPA Session Status
        # Codes documentation.
        if self.end_error and "NORMAL" not in self.end_error.upper():
            return f"closed:{self.end_error.lower()[:40]}"
        return "closed"

    @property
    def duration_s(self) -> Optional[float]:
        """Setup-to-end duration. None when either bound is missing."""
        if self.setup_ts is None or self.end_ts is None:
            return None
        return (self.end_ts - self.setup_ts).total_seconds()

    # ----- Phase 13 derived properties (2026-06-17) ------------------

    @property
    def total_bytes(self) -> Optional[int]:
        """Sum of all four byte counters — the simplest "how much
        data flowed" metric. None when the disconnect line wasn't seen."""
        parts = [
            self.bytes_client_rx, self.bytes_client_tx,
            self.bytes_server_rx, self.bytes_server_tx,
        ]
        if any(v is None for v in parts):
            return None
        return sum(parts)  # type: ignore[arg-type]

    @property
    def bytes_to_server(self) -> Optional[int]:
        """Bytes the app sent to the destination (client→server).
        Tracks request-volume from the user's machine.

        Phase 24 fallback chain:
          1. Authoritative: ``bytes_client_rx`` from the disconnect
             line (Cl:(Rx:N,...))
          2. Runtime: sum of ``Zpn client socket written bytes: N``
             events seen during the session
          3. None when neither is available
        """
        if self.bytes_client_rx is not None:
            return self.bytes_client_rx
        if self.bytes_runtime_written > 0:
            return self.bytes_runtime_written
        return None

    @property
    def bytes_from_server(self) -> Optional[int]:
        """Bytes the destination returned (server→client). Tracks
        response-volume.

        Phase 24 fallback chain:
          1. Authoritative: ``bytes_client_tx`` from the disconnect
             line (Cl:(...,Tx:N))
          2. Runtime: sum of ``Zpn Client socket read bytes: N``
             events seen during the session
          3. None when neither is available
        """
        if self.bytes_client_tx is not None:
            return self.bytes_client_tx
        if self.bytes_runtime_read > 0:
            return self.bytes_runtime_read
        return None

    @property
    def bytes_source(self) -> str:
        """Where the byte numbers came from — 'disconnect' (final
        stats), 'runtime' (chunked write/read events), or '' (no
        data). Useful for the UI to annotate values that were
        estimated from runtime events vs measured from the final
        disconnect-stats line."""
        if self.bytes_client_rx is not None or self.bytes_client_tx is not None:
            return "disconnect"
        if self.bytes_runtime_written or self.bytes_runtime_read:
            return "runtime"
        return ""

    @property
    def has_byte_imbalance(self) -> bool:
        """True when the four byte counters don't match the clean-
        session invariant (Cl.Rx == Sr.Tx, Cl.Tx == Sr.Rx). Indicates
        data dropped at one of the two pipes during the session."""
        parts = [
            self.bytes_client_rx, self.bytes_client_tx,
            self.bytes_server_rx, self.bytes_server_tx,
        ]
        if any(v is None for v in parts):
            return False
        # Cl side and Sr side should mirror each other.
        return (
            self.bytes_client_rx != self.bytes_server_tx
            or self.bytes_client_tx != self.bytes_server_rx
        )

    @property
    def throughput_bps(self) -> Optional[float]:
        """Bytes-per-second across the session window. Uses total_bytes
        / duration_s. None when either is unavailable. Useful for
        spotting slow-pipe symptoms — sessions that transferred plenty
        of data but took unusually long."""
        tb = self.total_bytes
        d = self.duration_s
        if tb is None or d is None or d <= 0:
            return None
        return tb / d

    @property
    def transport_label(self) -> str:
        """Human label for ip_protocol — '' when unknown."""
        if self.ip_protocol == 6:
            return "TCP"
        if self.ip_protocol == 17:
            return "UDP"
        if self.ip_protocol is None:
            return ""
        return f"proto={self.ip_protocol}"

    @property
    def close_initiator(self) -> str:
        """Human label for who closed the session: 'client', 'broker',
        'broker_switch', or '' when unknown."""
        if self.broker_switch_close:
            return "broker_switch"
        if self.client_initiated_close is True:
            return "client"
        if self.client_initiated_close is False:
            return "broker"
        return ""


# ---------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------

def extract_zpa_sessions(
    log_index: Any,
    app_registry: Optional[List[Any]] = None,
) -> List[ZpaSession]:
    """Walk the in-memory log_index for ZPA tag_id references and
    reconstruct one ZpaSession per tag_id.

    ``app_registry`` is the list from ``summary.bundle_meta["zpa_apps"]
    ["apps"]``. When provided, each session's ``app_registry`` field
    is populated with the matching registry entry (suffix-match
    against the ``app_domain``), giving the UI drill-in everything
    it needs to surface configured ports, bypass settings, etc.
    """
    if log_index is None or not getattr(log_index, "lines", None):
        return []

    # tag_id -> ZpaSession. Built up as we walk.
    sessions: Dict[str, ZpaSession] = {}

    def _get(tag: str) -> ZpaSession:
        s = sessions.get(tag)
        if s is None:
            s = ZpaSession(tag_id=tag)
            sessions[tag] = s
        return s

    for ln in log_index.lines:
        # Phase 28 (2026-06-17): direct attribute access — IndexedLine
        # always has ``body`` (slotted dataclass), so getattr-with-
        # default is needless overhead in this hot loop. The skip
        # check below catches the empty case the default was guarding.
        body = ln.body
        if not body:
            continue
        # Fast pre-filter — only inspect lines that LOOK like they
        # mention a tag_id / TAG-ID / "tag id" / "Tag id".
        #
        # Phase 28 bug fix (2026-06-17): the original filter only
        # checked "tag_id" and "TAG-ID=" — BUT several Phase 24
        # patterns use the unquoted "tag id:" / "Tag id:" form (with
        # space, no underscore), e.g. "Zpn client socket written
        # bytes: N ... tag id: M". Those lines were being silently
        # dropped before their pattern ever ran. Adding "ag id" as
        # a third check covers both "tag id" and "Tag id" without
        # needing case-insensitive matching.
        if (
            "tag_id" not in body
            and "TAG-ID=" not in body
            and "ag id" not in body
        ):
            continue

        # Setup line (`===>` post-broker-approval connection est.) —
        # carries App Name, dest, conn_id. Only fires for sessions that
        # successfully establish a connection; setup-failed sessions
        # rely on the request line below.
        m = _RE_SETUP.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            if not s.app_name:
                s.app_name = m.group("app").strip()
                s.app_name_source = "setup_line"
            s.conn_id = s.conn_id or m.group("conn_id")
            try:
                s.local_port = int(m.group("local_port"))
                s.dest_port = int(m.group("dest_port"))
            except (ValueError, TypeError):
                pass
            s.dest_ip = m.group("dest_ip")
            if "DoubleEncrypt=1" in body:
                s.double_encrypt = True
            if s.setup_ts is None:
                s.setup_ts = getattr(ln, "ts", None)
            s.lines.append(ln)
            continue

        # Outbound zpn_mtunnel_request — the client-side request to
        # the broker. Phase 11 addition (2026-06-17): this is the line
        # that resolves app_name for setup-failed sessions where the
        # `===>` setup line never fires.
        m = _RE_REQUEST.search(body)
        if m:
            req_body = m.group("body")
            tag_m = _RE_REQ_TAG_ID.search(req_body)
            if tag_m:
                tag = tag_m.group("v")
                s = _get(tag)
                # Only populate app_name if it wasn't already set by a
                # higher-confidence source (the `===>` setup line). The
                # setup line is logged AFTER broker approval so when
                # both exist, the setup-line app_name is the more
                # authoritative one — though in practice they match.
                if not s.app_name:
                    name_m = _RE_REQ_APP_NAME.search(req_body)
                    if name_m:
                        s.app_name = name_m.group("v").strip()
                        s.app_name_source = "request"
                # Always populate dest_ip / dest_port / ip_protocol /
                # double_encrypt from the request when missing — even
                # if app_name came from the setup line, these
                # operational fields might be empty.
                if not s.dest_ip:
                    dip_m = _RE_REQ_O_DIP.search(req_body)
                    if dip_m:
                        s.dest_ip = dip_m.group("v")
                if s.dest_port is None:
                    port_m = _RE_REQ_SERVER_PORT.search(req_body)
                    if port_m:
                        try:
                            s.dest_port = int(port_m.group("v"))
                        except (ValueError, TypeError):
                            pass
                if s.ip_protocol is None:
                    proto_m = _RE_REQ_IP_PROTOCOL.search(req_body)
                    if proto_m:
                        try:
                            s.ip_protocol = int(proto_m.group("v"))
                        except (ValueError, TypeError):
                            pass
                if not s.double_encrypt and _RE_REQ_DOUBLE_ENC.search(req_body):
                    s.double_encrypt = True
                if s.request_ts is None:
                    s.request_ts = getattr(ln, "ts", None)
                s.lines.append(ln)
                continue

        # request_ack — broker response. May carry mtunnel_id (always)
        # and `error` field (when the broker rejected the request).
        m = _RE_ACK.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            try:
                s.ack_err_code = int(m.group("code"))
            except (ValueError, TypeError):
                pass
            # mtunnel_id is the broker's session ID — capture as a
            # secondary correlation key. Most-recent ack wins (sessions
            # rarely re-ack but if they do, the latest mtunnel_id is
            # the authoritative one).
            mtid = m.group("mtunnel")
            if mtid:
                s.mtunnel_id = mtid
            # `error` field on the ack means the broker rejected the
            # setup — record it so the UI doesn't need to wait for the
            # end record to know why.
            ack_err = m.group("error")
            if ack_err and not s.ack_error:
                s.ack_error = ack_err
            # Phase 13: also capture reauth_timeout_s from the JSON body
            # so the session table can show how long the broker is
            # willing to leave the mtunnel up before forcing reauth.
            reauth_m = _RE_ACK_REAUTH.search(body)
            if reauth_m and s.reauth_timeout_s is None:
                try:
                    s.reauth_timeout_s = int(reauth_m.group("v"))
                except (ValueError, TypeError):
                    pass
            if s.ack_ts is None:
                s.ack_ts = getattr(ln, "ts", None)
            s.lines.append(ln)
            continue

        # ----- Phase 13 (2026-06-17) — per-session lifecycle events --

        # DBG companion to the INF ack carrying broker setup latency.
        m = _RE_SETUP_TIME.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            try:
                s.setup_latency_s = float(m.group("seconds"))
            except (ValueError, TypeError):
                pass
            s.lines.append(ln)
            continue

        # Transport protocol identification for this tag_id. Fires
        # repeatedly (once per data event in some builds); first-seen
        # wins.
        m = _RE_CLIENT_PROTO.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            if s.ip_protocol is None:
                try:
                    s.ip_protocol = int(m.group("proto"))
                except (ValueError, TypeError):
                    pass
            s.lines.append(ln)
            continue

        # Data-plane "Got data for tag_id: N" counter. Cheap to count;
        # high values indicate an active session.
        m = _RE_GOT_DATA.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            s.data_event_count += 1
            # Don't append every data event to s.lines — would balloon
            # memory on chatty sessions. The counter is the signal.
            continue

        # Keep-alive / reauth-timer reset events.
        m = _RE_KEEPALIVE.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            s.keepalive_count += 1
            # If we haven't captured reauth_timeout_s from the ack JSON
            # (e.g. ack body didn't include it), fall back to this line.
            if s.reauth_timeout_s is None:
                try:
                    s.reauth_timeout_s = int(m.group("timeout"))
                except (ValueError, TypeError):
                    pass
            continue

        # Client emitting an "mtunnel end" message — graceful close
        # initiated by the application side.
        m = _RE_CLIENT_END.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            # client_initiated_close is True only if this client-end
            # arrived BEFORE the broker's end response (s.end_ts is
            # None at this point in the walk). After end_ts is set,
            # subsequent client-ends are the cleanup pair (drop_data:1)
            # so they don't change the verdict.
            if s.client_initiated_close is None:
                s.client_initiated_close = s.end_ts is None
            if s.broker_switch_close is None:
                try:
                    s.broker_switch_close = int(m.group("switch")) == 1
                except (ValueError, TypeError):
                    pass
            s.lines.append(ln)
            continue

        # Shutdown-mode event.
        m = _RE_END_CONNECTION.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            # Most-recent shutdown wins — typical sequence is
            # SHUTDOWN_READ → SHUTDOWN_BOTH; final state is BOTH.
            s.shutdown_mode = m.group("mode")
            s.lines.append(ln)
            continue

        # Disconnect line — carries the per-session byte stats.
        # GOLD signal: tells the engineer exactly how much data flowed.
        m = _RE_DISCONNECT_STATS.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            try:
                s.bytes_client_rx = int(m.group("cl_rx"))
                s.bytes_client_tx = int(m.group("cl_tx"))
                s.bytes_server_rx = int(m.group("sr_rx"))
                s.bytes_server_tx = int(m.group("sr_tx"))
            except (ValueError, TypeError):
                pass
            s.lines.append(ln)
            continue

        # Phase 24: runtime byte-flow chunks. Accumulate per session
        # so the UI has a usable bytes value even when the final
        # disconnect-stats line is missing.
        m = _RE_RUNTIME_WRITE.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            try:
                s.bytes_runtime_written += int(m.group("bytes"))
                s.runtime_write_events += 1
            except (ValueError, TypeError):
                pass
            s.lines.append(ln)
            continue
        m = _RE_RUNTIME_READ.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            try:
                s.bytes_runtime_read += int(m.group("bytes"))
                s.runtime_read_events += 1
            except (ValueError, TypeError):
                pass
            s.lines.append(ln)
            continue

        # end — mtunnel closed. The double-end (drop_data:0 + :1)
        # within ~30 ms is the normal pair; we record only the FIRST
        # end (drop_data:0) as the canonical close. The second one
        # gets attached as a line but doesn't overwrite end_ts /
        # end_error.
        m = _RE_END.search(body)
        if m:
            tag = m.group("tag")
            s = _get(tag)
            if s.end_ts is None:
                s.end_ts = getattr(ln, "ts", None)
                s.end_error = m.group("error")
                try:
                    s.end_err_code = int(m.group("code"))
                    s.end_drop_data = int(m.group("drop"))
                except (ValueError, TypeError):
                    pass
            s.lines.append(ln)
            continue

        # Phase 24 multi-pronged fallback. Each ZSATunnel line that
        # didn't match a specific pattern above might still belong
        # to a known session. Three matching strategies, in order:
        #
        #   a. JSON-style "tag_id": N — already widely supported
        #   b. Loose "tag id: N" / "TAG-ID=N" — the form ZSATunnel
        #      uses in non-JSON debug lines (e.g. "Zpn client socket
        #      written bytes: 4416 ... tag id: 65572")
        #   c. Conn-ID-based "ID=N" — for the ZPA lifecycle debug
        #      lines that don't carry tag_id at all (e.g.
        #      "ID=1206691882, Successfully set SO_OOBINLINE...")
        attached = False
        tag_match = re.search(r'"tag_id"\s*:\s*(\d+)', body)
        if tag_match:
            tag = tag_match.group(1)
            if tag in sessions:
                sessions[tag].lines.append(ln)
                attached = True
        if not attached:
            loose = _RE_LOOSE_TAG_ID.search(body)
            if loose:
                tag = loose.group("tag")
                if tag in sessions:
                    sessions[tag].lines.append(ln)
                    attached = True
        if not attached:
            id_match = _RE_ID_REF.search(body)
            if id_match:
                conn = id_match.group("id")
                # Find a session with this conn_id. Cheap linear scan
                # — sessions dict is small (hundreds at most), and
                # this branch only fires for lines that didn't match
                # any prior pattern.
                for sess in sessions.values():
                    if sess.conn_id == conn:
                        sess.lines.append(ln)
                        break

    # ----- Phase 11 + 12 back-fill passes (2026-06-17) ---------------
    # Some sessions still have no app_name after the main scan — the
    # outbound request line might have been in a rotated-out log,
    # throttled, or skipped due to a dispatch-order edge case. Three
    # fallback strategies, applied in order:
    #
    # 0. Independent log_index re-walk for the request pattern. This
    #    is the most reliable strategy: it does NOT depend on what the
    #    main extraction loop did, so it catches sessions whose request
    #    line was the FIRST signal of that tag_id (in the old code's
    #    bare-tag fallback, that line would have been dropped because
    #    the session didn't exist yet). Phase 12 addition.
    #
    # 1. mtunnel_id cross-reference. If session A has a known mtunnel_id
    #    but empty app_name, and session B has the same mtunnel_id AND
    #    a known app_name, use B's. In practice mtunnel_ids are unique
    #    per attempt so this is rare, but if a session was reconstructed
    #    twice (e.g. log lines split across files), this catches it.
    #
    # 2. tag_id-adjacency inference. ZSATunnel emits tag_ids in strict
    #    monotonic order per process. If session N has no app_name but
    #    session N-1 and session N+1 both have the same app_name AND
    #    the timestamps are within 60s, the unknown session was almost
    #    certainly the same app (typical retry-loop pattern). Mark
    #    these clearly as "neighbor" so the operator can disbelieve
    #    them if context suggests otherwise.

    if sessions:
        # ----- Strategy 0: independent request-line re-walk ----------
        # Build a tag_id -> (app_name, dest_ip, server_port, ip_proto)
        # map by scanning EVERY line in log_index.lines for the request
        # pattern. Then back-fill any session with empty app_name.
        #
        # This pass runs independently of the main extraction loop, so
        # it survives the failure mode where the main loop's regex
        # dispatch missed the request line (e.g. if the main loop's
        # _RE_SETUP false-matched first, or if Python module-cache
        # weirdness loaded an older version of the dispatcher).
        #
        # Cost: one extra pass over log_index.lines. Cheap — only the
        # ~0.1% of lines that contain "zpn_mtunnel_request" actually
        # do regex work, the rest are filtered by a fast substring test.
        request_attrs_by_tag: Dict[str, Dict[str, Any]] = {}
        # Phase 28: direct attr access — IndexedLine.body always exists.
        for ln in log_index.lines:
            body = ln.body
            if not body or '"zpn_mtunnel_request"' not in body:
                continue
            m = _RE_REQUEST.search(body)
            if not m:
                continue
            req_body = m.group("body")
            tag_m = _RE_REQ_TAG_ID.search(req_body)
            if not tag_m:
                continue
            tag = tag_m.group("v")
            # First-seen wins (the earliest request defines the session).
            if tag in request_attrs_by_tag:
                continue
            attrs: Dict[str, Any] = {}
            name_m = _RE_REQ_APP_NAME.search(req_body)
            if name_m:
                attrs["app_name"] = name_m.group("v").strip()
            dip_m = _RE_REQ_O_DIP.search(req_body)
            if dip_m:
                attrs["dest_ip"] = dip_m.group("v")
            port_m = _RE_REQ_SERVER_PORT.search(req_body)
            if port_m:
                try:
                    attrs["dest_port"] = int(port_m.group("v"))
                except (ValueError, TypeError):
                    pass
            proto_m = _RE_REQ_IP_PROTOCOL.search(req_body)
            if proto_m:
                try:
                    attrs["ip_protocol"] = int(proto_m.group("v"))
                except (ValueError, TypeError):
                    pass
            attrs["request_ts"] = getattr(ln, "ts", None)
            request_attrs_by_tag[tag] = attrs

        # Apply the back-fill: only touch fields that are currently
        # missing on the session. Don't override a setup-line app_name.
        for s in sessions.values():
            attrs = request_attrs_by_tag.get(s.tag_id)
            if attrs is None:
                continue
            if not s.app_name and attrs.get("app_name"):
                s.app_name = attrs["app_name"]
                s.app_name_source = "request"
            if not s.dest_ip and attrs.get("dest_ip"):
                s.dest_ip = attrs["dest_ip"]
            if s.dest_port is None and attrs.get("dest_port") is not None:
                s.dest_port = attrs["dest_port"]
            if s.ip_protocol is None and attrs.get("ip_protocol") is not None:
                s.ip_protocol = attrs["ip_protocol"]
            if s.request_ts is None and attrs.get("request_ts") is not None:
                s.request_ts = attrs["request_ts"]

        # Diagnostic: surface in stderr when many sessions remain
        # unresolved after Strategy 0. Helps future debugging: if this
        # count is high on a bundle that DOES have request lines, the
        # log_index byte budget likely truncated them out (UI_BUDGET
        # in ui/analyse.py defaults to 50 MB).
        unresolved_after_s0 = sum(
            1 for s in sessions.values() if not s.app_name
        )
        if unresolved_after_s0 > 5 and unresolved_after_s0 > len(sessions) // 4:
            import sys
            print(
                f"[zpa_session_correlator] {unresolved_after_s0} of "
                f"{len(sessions)} sessions have no app_name after "
                f"request-line re-walk — check log_index byte budget "
                f"(UI_BUDGET in ui/analyse.py) if tunnel logs were "
                f"truncated. Strategies 1 & 2 may still resolve some.",
                file=sys.stderr,
            )

        # Build a mtunnel_id -> session index for strategy 1.
        by_mtid: Dict[str, ZpaSession] = {}
        for s in sessions.values():
            if s.mtunnel_id:
                by_mtid.setdefault(s.mtunnel_id, s)

        for s in sessions.values():
            if s.app_name or not s.mtunnel_id:
                continue
            other = by_mtid.get(s.mtunnel_id)
            if other is not None and other is not s and other.app_name:
                s.app_name = other.app_name
                s.app_name_source = "mtunnel_xref"

        # Strategy 2: tag_id neighbor inference. Build a sorted list
        # by tag_id (numeric where possible) so we can look at N-1 / N+1.
        def _tag_num(t: str) -> int:
            try:
                return int(t)
            except (ValueError, TypeError):
                return -1

        sorted_sessions = sorted(
            sessions.values(),
            key=lambda x: (_tag_num(x.tag_id), x.tag_id),
        )
        for i, s in enumerate(sorted_sessions):
            if s.app_name:
                continue
            # Anchor timestamp: prefer request_ts, fall back to ack_ts.
            anchor = s.request_ts or s.ack_ts or s.end_ts
            if anchor is None:
                continue
            # Look left + right for the nearest sibling with a known
            # app_name + a timestamp within 60s of anchor.
            window = timedelta(seconds=60)
            candidates: List[ZpaSession] = []
            for j in (i - 1, i + 1):
                if 0 <= j < len(sorted_sessions):
                    sib = sorted_sessions[j]
                    if not sib.app_name:
                        continue
                    sib_ts = (
                        sib.request_ts or sib.ack_ts or sib.end_ts
                    )
                    if sib_ts is not None and abs(sib_ts - anchor) <= window:
                        candidates.append(sib)
            # Strongest signal: BOTH neighbors agree on the same app.
            # Weaker but accepted: a single same-app neighbor.
            if len(candidates) >= 2 and (
                candidates[0].app_name == candidates[1].app_name
            ):
                s.app_name = candidates[0].app_name
                s.app_name_source = "neighbor"
            elif len(candidates) == 1:
                s.app_name = candidates[0].app_name
                s.app_name_source = "neighbor"
            # When neighbors disagree, leave the session unknown rather
            # than guess. The operator can drill into the log lines.

    # ----- Strategy 3 (Phase 38, 2026-06-19): pre-setup context -------
    # The main loop only attaches lines that match a tag_id-anchored
    # regex pattern. That misses the FRONT of every session: the
    # broker DNS-check exchange ("ZCC asks broker if storefront is a
    # ZPA app → broker says yes → ZCC writes the CGNAT local response")
    # and the per-socket setup events that carry the conn_id but not
    # the tag_id (e.g. "Successfully set SO_OOBINLINE socket option").
    #
    # Engineers drilling into a session want to see THIS context — the
    # "ZCC checking if it's a ZPA domain" steps the user explicitly
    # called out. Without it, the session looks like it starts at the
    # ===> arrow with no prior history.
    #
    # Strategy 3 does a single pass over log_index, building two
    # lookup tables (app_name → sessions, conn_id → sessions), then
    # attaches matching lines that aren't already on the session.
    if sessions:
        app_to_sessions: Dict[str, List[ZpaSession]] = {}
        conn_to_sessions: Dict[str, List[ZpaSession]] = {}
        for s in sessions.values():
            if s.app_name:
                app_to_sessions.setdefault(
                    s.app_name.lower(), [],
                ).append(s)
            if s.conn_id:
                conn_to_sessions.setdefault(s.conn_id, []).append(s)
        # Track already-attached lines per session by Python object
        # identity. Using id(ln) is safe — log_index.lines is held
        # alive by the caller for the whole correlation pass.
        attached_ids: Dict[str, set] = {
            s.tag_id: set(id(ln) for ln in s.lines)
            for s in sessions.values()
        }
        # Fast substring pre-filter to avoid regex on every line.
        for ln in log_index.lines:
            body = ln.body
            if not body:
                continue
            attached_to: List[ZpaSession] = []
            # --- DNS-check / CGNAT-response attachment ---
            # Match by app_name substring (case-insensitive). The
            # pre-filter keeps the cost of the inner loop down — we
            # only scan app_to_sessions when the line LOOKS like
            # ZPA-domain plumbing.
            if app_to_sessions and (
                "zpn_dns_client_check" in body
                or "ZPN domain:" in body
                or "DNS request to broker" in body
            ):
                body_low = body.lower()
                for app, sess_list in app_to_sessions.items():
                    if app in body_low:
                        attached_to.extend(sess_list)
                        break
            # --- conn_id-anchored socket / lifecycle attachment ---
            # Lines like "ID=N, Successfully set SO_OOBINLINE" carry
            # conn_id but no tag_id, so the main loop's prefilter
            # rejected them. The Phase 24 _RE_ID_REF fallback inside
            # the main loop only runs for lines that DID pass the
            # prefilter — these never do. Attach here.
            if conn_to_sessions and "ID=" in body:
                m = _RE_ID_REF.search(body)
                if m:
                    conn = m.group("id")
                    sess_list = conn_to_sessions.get(conn)
                    if sess_list:
                        attached_to.extend(sess_list)
            # Dedupe + append. Each session keeps at most one copy of
            # each line.
            if attached_to:
                # Avoid duplicate work for sessions that appear twice
                # (e.g. matched by both DNS app_name and conn_id —
                # rare but possible).
                seen_in_this_line: set = set()
                for s in attached_to:
                    if s.tag_id in seen_in_this_line:
                        continue
                    seen_in_this_line.add(s.tag_id)
                    if id(ln) not in attached_ids[s.tag_id]:
                        s.lines.append(ln)
                        attached_ids[s.tag_id].add(id(ln))

    # App-registry cross-reference. For each session whose app_name is
    # known, look it up in the registry.
    if app_registry:
        try:
            from zcc_diag.zpa_apps import find_app_for_domain
            for s in sessions.values():
                if s.app_name:
                    s.app_registry = find_app_for_domain(
                        app_registry, s.app_name,
                    )
        except Exception:
            # Phase 58e-L2 (2026-07-08): app-registry cross-reference is
            # non-fatal (the session view still renders without an
            # app_registry field), but the prior silent swallow made it
            # impossible to tell whether the import failed, the registry
            # was mis-shaped, or every session lacked app_name. Log so a
            # future MSSP engineer can diagnose during triage.
            log.exception("app_registry cross-reference failed")

    # Sort each session's lines and the session list by start time.
    #
    # Phase 58e-H3 (2026-07-08): every real ZCC timestamp is tz-aware UTC
    # (see log_parser._parse_ts). If we defaulted to a naive datetime.min
    # / datetime.max here, sorting mixed lists would raise
    # "can't compare offset-naive and offset-aware datetimes". Use aware
    # sentinels pinned to UTC.
    _AWARE_MIN = datetime.min.replace(tzinfo=timezone.utc)
    _AWARE_MAX = datetime.max.replace(tzinfo=timezone.utc)
    for s in sessions.values():
        s.lines.sort(key=lambda x: getattr(x, "ts", _AWARE_MIN))

    return sorted(
        sessions.values(),
        key=lambda s: (
            s.setup_ts or s.request_ts or s.ack_ts or s.end_ts
            or _AWARE_MAX
        ),
    )


# ---------------------------------------------------------------------
# Render helpers (table + per-session phase view)
# ---------------------------------------------------------------------

def sessions_summary_table(
    sessions: List[ZpaSession],
) -> List[Dict[str, Any]]:
    """One row per session, suitable for st.dataframe / st.table.

    Columns chosen so the engineer can scan a list of ZPA sessions and
    pick the interesting ones to drill into:

      Setup time   — when the mtunnel was opened
      App          — the connector application targeted
      Outcome      — open / closed / setup_failed / closed:<reason>
                     / incomplete  (post-2026-06-12 vocabulary; the
                     historical "broker_terminated" was split into
                     "closed" (NORMAL) and "closed:<reason>" (non-NORMAL)
                     after Zscaler docs validated that
                     BRK_MT_CLOSED_FROM_ASSISTANT is a normal close)
      Duration     — setup-to-end in seconds
      Dest         — local:port -> remote:port
      Tag ID       — for grep / drill-in
      Double encr  — bool, surfaced because customers sometimes config
                     double-encrypt for sensitive apps and want to
                     confirm it's enforced
    """
    rows = []
    for s in sessions:
        # Destination block. For setup-failed sessions we don't have a
        # local_port (no `===>` line), but we DO have dest_ip + dest_port
        # from the outbound request — render those alone.
        if s.local_port and s.dest_ip and s.dest_port:
            dest = f":{s.local_port} -> {s.dest_ip}:{s.dest_port}"
        elif s.dest_ip and s.dest_port:
            proto = (
                "TCP" if s.ip_protocol == 6
                else "UDP" if s.ip_protocol == 17
                else ""
            )
            dest = (
                f"-> {s.dest_ip}:{s.dest_port}"
                + (f" ({proto})" if proto else "")
            )
        else:
            dest = ""
        dur = s.duration_s
        dur_str = f"{dur:.2f}s" if dur is not None else "—"
        # Registry annotations
        reg_flag = ""
        if s.app_registry is not None:
            if getattr(s.app_registry, "bypass", False):
                reg_flag = "BYPASS"
            elif getattr(s.app_registry, "deleted", False):
                reg_flag = "DELETED"
        # Render app name with a confidence annotation when the source
        # is anything other than the authoritative setup line or the
        # outbound request. "(via neighbor)" tells the operator the
        # value was inferred from adjacent sessions and should be
        # verified.
        if s.app_name:
            if s.app_name_source == "neighbor":
                app_str = f"{s.app_name} (inferred)"
            elif s.app_name_source == "mtunnel_xref":
                app_str = f"{s.app_name} (via mtunnel_id)"
            else:
                app_str = s.app_name
        else:
            app_str = "(unknown)"
        # Phase 13: surface lifecycle metrics in the summary table.
        # Format byte totals as human-readable to fit in the column —
        # e.g. 31079 -> "30.4 KB", 1234567 -> "1.2 MB".
        def _fmt_bytes(n: Optional[int]) -> str:
            if n is None:
                return "—"
            if n < 1024:
                return f"{n} B"
            if n < 1024 * 1024:
                return f"{n / 1024:.1f} KB"
            if n < 1024 * 1024 * 1024:
                return f"{n / (1024 * 1024):.1f} MB"
            return f"{n / (1024 * 1024 * 1024):.2f} GB"

        # Phase 24: annotate runtime-sourced bytes with a "~" prefix so
        # the engineer knows they're accumulated from chunked write/read
        # events vs the authoritative final disconnect-stats line.
        _src = s.bytes_source
        _suffix = " (≈)" if _src == "runtime" else ""
        rx_str = (_fmt_bytes(s.bytes_from_server) + _suffix
                  if s.bytes_from_server is not None else "—")
        tx_str = (_fmt_bytes(s.bytes_to_server) + _suffix
                  if s.bytes_to_server is not None else "—")
        # Setup latency in ms (broker round-trip — typically 50-200ms).
        setup_ms = (
            f"{s.setup_latency_s * 1000:.0f} ms"
            if s.setup_latency_s is not None else "—"
        )
        # Close initiator — 'client' (graceful) vs 'broker' (server / broker reset)
        # vs 'broker_switch' (failover) vs '' (unknown).
        rows.append({
            "Setup time": (
                s.setup_ts.isoformat() if s.setup_ts else
                s.request_ts.isoformat() if s.request_ts else
                (s.ack_ts.isoformat() if s.ack_ts else "")
            ),
            "App": app_str,
            "Reg flag": reg_flag,
            "Outcome": s.outcome,
            "Duration": dur_str,
            "Setup": setup_ms,            # broker setup latency
            "↓ from svr": rx_str,         # bytes received from server
            "↑ to svr": tx_str,           # bytes sent to server
            "Events": s.data_event_count if s.data_event_count else "—",
            "Keep-alives": s.keepalive_count if s.keepalive_count else "—",
            "Close by": s.close_initiator or "—",
            "Drop": "⚠" if s.has_byte_imbalance else "",
            "Transport": s.transport_label,
            "Dest": dest,
            "Tag ID": s.tag_id,
            "DoubleEnc": "yes" if s.double_encrypt else "",
        })
    return rows


def session_phase_lines(session: ZpaSession) -> List[Any]:
    """Return the per-session log lines for the drill-in view. Already
    sorted by timestamp."""
    return list(session.lines)


def per_app_analytics(
    sessions: List[ZpaSession],
) -> List[Dict[str, Any]]:
    """Aggregate sessions by app_name and compute duration statistics.

    Returns one row per app_name::

        {
            "app_name": "storefront.corp-a.example",
            "total_sessions": 12,
            "closed": 7,            # NORMAL closures (BRK_MT_CLOSED_FROM_ASSISTANT)
            "open": 2,              # established, still active
            "setup_failed": 0,      # ack received but never ended
            "other": 3,             # non-NORMAL closures (e.g.
                                    #   closed:brk_mt_setup_fail_no_policy_found).
                                    # Was historically "broker_terminated"
                                    # until 2026-06-12, when Zscaler docs
                                    # confirmed BRK_MT_CLOSED_FROM_ASSISTANT
                                    # is a NORMAL close and the bucket was
                                    # redefined.
            "success_rate_pct": 70.0,   # closed / (closed + setup_failed + other) * 100
            "avg_duration_s": 4.7,
            "median_duration_s": 3.2,
            "min_duration_s": 0.6,
            "max_duration_s": 28.4,
            "first_seen": datetime(...),
            "last_seen": datetime(...),
        }

    Sessions with no app_name (or "(unknown app)") are aggregated under
    "(unknown)" — typically loose tag_id references from rotated logs.
    """
    from collections import defaultdict
    import statistics

    by_app: Dict[str, List[ZpaSession]] = defaultdict(list)
    for s in sessions:
        key = s.app_name or "(unknown)"
        by_app[key].append(s)

    out = []
    for app, lst in by_app.items():
        outcomes: Dict[str, int] = {
            "closed": 0, "open": 0, "setup_failed": 0, "other": 0,
        }
        durations = []
        first_seen = None
        last_seen = None
        for s in lst:
            oc = s.outcome
            if oc in outcomes:
                outcomes[oc] += 1
            else:
                # "closed:<reason>" or anything else not in the basic
                # four buckets — count as "other".
                outcomes["other"] += 1
            d = s.duration_s
            if d is not None:
                durations.append(d)
            # First/last across setup_ts OR end_ts.
            for ts in (s.setup_ts, s.end_ts):
                if ts is None:
                    continue
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

        total = len(lst)
        # Success rate = normal closes / (normal closes + setup
        # failures + other-close-codes). "Open" sessions are excluded
        # because they're in-flight — neither pass nor fail yet.
        decisive = (
            outcomes["closed"]
            + outcomes["setup_failed"]
            + outcomes["other"]
        )
        success_rate = (
            (outcomes["closed"] / decisive) * 100.0
            if decisive > 0 else 0.0
        )

        if durations:
            avg_d = statistics.mean(durations)
            med_d = statistics.median(durations)
            min_d = min(durations)
            max_d = max(durations)
        else:
            avg_d = med_d = min_d = max_d = None

        out.append({
            "app_name": app,
            "total_sessions": total,
            **outcomes,
            "success_rate_pct": round(success_rate, 1),
            "avg_duration_s": round(avg_d, 2) if avg_d is not None else None,
            "median_duration_s": round(med_d, 2) if med_d is not None else None,
            "min_duration_s": round(min_d, 2) if min_d is not None else None,
            "max_duration_s": round(max_d, 2) if max_d is not None else None,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })

    # Sort by total_sessions descending then by success_rate ascending
    # — the most-active + most-broken apps land at the top.
    out.sort(
        key=lambda r: (-r["total_sessions"], r["success_rate_pct"]),
    )
    return out


# Backwards-compat aliases.
_extract_zpa_sessions = extract_zpa_sessions
_sessions_summary_table = sessions_summary_table
_session_phase_lines = session_phase_lines
_per_app_analytics = per_app_analytics
