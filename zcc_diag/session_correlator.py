"""
Session correlation for the Search module.

Given a search hit (a single log line that mentions a host/URL/IP),
reconstructs the FULL connection lifecycle by walking the surrounding
±N-second window and grouping every related log line into a single
Session.

Why this matters:
  * The toolkit's tunnel log line ``DBG ID=1317841015, HTTPS, SNI-Host=
    example-tenant-b.my.salesforce.com`` is meaningless on its own.
    The interesting story is what happened *around* it -- DNS resolved
    to which IPs, PAC made what decision, did the tunnel api response
    say BYPASS or TUNNEL, was a broker assigned, did SSL inspection
    fire, did the server respond.
  * The ``ID=<N>`` in tunnel logs is a stable per-connection identifier.
    The PID is the tunnel process; TIDs are pooled and rotate, so they
    are NOT reliable session keys on their own.
  * Pre-ID phase lines (DNS resolve, Encoded URL) don't carry the ID
    but share the hostname with the immediately-following PAC parse
    line. We link them via (hostname, ±100 ms, same PID).

Public API:
    find_sessions_for_query(bundle, query, time_window_s=30) -> List[Session]
    sessions_summary_table(sessions) -> List[Dict]      # for the UI table
    session_phase_lines(session) -> List[PhaseLine]     # for the drill-in

This module reads files directly from the bundle (re-opening them is
cheap relative to a full parse). For multi-bundle batch search the
caller should cache the resulting Session list.
"""

from __future__ import annotations

import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------
# Line-level parsing
# ---------------------------------------------------------------------
#
# Format A (the only one any modern ZCC bundle emits) looks like:
#   2026-06-09 18:26:28.262134(-0500)[29976:29748] DBG ID=21862756, ...
#
# We capture: timestamp + tz offset, pid, tid, level, body.

_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+)"
    r"(?P<tz>\([+-]\d{4}\))?"
    r"\[(?P<pid>\d+):(?P<tid>\d+)\]\s+"
    r"(?P<level>DBG|INF|WRN|ERR|CRT|TRC)\s+"
    r"(?P<body>.*)$"
)

# Session-ID extractor. The `ID=` token always begins after `DBG `/`INF `
# but never appears in pre-ID phase lines (DNS resolve, Encoded URL).
_ID_RE = re.compile(r"\bID=(?P<id>\d+)")

# Hostname extractors. Each ZCC phase logs the host slightly differently,
# so we use a per-phase regex list and pick whichever matches.
_HOST_PATTERNS = [
    # DNS resolution
    re.compile(r"resolveDnsWithFamilyPriority(?:GW)?:\s+Host:\s+(?P<h>[^\s]+)"),
    # Encoded URL
    re.compile(r"Encoded URL:\s+https?://(?P<h>[^/\s]+)"),
    re.compile(r"Encoded Host:\s+(?P<h>[^\s]+)"),
    # PAC parse
    re.compile(r"PAC Parse Host:\s+(?P<h>[^\s]+)"),
    # Tunnel api request -- JSON has host: "X" or url:"https://X/..."
    re.compile(r'"host"\s*:\s*"(?P<h>[^"]+)"'),
    re.compile(r'"url"\s*:\s*"https?://(?P<h>[^/"]+)'),
    # Tunnel decision context
    re.compile(r"getTunnelRequestTypeJson:.*?\bhost:\s+(?P<h>[^\s]+)"),
    # SNI on TLS handshake
    re.compile(r"SNI-Host=(?P<h>[^\s,]+)"),
    # readFromClient pre-SNI
    re.compile(r"readFromClient:\s+Host(?:\s+Address)?:\s+(?P<h>[^\s]+)"),
]


@dataclass
class LogLine:
    """A single parsed tunnel-log line."""
    ts: datetime
    pid: str
    tid: str
    level: str
    body: str
    source_file: str          # filename (basename, no path)
    line_no: int              # 1-based line number in the source file
    # Derived:
    session_id: Optional[str] = None     # the ID=<N> token, if present
    host: Optional[str] = None           # hostname mentioned in the line, if any


def _parse_line(raw: str) -> Optional[Dict[str, str]]:
    m = _LINE_RE.match(raw)
    if not m:
        return None
    return m.groupdict()


def _extract_host(body: str) -> Optional[str]:
    for pat in _HOST_PATTERNS:
        m = pat.search(body)
        if m:
            return m.group("h").lower()
    return None


def _extract_session_id(body: str) -> Optional[str]:
    m = _ID_RE.search(body)
    if m:
        return m.group("id")
    return None


# ---------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------

# Phase order is what determines the row layout in the drill-in card.
PHASES = ("Resolve", "Policy", "Decision", "Setup", "Data", "Teardown", "Error")


@dataclass
class PhaseLine:
    """A single log line tagged with its phase."""
    phase: str
    ts: datetime
    component: str          # tunnel, service, tray, upm, ...
    line: str               # the raw log line


@dataclass
class Session:
    """A reconstructed connection lifecycle."""
    session_id: Optional[str]                 # the ID=<N> when known
    pid: str
    host: Optional[str]
    pivot_ts: datetime                        # the search hit's timestamp
    start_ts: datetime
    end_ts: datetime
    resolved_ips: List[str] = field(default_factory=list)
    pac_decision: str = ""                    # TUNNEL / BYPASS / DIRECT / BLOCK
    pac_proxy_chain: str = ""                 # the proxy chain string
    tunnel_request_json: str = ""             # raw JSON of Tunnel api request
    broker_ip: str = ""
    broker_name: str = ""
    broker_type: int = 0                      # 0=ZIA, 1=ZPA, etc.
    sme_used: str = ""                        # SME IP eventually picked
    service: str = ""                         # ZIA / ZPA / direct
    outcome: str = "unknown"                  # allowed / blocked / reset / timeout / unknown
    status_code: Optional[int] = None
    latency_ms: Optional[int] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    error_messages: List[str] = field(default_factory=list)
    phase_lines: List[PhaseLine] = field(default_factory=list)
    line_count: int = 0


# ---------------------------------------------------------------------
# Phase classifier
# ---------------------------------------------------------------------

def _phase_for(body: str) -> str:
    """Return the phase label for a tunnel-log line body.

    Pattern list originally audited 2026-06-10 against real ZSATunnel
    data. Order matters: Error wins over everything (so an error
    during Decision still gets the Error bucket); then phases in
    temporal order.

    Phase 35 (2026-06-19): added ZPA mtunnel / ZPN flow recognition
    grounded in Example Tenant A bundle 2026-06-18 where 100% of tunnel lines
    fell into the default Decision bucket because the prior
    classifier knew ZIA shapes only. The full ZPA microtunnel
    lifecycle has these markers:
      - "Got mtunnel request:" — inbound request from client app
        (Resolve phase — the moment ZCC sees the connection attempt)
      - "===> ID=N, ZPN Connection local:S->D" — outbound connection
        kicked off (Setup phase)
      - "zpn_mtunnel_request" / "_ack" — broker handshake (Setup)
      - "client for tag_id: N = proto=...; Double encrypt: ..."  —
        per-flow setup confirmation (Setup)
      - "Got data for tag_id: N" — data plane traffic (Data)
      - "Updating mtunnel entry tag_id: N, timeout:" — keepalive (Data)
      - "Sending mtunnel end json" — outbound teardown (Teardown)
      - "zpn_mtunnel_end" — broker confirms teardown (Teardown)
      - "BRK_MT_SETUP_FAIL_*" / "BRK_MT_CLOSED_*" — broker rejections
        (Error — these are the smoking guns for SAML expiry / policy
        miss / authentication required diagnostics)
    """
    b = body
    # ---- Error phase (highest priority) ----
    # ZPA broker rejection codes — BRK_MT_SETUP_FAIL_* and
    # BRK_MT_CLOSED_* — are unambiguously errors and the most
    # important triage signal in ZPA flows. Caught BEFORE the
    # generic 'failed' check so the literal string match wins.
    if "BRK_MT_SETUP_FAIL" in b or "BRK_MT_CLOSED" in b:
        return "Error"
    if "SAML_EXPIRED" in b or "AUTHENTICATION_REQUIRED" in b:
        return "Error"
    if "errorMessage" in b or "ZSCALER ERROR" in b or "failed" in b.lower():
        if "failed" in b.lower() and ("dns" in b.lower() or "resolve" in b.lower()):
            # Specifically a DNS failure -- still Resolve phase for ordering
            return "Resolve"
        return "Error"
    # zpn_mtunnel_*_ack / _end lines carrying an "error" payload —
    # the response JSON itself indicates broker-side failure even if
    # the line level is INF. Without this, the SAML_EXPIRED broker
    # response renders in Decision phase next to healthy traffic.
    if ("zpn_mtunnel_request_ack error:" in b
            or "zpn_mtunnel_end error:" in b):
        return "Error"

    # ---- Resolve phase ----
    # ZIA: DNS resolution. ZPA: the broker DNS-check exchange is the
    # first the tunnel sees of a new ZPA connection — ZCC asks the
    # broker if the requested domain is a ZPA app, broker confirms
    # and returns the CGNAT IP, then ZCC writes the local DNS
    # response. All three of those are Resolve phase.
    if "resolveDnsWithFamilyPriority" in b or "GetHostByName" in b:
        return "Resolve"
    if "Got mtunnel request:" in b or "mtunnel request from client" in b:
        return "Resolve"
    if "zpn_dns_client_check" in b:
        return "Resolve"
    if "ZPN domain:" in b:
        # "DNS: Send local A response for ZPN domain: app.foo.com -> 100.64.1.1"
        return "Resolve"
    if "Send DNS request to broker" in b:
        return "Resolve"

    # ---- Policy phase ----
    if ("PAC Parse Host:" in b or "Encoded URL:" in b
            or "Encoded Host:" in b or "pacparser_find_proxy" in b):
        return "Policy"

    # ---- Decision phase ----
    # ZIA: api request/response. ZPA: app-segment match / domain
    # routing lookup live here too.
    if ("getTunnelRequestType" in b or "Tunnel api request:" in b
            or "Tunnel api response:" in b):
        return "Decision"
    if ("zpa_domain_match" in b or "App Cache" in b
            or "Found in App Cache" in b
            or "Domain Found" in b):
        return "Decision"

    # ---- Setup phase ----
    # ZIA: TUN-Proxy / SME / SNI / TLS. ZPA: ZPN connection arrow,
    # mtunnel request/ack handshake, per-tag_id client setup.
    if ("SNI-Host=" in b or "readFromClient:" in b
            or "TLS Handshake" in b or "Connected to ZEN" in b
            or "TUN-Proxy: connection" in b or "Use Sme:" in b
            or "Sme IP:" in b or "Client socket" in b):
        return "Setup"
    if "===>" in b and "ZPN Connection" in b:
        return "Setup"
    # Per-socket setup events from ZSATunnel — fire BEFORE the
    # ===> arrow when the kernel-side socket is being prepared:
    #   "ID=N, Successfully set SO_OOBINLINE socket option for
    #    ZPN Client Socket!"
    # No TAG-ID on this line but it's part of session setup.
    if "ZPN Client Socket" in b and "Successfully set" in b:
        return "Setup"
    if "SO_OOBINLINE" in b:
        return "Setup"
    # zpn_mtunnel_request_ack — the broker's response to a tunnel-
    # setup request. Always part of the Setup phase regardless of
    # whether the response carries an error PAYLOAD. The previous
    # version had a `"error" not in b` guard, which was defeated by
    # JSON-embedded `"error":` keys in the Control Message Response
    # Data shape:
    #   ZPN:0: Control Message Response Data:
    #     {"zpn_mtunnel_request_ack":{"tag_id":N,"error":{...}}}
    # Result: the line fell through to Decision. Fix: any line
    # containing the marker is Setup. Error-coded responses
    # (BRK_MT_SETUP_FAIL_*, SAML_EXPIRED) are already routed to
    # Error by the higher-priority checks at the top of this
    # function — so the Error case is still correctly bucketed.
    if "zpn_mtunnel_request_ack" in b:
        return "Setup"
    if "client for tag_id:" in b and "proto=" in b:
        # "Zpn:N: client for tag_id: N = proto=N, handler=...,
        # Double encrypt: N" — per-flow setup confirmation.
        return "Setup"
    if "Setup Time:" in b and "tag_id:" in b:
        return "Setup"
    # The OUTGOING zpn_mtunnel_request (pre-ack) — pure setup.
    # Distinguished from the *_ack and *_end by the trailing colon /
    # the request JSON; check both lower- and upper-bound shapes.
    if "zpn_mtunnel_request" in b and "_ack" not in b and "_end" not in b:
        return "Setup"

    # ---- Data phase ----
    if ("txBytes" in b or "rxBytes" in b or "Send:" in b
            or "Recv:" in b or "bytes sent" in b or "bytes received" in b):
        return "Data"
    if "Got data for tag_id:" in b:
        return "Data"
    if "Updating mtunnel entry tag_id:" in b:
        # ZPA keepalive — the broker pings the per-tag_id entry to
        # keep it warm. Data plane.
        return "Data"

    # ---- Teardown phase ----
    if ("Connection closed" in b or "RST" in b or "FIN " in b
            or "Close connection" in b or "Tunnel closed" in b):
        return "Teardown"
    # ZPA-side teardown. Both the outbound "Sending mtunnel end"
    # and the broker's "zpn_mtunnel_end" response. ANY line
    # containing `zpn_mtunnel_end` is a teardown event — the
    # error payload is part of the teardown reason (the broker is
    # closing AND telling us why). The previous version had a
    # `"error" not in b` guard, which was defeated by JSON-embedded
    # `"error":` keys in the Control Message Response Data shape
    # (see Phase 35 fix on zpn_mtunnel_request_ack above for the
    # full root-cause analysis). Line-level error: prefix shapes
    # (`zpn_mtunnel_end error: <BRK_MT_*>`) are already routed to
    # Error by the higher-priority check above.
    if "Sending mtunnel end" in b:
        return "Teardown"
    if "zpn_mtunnel_end" in b:
        return "Teardown"

    return "Decision"  # default bucket — neutral middle phase


def _infer_pac_decision(proxy_chain: str) -> str:
    """Convert a PAC ``Proxy=...`` string into TUNNEL / BYPASS / DIRECT."""
    if not proxy_chain:
        return ""
    pc = proxy_chain.strip()
    if pc.upper().startswith("DIRECT") and "PROXY" not in pc.upper():
        return "DIRECT"
    if "PROXY" in pc.upper() and "DIRECT" in pc.upper():
        return "TUNNEL"  # falls back to DIRECT only if proxy fails
    if "PROXY" in pc.upper():
        return "TUNNEL"
    return ""


def _enrich_session(session: Session) -> None:
    """Walk the session's phase_lines and populate the structured fields
    (resolved_ips, pac_decision, broker_ip, etc.) for the summary table."""
    # Phase 29-F (2026-06-17) session_id backfill. The pivot line for
    # a query like "salesforce" is often a DNS line that doesn't
    # carry ID=N (DNS happens BEFORE the connection ID is assigned).
    # As a result the session's session_id was always blank on the
    # Find & Follow table, even when the related phase_lines DO carry
    # ID=N from the setup / decision phases. Pick the first ID=N we
    # find across phase_lines and use it as the canonical session_id.
    if not session.session_id:
        for pl in session.phase_lines:
            id_m = re.search(r"\bID=(\d+)\b", pl.line)
            if id_m:
                session.session_id = id_m.group(1)
                break

    for pl in session.phase_lines:
        body = pl.line.split("] ", 1)[-1] if "] " in pl.line else pl.line

        # Resolved IPs (from DNS line)
        if "resolveDnsWithFamilyPriority" in body and not session.resolved_ips:
            m = re.search(r"IP List:\s*([0-9a-fA-F.: ]+)", body)
            if m:
                session.resolved_ips = m.group(1).strip().split()
            else:
                m = re.search(r"Preferred ip:\s*([0-9a-fA-F.:]+)", body)
                if m:
                    session.resolved_ips = [m.group(1)]

        # PAC decision + proxy chain. ZCC emits the PAC outcome in
        # several different line shapes depending on the stage:
        #
        #   (a) PAC Parse Host: <host> uri=<url> Proxy=PROXY 1.2.3.4:9443; PROXY ...; DIRECT
        #       -- the initial PAC evaluation, lists the FULL proxy
        #          chain on the same line (key=value pairs).
        #   (b) PAC Parse Action: Proxy: <host>
        #       -- the actual decision ZCC went with, single proxy
        #          host. Colon-separated.
        #   (c) Using ZPHM proxy: [<host>]
        #       -- ZPHM (Zscaler Proxy Hardware Module) path, used
        #          when the connection is routed through the proxy.
        #   (d) Proxy: DIRECT  (when PAC said DIRECT)
        #
        # We need ALL four shapes to capture PAC decision reliably.
        # Each one sets a different aspect; first-wins for each field
        # so the most-specific shape doesn't get overwritten by
        # later, less-specific lines on the same session.
        if not session.pac_proxy_chain:
            # (a) Full proxy chain via Proxy=...
            m = re.search(r"PAC Parse Host:.*?Proxy=([^\n]+?)(?:\s+\w+=|$)",
                          body)
            if m:
                session.pac_proxy_chain = m.group(1).strip()
                session.pac_decision = _infer_pac_decision(
                    session.pac_proxy_chain
                )
        if not session.pac_decision:
            # (b) Single-proxy ACTION line -- this is the actually-
            #     chosen proxy. Implies TUNNEL.
            m = re.search(r"PAC Parse Action:\s*Proxy:\s*(\S+)", body)
            if m:
                session.pac_decision = "TUNNEL"
                if not session.pac_proxy_chain:
                    session.pac_proxy_chain = f"PROXY {m.group(1)}"
            # (c) ZPHM proxy in use -- also TUNNEL.
            if not session.pac_decision:
                m = re.search(
                    r"Using ZPHM proxy:\s*\[?([^\s\]]+)", body
                )
                if m:
                    session.pac_decision = "TUNNEL"
                    if not session.pac_proxy_chain:
                        session.pac_proxy_chain = (
                            f"ZPHM PROXY {m.group(1)}"
                        )
            # (d) Explicit DIRECT / BYPASS decision.
            #
            # ZCC writes a few shapes for direct routing:
            #   "PAC Parse Action: Direct"        (mixed case — most common)
            #   "Proxy: DIRECT"                   (older all-caps style)
            #   "Bypassing proxy for url=..."     (PAC bypass-list match)
            # The regex used to be all-caps DIRECT which missed the
            # modern mixed-case forms entirely; sessions for hosts that
            # matched the PAC bypass list (e.g. *.okta.com) ended up
            # with pac_decision="" and got mis-labelled downstream.
            #
            # BYPASS is distinguished from DIRECT because the former
            # explicitly came from a bypass rule (engineer needs to know
            # which bypass list / wildcard fired). Both route the
            # connection without the SME.
            if not session.pac_decision:
                if re.search(r"Bypassing proxy for url=", body, re.I):
                    session.pac_decision = "BYPASS"
                elif re.search(
                    r"\bPAC Parse Action:\s*Direct\b", body, re.I
                ):
                    session.pac_decision = "DIRECT"
                elif re.search(r"\bProxy:\s*DIRECT\b", body):
                    session.pac_decision = "DIRECT"
                elif re.search(r"\bPAC.*?DIRECT\b", body):
                    session.pac_decision = "DIRECT"

        # Tunnel request JSON + response broker
        if "Tunnel api request:" in body:
            session.tunnel_request_json = body
            # Pull brokerIp / brokerName / brokerType out of the response
            m = re.search(r'"brokerIp"\s*:\s*"([^"]*)"', body)
            if m:
                session.broker_ip = m.group(1)
            m = re.search(r'"brokerName"\s*:\s*"([^"]*)"', body)
            if m:
                session.broker_name = m.group(1)
            m = re.search(r'"brokerType"\s*:\s*(\d+)', body)
            if m:
                session.broker_type = int(m.group(1))
                session.service = {0: "ZIA", 1: "ZPA"}.get(session.broker_type, "")

        # SME used (from setup phase). Three signature shapes:
        #   "Connected to ZEN <name> <ip>"
        #   "Use Sme: 1 Sme IP: <ip>"
        #   "Sme IP: <ip>" (variant)
        # All map to the same field; first one wins per session.
        if not session.sme_used:
            for pat in (r"Connected to ZEN.*?(\d+\.\d+\.\d+\.\d+)",
                        r"Use Sme:\s*1\s+Sme IP:\s*(\d+\.\d+\.\d+\.\d+)",
                        r"\bSme IP:\s*(\d+\.\d+\.\d+\.\d+)"):
                m = re.search(pat, body)
                if m:
                    session.sme_used = m.group(1)
                    break

        # Bytes
        m = re.search(r"txBytes[=:]\s*(\d+)", body)
        if m:
            session.bytes_out = int(m.group(1))
        m = re.search(r"rxBytes[=:]\s*(\d+)", body)
        if m:
            session.bytes_in = int(m.group(1))

        # HTTP status
        m = re.search(r"\bHTTP/[0-9.]+\s+(\d{3})\b", body)
        if m and session.status_code is None:
            session.status_code = int(m.group(1))

        # errorMessage / level=ERR
        if pl.level if hasattr(pl, "level") else False:
            pass  # PhaseLine doesn't carry level today
        if "errorMessage" in body or "ERROR" in body:
            session.error_messages.append(body[:240])

    # SME fallback from PAC chain.
    #
    # The runtime "Connected to ZEN ..." / "Use Sme: 1 Sme IP: ..." markers
    # only appear once a request actually reaches the ZEN connect step.
    # Short sessions that hit the PAC parse and never proceeded (e.g. a
    # quick HTTP redirect to an auth IdP) end up with sme_used="" and
    # show "—" in the SME / Broker column even though the PAC chain
    # clearly named which SME the request would have used.
    #
    # When sme_used is still empty after the loop and we DO have a
    # populated pac_proxy_chain, fall back to the first PROXY IP in the
    # chain. That's exactly what the PAC said would be the primary SME,
    # so surfacing it (vs leaving the column blank) is more accurate.
    # Runtime markers still win when present — this is a fallback only.
    if not session.sme_used and session.pac_proxy_chain:
        m = re.search(
            r"PROXY\s+(\d+\.\d+\.\d+\.\d+)", session.pac_proxy_chain
        )
        if m:
            session.sme_used = m.group(1)

    # Clear sme_used for BYPASS / DIRECT sessions.
    #
    # The "Use Sme: 1 Sme IP: <ip>" line is tunnel-WIDE state — it tells
    # you which SME the ZCC tunnel is currently registered with, NOT
    # which proxy this particular session went through. For sessions
    # the PAC sent BYPASS or DIRECT, that SME IP is misleading: the
    # actual connection went directly to the destination IP, not via
    # the SME. The SME / Broker column should be blank for those
    # sessions so the engineer can tell at a glance which sessions
    # actually traversed Zscaler.
    if session.pac_decision in ("DIRECT", "BYPASS"):
        session.sme_used = ""

    # Service inference. The previous logic defaulted to "direct"
    # whenever broker_ip was empty, which mis-labelled obvious ZIA
    # tunnel sessions: PAC said TUNNEL, the proxy chain was populated,
    # and the log even showed "Use Sme: 1 Sme IP: 170.85.97.65" -- all
    # unambiguous TUNNEL signals -- yet we displayed "via direct"
    # because the brokerIp field of the Tunnel api response wasn't
    # populated (it isn't always, depending on the broker mode).
    #
    # New logic, in priority order:
    #   1. broker_type known (0=ZIA, 1=ZPA) -- trust it
    #   2. brokerIp set -- ZIA (since broker_type==1 is ZPA-only)
    #   3. "Use Sme: 1" appeared in any phase line -- ZIA tunnel
    #   4. PAC decision is TUNNEL -- ZIA tunnel
    #   5. PAC decision is DIRECT -- direct (no Zscaler)
    #   6. Otherwise: unknown
    if not session.service:
        # PAC BYPASS / DIRECT wins over the "Use Sme: 1" tunnel-wide
        # marker. That marker appears in *every* session because it
        # reflects the tenant's current SME registration, not what THIS
        # connection went through. Previously the inference checked the
        # marker before the PAC decision, so BYPASS sessions for hosts
        # like *.okta.com got mis-labelled as ZIA when they actually
        # connected directly to the origin IP.
        sme_used = any(
            ("Use Sme: 1" in pl.line)
            or ("TUN-Proxy: connection" in pl.line)
            for pl in session.phase_lines
        )
        if session.pac_decision in ("DIRECT", "BYPASS"):
            # PAC explicitly routed this session around the SME.
            session.service = "direct"
        elif session.broker_ip:
            session.service = "ZIA"
        elif session.pac_decision == "TUNNEL":
            session.service = "ZIA"
        elif sme_used:
            # Legacy fallback — only fires when PAC decision wasn't
            # captured at all. The marker alone isn't strong evidence,
            # but it's the best we've got.
            session.service = "ZIA"
        else:
            session.service = "unknown"

    # Outcome inference
    if session.error_messages:
        # Pick a more specific outcome from the error message
        em = " ".join(session.error_messages).lower()
        if "reset" in em or "rst" in em:
            session.outcome = "reset"
        elif "timeout" in em or "timed out" in em:
            session.outcome = "timeout"
        elif "block" in em or "denied" in em or "403" in em:
            session.outcome = "blocked"
        else:
            session.outcome = "error"
    elif session.status_code and session.status_code >= 400:
        session.outcome = "blocked" if session.status_code in (403, 407) else "error"
    elif session.broker_ip or session.sme_used or session.pac_decision in ("TUNNEL", "BYPASS", "DIRECT"):
        session.outcome = "allowed"

    # Latency
    if session.end_ts > session.start_ts:
        session.latency_ms = int((session.end_ts - session.start_ts).total_seconds() * 1000)


# ---------------------------------------------------------------------
# Bundle log enumeration
# ---------------------------------------------------------------------

_TUNNEL_LIKE_NAMES = (
    "ZSATunnel", "TRPTunnel",  # Windows + Mac tunnel logs
)
_SERVICE_LIKE_NAMES = ("ZSAService", "com.zscaler.ZscalerService", "TRPService")
_TRAY_LIKE_NAMES = ("ZSATrayManager", "ZSATray", "ZSATrayHelper")
_UPM_LIKE_NAMES = ("ZSAUpm", "ZSAUpmServiceController")


def _iter_bundle_files(bundle) -> Iterator[Tuple[str, str]]:
    """Yield (component, absolute_path) for every log file we care about
    in the bundle. ``component`` is one of: tunnel, service, tray, upm.
    Nested ``.log.zip`` rotated files are NOT auto-extracted here (the
    bundle.py infrastructure already unpacks them on initial extraction)."""
    for root, _, files in os.walk(bundle):
        for f in files:
            if not f.endswith((".log", ".snapshot")):
                continue
            path = os.path.join(root, f)
            base = f
            if any(base.startswith(p) for p in _TUNNEL_LIKE_NAMES):
                yield ("tunnel", path)
            elif any(base.startswith(p) for p in _SERVICE_LIKE_NAMES):
                yield ("service", path)
            elif any(base.startswith(p) for p in _TRAY_LIKE_NAMES):
                yield ("tray", path)
            elif any(base.startswith(p) for p in _UPM_LIKE_NAMES):
                yield ("upm", path)


def _scan_file(path: str, component: str,
               query: str, ts_range: Optional[Tuple[datetime, datetime]] = None
               ) -> Iterator[LogLine]:
    """Stream-parse a single log file. If ``query`` is provided, only
    lines that match (case-insensitive substring) the query OR carry a
    session ID we've already seen are yielded -- but to keep the API
    simple we yield ALL matching lines and let the caller filter."""
    q = query.lower() if query else ""
    with open(path, "r", encoding="utf-8", errors="replace") as fp:
        for line_no, raw in enumerate(fp, start=1):
            if q and q not in raw.lower():
                continue
            parsed = _parse_line(raw)
            if not parsed:
                continue
            try:
                # Phase 58e-H3 (2026-07-08): the numeric portion of a ZCC
                # log line IS UTC (see log_parser._parse_ts). Attach
                # timezone.utc directly so downstream ts_range comparisons
                # don't mix aware and naive datetimes.
                ts = datetime.strptime(
                    parsed["ts"], "%Y-%m-%d %H:%M:%S.%f"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if ts_range and not (ts_range[0] <= ts <= ts_range[1]):
                continue
            yield LogLine(
                ts=ts,
                pid=parsed["pid"],
                tid=parsed["tid"],
                level=parsed["level"],
                body=parsed["body"],
                source_file=os.path.basename(path),
                line_no=line_no,
                session_id=_extract_session_id(parsed["body"]),
                host=_extract_host(parsed["body"]),
            )


def _scan_file_by_ids(path: str, ids: Set[str], hosts: Set[str],
                      ts_range: Tuple[datetime, datetime],
                      strict_id_mode: bool = True,
                      ) -> Iterator[LogLine]:
    """Second-pass scan: yield log lines that belong to this session.

    Two modes (controlled by ``strict_id_mode``):

      * **Strict (default)**: when the session HAS at least one known
        ID, we yield lines whose ``session_id`` matches that ID. We
        ALSO yield host-matched lines BUT only when their phase is
        pre-ID (Resolve / Policy) -- i.e. DNS resolution and Encoded
        URL lines, which don't carry the ID but precede the first
        ID-tagged line for that host. This stops concurrent sessions
        to the same host from cross-contaminating each other.

      * **Loose**: when the session has NO known ID (e.g. matched on
        host only), we yield every line in the window whose host
        matches. The user's view will be noisier but at least
        complete.
    """
    yield_pre_id_hosts = hosts and not strict_id_mode
    with open(path, "r", encoding="utf-8", errors="replace") as fp:
        for line_no, raw in enumerate(fp, start=1):
            parsed = _parse_line(raw)
            if not parsed:
                continue
            try:
                # Phase 58e-H3 (2026-07-08): attach UTC to match aware
                # ts_range from find_sessions_for_query — otherwise every
                # second-pass strict-ID scan crashed with mixed tz compare.
                ts = datetime.strptime(
                    parsed["ts"], "%Y-%m-%d %H:%M:%S.%f"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if not (ts_range[0] <= ts <= ts_range[1]):
                continue
            body = parsed["body"]
            sid = _extract_session_id(body)
            host = _extract_host(body)

            include = False
            if strict_id_mode and ids:
                # Strict ID match
                if sid in ids:
                    include = True
                elif host and host in hosts and sid is None:
                    # Pre-ID phase line that shares a host with this
                    # session -- include only if it's a Resolve/Policy
                    # phase signature (the early phases that don't
                    # carry an ID yet). This prevents picking up later
                    # concurrent sessions that happen to share host.
                    phase = _phase_for(body)
                    if phase in ("Resolve", "Policy"):
                        include = True
            else:
                # Loose mode: id-or-host match anywhere
                if sid in ids or (host and host in hosts):
                    include = True

            if include:
                yield LogLine(
                    ts=ts, pid=parsed["pid"], tid=parsed["tid"],
                    level=parsed["level"], body=body,
                    source_file=os.path.basename(path), line_no=line_no,
                    session_id=sid, host=host,
                )


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

# --------------------------------------------------------------------
# ZDX synthetic-probe detection
# --------------------------------------------------------------------
#
# ZCC's UPM (User Performance Monitoring) module runs synthetic webload
# + traceroute probes against a configurable app list every ~5 minutes.
# These probes DO traverse the same tunnel as real user traffic -- they
# show up in ZSATunnel.log with valid SME IPs, broker IDs, etc. -- so
# they are INDISTINGUISHABLE from user-initiated traffic by looking
# at the tunnel log alone.
#
# However, the UPM module ALSO writes a separate log
# ``ZSAUpm_ZWebload_*.log`` that records every probe it kicks off:
#
#   DBG ZWB: Starting monitor: https://mail.google.com ;
#     [appId:82912, monId:307054] ; stime: 1781019136; SessionId: -1
#
# By correlating session pivot timestamps against this list, we can
# tag any session that fires within ~5 s of a UPM probe of the same
# host as "ZDX probe" rather than "ZIA" -- so the engineer knows it
# isn't user-generated traffic.


_ZDX_PROBE_RE = re.compile(
    r"ZWB:\s*Starting monitor:\s*https?://(?P<host>[^\s;]+)"
)


@dataclass
class _ZdxProbeIndex:
    """Maps lowercased host → sorted list of probe timestamps."""
    by_host: Dict[str, List[datetime]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def is_probe(self, host: str, ts: datetime,
                 window_s: float = 5.0) -> bool:
        if not host:
            return False
        candidates = self.by_host.get(host.lower(), [])
        if not candidates:
            return False
        target = ts.timestamp()
        # Tight loop -- list is short (one entry per probe per host),
        # 5-second window so even a wider correlator pivot still
        # only matches when probe is recent.
        for t in candidates:
            if abs(t.timestamp() - target) <= window_s:
                return True
        return False


def _build_zdx_probe_index(log_index) -> _ZdxProbeIndex:
    """Scan the in-memory log index for UPM webload probe records and
    return a host→timestamps map. Empty when there are no UPM logs
    or the bundle didn't capture them."""
    idx = _ZdxProbeIndex()
    if log_index is None:
        return idx
    for ln in log_index.lines:
        if ln.component != "upm":
            continue
        if "ZWB:" not in ln.body or "Starting monitor:" not in ln.body:
            continue
        m = _ZDX_PROBE_RE.search(ln.body)
        if not m:
            continue
        host = m.group("host").lower()
        # Strip any trailing port or path remnants.
        host = host.split("/", 1)[0].split(":", 1)[0]
        idx.by_host[host].append(ln.ts)
    return idx


# Need defaultdict import for the field default_factory above
from collections import defaultdict


def find_sessions_for_query_via_index(
    log_index,
    query: str,
    time_window_s: int = 30,
    max_sessions: int = 100,
) -> List[Session]:
    """Index-backed variant. ~100x faster than ``find_sessions_for_query``
    on large bundles because every line is already parsed and lives in
    memory -- no file I/O during the search."""
    if not log_index or not log_index.lines:
        return []

    q = query.lower()
    # Pass 1: gather pivot hits from the in-memory index (linear over
    # the parsed lines, no file opens).
    pivot_hits = [ln for ln in log_index.lines
                  if ln.component == "tunnel" and q in ln.body.lower()]
    if not pivot_hits:
        return []

    # Build the ZDX synthetic-probe index ONCE per query. This walks
    # the UPM log component for ``ZWB: Starting monitor:`` records and
    # gives us a host → probe-timestamps map. Sessions whose
    # (host, pivot_ts) fall within ±5 s of a probe are tagged as
    # synthetic so the engineer sees the difference between user
    # traffic and ZDX monitoring.
    zdx_idx = _build_zdx_probe_index(log_index)

    # ---- Two-pass grouping ----
    #
    # Pass A: every pivot hit with an explicit ID=<N> goes into its own
    # session group. The ID is ZCC's per-connection identifier so this
    # is the authoritative grouping key.
    #
    # Pass B: lines WITHOUT an ID (DNS resolve, Encoded URL, Encoded
    # Host, getTunnelRequestType -- the early phases that fire BEFORE
    # the ID is assigned) are attributed to the nearest ID group that:
    #   (a) shares the same hostname AND
    #   (b) starts within ±2 s of the no-ID line.
    # Lines that can't be attributed (no ID group nearby with matching
    # host) become "orphan" sessions bucketed by (pid, host, 10s
    # time-window) so distinct sessions to the same host but far apart
    # in time don't get merged.
    #
    # Why this matters: the previous code key'd no-ID lines on
    # (pid, host), which collapsed ALL DNS resolves for the same host
    # over the bundle's lifetime into a single "session" that could
    # span hours. Searching for a popular hostname like
    # "adminbyrequest" then produced one giant 11000-second group of
    # DNS resolves muddled together. Verified against real bundle:
    # OLD = 30 mixed groups including 11380s host-fallback group;
    # NEW = 26 cleanly-separated sessions, 0 orphans.

    id_groups: Dict[str, List] = {}
    no_id_pivots: List = []
    for ln in pivot_hits:
        if ln.session_id:
            id_groups.setdefault(ln.session_id, []).append(ln)
        else:
            no_id_pivots.append(ln)

    # Precompute (start_ts, hosts) per ID group for fast attribution.
    id_first_ts = {sid: min(x.ts for x in lst)
                   for sid, lst in id_groups.items()}
    id_hosts: Dict[str, Set[str]] = {
        sid: {x.host for x in lst if x.host}
        for sid, lst in id_groups.items()
    }

    # Attribute no-ID lines to nearest matching ID group.
    orphans: List = []
    for ln in no_id_pivots:
        best_sid = None
        best_dt = timedelta(seconds=2)
        for sid, t in id_first_ts.items():
            if ln.host and id_hosts.get(sid) and ln.host not in id_hosts[sid]:
                continue
            dt = abs(ln.ts - t)
            if dt < best_dt:
                best_dt = dt
                best_sid = sid
        if best_sid is not None:
            id_groups[best_sid].append(ln)
        else:
            orphans.append(ln)

    # Remaining orphans: bucket by (pid, host, 10s window) so concurrent
    # same-host actions don't merge.
    groups: Dict[Tuple[str, str], List] = {
        ("id", sid): lst for sid, lst in id_groups.items()
    }
    for ln in orphans:
        if not ln.host:
            continue
        bucket = int(ln.ts.timestamp() // 10)
        key = ("host", f"{ln.pid}|{ln.host}|{bucket}")
        groups.setdefault(key, []).append(ln)

    # Newest sessions first; cap.
    sorted_keys = sorted(
        groups.keys(),
        key=lambda k: min(ln.ts for ln in groups[k]),
        reverse=True,
    )[:max_sessions]

    sessions: List[Session] = []
    for key in sorted_keys:
        bucket = sorted(groups[key], key=lambda ln: ln.ts)
        pivot = bucket[0]
        sids: Set[str] = {ln.session_id for ln in bucket if ln.session_id}
        hosts: Set[str] = {ln.host for ln in bucket if ln.host}
        ts_lo = pivot.ts - timedelta(seconds=time_window_s)
        ts_hi = pivot.ts + timedelta(seconds=time_window_s)
        strict = bool(sids)

        # Pass 2: walk the in-memory window.
        related: List[Tuple[str, "object"]] = []
        for ln in log_index.lines:
            if ln.ts < ts_lo or ln.ts > ts_hi:
                continue
            include = False
            if strict and sids:
                if ln.session_id in sids:
                    include = True
                elif ln.host and ln.host in hosts and ln.session_id is None:
                    if _phase_for(ln.body) in ("Resolve", "Policy"):
                        include = True
            else:
                if ln.session_id in sids or (ln.host and ln.host in hosts):
                    include = True
            if include:
                related.append((ln.component, ln))
        if not related:
            continue

        first_ts = related[0][1].ts
        last_ts = related[-1][1].ts
        host_counts: Dict[str, int] = {}
        for _, ln in related:
            if ln.host:
                host_counts[ln.host] = host_counts.get(ln.host, 0) + 1
        primary_host = (max(host_counts, key=host_counts.get)
                        if host_counts else None)

        session = Session(
            session_id=pivot.session_id,
            pid=pivot.pid,
            host=primary_host,
            pivot_ts=pivot.ts,
            start_ts=first_ts,
            end_ts=last_ts,
            line_count=len(related),
        )
        for component, ln in related:
            session.phase_lines.append(PhaseLine(
                phase=_phase_for(ln.body),
                ts=ln.ts,
                component=component,
                line=(
                    f"{ln.ts.strftime('%H:%M:%S.%f')[:-3]} "
                    f"[{ln.pid}:{ln.tid}] {ln.level} {ln.body}"
                ),
            ))
        _enrich_session(session)
        # ZDX-probe tag — if this session's host + pivot timestamp
        # match a UPM webload probe within ±5 s, this isn't user
        # traffic: it's ZCC's own synthetic monitoring.
        if session.host and zdx_idx.is_probe(
                session.host, session.pivot_ts):
            session.service = "ZDX probe (synthetic monitoring)"
        sessions.append(session)
    return sessions


def find_sessions_for_query(
    bundle_path: str,
    query: str,
    time_window_s: int = 30,
    max_sessions: int = 100,
) -> List[Session]:
    """Find every session in the bundle that mentions ``query``.

    Algorithm:
      1. **Pass 1 (host pivot)**: scan tunnel logs for lines containing
         the query string. For each matching line, record its
         (session_id, host, pid, ts).
      2. **Group**: bucket the pass-1 hits by session_id. Lines without
         an ID get bucketed by (pid, host) -- they're typically DNS /
         Encoded URL phase lines that share the host with an ID-tagged
         line within ±100 ms.
      3. **Pass 2 (correlation)**: for each session, scan the same
         tunnel log (and service/tray/upm logs) over ±``time_window_s``
         around the session's pivot, collecting every line that shares
         the session_id OR the hostname.
      4. **Enrich**: classify lines into phases, extract structured
         fields (resolved_ips, broker_ip, outcome, latency), and sort
         by timestamp.
    """
    if not os.path.isdir(bundle_path):
        return []

    # ---- Pass 1: gather pivot hits in tunnel logs ----
    pivot_hits: List[LogLine] = []
    for component, path in _iter_bundle_files(bundle_path):
        if component != "tunnel":
            continue
        for ln in _scan_file(path, component, query):
            pivot_hits.append(ln)
            if len(pivot_hits) >= max_sessions * 50:
                break  # cap pass-1 work
        if len(pivot_hits) >= max_sessions * 50:
            break

    if not pivot_hits:
        return []

    # ---- Group by session_id (or (pid, host) when ID missing) ----
    groups: Dict[Tuple[str, Optional[str]], List[LogLine]] = {}
    for ln in pivot_hits:
        if ln.session_id:
            key = ("id", ln.session_id)
        elif ln.host:
            key = ("host", f"{ln.pid}|{ln.host}")
        else:
            continue
        groups.setdefault(key, []).append(ln)

    # Sort groups by earliest line time (most recent last)
    sorted_keys = sorted(
        groups.keys(),
        key=lambda k: min(ln.ts for ln in groups[k]),
        reverse=True,
    )
    sorted_keys = sorted_keys[:max_sessions]

    # ---- Pass 2: correlate each group ----
    sessions: List[Session] = []
    for key in sorted_keys:
        bucket = groups[key]
        bucket.sort(key=lambda ln: ln.ts)
        pivot = bucket[0]
        sids: Set[str] = {ln.session_id for ln in bucket if ln.session_id}
        hosts: Set[str] = {ln.host for ln in bucket if ln.host}
        if pivot.host:
            hosts.add(pivot.host)
        ts_lo = pivot.ts - timedelta(seconds=time_window_s)
        ts_hi = pivot.ts + timedelta(seconds=time_window_s)

        related: List[LogLine] = []
        # Strict mode when we know at least one session ID. Loose only
        # when this group is purely host-keyed (no ID anywhere).
        strict = bool(sids)
        for component, path in _iter_bundle_files(bundle_path):
            for ln in _scan_file_by_ids(path, sids, hosts,
                                         (ts_lo, ts_hi),
                                         strict_id_mode=strict):
                related.append((component, ln))  # type: ignore

        if not related:
            continue
        related.sort(key=lambda t: t[1].ts)

        first_ts = related[0][1].ts
        last_ts = related[-1][1].ts
        # Pick the primary hostname (most-frequently mentioned)
        host_counts: Dict[str, int] = {}
        for _, ln in related:
            if ln.host:
                host_counts[ln.host] = host_counts.get(ln.host, 0) + 1
        primary_host = max(host_counts, key=host_counts.get) if host_counts else None

        session = Session(
            session_id=pivot.session_id,
            pid=pivot.pid,
            host=primary_host,
            pivot_ts=pivot.ts,
            start_ts=first_ts,
            end_ts=last_ts,
            line_count=len(related),
        )
        for component, ln in related:
            session.phase_lines.append(PhaseLine(
                phase=_phase_for(ln.body),
                ts=ln.ts,
                component=component,
                line=f"{ln.ts.strftime('%H:%M:%S.%f')[:-3]} "
                     f"[{ln.pid}:{ln.tid}] {ln.level} {ln.body}",
            ))

        _enrich_session(session)
        sessions.append(session)

    return sessions


def sessions_summary_table(sessions: List[Session]) -> List[Dict[str, str]]:
    """Build the search-module summary table: one row per session.

    Phase 29-F (2026-06-17): the "Latency" column was misleading —
    the value is `start_ts → end_ts` (total session lifetime including
    handshake + data + teardown), not network RTT or per-hop latency.
    Renamed to "Duration" so the engineer doesn't misread it as a
    latency metric and conclude the network is slow when actually
    the session was just long-lived.
    """
    rows = []
    for s in sessions:
        sme_label = s.broker_ip or s.sme_used or "—"
        if s.latency_ms is not None:
            # Render ms when short, seconds when long (>= 10 seconds
            # of session lifetime — usual triage threshold for "long
            # session" vs "individual transaction").
            if s.latency_ms >= 10000:
                duration_str = f"{s.latency_ms / 1000:.1f} s"
            else:
                duration_str = f"{s.latency_ms} ms"
        else:
            duration_str = "—"
        rows.append({
            "Time": s.pivot_ts.strftime("%H:%M:%S.%f")[:-3],
            "Host": s.host or "—",
            "Service": s.service or "—",
            "SME / Broker": sme_label,
            "Outcome": s.outcome,
            "Duration": duration_str,
            "PAC": s.pac_decision or "—",
            "Status": str(s.status_code) if s.status_code else "—",
            "Lines": str(s.line_count),
            "Session ID": s.session_id or "—",
        })
    return rows


def session_phase_lines(session: Session) -> Dict[str, List[PhaseLine]]:
    """Group the session's phase_lines by phase, preserving order
    within each phase. Useful for the drill-in card's collapsible
    sections."""
    out: Dict[str, List[PhaseLine]] = {p: [] for p in PHASES}
    for pl in session.phase_lines:
        out.setdefault(pl.phase, []).append(pl)
    return out


def session_header_summary(session: Session) -> str:
    """One-line headline for the session card."""
    parts = []
    parts.append(session.host or "(unknown host)")
    if session.service:
        parts.append(f"via {session.service}")
    if session.broker_name:
        parts.append(f"broker {session.broker_name}")
    elif session.sme_used:
        parts.append(f"SME {session.sme_used}")
    parts.append(session.outcome.upper())
    if session.status_code:
        parts.append(f"HTTP {session.status_code}")
    if session.latency_ms is not None:
        parts.append(f"{session.latency_ms} ms")
    return "  ·  ".join(parts)
