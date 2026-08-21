"""Session reconstruction — Slice 3 of the Log-Analyzer rebuild (2026-08-07).

Given any ZCC-native identifier (session_id / tag_id / mtunnel_id /
broker_session prefix / connection_id), reconstruct every log line
that mentions it across the whole bundle, sort chronologically,
classify each line's phase (setup / data / close / auth-transition /
etc.), and surface related IDs seen alongside.

Design contract:
    * Zero interpretation. We label a line as `setup` because it matches
      a well-known setup regex, not because we've concluded anything
      about what "should have" happened next.
    * Reconstruction is pure ID matching. If the ID appears in the line
      body or in the IndexedLine.session_id field, the line is included.
    * Related IDs are extracted from the same lines with rigid regexes —
      no fuzzy correlation, no cross-line inference beyond "these IDs
      appear on the same lines".

Pure library — CLI-shared. No streamlit deps.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# --------------------------------------------------------------------------
# ID-type identification
# --------------------------------------------------------------------------

# Empirically observed ZPA broker-session prefixes. mtunnel_id is
# structured as "<control>,<data>" where control channel prefixes are
# usually 4-6 alnum chars we've seen: z5FN, ROgPN, ROgPP, ROgPQ, etc.
_ZPA_MTUNNEL_PREFIX_RE = re.compile(r"^[a-zA-Z0-9]{4,8}[a-zA-Z0-9+/=_-]{10,}$")
_UUID_LIKE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def guess_id_type(query_id: str) -> str:
    """Best-effort classification of an identifier's type.

    Returns one of:
        "tag_id"          — pure integer
        "session_id"      — UUID-like
        "mtunnel_id"      — contains a comma (control,data) or has both halves
        "broker_session"  — mtunnel-prefix-shaped alnum blob >10 chars
        "conn_id"         — starts with "conn_id="-style tag (rare in raw input)
        "free"            — anything else; treat as substring search
    """
    q = query_id.strip()
    if not q:
        return "free"

    # Pure integer → tag_id (or possibly PID; we lean tag_id because the
    # Session view is for lifecycle reconstruction).
    if q.isdigit():
        return "tag_id"

    # UUID-like → session_id
    if _UUID_LIKE_RE.match(q):
        return "session_id"

    # Full mtunnel_id: "control,data"
    if "," in q:
        left, right = q.split(",", 1)
        if _ZPA_MTUNNEL_PREFIX_RE.match(left) and _ZPA_MTUNNEL_PREFIX_RE.match(right):
            return "mtunnel_id"

    # Broker session prefix — long alnum blob
    if _ZPA_MTUNNEL_PREFIX_RE.match(q):
        return "broker_session"

    # Everything else — free-text substring
    return "free"


# --------------------------------------------------------------------------
# Phase classifier
# --------------------------------------------------------------------------

# Reuse the same categories as query.py's event: shortcuts, but ordered
# so that more-specific patterns win when a body could match multiple.
_PHASE_ORDER: List[Tuple[str, "re.Pattern"]] = [
    # ---- Setup / open ----
    ("mtunnel_setup",
     re.compile(r"mtunnel[_ ]?(?:setup|request|open|start)|BRK_MT_SETUP",
                re.IGNORECASE)),
    # ---- Close / termination ----
    ("mtunnel_close",
     re.compile(r"mtunnel[_ ]?(?:close|end|terminate)|"
                r"BRK_MT_(?:CLOSED|TERMINATED)|zpn_mtunnel_end",
                re.IGNORECASE)),
    # ---- Auth ----
    ("saml_expired",
     re.compile(r"SAML_EXPIRED|saml.*expir|saml force expired",
                re.IGNORECASE)),
    ("auth_transition",
     re.compile(r"AUTHENTICATED|AUTHENTICATION_REQUIRED",
                re.IGNORECASE)),
    # ---- Broker / SME ----
    ("broker_redirect",
     re.compile(r"BRK_REDIRECT|broker.*redirect|BRK_MT_.*BALANCE",
                re.IGNORECASE)),
    ("dc_changed",
     re.compile(r"zcc_tunnel.*dc_changed|SME.*chang|Service Edge.*chang",
                re.IGNORECASE)),
    # ---- Power / network ----
    ("power_change",
     re.compile(r"Power Change Event|Modern Standby|force_reauth_sleep_trigger",
                re.IGNORECASE)),
    ("network_change",
     re.compile(r"network[_ ](?:change|transition|state)|"
                r"adapter (?:up|down|state)", re.IGNORECASE)),
    ("trust_state_change",
     re.compile(r"trusted[_ ]?network.*(?:enter|exit|change)|"
                r"OFF_TRUSTED|NON_TRUSTED|TRUSTED_NETWORK",
                re.IGNORECASE)),
    # ---- Data / traffic ----
    ("data_ack",
     re.compile(r"mtunnel_request_ack|data.*(?:sent|received)|"
                r"bytes[_ ](?:in|out)", re.IGNORECASE)),
    # ---- Service lifecycle ----
    ("service_start",
     re.compile(r"service (?:started|starting|initialized)|"
                r"ZSAService (?:up|start)|ZCC (?:starting|up)",
                re.IGNORECASE)),
    # ---- Cert / posture / policy ----
    ("cert_expiry_check",
     re.compile(r"getCertExpiryDaySec|cert.*expir", re.IGNORECASE)),
    ("policy_push",
     re.compile(
         r"zpn_(?:trusted_networks|posture_profile|forwarding_profile)_ack"
         r"|TrayPolicy::serialize|policy.*push",
         re.IGNORECASE)),
    ("kerberos_lookup",
     re.compile(r"_kerberos\._tcp|kerberos.*SRV|_ldap\._tcp|_gc\._tcp",
                re.IGNORECASE)),
    # ---- Tray ----
    ("tray_notification",
     re.compile(r"send ZSATray Notification|tray.*notif", re.IGNORECASE)),
]


def classify_phase(body: str) -> str:
    """Return the phase name for a single log line body, or 'data' if
    nothing specific matches. The classifier is deterministic and
    order-sensitive: earlier patterns in `_PHASE_ORDER` win."""
    if not body:
        return "data"
    for name, pat in _PHASE_ORDER:
        if pat.search(body):
            return name
    return "data"


def known_phases() -> List[str]:
    return [name for name, _ in _PHASE_ORDER] + ["data"]


# --------------------------------------------------------------------------
# Related-ID extractors
# --------------------------------------------------------------------------

_RE_TAG_ID = re.compile(r"tag_id[=:\s]+(\d+)", re.IGNORECASE)
_RE_ERR_CODE = re.compile(r"err[_ ]?code[=:\s]+(\d+)", re.IGNORECASE)
_RE_MTUNNEL_ID = re.compile(
    r"mtunnel_id[=:\s]+([a-zA-Z0-9+/=_-]+,[a-zA-Z0-9+/=_-]+)",
    re.IGNORECASE,
)
_RE_CONN_ID = re.compile(r"conn_id[=:\s]+([a-zA-Z0-9+/=_-]+)", re.IGNORECASE)
_RE_APP_NAME = re.compile(
    r"app[_ ]?name[=:\s]+([a-zA-Z0-9._-]+)", re.IGNORECASE,
)
_RE_BROKER_HOST = re.compile(
    r"broker[a-z0-9_-]*\.(?:[a-z0-9_-]+\.)*(?:zpath|zscaler|zpalb|zpaservice)\.net",
    re.IGNORECASE,
)


def extract_related_ids(body: str) -> Dict[str, List[str]]:
    """Pull every recognisable ID / code / hostname out of a body string.

    Returns a dict of type -> list of matches, preserving order and
    duplicates so the caller can decide whether to dedupe or count.
    """
    out: Dict[str, List[str]] = defaultdict(list)
    for m in _RE_TAG_ID.finditer(body):
        out["tag_id"].append(m.group(1))
    for m in _RE_ERR_CODE.finditer(body):
        out["err_code"].append(m.group(1))
    for m in _RE_MTUNNEL_ID.finditer(body):
        out["mtunnel_id"].append(m.group(1))
    for m in _RE_CONN_ID.finditer(body):
        out["conn_id"].append(m.group(1))
    for m in _RE_APP_NAME.finditer(body):
        out["app"].append(m.group(1))
    for m in _RE_BROKER_HOST.finditer(body):
        out["broker"].append(m.group(0))
    return dict(out)


# --------------------------------------------------------------------------
# ID-matching predicate — how we decide a line belongs to the session
# --------------------------------------------------------------------------

def _build_matcher(query_id: str, id_type: str):
    """Return a callable(line) -> bool that decides whether a line belongs
    to this session's reconstruction.

    Matching rules per id_type:
      tag_id            : body contains "tag_id=<N>" or "tag_id: <N>"
      session_id        : IndexedLine.session_id == query_id, or body contains query_id
      mtunnel_id        : body contains query_id as a substring
      broker_session    : body contains query_id as a prefix of some mtunnel_id
      conn_id           : body contains "conn_id=<val>"
      free              : body substring match (case-insensitive)
    """
    q = query_id.strip()

    if id_type == "tag_id":
        pat = re.compile(rf"tag_id[=:\s]+{re.escape(q)}\b", re.IGNORECASE)

        def _m(line):
            return bool(pat.search(line.body or ""))
        return _m

    if id_type == "session_id":
        q_lower = q.lower()

        def _m(line):
            if line.session_id and str(line.session_id).lower() == q_lower:
                return True
            return q_lower in (line.body or "").lower()
        return _m

    if id_type in ("mtunnel_id", "broker_session"):
        # Both are substring matches on the body. mtunnel_id will hit
        # exact matches; broker_session prefix will hit BOTH matching
        # halves (which is what we want — a broker_session query pulls
        # every mtunnel that shares the control channel).
        q_lower = q.lower()

        def _m(line):
            return q_lower in (line.body or "").lower()
        return _m

    if id_type == "conn_id":
        pat = re.compile(rf"conn_id[=:\s]+{re.escape(q)}\b", re.IGNORECASE)

        def _m(line):
            return bool(pat.search(line.body or ""))
        return _m

    # free-text fallback
    q_lower = q.lower()

    def _m(line):
        return q_lower in (line.body or "").lower()
    return _m


# --------------------------------------------------------------------------
# Reconstruction output dataclass
# --------------------------------------------------------------------------

@dataclass
class ReconLine:
    """One line in the reconstructed session, plus its classified phase."""
    ts: datetime
    level: str
    component: str
    source_file: str
    line_no: int
    phase: str
    body: str
    related: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class SessionRecon:
    """Complete reconstruction for one queried ID."""
    query_id: str
    id_type: str
    line_count: int
    first_ts: Optional[datetime]
    last_ts: Optional[datetime]
    duration_seconds: Optional[float]
    files_touched: Dict[str, int]         # source_file -> line count
    components_touched: Dict[str, int]    # component -> line count
    phase_histogram: Dict[str, int]       # phase -> count
    related_id_summary: Dict[str, List[str]]  # type -> distinct sorted list
    lines: List[ReconLine] = field(default_factory=list)


# --------------------------------------------------------------------------
# Reconstruction entry point
# --------------------------------------------------------------------------

def reconstruct_session(idx, query_id: str,
                        id_type: Optional[str] = None) -> SessionRecon:
    """Walk `idx.lines` once, keep every line matching the ID, sort by
    timestamp, classify each line's phase, and summarize the result.

    `id_type` — if None, `guess_id_type()` is called. Callers can force
    a type when they want to override auto-detection (e.g. treat a
    numeric string as free-text, not tag_id).
    """
    if id_type is None:
        id_type = guess_id_type(query_id)

    matcher = _build_matcher(query_id, id_type)

    matched: List = []
    for line in idx.lines:
        if matcher(line):
            matched.append(line)

    # Sort chronologically. `sorted` is stable so ties preserve original
    # ordering — good for lines with identical timestamps (rare).
    matched.sort(key=lambda ln: (ln.ts, ln.source_file, ln.line_no))

    files_touched: Counter = Counter()
    components_touched: Counter = Counter()
    phase_hist: Counter = Counter()
    related_agg: Dict[str, set] = defaultdict(set)

    recon_lines: List[ReconLine] = []
    for line in matched:
        body = line.body or ""
        phase = classify_phase(body)
        related = extract_related_ids(body)
        recon_lines.append(ReconLine(
            ts=line.ts,
            level=line.level or "",
            component=line.component or "",
            source_file=line.source_file or "",
            line_no=line.line_no,
            phase=phase,
            body=body,
            related=related,
        ))
        files_touched[line.source_file] += 1
        components_touched[line.component] += 1
        phase_hist[phase] += 1
        for k, vs in related.items():
            for v in vs:
                related_agg[k].add(v)

    first_ts = recon_lines[0].ts if recon_lines else None
    last_ts = recon_lines[-1].ts if recon_lines else None
    duration = None
    if first_ts is not None and last_ts is not None:
        duration = (last_ts - first_ts).total_seconds()

    # De-dupe the "self-ID" from the related summary (if the query is
    # a tag_id, we don't want to list it in related.tag_id).
    if id_type in related_agg and query_id in related_agg[id_type]:
        related_agg[id_type].discard(query_id)

    return SessionRecon(
        query_id=query_id,
        id_type=id_type,
        line_count=len(recon_lines),
        first_ts=first_ts,
        last_ts=last_ts,
        duration_seconds=duration,
        files_touched=dict(files_touched),
        components_touched=dict(components_touched),
        phase_histogram=dict(phase_hist),
        related_id_summary={k: sorted(v) for k, v in related_agg.items()},
        lines=recon_lines,
    )


# --------------------------------------------------------------------------
# Component grouping — alternate presentation of a reconstruction
# --------------------------------------------------------------------------

def group_lines_by_component(recon: SessionRecon) -> Dict[str, List[ReconLine]]:
    """Group `recon.lines` by component, preserving chronological order
    WITHIN each group.

    `recon.lines` is already ts-sorted (see `reconstruct_session`), so a
    stable per-key filter keeps that order — no re-sort needed.

    Why this exists: the default reconstruction interleaves every
    component's lines by wall-clock time, which is right for "what
    happened, in order" but wrong for "what did ZSATunnel itself log for
    this session" — the tunnel's own narrative gets fragmented by tray
    and service lines sitting between its lines. Grouping by component
    lets an engineer read one process's story straight through, then
    switch to another, instead of untangling an interleaved stream.
    """
    out: Dict[str, List[ReconLine]] = defaultdict(list)
    for ln in recon.lines:
        out[ln.component or "(unknown)"].append(ln)
    return dict(out)
