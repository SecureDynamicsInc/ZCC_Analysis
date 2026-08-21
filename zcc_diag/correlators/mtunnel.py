"""
mtunnel lifecycle classifier.

Classifies BRK_MT_* close events into three actionable reasons:

  CLOSED_FROM_ASSISTANT  — ZCC client tore down the mtunnel (force-reauth,
                           app-profile change, service stop). Highest user
                           impact: indicates ZCC initiated the close.
  RESET_FROM_SERVER      — Server-side normal end (typical of Citrix
                           Workspace poll cycles). BENIGN.
  SETUP_FAIL_SAML_EXPIRED — Broker rejected the mtunnel setup because the
                            cached SAML assertion has expired. Seen in
                            bulk during morning re-auth windows.
  OTHER                  — Anything else (RESET_BY_PEER, TERMINATED, etc.)

Reverse-engineering audit finding H-3: "5 mtunnels severed" overstates
user impact if those mtunnels were idle. This module also tracks the
last-data-event timestamp per tag_id so a synthesizer can distinguish
"active session severed" (had bytes in last 30s) from "idle mtunnel
closed" (no bytes for minutes).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Iterable, List, Optional

from ..log_parser import LogLine


# Threshold above which "active" becomes "idle." 30 seconds matches the
# typical Citrix Workspace poll handshake duration.
ACTIVE_SESSION_WINDOW = timedelta(seconds=30)


class MtunnelCloseReason(str, Enum):
    CLOSED_FROM_ASSISTANT = "CLOSED_FROM_ASSISTANT"
    RESET_FROM_SERVER = "RESET_FROM_SERVER"
    SETUP_FAIL_SAML_EXPIRED = "SETUP_FAIL_SAML_EXPIRED"
    OTHER = "OTHER"


_RE_TAG_ID = re.compile(r'tag_id["\s:]*([0-9]+)')
_RE_APP_NAME = re.compile(r'App\s*Name[="\s:]+([^"\s,]+)')
_RE_MTUNNEL_END = re.compile(r"zpn_mtunnel_end", re.IGNORECASE)
_RE_MTUNNEL_REQUEST = re.compile(r"zpn_mtunnel_request", re.IGNORECASE)
_RE_REASON = re.compile(r'error["\s:]*"?(BRK_MT_\w+|[A-Z_]+)', re.IGNORECASE)
# Lines indicating actual data flowing through the mtunnel (used to
# set last_byte_ts).
#
# Phase 58e-C6 (2026-07-08): removed "ZPN Connection" — that literal
# appears in every mtunnel SETUP line (e.g., "===> ID=X, ZPN
# Connection local:P->IP:443 App Name=NAME TAG-ID=N"), which means
# every mtunnel's last_byte_ts was being pinned to setup time. The
# consequence was `was_active_at_close = True` for every session —
# the entire "distinguish active-severance from idle-close" mechanism
# was defeated. The remaining tokens are unambiguously data-flow.
_RE_DATA = re.compile(
    r"(bytes|data\s+event|onSocketReadable|RxBytes|TxBytes|zpn_data)",
    re.IGNORECASE,
)


@dataclass
class MtunnelClose:
    """One mtunnel close event with classification + activity context."""
    tag_id: int
    close_ts: datetime
    reason: MtunnelCloseReason
    app_name: Optional[str] = None
    open_ts: Optional[datetime] = None
    last_byte_ts: Optional[datetime] = None
    record: Optional[LogLine] = None

    @property
    def lifetime_seconds(self) -> Optional[float]:
        if self.open_ts is None:
            return None
        return (self.close_ts - self.open_ts).total_seconds()

    @property
    def idle_seconds_before_close(self) -> Optional[float]:
        """How long the mtunnel was idle before close. None = no data
        traffic observed (likely a setup-rejected mtunnel)."""
        if self.last_byte_ts is None:
            return None
        return (self.close_ts - self.last_byte_ts).total_seconds()

    @property
    def was_active_at_close(self) -> bool:
        """True if this mtunnel had byte-flow within the active window
        before the close. Reverse-engineering finding H-3: this is the
        signal that distinguishes user pain from cosmetic teardown."""
        idle = self.idle_seconds_before_close
        if idle is None:
            return False
        return idle <= ACTIVE_SESSION_WINDOW.total_seconds()


def _classify_reason(text: str) -> MtunnelCloseReason:
    t = text.upper()
    if "CLOSED_FROM_ASSISTANT" in t:
        return MtunnelCloseReason.CLOSED_FROM_ASSISTANT
    if "RESET_FROM_SERVER" in t:
        return MtunnelCloseReason.RESET_FROM_SERVER
    if "SETUP_FAIL_SAML_EXPIRED" in t:
        return MtunnelCloseReason.SETUP_FAIL_SAML_EXPIRED
    return MtunnelCloseReason.OTHER


def classify_mtunnel_closes(
    records: Iterable[LogLine],
) -> List[MtunnelClose]:
    """Walk records once. Emit one MtunnelClose per (tag_id, close_ts_second)
    tuple — collapsing ZCC's typical pattern of TWO log lines per close
    (the JSON zpn_mtunnel_end + the follow-up "No zpn client map entry"
    error) while preserving distinct closes across service restarts.

    NOTE on tag_id reuse: ZCC restarts its tag_id counter at 65536 every
    fresh ZSATunnel start. So the same tag_id (e.g., 65589) legitimately
    appears in multiple sessions across the bundle window. Deduping by
    tag_id ALONE collapses those into one — a bug found during Phase 48
    validation (Tue 15:43:48 close of tag 65589 was being shadowed by
    the Jun 21 close of a different mtunnel that happened to reuse the
    tag number). Keying by (tag_id, close_ts_to_second) preserves
    distinct sessions while still collapsing duplicate log lines emitted
    in the same instant.
    """
    # State by tag_id while we walk — we still track most-recent open
    # and last_byte per tag_id for activity tracking on the CURRENT
    # session; an mtunnel close consumes that state and resets it.
    open_ts_by_tag: Dict[int, datetime] = {}
    last_byte_by_tag: Dict[int, datetime] = {}
    app_name_by_tag: Dict[int, str] = {}
    closes_seen: Dict = {}  # key: (tag_id, ts_truncated_to_second)

    for r in records:
        msg = r.message or ""
        tag_match = _RE_TAG_ID.search(msg)
        if not tag_match:
            continue
        tag_id = int(tag_match.group(1))

        # Application name — refresh whenever we see a new one (cheap;
        # last writer wins, which is correct after a session restart).
        app_match = _RE_APP_NAME.search(msg)
        if app_match:
            app_name_by_tag[tag_id] = app_match.group(1)

        # Data event → bump last-byte timestamp for activity tracking.
        if _RE_DATA.search(msg):
            last_byte_by_tag[tag_id] = r.timestamp

        # Open event → record the open timestamp (most recent — service
        # restart will re-record this for a reused tag_id).
        if _RE_MTUNNEL_REQUEST.search(msg):
            open_ts_by_tag[tag_id] = r.timestamp

        # Close event → classify and stash, keyed by (tag, close-second)
        # to keep distinct sessions separate.
        if _RE_MTUNNEL_END.search(msg):
            key = (tag_id, r.timestamp.replace(microsecond=0))
            if key in closes_seen:
                continue
            reason = _classify_reason(msg)
            closes_seen[key] = MtunnelClose(
                tag_id=tag_id,
                close_ts=r.timestamp,
                reason=reason,
                app_name=app_name_by_tag.get(tag_id),
                open_ts=open_ts_by_tag.get(tag_id),
                last_byte_ts=last_byte_by_tag.get(tag_id),
                record=r,
            )
            # After a close, clear the per-tag state so the NEXT
            # appearance of this tag (which will be a different session)
            # doesn't inherit the closed session's open_ts / last_byte.
            open_ts_by_tag.pop(tag_id, None)
            last_byte_by_tag.pop(tag_id, None)

    return sorted(closes_seen.values(), key=lambda c: c.close_ts)
