"""Timeline library — Slice 4 of the Log-Analyzer rebuild (2026-08-07).

Given a bundle's LogIndex, a centre timestamp, and a radius (± duration),
extract every log line in the window and bucket it into a fixed set of
**lanes** derived from the phase classifier used by `session_recon.py`.

A "lane" is a coarser category than a phase — it groups related phases
so a swim-lane chart doesn't have 15 rows. Mapping:

    auth      : auth_transition, saml_expired
    mtunnel   : mtunnel_setup, mtunnel_close, data_ack
    broker    : broker_redirect, dc_changed
    power     : power_change
    network   : network_change, trust_state_change
    service   : service_start
    policy    : policy_push
    cert      : cert_expiry_check
    kerberos  : kerberos_lookup
    tray      : tray_notification
    data      : anything not classified above

Also provides `diff_windows(w1, w2)` — a symmetric compare of two
windows in the same bundle. Emits per-lane count deltas plus new/gone
IDs (tag_id, mtunnel_id, broker_session, err_code, app, broker,
sme_host, ipv4) between them.

Zero interpretation. A count delta is a count delta, not a "regression".

Pure library — no streamlit deps. CLI-shared.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from .id_inventory import _extract_all as _extract_ids
from .session_recon import ReconLine, classify_phase


# --------------------------------------------------------------------------
# Phase -> lane mapping
# --------------------------------------------------------------------------

_PHASE_TO_LANE: Dict[str, str] = {
    "auth_transition": "auth",
    "saml_expired": "auth",
    "mtunnel_setup": "mtunnel",
    "mtunnel_close": "mtunnel",
    "data_ack": "mtunnel",
    "broker_redirect": "broker",
    "dc_changed": "broker",
    "power_change": "power",
    "network_change": "network",
    "trust_state_change": "network",
    "service_start": "service",
    "policy_push": "policy",
    "cert_expiry_check": "cert",
    "kerberos_lookup": "kerberos",
    "tray_notification": "tray",
    # anything else = data
}

# Canonical lane order — this is the order the UI renders them.
LANE_ORDER: List[str] = [
    "auth", "mtunnel", "broker", "power", "network",
    "service", "policy", "cert", "kerberos", "tray", "data",
]


def phase_to_lane(phase: str) -> str:
    return _PHASE_TO_LANE.get(phase, "data")


def known_lanes() -> List[str]:
    return list(LANE_ORDER)


# --------------------------------------------------------------------------
# TimelineEvent — one row inside a window
# --------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    """One log line pinned to a lane."""
    ts: datetime
    lane: str
    phase: str
    level: str
    component: str
    source_file: str
    line_no: int
    body: str


# --------------------------------------------------------------------------
# TimelineWindow — everything within [centre - radius, centre + radius]
# --------------------------------------------------------------------------

@dataclass
class TimelineWindow:
    """One time-slice around a chosen centre."""
    centre_ts: datetime
    radius: timedelta
    start_ts: datetime
    end_ts: datetime
    total_events: int
    lane_counts: Dict[str, int]
    lane_events: Dict[str, List[TimelineEvent]]
    # De-duped identifiers seen in the window (from id_inventory)
    ids_seen: Dict[str, Set[str]] = field(default_factory=dict)


def build_timeline(
    idx,
    centre_ts: datetime,
    radius: timedelta,
    lanes: Optional[List[str]] = None,
) -> TimelineWindow:
    """Extract every line in `idx.lines` within `centre_ts ± radius`,
    bucket into lanes, and return a `TimelineWindow`.

    `lanes` — if given, only events for these lanes are kept in
    `lane_events` (the counts still cover all lanes). Useful when the UI
    filters lanes without re-running the extraction.
    """
    if centre_ts.tzinfo is None:
        centre_ts = centre_ts.replace(tzinfo=timezone.utc)

    start_ts = centre_ts - radius
    end_ts = centre_ts + radius

    lane_events: Dict[str, List[TimelineEvent]] = defaultdict(list)
    lane_counts: Counter = Counter()
    ids_seen: Dict[str, Set[str]] = defaultdict(set)
    total = 0

    for ln in idx.lines:
        ts = ln.ts
        if ts is None:
            continue
        if ts < start_ts or ts > end_ts:
            continue

        body = ln.body or ""
        phase = classify_phase(body)
        lane = phase_to_lane(phase)

        lane_counts[lane] += 1
        total += 1

        if lanes is None or lane in lanes:
            lane_events[lane].append(TimelineEvent(
                ts=ts,
                lane=lane,
                phase=phase,
                level=ln.level or "",
                component=ln.component or "",
                source_file=ln.source_file or "",
                line_no=ln.line_no,
                body=body,
            ))

        # Extract IDs so a window has a "who was on stage" summary.
        for id_type, values in _extract_ids(body).items():
            for v in values:
                ids_seen[id_type].add(v)

    # Ensure every lane appears in the counts dict even if zero — makes
    # downstream rendering simpler (no key errors on empty lanes).
    for lane in LANE_ORDER:
        lane_counts.setdefault(lane, 0)

    # Sort per-lane events chronologically.
    for lane_key in list(lane_events):
        lane_events[lane_key].sort(key=lambda e: (e.ts, e.line_no))

    return TimelineWindow(
        centre_ts=centre_ts,
        radius=radius,
        start_ts=start_ts,
        end_ts=end_ts,
        total_events=total,
        lane_counts=dict(lane_counts),
        lane_events=dict(lane_events),
        ids_seen=dict(ids_seen),
    )


def flatten_events(w: TimelineWindow) -> List[TimelineEvent]:
    """Return every event in a TimelineWindow sorted chronologically."""
    out: List[TimelineEvent] = []
    for events in w.lane_events.values():
        out.extend(events)
    out.sort(key=lambda e: (e.ts, e.source_file, e.line_no))
    return out


# --------------------------------------------------------------------------
# WindowDiff — symmetric compare of two windows
# --------------------------------------------------------------------------

@dataclass
class LaneDelta:
    """Count and diff for one lane across two windows."""
    lane: str
    count_a: int
    count_b: int
    delta: int  # count_b - count_a


@dataclass
class IdDelta:
    """Identifiers new / gone / retained per tag type."""
    tag_type: str
    only_in_a: List[str] = field(default_factory=list)
    only_in_b: List[str] = field(default_factory=list)
    in_both: List[str] = field(default_factory=list)


@dataclass
class WindowDiff:
    """Two TimelineWindows compared side-by-side."""
    window_a: TimelineWindow
    window_b: TimelineWindow
    lane_deltas: List[LaneDelta]
    id_deltas: List[IdDelta]


def diff_windows(w_a: TimelineWindow, w_b: TimelineWindow) -> WindowDiff:
    """Symmetric compare. Both windows must come from the same bundle
    for the comparison to be meaningful — this function does not guard
    against that, it's the caller's responsibility."""
    lane_deltas: List[LaneDelta] = []
    for lane in LANE_ORDER:
        a = w_a.lane_counts.get(lane, 0)
        b = w_b.lane_counts.get(lane, 0)
        lane_deltas.append(LaneDelta(
            lane=lane, count_a=a, count_b=b, delta=b - a,
        ))

    id_deltas: List[IdDelta] = []
    all_types = sorted(set(w_a.ids_seen) | set(w_b.ids_seen))
    for tag_type in all_types:
        a_set = w_a.ids_seen.get(tag_type, set())
        b_set = w_b.ids_seen.get(tag_type, set())
        id_deltas.append(IdDelta(
            tag_type=tag_type,
            only_in_a=sorted(a_set - b_set),
            only_in_b=sorted(b_set - a_set),
            in_both=sorted(a_set & b_set),
        ))

    return WindowDiff(
        window_a=w_a,
        window_b=w_b,
        lane_deltas=lane_deltas,
        id_deltas=id_deltas,
    )
