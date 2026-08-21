"""
zcc_zpa_force_reauth_sleep_trigger correlator.

Locates every force_reauth event in the bundle and tries to correlate
each one to a Modern Standby exit. Critically, it ALSO surfaces
force_reauth events that have NO matching Modern Standby exit —
because those are evidence that something other than sleep is firing
the re-auth (network change, policy refresh, broker-initiated, etc.).

Reverse-engineering audit finding H-2: "Modern Standby = root cause"
is correlation, not causation. This correlator counts unmatched events
separately so the synthesizer can frame the root cause honestly.

Reverse-engineering audit finding L-11: clock drift between subsystems
can be a few milliseconds. We allow ±50ms drift when matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

from ..log_parser import LogLine
from .power_change import ModernStandbyCycle


_RE_FORCE_REAUTH = re.compile(
    r"zcc_zpa_force_reauth_sleep_trigger", re.IGNORECASE
)

# Maximum clock drift between the ZSATunnel power-change log and the
# ZSATray ZEvent log when correlating same-instant events.
MATCH_TOLERANCE = timedelta(milliseconds=50)


@dataclass
class ForceReauthEvent:
    """A single force_reauth_sleep_trigger occurrence.

    `matched_standby_cycle` is None when no Modern Standby exit fired
    within the tolerance window — that's the "unsleep-triggered"
    signal the synthesizer needs to flag.
    """
    ts: datetime
    record: LogLine
    matched_standby_cycle: Optional[ModernStandbyCycle] = None

    @property
    def is_sleep_correlated(self) -> bool:
        return self.matched_standby_cycle is not None


@dataclass
class ForceReauthSummary:
    """Aggregate view across all force_reauth events in the bundle."""
    events: List[ForceReauthEvent] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def count_sleep_correlated(self) -> int:
        return sum(1 for e in self.events if e.is_sleep_correlated)

    @property
    def count_unmatched(self) -> int:
        return sum(1 for e in self.events if not e.is_sleep_correlated)

    @property
    def all_sleep_correlated(self) -> bool:
        """If every force_reauth in the bundle pairs to a Modern Standby
        exit, the synthesizer can confidently name sleep as the trigger.
        If even one is unmatched, the framing must be "sleep is A trigger,
        not THE trigger." (Reverse-engineering finding H-2)"""
        return self.count > 0 and self.count_unmatched == 0


def find_force_reauth_events(
    records: Iterable[LogLine],
    standby_cycles: List[ModernStandbyCycle],
) -> ForceReauthSummary:
    """Locate every force_reauth event and match to the nearest Modern
    Standby exit within ±50ms.

    `standby_cycles` is the output of `power_change.find_modern_standby_cycles`.
    """
    # Pull all matching records.
    raw: List[LogLine] = []
    for r in records:
        msg = r.message or ""
        if _RE_FORCE_REAUTH.search(msg):
            raw.append(r)

    # De-dup: ZSATray emits two lines per event ("ZEvent::" disposition
    # and "ZEvents: Raised event"). Both have the same timestamp/PID; we
    # collapse on (timestamp, thread_id).
    seen = set()
    deduped: List[LogLine] = []
    for r in raw:
        key = (r.timestamp, getattr(r, "tid", None))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    deduped.sort(key=lambda r: r.timestamp)

    # Build a sorted list of Modern Standby exits for O(log n) lookup.
    exits_with_cycle = [
        (c.exit_ts, c) for c in standby_cycles if c.exit_ts is not None
    ]
    exits_with_cycle.sort(key=lambda t: t[0])

    summary = ForceReauthSummary()
    for r in deduped:
        match = _nearest_match(r.timestamp, exits_with_cycle, MATCH_TOLERANCE)
        summary.events.append(ForceReauthEvent(
            ts=r.timestamp, record=r, matched_standby_cycle=match,
        ))
    return summary


def _nearest_match(
    ts: datetime,
    sorted_exits: List,
    tolerance: timedelta,
) -> Optional[ModernStandbyCycle]:
    """Return the ModernStandbyCycle whose exit_ts is closest to `ts`,
    iff within `tolerance`."""
    if not sorted_exits:
        return None
    # Linear scan is fine — bundles rarely have more than a handful of
    # Modern Standby cycles. Binary search adds complexity without payoff.
    best: Optional[ModernStandbyCycle] = None
    best_delta = tolerance + timedelta(seconds=1)
    for exit_ts, cycle in sorted_exits:
        delta = abs(ts - exit_ts)
        if delta < best_delta:
            best_delta = delta
            best = cycle
        # Early exit once we've passed ts by more than tolerance
        if exit_ts > ts and (exit_ts - ts) > tolerance:
            break
    if best is not None and best_delta <= tolerance:
        return best
    return None
