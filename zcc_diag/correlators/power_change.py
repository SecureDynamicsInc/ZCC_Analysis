"""
Modern Standby entry/exit pairing.

ZSATunnel logs the OS power transitions explicitly:

    INF Power Change Event: Detected Modern Standby entry
    INF Power Change Event: Detected Modern Standby exit

This module pairs entry → exit lines into `ModernStandbyCycle` objects with
durations. Validated against Example Tenant A bundle (Mon 18:10:44→18:12:40 EDT and
Tue 15:29:43→15:30:13 EDT — both cycles confirmed by direct log evidence).

Edge cases handled:
  - Modern Standby entry with no matching exit (machine still asleep at
    bundle export time — produces a cycle with `exit_ts=None`).
  - Modern Standby exit with no preceding entry (entry was in a rotated-off
    log — produces a cycle with `entry_ts=None`).
  - Multiple back-to-back cycles (each pair stands on its own).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional

from ..log_parser import LogLine


_RE_ENTRY = re.compile(
    r"Power Change Event:\s*Detected Modern Standby entry", re.IGNORECASE
)
_RE_EXIT = re.compile(
    r"Power Change Event:\s*Detected Modern Standby exit", re.IGNORECASE
)


@dataclass
class ModernStandbyCycle:
    """One sleep/wake cycle. Either timestamp may be None at bundle edges."""
    entry_ts: Optional[datetime]
    exit_ts: Optional[datetime]
    entry_record: Optional[LogLine] = None
    exit_record: Optional[LogLine] = None

    @property
    def duration_seconds(self) -> Optional[float]:
        """How long the device was in Modern Standby. None if either end
        is missing."""
        if self.entry_ts is None or self.exit_ts is None:
            return None
        return (self.exit_ts - self.entry_ts).total_seconds()

    @property
    def is_complete(self) -> bool:
        return self.entry_ts is not None and self.exit_ts is not None


def find_modern_standby_cycles(
    records: Iterable[LogLine],
) -> List[ModernStandbyCycle]:
    """Pair Modern Standby entry/exit log lines into cycles.

    The function is order-tolerant: it consumes records in arrival order
    but pairs by chronological adjacency. Records that don't match the
    entry/exit patterns are ignored.

    Returns cycles sorted by entry timestamp (or exit timestamp if entry
    is None).
    """
    entries: List[LogLine] = []
    exits: List[LogLine] = []
    for r in records:
        msg = r.message or ""
        if _RE_ENTRY.search(msg):
            entries.append(r)
        elif _RE_EXIT.search(msg):
            exits.append(r)

    # Sort both lists chronologically — log files can be processed out of
    # order, especially when multiple rotated logs are walked.
    entries.sort(key=lambda r: r.timestamp)
    exits.sort(key=lambda r: r.timestamp)

    cycles: List[ModernStandbyCycle] = []
    i = j = 0
    while i < len(entries) or j < len(exits):
        e = entries[i] if i < len(entries) else None
        x = exits[j] if j < len(exits) else None

        if e is None:
            # No more entries — remaining exits are unmatched (entry rotated off).
            cycles.append(ModernStandbyCycle(
                entry_ts=None, exit_ts=x.timestamp, exit_record=x,
            ))
            j += 1
            continue

        if x is None:
            # No more exits — remaining entries are unmatched (still asleep).
            cycles.append(ModernStandbyCycle(
                entry_ts=e.timestamp, exit_ts=None, entry_record=e,
            ))
            i += 1
            continue

        if x.timestamp < e.timestamp:
            # An exit before the next entry — unmatched (entry rotated off).
            cycles.append(ModernStandbyCycle(
                entry_ts=None, exit_ts=x.timestamp, exit_record=x,
            ))
            j += 1
            continue

        # Normal pair: entry e, then exit x.
        cycles.append(ModernStandbyCycle(
            entry_ts=e.timestamp, exit_ts=x.timestamp,
            entry_record=e, exit_record=x,
        ))
        i += 1
        j += 1

    return cycles
