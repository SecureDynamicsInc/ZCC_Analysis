"""
ZCC service start detector.

Distinguishes fresh service starts (process restart, PID change, Version
banner emitted) from log rotations (same PID, [LogMon] Previous log
marker on the first line).

Reverse-engineering audit findings M-5 + M-7:
  - M-5: "Pre-work fresh start" needs a defined window. Set to 120 s.
  - M-7: the first line of a log file is "Previous log" for rotations
    vs "Timezone:"/"App Version:" banner for fresh starts. If we
    treated rotations as fresh starts, we'd misclassify mid-work
    re-auths as pre-work.

Output: a list of ServiceStart events, each with a `kind` indicating
which signal it came from, plus the PID at the time so synthesizers can
join against auth events and mtunnel events.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Optional

from ..log_parser import LogLine, classify_log_file


# A re-auth that fires within this many seconds of a fresh start is
# classified PRE_WORK_FRESH_START. Beyond this, the user has had time
# to start using ZPA and the event is mid-work.
FRESH_START_WINDOW_SECONDS = 120


_RE_VERSION_BANNER = re.compile(
    r"(ZSATunnel|ZSATray|ZSATrayManager|ZSAService)\s+(App\s+)?Version",
    re.IGNORECASE,
)
_RE_LOGMON_ROTATION = re.compile(
    r"\[LogMon\]\s+Previous\s+log", re.IGNORECASE
)
_RE_TIMEZONE_BANNER = re.compile(r"^Timezone\s*:", re.IGNORECASE)


class ServiceStartKind(str, Enum):
    FRESH_PROCESS_START = "FRESH_PROCESS_START"
    """Version banner emitted at the top of a new log file — confirmed
    new process. PID typically also distinct from prior log's PID."""

    LOG_ROTATION = "LOG_ROTATION"
    """Same process, log file rolled over. First line is the [LogMon]
    Previous log marker. Should NOT be treated as a fresh start."""


@dataclass
class ServiceStart:
    """One service start (or log rotation) event."""
    ts: datetime
    kind: ServiceStartKind
    component: str          # "ZSATunnel", "ZSATray", etc.
    pid: Optional[int]
    log_file: str
    record: LogLine

    @property
    def is_fresh_start(self) -> bool:
        return self.kind == ServiceStartKind.FRESH_PROCESS_START

    def is_within_fresh_window(self, event_ts: datetime) -> bool:
        """True if an event at event_ts happened within
        FRESH_START_WINDOW_SECONDS of this start."""
        if not self.is_fresh_start:
            return False
        delta = (event_ts - self.ts).total_seconds()
        return 0 <= delta <= FRESH_START_WINDOW_SECONDS


def find_service_starts(
    records_per_file: List[List[LogLine]],
) -> List[ServiceStart]:
    """Walk each log file's records; the FIRST line of each file is the
    determinant signal. Returns one ServiceStart per file (per component).

    `records_per_file` is a list of record-lists, one per log file —
    the caller is expected to group records by source_file before
    calling. (We need the file-boundary information, which is lost
    when records are merged into a single stream.)
    """
    starts: List[ServiceStart] = []
    for file_records in records_per_file:
        if not file_records:
            continue
        # Look at the first few non-empty lines of each file.
        for rec in file_records[:5]:
            msg = rec.message or ""
            if _RE_LOGMON_ROTATION.search(msg):
                starts.append(_make_start(rec, ServiceStartKind.LOG_ROTATION))
                break
            if _RE_VERSION_BANNER.search(msg) or _RE_TIMEZONE_BANNER.search(msg):
                starts.append(_make_start(rec, ServiceStartKind.FRESH_PROCESS_START))
                break
        # If neither marker appears in the first 5 lines, we make no
        # claim about this file — synthesizer treats it as "unknown
        # provenance" rather than guessing.

    starts.sort(key=lambda s: s.ts)
    return starts


def _make_start(rec: LogLine, kind: ServiceStartKind) -> ServiceStart:
    source = Path(rec.source_path).name if rec.source_path else ""
    component = classify_log_file(rec.source_path) if rec.source_path else "unknown"
    return ServiceStart(
        ts=rec.timestamp, kind=kind,
        component=component,
        pid=getattr(rec, "pid", None),
        log_file=source,
        record=rec,
    )


def nearest_fresh_start(
    starts: List[ServiceStart],
    event_ts: datetime,
    component: Optional[str] = None,
) -> Optional[ServiceStart]:
    """Find the most recent fresh start that precedes `event_ts`,
    optionally filtered by component (e.g., "tunnel").

    Used by the synthesizer to answer: "was the auth event a pre-work
    fresh-start?" → check if a fresh start of the relevant component
    happened within FRESH_START_WINDOW_SECONDS before the event.
    """
    candidates = [
        s for s in starts
        if s.is_fresh_start
        and s.ts <= event_ts
        and (component is None or s.component == component)
    ]
    if not candidates:
        return None
    return candidates[-1]
