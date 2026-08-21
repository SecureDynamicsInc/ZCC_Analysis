"""Locate the current ZSATunnel.log and prepare it for the full-file view.

The paged raw viewer answers "show me the matching records". This answers a
different question: *what happened around them*. A filtered page strips the
preceding and following records, which is where the cause usually sits — a
reset means little without the setup attempt above it and the retry below it.
So this module hands the UI one whole log, in order, with nothing removed.

Choosing "the current log" needs care. Source-file labels are deduplicated by
the store (``ZSATunnel.log``, ``ZSATunnel.log#2``, ...), and a compressed
rotation can carry the same basename as the live file, so the name cannot
decide it. The newest last-record timestamp can, and does.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional, Sequence, Tuple

from zcc_diag.log_store import classify_component

#: Component key the parser assigns to ZSATunnel / TRPTunnel / ZscalerTunnel.
TUNNEL_COMPONENT = "tunnel"

#: Ceiling on records rendered in one block. A live ZSATunnel.log runs to tens
#: of thousands of records and rows are cheap to skip with
#: ``content-visibility``, but a bundle read at full rotation depth can present
#: far more than any browser should be handed at once. When the cap bites, the
#: *tail* is kept: the newest records are the ones an incident lives in, and the
#: view says plainly what it dropped.
MAX_RENDERED_RECORDS = 120_000


@dataclass(frozen=True)
class TunnelLogChoice:
    """Which log was chosen, and why."""

    source_file: str
    records: int
    first_ts: Optional[datetime]
    last_ts: Optional[datetime]
    candidates: int
    reason: str

    @property
    def span_label(self) -> str:
        if not self.first_ts or not self.last_ts:
            return "time span not evidenced"
        return f"{self.first_ts:%Y-%m-%d %H:%M} → {self.last_ts:%Y-%m-%d %H:%M} UTC"


def _to_dt(value: float) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def _bounds_from_lines(idx: Any) -> List[Tuple[str, int, float, float]]:
    """Fallback for a plain in-memory index, which has no aggregate query."""
    seen: dict = {}
    for line in getattr(idx, "lines", []) or []:
        name = getattr(line, "source_file", "") or ""
        component = getattr(line, "component", "") or classify_component(name) or ""
        if component != TUNNEL_COMPONENT:
            continue
        stamp = getattr(line, "ts", None)
        value = stamp.timestamp() if stamp else 0.0
        record = seen.get(name)
        if record is None:
            seen[name] = [1, value, value]
        else:
            record[0] += 1
            if value:
                record[1] = min(record[1] or value, value)
                record[2] = max(record[2], value)
    return [(name, data[0], data[1], data[2]) for name, data in seen.items()]


def select_current_tunnel_log(idx: Any) -> Optional[TunnelLogChoice]:
    """The live ZSATunnel.log, or ``None`` when the bundle has no tunnel log."""
    bounds_fn = getattr(idx, "component_file_bounds", None)
    bounds = (
        bounds_fn(TUNNEL_COMPONENT) if callable(bounds_fn)
        else _bounds_from_lines(idx)
    )
    bounds = [row for row in bounds if row[1]]
    if not bounds:
        return None

    # Newest last record wins. Ties break on record count, then name, so the
    # choice is deterministic across reruns.
    best = max(bounds, key=lambda row: (row[3], row[1], row[0]))
    name, records, first, last = best

    if len(bounds) == 1:
        reason = "the only tunnel log in this bundle"
    else:
        reason = (
            f"newest of {len(bounds)} tunnel logs, by last record time"
        )
    return TunnelLogChoice(
        source_file=name,
        records=records,
        first_ts=_to_dt(first),
        last_ts=_to_dt(last),
        candidates=len(bounds),
        reason=reason,
    )


def load_tunnel_records(
    idx: Any, source_file: str, *, limit: int = MAX_RENDERED_RECORDS,
) -> Tuple[List[Any], int]:
    """Every record in ``source_file``, in file order.

    Returns ``(records, dropped)``. When the cap bites, the oldest records are
    dropped and the count is returned so the view can say so rather than
    silently showing a truncated log.
    """
    getter = getattr(idx, "lines_for_file", None)
    if callable(getter):
        lines = list(getter(source_file))
    else:
        lines = [
            line for line in (getattr(idx, "lines", []) or [])
            if (getattr(line, "source_file", "") or "") == source_file
        ]
    lines.sort(key=lambda line: getattr(line, "line_no", 0))
    if limit and len(lines) > limit:
        dropped = len(lines) - limit
        return lines[-limit:], dropped
    return lines, 0


def critical_anchors(
    rows: Sequence[Any], *, limit: int = 60,
) -> List[Tuple[int, str, str]]:
    """``[(line_no, label, severity), ...]`` for jump-to navigation.

    The point of the full-file view is context, so the navigation moves the
    reader *to* a record inside the surrounding log rather than filtering the
    log down to it.
    """
    out: List[Tuple[int, str, str]] = []
    for row in rows:
        if row.severity != "critical":
            continue
        label = f"{row.ts_iso}  {row.body[:88]}" if row.ts_iso else row.body[:96]
        out.append((row.line_no, label, row.severity))
        if len(out) >= limit:
            break
    return out
