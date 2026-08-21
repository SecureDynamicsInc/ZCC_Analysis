"""Choosing the current ZSATunnel.log, and loading it whole.

Picking the wrong file here is quiet and expensive: a rotation can carry the
same basename as the live log, so a name-based choice would show last week's
tunnel log while claiming to show the current one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Optional

from zcc_diag.raw_view import to_raw_lines
from zcc_diag.tunnel_log import (
    MAX_RENDERED_RECORDS,
    critical_anchors,
    load_tunnel_records,
    select_current_tunnel_log,
)


def _ts(day: int, hour: int = 12) -> float:
    return datetime(2026, 8, day, hour, tzinfo=timezone.utc).timestamp()


@dataclass
class _Line:
    line_no: int
    level: str
    body: str
    ts: Optional[datetime]
    source_file: str
    component: str = "tunnel"


class _Store:
    """Stands in for LogStore's aggregate query surface."""

    def __init__(self, bounds, lines=None):
        self._bounds = bounds
        self._lines = lines or {}

    def component_file_bounds(self, component):
        return [row for row in self._bounds] if component == "tunnel" else []

    def lines_for_file(self, source_file):
        return list(self._lines.get(source_file, []))


class _Index:
    """Stands in for a plain in-memory index with no aggregate query."""

    def __init__(self, lines: List[_Line]):
        self.lines = lines


def test_the_only_tunnel_log_is_chosen_and_says_so():
    store = _Store([("ZSATunnel.log", 4_210, _ts(14), _ts(18))])

    choice = select_current_tunnel_log(store)

    assert choice.source_file == "ZSATunnel.log"
    assert choice.records == 4_210
    assert choice.candidates == 1
    assert choice.reason == "the only tunnel log in this bundle"
    assert choice.span_label == "2026-08-14 12:00 → 2026-08-18 12:00 UTC"


def test_the_newest_last_record_wins_not_the_bare_filename():
    """A rotation can hold the basename while the live log is the deduped label.

    Choosing on the name would show a rotation and call it current.
    """
    store = _Store([
        ("ZSATunnel.log", 90_000, _ts(1), _ts(9)),      # an older rotation
        ("ZSATunnel.log#2", 5_400, _ts(17), _ts(19)),   # the live log
        ("ZSATunnel.log#3", 60_000, _ts(10), _ts(16)),
    ])

    choice = select_current_tunnel_log(store)

    assert choice.source_file == "ZSATunnel.log#2"
    assert choice.candidates == 3
    assert "newest of 3 tunnel logs" in choice.reason


def test_a_bundle_with_no_tunnel_log_returns_nothing():
    assert select_current_tunnel_log(_Store([])) is None
    # Empty files must not be selected either.
    assert select_current_tunnel_log(_Store([("ZSATunnel.log", 0, 0.0, 0.0)])) is None


def test_selection_falls_back_to_scanning_a_plain_index():
    lines = [
        _Line(1, "INFO", "old", datetime(2026, 8, 1, tzinfo=timezone.utc), "ZSATunnel.log#2"),
        _Line(1, "INFO", "new", datetime(2026, 8, 19, tzinfo=timezone.utc), "ZSATunnel.log"),
        _Line(2, "INFO", "tray", datetime(2026, 8, 19, tzinfo=timezone.utc), "ZSATray.log", "tray"),
    ]

    choice = select_current_tunnel_log(_Index(lines))

    assert choice.source_file == "ZSATunnel.log"
    # The tray log is a different component and must not be a candidate.
    assert choice.candidates == 2


def test_records_load_in_file_order():
    lines = [
        _Line(3, "INFO", "third", None, "ZSATunnel.log"),
        _Line(1, "INFO", "first", None, "ZSATunnel.log"),
        _Line(2, "ERROR", "second", None, "ZSATunnel.log"),
    ]
    store = _Store([("ZSATunnel.log", 3, 0, 0)], {"ZSATunnel.log": lines})

    records, dropped = load_tunnel_records(store, "ZSATunnel.log")

    assert [line.line_no for line in records] == [1, 2, 3]
    assert dropped == 0


def test_an_oversized_log_keeps_the_tail_and_reports_the_drop():
    """The newest records are where an incident lives, so the tail is kept."""
    lines = [
        _Line(n, "INFO", f"line {n}", None, "ZSATunnel.log")
        for n in range(1, 51)
    ]
    store = _Store([("ZSATunnel.log", 50, 0, 0)], {"ZSATunnel.log": lines})

    records, dropped = load_tunnel_records(store, "ZSATunnel.log", limit=10)

    assert dropped == 40
    assert [line.line_no for line in records] == list(range(41, 51))


def test_the_default_cap_is_generous_enough_for_a_live_log():
    # A live ZSATunnel.log runs to tens of thousands of records; the cap exists
    # for full-rotation-depth reads, not for the normal case.
    assert MAX_RENDERED_RECORDS >= 100_000


def test_anchors_point_at_critical_records_only():
    rows = to_raw_lines([
        _Line(1, "INFO", "tunnel forwarding", None, "ZSATunnel.log"),
        _Line(2, "ERROR", "connect failed", None, "ZSATunnel.log"),
        _Line(3, "WARN", "retrying", None, "ZSATunnel.log"),
        _Line(4, "FATAL", "driver lost", None, "ZSATunnel.log"),
    ])

    anchors = critical_anchors(rows)

    assert [line_no for line_no, _label, _sev in anchors] == [2, 4]
    assert all(sev == "critical" for _n, _l, sev in anchors)


def test_anchor_list_is_capped_so_the_jump_list_stays_usable():
    rows = to_raw_lines([
        _Line(n, "ERROR", f"failure {n}", None, "ZSATunnel.log")
        for n in range(1, 200)
    ])

    anchors = critical_anchors(rows, limit=25)

    assert len(anchors) == 25
    assert anchors[0][0] == 1
