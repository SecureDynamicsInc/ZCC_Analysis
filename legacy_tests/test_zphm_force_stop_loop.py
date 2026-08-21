"""
Synthetic-data test for the zphm_force_stop_loop detector.

Run:  python test_zphm_force_stop_loop.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.zphm_force_stop_loop import (
    ZphmForceStopLoopDetector, THRESHOLD,
)


def make_rec(msg: str) -> LogLine:
    return LogLine(
        timestamp=datetime(2026, 5, 19, 21, 0, 0, tzinfo=timezone.utc),
        level="ERROR",
        pid=11748,
        tid=13088,
        message=msg,
        source_path=Path("ZSATunnel_2026-05-19-20-46-05.645308.log"),
        raw=msg,
        line_no=1,
    )


def assert_eq(label, got, want):
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def main() -> int:
    failed = 0
    summary = BundleSummary()

    # ---- Case 1: 19 hits (below threshold) -> no finding ----
    d = ZphmForceStopLoopDetector()
    for _ in range(19):
        d.feed(make_rec("ZPHM stopAndJoinManager Called!! Join Time: 5000"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "19 hits (below threshold) -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 2: 20 hits (at threshold) -> fires ----
    d = ZphmForceStopLoopDetector()
    for _ in range(20):
        d.feed(make_rec("ZPHM stopAndJoinManager Called!! Join Time: 5000"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "20 hits (at threshold) fires ZPHM_FORCE_STOP_LOOP",
        {f.code for f in findings},
        {"ZPHM_FORCE_STOP_LOOP"},
    ):
        failed += 1

    # ---- Case 3: 239 hits (synthetic reference count) -> fires ----
    d = ZphmForceStopLoopDetector()
    for _ in range(239):
        d.feed(make_rec("ZPHM stopAndJoinManager Called!! Join Time: 5000"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "239 hits (real bundle count) fires + reports count",
        {f.code for f in findings},
        {"ZPHM_FORCE_STOP_LOOP"},
    ):
        failed += 1
    if findings and "239" not in findings[0].title:
        print(f"  FAIL  title doesn't mention 239: {findings[0].title!r}")
        failed += 1

    # ---- Case 4: unrelated lines -> no finding ----
    d = ZphmForceStopLoopDetector()
    for _ in range(100):
        d.feed(make_rec("Some other unrelated tunnel log line"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "unrelated lines -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 5: case-insensitive match ----
    d = ZphmForceStopLoopDetector()
    for _ in range(THRESHOLD):
        d.feed(make_rec("ZPHM   stopandjoinmanager  CALLED!! join time: 5000"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "case variations still fire",
        {f.code for f in findings},
        {"ZPHM_FORCE_STOP_LOOP"},
    ):
        failed += 1

    # ---- Case 6: evidence cap (sample size capped, count still accurate) ----
    d = ZphmForceStopLoopDetector()
    for _ in range(100):
        d.feed(make_rec("ZPHM stopAndJoinManager Called!! Join Time: 5000"), summary)
    findings = d.finalize(summary)
    if findings:
        # Title should report 100, evidence should be capped at 5.
        ok_count = "100" in findings[0].title
        ok_evidence = len(findings[0].evidence) <= 5
        if not assert_eq(
            "100 hits: title reports count, evidence capped",
            (ok_count, ok_evidence),
            (True, True),
        ):
            failed += 1

    print()
    if failed:
        print(f"FAILED ({failed} test case(s))")
        return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
