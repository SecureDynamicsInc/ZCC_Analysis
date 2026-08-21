"""
Synthetic-data test for the zpa_mtunnel_reconnect_loop detector.

Run:  python test_zpa_mtunnel_reconnect_loop.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues import Severity
from zcc_diag.issues.zpa_mtunnel_reconnect_loop import (
    ZpaMtunnelReconnectLoopDetector,
    THRESHOLD_TOTAL, THRESHOLD_SUSTAINED,
)


_BASE_TS = datetime(2026, 5, 22, 12, 0, 0, tzinfo=timezone.utc)


def make_rec(msg: str, offset_sec: int = 0) -> LogLine:
    return LogLine(
        timestamp=_BASE_TS + timedelta(seconds=offset_sec),
        level="INFO",
        pid=1234,
        tid=5678,
        message=msg,
        source_path=Path("ZSATunnel_2026-05-22-12-00-00.000000.log"),
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


CLOSED_FROM_ASSISTANT = (
    '{"zpn_mtunnel_end":{"tag_id":119,'
    '"error":"BRK_MT_CLOSED_FROM_ASSISTANT","err_code":5027}}'
)
RESET_FROM_SERVER = (
    '{"zpn_mtunnel_end":{"tag_id":120,'
    '"error":"BRK_MT_RESET_FROM_SERVER","err_code":5028}}'
)
TERMINATED = (
    '{"zpn_mtunnel_end":{"tag_id":121,'
    '"error":"BRK_MT_TERMINATED","err_code":5029}}'
)


def main() -> int:
    failed = 0
    summary = BundleSummary()

    # ---- Case 1: 29 hits (below threshold) -> no finding ----
    d = ZpaMtunnelReconnectLoopDetector()
    for i in range(29):
        d.feed(make_rec(CLOSED_FROM_ASSISTANT, offset_sec=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "29 hits (below threshold) -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 2: 35 hits -> INFO (elevated) ----
    d = ZpaMtunnelReconnectLoopDetector()
    for i in range(35):
        d.feed(make_rec(CLOSED_FROM_ASSISTANT, offset_sec=i * 2), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "35 hits -> ZPA_MTUNNEL_RECONNECT_LOOP INFO",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_MTUNNEL_RECONNECT_LOOP"}, Severity.INFO),
    ):
        failed += 1

    # ---- Case 3: 150 hits -> WARNING (sustained) ----
    d = ZpaMtunnelReconnectLoopDetector()
    for i in range(150):
        d.feed(make_rec(CLOSED_FROM_ASSISTANT, offset_sec=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "150 hits (>= THRESHOLD_SUSTAINED) -> WARNING",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_MTUNNEL_RECONNECT_LOOP"}, Severity.WARNING),
    ):
        failed += 1

    # ---- Case 4: real-bundle mix (example-tenant-c: 192/221/27) ----
    d = ZpaMtunnelReconnectLoopDetector()
    for i in range(192):
        d.feed(make_rec(CLOSED_FROM_ASSISTANT, offset_sec=i), summary)
    for i in range(221):
        d.feed(make_rec(RESET_FROM_SERVER, offset_sec=200 + i), summary)
    for i in range(27):
        d.feed(make_rec(TERMINATED, offset_sec=500 + i), summary)
    findings = d.finalize(summary)
    if findings:
        f = findings[0]
        # All three reasons should appear in the breakdown.
        ok = all(
            t in f.description
            for t in (
                "BRK_MT_CLOSED_FROM_ASSISTANT",
                "BRK_MT_RESET_FROM_SERVER",
                "BRK_MT_TERMINATED",
            )
        )
        if not assert_eq(
            "real-bundle mix: all three reasons in description breakdown",
            ok, True,
        ):
            failed += 1
        # Total count should be 440.
        if "440" not in f.title:
            print(f"  FAIL  total 440 not in title: {f.title!r}")
            failed += 1
        else:
            print("  OK    total count 440 appears in title")
        # Rate-per-minute computation should be present when window > 0.
        if "/min" not in f.title:
            print(f"  FAIL  rate-per-minute not in title: {f.title!r}")
            failed += 1
        else:
            print("  OK    rate-per-minute appears in title")

    # ---- Case 5: unrelated tokens don't fire ----
    d = ZpaMtunnelReconnectLoopDetector()
    for _ in range(200):
        d.feed(make_rec('{"zpn_mtunnel_end":{"error":"OK","err_code":0}}'),
               summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "unrelated mtunnel records -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 6: BRK_MT_SETUP_FAIL_X is NOT our concern ----
    d = ZpaMtunnelReconnectLoopDetector()
    for _ in range(200):
        d.feed(make_rec(
            '{"zpn_mtunnel_setup":{"error":"BRK_MT_SETUP_FAIL_NO_POLICY_FOUND"}}'
        ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "BRK_MT_SETUP_FAIL_X is the auth detector's concern, not ours",
        {f.code for f in findings},
        set(),
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
