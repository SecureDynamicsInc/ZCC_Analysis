"""
Synthetic-data test for the zpa_app_not_reachable detector.

Run:  python test_zpa_app_not_reachable.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues import Severity
from zcc_diag.issues.zpa_app_not_reachable import (
    ZpaAppNotReachableDetector,
)


def make_rec(msg: str) -> LogLine:
    return LogLine(
        timestamp=datetime(2026, 5, 22, 12, 0, 0, tzinfo=timezone.utc),
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


# Synthetic ZPN mtunnel-end JSON shapes (modeled on iatwater bundle).
APP_NOT_REACHABLE = (
    '{"zpn_mtunnel_end":{"tag_id":119,'
    '"error":"APP_NOT_REACHABLE","err_code":4002}}'
)
NO_CONNECTOR_AVAILABLE = (
    '{"zpn_mtunnel_end":{"tag_id":222,'
    '"error":"NO_CONNECTOR_AVAILABLE","err_code":4001}}'
)
INVALID_DOMAIN = (
    '{"zpn_mtunnel_end":{"tag_id":42,'
    '"error":"INVALID_DOMAIN","err_code":4003}}'
)
AST_SETUP_TIMEOUT = (
    '{"zpn_mtunnel_end":{"tag_id":501,'
    '"error":"AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER","err_code":4099}}'
)


def main() -> int:
    failed = 0
    summary = BundleSummary()

    # ---- Case 1: APP_NOT_REACHABLE -> CRITICAL finding ----
    d = ZpaAppNotReachableDetector()
    for _ in range(18):
        d.feed(make_rec(APP_NOT_REACHABLE), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "APP_NOT_REACHABLE fires ZPA_APP_NOT_REACHABLE CRITICAL",
        (
            {f.code for f in findings},
            {f.severity for f in findings},
        ),
        ({"ZPA_APP_NOT_REACHABLE"}, {Severity.CRITICAL}),
    ):
        failed += 1

    # ---- Case 2: NO_CONNECTOR_AVAILABLE -> CRITICAL ----
    d = ZpaAppNotReachableDetector()
    d.feed(make_rec(NO_CONNECTOR_AVAILABLE), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "NO_CONNECTOR_AVAILABLE fires ZPA_NO_CONNECTOR_AVAILABLE CRITICAL",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_NO_CONNECTOR_AVAILABLE"}, Severity.CRITICAL),
    ):
        failed += 1

    # ---- Case 3: INVALID_DOMAIN -> WARNING ----
    d = ZpaAppNotReachableDetector()
    d.feed(make_rec(INVALID_DOMAIN), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "INVALID_DOMAIN fires ZPA_INVALID_DOMAIN WARNING",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_INVALID_DOMAIN"}, Severity.WARNING),
    ):
        failed += 1

    # ---- Case 4: AST_SETUP_TIMEOUT -> WARNING ----
    d = ZpaAppNotReachableDetector()
    d.feed(make_rec(AST_SETUP_TIMEOUT), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "AST setup timeout fires ZPA_AST_SETUP_TIMEOUT WARNING",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_AST_SETUP_TIMEOUT"}, Severity.WARNING),
    ):
        failed += 1

    # ---- Case 5: mixed errors -> separate findings per code ----
    d = ZpaAppNotReachableDetector()
    d.feed(make_rec(APP_NOT_REACHABLE), summary)
    d.feed(make_rec(NO_CONNECTOR_AVAILABLE), summary)
    d.feed(make_rec(INVALID_DOMAIN), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "mixed errors -> separate findings per code",
        {f.code for f in findings},
        {
            "ZPA_APP_NOT_REACHABLE",
            "ZPA_NO_CONNECTOR_AVAILABLE",
            "ZPA_INVALID_DOMAIN",
        },
    ):
        failed += 1

    # ---- Case 6: tag_id collected and surfaced in title ----
    d = ZpaAppNotReachableDetector()
    for tid in (119, 220, 333):
        d.feed(make_rec(
            '{"zpn_mtunnel_end":{"tag_id":%d,'
            '"error":"APP_NOT_REACHABLE","err_code":4002}}' % tid
        ), summary)
    findings = d.finalize(summary)
    if findings:
        title = findings[0].title
        ok = "119" in title and "220" in title and "333" in title
        if not assert_eq(
            "tag_ids 119, 220, 333 all appear in title",
            ok, True,
        ):
            failed += 1

    # ---- Case 7: unrelated tunnel records -> no finding ----
    d = ZpaAppNotReachableDetector()
    for _ in range(50):
        d.feed(make_rec('{"zpn_mtunnel_end":{"error":"OK","err_code":0}}'),
               summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "unrelated mtunnel records -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 8: BRK_MT_TERMINATED is NOT our concern (reconnect-loop is) ----
    d = ZpaAppNotReachableDetector()
    d.feed(make_rec(
        '{"zpn_mtunnel_end":{"error":"BRK_MT_TERMINATED","err_code":5099}}'
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "BRK_MT_TERMINATED is not our concern -> no finding here",
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
