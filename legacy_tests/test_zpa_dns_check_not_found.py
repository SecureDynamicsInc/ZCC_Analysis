"""
Synthetic-data test for the zpa_dns_check_not_found detector.

Run:  python test_zpa_dns_check_not_found.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues import Severity
from zcc_diag.issues.zpa_dns_check_not_found import (
    ZpaDnsCheckNotFoundDetector, THRESHOLD_TOTAL,
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


# Synthetic ZPN JSON shapes the detector should match.
DNS_NOT_FOUND_TEMPLATE = (
    '{"zpn_dns_client_check":{"name":"%s",'
    '"error":"ZPN_ERR_DNS_CHECK_NOT_FOUND","err_code":3001}}'
)
APP_INVALID_LINE = (
    '{"zpn_application_invalid":{"tag_id":42,'
    '"error":"ZPN_ERR_APPLICATION_INVALID","err_code":1002}}'
)


def main() -> int:
    failed = 0
    summary = BundleSummary()

    # ---- Case 1: 9 hits (below threshold) -> no finding ----
    d = ZpaDnsCheckNotFoundDetector()
    for i in range(9):
        d.feed(make_rec(DNS_NOT_FOUND_TEMPLATE % f"host{i}.example.local"),
               summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "9 hits (below threshold) -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 2: 15 hits (between threshold and sustained) -> INFO ----
    d = ZpaDnsCheckNotFoundDetector()
    for i in range(15):
        d.feed(make_rec(DNS_NOT_FOUND_TEMPLATE % f"host{i}.example.local"),
               summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "15 hits -> INFO severity",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_DNS_CHECK_NOT_FOUND"}, Severity.INFO),
    ):
        failed += 1

    # ---- Case 3: 75 hits -> WARNING (sustained) ----
    d = ZpaDnsCheckNotFoundDetector()
    for i in range(75):
        d.feed(make_rec(DNS_NOT_FOUND_TEMPLATE % "pct-dc1.corp-c.example"),
               summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "75 hits -> WARNING severity (sustained)",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_DNS_CHECK_NOT_FOUND"}, Severity.WARNING),
    ):
        failed += 1

    # ---- Case 4: 250 hits across multiple names -> WARNING + top-N report ----
    d = ZpaDnsCheckNotFoundDetector()
    for _ in range(180):
        d.feed(make_rec(DNS_NOT_FOUND_TEMPLATE % "pct-dc1.corp-c.example"),
               summary)
    for _ in range(40):
        d.feed(make_rec(DNS_NOT_FOUND_TEMPLATE % "_ldap._tcp.dc._msdcs.x"),
               summary)
    for _ in range(30):
        d.feed(make_rec(APP_INVALID_LINE), summary)
    findings = d.finalize(summary)
    if not findings:
        print("  FAIL  expected a finding for 250 hits")
        failed += 1
    else:
        f = findings[0]
        # The top hostname must appear in the description.
        if "pct-dc1.corp-c.example" not in f.description:
            print(f"  FAIL  top hostname not in description: {f.description[:200]!r}")
            failed += 1
        else:
            print("  OK    250 hits: top-N hostnames listed in description")
        # The invalid count should also be reflected.
        if "30" not in f.description:
            print(f"  FAIL  invalid count 30 not in description")
            failed += 1
        else:
            print("  OK    invalid count appears in description")

    # ---- Case 5: only application_invalid (no name lookups) ----
    d = ZpaDnsCheckNotFoundDetector()
    for _ in range(20):
        d.feed(make_rec(APP_INVALID_LINE), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "application_invalid-only above threshold -> fires",
        {f.code for f in findings},
        {"ZPA_DNS_CHECK_NOT_FOUND"},
    ):
        failed += 1

    # ---- Case 6: unrelated DNS lines don't fire ----
    d = ZpaDnsCheckNotFoundDetector()
    for _ in range(50):
        d.feed(make_rec('DBG DNS: Domain: app.foo.com found in bypass cache'),
               summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "unrelated DNS bypass-cache lines -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 7: case-insensitive matching on error token ----
    d = ZpaDnsCheckNotFoundDetector()
    weird = '{"zpn_dns_client_check":{"name":"x.local","error":"zpn_err_dns_check_not_found"}}'
    for _ in range(THRESHOLD_TOTAL + 1):
        d.feed(make_rec(weird), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "case-insensitive ZPN_ERR_DNS_CHECK_NOT_FOUND fires",
        {f.code for f in findings},
        {"ZPA_DNS_CHECK_NOT_FOUND"},
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
