"""
Synthetic-data test for the ncsi_false_negative detector.

Run:  python test_ncsi_false_negative.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.ncsi_false_negative import NcsiFalseNegativeDetector


def make_rec(msg: str, pid: int = 1000, tid: int = 2000) -> LogLine:
    return LogLine(
        timestamp=datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc),
        level="ERROR",
        pid=pid,
        tid=tid,
        message=msg,
        source_path=Path("ZSATunnel_2026-05-15-12-00-00.log"),
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

    # ---- Case 1: NCSI probe SSL fail (Example Tenant O case) ----
    d = NcsiFalseNegativeDetector()
    d.feed(make_rec("ID=1, Host=www.msftncsi.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "NCSI host SSL fail fires NCSI_PROBE_SSL_FAIL",
        {f.code for f in findings},
        {"NCSI_PROBE_SSL_FAIL"},
    ):
        failed += 1

    # ---- Case 2: msftconnecttest.com (Windows 10+) ----
    d = NcsiFalseNegativeDetector()
    d.feed(make_rec("ID=2, Host=www.msftconnecttest.com:443"), summary)
    d.feed(make_rec("SSL handshake failure"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "msftconnecttest fires NCSI_PROBE_SSL_FAIL",
        {f.code for f in findings},
        {"NCSI_PROBE_SSL_FAIL"},
    ):
        failed += 1

    # ---- Case 3: Mimecast IP range SSL fail (Example Tenant O observed) ----
    d = NcsiFalseNegativeDetector()
    d.feed(make_rec("ID=3, DestIP=216.145.216.42"), summary)
    d.feed(make_rec("SSL handshake failure"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "Mimecast IP range fires MIMECAST_SSL_FAIL",
        {f.code for f in findings},
        {"MIMECAST_SSL_FAIL"},
    ):
        failed += 1

    # ---- Case 4: Apple captive probe ----
    d = NcsiFalseNegativeDetector()
    d.feed(make_rec("ID=4, Host=captive.apple.com:443"), summary)
    d.feed(make_rec(
        "TLS handshake failed: certificate verify failed"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "captive.apple.com fires NCSI_PROBE_SSL_FAIL",
        {f.code for f in findings},
        {"NCSI_PROBE_SSL_FAIL"},
    ):
        failed += 1

    # ---- Case 5: non-NCSI / non-Mimecast host -> no finding ----
    d = NcsiFalseNegativeDetector()
    d.feed(make_rec("ID=5, Host=example.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "non-NCSI host does NOT fire this detector",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 6: NCSI host SSL fail across threads (no attribution) ----
    d = NcsiFalseNegativeDetector()
    d.feed(make_rec("ID=6, Host=www.msftncsi.com:443",
                    pid=1, tid=10), summary)
    d.feed(make_rec(
        "SSL handshake failure", pid=2, tid=20  # different thread
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "cross-thread SSL fail doesn't attribute to NCSI on other thread",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 7: both NCSI + Mimecast in one bundle ----
    d = NcsiFalseNegativeDetector()
    d.feed(make_rec("ID=7, Host=www.msftncsi.com:443",
                    pid=1, tid=10), summary)
    d.feed(make_rec(
        "SSL handshake failure", pid=1, tid=10,
    ), summary)
    d.feed(make_rec("ID=8, DestIP=216.145.216.99",
                    pid=2, tid=20), summary)
    d.feed(make_rec(
        "TLS handshake failed", pid=2, tid=20,
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "both NCSI + Mimecast fire separately",
        {f.code for f in findings},
        {"NCSI_PROBE_SSL_FAIL", "MIMECAST_SSL_FAIL"},
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
