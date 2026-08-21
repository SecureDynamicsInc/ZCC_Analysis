"""
Synthetic-data test for the p2p_app_blocked detector.

Run:  python test_p2p_app_blocked.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.p2p_app_blocked import P2pAppBlockedDetector


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

    # ---- Case 1: 3 distinct public peers, non-standard ports -> fires ----
    d = P2pAppBlockedDetector()
    d.feed(make_rec("DestIP=203.0.113.10:48121 connection timed out"), summary)
    d.feed(make_rec("DestIP=198.51.100.42:51234 connection refused"), summary)
    d.feed(make_rec("DestIP=192.0.2.99:60001 no route to host"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "3 distinct public-peer failures on non-standard ports fire",
        {f.code for f in findings},
        {"POSSIBLE_P2P_APP_BLOCKED_BY_ZIA"},
    ):
        failed += 1

    # ---- Case 2: same peer 5 times -> NOT enough distinct, no finding ----
    d = P2pAppBlockedDetector()
    for _ in range(5):
        d.feed(make_rec(
            "DestIP=203.0.113.10:48121 connection timed out"
        ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "5 hits on same peer does NOT fire (need distinct peers)",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 3: 5 failures on port 443 (control plane) -> no finding ----
    d = P2pAppBlockedDetector()
    d.feed(make_rec("DestIP=203.0.113.10:443 connection timed out"), summary)
    d.feed(make_rec("DestIP=198.51.100.42:443 connection refused"), summary)
    d.feed(make_rec("DestIP=192.0.2.99:443 connection failed"), summary)
    d.feed(make_rec("DestIP=203.0.113.11:443 connection failed"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "all-443 failures filtered out as control plane",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 4: 3 failures + a FIREWALL_BLOCK_ERROR -> no finding ----
    d = P2pAppBlockedDetector()
    d.feed(make_rec("DestIP=203.0.113.10:48121 connection timed out"), summary)
    d.feed(make_rec("DestIP=198.51.100.42:51234 connection refused"), summary)
    d.feed(make_rec("DestIP=192.0.2.99:60001 no route to host"), summary)
    d.feed(make_rec(
        "Changing ZIA state from CONNECTING to FIREWALL_BLOCK_ERROR"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "tunnel broken -> detector suppressed",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 5: failures to RFC1918 IPs are not P2P signals ----
    d = P2pAppBlockedDetector()
    d.feed(make_rec("DestIP=10.0.0.5:48121 connection timed out"), summary)
    d.feed(make_rec("DestIP=192.168.1.42:51234 connection refused"), summary)
    d.feed(make_rec("DestIP=172.16.0.99:60001 no route to host"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "RFC1918 failures don't fire P2P detector",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 6: 100.64.x.x CGNAT health checks don't fire ----
    d = P2pAppBlockedDetector()
    d.feed(make_rec("DestIP=100.64.0.6:9090 connection refused"), summary)
    d.feed(make_rec("DestIP=100.64.0.8:9090 connection refused"), summary)
    d.feed(make_rec("DestIP=100.64.0.6:443 connection refused"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "100.64.x.x CGNAT health-check failures don't fire P2P",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 7: only 2 distinct peers -> below threshold ----
    d = P2pAppBlockedDetector()
    d.feed(make_rec("DestIP=203.0.113.10:48121 connection timed out"), summary)
    d.feed(make_rec("DestIP=198.51.100.42:51234 connection refused"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "2 distinct peers (below threshold) doesn't fire",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 8: healthy bundle with no failures -> no finding ----
    d = P2pAppBlockedDetector()
    d.feed(make_rec("Tunnel forwarding active"), summary)
    d.feed(make_rec("PAC fetch successful"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "healthy bundle -> no finding",
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
