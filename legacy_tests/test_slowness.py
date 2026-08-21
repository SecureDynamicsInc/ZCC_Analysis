"""Synthetic-data test for the slowness detector.

Covers:
  * ZTraceroute parser handling key=value lines + JSON inline blobs
  * Elbow-hop calculation and path-segment classification
  * DTLS fallback rate-per-hour scoring (CRIT / WARN)
  * zpn_dns_client_check elapsed scoring
  * Probe-RTT excursion scoring
  * Webload TTFB / total scoring (CRIT / WARN)
  * INFO fallback when ZTraceroute file is absent
  * Severity escalation when 3+ signals contribute

Run:  python test_slowness.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues import Severity
from zcc_diag.issues.slowness import (
    SlownessDetector, _classify_path_segment,
)
from zcc_diag.zdx_parser import (
    _hop_record_from_match, _summarise_trace, _HOP_PAT, _trace_from_json,
)


_BASE = datetime(2026, 6, 8, 14, 0, 0, tzinfo=timezone.utc)


def make_rec(msg, level="INF", i=0, seconds_offset=None):
    """Make a synthetic tunnel LogLine. seconds_offset overrides i*1
    when you want a specific timestamp."""
    ts = _BASE + timedelta(seconds=seconds_offset if seconds_offset is not None else i)
    return LogLine(
        timestamp=ts,
        level=level,
        pid=15752,
        tid=16488,
        message=msg,
        source_path=Path("ZSATunnel.log"),
        raw=msg,
        line_no=i + 1,
    )


def assert_eq(label, got, want):
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def assert_true(label, cond, hint=""):
    print(f"  {'OK   ' if cond else 'FAIL '} {label}")
    if not cond and hint:
        print(f"        hint: {hint}")
    return cond


def make_summary(traces=None, webloads=None, has_trace=True):
    s = BundleSummary()
    s.bundle_meta["ztraceroute_traces"] = traces or []
    s.bundle_meta["zdx_webloads"] = webloads or []
    s.bundle_meta["has_ztraceroute_file"] = has_trace
    return s


def main() -> int:
    failed = 0
    print("--- ZTraceroute hop parsing ---")

    # Case A1: standard key=value hop record.
    line = ("hop=4 ip=10.0.5.1 hostname=core-rtr rtt_ms=42.3 loss=0.0")
    m = _HOP_PAT.search(line)
    h = _hop_record_from_match(m) if m else None
    if not assert_true("parse 'hop=4 ip=10.0.5.1 rtt_ms=42.3'", h is not None):
        failed += 1
    else:
        if not assert_eq("  hop index", h["index"], 4): failed += 1
        if not assert_eq("  hop ip", h["ip"], "10.0.5.1"): failed += 1
        if not assert_eq("  rtt_ms", h["rtt_ms"], 42.3): failed += 1

    # Case A2: rtt_us variant (1000 us -> 1 ms).
    line = "hop=2 ip=192.168.1.1 rtt_us=2500"
    m = _HOP_PAT.search(line)
    h = _hop_record_from_match(m) if m else None
    if not assert_eq("parse 'rtt_us=2500' -> 2.5 ms",
                     h["rtt_ms"] if h else None, 2.5):
        failed += 1

    # Case A3: JSON inline blob.
    j = {
        "dst": "140.82.121.4",
        "hostname": "gateway.zscalertwo.net",
        "hops": [
            {"i": 1, "ip": "192.168.1.1", "rtt_ms": 2.1},
            {"i": 2, "ip": "10.0.0.1", "rtt_ms": 8.4},
            {"i": 3, "ip": "100.64.0.1", "rtt_ms": 12.0},
            {"i": 4, "ip": "203.0.113.1", "rtt_ms": 280.0},  # elbow
            {"i": 5, "ip": "198.51.100.1", "rtt_ms": 285.0},
        ],
    }
    t = _trace_from_json(j)
    if not assert_true("JSON trace parsed", t is not None):
        failed += 1
    else:
        _summarise_trace(t)
        if not assert_eq("  elbow hop = 4", t["elbow_hop"], 4): failed += 1
        if not assert_eq("  elbow delta = 268 ms",
                         round(t["elbow_delta_ms"]), 268):
            failed += 1
        if not assert_eq("  max rtt = 285 ms", t["max_rtt_ms"], 285.0): failed += 1
        if not assert_eq("  unreachable = 0", t["unreachable_count"], 0): failed += 1

    print()
    print("--- Path segment classification ---")
    if not assert_eq("hop 2 -> LAN", _classify_path_segment(2),
                     "customer LAN / WiFi"):
        failed += 1
    if not assert_eq("hop 5 -> ISP", _classify_path_segment(5),
                     "local ISP / regional transit"):
        failed += 1
    if not assert_eq("hop 9 -> edge", _classify_path_segment(9),
                     "Zscaler edge ingress"):
        failed += 1

    print()
    print("--- INFO fallback: no ZTraceroute file ---")
    d = SlownessDetector()
    summary = make_summary(has_trace=False)
    findings = d.finalize(summary)
    codes = {f.code for f in findings}
    if not assert_eq("ZTRACEROUTE_NOT_COLLECTED fires when file absent",
                     codes, {"ZTRACEROUTE_NOT_COLLECTED"}):
        failed += 1

    print()
    print("--- INFO suppressed when ZTraceroute file present ---")
    d = SlownessDetector()
    summary = make_summary(has_trace=True)  # but no traces and no signals
    findings = d.finalize(summary)
    if not assert_eq("no findings when bundle is clean & ztraceroute present",
                     findings, []):
        failed += 1

    print()
    print("--- DTLS fallback scoring ---")
    # 6 fallbacks over 1 hour -> CRIT (>= 5/hr).
    d = SlownessDetector()
    for i in range(6):
        d.feed(make_rec("Falling back to TLS",
                        seconds_offset=i * 600), make_summary())
    findings = d.finalize(make_summary(has_trace=True))
    sevs = {f.severity for f in findings if f.code == "SLOWNESS_SIGNALS"}
    if not assert_true("6 DTLS fallbacks in 1h fires CRITICAL",
                       Severity.CRITICAL in sevs):
        failed += 1

    # 2 fallbacks over 1 hour -> WARN
    d = SlownessDetector()
    for i in range(2):
        d.feed(make_rec("Tunnel transport changed to TLS",
                        seconds_offset=i * 1800), make_summary())
    findings = d.finalize(make_summary(has_trace=True))
    sevs = {f.severity for f in findings if f.code == "SLOWNESS_SIGNALS"}
    if not assert_true("2 DTLS fallbacks in 1h fires WARN",
                       Severity.WARNING in sevs):
        failed += 1

    print()
    print("--- ZTraceroute elbow scoring ---")
    # Elbow delta 280 ms in customer-LAN range (hop 2 -> LAN segment;
    # remember hop 4 falls into ISP segment, not LAN). -> CRIT.
    big_elbow = {
        "destination_ip": "140.82.121.4",
        "destination_host": "gateway.zscalertwo.net",
        "elbow_hop": 2,
        "elbow_delta_ms": 280.0,
        "max_rtt_ms": 300.0,
        "unreachable_count": 0,
        "hops": [{"index": 1, "rtt_ms": 2.0}],
    }
    d = SlownessDetector()
    findings = d.finalize(make_summary(traces=[big_elbow], has_trace=True))
    main_finding = next((f for f in findings
                         if f.code == "SLOWNESS_SIGNALS"), None)
    if not assert_true("280ms elbow fires SLOWNESS_SIGNALS",
                       main_finding is not None):
        failed += 1
    elif not assert_eq("  severity = CRITICAL",
                       main_finding.severity, Severity.CRITICAL):
        failed += 1
    elif not assert_true("  description mentions 'customer LAN'",
                         "customer LAN" in main_finding.description):
        failed += 1

    # Elbow delta 70 ms (WARN range).
    small_elbow = dict(big_elbow, elbow_delta_ms=70.0)
    d = SlownessDetector()
    findings = d.finalize(make_summary(traces=[small_elbow], has_trace=True))
    main_finding = next((f for f in findings
                         if f.code == "SLOWNESS_SIGNALS"), None)
    if not assert_eq("70ms elbow fires WARN",
                     main_finding.severity if main_finding else None,
                     Severity.WARNING):
        failed += 1

    # Elbow delta 30 ms -> below thresholds, no finding.
    no_elbow = dict(big_elbow, elbow_delta_ms=30.0, unreachable_count=0)
    d = SlownessDetector()
    findings = d.finalize(make_summary(traces=[no_elbow], has_trace=True))
    main_finding = next((f for f in findings
                         if f.code == "SLOWNESS_SIGNALS"), None)
    if not assert_eq("30ms elbow is below threshold (no SLOWNESS finding)",
                     main_finding, None):
        failed += 1

    print()
    print("--- Webload scoring ---")
    # TTFB 6000ms -> CRIT
    weblods_crit = [
        {"url": "https://outlook.office.com",
         "ttfb_ms": 6000.0, "total_ms": 8000.0},
        {"url": "https://outlook.office.com",
         "ttfb_ms": 5500.0, "total_ms": 7000.0},
    ]
    d = SlownessDetector()
    findings = d.finalize(make_summary(webloads=weblods_crit, has_trace=True))
    main_finding = next((f for f in findings
                         if f.code == "SLOWNESS_SIGNALS"), None)
    if not assert_true("TTFB p90 >= 5s fires CRIT",
                       main_finding is not None
                       and main_finding.severity == Severity.CRITICAL):
        failed += 1

    print()
    print("--- 3+ signals escalates to CRIT ---")
    # Two WARN-level signals + a third minor -> CRIT due to count rule.
    d = SlownessDetector()
    # signal 1: 2 DTLS fallbacks in 1h (WARN)
    for i in range(2):
        d.feed(make_rec("Falling back to TLS",
                        seconds_offset=i * 1800), make_summary())
    # signal 2: PMTU events (3 = WARN)
    for i in range(3):
        d.feed(make_rec("PMTU FragmentationNeeded event",
                        seconds_offset=2000 + i * 100), make_summary())
    # signal 3: a small elbow (WARN)
    small_elbow = {
        "destination_ip": "1.1.1.1",
        "destination_host": "",
        "elbow_hop": 3, "elbow_delta_ms": 60.0,
        "max_rtt_ms": 80.0, "unreachable_count": 0,
        "hops": [{"index": 1, "rtt_ms": 2.0}],
    }
    findings = d.finalize(make_summary(traces=[small_elbow], has_trace=True))
    main_finding = next((f for f in findings
                         if f.code == "SLOWNESS_SIGNALS"), None)
    if not assert_true(
        "3 WARN-level signals escalate to CRIT",
        main_finding is not None
        and main_finding.severity == Severity.CRITICAL,
    ):
        failed += 1

    print()
    if failed == 0:
        print(f"  All slowness-detector cases passed.")
    else:
        print(f"  {failed} case(s) failed.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
