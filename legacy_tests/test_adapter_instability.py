"""Synthetic-data test for adapter_instability detector. Run: python test_adapter_instability.py"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.adapter_instability import AdapterInstabilityDetector


_BASE = datetime(2026, 6, 2, 14, 0, 0, tzinfo=timezone.utc)


def make_rec(msg, level="ERR", i=0):
    return LogLine(
        timestamp=_BASE + timedelta(seconds=i),
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


def main() -> int:
    failed = 0
    summary = BundleSummary()

    # ---- Case 1: 152 LUID failures (Scenario Other / file-export shape) -> CRIT ----
    d = AdapterInstabilityDetector()
    for i in range(152):
        d.feed(make_rec(
            f"ConvertInterfaceLuidToAlias Failed. Error: 0x00000008  (try {i})",
            i=i,
        ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "152 LUID failures fires CRITICAL (the field bundle shape)",
        {(f.code, f.severity.value) for f in findings},
        {("ADAPTER_INSTABILITY", "CRITICAL")},
    ):
        failed += 1

    # ---- Case 2: only 50 LUID failures -> WARN (above 30, below 100) ----
    d = AdapterInstabilityDetector()
    for i in range(50):
        d.feed(make_rec("ConvertInterfaceLuidToAlias Failed. Error: 0x00000008", i=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "50 LUID failures fires WARN",
        {(f.code, f.severity.value) for f in findings},
        {("ADAPTER_INSTABILITY", "WARNING")},
    ):
        failed += 1

    # ---- Case 3: only 10 LUID failures -> nothing (below WARN threshold) ----
    d = AdapterInstabilityDetector()
    for i in range(10):
        d.feed(make_rec("ConvertInterfaceLuidToAlias Failed. Error: 0x00000008", i=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "10 LUID failures doesn't fire (below WARN threshold of 30)",
        {f.code for f in findings}, set(),
    ):
        failed += 1

    # ---- Case 4: NP-parse-fail signal alone (3+) -> WARN ----
    d = AdapterInstabilityDetector()
    for i in range(4):
        d.feed(make_rec(f"addTrafficForwardingFilters: Failed to parse NP tunnel ip: ", i=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "4 NP-parse fails fires WARN (low-volume signal-by-itself trip)",
        {(f.code, f.severity.value) for f in findings},
        {("ADAPTER_INSTABILITY", "WARNING")},
    ):
        failed += 1

    # ---- Case 5: 12 NP-parse fails -> CRIT (>= 10) ----
    d = AdapterInstabilityDetector()
    for i in range(12):
        d.feed(make_rec(f"addTrafficForwardingFilters: Failed to parse NP tunnel ip: ", i=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "12 NP-parse fails fires CRITICAL",
        {(f.code, f.severity.value) for f in findings},
        {("ADAPTER_INSTABILITY", "CRITICAL")},
    ):
        failed += 1

    # ---- Case 6: gateway-change only -> WARN at 20+ ----
    d = AdapterInstabilityDetector()
    for i in range(25):
        d.feed(make_rec(f"Default Interface Gateway is: 192.168.1.{i}", i=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "25 gateway-change ERRs fires WARN",
        {(f.code, f.severity.value) for f in findings},
        {("ADAPTER_INSTABILITY", "WARNING")},
    ):
        failed += 1

    # ---- Case 7: gateway-change at INFO level (not ERR) doesn't count ----
    d = AdapterInstabilityDetector()
    for i in range(30):
        d.feed(make_rec(f"Default Interface Gateway is: 192.168.1.1", level="INFO", i=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "Gateway-change at INFO level doesn't trip (the detector wants ERR)",
        {f.code for f in findings}, set(),
    ):
        failed += 1

    # ---- Case 8: WTS failures only (5+) -> WARN ----
    d = AdapterInstabilityDetector()
    for i in range(6):
        d.feed(make_rec("WTSQuerySessionInformation failed; error: 0x00000002", i=i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "6 WTS session-lookup fails fires WARN",
        {(f.code, f.severity.value) for f in findings},
        {("ADAPTER_INSTABILITY", "WARNING")},
    ):
        failed += 1

    # ---- Case 9: empty/healthy bundle -> no finding ----
    d = AdapterInstabilityDetector()
    d.feed(make_rec("Tunnel forwarding active"), summary)
    d.feed(make_rec("ZApp Status: getSmeProxyState:TUNNEL_FORWARDING"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "healthy bundle -> no finding",
        {f.code for f in findings}, set(),
    ):
        failed += 1

    # ---- Case 10: evidence cap ----
    d = AdapterInstabilityDetector()
    for i in range(200):
        d.feed(make_rec("ConvertInterfaceLuidToAlias Failed. Error: 0x00000008", i=i), summary)
    findings = d.finalize(summary)
    if findings:
        if not assert_eq(
            "evidence capped (not 200, capped at 12 ish)",
            len(findings[0].evidence) <= 12,
            True,
        ):
            failed += 1

    # ---- Case 11: realistic field-bundle shape combined ----
    d = AdapterInstabilityDetector()
    for i in range(152):
        d.feed(make_rec("ConvertInterfaceLuidToAlias Failed. Error: 0x00000008", i=i), summary)
    for i in range(11):
        d.feed(make_rec("addTrafficForwardingFilters: Failed to parse NP tunnel ip: ", i=300 + i), summary)
    for i in range(38):
        d.feed(make_rec(f"Default Interface Gateway is: 192.168.1.1", i=400 + i), summary)
    for i in range(5):
        d.feed(make_rec("WTSQuerySessionInformation failed; error: 0x00000002", i=500 + i), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "field-bundle multi-signal shape fires CRITICAL",
        {(f.code, f.severity.value) for f in findings},
        {("ADAPTER_INSTABILITY", "CRITICAL")},
    ):
        failed += 1
    if findings:
        ttl = findings[0].title
        if "CRITICAL volume" in ttl or "instability" in ttl.lower():
            print(f"  OK    title is descriptive: {ttl}")
        else:
            print(f"  FAIL  title should describe the trigger: {ttl!r}")
            failed += 1

    print()
    if failed:
        print(f"FAILED ({failed} test case(s))")
        return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
