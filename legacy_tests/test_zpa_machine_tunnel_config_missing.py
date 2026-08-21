"""
Synthetic-data test for the zpa_machine_tunnel_config_missing detector.

Run:  python test_zpa_machine_tunnel_config_missing.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues import Severity
from zcc_diag.issues.zpa_machine_tunnel_config_missing import (
    ZpaMachineTunnelConfigMissingDetector,
)


def make_rec(msg: str) -> LogLine:
    return LogLine(
        timestamp=datetime(2026, 5, 22, 12, 0, 0, tzinfo=timezone.utc),
        level="ERROR",
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


CONFIG_MISSING = "ERR machine tunnel, tunnel config file doesn't exist"
CONFIG_UNREADABLE = "Failed to read the machine tunnel config data"
CREDPROV_FAIL = "Failed to disable credential provider"


def main() -> int:
    failed = 0
    summary = BundleSummary()

    # ---- Case 1: no relevant lines -> no finding ----
    d = ZpaMachineTunnelConfigMissingDetector()
    for _ in range(50):
        d.feed(make_rec("DBG Some unrelated tunnel log line"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "no relevant lines -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 2: config-missing only (no credprov) -> INFO ----
    d = ZpaMachineTunnelConfigMissingDetector()
    for _ in range(3):
        d.feed(make_rec(CONFIG_MISSING), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "config-missing only -> INFO",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_MACHINE_TUNNEL_CONFIG_MISSING"}, Severity.INFO),
    ):
        failed += 1

    # ---- Case 3: config-unreadable only (no credprov) -> INFO ----
    d = ZpaMachineTunnelConfigMissingDetector()
    for _ in range(3):
        d.feed(make_rec(CONFIG_UNREADABLE), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "config-unreadable only -> INFO",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_MACHINE_TUNNEL_CONFIG_MISSING"}, Severity.INFO),
    ):
        failed += 1

    # ---- Case 4: credential-provider failure -> WARNING ----
    d = ZpaMachineTunnelConfigMissingDetector()
    d.feed(make_rec(CONFIG_MISSING), summary)
    d.feed(make_rec(CREDPROV_FAIL), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "credprov-fail present -> WARNING",
        (
            {f.code for f in findings},
            findings[0].severity if findings else None,
        ),
        ({"ZPA_MACHINE_TUNNEL_CONFIG_MISSING"}, Severity.WARNING),
    ):
        failed += 1

    # ---- Case 5: counts are accurate in description ----
    d = ZpaMachineTunnelConfigMissingDetector()
    for _ in range(7):
        d.feed(make_rec(CONFIG_MISSING), summary)
    for _ in range(2):
        d.feed(make_rec(CONFIG_UNREADABLE), summary)
    for _ in range(3):
        d.feed(make_rec(CREDPROV_FAIL), summary)
    findings = d.finalize(summary)
    if findings:
        desc = findings[0].description
        ok = "7" in desc and "2" in desc and "3" in desc
        if not assert_eq(
            "counts (7/2/3) all present in description",
            ok, True,
        ):
            failed += 1

    # ---- Case 6: case-insensitive matching ----
    d = ZpaMachineTunnelConfigMissingDetector()
    d.feed(make_rec("err MACHINE TUNNEL tunnel config file doesn't exist"),
           summary)
    d.feed(make_rec("failed to DISABLE credential PROVIDER"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "case-insensitive matching",
        {f.code for f in findings},
        {"ZPA_MACHINE_TUNNEL_CONFIG_MISSING"},
    ):
        failed += 1

    # ---- Case 7: similar-but-different phrasings DON'T false-positive ----
    d = ZpaMachineTunnelConfigMissingDetector()
    d.feed(make_rec("Machine tunnel: config loaded successfully"), summary)
    d.feed(make_rec("Read machine tunnel data: 1024 bytes"), summary)
    d.feed(make_rec("Disabled credential provider as requested"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "near-miss phrasings do not fire",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 8: applies_to_os gate is windows-only ----
    if ZpaMachineTunnelConfigMissingDetector.applies_to_os != ("windows",):
        print(
            "  FAIL  applies_to_os should be ('windows',) but is "
            f"{ZpaMachineTunnelConfigMissingDetector.applies_to_os!r}"
        )
        failed += 1
    else:
        print("  OK    applies_to_os = ('windows',)")

    print()
    if failed:
        print(f"FAILED ({failed} test case(s))")
        return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
