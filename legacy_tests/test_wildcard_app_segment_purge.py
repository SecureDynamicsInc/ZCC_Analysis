"""
Synthetic-data test for the wildcard_app_segment_purge detector.

Rewritten 2026-05-19 to exercise the cache-size signal design.
The old design walked summary.forwarding_profile for wildcard
literals and asserted on WILDCARD_IN_DESTINATION / WILDCARD_IN_PROFILE
codes -- those codes were retired and the detector now uses
``len(summary.bypass_cache)`` as the policy-permissiveness signal.

Run:  python test_wildcard_app_segment_purge.py
"""

from __future__ import annotations

import sys

from zcc_diag.summary import BundleSummary
from zcc_diag.issues.wildcard_app_segment_purge import (
    WildcardAppSegmentPurgeDetector,
)


def assert_eq(label, got, want):
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def with_cache(*hosts):
    s = BundleSummary()
    s.bypass_cache = list(hosts)
    return s


def main() -> int:
    failed = 0

    # ---- Case 1: empty cache -> no finding ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache())
    if not assert_eq(
        "empty cache -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 2: 50 hosts (healthy Example Tenant C scale) -> no finding ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"host{i}.example.com" for i in range(50)]))
    if not assert_eq(
        "50 hosts (healthy enterprise scale) -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 3: 200 hosts (top of healthy range) -> no finding ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"host{i}.example.com" for i in range(200)]))
    if not assert_eq(
        "200 hosts (top of healthy range) -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 4: 300 hosts (INFO threshold) -> BYPASS_CACHE_LARGE ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"h{i}.example.com" for i in range(300)]))
    if not assert_eq(
        "300 hosts fires BYPASS_CACHE_LARGE (INFO)",
        {f.code for f in findings},
        {"BYPASS_CACHE_LARGE"},
    ):
        failed += 1

    # ---- Case 5: 500 hosts (mid INFO range) -> BYPASS_CACHE_LARGE ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"h{i}.example.com" for i in range(500)]))
    if not assert_eq(
        "500 hosts still INFO (below WARN threshold)",
        {f.code for f in findings},
        {"BYPASS_CACHE_LARGE"},
    ):
        failed += 1

    # ---- Case 6: 1000 hosts (WARN threshold) -> BYPASS_CACHE_VERY_LARGE ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"h{i}.example.com" for i in range(1000)]))
    if not assert_eq(
        "1000 hosts fires BYPASS_CACHE_VERY_LARGE (WARN)",
        {f.code for f in findings},
        {"BYPASS_CACHE_VERY_LARGE"},
    ):
        failed += 1

    # ---- Case 7: 5000 hosts (Example Tenant D-scale) -> BYPASS_CACHE_VERY_LARGE ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"h{i}.example.com" for i in range(5000)]))
    if not assert_eq(
        "5000 hosts fires BYPASS_CACHE_VERY_LARGE",
        {f.code for f in findings},
        {"BYPASS_CACHE_VERY_LARGE"},
    ):
        failed += 1
    if findings and "5000" not in findings[0].title:
        print(f"  FAIL  title should mention 5000: {findings[0].title!r}")
        failed += 1

    # ---- Case 8: at-the-edge boundaries ----
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"h{i}.example.com" for i in range(299)]))
    if not assert_eq(
        "299 hosts (one below INFO threshold) -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*[f"h{i}.example.com" for i in range(999)]))
    if not assert_eq(
        "999 hosts (one below WARN threshold) -> still INFO",
        {f.code for f in findings},
        {"BYPASS_CACHE_LARGE"},
    ):
        failed += 1

    # ---- Case 9: sample text shows in description (first few hosts) ----
    hosts = [f"app{i}.example.com" for i in range(2000)]
    d = WildcardAppSegmentPurgeDetector()
    findings = d.finalize(with_cache(*hosts))
    if findings:
        desc = findings[0].description
        if "app0.example.com" not in desc:
            print(f"  FAIL  description should sample app0.example.com:")
            print(f"        {desc[:300]}")
            failed += 1
        else:
            print("  OK    description includes sample of bypass cache")
    else:
        print("  FAIL  expected a finding for 2000-host cache")
        failed += 1

    print()
    if failed:
        print(f"FAILED ({failed} test case(s))")
        return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
