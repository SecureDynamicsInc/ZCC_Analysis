"""
Synthetic-data test for the zcc_client_version_drift detector.

Run:  python test_zcc_client_version_drift.py
"""

from __future__ import annotations

import sys

from zcc_diag.summary import BundleSummary, VersionInfo
from zcc_diag.issues.zcc_client_version_drift import (
    ZccClientVersionDriftDetector,
)


def assert_eq(label, got, want):
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def mk_summary(**components):
    s = BundleSummary()
    s.versions = VersionInfo(components=dict(components))
    return s


def main() -> int:
    failed = 0

    # ---- Case 1: matching the baseline -> no findings ----
    # Updated 2026-05-19: defect-fix #50 bumped _BASELINE_GA from
    # 4.7.0.202 -> 4.8.0.156 (the current observed GA in Example Tenant C
    # bundles). Test must track the detector's baseline.
    s = mk_summary(ZSATunnel="4.8.0.156")
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "current GA -> no finding",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 1b: newer than baseline -> silent (forward-compat) ----
    # The fix in defect #50 makes "newer than baseline" silently
    # return 0 builds-behind so we don't false-positive when Zscaler
    # ships a new GA before we bump _BASELINE_GA.
    s = mk_summary(ZSATunnel="4.8.0.200")
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "newer than baseline -> silent (forward-compat)",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 2: 30 builds behind -> WARN ----
    s = mk_summary(ZSATunnel="4.8.0.126")  # 30 builds behind 4.8.0.156
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "30 builds behind fires ZCC_VERSION_BEHIND (WARN)",
        {f.code for f in findings},
        {"ZCC_VERSION_BEHIND"},
    ):
        failed += 1

    # ---- Case 3: 100 builds behind -> CRIT (WestStar case) ----
    s = mk_summary(ZSATunnel="4.7.0.141")  # WestStar's TimG
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "100 builds behind fires ZCC_VERSION_FAR_BEHIND (CRIT)",
        {f.code for f in findings},
        {"ZCC_VERSION_FAR_BEHIND"},
    ):
        failed += 1

    # ---- Case 4: a really old minor (4.6.x) -> CRIT ----
    s = mk_summary(ZSATunnel="4.6.0.168")
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "older minor version fires ZCC_VERSION_FAR_BEHIND",
        {f.code for f in findings},
        {"ZCC_VERSION_FAR_BEHIND"},
    ):
        failed += 1

    # ---- Case 5: only the macOS ZCC plist key populated -> still works ----
    s = mk_summary(ZCC="4.7.0.141")
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "macOS ZCC plist key triggers detection",
        {f.code for f in findings},
        {"ZCC_VERSION_FAR_BEHIND"},
    ):
        failed += 1

    # ---- Case 6: empty version components -> no findings ----
    s = mk_summary()
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "empty components -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 7: malformed version string -> no findings ----
    s = mk_summary(ZSATunnel="unknown")
    d = ZccClientVersionDriftDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "malformed version string -> no findings",
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
