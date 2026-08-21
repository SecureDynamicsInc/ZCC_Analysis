"""
Synthetic-data test for the hostfile_interference detector.

Run:  python test_hostfile_interference.py
"""

from __future__ import annotations

import sys

from zcc_diag.summary import BundleSummary
from zcc_diag.issues.hostfile_interference import (
    HostFileInterferenceDetector,
)


def assert_eq(label, got, want):
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def mk_summary(*entries):
    s = BundleSummary()
    s.hosts_file_entries = [
        {"ip": ip, "hostname": host} for ip, host in entries
    ]
    return s


def main() -> int:
    failed = 0

    # ---- Case 1: Example Tenant L-style private override -> CRIT ----
    s = mk_summary(
        ("127.0.0.1", "localhost"),  # boilerplate, should not fire
        ("10.20.30.40", "portal.example.local"),  # synthetic conflict
    )
    d = HostFileInterferenceDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "private-IP internal override fires HOSTFILE_PRIVATE_OVERRIDE",
        {f.code for f in findings},
        {"HOSTFILE_PRIVATE_OVERRIDE"},
    ):
        failed += 1

    # ---- Case 2: public IP mapped to internal-looking host -> WARN ----
    s = mk_summary(
        ("203.0.113.42", "intranet.corp-m.example"),
    )
    d = HostFileInterferenceDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "public-IP internal override fires HOSTFILE_PUBLIC_OVERRIDE",
        {f.code for f in findings},
        {"HOSTFILE_PUBLIC_OVERRIDE"},
    ):
        failed += 1

    # ---- Case 3: ONLY default Windows hosts boilerplate -> no findings ----
    s = mk_summary(
        ("127.0.0.1", "localhost"),
        ("::1", "ip6-localhost"),
        ("::1", "ip6-loopback"),
    )
    d = HostFileInterferenceDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "default hosts boilerplate -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 4: empty / unset hosts_file_entries -> no findings ----
    s = BundleSummary()
    d = HostFileInterferenceDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "unset hosts -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 5: multiple private overrides collapse to ONE finding ----
    s = mk_summary(
        ("10.1.1.1", "app1.corp"),
        ("10.1.1.2", "app2.corp"),
        ("10.1.1.3", "app3.corp"),
    )
    d = HostFileInterferenceDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "3 private overrides -> 1 HOSTFILE_PRIVATE_OVERRIDE finding",
        {f.code for f in findings},
        {"HOSTFILE_PRIVATE_OVERRIDE"},
    ):
        failed += 1
    if findings and "3" not in findings[0].title:
        print(f"  FAIL  title should mention count 3: {findings[0].title!r}")
        failed += 1
    elif findings:
        print(f"  OK    title mentions count: {findings[0].title}")

    # ---- Case 6: single-label internal hostname -> CRIT ----
    s = mk_summary(
        ("10.0.0.1", "fileserver"),
    )
    d = HostFileInterferenceDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "single-label hostname fires HOSTFILE_PRIVATE_OVERRIDE",
        {f.code for f in findings},
        {"HOSTFILE_PRIVATE_OVERRIDE"},
    ):
        failed += 1

    # ---- Case 7: mix of CRIT + WARN findings ----
    s = mk_summary(
        ("127.0.0.1", "localhost"),
        ("10.0.0.1", "internal-app.local"),
        ("203.0.113.99", "public-intranet.corp"),
    )
    d = HostFileInterferenceDetector()
    findings = d.finalize(s)
    if not assert_eq(
        "mixed-class entries fire both findings",
        {f.code for f in findings},
        {"HOSTFILE_PRIVATE_OVERRIDE", "HOSTFILE_PUBLIC_OVERRIDE"},
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
