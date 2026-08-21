"""
Synthetic-data test for the bypass_misconfiguration detector.

Rewritten 2026-05-19 to exercise the new bypass_cache-driven design.
The old design walked ``summary.forwarding_profile`` and asserted on
``BYPASS_FORMAT_DOT_VS_STAR`` — that finding code was retired and
the detector now cross-references cert errors against
``summary.bypass_cache`` instead.

Cases exercised:
  1. Cert-pinning gateway absent from bypass cache -> GATEWAY_NOT_IN_BYPASS (CRIT)
  2. Cert error against an unknown host not in bypass cache -> CERT_ERROR_HOST_NOT_BYPASSED (WARN)
  3. Cert error against a host THAT IS in bypass cache -> no finding (cause is elsewhere)
  4. Cert error with no host context -> CERT_ERROR_UNATTRIBUTED (WARN)
  5. Cert errors observed but bypass_cache is empty -> BYPASS_CACHE_EMPTY (INFO)
  6. Healthy bundle (no cert errors) -> no finding
  7. Two distinct gateways in the same bundle -> two GATEWAY_NOT_IN_BYPASS buckets

Run:  python test_bypass_misconfiguration.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.bypass_misconfiguration import BypassMisconfigurationDetector


def make_rec(msg: str, pid: int = 1000, tid: int = 2000) -> LogLine:
    return LogLine(
        timestamp=datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
        level="ERROR",
        pid=pid,
        tid=tid,
        message=msg,
        source_path=Path("ZSATunnel_2026-05-19-12-00-00.log"),
        raw=msg,
        line_no=1,
    )


def assert_eq(label: str, got, want) -> bool:
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def main() -> int:
    failed = 0

    # ---- Case 1: pinned gateway absent from bypass cache -> CRIT ----
    summary = BundleSummary()
    summary.bypass_cache = ["other.example.com", "mobile.zscaler.net"]
    d = BypassMisconfigurationDetector()
    d.feed(make_rec(
        "ID=42, Host=agent.jumpcloud.com:443, request initiated"
    ), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate from "
        "agent.jumpcloud.com"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "pinned gateway absent fires GATEWAY_NOT_IN_BYPASS",
        {f.code for f in findings},
        {"GATEWAY_NOT_IN_BYPASS"},
    ):
        failed += 1

    # ---- Case 2: cert error against an unknown host -> WARN ----
    summary = BundleSummary()
    summary.bypass_cache = ["foo.com", "bar.com"]
    d = BypassMisconfigurationDetector()
    d.feed(make_rec("ID=7, Host=randomsaas.example.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "unknown host fires CERT_ERROR_HOST_NOT_BYPASSED",
        {f.code for f in findings},
        {"CERT_ERROR_HOST_NOT_BYPASSED"},
    ):
        failed += 1

    # ---- Case 3: cert error against a host already in bypass cache -> no finding ----
    summary = BundleSummary()
    summary.bypass_cache = ["app.example.com"]
    d = BypassMisconfigurationDetector()
    d.feed(make_rec("ID=11, Host=app.example.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "host already bypassed -> no finding (cause is elsewhere)",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 4: cert error with no host context -> WARN unattributed ----
    summary = BundleSummary()
    summary.bypass_cache = ["whatever.com"]
    d = BypassMisconfigurationDetector()
    # No preceding Host=...; just a bare cert error
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "cert error with no host context fires CERT_ERROR_UNATTRIBUTED",
        {f.code for f in findings},
        {"CERT_ERROR_UNATTRIBUTED"},
    ):
        failed += 1

    # ---- Case 5: cert errors with EMPTY bypass cache -> INFO ----
    summary = BundleSummary()
    summary.bypass_cache = []  # cache empty (e.g. auth-failing bundle)
    d = BypassMisconfigurationDetector()
    d.feed(make_rec("ID=99, Host=agent.jumpcloud.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "cert errors + empty cache fires BYPASS_CACHE_EMPTY (only)",
        {f.code for f in findings},
        {"BYPASS_CACHE_EMPTY"},
    ):
        failed += 1

    # ---- Case 6: healthy bundle (no cert errors) -> no findings ----
    summary = BundleSummary()
    summary.bypass_cache = ["foo.example.com", "bar.com"]
    d = BypassMisconfigurationDetector()
    d.feed(make_rec("ID=1, Host=foo.example.com:443"), summary)
    d.feed(make_rec("ID=1, status=connected"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "healthy bundle (no cert errors) -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 7: two distinct gateways absent -> single bucket per code, but evidence accumulates ----
    summary = BundleSummary()
    summary.bypass_cache = ["foo.example.com"]
    d = BypassMisconfigurationDetector()
    d.feed(make_rec(
        "ID=10, Host=agent.jumpcloud.com:443", pid=1, tid=1,
    ), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate",
        pid=1, tid=1,
    ), summary)
    d.feed(make_rec(
        "ID=11, Host=login.microsoftonline.com:443", pid=2, tid=2,
    ), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate",
        pid=2, tid=2,
    ), summary)
    findings = d.finalize(summary)
    # Both gateways are pinned -> single bucket (the bucket key is the
    # finding code, not the host).
    if not assert_eq(
        "two pinned gateways collapse to single GATEWAY_NOT_IN_BYPASS",
        {f.code for f in findings},
        {"GATEWAY_NOT_IN_BYPASS"},
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
