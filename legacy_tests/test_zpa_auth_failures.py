"""
Consolidated test for the ZPA auth-failures detector
(``zcc_diag.issues.zpa_auth_failures.ZPAAuthFailuresDetector``).

Combines two previously-separate test files:

  * **42xxx PA-error code parsing** (former ``test_pa_codes.py``).
    Exercises the private ``_detect_pa_error_codes`` helper which
    matches both anchored shapes (``[42016]``, ``error 42016``) and
    phrase-trigger shapes (the documentation's "Error Message" text plus a bare
    code). Plus a false-positive guard: bare 42xxx integers without
    anchors and without phrase context must NOT fire (would mis-flag
    byte counts and thread IDs). Plus 42016-specific IdP timestamp /
    accepted-range extraction.

  * **v6 detector extensions** (former ``test_zpa_auth_extensions.py``).
    Detector-level tests for the BRK_MT_SETUP_FAIL family
    (NO_POLICY_FOUND, REJECTED_BY_POLICY, SAML_EXPIRED,
    WEBPROBE_HTTPS_DISABLED, and the catch-all generic bucket) plus
    ZPN_STATUS_<X> auth-state transition normalisation.

Run:  python test_zpa_auth_failures.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues import Severity
from zcc_diag.issues.zpa_auth_failures import (
    ZPAAuthFailuresDetector,
    _detect_pa_error_codes,
    _RE_42016_DETAIL,
)


# -- shared helpers -------------------------------------------------------

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


# -- Section 1: 42xxx PA-error code parsing ------------------------------

_PA_CASES = [
    # (label, message, expected_codes_set)
    (
        "anchored bracket [42016]",
        "SAML validation failed: [42016] response issue time out of range",
        {"42016"},
    ),
    (
        "anchored 'error 42016'",
        "Authentication error 42016 occurred during enrollment",
        {"42016"},
    ),
    (
        "anchored 'code: 42029'",
        "PA enroll failed; code: 42029 reported by service",
        {"42029"},
    ),
    (
        "phrase + bare code (42022 missing NameID)",
        "Missing NameID in the SAML response (error 42022)",
        {"42022"},
    ),
    (
        "phrase 'Inconsistency in user credentials' + 42000",
        "Inconsistency in user credentials is detected (42000)",
        {"42000"},
    ),
    (
        "phrase only — bare integer present elsewhere is unrelated",
        "Inconsistency in user credentials is detected, retry id=42000",
        {"42000"},
    ),
    (
        "bare 42500 (out of table) — nothing fires",
        "Wrote 42500 bytes to socket buffer",
        set(),
    ),
    (
        "bare 42016 with no anchor and no phrase — nothing fires",
        "tid=42016 sent heartbeat",
        set(),
    ),
    (
        "two codes in one line",
        "[42016] and (42029) both reported",
        {"42016", "42029"},
    ),
]


def section_pa_codes() -> int:
    print("=== 42xxx PA-error code parsing ===")
    failures = 0
    for label, msg, expected in _PA_CASES:
        got = {code for code, _g, _a in _detect_pa_error_codes(msg)}
        if not assert_eq(label, got, expected):
            failures += 1

    # 42016 detail extraction
    sample = (
        "[42016] The response issue time is either too old or with date "
        "in the future. IdP Issue Time: 2026-05-06T10:15:00Z "
        "Accepted Range: 2026-05-06T10:13:00Z to 2026-05-06T10:17:00Z"
    )
    m = _RE_42016_DETAIL.search(sample)
    if m and "10:15:00Z" in m.group("idp_ts") and "10:13:00Z" in m.group("accept_from"):
        print("  OK    42016 detail extraction")
    else:
        print(f"  FAIL  42016 detail extraction: m={m}")
        failures += 1

    print()
    return failures


# -- Section 2: v6 detector extensions -----------------------------------

def section_v6_extensions() -> int:
    print("=== v6 detector extensions (BRK_MT_* + ZPN_STATUS_*) ===")
    failed = 0
    summary = BundleSummary()

    # Case 1: BRK_MT_SETUP_FAIL_NO_POLICY_FOUND -> CRITICAL
    d = ZPAAuthFailuresDetector()
    for _ in range(5):
        d.feed(make_rec(
            'BRK_MT_SETUP_FAIL_NO_POLICY_FOUND for tag_id=119'
        ), summary)
    findings = d.finalize(summary)
    codes = {f.code: f.severity for f in findings}
    if not assert_eq(
        "NO_POLICY_FOUND -> BRK_MT_NO_POLICY_FOUND CRITICAL",
        codes.get("BRK_MT_NO_POLICY_FOUND"),
        Severity.CRITICAL,
    ):
        failed += 1

    # Case 2: BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY -> CRITICAL
    d = ZPAAuthFailuresDetector()
    d.feed(make_rec(
        'BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY for tag_id=42'
    ), summary)
    findings = d.finalize(summary)
    codes = {f.code: f.severity for f in findings}
    if not assert_eq(
        "REJECTED_BY_POLICY -> BRK_MT_REJECTED_BY_POLICY CRITICAL",
        codes.get("BRK_MT_REJECTED_BY_POLICY"),
        Severity.CRITICAL,
    ):
        failed += 1

    # Case 3: real-bundle volume (example-tenant-c: 420 NO_POLICY)
    d = ZPAAuthFailuresDetector()
    for _ in range(420):
        d.feed(make_rec(
            'BRK_MT_SETUP_FAIL_NO_POLICY_FOUND for tag_id=119'
        ), summary)
    findings = d.finalize(summary)
    bkt = next(
        (f for f in findings if f.code == "BRK_MT_NO_POLICY_FOUND"),
        None,
    )
    if bkt is None or bkt.count != 420:
        print(f"  FAIL  expected count=420, got {bkt.count if bkt else None}")
        failed += 1
    else:
        print("  OK    420 hits accumulated in single bucket")

    # Case 4: SAML_EXPIRED routes to SAML_EXPIRED_BROKER at WARNING.
    #
    # CORRECTED 2026-06-12: BRK_MT_SETUP_FAIL_SAML_EXPIRED is the
    # documented "Timeout policy blocked access" Policy Block code per
    # the authentic Zscaler documentation "Understanding Private Access Session
    # Status Codes". It is NOT a SAML cert / clock-skew failure — it's
    # the tenant's configured Timeout Policy requiring re-auth.
    # Severity dropped from CRITICAL to WARNING accordingly.
    d = ZPAAuthFailuresDetector()
    d.feed(make_rec('BRK_MT_SETUP_FAIL_SAML_EXPIRED reason: token expired'),
           summary)
    findings = d.finalize(summary)
    codes = {f.code: f.severity for f in findings}
    if not assert_eq(
        "SAML_EXPIRED routes to SAML_EXPIRED_BROKER at WARNING",
        codes.get("SAML_EXPIRED_BROKER"),
        Severity.WARNING,
    ):
        failed += 1

    # Case 5: WEBPROBE_HTTPS_DISABLED still works (regression guard)
    d = ZPAAuthFailuresDetector()
    d.feed(make_rec(
        'BRK_MT_SETUP_FAIL_WEBPROBE_HTTPS_DISABLED some context'
    ), summary)
    findings = d.finalize(summary)
    codes = {f.code for f in findings}
    if not assert_eq(
        "WEBPROBE_HTTPS_DISABLED still routes correctly",
        "WEBPROBE_HTTPS_DISABLED" in codes,
        True,
    ):
        failed += 1

    # Case 6: unknown reason still routes to generic bucket
    d = ZPAAuthFailuresDetector()
    d.feed(make_rec(
        'BRK_MT_SETUP_FAIL_FOOBAR_QUUX something unknown'
    ), summary)
    findings = d.finalize(summary)
    codes = {f.code for f in findings}
    if not assert_eq(
        "unknown reason -> generic BRK_MT_SETUP_FAIL_<reason> bucket",
        "BRK_MT_SETUP_FAIL_FOOBAR_QUUX" in codes,
        True,
    ):
        failed += 1

    # Case 7: ZPN_STATUS_AUTHENTICATED -> ZPN_STATUS_DISCONNECTED transition
    d = ZPAAuthFailuresDetector()
    d.feed(make_rec("ZPN_STATUS_AUTHENTICATED reported"), summary)
    d.feed(make_rec("ZPN_STATUS_DISCONNECTED reported"), summary)
    d.feed(make_rec("ZPN_STATUS_AUTHENTICATED reported"), summary)
    findings = d.finalize(summary)
    codes = {f.code for f in findings}
    if not assert_eq(
        "ZPN_STATUS_<X> transitions fire AUTH_STATE_FLAPPED",
        "AUTH_STATE_FLAPPED" in codes,
        True,
    ):
        failed += 1

    # Case 8: mixed legacy/modern phrasing stays continuous
    d = ZPAAuthFailuresDetector()
    d.feed(make_rec("getZpnAuthState: AUTHENTICATED"), summary)
    d.feed(make_rec("ZPN_STATUS_AUTHENTICATED reported"), summary)
    findings = d.finalize(summary)
    codes = {f.code for f in findings}
    if not assert_eq(
        "legacy + modern phrasing of same state -> no spurious transition",
        "AUTH_STATE_FLAPPED" in codes,
        False,
    ):
        failed += 1

    print()
    return failed


def main() -> int:
    failed = section_pa_codes() + section_v6_extensions()
    if failed:
        print(f"FAILED ({failed} case(s))")
        return 1
    print("all ZPA auth-failure cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
