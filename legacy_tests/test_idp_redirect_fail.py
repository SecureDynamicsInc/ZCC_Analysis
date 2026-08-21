"""
Synthetic-data test for the idp_redirect_fail detector.

Run:  python test_idp_redirect_fail.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.idp_redirect_fail import IdpRedirectFailDetector


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

    # ---- Case 1: Example Tenant N AWS VPN -> Entra ID redirect breaks ----
    d = IdpRedirectFailDetector()
    # Order matters: VPN gateway first, then IdP, then cert error.
    d.feed(make_rec("ID=1, Host=client.vpn-endpoint-12345.amazonaws.com:443"), summary)
    d.feed(make_rec("ID=1, Host=login.microsoftonline.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "AWS VPN -> Entra fires IDP_REDIRECT_FAIL_VPN__login.microsoftonline.com",
        {f.code for f in findings},
        {"IDP_REDIRECT_FAIL_VPN__login.microsoftonline.com"},
    ):
        failed += 1

    # ---- Case 2: Cisco AnyConnect -> Okta tenant ----
    d = IdpRedirectFailDetector()
    d.feed(make_rec("ID=2, Host=anyconnect.example.com:443"), summary)
    d.feed(make_rec("ID=2, Host=acme.okta.com:443"), summary)
    d.feed(make_rec("SSL handshake failure"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "AnyConnect + Okta fires IDP_REDIRECT_FAIL_VPN__okta.com",
        {f.code for f in findings},
        {"IDP_REDIRECT_FAIL_VPN__okta.com"},
    ):
        failed += 1

    # ---- Case 3: IdP cert error without VPN context -> WARN ----
    d = IdpRedirectFailDetector()
    d.feed(make_rec("ID=3, Host=login.microsoftonline.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "IdP without VPN context fires IDP_REDIRECT_FAIL__login.microsoftonline.com",
        {f.code for f in findings},
        {"IDP_REDIRECT_FAIL__login.microsoftonline.com"},
    ):
        failed += 1

    # ---- Case 4: non-IdP host cert error -> no finding ----
    d = IdpRedirectFailDetector()
    d.feed(make_rec("ID=4, Host=intranet.example.com:443"), summary)
    d.feed(make_rec("SSL handshake failure"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "non-IdP host -> no finding from this detector",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 5: cross-thread isolation ----
    d = IdpRedirectFailDetector()
    d.feed(make_rec("ID=5, Host=vpn.cisco.com:443",
                    pid=1, tid=10), summary)
    d.feed(make_rec("ID=6, Host=login.microsoftonline.com:443",
                    pid=2, tid=20), summary)
    d.feed(make_rec("SSL handshake failure", pid=2, tid=20), summary)
    findings = d.finalize(summary)
    # Cross-thread: IdP failure fires WARN (no VPN context on its
    # thread), not CRIT.
    if not assert_eq(
        "cross-thread VPN doesn't attribute to IdP error elsewhere (WARN, not CRIT)",
        {f.code for f in findings},
        {"IDP_REDIRECT_FAIL__login.microsoftonline.com"},
    ):
        failed += 1

    # ---- Case 6: GlobalProtect + Duo ----
    d = IdpRedirectFailDetector()
    d.feed(make_rec("ID=7, Host=portal.globalprotect.com:443"), summary)
    d.feed(make_rec("ID=7, Host=api-1234.duosecurity.com:443"), summary)
    d.feed(make_rec(
        "TLS handshake failed: certificate verify failed"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "GlobalProtect + Duo fires IDP_REDIRECT_FAIL_VPN__duosecurity.com",
        {f.code for f in findings},
        {"IDP_REDIRECT_FAIL_VPN__duosecurity.com"},
    ):
        failed += 1

    # ---- Case 7: Pulse Secure + Auth0 ----
    d = IdpRedirectFailDetector()
    d.feed(make_rec("ID=8, Host=vpn.pulsesecure.net:443"), summary)
    d.feed(make_rec("ID=8, Host=corp.auth0.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "Pulse Secure + Auth0 fires IDP_REDIRECT_FAIL_VPN__auth0.com",
        {f.code for f in findings},
        {"IDP_REDIRECT_FAIL_VPN__auth0.com"},
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
