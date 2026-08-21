"""
Consolidated test for the ZIA auth-failures detector
(``zcc_diag.issues.zia_auth_failures.ZIAAuthFailuresDetector``).

Combines two previously-separate test files into one:

  * **Mac tray-log Mobile API path** (former ``test_mac_zia.py``).
    Plants the ``Auth::Lib::executeMobileAdminPostAPI`` line shapes
    that appear in macOS ZSATray logs and verifies that HTTP failure
    responses (401 / 403 / 407 / 5xx) attribute correctly per-thread
    to the in-flight URL. Mac development bundles available so far
    have all been healthy on auth, so coverage relies on synthetic
    data.

  * **OneID / OIDC signatures** (former ``test_zia_auth_oneid.py``).
    Grounded in a synthetic reference bundle which exhibited
    ``One::ID::Device <ZIA|ZPA> registration fail with error: -<N>``
    plus ``One::ID::ZS_Keep_Alive_Req http status code 401, content:
    INVALID TOKEN``. Verifies each signature fires its own bucket,
    that supplementary informational lines don't double-fire, and
    that error-code variants are distinct.

Run:  python test_zia_auth_failures.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.zia_auth_failures import ZIAAuthFailuresDetector


# -- shared helpers -------------------------------------------------------

def make_tray_rec(level: str, msg: str, pid: int = 28751,
                  tid: int = 11259134) -> LogLine:
    """Synthetic ZSATray-format LogLine (for the Mac Mobile API tests)."""
    return LogLine(
        timestamp=datetime(2026, 5, 11, 21, 4, 26, tzinfo=timezone.utc),
        level=level,
        pid=pid,
        tid=tid,
        message=msg,
        source_path=Path("ZSATray_2026-05-11-21-04-26.140615.log"),
        raw=f"2026-05-11 21:04:26(-0500)[{pid}:{tid}] {level} {msg}",
        line_no=1,
    )


def make_tunnel_rec(msg: str, level: str = "ERROR", pid: int = 2028,
                    tid: int = 15172) -> LogLine:
    """Synthetic ZSATunnel-format LogLine (for the OneID tests)."""
    return LogLine(
        timestamp=datetime(2026, 5, 14, 21, 53, 8, tzinfo=timezone.utc),
        level=level,
        pid=pid,
        tid=tid,
        message=msg,
        source_path=Path("ZSATunnel_2026-05-14-21-53-44.250836.log"),
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


# -- Section 1: Mac tray-log Mobile API path -----------------------------

def section_mac_tray() -> int:
    print("=== Mac tray-log Mobile API path ===")
    failed = 0
    summary = BundleSummary()

    # Case 1: healthy API call sequence (200 response). No finding.
    d = ZIAAuthFailuresDetector()
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Begin"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Trial: 0"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: https://mobile.zscalerthree.net/api/mobile/policy/forceKeepAlive"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Response: 200, Length: 772"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Finish"), summary)
    findings = d.finalize(summary)
    if not assert_eq("healthy 200 sequence: no finding",
                     {f.code for f in findings}, set()):
        failed += 1

    # Case 2: 401 failure on keepAlive
    d = ZIAAuthFailuresDetector()
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Begin"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: https://mobile.zscalerthree.net/api/mobile/policy/forceKeepAlive"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Response: 401, Length: 0"), summary)
    findings = d.finalize(summary)
    if not assert_eq("401 failure fires MAC_MOBILE_API_HTTP_401",
                     {f.code for f in findings}, {"MAC_MOBILE_API_HTTP_401"}):
        failed += 1

    # Case 3: 407 upstream proxy auth required
    d = ZIAAuthFailuresDetector()
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: https://mobile.zscalerthree.net/api/mobile/policy/v2/forcePolicyDownload"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Response: 407, Length: 142"), summary)
    findings = d.finalize(summary)
    if not assert_eq("407 fires MAC_MOBILE_API_HTTP_407",
                     {f.code for f in findings}, {"MAC_MOBILE_API_HTTP_407"}):
        failed += 1

    # Case 4: 5xx ZIA backend failure
    d = ZIAAuthFailuresDetector()
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: https://mobile.zscalerthree.net/api/mobile/device/updateServices"), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Response: 503, Length: 0"), summary)
    findings = d.finalize(summary)
    if not assert_eq("503 fires MAC_MOBILE_API_HTTP_503",
                     {f.code for f in findings}, {"MAC_MOBILE_API_HTTP_503"}):
        failed += 1

    # Case 5: per-thread URL tracking. Two concurrent threads with different
    # in-flight URLs; one fails, one succeeds. The failure must be attributed
    # to its OWN URL, not the other thread's.
    d = ZIAAuthFailuresDetector()
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: https://mobile.zscalerthree.net/api/mobile/policy/forceKeepAlive", pid=1, tid=100), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: https://mobile.zscalerthree.net/api/mobile/policy/v2/forcePolicyDownload", pid=1, tid=200), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Response: 200, Length: 12", pid=1, tid=100), summary)
    d.feed_tray(make_tray_rec("INFO", "Auth::Lib::executeMobileAdminPostAPI: Response: 403, Length: 0", pid=1, tid=200), summary)
    findings = d.finalize(summary)
    if not assert_eq("per-thread tracking: only the 403 thread fires",
                     {f.code for f in findings}, {"MAC_MOBILE_API_HTTP_403"}):
        failed += 1
    if findings:
        desc = findings[0].description
        if "forcePolicyDownload" not in desc:
            print(f"  FAIL  per-thread URL attribution — description didn't mention forcePolicyDownload")
            failed += 1
        else:
            print(f"  OK    per-thread URL attribution mentions the right endpoint")

    # Case 6: unrelated noise — no finding
    d = ZIAAuthFailuresDetector()
    d.feed_tray(make_tray_rec("INFO", "Tray is an agent"), summary)
    d.feed_tray(make_tray_rec("INFO", "ZSHTTPSession firstly connecting to 1.2.3.4:443"), summary)
    findings = d.finalize(summary)
    if not assert_eq("unrelated lines: no finding",
                     {f.code for f in findings}, set()):
        failed += 1

    print()
    return failed


# -- Section 2: OneID / OIDC signatures ----------------------------------

def section_oneid() -> int:
    print("=== OneID / OIDC signatures ===")
    failed = 0
    summary = BundleSummary()

    # Case 1: ZIA device registration failure (synthetic fixture)
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "One::ID::Device ZIA registration fail with error: -9"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "ZIA registration fail fires ONEID_DEVICE_REG_FAIL_ZIA_-9",
        {f.code for f in findings},
        {"ONEID_DEVICE_REG_FAIL_ZIA_-9"},
    ):
        failed += 1

    # Case 2: ZPA device registration failure
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "One::ID::Device ZPA registration fail with error: -9"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "ZPA registration fail fires ONEID_DEVICE_REG_FAIL_ZPA_-9",
        {f.code for f in findings},
        {"ONEID_DEVICE_REG_FAIL_ZPA_-9"},
    ):
        failed += 1

    # Case 3: both ZIA and ZPA fail (synthetic reference shape)
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "One::ID::Device ZIA registration fail with error: -9"
    ), summary)
    d.feed(make_tunnel_rec(
        "One::ID::Device ZPA registration fail with error: -9"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "both products firing get separate finding codes",
        {f.code for f in findings},
        {"ONEID_DEVICE_REG_FAIL_ZIA_-9", "ONEID_DEVICE_REG_FAIL_ZPA_-9"},
    ):
        failed += 1

    # Case 4: different error code value (e.g. -12)
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "One::ID::Device ZIA registration fail with error: -12"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "different errCode produces a distinct bucket",
        {f.code for f in findings},
        {"ONEID_DEVICE_REG_FAIL_ZIA_-12"},
    ):
        failed += 1

    # Case 5: OneID keep-alive 401 INVALID TOKEN
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "One::ID::ZS_Keep_Alive_Req http status code 401, content: "
        "INVALID TOKEN, reason: Unauthorized"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "OneID keep-alive 401 fires ONEID_KEEPALIVE_401",
        {f.code for f in findings},
        {"ONEID_KEEPALIVE_401"},
    ):
        failed += 1

    # Case 6: a NON-OneID 401 should NOT fire the OneID detector
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "Generic HTTP response: 401 from some.other.endpoint"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "generic 401 (no OneID prefix) does not fire OneID detector",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # Case 7: supplementary error-context line should NOT double-fire
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "One::ID::ZS_Device_Registration_ZIA_Req failed type 3, "
        "errCode: -9, reason: App Internal Error, Please Contact "
        "Administrator."
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "ZS_Device_Registration_*_Req line alone does NOT fire (avoids double-fire)",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # Case 8: full real-bundle trio fires exactly one bucket per product
    d = ZIAAuthFailuresDetector()
    d.feed(make_tunnel_rec(
        "One::ID::ZS_Device_Registration_ZIA_Req failed type 3, "
        "errCode: -9, reason: App Internal Error, Please Contact "
        "Administrator."
    ), summary)
    d.feed(make_tunnel_rec(
        "One::ID::error on service: ZS_Device_Registration_ZIA_Req "
        "type: 3, err code: -9, error = App Internal Error, Please "
        "Contact Administrator.", level="INFO",
    ), summary)
    d.feed(make_tunnel_rec(
        "One::ID::Device ZIA registration fail with error: -9"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "real-bundle trio fires exactly one bucket",
        {f.code for f in findings},
        {"ONEID_DEVICE_REG_FAIL_ZIA_-9"},
    ):
        failed += 1
    if findings:
        title = findings[0].title
        if "ZIA" not in title or "-9" not in title:
            print(f"  FAIL  title missing product/code: {title!r}")
            failed += 1
        else:
            print(f"  OK    title reports product + errCode: {title!r}")

    print()
    return failed


def main() -> int:
    failed = section_mac_tray() + section_oneid()
    if failed:
        print(f"FAILED ({failed} case(s))")
        return 1
    print("all ZIA auth-failure cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
