"""
Synthetic-line test for the Network Error detector.

Real bundles 1, 2, 3 don't contain network-error keepalive failures
(error:-8), but they DO contain non-empty ``errorMessage`` values that
must NOT trigger the network detector (``"Invalid user/password"``,
``"No ZCC update available"``, ``"Bad Gateway"``).

Verifies:

    1. Each of the six runbook-documented categories fires its specific
       finding:
       - Host not found      -> NETERR_HOST_NOT_FOUND
       - Connection reset    -> NETERR_CONNECTION_RESET
       - No route to host    -> NETERR_NO_ROUTE
       - Network unreachable -> NETERR_NET_UNREACHABLE
       - Cert validation     -> NETERR_CERT_VALIDATION
       - SSL Exception       -> NETERR_SSL_EXCEPTION

    2. The real-bundle ``errorMessage`` values that are NOT network
       errors do NOT fire:
       - "Invalid user/password"  (auth, observed in bundle 1)
       - "No ZCC update available" (informational, bundle 2)
       - "Bad Gateway"             (update check, bundle 2)

    3. Healthy empty errorMessage and unrelated config dumps do not
       fire.

Run:  python test_network_error.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.network_error import NetworkErrorDetector


def make_record(level: str, message: str) -> LogLine:
    return LogLine(
        timestamp=datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc),
        level=level,
        pid=1,
        tid=1,
        message=message,
        source_path=Path("synthetic.log"),
        raw=f"2026-05-05 12:00:00.000(+0000)[1:1] {level} {message}",
        line_no=1,
    )


CASES = [
    # ---- positive cases: each runbook category ----
    (
        "Host not found (DNS failure)",
        "ERROR",
        'Update check failed: {"error":-8,"errorMessage":"Host not found. mobile.zscloud.net","response":"","success":"false"}',
        {"NETERR_HOST_NOT_FOUND"},
    ),
    (
        "Connection reset by peer",
        "ERROR",
        '{"error":-8,"errorMessage":"Connection reset by peer.","response":""}',
        {"NETERR_CONNECTION_RESET"},
    ),
    (
        "Net Exception. No route to host",
        "ERROR",
        '{"error":-8,"errorMessage":"Net Exception. No route to host (mobile.zscloud.net:443)"}',
        {"NETERR_NO_ROUTE"},
    ),
    (
        "Net Exception. Network is unreachable",
        "ERROR",
        '{"error":-8,"errorMessage":"Net Exception. Network is unreachable"}',
        {"NETERR_NET_UNREACHABLE"},
    ),
    (
        "Certificate validation error (SSL interception)",
        "ERROR",
        '{"error":-8,"errorMessage":"Certificate validation error. Unacceptable certificate from mobile.zscloud.net: application verification failure"}',
        {"NETERR_CERT_VALIDATION"},
    ),
    (
        "SSL Exception (certificate verify failed variant)",
        "ERROR",
        '{"error":-8,"errorMessage":"SSL Exception. error:14090086:SSL routines:ssl3_get_server_certificate:certificate verify failed"}',
        {"NETERR_SSL_EXCEPTION"},
    ),

    # ---- negative cases: REAL bundle errorMessage values that are
    # NOT network errors ----
    (
        "Bundle 1 false-positive lookalike: 'Invalid user/password' (auth)",
        "ERROR",
        '{"error":"401","errorMessage":"Invalid user/password","success":"false"}',
        set(),
    ),
    (
        "Bundle 2 false-positive lookalike: 'No ZCC update available' (info)",
        "INFO",
        '{"error":"0","errorMessage":"No ZCC update available","success":"true"}',
        set(),
    ),
    (
        "Bundle 2 false-positive lookalike: 'Bad Gateway' (update check)",
        "WARN",
        '{"error":502,"errorMessage":"Bad Gateway","response":""}',
        set(),
    ),
    (
        "Healthy empty errorMessage",
        "INFO",
        'Auth::Lib::getUserTypeV2: Finish: {"error":"0","errorMessage":"","success":"true"}',
        set(),
    ),
    (
        "Healthy TrayPolicy config dump (contains 'errorMessage' as schema field)",
        "DEBUG",
        'TrayPolicy::serialize() - trayPolicy = {"aupData":{"errorMessage":""},"error":0,"errorMessage":""}',
        set(),
    ),
    (
        "Random log line not in JSON form (negative)",
        "INFO",
        "ZSATray starting up; checking for updates...",
        set(),
    ),
    (
        "Unrelated 'Host not found' phrasing outside errorMessage (must not fire)",
        "INFO",
        "Note: Host not found is a common DNS error; here's a help link.",
        set(),  # not inside "errorMessage":"..." -> no match
    ),
    (
        "Driver Error tray string (different detector, must not fire here)",
        "ERROR",
        "Service Status updated: Driver Error",
        set(),
    ),
]


def run_one(label: str, level: str, msg: str, expected: set) -> bool:
    det = NetworkErrorDetector()
    rec = make_record(level, msg)
    summary = BundleSummary()
    det.feed_tray(rec, summary)
    findings = det.finalize(summary)
    actual = {f.code for f in findings}
    ok = actual == expected
    mark = "OK   " if ok else "FAIL "
    print(f"  {mark} {label}")
    if not ok:
        print(f"        expected: {expected}")
        print(f"        actual:   {actual}")
    return ok


def main() -> int:
    failed = 0
    for label, level, msg, expected in CASES:
        if not run_one(label, level, msg, expected):
            failed += 1
    print()
    if failed:
        print(f"{failed} FAILED out of {len(CASES)}")
        return 1
    print(f"all {len(CASES)} network-error cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
