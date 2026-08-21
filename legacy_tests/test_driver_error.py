"""
Synthetic-line test for the Driver Error detector.

Real bundles 1, 2, 3 don't contain a driver-load failure, so we
manufacture log lines to verify:

    1. Each documented failure mode fires a finding:
       - LWF: Unable to load driver
       - lwf: Initial driver check FAILED
       - LightWeightFilter not loaded (backstop)
       - Tray "Driver Error" string

    2. Healthy patterns observed in real bundles do NOT fire:
       - 'getUserTypeV2: Finish: {"error":"0","errorMessage":""}'
         (auth response, empty error)
       - 'TrayPolicy::serialize()' config dump
       - 'ZSATrayHelper App Version' banner
       - 'lwfDriverRunning:true' healthy state
       - Unrelated 'Driver' mentions (e.g., 'TAP Driver healthy')

Run:  python test_driver_error.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.driver_error import DriverErrorDetector


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
    # ---- positive cases (runbook signatures) ----
    (
        "LWF: Unable to load driver (verbatim runbook)",
        "ERROR",
        "LWF: Unable to load driver!",
        {"LWF_UNABLE_TO_LOAD"},
    ),
    (
        "lwf: Initial driver check FAILED (verbatim runbook)",
        "ERROR",
        "lwf: Initial driver check FAILED! LightWeightFilter not loaded! ZApp moves to DRIVER ERROR!",
        # The Initial-check pattern is checked before the backstop, so
        # we expect only LWF_INITIAL_CHECK_FAILED (the more specific
        # match wins via the return statement in feed_tray).
        {"LWF_INITIAL_CHECK_FAILED"},
    ),
    (
        "LightWeightFilter not loaded (backstop, no Initial-check prefix)",
        "ERROR",
        "Service Status: LightWeightFilter not loaded -- driver subsystem unavailable",
        {"LIGHTWEIGHT_FILTER_NOT_LOADED"},
    ),
    (
        "Tray Service Status: 'Driver Error'",
        "INFO",
        "Service Status updated: Driver Error",
        {"TRAY_DRIVER_ERROR"},
    ),

    # ---- negative cases (real healthy bundle shapes) ----
    (
        "Healthy auth response (errorMessage empty)",
        "INFO",
        'Auth::Lib::getUserTypeV2: Finish: {"error":"0","errorMessage":"","response":{"saml":"1"},"success":"true"}',
        set(),
    ),
    (
        "Healthy TrayPolicy serialize() dump (config, contains 'errorMessage')",
        "DEBUG",
        'TrayPolicy::serialize() - trayPolicy = {"errorMessage":"","success":false,"loginName":""}',
        set(),
    ),
    (
        "ZSATrayHelper App Version banner",
        "INFO",
        "ZSATrayHelper App Version: 4.6.0.168",
        set(),
    ),
    (
        "Healthy lwfDriverRunning:true status",
        "INFO",
        '{"lwfDriverRunning":true,"tapDriverRunning":false}',
        set(),
    ),
    (
        "Unrelated mention of 'Driver' (no error)",
        "INFO",
        "TAP Driver healthy; LWF Driver online",
        set(),
    ),
    (
        "Unrelated 'lwf' mention (no Initial-check or FAILED)",
        "DEBUG",
        "lwf: getStatus returned OK",
        set(),
    ),
    (
        "Routine TrayManager startup line",
        "INFO",
        "ZSATrayManager Version: 4.6.0.168",
        set(),
    ),
    (
        "Auth error WITH errorMessage but unrelated to driver",
        "ERROR",
        'Auth response: {"error":"401","errorMessage":"Invalid user/password","success":"false"}',
        # this is auth not driver -- the network_error detector also
        # ignores it because "Invalid user/password" isn't in the
        # documented network-error categories
        set(),
    ),
]


def run_one(label: str, level: str, msg: str, expected: set) -> bool:
    det = DriverErrorDetector()
    rec = make_record(level, msg)
    summary = BundleSummary()
    # DriverErrorDetector uses feed_tray, not feed
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
    print(f"all {len(CASES)} driver-error cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
