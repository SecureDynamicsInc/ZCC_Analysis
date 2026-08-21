"""
Synthetic-data test for the ai_cli_pin detector.

Run:  python test_ai_cli_pin.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.ai_cli_pin import AiCliPinDetector


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

    # ---- Case 1: Claude.ai cert error (Example Tenant I case) ----
    d = AiCliPinDetector()
    d.feed(make_rec("ID=1, Host=claude.ai:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "Claude.ai cert error fires AI_CLI_PIN__claude.ai",
        {f.code for f in findings},
        {"AI_CLI_PIN__claude.ai"},
    ):
        failed += 1

    # ---- Case 2: Cursor SSL handshake fail (Example Tenant H case) ----
    d = AiCliPinDetector()
    d.feed(make_rec("ID=2, Host=api.cursor.sh:443"), summary)
    d.feed(make_rec("SSL handshake failure on outbound connection"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "api.cursor.sh handshake failure fires AI_CLI_PIN__cursor.sh",
        {f.code for f in findings},
        {"AI_CLI_PIN__cursor.sh"},
    ):
        failed += 1

    # ---- Case 3: regular non-AI host cert error -> NO finding ----
    d = AiCliPinDetector()
    d.feed(make_rec("ID=3, Host=intranet.example.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "non-AI cert error does NOT fire this detector",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 4: cross-thread context isolation ----
    # Two threads: one to claude.ai (no error), one with an SSL fail
    # on a different host. The detector should NOT pair them.
    d = AiCliPinDetector()
    d.feed(make_rec("ID=4, Host=claude.ai:443", pid=1, tid=10), summary)
    d.feed(make_rec(
        "SSL handshake failure", pid=2, tid=20
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "cross-thread SSL fail doesn't attribute to AI host on other thread",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 5: anthropic.com subdomain ----
    d = AiCliPinDetector()
    d.feed(make_rec("ID=5, Host=api.anthropic.com:443"), summary)
    d.feed(make_rec(
        "TLS handshake failed: certificate verify failed"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "api.anthropic.com fires AI_CLI_PIN__anthropic.com",
        {f.code for f in findings},
        {"AI_CLI_PIN__anthropic.com"},
    ):
        failed += 1

    # ---- Case 6: multiple AI domains in one bundle ----
    d = AiCliPinDetector()
    d.feed(make_rec("ID=6, Host=claude.ai:443", pid=1, tid=10), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate",
        pid=1, tid=10,
    ), summary)
    d.feed(make_rec("ID=7, Host=copilot.microsoft.com:443", pid=2, tid=20), summary)
    d.feed(make_rec(
        "SSL handshake failure", pid=2, tid=20,
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "two AI domains fire two distinct buckets",
        {f.code for f in findings},
        {"AI_CLI_PIN__claude.ai", "AI_CLI_PIN__copilot.microsoft.com"},
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
