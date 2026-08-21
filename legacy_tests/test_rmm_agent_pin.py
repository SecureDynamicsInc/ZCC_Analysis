"""
Synthetic-data test for the rmm_agent_pin detector.

Run:  python test_rmm_agent_pin.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.rmm_agent_pin import RmmAgentPinDetector


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

    # ---- Case 1: Datto centrastage cert error (Example Tenant E case) ----
    d = RmmAgentPinDetector()
    d.feed(make_rec("ID=1, Host=mng-1.centrastage.net:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "Datto centrastage fires RMM_AGENT_PIN__centrastage.net",
        {f.code for f in findings},
        {"RMM_AGENT_PIN__centrastage.net"},
    ):
        failed += 1

    # ---- Case 2: NinjaOne SSL fail ----
    d = RmmAgentPinDetector()
    d.feed(make_rec("ID=2, Host=app.ninjarmm.com:443"), summary)
    d.feed(make_rec("SSL handshake failed"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "NinjaOne fires RMM_AGENT_PIN__ninjarmm.com",
        {f.code for f in findings},
        {"RMM_AGENT_PIN__ninjarmm.com"},
    ):
        failed += 1

    # ---- Case 3: ConnectWise Automate ----
    d = RmmAgentPinDetector()
    d.feed(make_rec("ID=3, Host=agent.labtechsoftware.com:443"), summary)
    d.feed(make_rec(
        "TLS handshake failure: certificate verify failed"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "Automate fires RMM_AGENT_PIN__labtechsoftware.com",
        {f.code for f in findings},
        {"RMM_AGENT_PIN__labtechsoftware.com"},
    ):
        failed += 1

    # ---- Case 4: non-RMM host -> no finding ----
    d = RmmAgentPinDetector()
    d.feed(make_rec("ID=4, Host=intranet.example.com:443"), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "non-RMM host does NOT fire this detector",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 5: cross-thread isolation ----
    d = RmmAgentPinDetector()
    d.feed(make_rec(
        "ID=5, Host=app.kaseya.com:443", pid=1, tid=10
    ), summary)
    d.feed(make_rec(
        "SSL handshake failed", pid=2, tid=20  # different thread
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "cross-thread SSL fail doesn't attribute to RMM on other thread",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 6: multiple RMM domains in one bundle ----
    d = RmmAgentPinDetector()
    d.feed(make_rec("ID=6, Host=mng-1.centrastage.net:443",
                    pid=1, tid=10), summary)
    d.feed(make_rec(
        "Auth::Lib::certificateErroCallback: Invalid certificate",
        pid=1, tid=10,
    ), summary)
    d.feed(make_rec("ID=7, Host=app.kaseya.com:443",
                    pid=2, tid=20), summary)
    d.feed(make_rec(
        "SSL handshake failure", pid=2, tid=20,
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "two RMM vendors fire two distinct buckets",
        {f.code for f in findings},
        {"RMM_AGENT_PIN__centrastage.net", "RMM_AGENT_PIN__kaseya.com"},
    ):
        failed += 1

    # ---- Case 7: Atera ----
    d = RmmAgentPinDetector()
    d.feed(make_rec("ID=8, Host=app.atera.com:443"), summary)
    d.feed(make_rec("SSL handshake failure"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "Atera fires RMM_AGENT_PIN__atera.com",
        {f.code for f in findings},
        {"RMM_AGENT_PIN__atera.com"},
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
