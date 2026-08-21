"""
Synthetic-line test for the two Connection Error runbook signatures
in the tunnel_not_established detector:

  1. SSL/TLS interception (Auth::Lib::certificateErroCallback)
  2. Z-Tunnel 2.0 fell back to Z-Tunnel 1.0 (SME List is empty.)

Real bundles 1, 2, 3 don't contain either signature, so we manufacture
log lines to verify both fire when planted, and that healthy lookalike
patterns don't accidentally trigger them.

Run:  python test_tunnel_not_established.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.tunnel_not_established import (
    TunnelNotEstablishedDetector,
)


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
    # ---- positive cases ----
    (
        "SSL interception (verbatim runbook signature)",
        "INFO",
        "Auth::Lib::certificateErroCallback: Invalid certificate",
        {"SSL_INTERCEPTION_DETECTED"},
    ),
    (
        "Explicit T2->T1 fallback (verbatim runbook signature)",
        "INFO",
        "ZST2M::ACTIVE::updateZiaConfig: SME List is empty. Fallback to ZTunnel 1.0",
        {"T2_FALLBACK_TO_T1"},
    ),

    # ---- negative cases: must NOT fire ----
    (
        "Routine Data Channel establishment Failed (intra-T2 fallback, NOT SSL interception)",
        "INFO",
        "ZST2M::ZT2A::initialize: Data Channel establishment Failed. Reusing the same ZST2M instance for TLS forwarding.",
        set(),
    ),
    (
        "Healthy auth callback line (no Erro typo / no Invalid certificate)",
        "INFO",
        "Auth::Lib::someOtherCallback: completed successfully",
        set(),
    ),
    (
        "Healthy SME list with entries (not empty)",
        "INFO",
        "ZST2M::ACTIVE::updateZiaConfig: SME List has 3 entries; primary=165.225.1.1",
        set(),
    ),
    (
        "Generic 'Invalid certificate' without the certificateErroCallback context",
        "WARN",
        "Some unrelated TLS validator: Invalid certificate observed in chain",
        set(),
    ),
    (
        "DTLS fallback zEvent (different finding -- still fires, but as zEvent)",
        "INFO",
        "ZEvents: Raised event:  zcc_t2_dtls_to_tls_fallback / 0x300236503 added to queue. Size 1",
        {"ZCC_T2_DTLS_TO_TLS_FALLBACK"},  # this is the EXISTING zevent finding, not new ones
    ),
]


def run_one(label: str, level: str, msg: str, expected: set) -> bool:
    det = TunnelNotEstablishedDetector()
    rec = make_record(level, msg)
    summary = BundleSummary()
    det.feed(rec, summary)
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
    print(f"all {len(CASES)} tunnel_not_established cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
