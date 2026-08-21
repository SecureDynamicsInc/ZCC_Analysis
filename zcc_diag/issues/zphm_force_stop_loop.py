"""
Detector: ZPHM (Zscaler Proxy Health Monitor) force-stop loop.

When the ZIA / ZPA tunnel is broken (auth failing, broker unreachable,
SAML empty, etc.), ZCC's Proxy Health Monitor (ZPHM) enters a force-
stop loop: it tries to bring the proxy state up, fails, calls
``ZPHM Stop`` to drop into FORCESTOP, calls
``stopAndJoinManager`` with a 5-second join timeout, and starts over.
Each force-stop accumulates 5 s of housekeeping latency. At sustained
rates this can add up to many minutes of wasted overhead.

This detector is a **downstream-symptom** detector. ZPHM force-stops
don't tell you *why* the tunnel is broken; they tell you that *one of
the other detectors* should also be firing. When the count exceeds
the threshold, surface a WARN-level finding that points the operator
at the upstream root cause.

Grounded by a synthetic multi-bundle calibration: the reference test
bundle (WORKGROUP Win 11, ZCC 4.8.0.156, captured 2026-05-19) exhibits
239 ZPHM stopAndJoinManager events while ZPA SAML is empty and
SERVER_AUTH_ERROR fires 4811 times. The pattern is a clean
downstream signal that the real failure is in ZIA / ZPA auth.

Signature is a single-regex match on tunnel-log lines:

    ERR ZPHM stopAndJoinManager Called!! Join Time: 5000

The detector counts hits and fires WARN if >= ``THRESHOLD``. No
state-machine tracking needed.
"""

from __future__ import annotations

import re
from typing import List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


_RE_ZPHM_STOP = re.compile(
    r"ZPHM\s+stopAndJoinManager\s+Called",
    re.IGNORECASE,
)

THRESHOLD = 20  # below this, treat as normal startup / shutdown
EVIDENCE_CAP = 5


@register
class ZphmForceStopLoopDetector(IssueDetector):
    id = "zphm_force_stop_loop"
    title = "ZPHM (proxy health monitor) is force-stopping in a loop"
    sop_file = "zphm_force_stop_loop.md"
    # ZIA-only + Windows-only: ZPHM = Zscaler Proxy Health Monitor,
    # a ZIA-side component on Windows. Mac uses NEFilterDataProvider
    # whose lifecycle is managed differently.
    applies_to_suite = ("zia",)
    applies_to_os = ("windows",)
    # Hot-path skip: the single regex requires "ZPHM" literally.
    prematch_substrings = ("ZPHM",)

    def __init__(self) -> None:
        super().__init__()
        self._count = 0
        self._first_record: Optional[LogLine] = None
        self._last_record: Optional[LogLine] = None
        # Keep a small slice of evidence records for the finding.
        self._sample_records: List[LogLine] = []

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        if _RE_ZPHM_STOP.search(record.message):
            self._count += 1
            if self._first_record is None:
                self._first_record = record
            self._last_record = record
            if len(self._sample_records) < EVIDENCE_CAP:
                self._sample_records.append(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        if self._count < THRESHOLD:
            return []

        # Estimated cumulative latency: each force-stop blocks up to
        # 5 s on the manager-thread join.
        latency_seconds = self._count * 5

        f = Finding(
            code="ZPHM_FORCE_STOP_LOOP",
            severity=Severity.WARNING,
            title=(
                f"ZPHM force-stopped {self._count} times "
                f"(~{latency_seconds // 60} min cumulative latency)"
            ),
            description=(
                f"Zscaler Proxy Health Monitor (ZPHM) entered FORCESTOP "
                f"{self._count} times in this bundle window. Each "
                f"``stopAndJoinManager`` call blocks up to 5 seconds "
                f"on the manager-thread join (the ``Join Time: 5000`` "
                f"value in the log line). Cumulative housekeeping "
                f"latency: ~{latency_seconds} s "
                f"(~{latency_seconds // 60} min).\n\n"
                f"ZPHM force-stops are a **downstream symptom**, not a "
                f"root cause. The monitor is trying to bring the proxy "
                f"state up, repeatedly failing, and force-stopping. "
                f"Look at the other detector findings:\n\n"
                f"  * ``zia_auth_failures`` -- if SERVER_AUTH_ERROR is "
                f"firing, that's the cause.\n"
                f"  * ``zpa_auth_failures`` -- if SAML is empty or "
                f"BRK_MT_SETUP_FAIL_* is firing, that's the cause.\n"
                f"  * ``tunnel_not_established`` -- if SERVER_DOWN_ERROR "
                f"is flapping, that's the cause.\n"
                f"  * ``endpoint_fw_av`` -- if FIREWALL_BLOCK_ERROR is "
                f"firing, that's the cause.\n\n"
                f"Fix the upstream finding; the ZPHM loop will stop on "
                f"its own."
            ),
            sop_anchor="#zphm-force-stop-loop",
        )
        for rec in self._sample_records:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        return [f]
