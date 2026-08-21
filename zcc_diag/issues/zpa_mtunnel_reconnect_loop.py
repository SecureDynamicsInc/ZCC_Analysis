"""
Detector: ZPA microtunnel reconnect loop.

When a ZPA microtunnel's peer (broker or app-connector-assistant)
forcibly tears down the session, ZCC emits one of these tokens on
``zpn_mtunnel_end``:

  * ``BRK_MT_CLOSED_FROM_ASSISTANT`` -- the App Connector assistant
    closed the session (typically idle-timeout or AC reload).
  * ``BRK_MT_RESET_FROM_SERVER`` -- the broker or app side sent a
    forcible reset (RST) mid-flow.
  * ``BRK_MT_TERMINATED`` -- the microtunnel was terminated by ZPA
    backend logic, often due to policy refresh or admin action.

In isolation each of these is benign (the client reconnects). But
when they cluster -- many teardowns in a short window with the same
client reconnecting -- it's a reconnect loop: ZPA is repeatedly
tearing down a tunnel the client keeps re-establishing. The most
common drivers are:

  1. **Idle-timeout mismatch** between the AC and the broker / app.
  2. **Policy refresh storm** (admin pushed a policy change and every
     existing tunnel terminated; healthy on its own, pathological if
     the policy is unstable).
  3. **Connector under-provisioning** -- the AC kills sessions to
     reclaim resources because it's at limit.
  4. **Aggressive peer-side stateful firewall** clearing entries faster
     than ZCC reconnects.

Grounded by example-tenant-c-windows where these three tokens fire
192 / 221 / 27 times respectively in a captured window. That's a
strong reconnect-loop signature.

The detector counts hits across the three tokens. The breakdown is
reported per-token so the operator can see which teardown reason
dominates -- different reasons point at different root causes.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


_RE_TEARDOWN = re.compile(
    r'"error"\s*:\s*"(?P<reason>'
    r'BRK_MT_CLOSED_FROM_ASSISTANT'
    r'|BRK_MT_RESET_FROM_SERVER'
    r'|BRK_MT_TERMINATED'
    r')"',
)

# Threshold below which we treat this as normal: a handful of
# reconnects on network change or sleep/wake is expected.
THRESHOLD_TOTAL = 30
# Threshold above which we escalate to WARNING (sustained loop).
THRESHOLD_SUSTAINED = 100

EVIDENCE_CAP = 10

_REASON_HINTS = {
    "BRK_MT_CLOSED_FROM_ASSISTANT": (
        "App Connector assistant closed -- usually idle timeout or "
        "AC reload"
    ),
    "BRK_MT_RESET_FROM_SERVER": (
        "Broker/app sent forcible RST -- stateful firewall or peer "
        "process death"
    ),
    "BRK_MT_TERMINATED": (
        "ZPA backend terminated -- policy refresh or admin action"
    ),
}


@register
class ZpaMtunnelReconnectLoopDetector(IssueDetector):
    id = "zpa_mtunnel_reconnect_loop"
    title = "ZPA microtunnel reconnect loop"
    sop_file = "zpa_mtunnel_reconnect_loop.md"
    # ZPA-only: BRK_MT_* close-code teardown loops are ZPA-side.
    applies_to_suite = ("zpa",)
    # All three teardown tokens share the BRK_MT_ prefix; one cheap
    # substring covers the lot.
    prematch_substrings = ("BRK_MT_",)

    def __init__(self) -> None:
        super().__init__()
        self._counts: Dict[str, int] = {
            "BRK_MT_CLOSED_FROM_ASSISTANT": 0,
            "BRK_MT_RESET_FROM_SERVER": 0,
            "BRK_MT_TERMINATED": 0,
        }
        self._sample_records: List[LogLine] = []
        self._first_record: Optional[LogLine] = None
        self._last_record: Optional[LogLine] = None

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        m = _RE_TEARDOWN.search(record.message)
        if not m:
            return
        reason = m.group("reason")
        self._counts[reason] += 1
        if self._first_record is None:
            self._first_record = record
        self._last_record = record
        if len(self._sample_records) < EVIDENCE_CAP:
            self._sample_records.append(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        total = sum(self._counts.values())
        if total < THRESHOLD_TOTAL:
            return []

        if total >= THRESHOLD_SUSTAINED:
            severity = Severity.WARNING
            severity_tag = "sustained reconnect loop"
        else:
            severity = Severity.INFO
            severity_tag = "elevated teardown rate"

        # Compute observed window if we have both endpoints. Useful
        # signal: rate per minute tells the operator how aggressive
        # the loop is.
        rate_block = ""
        if self._first_record and self._last_record:
            span = (
                self._last_record.timestamp
                - self._first_record.timestamp
            ).total_seconds()
            if span > 0:
                rate = total / (span / 60.0)
                rate_block = f" (~{rate:.1f}/min over {span/60:.1f} min)"

        # Per-reason breakdown for the description.
        bd_lines = []
        for reason, count in self._counts.items():
            if count == 0:
                continue
            bd_lines.append(
                f"  * ``{reason}`` x{count} -- "
                f"{_REASON_HINTS[reason]}"
            )
        breakdown = "\n".join(bd_lines)

        f = Finding(
            code="ZPA_MTUNNEL_RECONNECT_LOOP",
            severity=severity,
            title=(
                f"{total} ZPA microtunnel teardowns "
                f"({severity_tag}){rate_block}"
            ),
            description=(
                f"ZCC observed {total} ZPA microtunnel forced "
                f"teardowns in this bundle. Breakdown by reason:\n\n"
                f"{breakdown}\n\n"
                f"Reconnect loops compound: each teardown triggers "
                f"a fresh broker handshake (SAML re-presentation, "
                f"connector selection, mtunnel setup) which is "
                f"latency- and CPU-expensive. Sustained loops affect "
                f"battery life on laptops and amplify backend "
                f"connector load. See SOP for the per-reason "
                f"diagnostic flow."
            ),
            sop_anchor="#zpa-mtunnel-reconnect-loop",
        )
        for rec in self._sample_records:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        return [f]
