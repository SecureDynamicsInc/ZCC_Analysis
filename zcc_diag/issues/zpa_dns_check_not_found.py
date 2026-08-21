"""
Detector: ZPA DNS check / application invalid -- app-segment coverage gap.

When ZCC's tunnel does a per-application DNS check before microtunnel
setup and the hostname isn't covered by any ZPA application segment,
two related JSON tokens appear in the tunnel log:

  * ``"zpn_dns_client_check": {"name": "...", "error":
    "ZPN_ERR_DNS_CHECK_NOT_FOUND", ...}``
  * ``"zpn_application_invalid": {... "error":
    "ZPN_ERR_APPLICATION_INVALID", ...}``

Both indicate that the client tried to resolve a destination that ZPA
doesn't recognize as one of its app segments. The most common root
causes are:

  1. **Internal AD names not in an app segment** -- the bundle mining
     pass found ``pct-dc1.corp-c.example`` and
     ``_ldap._tcp.dc._msdcs.corp-c.example`` hitting this 180+
     times. Classic AD app-segment gap.
  2. **Newly-onboarded application not yet pushed to the connector
     group** -- segment exists in admin console but the connector hasn't
     received the policy refresh.
  3. **Wildcard segment was purged or scoped too narrowly** -- the user
     intended ``*.corp.example.com`` but the segment is
     ``app.corp.example.com``.

The detector buckets findings by the queried hostname so the operator
can see the top-N missing names at a glance. Severity is WARNING
(not CRITICAL) because some hits are benign client noise (random apps
probing internal names that should never have been routed through
ZPA in the first place) -- the operator decides which.

Grounded in the example-tenant-c-windows bundle (180 hits across
``ZPN_ERR_DNS_CHECK_NOT_FOUND`` + ``ZPN_ERR_APPLICATION_INVALID``).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# ZPN_ERR_DNS_CHECK_NOT_FOUND appears in a zpn_dns_client_check JSON
# blob. The "name" field carries the queried hostname. Extract both in
# one shot.
_RE_DNS_CHECK_NOT_FOUND = re.compile(
    r'"zpn_dns_client_check"\s*:\s*\{[^{}]*?'
    r'"name"\s*:\s*"(?P<name>[^"]+)"[^{}]*?'
    r'"error"\s*:\s*"ZPN_ERR_DNS_CHECK_NOT_FOUND"',
    re.IGNORECASE,
)

# ZPN_ERR_APPLICATION_INVALID often appears without a queried name in
# the immediate JSON object (the name is in an earlier line on the
# same thread). Match on the error string alone for the counter; the
# evidence sample carries the surrounding context.
_RE_APPLICATION_INVALID = re.compile(
    r'"error"\s*:\s*"ZPN_ERR_APPLICATION_INVALID"',
    re.IGNORECASE,
)

# Threshold below which we treat hits as expected noise (a handful of
# probe lookups for non-ZPA apps is normal on enterprise endpoints).
THRESHOLD_TOTAL = 10
TOP_N_NAMES = 10
EVIDENCE_CAP = 10


@register
class ZpaDnsCheckNotFoundDetector(IssueDetector):
    id = "zpa_dns_check_not_found"
    title = "ZPA DNS check fell through (app-segment gap)"
    sop_file = "zpa_dns_check_not_found.md"
    # ZPA-only: ZPN_ERR_DNS_CHECK_NOT_FOUND is a ZPA app-segment gap.
    applies_to_suite = ("zpa",)
    # Both regexes require one of these literal tokens, so the
    # multiplexer can cheaply skip ~99% of records.
    prematch_substrings = (
        "ZPN_ERR_DNS_CHECK_NOT_FOUND",
        "ZPN_ERR_APPLICATION_INVALID",
    )

    def __init__(self) -> None:
        super().__init__()
        self._name_counter: Counter[str] = Counter()
        self._invalid_count: int = 0
        self._sample_records: List[LogLine] = []
        self._first_record: Optional[LogLine] = None
        self._last_record: Optional[LogLine] = None

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        matched = False

        m = _RE_DNS_CHECK_NOT_FOUND.search(msg)
        if m:
            name = m.group("name").lower().rstrip(".")
            self._name_counter[name] += 1
            matched = True

        if _RE_APPLICATION_INVALID.search(msg):
            self._invalid_count += 1
            matched = True

        if matched:
            if self._first_record is None:
                self._first_record = record
            self._last_record = record
            if len(self._sample_records) < EVIDENCE_CAP:
                self._sample_records.append(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        total = sum(self._name_counter.values()) + self._invalid_count
        if total < THRESHOLD_TOTAL:
            return []

        top = self._name_counter.most_common(TOP_N_NAMES)
        top_block = "\n".join(
            f"  * ``{name}`` ({count}x)" for name, count in top
        ) or "  (no individual name extracted -- check evidence)"

        # Severity escalation: a small number of one-off probes is INFO;
        # a sustained pattern (>=50 total) is WARNING; a heavy bombardment
        # (>=200 total) is a strong app-segment-gap signal -- still WARN
        # because we don't want to fire CRITICAL on a config gap that
        # may be intentional, but the operator should see it loud.
        if total >= 200:
            severity = Severity.WARNING
            severity_tag = "(sustained, >=200 hits)"
        elif total >= 50:
            severity = Severity.WARNING
            severity_tag = "(sustained)"
        else:
            severity = Severity.INFO
            severity_tag = ""

        f = Finding(
            code="ZPA_DNS_CHECK_NOT_FOUND",
            severity=severity,
            title=(
                f"{total} ZPA DNS-check fall-throughs "
                f"({len(self._name_counter)} distinct names) "
                f"{severity_tag}"
            ).strip(),
            description=(
                f"ZCC tried to do a ZPA app-segment DNS check for "
                f"{total} requests and the destination wasn't covered "
                f"by any ZPA application segment "
                f"(``ZPN_ERR_DNS_CHECK_NOT_FOUND`` x"
                f"{sum(self._name_counter.values())}, "
                f"``ZPN_ERR_APPLICATION_INVALID`` x"
                f"{self._invalid_count}).\n\n"
                f"Top {min(TOP_N_NAMES, len(top))} unique destinations:\n"
                f"{top_block}\n\n"
                f"Common root causes: an internal AD/DC hostname or "
                f"newly-onboarded application isn't yet in an app "
                f"segment, or a wildcard segment was purged or "
                f"narrowed. Cross-reference against the ZPA Admin "
                f"Console: Applications -> Application Segments. "
                f"See SOP for the full triage flow."
            ),
            sop_anchor="#zpa-dns-check-not-found",
        )
        for rec in self._sample_records:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        return [f]
