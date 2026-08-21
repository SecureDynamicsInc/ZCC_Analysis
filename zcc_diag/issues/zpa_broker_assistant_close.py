"""
Detector: ZPA application session close events (per-app aggregator).

What this surfaces
-----------------
The ZPA broker establishes a microtunnel (M-Tunnel) to a connector
for a specific ZPA application. Each microtunnel has a ``tag_id`` and
is associated with an ``App Name``. When the application server (the
target connector application — RDS, internal web app, etc) closes
its TCP session, the App Connector cleanly closes the M-Tunnel and
the ZPA client logs:

    {"zpn_mtunnel_end":{"tag_id":N,"error":"BRK_MT_CLOSED_FROM_ASSISTANT",
                        "err_code":5027,"drop_data":0}}

VALIDATION (2026-06-12)
-----------------------
Per Zscaler's documented ZPA Session Status Codes, ``BRK_MT_CLOSED_
FROM_ASSISTANT`` is the NORMAL CLOSE signal:

> "The App Connector closed the application Microtunnel (M-Tunnel)
>  as a result of the application server terminating the TCP session
>  with a TCP FIN. No action is required."
>
> -- help.zscaler.com/zpa/understanding-zpa-session-status-codes

This means BRK_MT_CLOSED_FROM_ASSISTANT is NOT a failure signal — it's
the documented signature of a successful session ending. Earlier
versions of this detector classified it as CRITICAL; that was wrong
and has been corrected. It now fires INFO findings that aggregate
per-application session counts so the engineer can see what apps the
user actually reached and how often, but it does NOT contribute to
incident-level verdicts.

Why keep the detector at all
----------------------------
Per-App-Name session counts are useful context. They tell the engineer:
  * Which applications the user reached during the bundle window
  * How many sessions per app (a proxy for activity / usage)
  * Whether a customer-reported app appears at all (if not, the user
    may have a different issue — DNS / policy / connector down)

The framing is "session activity summary", not "incident detection".

Distinct from BRK_MT_SETUP_FAIL_*
---------------------------------
The ``zpa_auth_failures`` detector catches ``BRK_MT_SETUP_FAIL_*``
events. Those ARE failures — broker rejected the setup request at
SAML / cert / segment / access-policy time. Those remain CRITICAL.

Earlier validation note (now corrected)
---------------------------------------
Synthetic Windows Scenario D had 9 BRK_MT_CLOSED_FROM_
ASSISTANT events clustered in a 2-minute window across 3 apps. The
first version of this detector flagged that as a CRITICAL "broker
terminated connection" pattern. Per the docs, it's actually three
normal user-driven sessions: the user opened storefront.corp-a.example
three times, each time the application server closed the TCP session
when the user finished, and the M-Tunnel closed cleanly. No incident.

App-name extraction
-------------------
The ZSATunnel log emits an ``===> ID=X, ZPN Connection ... App Name=
NAME, ... TAG-ID=N`` setup line BEFORE the matching
mtunnel_request_ack + mtunnel_end pair. This detector remembers the
tag_id -> App Name mapping at setup time so that when the close fires
seconds later, we can attribute it to the specific application. Apps
get their own per-name finding bucket so the engineer sees:

    BRK_MT_CLOSED_FROM_ASSISTANT for storefront.corp-a.example (3 events)
    BRK_MT_CLOSED_FROM_ASSISTANT for rds.corp-a.example       (4 events)

…instead of one combined "9 events across unknown apps" lump.

CALIBRATION
-----------
Scenario Windows D bundle (Win 11 Enterprise, ZCC 4.8.0.232, Den3 brokers):
9 BRK_MT_CLOSED_FROM_ASSISTANT events clustered in 2 minutes
(2026-06-12 17:50:19 -> 17:51:59), three distinct tag_ids (65744,
65745, 65746). Each tag_id had ONE request_ack and TWO end lines
(drop_data:0 + drop_data:1, ~30 ms apart) -- the double-end is normal,
not a bug; both end lines reference the same close so we deduplicate
by tag_id within a 1-second window.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# The setup line carries the App Name and the TAG-ID. We use this to
# remember which app a tag_id belongs to so the close-fire can attribute
# correctly. Format A example:
#
#   ===> ID=1759254811, ZPN Connection local:55984->100.64.1.1:443
#                       App Name=storefront.corp-a.example,
#                       DoubleEncrypt=0 TAG-ID=65744
# Phase 58e-C2 (2026-07-08): dropped re.IGNORECASE. Under IGNORECASE,
# [^A] excludes both A AND a — and the intervening text contains 'a' in
# "local"; likewise [^T] excludes T and t, and "Encrypt"/"DoubleEncrypt"
# contain 't'. The regex therefore never matched. Same class of bug as
# Phase 25.1 fixed in zpa_session_correlator. The literal tokens
# "ZPN Connection", "App Name=", and "TAG-ID=" are canonical
# uppercase in every observed Format-A log line, so case-sensitive
# matching is correct.
_RE_SETUP = re.compile(
    r"ZPN Connection[^A]*App Name=(?P<app>[^,]+),"
    r"[^T]*TAG-ID=(?P<tag>\d+)",
)

# The close fires inside a Control Message Response Data JSON payload.
# Two variants of the same logical event:
#   1. The JSON line itself (INF level)
#   2. The bare ERR-level companion "zpn_mtunnel_end error:
#      BRK_MT_CLOSED_FROM_ASSISTANT"
# We anchor on (1) because it has the tag_id; (2) is informational and
# would double-count if we matched it too.
_RE_CLOSE_JSON = re.compile(
    r'\{"zpn_mtunnel_end":\{"tag_id":(?P<tag>\d+),'
    r'\s*"error":"BRK_MT_CLOSED_FROM_ASSISTANT"'
    r'[^}]*"err_code":(?P<code>\d+)'
    r'[^}]*"drop_data":(?P<drop>\d+)\}\}'
)

# Burst-dedup: same tag_id appearing twice within DEDUP_S seconds is
# the normal drop_data:0 + drop_data:1 pair; count once.
DEDUP_S = 1.0

EVIDENCE_CAP = 20


# --- Detector ---------------------------------------------------------

@register
class ZpaAppSessionsDetector(IssueDetector):
    """Per-app session-activity tally. NOT an incident detector — see
    module docstring for the validation citation explaining why
    BRK_MT_CLOSED_FROM_ASSISTANT is a normal-closure signal."""
    id = "zpa_app_sessions"
    title = "ZPA app session activity (informational)"
    sop_file = ""
    # ZPA-only: per-app session activity is derived from zpn_mtunnel_*.
    applies_to_suite = ("zpa",)

    # All signals appear in ZSATunnel logs. No tray / service / upm
    # walking needed.

    # Pre-filter: every signal contains one of these substrings, so
    # the multiplexer can skip records without scanning regexes.
    prematch_substrings = (
        "TAG-ID=",          # setup line
        "BRK_MT_CLOSED_FROM_ASSISTANT",  # close line
    )

    # Cross-platform — both Mac TRPTunnel and Windows ZSATunnel emit
    # the same JSON shape.
    applies_to_os = None

    def __init__(self) -> None:
        super().__init__()
        # tag_id -> App Name. Built up by feed() at setup time, read
        # at close time. We never expire entries — a tag_id only
        # appears once (mtunnels are not reused).
        self._tag_to_app: Dict[str, str] = {}
        # tag_id -> last_close_ts (datetime). Used to dedupe the
        # drop_data:0/1 pair.
        self._tag_last_close = {}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # Capture App Name from the setup line.
        m = _RE_SETUP.search(msg)
        if m:
            tag = m.group("tag")
            app = m.group("app").strip()
            # Only record on first sight; same tag_id seen again means
            # log rotation crossed the same session, keep the first.
            self._tag_to_app.setdefault(tag, app)
            return

        # Match the close event. drop_data:1 within 1s of drop_data:0
        # for the same tag_id is the normal double-end; collapse.
        m = _RE_CLOSE_JSON.search(msg)
        if not m:
            return
        tag = m.group("tag")
        err_code = m.group("code")
        last_ts = self._tag_last_close.get(tag)
        if last_ts is not None and (record.timestamp - last_ts).total_seconds() < DEDUP_S:
            # Same tag_id within the dedup window — second half of the
            # double-end pair. Skip without bumping count.
            self._tag_last_close[tag] = record.timestamp
            return
        self._tag_last_close[tag] = record.timestamp

        app = self._tag_to_app.get(tag, "(unknown app)")

        # Per-app bucket — informational session-activity tally, NOT
        # an incident. See module docstring for the validation citation.
        safe_app = re.sub(r"[^A-Za-z0-9._-]", "_", app)
        code_str = f"ZPA_APP_SESSION_CLOSED::{safe_app}"
        f = self._bucket(
            code=code_str,
            severity=Severity.INFO,
            title=f"ZPA app session(s) to {app} ended normally",
            description=(
                f"The ZPA app `{app}` (tag_id {tag}) completed and "
                f"closed cleanly. Per Zscaler's documented ZPA Session "
                f"Status Codes, `BRK_MT_CLOSED_FROM_ASSISTANT` "
                f"(err_code {err_code}) is the NORMAL close signal — "
                f"the App Connector closed the M-Tunnel because the "
                f"application server terminated the TCP session with "
                f"a TCP FIN.\n\n"
                f"_No action required._ This finding is informational, "
                f"surfacing which ZPA apps the user actually reached "
                f"during the bundle window. If the user reported "
                f"trouble reaching a specific app and you see clean "
                f"sessions to that app here, the issue is likely on "
                f"the application side, not in ZPA's transport.\n\n"
                f"Reference: help.zscaler.com/zpa/understanding-zpa-"
                f"session-status-codes"
            ),
            sop_anchor=None,
        )
        f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        # Sort findings by count descending so the worst-affected app
        # leads.
        return sorted(
            self._buckets.values(),
            key=lambda f: -f.count,
        )
