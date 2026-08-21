"""
Detector: ZPA application not reachable from the connector.

When the ZPA broker can route to an app-connector but the connector
itself cannot reach the destination application, ZCC's microtunnel
end-record JSON carries one of a small family of error tokens that
identify which step in the connector-side reachability flow failed:

  * ``APP_NOT_REACHABLE`` (``err_code 4002``) -- connector is up; the
    destination app's TCP port refused / timed out. App is down, the
    firewall in front of it is blocking, or the connector is in the
    wrong network segment to reach it.
  * ``NO_CONNECTOR_AVAILABLE`` -- the app segment exists but no
    connector in the matching connector group is online to service the
    request. Typically a connector outage or a misrouted segment.
  * ``INVALID_DOMAIN`` -- the destination domain doesn't match what the
    connector expects to service. Most often a connector-group / app-
    segment mapping mistake.
  * ``AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER`` -- the App Connector
    (AST = App Service Tunnel) explicitly timed out trying to reach the
    backend. Sibling of APP_NOT_REACHABLE but emitted by a different
    code path; both fire on connector-to-app reachability problems.

Grounded by the iatwater Mac bundle: ``APP_NOT_REACHABLE`` fires 18
times on ``zpn_mtunnel_end`` (errcode 4002). The Cyderes
ZPA-troubleshooting KB confirms NO_CONNECTOR_AVAILABLE and
INVALID_DOMAIN as connector-reachability tokens; the
AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER token is documented in
the Zscaler PSE training materials and surfaces on customer bundles
where the AC has a one-way network path to the destination.

The detector buckets each error string into its own finding code so
the operator can tell at a glance which kind of reachability problem
dominates.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


_RE_MT_ERROR = re.compile(
    r'"error"\s*:\s*"(?P<err>'
    r'APP_NOT_REACHABLE'
    r'|NO_CONNECTOR_AVAILABLE'
    r'|INVALID_DOMAIN'
    r'|AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER'
    r')"',
)

# Some implementations of zpn_mtunnel_end also expose an err_code
# numeric. We don't gate on it; the string is authoritative.
_RE_ERR_CODE = re.compile(r'"err_code"\s*:\s*(?P<code>\d+)')

# Tag id helps the operator cross-reference the failing app segment
# in the admin console. Extract when present.
_RE_TAG_ID = re.compile(r'"tag_id"\s*:\s*(?P<tag>\d+)')

EVIDENCE_CAP = 10


_ERR_META = {
    "APP_NOT_REACHABLE": {
        "code": "ZPA_APP_NOT_REACHABLE",
        "title": "ZPA app unreachable from the connector",
        "description": (
            "App Connector is online but cannot reach the destination "
            "application's listener. Confirm: (a) the destination is "
            "actually up, (b) the App Connector's interface has a "
            "route to it, (c) any firewall between the connector and "
            "the app permits the relevant TCP port. The "
            "``err_code:4002`` accompanying these records is the "
            "canonical signature."
        ),
        "sop_anchor": "#zpa-app-not-reachable",
        "severity": Severity.CRITICAL,
    },
    "NO_CONNECTOR_AVAILABLE": {
        "code": "ZPA_NO_CONNECTOR_AVAILABLE",
        "title": "No ZPA App Connector available for this app segment",
        "description": (
            "No App Connector in the matching connector group is "
            "currently online for this app segment. Either every "
            "connector in the group is down, or the segment is mapped "
            "to a connector group with no live members. Check ZPA "
            "Admin Console -> Connectors for connector status, then "
            "Applications -> Application Segments for the segment's "
            "connector-group mapping."
        ),
        "sop_anchor": "#zpa-no-connector-available",
        "severity": Severity.CRITICAL,
    },
    "INVALID_DOMAIN": {
        "code": "ZPA_INVALID_DOMAIN",
        "title": "ZPA destination domain rejected by connector",
        "description": (
            "App Connector refused to service the request because "
            "the destination domain isn't in its expected set. This "
            "is usually a segment-to-connector-group mismatch (the "
            "app segment was mapped to a connector group that doesn't "
            "serve this domain) or a stale connector that hasn't "
            "received the current policy."
        ),
        "sop_anchor": "#zpa-invalid-domain",
        "severity": Severity.WARNING,
    },
    "AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER": {
        "code": "ZPA_AST_SETUP_TIMEOUT",
        "title": "App Connector timed out reaching backend",
        "description": (
            "App Service Tunnel (AST) on the connector timed out "
            "trying to establish the back-end TCP session. Same "
            "family as APP_NOT_REACHABLE but emitted by the "
            "connector-side timeout path. Common with one-way network "
            "paths (asymmetric routing, firewall dropping outbound "
            "SYN-ACK)."
        ),
        "sop_anchor": "#zpa-ast-setup-timeout",
        "severity": Severity.WARNING,
    },
}


@register
class ZpaAppNotReachableDetector(IssueDetector):
    id = "zpa_app_not_reachable"
    title = "ZPA application reachability failures"
    sop_file = "zpa_app_not_reachable.md"
    # ZPA-only: connector→app reachability tokens are ZPA-side.
    applies_to_suite = ("zpa",)
    # All four error tokens are unique enough to use as cheap
    # substring anchors; the multiplexer skips records that contain
    # none of them before the regex pass runs.
    prematch_substrings = (
        "APP_NOT_REACHABLE",
        "NO_CONNECTOR_AVAILABLE",
        "INVALID_DOMAIN",
        "AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER",
    )

    def __init__(self) -> None:
        super().__init__()
        # Per-error-string evidence counter and sample-record list.
        self._tag_ids: Dict[str, set] = {k: set() for k in _ERR_META}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        m = _RE_MT_ERROR.search(record.message)
        if not m:
            return
        err = m.group("err")
        meta = _ERR_META[err]
        f = self._bucket(
            meta["code"],
            meta["severity"],
            meta["title"],
            meta["description"],
            sop_anchor=meta["sop_anchor"],
        )
        f.add_evidence(record, cap=EVIDENCE_CAP)

        m_tag = _RE_TAG_ID.search(record.message)
        if m_tag:
            self._tag_ids[err].add(m_tag.group("tag"))

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        # If we collected tag_ids per error, append them to the title
        # so the operator can grep the ZPA admin console.
        for err, tag_set in self._tag_ids.items():
            meta = _ERR_META[err]
            f = self._buckets.get(meta["code"])
            if f is None or not tag_set:
                continue
            tags = ", ".join(sorted(tag_set, key=lambda x: int(x))[:5])
            more = "" if len(tag_set) <= 5 else f" (+{len(tag_set)-5} more)"
            f.title = (
                f"{meta['title']} "
                f"[{f.count} hits, tag_ids: {tags}{more}]"
            )
        return list(self._buckets.values())
