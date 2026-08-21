"""
Detector: cert-pinned SaaS apps hit by SSL inspection.

Sister detector to ``ai_cli_pin`` and ``rmm_agent_pin``. Catches the
canonical "must-bypass SSL inspection" SaaS apps that Zscaler itself
documents as cert-pinning:

  * Microsoft 365 (Outlook / SharePoint / Teams / Office endpoints)
  * Apple (iCloud / FaceTime / iMessage / Apple ID infrastructure)
  * Cisco WebEx
  * Dropbox
  * GoToMeeting / LogMeIn

Per Zscaler's own help docs (verbatim, sourced from
help.zscaler.com/zia/zscaler-traffic-bypasses): *"Zscaler cannot
inspect TLS traffic from sites or applications that use certificate
pinning including Microsoft 365 and apps like WebEx, Dropbox and
others."*

A new customer onboarding to ZCC frequently forgets to add these to
their BLSSL bypass list. The user-visible symptom is "Outlook won't
sync" / "Teams calls drop" / "Dropbox stopped syncing files." The
ZCC log signature is the standard cert-error pattern but against
hosts in this well-known catalogue.

This detector fires CRITICAL when an SSL handshake fails against a
catalogue host AND that host is NOT in the customer's runtime
bypass cache. If the host IS in bypass_cache, the cert error has a
different root cause (and ``bypass_misconfiguration`` handles that).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Canonical cert-pinning SaaS catalogue. Each tuple is
# (suffix, display-name-for-vendor). Suffix matches against the
# trailing portion of the host (case-insensitive). When a `*.` prefix
# is present, the dot is included so we match foo.X but not fooX.
_CERT_PINNED_SAAS = (
    # Microsoft 365 suite -- the highest-traffic cert-pinning case
    ("outlook.office.com",      "Microsoft 365 (Outlook)"),
    ("outlook.office365.com",   "Microsoft 365 (Outlook)"),
    ("teams.microsoft.com",     "Microsoft 365 (Teams)"),
    ("teams.cloud.microsoft",   "Microsoft 365 (Teams)"),
    ("graph.microsoft.com",     "Microsoft 365 (Graph)"),
    ("sharepoint.com",          "Microsoft 365 (SharePoint)"),
    ("officeapps.live.com",     "Microsoft 365"),
    ("office.com",              "Microsoft 365"),
    ("microsoft365.com",        "Microsoft 365"),
    ("skype.com",               "Microsoft 365 (Skype for Business)"),
    # Apple -- cert-pinned iCloud / FaceTime / Apple ID
    ("icloud.com",              "Apple iCloud"),
    ("apple.com",               "Apple infrastructure"),
    ("itunes.apple.com",        "Apple iTunes"),
    ("apple-cloudkit.com",      "Apple CloudKit"),
    ("facetime.apple.com",      "Apple FaceTime"),
    # WebEx
    ("webex.com",               "Cisco WebEx"),
    ("webexcontent.com",        "Cisco WebEx CDN"),
    # Dropbox
    ("dropbox.com",             "Dropbox"),
    ("dropboxusercontent.com",  "Dropbox content"),
    # LogMeIn / GoTo
    ("gotomeeting.com",         "GoToMeeting"),
    ("goto.com",                "LogMeIn GoTo"),
    ("logmein.com",             "LogMeIn"),
    # Salesforce (cert-pinned in some configurations)
    ("salesforce.com",          "Salesforce"),
    ("force.com",               "Salesforce"),
    # Zoom -- not always cert-pinned, but commonly broken by inspection
    ("zoom.us",                 "Zoom"),
    ("zoomgov.com",             "Zoom for Government"),
)


_RE_HOST_LINE = re.compile(
    r"\bHost=(?P<host>[A-Za-z0-9.\-]+)(?::\d+)?",
)
_RE_SSL_FAIL = re.compile(
    r"Auth::Lib::certificateErroCallback:\s*Invalid certificate"
    r"|Certificate validation error"
    r"|SSL handshake (?:failure|failed|fail)"
    r"|TLS handshake (?:failure|failed|fail)"
    r"|ssl3_get_server_certificate.*?verify failed",
    re.IGNORECASE,
)


def _matches_pinned_saas(host: str) -> Optional[str]:
    """Return the matching vendor display name if ``host`` is in the
    cert-pinned SaaS catalogue, else None.
    """
    h = host.lower().rstrip(".")
    for suffix, vendor in _CERT_PINNED_SAAS:
        s = suffix.lower()
        if h == s or h.endswith("." + s):
            return vendor
    return None


EVIDENCE_CAP = 10


@register
class CertPinnedSaasInspectionDetector(IssueDetector):
    id = "cert_pinned_saas_inspection"
    title = "Cert-pinned SaaS broken by SSL inspection"
    sop_file = "cert_pinned_saas_inspection.md"
    # ZIA-only: SSL inspection is a ZIA-side feature. ZPA's M-Tunnel
    # is end-to-end encrypted with a client/connector cert pair, not
    # subject to SSL inspection.
    applies_to_suite = ("zia",)

    def __init__(self) -> None:
        super().__init__()
        self._thread_last_saas: Dict[tuple, str] = {}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        key = (record.pid, record.tid)

        m_host = _RE_HOST_LINE.search(msg)
        if m_host:
            vendor = _matches_pinned_saas(m_host.group("host"))
            if vendor is not None:
                self._thread_last_saas[key] = m_host.group("host")

        if _RE_SSL_FAIL.search(msg):
            host = self._thread_last_saas.get(key)
            if host is None:
                return
            vendor = _matches_pinned_saas(host)
            if vendor is None:
                return
            # If the host is already in the customer's runtime bypass
            # cache, the cert error has a different cause (corrupt
            # cert store, vendor cert rotation, etc.) -- skip and let
            # bypass_misconfiguration handle it.
            if host.lower() in set(summary.bypass_cache or []):
                return
            f = self._bucket(
                f"CERT_PINNED_SAAS__{vendor}",
                Severity.CRITICAL,
                f"SSL inspection breaking {vendor} (``{host}``)",
                (
                    f"ZCC's SSL inspection caused a handshake / cert "
                    f"failure against ``{host}`` -- a {vendor} "
                    f"endpoint. {vendor} pins its certificate (per "
                    f"Zscaler's own documentation, this app must be "
                    f"bypassed from SSL inspection), so interception "
                    f"breaks the user's experience.\n\n"
                    f"The host is NOT in the customer's runtime "
                    f"bypass cache.\n\n"
                    f"Fix: add the {vendor} endpoint to BLSSL bypass. "
                    f"For the broad fix, add the wildcard parent "
                    f"domain (e.g. ``*.outlook.office.com`` for "
                    f"Outlook). For the narrow fix, add just "
                    f"``{host}``.\n\n"
                    f"Per Zscaler's published 'Skipping Inspection "
                    f"of Traffic for Specific URLs or Cloud Apps' "
                    f"doc, this app belongs in the customer's default "
                    f"SSL-inspection-bypass policy. New tenants often "
                    f"forget this; mature tenants tend to have it "
                    f"already (the Example Tenant C calibration bundles "
                    f"show all of Microsoft 365 and Zoom bypassed)."
                ),
                sop_anchor="#cert-pinned-saas-inspection",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
