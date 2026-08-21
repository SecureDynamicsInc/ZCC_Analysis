"""
Detector: RMM agent cert pinning failures.

Same shape as ``ai_cli_pin`` but for Remote Monitoring & Management
(RMM) tooling endpoints. RMM agents pin their certificates because
they're the customer's privileged-access channel; intercepting them
breaks management ops, often catastrophically.

Grounded by:
- an anonymized internal case (Example Tenant E Datto). observed: adding
  Amazon S3 East URL to file-type control to allow Datto-style RMM
  payloads through.
- an anonymized internal case (Example Tenant F Datto Unanet block).
  Prior narrative captured a PDF block on Datto/Unanet traffic.
- Cross-customer: this pattern is the second-most-common "Zscaler
  broke our tooling" report after AI tooling.

Signature shape mirrors ``ai_cli_pin``: SSL handshake fail on a
tunnel-log thread whose most recent ``Host=...`` line names a host in
the RMM vendor catalogue.

Distinct policy surface from AI: the SOP recommends adding to the
appropriate FILE TYPE CONTROL exception (for download channels) in
addition to BLSSL bypass -- some RMM agents push large binary
payloads that hit MIME-based blocks separately from SSL inspection.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# RMM vendor catalogue. Endsswith match against host. Update when
# customers report new vendors.
_RMM_DOMAINS = (
    # Datto (now Kaseya-owned) — Datto RMM agents talk to centrastage
    "centrastage.net",
    "datto.com",
    "autotask.net",
    "rmm.datto.com",
    # Kaseya VSA
    "kaseya.com",
    "kaseyaplus.com",
    "kaseya.net",
    "vsa.kaseya.com",
    # NinjaOne (formerly NinjaRMM)
    "ninjarmm.com",
    "ninjastage.com",
    "ninjaone.com",
    # ConnectWise Automate (formerly LabTech)
    "labtechsoftware.com",
    "connectwise.com",
    "automate.connectwise.com",
    # N-able (formerly SolarWinds MSP)
    "n-able.com",
    "solarwindsmsp.com",
    # Atera
    "atera.com",
    "ateraagent.com",
    # ITSM-adjacent
    "syncromsp.com",
    "level.io",
    "pulseway.com",
    # Generic Microsoft Intune endpoints (similar pinning behavior
    # though Intune is broader than "RMM"). Include only the agent-
    # specific subdomains.
    "manage.microsoft.com",
    "azureedge.net",   # intune content delivery
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


def _is_rmm_host(host: str) -> Optional[str]:
    h = host.lower().rstrip(".")
    for d in _RMM_DOMAINS:
        if h == d or h.endswith("." + d):
            return d
    return None


EVIDENCE_CAP = 10


@register
class RmmAgentPinDetector(IssueDetector):
    id = "rmm_agent_pin"
    title = "RMM agent cert pinning failures"
    sop_file = "rmm_agent_pin.md"
    # Cross-suite: RMM-agent pinning breaks at any SSL-inspection
    # layer; either ZIA or ZPA can trigger the symptom.
    applies_to_suite = None

    def __init__(self) -> None:
        super().__init__()
        self._thread_last_rmm_host: Dict[tuple, str] = {}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        key = (record.pid, record.tid)

        m_host = _RE_HOST_LINE.search(msg)
        if m_host:
            rmm = _is_rmm_host(m_host.group("host"))
            if rmm is not None:
                self._thread_last_rmm_host[key] = m_host.group("host")

        if _RE_SSL_FAIL.search(msg):
            target = self._thread_last_rmm_host.get(key)
            if target is None:
                return
            rmm = _is_rmm_host(target)
            if rmm is None:
                return
            f = self._bucket(
                f"RMM_AGENT_PIN__{rmm}",
                Severity.CRITICAL,
                f"SSL inspection breaking RMM agent ``{target}``",
                (
                    f"ZCC's SSL inspection caused a handshake / cert "
                    f"failure against ``{target}``, an endpoint in "
                    f"the detector's RMM agent catalogue (matched "
                    f"``{rmm}``). RMM agents pin their certificates "
                    f"because they're the customer's privileged-"
                    f"access channel; interception breaks management "
                    f"ops, often silently.\n\n"
                    f"Two policy edits usually needed:\n"
                    f"  1. **BLSSL bypass**: add ``*.{rmm}`` to the "
                    f"BLSSL list so ZCC stops inspecting the "
                    f"endpoint. Use star wildcard form, not leading "
                    f"dot.\n"
                    f"  2. **File Type Control exception** (Example Tenant E "
                    f"pattern): RMM agents push binary payloads "
                    f"(installers, scripts, telemetry zips). If a "
                    f"customer's File Type Control rule blocks the "
                    f"MIME types, add the RMM endpoint URLs or "
                    f"S3/blob-storage CDN ranges to the exception. "
                    f"Example Tenant E's observed fix added Amazon S3 East "
                    f"URLs to bypass for Datto-style payloads.\n\n"
                    f"Severity is CRITICAL because RMM ops are how "
                    f"the customer's MSP restores services -- "
                    f"breaking it can cascade into a multi-customer "
                    f"outage."
                ),
                sop_anchor="#rmm-agent-pin",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
