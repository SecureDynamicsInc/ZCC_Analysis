"""
Detector: macOS connectivity-probe false-negative.

Mac sibling of ``ncsi_false_negative`` (Windows). macOS uses a
different set of captive-portal / connectivity probes than Windows
NCSI, but the failure mode is identical: ZCC's SSL inspection
corrupts the probe response, the OS declares "no internet" or
"captive portal needed," and apps that gate behaviour on
connectivity state (Mail, Safari, App Store, system updates)
refuse to operate normally.

Documented probe domains (per Apple + Mozilla docs, confirmed via
Zscaler community discussions):

  - ``captive.apple.com`` -- the canonical macOS captive-portal
    probe. Apple's Captive Network Assistant fetches this URL
    expecting the literal body ``Success``.
  - ``detectportal.firefox.com`` -- Firefox's captive-portal probe
    (used by Firefox on all OSes, but especially relevant on Mac
    where Firefox is a common browser).
  - ``www.msftconnecttest.com`` -- Microsoft's connectivity probe
    used by Edge / Office apps on Mac (cross-platform; covered by
    the Windows ``ncsi_false_negative`` detector too, but the
    failure-mode on Mac is the same).

Signature: SSL handshake failure (or unexpected response) against
any of these hosts. Mac-gated via ``applies_to_os = ("macos",)``
since these probes are most-broken on Mac specifically (Windows
NCSI lives in ``ncsi_false_negative``).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


_MAC_PROBE_HOSTS = (
    "captive.apple.com",
    "www.apple.com",          # Apple's secondary connectivity probe
    "detectportal.firefox.com",
    "www.msftconnecttest.com",
    "ipv6.msftconnecttest.com",
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


def _is_mac_probe(host: str) -> Optional[str]:
    h = host.lower().rstrip(".")
    for p in _MAC_PROBE_HOSTS:
        if h == p:
            return p
    return None


EVIDENCE_CAP = 10


@register
class NcsiFalseNegativeMacDetector(IssueDetector):
    id = "ncsi_false_negative_mac"
    title = "macOS connectivity probe SSL failure"
    sop_file = "ncsi_false_negative_mac.md"
    # Cross-suite: macOS connectivity probe is OS-level. Affects all
    # ZCC suite enrollments equally.
    applies_to_suite = None
    applies_to_os = ("macos",)
    wants_tray_logs = True

    def __init__(self) -> None:
        super().__init__()
        self._thread_target: Dict[tuple, str] = {}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        self._check(record)

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        self._check(record)

    def _check(self, record: LogLine) -> None:
        msg = record.message
        key = (record.pid, record.tid)

        m_host = _RE_HOST_LINE.search(msg)
        if m_host:
            probe = _is_mac_probe(m_host.group("host"))
            if probe is not None:
                self._thread_target[key] = m_host.group("host")

        if _RE_SSL_FAIL.search(msg):
            target = self._thread_target.get(key)
            if target is None:
                return
            probe = _is_mac_probe(target)
            if probe is None:
                return
            f = self._bucket(
                "MAC_CONNECTIVITY_PROBE_SSL_FAIL",
                Severity.WARNING,
                (
                    f"Mac connectivity probe ``{target}`` hit SSL "
                    f"inspection"
                ),
                (
                    f"ZCC's SSL inspection caused a handshake / cert "
                    f"failure against ``{target}``, a macOS "
                    f"connectivity probe endpoint. macOS uses these "
                    f"probes to decide whether the network is "
                    f"online, requires captive-portal sign-in, or "
                    f"is offline. When the probe response is "
                    f"corrupted by SSL interception, macOS may show "
                    f"a captive-portal sign-in window even on a "
                    f"normal corporate network, or apps that consult "
                    f"connectivity state (Mail, App Store, system "
                    f"updates, Office for Mac) refuse to operate "
                    f"normally.\n\n"
                    f"Fix: add the macOS connectivity-probe hosts "
                    f"to the customer's BLSSL bypass list:\n"
                    f"  * ``captive.apple.com``\n"
                    f"  * ``www.apple.com``\n"
                    f"  * ``detectportal.firefox.com``\n"
                    f"  * ``*.msftconnecttest.com``\n\n"
                    f"In ZIA, there's a built-in URL category called "
                    f"``Captive Portal`` that bundles these hosts -- "
                    f"add the category to BLSSL rather than "
                    f"individual hosts for maintainability."
                ),
                sop_anchor="#mac-connectivity-probe-ssl-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
