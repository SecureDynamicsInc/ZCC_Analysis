"""
Detector: ZPA App Segment is missing Active Directory service-discovery
DNS records.

This condition has a specific signature that neither
``zpa_dns_check_not_found`` nor ``zpa_broker_assistant_close`` alone can
identify:

  1. **The DC/file-server A records DO resolve via the broker** (e.g.
     ``dc01.corp.example.com`` returns a CGNAT IP successfully).
  2. **The AD service-discovery SRV records DO NOT resolve** — they hit
     ``ZPN_ERR_DNS_CHECK_NO_ASSISTANT`` (err_code 3002), meaning no
     App Connector is configured to serve those names. Examples:
       * ``_kerberos._tcp.dc._msdcs.<domain>``
       * ``_kerberos._tcp.<site>._sites.dc._msdcs.<domain>``
       * ``_ldap._tcp.<domain>``, ``_ldap._tcp.dc._msdcs.<domain>``
       * ``_gc._tcp.<domain>``, ``_kpasswd._udp.<domain>``
  3. Because Kerberos discovery fails, Windows either fails ticket
     acquisition or falls back to NTLM. With modern Windows 11 SMB
     signing requirements and GPO-restricted NTLM, the SMB
     SESSION_SETUP fails and the App Connector RSTs every ``:445``
     tunnel with ``BRK_MT_CLOSED_FROM_ASSISTANT`` (err_code 5027).

So the SYMPTOM is 100-1000s of ``BRK_MT_CLOSED_FROM_ASSISTANT`` events on
the DC/file-server, but the ROOT CAUSE is a missing ZPA App Segment for
the AD service-discovery names, ~10 DNS lookups earlier in the log.

This detector fires CRITICAL when it sees ``ZPN_ERR_DNS_CHECK_NO_ASSISTANT``
on ANY name matching AD service-discovery patterns (``_kerberos._*``,
``_ldap._*``, ``_gc._*``, ``_kpasswd._*``, or ``*._msdcs.*``). This is
extremely specific — those DNS names are only ever queried by Windows'
domain-joined authentication stack, so seeing them fail through ZPA is
diagnostic of an incomplete App Segment.

Fires WARNING (informational) if only WPAD or benign names hit
NO_ASSISTANT — those are noise on many enterprises.

The detector correlates failed AD service-discovery lookups with subsequent
SMB sessions that close during the session-setup window.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# ZPN_ERR_DNS_CHECK_NO_ASSISTANT with the queried name + type extracted
# in one regex pass. The JSON keys can arrive in different orders, so
# the pattern is intentionally loose about internal separators.
_RE_NO_ASSISTANT = re.compile(
    r'"zpn_dns_client_check"\s*:\s*\{[^{}]*?'
    r'"name"\s*:\s*"(?P<name>[^"]+)"'
    r'[^{}]*?'
    r'"type"\s*:\s*"(?P<type>[A-Z]+)"'
    r'[^{}]*?'
    r'"error"\s*:\s*"ZPN_ERR_DNS_CHECK_NO_ASSISTANT"',
    re.IGNORECASE,
)

# Names that are DIAGNOSTIC of an AD service-discovery gap. If any of
# these appear with NO_ASSISTANT, we know Windows can't get a Kerberos
# ticket and the customer's SMB / GPO / Autodiscover / any-domain-auth
# app is going to be broken.
#
# Match on ANY of:
#   _kerberos._{tcp,udp}.*
#   _ldap._{tcp,udp}.*
#   _gc._{tcp,udp}.*
#   _kpasswd._{tcp,udp}.*
#   *._msdcs.*         (root, PDC lookup, forest-wide DC lookups)
_RE_AD_SERVICE = re.compile(
    r"^_(kerberos|ldap|gc|kpasswd)\._(tcp|udp)\."
    r"|^[^.]*\._msdcs\.",
    re.IGNORECASE,
)

# Domain root A-record probe (e.g. Windows queries `corp.example.com`
# as part of discovery) — treated as a supporting signal, not primary.
def _looks_like_domain_root(name: str, ad_domains: Set[str]) -> bool:
    return name.lower() in ad_domains


# Cap on evidence lines carried in each finding (matches the framework
# default; explicit here so the intent is visible).
EVIDENCE_CAP = 20


def _extract_ad_domain(srv_name: str) -> Optional[str]:
    """Return the AD domain portion of an AD-service-discovery FQDN.

    ``_kerberos._tcp.dc._msdcs.corp.example.com`` → ``corp.example.com``
    ``_ldap._tcp.site._sites.corp.example.com`` → ``corp.example.com``
    ``_ldap._tcp.<guid>.domains._msdcs.corp.example.com`` → ``corp.example.com``
    ``dc01.corp.example.com`` (non-AD-shaped) → None

    Algorithm: walk labels right-to-left, stop when we hit an
    underscore-prefixed label OR the literal ``_msdcs`` / ``_sites`` /
    ``domains`` (which are AD structure markers, not domain parts).
    The remaining right-hand labels are the AD domain.
    """
    if not _RE_AD_SERVICE.match(srv_name):
        return None
    labels = srv_name.strip(".").split(".")
    keep: List[str] = []
    for lbl in reversed(labels):
        low = lbl.lower()
        if low.startswith("_") or low in {"_msdcs", "_sites", "domains", "dc"}:
            break
        keep.insert(0, lbl)
    return ".".join(keep) if keep else None


@register
class ZpaMissingAdSrvSegmentDetector(IssueDetector):
    id = "zpa_missing_ad_srv_segment"
    title = "ZPA App Segment missing Active Directory SRV records"
    sop_file = "zpa_missing_ad_srv_segment.md"
    applies_to_suite = ("zpa",)
    # Every match requires the literal error token, so the multiplexer
    # can cheaply skip ~99% of records via this substring pre-filter.
    prematch_substrings = ("ZPN_ERR_DNS_CHECK_NO_ASSISTANT",)

    def __init__(self) -> None:
        super().__init__()
        # Per-domain aggregation
        # ad_domain → {service_name: count of failures}
        self._ad_failures: Dict[str, Counter[str]] = defaultdict(Counter)
        # ad_domain → set of query types (SRV, A, ...) that failed
        self._ad_types: Dict[str, Set[str]] = defaultdict(set)
        # Full list of failing name→count for the description (non-AD
        # names too — worth surfacing for completeness).
        self._all_failures: Counter[str] = Counter()
        # Sample records for evidence
        self._sample_records: List[LogLine] = []
        # Distinct AD-service names we've seen fail (for the summary)
        self._ad_service_names: Set[str] = set()

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        for m in _RE_NO_ASSISTANT.finditer(msg):
            name = m.group("name").lower().rstrip(".")
            qtype = m.group("type").upper()
            self._all_failures[name] += 1

            if _RE_AD_SERVICE.match(name):
                domain = _extract_ad_domain(name) or "(unknown-ad-domain)"
                self._ad_failures[domain][name] += 1
                self._ad_types[domain].add(qtype)
                self._ad_service_names.add(name)

            if len(self._sample_records) < EVIDENCE_CAP:
                self._sample_records.append(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        if not self._all_failures:
            return []

        findings: List[Finding] = []

        # CRITICAL finding: AD service-discovery gap detected.
        if self._ad_failures:
            n_ad_failures = sum(
                sum(c.values()) for c in self._ad_failures.values()
            )
            n_distinct = len(self._ad_service_names)
            domain_list = sorted(self._ad_failures.keys())

            # Build a per-domain breakdown for the description
            domain_blocks: List[str] = []
            for dom in domain_list:
                names = self._ad_failures[dom]
                per = "\n".join(
                    f"    - ``{n}`` ({c}x)"
                    for n, c in names.most_common()
                )
                types = ", ".join(sorted(self._ad_types[dom]))
                domain_blocks.append(
                    f"  * **{dom}** ({types}):\n{per}"
                )
            blocks_str = "\n".join(domain_blocks)

            f = Finding(
                code="ZPA_AD_SRV_SEGMENT_MISSING",
                severity=Severity.CRITICAL,
                title=(
                    f"AD service-discovery DNS records not covered "
                    f"by any ZPA App Segment "
                    f"({n_distinct} distinct name(s), "
                    f"{n_ad_failures} total failure(s) across "
                    f"{len(domain_list)} domain(s))"
                ),
                description=(
                    "The ZPA broker returned ``ZPN_ERR_DNS_CHECK_NO_"
                    "ASSISTANT`` (err_code 3002) for Active Directory "
                    "service-discovery DNS records — meaning no App "
                    "Connector on this tenant is configured to serve "
                    "those names. Without Kerberos / LDAP SRV records, "
                    "domain-joined Windows clients cannot get a "
                    "Kerberos ticket for internal servers, which "
                    "typically manifests as SMB share failures, slow "
                    "GPO processing, Outlook Autodiscover errors, and "
                    "Explorer hangs when accessing ``\\\\dc-hostname\\"
                    "share``.\n\n"
                    "Missing AD service-discovery records per domain:\n"
                    f"{blocks_str}\n\n"
                    "This is almost always a ZPA App Segment gap. The "
                    "customer's admin has correctly added the specific "
                    "server hostnames but forgot to add the "
                    "service-discovery layer. Standard remediation is "
                    "either a ``*.<ad-domain>`` wildcard segment with "
                    "AD ports (TCP 88, 135, 389, 445, 464, 636, 3268, "
                    "3269; UDP 88, 123, 389, 464) OR a dedicated "
                    "segment listing the ``_kerberos._*``, "
                    "``_ldap._*``, ``_gc._*``, ``_kpasswd._*`` names. "
                    "See SOP for both options."
                ),
                sop_anchor="#zpa-missing-ad-srv-segment",
            )
            for rec in self._sample_records:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        # Optional INFO for non-AD NO_ASSISTANT (WPAD, one-off probes).
        # We already accounted for AD names above; subtract them from
        # the total to see if anything else is worth surfacing.
        non_ad_total = sum(
            c for name, c in self._all_failures.items()
            if name not in self._ad_service_names
        )
        if non_ad_total > 0 and not self._ad_failures:
            # Only emit the INFO finding when there's NO critical
            # AD-service finding — otherwise it's just noise beneath
            # the critical one.
            other_names = [
                (n, c) for n, c in self._all_failures.most_common()
                if n not in self._ad_service_names
            ]
            names_block = "\n".join(
                f"  * ``{n}`` ({c}x)" for n, c in other_names[:10]
            )
            f = Finding(
                code="ZPA_DNS_NO_ASSISTANT_MISC",
                severity=Severity.INFO,
                title=(
                    f"{non_ad_total} non-AD ``NO_ASSISTANT`` DNS "
                    f"check(s) ({len(other_names)} distinct name(s))"
                ),
                description=(
                    "The ZPA broker returned ``NO_ASSISTANT`` for "
                    "these DNS names but they do not match Active "
                    "Directory service-discovery patterns. Frequently "
                    "benign (WPAD lookups, one-off probes), but if "
                    "any of these names correspond to internal apps "
                    "the customer expects to reach through ZPA, add "
                    "them to an App Segment.\n\n"
                    f"Top names:\n{names_block}"
                ),
                sop_anchor="#zpa-missing-ad-srv-segment",
            )
            for rec in self._sample_records[:5]:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        return findings
