"""
ZDX-vs-ZPA catalog drift cross-reference (Phase 42b, 2026-06-19).

Originally drafted as a streaming detector but pivoted to a post-
extractor function because the inputs (Phase 42a ZDX telemetry +
existing extract_zpa_apps output) are populated AFTER ``run_detectors``
finishes. Called from ``ui/analyse.py`` once both data sources are
available — the result Findings is appended to the analyse output.

Logic (verified against Example Tenant A bundle 2026-06-18):

  - Pull the set of ZDX-monitored hosts from
    ``bundle_meta["zdx_telemetry"].monitored_urls`` (Phase 42a).
  - Pull the ZPA app catalog from
    ``bundle_meta["zpa_apps"]["apps"]`` (existing zpa_apps.py).
  - For each ZDX-monitored host that's *internal*
    (.local / .internal / .corp / .intra / .lan / .home / etc.) and
    NOT in the ZPA catalog, flag the drift.
  - SaaS / public-TLD hosts are intentionally NOT flagged — those
    reach via ZIA, not ZPA, and shouldn't be in the ZPA catalog.

Severity:

  - CRITICAL when the drift is corroborated by either of:
      * ZDX traceroute couldn't resolve the host's IP
        (has_unresolved_ip == True), OR
      * The ZPA broker logged ``BRK_MT_SETUP_FAIL_NO_POLICY_FOUND``
        for an app whose name matches the host
  - WARNING when the host is in ZDX but absent from ZPA without
    concrete break-evidence (might be reachable via DIRECT routing).

Example Tenant A bundle ground truth: 3 synthetic internal hosts
(filesvc-a / filesvc-b / appsvc-a
.corp-a.example) all confirmed CRITICAL — 0% ZDX availability,
unresolved traceroute, AND broker NO_POLICY_FOUND for each.
"""

from __future__ import annotations

from typing import Any, List

from . import Finding, Findings, Severity
from ..summary import BundleSummary


# Internal-domain TLD suffixes that indicate "should be a ZPA app
# segment" hosts. Conservative — public TLDs are excluded so SaaS
# apps don't false-positive.
_INTERNAL_TLDS = (
    ".local", ".internal", ".corp", ".intra", ".lan", ".home",
    ".lcl", ".private", ".ad",
)


def _is_internal_host(host: str) -> bool:
    if not host:
        return False
    return host.lower().rstrip(".").endswith(_INTERNAL_TLDS)


def _is_in_catalog(host: str, catalog_domains: List[str]) -> bool:
    """Catalog match: exact OR suffix on a label boundary. The ZPA
    catalog stores entries as bare FQDNs, ``*.<domain>`` wildcards,
    SRV records, and CIDR blocks; this helper handles the FQDN +
    wildcard cases."""
    if not host or not catalog_domains:
        return False
    h = host.lower().rstrip(".")
    norm = set()
    for d in catalog_domains:
        if not d:
            continue
        d = d.lower().lstrip("*.").lstrip(".").rstrip(".")
        if d:
            norm.add(d)
    if h in norm:
        return True
    parts = h.split(".")
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in norm:
            return True
    return False


def _catalog_from_meta(summary: BundleSummary) -> List[str]:
    """Pull ZPA app-catalog domains out of summary.bundle_meta."""
    bm = getattr(summary, "bundle_meta", {}) or {}
    raw = bm.get("zpa_apps") or {}
    if isinstance(raw, dict):
        apps = raw.get("apps") or []
    elif isinstance(raw, list):
        apps = raw
    else:
        return []
    out: List[str] = []
    for a in apps:
        d = getattr(a, "app_domain", None)
        if d is None and isinstance(a, dict):
            d = a.get("app_domain") or a.get("domain")
        if d:
            out.append(str(d))
    return out


def _broker_no_policy_hosts(summary: BundleSummary) -> set:
    """Set of hostnames for which the ZPA broker emitted
    ``BRK_MT_SETUP_FAIL_NO_POLICY_FOUND``. Best-effort: relies on
    zpa_sessions carrying ``ack_error`` + ``app_name``."""
    bm = getattr(summary, "bundle_meta", {}) or {}
    sessions = bm.get("zpa_sessions") or []
    hosts: set = set()
    for s in sessions:
        err = getattr(s, "ack_error", "") or ""
        if "NO_POLICY_FOUND" in err:
            app = getattr(s, "app_name", "") or ""
            if app:
                hosts.add(app.lower())
    return hosts


def _describe_critical(hits: List[str], catalog_size: int) -> str:
    return (
        "BundleScope cross-referenced the ZDX-monitored host list "
        "(from `upm_webload` and `upm_traceroute` SQLite telemetry) "
        f"against the ZPA Application Segment catalog "
        f"({catalog_size} segments). The hosts below are "
        "ZDX-monitored AND **confirmed broken** (ZDX traceroute "
        "couldn't resolve, OR the ZPA broker rejected setup with "
        "`BRK_MT_SETUP_FAIL_NO_POLICY_FOUND`). This pattern is the "
        "textbook \"app exists in ZDX dashboard but customer forgot "
        "to add an Application Segment\" misconfiguration.\n\n"
        "Affected hosts:\n\n"
        + "\n".join(f"- {h}" for h in hits)
        + "\n\n**Action**: in the ZPA admin UI, create an "
        "Application Segment covering each affected host (with the "
        "right ports — RDP 3389, SMB 445, etc, based on what the "
        "customer uses). Confirm a Segment Group is assigned to a "
        "healthy App Connector group, and that the user's group has "
        "access via Policy."
    )


def _describe_warning(hits: List[str], catalog_size: int) -> str:
    return (
        "BundleScope's cross-reference found internal host(s) that "
        "are ZDX-monitored but absent from the ZPA app catalog "
        f"({catalog_size} segments). Unlike the CRITICAL variant of "
        "this finding, BundleScope did NOT see ZDX traceroute or "
        "ZPA broker errors confirming these are broken — they may "
        "be reachable via DIRECT (non-tunneled) routing or via a "
        "different path.\n\nAffected hosts:\n\n"
        + "\n".join(f"- {h}" for h in hits)
        + "\n\n**Action**: confirm whether each host should be "
        "tunneled via ZPA. If yes, add an Application Segment. If "
        "intentionally direct, document the bypass so a future "
        "engineer doesn't reopen this finding."
    )


def _run_drift_check(summary: BundleSummary) -> List[Finding]:
    """Core cross-reference. Returns 0, 1, or 2 Finding objects
    (CRITICAL and/or WARNING). Empty if either data source is
    unavailable or no drift detected."""
    bm = getattr(summary, "bundle_meta", {}) or {}
    telemetry = bm.get("zdx_telemetry")
    if telemetry is None:
        return []
    monitored = getattr(telemetry, "monitored_urls", None) or []
    if not monitored:
        return []
    catalog_domains = _catalog_from_meta(summary)
    if not catalog_domains:
        return []

    critical_hits: List[str] = []
    warning_hits: List[str] = []
    broker_no_policy = _broker_no_policy_hosts(summary)

    for u in monitored:
        host = getattr(u, "host", "")
        if not host:
            continue
        if not _is_internal_host(host):
            continue
        if _is_in_catalog(host, catalog_domains):
            continue
        unresolved = getattr(u, "has_unresolved_ip", False)
        avail = getattr(u, "availability_pct", None)
        samples = getattr(u, "sample_count", 0)
        broker_failures = host.lower() in broker_no_policy
        label_bits = [f"`{host}`", f"{samples} ZDX webload sample(s)"]
        if avail is not None:
            label_bits.append(f"avail={avail:.0f}%")
        if unresolved:
            label_bits.append("ZDX traceroute couldn't resolve")
        if broker_failures:
            label_bits.append(
                "ZPA broker emitted "
                "BRK_MT_SETUP_FAIL_NO_POLICY_FOUND"
            )
        entry = " — ".join(label_bits)
        if unresolved or broker_failures:
            critical_hits.append(entry)
        else:
            warning_hits.append(entry)

    findings: List[Finding] = []
    if critical_hits:
        findings.append(Finding(
            code="ZDX_ZPA_CATALOG_DRIFT_CRITICAL",
            severity=Severity.CRITICAL,
            title=(
                f"ZDX monitors {len(critical_hits)} internal host(s) "
                "missing from ZPA catalog AND confirmed broken"
            ),
            description=_describe_critical(
                critical_hits, len(catalog_domains),
            ),
            count=len(critical_hits),
            sop_anchor="#critical-drift-with-confirmed-failures",
        ))
    if warning_hits:
        findings.append(Finding(
            code="ZDX_ZPA_CATALOG_DRIFT_WARNING",
            severity=Severity.WARNING,
            title=(
                f"ZDX monitors {len(warning_hits)} internal host(s) "
                "not in the ZPA app catalog"
            ),
            description=_describe_warning(
                warning_hits, len(catalog_domains),
            ),
            count=len(warning_hits),
            sop_anchor="#warning-drift-without-confirmed-failure",
        ))
    return findings


def derive_catalog_drift_findings(summary: BundleSummary) -> Findings:
    """Public entry: returns a ``Findings`` container the caller
    appends to the analyse output's findings list."""
    return Findings(
        issue_id="zdx_zpa_catalog_drift",
        issue_title="ZDX-monitored hosts missing from ZPA app catalog",
        sop_path=None,
        findings=_run_drift_check(summary),
    )


# Phase 43g (2026-06-24): removed the tombstone ZdxZpaCatalogDriftDetector
# class. The real logic is post_extractor `derive_catalog_drift_findings`
# above; the tombstone was leftover from a brief Phase 42b experiment
# with a streaming detector that never panned out. Registry now lives
# in `issues.POST_EXTRACTORS` and `ui/analyse.py` iterates it.
