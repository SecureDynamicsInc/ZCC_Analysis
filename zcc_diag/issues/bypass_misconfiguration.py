"""
Detector: Bypass-rule misconfiguration.

Customers regularly *think* they've bypassed a host from SSL inspection
but the entry doesn't actually match the traffic. This detector
catches the resulting cert errors and attributes them to specific
bypass-policy holes.

DATA-SOURCE NOTE (rewritten 2026-05-19 based on multi-bundle
calibration): the detector originally walked
``summary.forwarding_profile`` looking for bypass entries. Real
bundles confirmed that ``forwarding_profile`` contains ONLY the
TUNNEL transport-config JSON (35 timing / MTU / flag keys, no bypass
list at all). The actual runtime bypass policy lives in tunnel-log
``DBG DNS: Domain: <host> found in bypass cache`` lines, which
``summary.py`` now populates into ``summary.bypass_cache``. This
rewrite consumes that field instead.

The dot-vs-star format-mistake finding from the v1 design is dropped
here -- it required reading the actual PAC file / policy config to
detect, neither of which lives in the bundle. The same misconfiguration
will surface as ``GATEWAY_NOT_IN_BYPASS`` instead (because the runtime
bypass cache never contains hosts that the leading-dot entry was meant
to cover -- the entry never matched anything).

Signature shape: a stream of ``Auth::Lib::certificateErroCallback:
Invalid certificate`` lines (note the verbatim typo `Erro`, preserved
across ZCC versions) for hosts that aren't actually in the bypass
cache. The detector emits:

  (a) ``GATEWAY_NOT_IN_BYPASS`` -- the failing host matches a known
      cert-pinning gateway catalogue but isn't in bypass_cache.
  (b) ``CERT_ERROR_HOST_NOT_BYPASSED`` -- failing host isn't in
      bypass_cache and isn't in the gateway catalogue.
  (c) ``BYPASS_CACHE_EMPTY`` -- bundle has cert errors AND an empty
      bypass cache (= bundle didn't capture enough traffic to populate
      it; detector can't be confident).

Distinct from other detectors:
  * ``endpoint_fw_av`` (Windows) watches infrastructure-level FW/AV
    blocks; this is policy-config layer.
  * ``tunnel_not_established`` watches the SSL-interception state
    transition; this attributes the cause to a specific bypass-list
    gap the customer needs to fix.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# The runbook-verified cert-callback line. Verbatim typo "Erro" is
# preserved -- DO NOT "fix" it; it's how ZCC emits the line.
_RE_CERT_ERROR_CALLBACK = re.compile(
    r"Auth::Lib::certificateErroCallback:\s*Invalid certificate",
    re.IGNORECASE,
)

# Same shape but the secondary phrasing some ZCC versions emit. Both
# resolve to the same finding code; we just need to catch both.
_RE_CERT_VALIDATION_ERROR = re.compile(
    r"Certificate validation error", re.IGNORECASE,
)

# Earlier-on-the-same-thread context line giving the target host.
# ZCC writes ``ID=<id>, ... Host=<hostname>(:port)`` -- we extract the
# host to feed back to the cert-error correlation.
_RE_CONN_HOST = re.compile(
    r"\bHost=(?P<host>[A-Za-z0-9.\-]+)(?::\d+)?",
)

EVIDENCE_CAP = 10


# Known cert-pinning gateways / SSO / partner endpoints. When one of
# these hosts hits an SSL error and isn't in the customer's bypass
# list, it's almost always a "gateway not in bypass" finding. List is
# curated from the customer-grounding sweep -- only entries with 2+
# customer corroborations are included.
_GATEWAY_PINS = (
    "agent.jumpcloud.com",
    "connect.jumpcloud.com",
    "*.simplepractice.com",
    "*.ariba.com",
    "*.smartsupplier.ariba.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "azuredevops.microsoft.com",
    "*.azurewebsites.net",
)


# --- Helpers ----------------------------------------------------------

def _matches_pin_catalogue(host: str) -> Optional[str]:
    """Return the matching pin entry if ``host`` matches a known cert-
    pinning gateway, else None."""
    h = host.lower().rstrip(".")
    for pin in _GATEWAY_PINS:
        p = pin.lower()
        if p.startswith("*."):
            if h.endswith(p[1:]):
                return pin
        elif h == p:
            return pin
    return None


# --- Detector ---------------------------------------------------------

@register
class BypassMisconfigurationDetector(IssueDetector):
    id = "bypass_misconfiguration"
    title = "Bypass rule looks present but isn't matching"
    sop_file = "bypass_misconfiguration.md"
    # Cross-suite: bypass-rule matching applies to both ZIA and ZPA
    # forwarding paths.
    applies_to_suite = None

    def __init__(self) -> None:
        super().__init__()
        # Per-thread (pid, tid) -> last Host= seen. Cert-error lines
        # rarely carry the host inline, so we walk the same-thread
        # context to attribute the error.
        self._thread_last_host: Dict[tuple, str] = {}
        # Records that hit a cert-error pattern, in order. Resolved
        # in finalize() once we have the full forwarding profile.
        self._cert_errors: List[LogLine] = []
        self._cert_errors_host: List[Optional[str]] = []

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # Update last-host-by-thread on every record that mentions a host.
        m_host = _RE_CONN_HOST.search(msg)
        if m_host:
            key = (record.pid, record.tid)
            self._thread_last_host[key] = m_host.group("host")

        # Cert error: stash for finalize().
        if (
            _RE_CERT_ERROR_CALLBACK.search(msg)
            or _RE_CERT_VALIDATION_ERROR.search(msg)
        ):
            key = (record.pid, record.tid)
            host = self._thread_last_host.get(key)
            self._cert_errors.append(record)
            self._cert_errors_host.append(host)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        if not self._cert_errors:
            return []

        # The runtime bypass set (built from ``Domain: <h> found in
        # bypass cache`` DBG lines during the tunnel-log scan).
        bypass_set = set(summary.bypass_cache or [])

        # Special case: if there are cert errors AND the bypass cache
        # is empty, the bundle didn't capture enough traffic to
        # populate it -- detector can't be confident either way.
        if not bypass_set:
            f = Finding(
                code="BYPASS_CACHE_EMPTY",
                severity=Severity.INFO,
                title=(
                    f"{len(self._cert_errors)} cert error(s) but bypass "
                    f"cache is empty — analysis inconclusive"
                ),
                description=(
                    f"This bundle has {len(self._cert_errors)} "
                    f"SSL cert-validation failures but no "
                    f"``DBG DNS: Domain: <host> found in bypass cache`` "
                    f"lines were captured. Either (a) the tunnel never "
                    f"reached steady state during the capture window "
                    f"(e.g. auth was failing the entire time -- check "
                    f"``zia_auth_failures`` / ``zpa_auth_failures`` / "
                    f"``tunnel_not_established``), or (b) ZCC's DEBUG "
                    f"logging level is suppressed for DNS. Without "
                    f"the runtime bypass cache, the detector can't "
                    f"determine whether each failing host is supposed "
                    f"to be bypassed. Capture a new bundle after the "
                    f"upstream issue is fixed."
                ),
                sop_anchor="#bypass-cache-empty",
            )
            for rec in self._cert_errors[:EVIDENCE_CAP]:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            return [f]

        for rec, host in zip(self._cert_errors, self._cert_errors_host):
            if host is None:
                # Cert error with no resolved host -- surface as a
                # generic finding so the operator still sees it.
                f = self._bucket(
                    "CERT_ERROR_UNATTRIBUTED",
                    Severity.WARNING,
                    "SSL cert validation failure (unattributed)",
                    (
                        "ZCC logged ``certificateErroCallback: Invalid "
                        "certificate`` but the failing host could not "
                        "be resolved from the surrounding thread "
                        "context. Investigate manually via the "
                        "correlation window."
                    ),
                    sop_anchor="#cert-error-unattributed",
                )
                f.add_evidence(rec, cap=EVIDENCE_CAP)
                continue

            h = host.lower().rstrip(".")

            # Case A: host IS in the runtime bypass cache. Then ZCC
            # was actually bypassing this host -- the cert error has
            # a different root cause (corrupt local cert store,
            # vendor cert rotation, etc.). Out of this detector's
            # scope; skip.
            if h in bypass_set:
                continue

            # Case B: host is NOT in bypass cache. Subcases:
            #   (i)  matches a known pinning gateway -> CRIT
            #   (ii) otherwise -> WARN
            pin = _matches_pin_catalogue(h)
            if pin is not None:
                f = self._bucket(
                    "GATEWAY_NOT_IN_BYPASS",
                    Severity.CRITICAL,
                    (
                        f"Cert-pinning gateway ``{host}`` is missing "
                        f"from the bypass list"
                    ),
                    (
                        f"``{host}`` matched the cert-pinning "
                        f"catalogue entry ``{pin}`` but the runtime "
                        f"bypass cache does NOT contain this host "
                        f"(or any pattern that would match it). ZCC "
                        f"is doing SSL interception against a "
                        f"cert-pinned endpoint.\n\n"
                        f"Fix: add ``{pin}`` (or the exact hostname) "
                        f"to the appropriate bypass policy -- BLSSL "
                        f"is the right home for cert-pinning "
                        f"endpoints. Common gateways: JumpCloud, "
                        f"Microsoft 365, Ariba, SimplePractice.\n\n"
                        f"If the customer thinks they ALREADY have a "
                        f"bypass entry for this host: it's likely a "
                        f"format issue (e.g. ``.host.com`` instead "
                        f"of ``*.host.com`` in a destination-IP-"
                        f"group rule). The runtime cache only "
                        f"contains hosts whose bypass entries "
                        f"actually matched, so a misformatted entry "
                        f"would leave its intended target absent "
                        f"from the cache -- which is what we're "
                        f"seeing now."
                    ),
                    sop_anchor="#gateway-not-in-bypass",
                )
                f.add_evidence(rec, cap=EVIDENCE_CAP)
                continue

            # Case 3: cert error against an unknown host that's not in
            # the bypass list. Surface at INFO so the operator can
            # consider adding it.
            f = self._bucket(
                "CERT_ERROR_HOST_NOT_BYPASSED",
                Severity.WARNING,
                (
                    f"Cert error against ``{host}`` (not in bypass list)"
                ),
                (
                    f"ZCC logged an SSL cert validation failure for "
                    f"``{host}``. This host is not in the customer's "
                    f"forwarding profile bypass list and not in the "
                    f"known cert-pinning catalogue. Either (a) add it "
                    f"to BLSSL if it's a legitimate cert-pinned "
                    f"endpoint, (b) replace the Zscaler intermediate "
                    f"cert on the endpoint, or (c) check whether the "
                    f"customer is using an obsolete pack file."
                ),
                sop_anchor="#cert-error-host-not-bypassed",
            )
            f.add_evidence(rec, cap=EVIDENCE_CAP)

        return list(self._buckets.values())
