"""
network_error RCA synthesizer (Phase 49f, 2026-06-24).

Maps the 6 NETERR_* finding codes from network_error detector to
Root Cause buckets matching the official Zscaler runbook's Network
Error -8 categories.

Finding code → bucket:
  NETERR_HOST_NOT_FOUND    → dns          (DNS resolution failed)
  NETERR_CONNECTION_RESET  → conn_reset   (TCP RST mid-handshake)
  NETERR_NO_ROUTE          → no_route     (routing table doesn't have path)
  NETERR_NET_UNREACHABLE   → no_network   (adapter down / no DHCP)
  NETERR_CERT_VALIDATION   → cert         (certificate validation failed)
  NETERR_SSL_EXCEPTION     → cert         (SSL exception — same family as cert)
"""

from __future__ import annotations

from datetime import timezone
from typing import Any, Dict, List, Optional

from ..model import (
    ContributingFactor, Evidence, EvidenceStrength, EventClassification,
    FixHorizon, FixRecommendation, ImpactMetric, OpenQuestion,
    RootCause, TimelineEvent,
)
from ..synthesizer_base import RCASynthesizer


_BUCKETS = {
    "NETERR_HOST_NOT_FOUND": "dns",
    "NETERR_CONNECTION_RESET": "conn_reset",
    "NETERR_NO_ROUTE": "no_route",
    "NETERR_NET_UNREACHABLE": "no_network",
    "NETERR_CERT_VALIDATION": "cert",
    "NETERR_SSL_EXCEPTION": "cert",
}


def _bucket_for_code(code: str) -> str:
    return _BUCKETS.get((code or "").upper(), "other")


class NetworkErrorSynthesizer(RCASynthesizer):
    synthesizer_id = "network_error"
    synthesizer_version = "1.0"
    issue_title = "Network Error (errorMessage from keepAlive)"

    def __init__(self, summary, findings, correlators):
        super().__init__(summary, findings, correlators)
        self._buckets: Dict[str, List] = {}
        for f in self.findings:
            b = _bucket_for_code(getattr(f, "code", "") or "")
            self._buckets.setdefault(b, []).append(f)

    def _build_timeline(self) -> List[TimelineEvent]:
        result = []
        for f in self.findings:
            tr = getattr(f, "time_range", None)
            if not tr or tr[0] is None:
                continue
            ts_local = tr[0]
            try:
                ts_utc = ts_local.astimezone(timezone.utc)
            except (TypeError, ValueError):
                ts_utc = ts_local
            duration = None
            if tr[1] is not None:
                duration = (tr[1] - tr[0]).total_seconds()
            # Phase 58e-H6 (2026-07-08): network_error findings don't
            # inherently tell us whether the user was actively working at
            # the moment the tunnel broke — we'd need Modern-Standby /
            # foreground-app correlation. Default to UNKNOWN; other
            # correlators (power_change, foreground_app) can enrich this
            # later. Prior code unconditionally tagged every event as
            # MID_WORK, which over-escalated background blips.
            classification = EventClassification.UNKNOWN
            result.append(TimelineEvent(
                ts_local=ts_local,
                ts_utc=ts_utc,
                classification=classification,
                recovery_seconds=duration,
                tunnel_impact=getattr(f, "title", "")
                              or getattr(f, "code", ""),
            ))
        result.sort(key=lambda e: e.ts_local)
        return result

    def _build_summary(self) -> List[str]:
        if not self.findings:
            return ["No network_error findings emitted for this bundle."]
        n = len(self.findings)
        bucket_names = list(self._buckets.keys())
        paras = [
            f"The network_error detector emitted **{n} finding(s)** "
            f"across these categories: `{', '.join(bucket_names)}`."
        ]
        if "no_network" in self._buckets or "no_route" in self._buckets:
            paras.append(
                "**Network-layer failure** detected — the device had no "
                "underlying connectivity (adapter down, no DHCP, no "
                "default route). ZCC cannot establish a tunnel without "
                "a working network. Diagnose at the OS networking layer "
                "first."
            )
        if "dns" in self._buckets:
            paras.append(
                "**DNS resolution failure** for ZCC's service edges. "
                "Could be: local DNS server unreachable, DNS server "
                "blocking the Zscaler hostname (rare), or a captive "
                "portal intercepting DNS."
            )
        if "cert" in self._buckets:
            paras.append(
                "**Certificate validation failure** — a middlebox is "
                "intercepting TLS to a Zscaler service edge, OR the "
                "client's CA bundle is stale, OR clock skew is invalidating "
                "the cert. All three look the same in the log."
            )
        if "conn_reset" in self._buckets:
            paras.append(
                "**TCP RST mid-handshake** — something between the client "
                "and the SME is killing the TCP connection. Typically a "
                "stateful firewall that doesn't recognise Zscaler edge "
                "subnets, or QoS / DPI dropping packets selectively."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes = []
        n = 0

        for bucket_key, title, mech in [
            ("no_network", "No underlying network connectivity",
             "The device's network adapter is down, DHCP didn't lease, "
             "or all default routes are missing. Verify with "
             "``ipconfig`` / ``ifconfig`` and ``route print``. ZCC has "
             "no path forward until basic connectivity returns."),
            ("no_route", "No route to Zscaler edges",
             "The OS routing table has no path to the assigned SME "
             "subnets. This is typically a misconfigured VPN client "
             "that's stealing the default route, or static routes "
             "pointing at unreachable next-hops."),
            ("dns", "DNS resolution failed for Zscaler hostnames",
             "ZCC could not resolve its assigned service-edge hostnames. "
             "Verify with ``nslookup gateway.<cloud>.net`` on the "
             "affected device. Common causes: DNS server unreachable, "
             "DNS blocking by upstream firewall, captive portal "
             "intercepting DNS."),
            ("cert", "TLS certificate validation failed",
             "ZCC's TLS handshake to a service edge was rejected on "
             "cert validation. Three indistinguishable causes (in "
             "decreasing order of frequency): (1) a middlebox is "
             "intercepting TLS and presenting its own cert; (2) the "
             "client's CA bundle is stale; (3) device clock is skewed "
             "outside the cert validity window."),
            ("conn_reset", "TCP RST mid-handshake",
             "The TCP connection to the SME was reset before completion. "
             "A stateful firewall or DPI device on the path is killing "
             "the connection. Often vendor-specific signatures (Zscaler "
             "edge subnets get classified as 'unknown' by some firewalls)."),
        ]:
            if bucket_key in self._buckets:
                n += 1
                bucket = self._buckets[bucket_key]
                ev = []
                for f in bucket[:1]:
                    for rec in (getattr(f, "evidence", []) or [])[:2]:
                        ev.append(Evidence(
                            text=(getattr(rec, "raw", None)
                                  or rec.message or "").strip()[:200],
                            strength=EvidenceStrength.DIRECT_QUOTE,
                            source_file=(rec.source_path.name
                                         if hasattr(rec.source_path, "name")
                                         else None),
                            ts=getattr(rec, "timestamp", None),
                        ))
                causes.append(RootCause(
                    id=f"RC-{n}", title=title, mechanism=mech, evidence=ev,
                ))
        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        return []

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        if not self.findings:
            return []
        return [
            ImpactMetric("Total network_error findings", str(len(self.findings))),
            ImpactMetric("DNS failures", str(len(self._buckets.get("dns", [])))),
            ImpactMetric("No-network failures", str(len(self._buckets.get("no_network", [])))),
            ImpactMetric("No-route failures", str(len(self._buckets.get("no_route", [])))),
            ImpactMetric("Certificate failures", str(len(self._buckets.get("cert", [])))),
            ImpactMetric("TCP RST events", str(len(self._buckets.get("conn_reset", [])))),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes = []
        if "no_network" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="User / IT support",
                title="Restore basic network connectivity",
                body="Diagnose at the OS networking layer:",
                bullets=[
                    "Check adapter state (Wi-Fi enabled? Ethernet plugged in?)",
                    "Confirm DHCP leased an IP (ipconfig / ifconfig)",
                    "Default route exists (route print / netstat -rn)",
                ],
            ))
        if "dns" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="User / IT support",
                title="Resolve DNS issue",
                body="Test DNS on the affected device:",
                bullets=[
                    "nslookup gateway.zscaler.net (or the cloud-specific hostname)",
                    "If fails: try another DNS server (8.8.8.8) to isolate local-DNS issue",
                    "Check for captive portal intercepting DNS (suspicious if every name resolves to same IP)",
                ],
            ))
        if "cert" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="ZCC admin / network admin",
                title="Identify which of the 3 cert-failure causes is active",
                body="Distinguish:",
                bullets=[
                    "Middlebox interception — connect from a different network; if cert error disappears, it's the original network's middlebox",
                    "Stale CA bundle — verify Zscaler root CAs are present in the OS trust store",
                    "Clock skew — `w32tm /query /status` on Windows; sync NTP if off by >5 min",
                ],
            ))
        if "conn_reset" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Customer network admin",
                title="Investigate TCP RST source",
                body="The customer's stateful firewall or DPI device is likely the source. Provide them:",
                bullets=[
                    "The destination IPs ZCC was trying to reach (in the findings evidence)",
                    "Zscaler's published SME subnet ranges",
                    "Ask them to allowlist outbound to those subnets without DPI",
                ],
            ))
        if "no_route" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="IT support",
                title="Fix the routing table",
                body=(
                    "Check for: a third-party VPN client that's stolen "
                    "the default route, manually-added static routes "
                    "pointing at dead next-hops, or misconfigured "
                    "split-tunneling."
                ),
            ))
        return fixes

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if "cert" in self._buckets:
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    "Does the customer operate any TLS-inspecting "
                    "middlebox (Palo Alto, Forcepoint, etc.) on the "
                    "affected network?"
                ),
            ))
        if "conn_reset" in self._buckets:
            questions.append(OpenQuestion(
                id="Q2",
                question=(
                    "What firewall / IDS / DPI products are between the "
                    "affected device and the internet?"
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no network_error findings"
        if "no_network" in self._buckets or "no_route" in self._buckets:
            return "High — basic connectivity broken, ZCC cannot function"
        if "cert" in self._buckets:
            return f"High — cert validation failures ({len(self._buckets['cert'])} finding(s))"
        if "dns" in self._buckets:
            return f"High — DNS failures ({len(self._buckets['dns'])} finding(s))"
        return f"Medium — {len(self.findings)} network_error finding(s)"
