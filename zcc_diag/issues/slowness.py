"""
Detector: slowness / performance degradation.

The original Zscaler runbook treats performance as a methodology-only
issue diagnosed by isolation (bypass test, direct-vs-tunneled compare,
ZDX scoring). This detector adds a log-grounded layer on top of that:
it consolidates the signals ZCC actually emits about slowness into a
single finding so an engineer doesn't have to scroll through six
different log kinds to find the picture.

Signals (gathered in ``feed()`` from tunnel logs + ``finalize()``
from pre-parsed ZDX data on ``summary.bundle_meta``):

  * **ZTraceroute "elbow" hop** — the hop where latency jumps most.
    Maps to a path segment:
      hops 1–3        ⇒ customer LAN / WiFi
      hops 3–7        ⇒ local ISP / regional transit
      hops 7–12       ⇒ Zscaler edge ingress
      beyond edge     ⇒ Zscaler back-end (rare; usually edge is hop ≈10)
  * **ZTraceroute unreachable hops** — runs of `*` responses, or
    final-hop no-reply, indicate path black-holes or packet filtering.
  * **DTLS → TLS fallback frequency** — UDP being shaped/dropped by
    something between the endpoint and the SME. Every fallback costs
    ~3-way handshake latency + reduces throughput meaningfully.
  * **zpn_dns_client_check elapsed_us** — the cloud-connectivity DNS
    check. Sustained values >50ms indicate a slow upstream resolver
    (typical bad-WiFi DNS or sinkhole on a SOHO router).
  * **Probe RTT** — Zen probe to the edge. Sustained excursions
    above the bundle's median by >2x indicate edge / capacity stress.
  * **Webload TTFB / total** — when ZDX webload telemetry is present,
    sustained TTFB >2s on the configured probe URLs strongly suggests
    server-side slowness (rather than network).
  * **PMTU / fragmentation events** — Path-MTU black-holing. Causes
    retransmits and "slow but eventually works" feel.

Scoring:
  * **CRIT** — 3+ strong signals, OR ZTraceroute elbow with delta >
    150ms in the customer-LAN/ISP range, OR DTLS-fallback rate
    > 5/hour sustained across the bundle window.
  * **WARN** — 2 signals, OR elbow delta 50–150ms, OR DTLS-fallback
    rate 2–5/hour, OR sustained TTFB >2s.
  * **INFO** — fallback when ZTraceroute is absent, telling the
    engineer to enable Diagnostic Route Collection in the app profile
    and re-export.

Thresholds are intentionally conservative on first release; tune them
against a real slow-bundle when one is available.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Substring anchors so the multiplexer cheap-dispatches lines that
# can't possibly match. ZSATunnel emits all these strings somewhere
# in the relevant records.
_PREMATCH = (
    "Falling back to TLS",      # DTLS fallback
    "Tunnel transport changed", # Transport changed to TLS
    "zpn_dns_client_check",     # DNS-check elapsed_us
    "Probe RTT",                # Edge probe RTT
    "PMTU",                     # Path-MTU discovery / black-holing
    "FragmentationNeeded",
    "fragmentation needed",
)

# Regex helpers. Cheap re.search calls -- only run after prematch.
_DTLS_FALLBACK = re.compile(
    r"Falling back to TLS|Tunnel transport changed to TLS",
    re.IGNORECASE,
)
_DNS_ELAPSED = re.compile(
    r"zpn_dns_client_check.*?elapsed_us[=:]\s*(?P<us>\d+)",
    re.IGNORECASE,
)
_PROBE_RTT = re.compile(
    r"Probe RTT[=:\s]+(?P<ms>[\d\.]+)\s*ms",
    re.IGNORECASE,
)
_PMTU = re.compile(
    r"PMTU\b|FragmentationNeeded|fragmentation needed",
    re.IGNORECASE,
)

# TLS handshake duration. Two phrasing variants seen in tunnel logs:
#   "SSL handshake completed in 247 ms"
#   "TLS handshake took 1.234 seconds"
#   "ssl_handshake_ms=247"
# All three normalize to milliseconds.
_TLS_HANDSHAKE_MS = re.compile(
    r"(?:SSL|TLS)\s+handshake\s+(?:completed\s+in|took)\s+"
    r"(?P<val>[\d.]+)\s*(?P<unit>ms|s|sec|second)",
    re.IGNORECASE,
)
_TLS_HANDSHAKE_KV = re.compile(
    r"(?:ssl|tls)_handshake_ms[=:]\s*(?P<ms>\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

# TCP retransmit signal — appears in some ZSAService log lines
# referencing socket state.
_RETRANSMIT = re.compile(
    r"\bretransmit(?:s|tion)?\b|retx[_ ]count[=:]\s*\d+",
    re.IGNORECASE,
)

# Path-segment classification thresholds (hop index -> path segment).
_PATH_SEGMENTS = (
    (3,  "customer LAN / WiFi"),
    (7,  "local ISP / regional transit"),
    (12, "Zscaler edge ingress"),
    (99, "Zscaler back-end"),
)


def _classify_path_segment(hop: int) -> str:
    for max_hop, label in _PATH_SEGMENTS:
        if hop <= max_hop:
            return label
    return "beyond known path"


# Severity thresholds. CRIT > WARN > 0 (silent).
_ELBOW_CRIT_MS = 150.0
_ELBOW_WARN_MS = 50.0
_DTLS_CRIT_PER_HOUR = 5.0
_DTLS_WARN_PER_HOUR = 2.0
_DNS_CRIT_US = 200_000   # 200 ms
_DNS_WARN_US = 50_000    # 50 ms
_TTFB_CRIT_MS = 5_000.0
_TTFB_WARN_MS = 2_000.0
_TOTAL_CRIT_MS = 10_000.0
_TOTAL_WARN_MS = 4_000.0


@register
class SlownessDetector(IssueDetector):
    id = "slowness"
    title = "Slowness / performance degradation"
    sop_file = "slowness.md"
    # Cross-suite: slowness can manifest on either suite's traffic
    # path. Detector emits suite-tagged findings via the signal source
    # (DTLS fallbacks are ZIA-side, ZTraceroute can be either, etc.).
    applies_to_suite = None
    prematch_substrings = _PREMATCH

    def __init__(self) -> None:
        super().__init__()
        # Phase 58e-C4 (2026-07-08): dtls fallback tracking split into
        # a bounded evidence sample AND an unbounded true count. Prior
        # code used len(self._dtls_fallbacks) as the total for the
        # rate calc — with the list capped at 20, bundles with 200
        # fallbacks/hour reported 20 and the _DTLS_CRIT_PER_HOUR
        # threshold was unreachable.
        self._dtls_fallbacks: List[LogLine] = []
        self._dtls_fallback_count: int = 0
        self._dns_elapsed_us: List[int] = []
        self._dns_evidence: List[LogLine] = []
        self._probe_rtt_ms: List[float] = []
        self._probe_evidence: List[LogLine] = []
        self._pmtu_count = 0
        self._pmtu_evidence: List[LogLine] = []
        # NEW (2026-06-12): TLS handshake durations and retransmit
        # counts — real bandwidth-degradation signal beyond the
        # methodology-only baseline.
        self._tls_handshake_ms: List[float] = []
        self._tls_evidence: List[LogLine] = []
        self._retransmit_count = 0
        self._retransmit_evidence: List[LogLine] = []
        # First and last timestamp seen so we can compute rates / hour.
        self._first_ts = None
        self._last_ts = None

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        ts = record.timestamp
        if self._first_ts is None or ts < self._first_ts:
            self._first_ts = ts
        if self._last_ts is None or ts > self._last_ts:
            self._last_ts = ts

        if _DTLS_FALLBACK.search(msg):
            self._dtls_fallback_count += 1
            if len(self._dtls_fallbacks) < 20:
                self._dtls_fallbacks.append(record)
            return
        m = _DNS_ELAPSED.search(msg)
        if m:
            try:
                self._dns_elapsed_us.append(int(m.group("us")))
                if len(self._dns_evidence) < 3:
                    self._dns_evidence.append(record)
            except ValueError:
                pass
            return
        m = _PROBE_RTT.search(msg)
        if m:
            try:
                self._probe_rtt_ms.append(float(m.group("ms")))
                if len(self._probe_evidence) < 3:
                    self._probe_evidence.append(record)
            except ValueError:
                pass
            return
        if _PMTU.search(msg):
            self._pmtu_count += 1
            if len(self._pmtu_evidence) < 3:
                self._pmtu_evidence.append(record)
            return

        # TLS handshake duration (two phrasings).
        m = _TLS_HANDSHAKE_MS.search(msg)
        if m:
            try:
                val = float(m.group("val"))
                unit = m.group("unit").lower()
                ms = val * 1000.0 if unit in ("s", "sec", "second") else val
                self._tls_handshake_ms.append(ms)
                if len(self._tls_evidence) < 3:
                    self._tls_evidence.append(record)
            except (ValueError, TypeError):
                pass
            return
        m = _TLS_HANDSHAKE_KV.search(msg)
        if m:
            try:
                self._tls_handshake_ms.append(float(m.group("ms")))
                if len(self._tls_evidence) < 3:
                    self._tls_evidence.append(record)
            except (ValueError, TypeError):
                pass
            return

        # TCP retransmit signal.
        if _RETRANSMIT.search(msg):
            self._retransmit_count += 1
            if len(self._retransmit_evidence) < 5:
                self._retransmit_evidence.append(record)
            return

    # -----------------------------------------------------------------

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        meta = summary.bundle_meta or {}
        traces: List[Dict[str, Any]] = meta.get("ztraceroute_traces") or []
        webloads: List[Dict[str, Any]] = meta.get("zdx_webloads") or []
        has_trace_file = meta.get("has_ztraceroute_file", False)
        ztr_health: List[Dict[str, Any]] = (
            meta.get("ztraceroute_health") or []
        )
        # NEW (correct) per-app per-leg data. Replaces ztr_health
        # for the DC-path scoring path -- see ``_score_zscaler_dc_path``
        # for why (raw per-hop RTT is misleading; leg latency is the
        # truth).
        app_health: List[Dict[str, Any]] = (
            meta.get("app_health") or []
        )

        # ---- Score each signal independently ----
        # PMTU scoring inlined below for the volume-threshold logic that
        # doesn't fit the (no-arg) pattern of the other scorers.
        pmtu_sig: Optional[Dict[str, Any]] = None
        if self._pmtu_count >= 3:
            sev = (
                Severity.WARNING if self._pmtu_count < 10
                else Severity.CRITICAL
            )
            pmtu_sig = {
                "label": "PMTU / fragmentation events",
                "severity": sev,
                "detail": (
                    f"{self._pmtu_count} PMTU / fragmentation events. "
                    f"Path-MTU black-holing on the customer's path; "
                    f"causes retransmits and 'slow but eventually works' "
                    f"feel. Lower mtuForZadapter to 1240 in the "
                    f"forwarding profile."
                ),
                "evidence": list(self._pmtu_evidence),
            }

        signals: List[Dict[str, Any]] = [
            s for s in (
                self._score_traceroute(traces),
                self._score_dtls_fallback(),
                self._score_dns(),
                self._score_probe(),
                pmtu_sig,
                self._score_webloads(webloads),
                self._score_zscaler_dc_path(app_health),
            ) if s
        ]

        # -- Build the final findings list --
        findings: List[Finding] = []

        if signals:
            # Severity = highest among contributing signals + bonus
            # rule: 3 or more contributing signals => CRIT.
            sev_rank = {
                Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2,
            }
            highest = max(signals, key=lambda s: sev_rank[s["severity"]])
            severity = highest["severity"]
            if len(signals) >= 3 and severity != Severity.CRITICAL:
                severity = Severity.CRITICAL

            title_bits = [s["label"] for s in signals]
            title = (
                f"Slowness — {len(signals)} signal(s) contributing: "
                + ", ".join(title_bits)
            )

            # Localize root cause via the trace signal if present.
            location_line = ""
            for s in signals:
                if s["label"].startswith("ZTraceroute"):
                    location_line = (
                        f"\nMost likely bottleneck location: "
                        f"**{s.get('path_segment', 'unknown segment')}**\n"
                    )
                    break

            desc = (
                f"Performance / slowness signals consolidated from tunnel "
                f"logs and ZDX telemetry.\n"
                f"{location_line}\n"
                + "\n".join(
                    f"  - **{s['label']}** ({s['severity'].value}): "
                    f"{s['detail']}"
                    for s in signals
                )
                + "\n\nTriage steps:\n"
                + "  1. Run a bypass test on the affected app — does the "
                "slowness persist when ZCC is bypassed? If yes, the "
                "bottleneck is downstream of ZCC.\n"
                + "  2. If ZTraceroute localized the bottleneck to the "
                "customer LAN/ISP, escalate to the customer's network "
                "team / ISP rather than Zscaler.\n"
                + "  3. If DTLS fallback is frequent, check for UDP "
                "shaping / QoS on the upstream path (corporate FW, ISP).\n"
                + "  4. If webload TTFB is dominant, the slowness is "
                "server-side — not a Zscaler issue."
            )

            f = Finding(
                code="SLOWNESS_SIGNALS",
                severity=severity,
                title=title,
                description=desc,
                sop_anchor="#slowness",
            )
            # Pull a few representative evidence lines.
            ev = []
            for s in signals:
                ev.extend(s.get("evidence") or [])
            for rec in ev[:15]:
                f.add_evidence(rec, cap=15)
            findings.append(f)

        # 6.5  Cloud Performance Test context. If the user ran the test
        # page during the bundle window, surface it as an INFO finding
        # so the engineer can correlate a screenshot to a moment in the
        # bundle. Pulled from bundle_meta (multiplexer preamble).
        cpt_events = meta.get("cpt_events") or []
        if cpt_events:
            # Group by DC so multiple events to the same DC become one
            # line in the description.
            by_dc: Dict[str, List[Dict[str, Any]]] = {}
            for ev in cpt_events:
                by_dc.setdefault(ev["dc_name"], []).append(ev)
            lines = []
            for dc, evs in sorted(by_dc.items()):
                first = min((e["first_seen"] for e in evs if e["first_seen"]),
                            default="(unknown)")
                last = max((e["last_seen"] for e in evs if e["last_seen"]),
                           default="(unknown)")
                ips = ", ".join(sorted({e["sme_ip"] for e in evs}))
                total = sum(e["probe_count"] for e in evs)
                lines.append(
                    f"  - **{dc}** ({ips}): {total} probes "
                    f"from {first} to {last}"
                )
            findings.append(Finding(
                code="CPT_EVENT_DETECTED",
                severity=Severity.INFO,
                title=(
                    f"Cloud Performance Test activity detected "
                    f"({len(cpt_events)} event(s))"
                ),
                description=(
                    "The user opened https://zscaler.com/test (or a "
                    "similar test page) during the bundle window. "
                    "ZTraceroute recorded probes egressing through these "
                    "SMEs:\n\n"
                    + "\n".join(lines)
                    + "\n\nUseful for matching a Cloud Performance Test "
                    "screenshot to a specific moment in the bundle — "
                    "the DC named on the test page should match one of "
                    "the above."
                ),
                sop_anchor="#cpt-event",
            ))

        # 7. Fallback INFO: ZTraceroute file missing entirely.
        if not has_trace_file:
            findings.append(Finding(
                code="ZTRACEROUTE_NOT_COLLECTED",
                severity=Severity.INFO,
                title=(
                    "ZTraceroute not present — best slowness signal is missing"
                ),
                description=(
                    "This bundle has no ``ztraceroute`` log file, which "
                    "means the customer's app profile does NOT have "
                    "**Diagnostic Route Collection** enabled. Without "
                    "ZTraceroute the slowness detector can only fall "
                    "back to secondary signals (DTLS fallback, DNS "
                    "elapsed, probe RTT, PMTU) — these can tell you "
                    "something is slow, but they cannot localize WHERE "
                    "in the network path the latency lives.\n\n"
                    "Action:\n"
                    "  1. In Mobile Admin, open the customer's App "
                    "Profile and enable **Diagnostic Route Collection** "
                    "(under ZCC Settings).\n"
                    "  2. Have the customer reproduce the slowness with "
                    "the flag on.\n"
                    "  3. Re-export the support bundle.\n"
                    "  4. Re-run this analysis.\n\n"
                    "The ZTraceroute file will let the detector localize "
                    "the elbow (the hop where most latency accumulates) "
                    "to one of: customer LAN, local ISP, Zscaler edge "
                    "ingress, or Zscaler back-end — turning 'app feels "
                    "slow' into an actionable network-team escalation."
                ),
                sop_anchor="#ztraceroute-missing",
            ))

        # NEW (2026-06-12): TLS handshake + retransmit + RTT inflation
        # signals. These score independently and may fire alongside the
        # ZTraceroute / DTLS / DNS findings above.

        # TLS handshake duration scoring.
        if len(self._tls_handshake_ms) >= 3:
            sorted_ms = sorted(self._tls_handshake_ms)
            median_ms = sorted_ms[len(sorted_ms) // 2]
            p95_ms = sorted_ms[int(len(sorted_ms) * 0.95)]
            # Heuristic thresholds: >500ms p95 = WARN, >1500ms = CRIT.
            # Healthy TLS handshakes are 80-200ms; persistent >500ms
            # indicates broker congestion OR routing detour OR
            # cipher-negotiation issue.
            if p95_ms > 1500.0:
                sev = Severity.CRITICAL
            elif p95_ms > 500.0:
                sev = Severity.WARNING
            else:
                sev = None
            if sev is not None:
                f = self._bucket(
                    "SLOWNESS_TLS_HANDSHAKE_INFLATED",
                    sev,
                    f"TLS handshake p95 = {p95_ms:.0f}ms "
                    f"(median {median_ms:.0f}ms)",
                    f"TLS handshake durations are persistently slow. "
                    f"Median: {median_ms:.0f}ms; p95: {p95_ms:.0f}ms; "
                    f"samples: {len(sorted_ms)}. Healthy is "
                    f"80-200ms. >500ms p95 indicates congestion "
                    f"on the broker path, cipher renegotiation, or "
                    f"a MITM doing SSL inspection of *.zscaler.net. "
                    f"Verify SSL bypass rules for Zscaler "
                    f"infrastructure.",
                    sop_anchor=None,
                )
                for rec in self._tls_evidence:
                    f.add_evidence(rec, cap=10)
                findings.append(f)

        # TCP retransmit scoring. Threshold based on volume; counts
        # are typically O(1-3) on healthy bundles, O(20+) on bandwidth-
        # constrained links.
        if self._retransmit_count >= 20:
            sev = Severity.CRITICAL
        elif self._retransmit_count >= 5:
            sev = Severity.WARNING
        else:
            sev = None
        if sev is not None:
            f = self._bucket(
                "SLOWNESS_TCP_RETRANSMITS",
                sev,
                f"{self._retransmit_count} TCP retransmit event(s)",
                f"Sustained TCP retransmit signal. {self._retransmit_count} "
                f"events. Retransmits cap effective throughput and "
                f"compound on the tunnel — every retransmit on the "
                f"underlying TCP-T1 path also retransmits the "
                f"encapsulated payload. Common causes: bandwidth-"
                f"constrained uplink (DSL/hotspot), packet-loss MTU "
                f"mismatch (cross-check with PMTU finding above), "
                f"or NIC driver under stress (cross-check with "
                f"adapter_instability).",
                sop_anchor=None,
            )
            for rec in self._retransmit_evidence:
                f.add_evidence(rec, cap=10)
            findings.append(f)

        # RTT inflation: split probe RTTs into first half / second
        # half of the bundle window. If the second half median is
        # 2x+ the first half median (and we have enough samples on
        # both sides), the connection is degrading over time.
        rtts = self._probe_rtt_ms
        if len(rtts) >= 10:
            mid = len(rtts) // 2
            first_half = sorted(rtts[:mid])
            second_half = sorted(rtts[mid:])
            if first_half and second_half:
                first_median = first_half[len(first_half) // 2]
                second_median = second_half[len(second_half) // 2]
                # Only fire when first half had non-trivial RTT (avoid
                # divide-by-near-zero on lab bundles); 5ms floor.
                if first_median >= 5.0 and second_median >= first_median * 2.0:
                    sev = (
                        Severity.CRITICAL
                        if second_median >= first_median * 4.0
                        else Severity.WARNING
                    )
                    f = self._bucket(
                        "SLOWNESS_RTT_DEGRADING",
                        sev,
                        f"Probe RTT degrading over the bundle window "
                        f"({first_median:.0f}ms -> {second_median:.0f}ms)",
                        f"Probe round-trip time has degraded over the "
                        f"bundle window. Median in the first half: "
                        f"{first_median:.0f}ms; second half: "
                        f"{second_median:.0f}ms ({second_median / first_median:.1f}x "
                        f"increase). Indicates progressive network "
                        f"congestion, the user moving to a slower "
                        f"network, or a routing change pushing traffic "
                        f"over a longer path. Cross-reference with "
                        f"network_transitions; if many transitions "
                        f"happened mid-window, the user changed "
                        f"networks.",
                        sop_anchor=None,
                    )
                    for rec in self._probe_evidence[:5]:
                        f.add_evidence(rec, cap=10)
                    findings.append(f)

        return findings

    # --- per-signal scorers ------------------------------------------

    def _score_traceroute(
        self, traces: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not traces:
            return None
        # Pick the trace with the largest elbow delta as representative.
        worst = max(
            traces,
            key=lambda t: t.get("elbow_delta_ms") or 0.0,
        )
        delta = worst.get("elbow_delta_ms") or 0.0
        elbow_hop = worst.get("elbow_hop")
        unreach = worst.get("unreachable_count") or 0
        # No interesting trace data?
        if delta < _ELBOW_WARN_MS and unreach < 3:
            return None
        if delta >= _ELBOW_CRIT_MS or unreach >= 3:
            sev = Severity.CRITICAL
        else:
            sev = Severity.WARNING
        path_segment = (
            _classify_path_segment(elbow_hop) if elbow_hop else "unknown"
        )
        dst = (
            worst.get("destination_host")
            or worst.get("destination_ip")
            or "(unknown)"
        )
        detail = (
            f"ZTraceroute to {dst}: elbow at hop {elbow_hop} "
            f"(+{delta:.0f}ms vs. prior hop), {unreach} unreachable hop(s). "
            f"Median path RTT max: {worst.get('max_rtt_ms', 0):.0f}ms. "
            f"Bottleneck localizes to **{path_segment}** "
            f"(based on hop-index → path-segment mapping)."
        )
        return {
            "label": "ZTraceroute elbow",
            "severity": sev,
            "detail": detail,
            "evidence": [],
            "path_segment": path_segment,
        }

    def _score_dtls_fallback(self) -> Optional[Dict[str, Any]]:
        if not self._dtls_fallbacks:
            return None
        # Phase 58e-C4 (2026-07-08): use uncapped counter, not len(list).
        count = self._dtls_fallback_count
        hours = self._bundle_window_hours() or 1.0
        rate = count / hours
        if rate < _DTLS_WARN_PER_HOUR and count < 3:
            return None
        sev = (
            Severity.CRITICAL if rate >= _DTLS_CRIT_PER_HOUR
            else Severity.WARNING
        )
        return {
            "label": "DTLS → TLS fallback",
            "severity": sev,
            "detail": (
                f"{count} DTLS fallback event(s) over "
                f"~{hours:.1f}h ({rate:.1f}/hour). UDP is being "
                f"shaped/dropped between the endpoint and the SME — "
                f"check for corporate FW UDP rate-limit, ISP UDP "
                f"throttling, or aggressive QoS."
            ),
            "evidence": list(self._dtls_fallbacks[:5]),
        }

    def _score_dns(self) -> Optional[Dict[str, Any]]:
        if not self._dns_elapsed_us:
            return None
        # Use 90th percentile as the headline.
        vals = sorted(self._dns_elapsed_us)
        p90 = vals[int(0.9 * (len(vals) - 1))]
        median = vals[len(vals) // 2]
        if p90 < _DNS_WARN_US:
            return None
        sev = (
            Severity.CRITICAL if p90 >= _DNS_CRIT_US
            else Severity.WARNING
        )
        return {
            "label": "zpn_dns_client_check latency",
            "severity": sev,
            "detail": (
                f"Cloud-connectivity DNS check elapsed median "
                f"{median/1000:.1f}ms / p90 {p90/1000:.1f}ms across "
                f"{len(vals)} probes. Sustained values above 50ms "
                f"indicate a slow upstream resolver — typical bad-WiFi "
                f"DNS or SOHO-router DNS sinkhole. Try forcing ZCC's "
                f"DNS to a known-good resolver via app profile."
            ),
            "evidence": list(self._dns_evidence),
        }

    def _score_probe(self) -> Optional[Dict[str, Any]]:
        if len(self._probe_rtt_ms) < 5:
            # Not enough data points to score reliably.
            return None
        vals = sorted(self._probe_rtt_ms)
        median = vals[len(vals) // 2]
        p90 = vals[int(0.9 * (len(vals) - 1))]
        # Excursion = p90 / median.
        if median == 0:
            return None
        excursion = p90 / median
        # Flag if excursion > 2x AND p90 > 100ms.
        if excursion < 2.0 or p90 < 100.0:
            return None
        sev = (
            Severity.CRITICAL if (excursion >= 3.0 and p90 >= 200.0)
            else Severity.WARNING
        )
        return {
            "label": "Edge probe RTT excursion",
            "severity": sev,
            "detail": (
                f"Zen edge probe RTT median {median:.0f}ms / p90 "
                f"{p90:.0f}ms ({excursion:.1f}x excursion) across "
                f"{len(vals)} probes. Edge path capacity or hot-spot "
                f"issue — verify by trying an alternate SME if the "
                f"customer's cloud has multiple edges in their region."
            ),
            "evidence": list(self._probe_evidence),
        }

    def _score_webloads(
        self, webloads: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not webloads:
            return None
        # Look at TTFB and total.
        ttfbs = [w["ttfb_ms"] for w in webloads if w.get("ttfb_ms")]
        totals = [w["total_ms"] for w in webloads if w.get("total_ms")]
        if not ttfbs and not totals:
            return None
        bits = []
        sev = Severity.INFO
        # NOTE: Severity is a str Enum -- DON'T compare values via max()
        # (alphabetical "WARNING" > "INFO" but "CRITICAL" < "INFO"!).
        # Use the explicit rank dict already used in finalize().
        sev_rank_local = {
            Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2,
        }

        def _upgrade(current, candidate):
            return (
                candidate
                if sev_rank_local[candidate] > sev_rank_local[current]
                else current
            )

        if ttfbs:
            ttfb_p90 = sorted(ttfbs)[int(0.9 * (len(ttfbs) - 1))]
            if ttfb_p90 >= _TTFB_CRIT_MS:
                sev = _upgrade(sev, Severity.CRITICAL)
                bits.append(
                    f"TTFB p90 {ttfb_p90:.0f}ms (server-side slowness)"
                )
            elif ttfb_p90 >= _TTFB_WARN_MS:
                sev = _upgrade(sev, Severity.WARNING)
                bits.append(f"TTFB p90 {ttfb_p90:.0f}ms")
        if totals:
            total_p90 = sorted(totals)[int(0.9 * (len(totals) - 1))]
            if total_p90 >= _TOTAL_CRIT_MS:
                sev = _upgrade(sev, Severity.CRITICAL)
                bits.append(f"page total p90 {total_p90:.0f}ms")
            elif total_p90 >= _TOTAL_WARN_MS:
                sev = _upgrade(sev, Severity.WARNING)
                bits.append(f"page total p90 {total_p90:.0f}ms")
        if not bits:
            return None
        urls = sorted({w["url"] for w in webloads})[:3]
        return {
            "label": "Webload page-load slowness",
            "severity": sev,
            "detail": (
                f"ZDX webload: {', '.join(bits)} across "
                f"{len(webloads)} probe(s) to {', '.join(urls)}"
                f"{' (and others)' if len(urls) < len(webloads) else ''}. "
                f"High TTFB with low DNS/TCP/TLS indicates the "
                f"slowness is server-side, NOT a Zscaler problem."
            ),
            "evidence": [],
        }

    def _score_zscaler_dc_path(
        self, app_health: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Score per-app reachability based on the NEW app-centric
        ``app_health`` data. Names the offending LEG explicitly:
        underlay / client→Zscaler / Zscaler→app.

        This replaces an older implementation that read
        ``ztraceroute_health`` (raw per-hop max RTT, which can be
        falsely inflated by intermediate-hop ICMP rate limiting). The
        new data uses ZCC's per-leg ``latency`` field which is
        adjusted for hop-dependency artefacts and is the truth.

        Thresholds, per leg, after the MTR engine's adjustment:
          * CRIT: leg loss ≥ 5% OR leg latency ≥ 200ms
          * WARN: leg loss 1–5% OR leg latency 100–200ms
        """
        if not app_health:
            return None
        bad_apps: List[Dict[str, Any]] = []
        worst_sev = Severity.INFO
        sev_rank = {Severity.INFO: 0, Severity.WARNING: 1,
                    Severity.CRITICAL: 2}
        for r in app_health:
            if r.get("verdict") == "ok":
                continue
            row_sev = (
                Severity.CRITICAL if r["verdict"] == "bad"
                else Severity.WARNING
            )
            bad_apps.append({"row": r, "sev": row_sev})
            if sev_rank[row_sev] > sev_rank[worst_sev]:
                worst_sev = row_sev

        if not bad_apps:
            return None

        lines = []
        for entry in bad_apps:
            r = entry["row"]
            mark = "CRIT" if entry["sev"] == Severity.CRITICAL else "WARN"
            tunneling = (
                f"via {r['sme_dc']}" if r.get("sme_dc")
                else ("via Zscaler" if r.get("via_zscaler") else "direct")
            )
            # Per-leg breakdown
            leg_bits = []
            for lbl, lat_key, loss_key in [
                ("underlay",
                 "underlay_latency_median_ms",
                 "underlay_loss_median_pct"),
                ("client→Zscaler",
                 "zen_latency_median_ms",
                 "zen_loss_median_pct"),
                ("Zscaler→app",
                 "server_latency_median_ms",
                 "server_loss_median_pct"),
            ]:
                lat = r.get(lat_key)
                loss = r.get(loss_key)
                if lat is None and loss is None:
                    continue
                pieces = []
                if lat is not None:
                    pieces.append(f"{lat:.0f}ms")
                if loss is not None and loss >= 0:
                    pieces.append(f"{loss:.1f}% loss")
                leg_bits.append(f"{lbl} {'/'.join(pieces)}")
            lines.append(
                f"{mark} **{r['app_name']}** ({tunneling}): "
                f"{' · '.join(leg_bits)} — {r['verdict_reason']}"
            )

        return {
            "label": "App reachability degraded",
            "severity": worst_sev,
            "detail": (
                f"{len(bad_apps)} of {len(app_health)} measured "
                "application(s) show degraded reachability. The "
                "offending leg is named in each verdict so you know "
                "WHICH part of the path is at fault:\n    "
                + "\n    ".join(lines)
                + "\n\n  **Per-leg interpretation:**\n"
                "    - `underlay` slow/lossy → local network or ISP\n"
                "    - `client→Zscaler` slow/lossy → transit network "
                "between the ISP and the Zscaler edge\n"
                "    - `Zscaler→app` slow/lossy → Zscaler backbone or "
                "destination-side issue"
            ),
            "evidence": [],
        }

    def _bundle_window_hours(self) -> Optional[float]:
        if self._first_ts is None or self._last_ts is None:
            return None
        delta = (self._last_ts - self._first_ts).total_seconds() / 3600.0
        return delta if delta > 0 else None
