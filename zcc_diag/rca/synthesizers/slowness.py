"""
slowness RCA synthesizer (Phase 49h, 2026-06-24).

The slowness detector emits a small number of code types but the
underlying analysis is rich — it aggregates DTLS fallback rates, DNS
elapsed times, probe RTTs, PMTU events, TLS handshakes, retransmits,
plus ZDX traceroute/webload/app_health/edge_probe summaries.

Finding code → bucket:
  SLOWNESS_SIGNALS       → signals       (aggregate slowness with detail in description)
  CPT_EVENT_DETECTED     → cpt_event     (Cloud Performance Test context — INFO only)
  ZTRACEROUTE_NOT_COLLECTED → gating     (ZDX data missing entirely; can't analyse)
  other                  → other

The synthesizer reads bundle_meta keys (ztraceroute_health, app_health,
edge_probes, zdx_webloads) to enrich the RCA when SLOWNESS_SIGNALS
fires, citing per-leg degradation (underlay vs zen vs server) when
the data is available.
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


def _bucket_for_code(code: str) -> str:
    code = (code or "").upper()
    if code == "SLOWNESS_SIGNALS":
        return "signals"
    if code == "CPT_EVENT_DETECTED":
        return "cpt_event"
    if code == "ZTRACEROUTE_NOT_COLLECTED":
        return "gating"
    return "other"


class SlownessSynthesizer(RCASynthesizer):
    synthesizer_id = "slowness"
    synthesizer_version = "1.0"
    issue_title = "Performance / Slowness Signals"

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
            code = (getattr(f, "code", "") or "").upper()
            # Phase 58e-H6 (2026-07-08): slowness findings are neither an
            # IdP reauth nor a session sever — misusing
            # IDP_FORCED_REAUTH here poisoned the tray-legend counts on
            # any bundle that had a slowness finding. UNKNOWN is the
            # correct neutral default; SLOWNESS_SIGNALS keeps its
            # foreground-blip label because degraded UX is the whole
            # point.
            classification = EventClassification.UNKNOWN
            if code == "SLOWNESS_SIGNALS":
                # Slowness affects user experience but doesn't sever
                # sessions — closer to the "background blip" category
                # in user-impact terms.
                classification = EventClassification.POST_STANDBY_FOREGROUND_BLIP
            result.append(TimelineEvent(
                ts_local=ts_local, ts_utc=ts_utc,
                classification=classification,
                recovery_seconds=duration,
                tunnel_impact=getattr(f, "title", "") or code,
            ))
        result.sort(key=lambda e: e.ts_local)
        return result

    def _build_summary(self) -> List[str]:
        if not self.findings:
            return ["No slowness signals emitted for this bundle."]
        if "gating" in self._buckets:
            return [
                "**ZTraceroute not collected.** The customer's app profile "
                "does NOT have Diagnostic Route Collection enabled, so the "
                "best slowness signal (per-hop loss + latency) is missing "
                "entirely. The slowness analysis below uses only the "
                "secondary signals (DTLS fallback, TLS handshake, "
                "retransmits, webload TTFB) which are less conclusive."
            ]
        n = len(self.findings)
        bucket_names = list(self._buckets.keys())
        paras = [
            f"The slowness detector emitted **{n} finding(s)** across "
            f"these buckets: `{', '.join(bucket_names)}`."
        ]
        if "signals" in self._buckets:
            paras.append(
                "**Slowness signals detected** — the detector aggregated "
                "multiple per-signal observations (DTLS fallback, DNS "
                "elapsed, probe RTT, PMTU, TLS handshake, retransmits, "
                "ZDX trace/webload). The RC sections below summarise "
                "which sub-signals dominated; see the finding "
                "description in the Detected Issues view for the "
                "verbatim per-signal breakdown."
            )
        if "cpt_event" in self._buckets:
            paras.append(
                "**Cloud Performance Test context** — the user opened "
                "https://zscaler.com/test (or a similar test page) "
                "during the bundle window. The CPT_EVENT_DETECTED "
                "finding identifies which SMEs the test probes egressed "
                "through, so a screenshot from the user's CPT run can "
                "be matched to a specific moment in the bundle."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes = []
        n = 0
        bm = self.bm  # bundle_meta

        if "gating" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="Diagnostic Route Collection not enabled in App Profile",
                mechanism=(
                    "The slowness detector's primary signal is ZTraceroute "
                    "(per-hop loss + latency to each Zscaler DC). When "
                    "the app profile has Diagnostic Route Collection "
                    "DISABLED, no ZTraceroute file ends up in the "
                    "bundle. The detector can only fall back to "
                    "secondary signals (DTLS fallback, retransmits, "
                    "webload TTFB) which can suggest slowness but "
                    "cannot localise it to a network leg."
                ),
            ))
            # Without ZTraceroute, no further RCs can be confidently
            # named — return early.
            return causes

        if "signals" in self._buckets:
            n += 1
            # Pull per-leg verdict from app_health if available.
            app_health = bm.get("app_health") or []
            ztr_health = bm.get("ztraceroute_health") or []
            edge_probes = bm.get("edge_probes") or []

            sub_msgs = []
            if app_health:
                bad_apps = [
                    a for a in app_health
                    if (a.get("verdict") or "").lower() not in ("good", "ok", "healthy")
                ]
                if bad_apps:
                    sub_msgs.append(
                        f"{len(bad_apps)} of {len(app_health)} monitored "
                        "applications show degradation; the app_health "
                        "summary in the Network Path module identifies "
                        "WHICH LEG (underlay / zen / server) owns each."
                    )
            if ztr_health:
                worst = sorted(
                    ztr_health,
                    key=lambda h: -(h.get("loss_pct") or 0),
                )[:3]
                if worst and worst[0].get("loss_pct"):
                    sub_msgs.append(
                        f"Worst destination by loss: "
                        f"{worst[0].get('dest_label', '?')} "
                        f"at {worst[0].get('loss_pct', 0):.1f}% loss"
                    )
            if edge_probes:
                bad_edges = [
                    e for e in edge_probes
                    if not e.get("reachable", True)
                ]
                if bad_edges:
                    sub_msgs.append(
                        f"{len(bad_edges)} of {len(edge_probes)} edge "
                        "probes unreachable — service edge availability "
                        "issue."
                    )

            mechanism_text = (
                "The slowness detector raises SLOWNESS_SIGNALS when one "
                "or more secondary indicators exceed the configured "
                "thresholds. The Detected Issues finding description "
                "lists each contributing sub-signal with its measured "
                "value vs threshold. Common signals: DTLS fallback rate "
                ">10% (UDP path degraded), TLS handshake p95 >2s "
                "(certificate / RTT issue), TCP retransmit rate >2% "
                "(packet loss on the user's last mile), webload TTFB "
                ">5s (server-side latency, not Zscaler)."
            )
            if sub_msgs:
                mechanism_text += "\n\nFrom this bundle's ZDX data:\n- " + "\n- ".join(sub_msgs)

            causes.append(RootCause(
                id=f"RC-{n}",
                title="Multiple slowness signals exceeded thresholds",
                mechanism=mechanism_text,
            ))
        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        factors = []
        if "cpt_event" in self._buckets:
            n = len(self._buckets["cpt_event"])
            factors.append(ContributingFactor(
                id="CF-1",
                title=f"Cloud Performance Test ran during bundle window ({n} event(s))",
                body=(
                    "The user ran the CPT page — the resulting probes "
                    "are visible in ZTraceroute. Cross-reference any "
                    "screenshot the user captured against the SME IPs "
                    "in the CPT_EVENT_DETECTED finding to align the "
                    "test result with bundle data."
                ),
                is_hypothesis=False,
            ))
        return factors

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        if not self.findings:
            return []
        bm = self.bm
        app_health = bm.get("app_health") or []
        ztr_health = bm.get("ztraceroute_health") or []
        return [
            ImpactMetric("Total slowness findings", str(len(self.findings))),
            ImpactMetric(
                "Apps monitored (ZDX)", str(len(app_health))
            ),
            ImpactMetric(
                "ZTraceroute destinations", str(len(ztr_health))
            ),
            ImpactMetric(
                "Diagnostic Route Collection enabled?",
                "no — gating issue" if "gating" in self._buckets else "yes",
                highlight=("gating" in self._buckets),
            ),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes = []
        if "gating" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="ZCC admin",
                title="Enable Diagnostic Route Collection in App Profile",
                body=(
                    "Without ZTraceroute data, slowness diagnosis is "
                    "guesswork. Enable Diagnostic Route Collection on "
                    "the affected user's app profile and ask the user "
                    "to repro the slowness; capture a new bundle."
                ),
                effect=(
                    "Next bundle contains per-hop loss + latency data; "
                    "slowness can be localised to a network leg."
                ),
            ))
        if "signals" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Engineer / customer (per signal)",
                title="Address dominant sub-signal",
                body=(
                    "Open the SLOWNESS_SIGNALS finding in Detected "
                    "Issues — the description lists the dominant "
                    "sub-signal (e.g. \"DTLS fallback rate 32%\"). The "
                    "fix depends on which signal dominates:"
                ),
                bullets=[
                    "Frequent DTLS fallback → check for UDP 443 shaping on customer FW / ISP",
                    "High TCP retransmits → customer LAN / Wi-Fi / ISP issue (escalate to their network team)",
                    "TLS handshake p95 high → middlebox MITM or RTT to nearest SME is high",
                    "Webload TTFB high → server-side, NOT a Zscaler issue (point at the application vendor)",
                ],
            ))
        return fixes

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if "signals" in self._buckets and "gating" not in self._buckets:
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    "Which application or workflow does the user perceive "
                    "as slow? Slowness signals are aggregate — knowing "
                    "the specific application narrows the diagnosis."
                ),
            ))
            questions.append(OpenQuestion(
                id="Q2",
                question=(
                    "Has the user repro'd the slowness while running "
                    "the Cloud Performance Test (https://zscaler.com/test)? "
                    "If yes, the CPT screenshot + the bundle's "
                    "CPT_EVENT_DETECTED finding can be cross-referenced."
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no slowness findings"
        if "gating" in self._buckets:
            return "Medium — diagnosis gated by missing ZTraceroute data"
        if "signals" in self._buckets:
            return "Medium — slowness signals exceeded thresholds, see RC for breakdown"
        return f"Low — {len(self.findings)} slowness-related finding(s)"
