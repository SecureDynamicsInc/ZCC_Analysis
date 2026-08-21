"""
tunnel_not_established RCA synthesizer (Phase 49b, 2026-06-24).

Second synthesizer, after Phase 49a's zpa_reauth_loop. Validates that
the framework scales: same pattern, different finding shapes.

tunnel_not_established is the detector for ZCC's tunnel state machine
issues — when the ZIA or ZPA tunnel doesn't reach TUNNEL_FORWARDING
(or flaps in/out of it). Finding codes the synthesizer recognises:

  LOCAL_NETWORK_DOWN           — adapter / DNS / route issues stopping ZCC from reaching service edges
  SME_FAILURE_COUNT_HIGH       — service edge unreachable from the client
  {svc}_TUNNEL_DOWN_{state}    — state machine spent time in a non-FORWARDING state
                                  (e.g., ZIA_TUNNEL_DOWN_FAILED, ZPA_TUNNEL_DOWN_CONNECTING)
  ZEVENT_*                     — zcc_zia_* / zcc_zpa_* / t2_to_t1_fallback events
  SSL_INTERCEPTION             — middlebox doing TLS interception on the tunnel
  DTLS_TO_TLS_FALLBACK         — UDP blocked, DTLS unavailable, fell back to TLS over TCP

The synthesizer classifies the findings into Root Cause buckets and
emits one RootCause per active bucket. Fix recommendations are tailored
to which buckets fired.
"""

from __future__ import annotations

from datetime import timezone
from typing import Any, Dict, List, Optional

from ..model import (
    ContributingFactor,
    Evidence,
    EvidenceStrength,
    EventClassification,
    FixHorizon,
    FixRecommendation,
    ImpactMetric,
    OpenQuestion,
    RootCause,
    TimelineEvent,
    VerificationStep,
)
from ..synthesizer_base import RCASynthesizer


# Map detector finding codes → root cause bucket. A single bundle can
# fire several buckets simultaneously (e.g., LOCAL_NETWORK_DOWN +
# SME_FAILURE_COUNT_HIGH typically appear together when the upstream
# network is broken).
_RC_BUCKETS = {
    "LOCAL_NETWORK_DOWN": "local_network",
    "SME_FAILURE_COUNT_HIGH": "sme_unreachable",
    "SSL_INTERCEPTION": "middlebox",
    "DTLS_TO_TLS_FALLBACK": "fallback",
    "T2_TO_T1_FALLBACK": "fallback",
}


def _bucket_for_code(code: str) -> str:
    """Map a finding code to a Root Cause bucket. Handles the
    {svc}_TUNNEL_DOWN_{state} pattern."""
    if code in _RC_BUCKETS:
        return _RC_BUCKETS[code]
    if code.endswith("_TUNNEL_DOWN_FAILED"):
        return "state_machine_failed"
    if "_TUNNEL_DOWN_" in code:
        return "state_machine_flap"
    if code.startswith("ZEVENT_"):
        return "zevent"
    return "other"


class TunnelNotEstablishedSynthesizer(RCASynthesizer):
    """RCA synthesis for the tunnel_not_established detector."""

    synthesizer_id = "tunnel_not_established"
    synthesizer_version = "1.0"
    issue_title = "Tunnel Not Established / Network Error"

    def __init__(self, summary, findings, correlators):
        super().__init__(summary, findings, correlators)
        self._standby_cycles = correlators.get("modern_standby_cycles") or []
        self._buckets_seen = self._classify_buckets()

    def _classify_buckets(self) -> Dict[str, List]:
        """Group findings by Root Cause bucket."""
        buckets: Dict[str, List] = {}
        for f in self.findings:
            code = getattr(f, "code", "") or ""
            bucket = _bucket_for_code(code)
            buckets.setdefault(bucket, []).append(f)
        return buckets

    # ──────────────────────────────────────────────── section hooks

    def _build_timeline(self) -> List[TimelineEvent]:
        """Each tunnel-state-flap finding becomes one TimelineEvent.
        Classification is heuristic: if the finding's time_range overlaps
        a Modern Standby cycle, label it POST_STANDBY; otherwise IDP_FORCED
        is the wrong label here so we leave UNKNOWN-style as a tunnel-flap
        signal (re-using EventClassification because the framework wants
        a typed value)."""
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
            # Duration as recovery_seconds for the timeline column.
            duration = None
            if tr[1] is not None:
                duration = (tr[1] - tr[0]).total_seconds()

            # Classification — was this near a Modern Standby cycle?
            #
            # Phase 58e-H6 (2026-07-08): default was IDP_FORCED_REAUTH,
            # which is nonsensical for a tunnel-not-established event.
            # Use UNKNOWN so the tray legend counts stay honest; the
            # Modern-Standby correlator below still promotes to
            # POST_STANDBY_* and code-based overrides still promote to
            # MID_WORK for LOCAL_NETWORK_DOWN / TUNNEL_DOWN.
            classification = EventClassification.UNKNOWN
            for c in self._standby_cycles:
                if c.exit_ts is None:
                    continue
                if abs((ts_local - c.exit_ts).total_seconds()) <= 60:
                    classification = (
                        EventClassification.POST_STANDBY_FOREGROUND_BLIP
                    )
                    break
            # Heuristic relabel: code-based override. A
            # LOCAL_NETWORK_DOWN or SME_FAILURE finding is more
            # accurately MID_WORK_ACTIVE_SESSION_SEVERED — those are
            # user-visible because the entire tunnel is gone.
            code = (getattr(f, "code", "") or "").upper()
            if "TUNNEL_DOWN" in code or "LOCAL_NETWORK_DOWN" in code:
                classification = (
                    EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED
                )

            result.append(TimelineEvent(
                ts_local=ts_local,
                ts_utc=ts_utc,
                classification=classification,
                recovery_seconds=duration,
                tunnel_impact=getattr(f, "title", "") or code,
            ))
        # Sort by timestamp ascending so the timeline reads as a story.
        result.sort(key=lambda e: e.ts_local)
        return result

    def _build_summary(self) -> List[str]:
        timeline = self._build_timeline()
        if not timeline:
            return ["No tunnel-not-established findings emitted for this bundle."]
        n = len(timeline)
        buckets = list(self._buckets_seen.keys())
        bucket_text = ", ".join(buckets)
        paras = [
            f"The tunnel-not-established detector emitted **{n} finding(s)** "
            f"on this bundle, spanning the following root-cause buckets: "
            f"`{bucket_text}`."
        ]
        if "local_network" in self._buckets_seen:
            paras.append(
                "**LOCAL_NETWORK_DOWN** was flagged — ZCC was unable to "
                "reach its service edges due to upstream network issues "
                "(adapter down, DNS broken, default route missing, or a "
                "firewall blocking outbound 443/UDP). Diagnose at the "
                "network layer FIRST — no ZCC config change will help if "
                "the laptop can't reach the internet."
            )
        if "sme_unreachable" in self._buckets_seen:
            paras.append(
                "**SME_FAILURE_COUNT_HIGH** was flagged — the assigned "
                "Zscaler service edges were unreachable from the client. "
                "Cross-check against the Zscaler trust portal and the "
                "client's DNS resolution path to the service-edge "
                "hostnames."
            )
        if "state_machine_flap" in self._buckets_seen:
            paras.append(
                "The tunnel state machine **flapped through non-forwarding "
                "states**. This is consistent with network instability or "
                "with ZCC restarting (Intune update, manual stop/start). "
                "The Timeline below shows the per-run durations."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes: List[RootCause] = []
        nbucket = 0

        if "local_network" in self._buckets_seen:
            nbucket += 1
            findings_in_bucket = self._buckets_seen["local_network"]
            ev = []
            for f in findings_in_bucket[:1]:
                for rec in (getattr(f, "evidence", []) or [])[:2]:
                    ev.append(Evidence(
                        text=(getattr(rec, "raw", None) or rec.message or "")
                            .strip()[:200],
                        strength=EvidenceStrength.DIRECT_QUOTE,
                        source_file=(rec.source_path.name
                                     if hasattr(rec.source_path, "name")
                                     else None),
                        ts=getattr(rec, "timestamp", None),
                    ))
            causes.append(RootCause(
                id=f"RC-{nbucket}",
                title="Local network unable to reach Zscaler service edges",
                mechanism=(
                    "ZCC logs LOCAL_NETWORK_DOWN when it cannot establish a "
                    "connection to ANY assigned service edge. The cause is "
                    "almost always upstream of ZCC — a broken adapter, "
                    "missing default route, blocked DNS, or a firewall "
                    "policy that drops outbound 443/UDP on the customer's "
                    "WAN/local network. ZCC has no way to fix this; the "
                    "user must regain general internet connectivity first."
                ),
                evidence=ev,
            ))

        if "sme_unreachable" in self._buckets_seen:
            nbucket += 1
            causes.append(RootCause(
                id=f"RC-{nbucket}",
                title="Assigned service edges (SMEs) unreachable",
                mechanism=(
                    "ZCC keeps a per-SME failure counter. SME_FAILURE_COUNT_HIGH "
                    "indicates the client repeatedly failed to reach the "
                    "service-edge hostnames assigned to its cloud — typical "
                    "causes include geo-DNS returning unreachable edges, the "
                    "customer network blocking 443/UDP to specific Zscaler "
                    "subnets, or stale tunnel state pointing at a "
                    "decommissioned edge."
                ),
            ))

        if "state_machine_flap" in self._buckets_seen or "state_machine_failed" in self._buckets_seen:
            nbucket += 1
            flap_findings = (
                self._buckets_seen.get("state_machine_flap", [])
                + self._buckets_seen.get("state_machine_failed", [])
            )
            states_text = ", ".join(
                sorted({
                    getattr(f, "code", "").split("_TUNNEL_DOWN_")[-1]
                    for f in flap_findings
                    if "_TUNNEL_DOWN_" in (getattr(f, "code", "") or "")
                })
            )
            causes.append(RootCause(
                id=f"RC-{nbucket}",
                title="Tunnel state machine flapped through non-forwarding states",
                mechanism=(
                    f"The tunnel state machine spent measurable time in "
                    f"non-forwarding states ({states_text or 'multiple'}). "
                    "Common drivers: network instability (Wi-Fi roaming, "
                    "VPN coexistence), ZCC service restart (Intune update, "
                    "manual stop/start), or sleep/wake transitions. The "
                    "Timeline section shows per-run durations — single "
                    "short runs are typically benign; sustained runs > 30s "
                    "indicate a genuine outage."
                ),
            ))

        if "middlebox" in self._buckets_seen:
            nbucket += 1
            causes.append(RootCause(
                id=f"RC-{nbucket}",
                title="Middlebox performing TLS interception",
                mechanism=(
                    "ZCC's tunnel TLS handshake to a service edge was "
                    "intercepted by a middlebox (typically the customer's "
                    "own SSL-inspecting firewall). The customer must add "
                    "Zscaler service-edge hostnames + the ZCC client "
                    "certificate exchange to the firewall's bypass list — "
                    "no ZCC-side fix possible."
                ),
            ))

        if "fallback" in self._buckets_seen:
            nbucket += 1
            causes.append(RootCause(
                id=f"RC-{nbucket}",
                title="Transport fell back to lower-throughput path",
                mechanism=(
                    "ZCC tried T2/DTLS first (faster, lower-latency) and "
                    "fell back to T1/TLS-over-TCP after T2 failed. Common "
                    "cause: customer network drops UDP 443 outbound or "
                    "blocks DTLS specifically. The tunnel will work but "
                    "with measurable latency overhead — relevant for VoIP, "
                    "Citrix, and other latency-sensitive workloads."
                ),
            ))

        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        factors: List[ContributingFactor] = []
        # CF only when the timeline correlates with sleep/wake events
        timeline = self._build_timeline()
        post_standby = [
            e for e in timeline
            if e.classification in (
                EventClassification.POST_STANDBY_BACKGROUND_BLIP,
                EventClassification.POST_STANDBY_FOREGROUND_BLIP,
            )
        ]
        if post_standby:
            factors.append(ContributingFactor(
                id="CF-1",
                title=(
                    f"{len(post_standby)} of {len(timeline)} flap event(s) "
                    "correlate with sleep/wake transitions"
                ),
                body=(
                    "These are expected tunnel rebuilds on wake — not "
                    "necessarily incidents. ZCC's lifecycle downgrader "
                    "already marks them INFO in the Detected Issues view. "
                    "Investigate the non-sleep-correlated events first."
                ),
                is_hypothesis=False,
            ))
        return factors

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        timeline = self._build_timeline()
        if not timeline:
            return []
        durations = [
            e.recovery_seconds for e in timeline
            if e.recovery_seconds is not None
        ]
        total_bad = sum(durations) if durations else 0
        longest = max(durations, default=0)
        post_standby = sum(
            1 for e in timeline
            if e.classification in (
                EventClassification.POST_STANDBY_BACKGROUND_BLIP,
                EventClassification.POST_STANDBY_FOREGROUND_BLIP,
            )
        )
        return [
            ImpactMetric("Total flap events", str(len(timeline))),
            ImpactMetric(
                "Sleep/wake-correlated (likely benign)", str(post_standby)
            ),
            ImpactMetric(
                "Other (investigate)", str(len(timeline) - post_standby)
            ),
            ImpactMetric(
                "Total bad-state time",
                f"{total_bad:.0f}s" if total_bad < 60 else f"{total_bad/60:.1f} min",
                highlight=(total_bad > 60),
            ),
            ImpactMetric(
                "Longest single bad run",
                f"{longest:.0f}s" if longest < 60 else f"{longest/60:.1f} min",
                highlight=(longest > 60),
            ),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes: List[FixRecommendation] = []
        if "local_network" in self._buckets_seen:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="User / IT support",
                title="Restore basic internet connectivity on the affected device",
                body=(
                    "ZCC cannot establish a tunnel without an underlying "
                    "network. Verify:"
                ),
                bullets=[
                    "Network adapter is up (ipconfig / ifconfig)",
                    "DNS resolves an external host (nslookup zscaler.com)",
                    "Default route exists (route print)",
                    "Outbound 443 (TCP + UDP) is not blocked by a downstream firewall",
                ],
                effect="Tunnel will re-establish once basic connectivity returns.",
            ))
        if "sme_unreachable" in self._buckets_seen:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Network / Zscaler admin",
                title="Verify reachability to assigned service edges",
                body=(
                    "Cross-check the customer's outbound firewall against "
                    "Zscaler's published service-edge subnets:"
                ),
                bullets=[
                    "Confirm DNS resolution of the assigned cloud's service-edge hostnames",
                    "Run trace / mtr to each assigned SME from the client network",
                    "Verify customer firewall isn't blocking specific Zscaler subnets",
                ],
                effect="Reduces SME failure counter and stabilises tunnel.",
            ))
        if "middlebox" in self._buckets_seen:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Customer network admin",
                title="Bypass SSL inspection for Zscaler service edges",
                body=(
                    "ZCC's tunnel TLS must NOT be intercepted by a "
                    "middlebox. Configure the customer's SSL-inspecting "
                    "firewall to pass-through Zscaler traffic."
                ),
                effect="Tunnel TLS handshake succeeds; no fallback path.",
            ))
        if "fallback" in self._buckets_seen:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.MEDIUM,
                owner="Customer network admin",
                title="Allow UDP 443 outbound to Zscaler edges",
                body=(
                    "T2/DTLS requires UDP 443 to reach Zscaler edges. The "
                    "fallback to T1/TLS works but adds measurable latency."
                ),
                effect="Restores T2/DTLS performance.",
            ))
        return fixes

    def _build_verifications(self) -> List[VerificationStep]:
        return [
            VerificationStep(
                after_fix="After applying any of the fixes above",
                action=(
                    "Capture a fresh 1-hour ZCC bundle while the user is "
                    "actively working"
                ),
                expected=(
                    "ZIA and ZPA tunnels stay in TUNNEL_FORWARDING state "
                    "for the entire capture window. No new "
                    "{svc}_TUNNEL_DOWN_* findings in the Detected "
                    "Issues view."
                ),
            ),
        ]

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if "local_network" in self._buckets_seen:
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    "Was the user on a stable network during the affected "
                    "window? (home Wi-Fi vs hotspot vs corporate LAN)"
                ),
                why_it_matters=(
                    "LOCAL_NETWORK_DOWN often reflects flaky underlying "
                    "connectivity, not a ZCC issue."
                ),
            ))
        if "middlebox" in self._buckets_seen:
            questions.append(OpenQuestion(
                id="Q2",
                question=(
                    "Does the customer operate an SSL-inspecting firewall "
                    "or proxy on the network the user was on?"
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no tunnel-not-established findings"
        n = len(self.findings)
        has_local = "local_network" in self._buckets_seen
        has_state = (
            "state_machine_flap" in self._buckets_seen
            or "state_machine_failed" in self._buckets_seen
        )
        if has_local or has_state:
            return f"High — {n} tunnel-state issue(s), active user impact possible"
        return f"Medium — {n} finding(s), most likely lifecycle-related"
