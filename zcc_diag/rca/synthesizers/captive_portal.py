"""
captive_portal RCA synthesizer (Phase 49e, 2026-06-24).

Captive portals are the hotel-Wi-Fi / airport-Wi-Fi / corporate-guest-
network pattern: an HTTP middlebox intercepts ZCC's probe URLs and
redirects to a sign-in page. ZCC's Captive Portal Module (ZCPM) detects
this and pauses the tunnel until the user authenticates.

Finding codes mapped to Root Cause buckets:

  cpm_error          — CAPTIVE_PORTAL_ERROR_STATE   (ZCPM in error state)
  cpm_failopen       — CAPTIVE_PORTAL_FAILOPEN_STATE (user-facing fail-open)
  tray_detected      — TRAY_CAPTIVE_PORTAL_DETECTED (tray surfaced "captive portal")
  probe_non_204      — ZCPM_PROBE_NON_204_{code} (probe returned not-204)
  other              — anything unrecognized
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
    if code == "CAPTIVE_PORTAL_ERROR_STATE":
        return "cpm_error"
    if code == "CAPTIVE_PORTAL_FAILOPEN_STATE":
        return "cpm_failopen"
    if code == "TRAY_CAPTIVE_PORTAL_DETECTED":
        return "tray_detected"
    if code.startswith("ZCPM_PROBE_NON_204_"):
        return "probe_non_204"
    return "other"


class CaptivePortalSynthesizer(RCASynthesizer):
    synthesizer_id = "captive_portal"
    synthesizer_version = "1.0"
    issue_title = "Captive Portal Detection / Fail-Open"

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
            # Phase 58e-H6 (2026-07-08): captive-portal state means the
            # tunnel is paused pending sign-in, but that only becomes
            # user-visible disruption if the user was actively trying to
            # send traffic. Default to UNKNOWN; power_change /
            # foreground_app correlators can promote to MID_WORK when
            # they show simultaneous activity. Fail-open keeps its
            # low-severity label. Prior code blanket-labeled every event
            # as MID_WORK, over-escalating boot-time hotspot detection.
            classification = EventClassification.UNKNOWN
            if code == "CAPTIVE_PORTAL_FAILOPEN_STATE":
                # Fail-open means traffic continues unprotected; less
                # severe than a hard pause.
                classification = EventClassification.POST_STANDBY_FOREGROUND_BLIP
            result.append(TimelineEvent(
                ts_local=ts_local,
                ts_utc=ts_utc,
                classification=classification,
                recovery_seconds=duration,
                tunnel_impact=getattr(f, "title", "") or code,
            ))
        result.sort(key=lambda e: e.ts_local)
        return result

    def _build_summary(self) -> List[str]:
        if not self.findings:
            return ["No captive-portal events emitted for this bundle."]
        n = len(self.findings)
        bucket_names = list(self._buckets.keys())
        paras = [
            f"The captive_portal detector emitted **{n} finding(s)** "
            f"across these buckets: `{', '.join(bucket_names)}`."
        ]
        if "tray_detected" in self._buckets or "probe_non_204" in self._buckets:
            paras.append(
                "**ZCC entered captive-portal-aware mode** — the tunnel "
                "paused while ZCC waited for the user to complete a "
                "Wi-Fi sign-in. This is expected behaviour on hotel / "
                "airport / corporate-guest Wi-Fi. The finding count is "
                "informational unless the user reports being stuck."
            )
        if "cpm_error" in self._buckets:
            paras.append(
                "**ZCPM error state** detected — the captive-portal "
                "module hit an error while trying to detect/handle a "
                "portal. ZCC may have failed to detect the portal AT "
                "ALL (user sees a broken tunnel with no clear cause), "
                "or failed to recover after sign-in. See RC for fix."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes = []
        n = 0

        if "cpm_error" in self._buckets:
            n += 1
            ev = []
            for f in self._buckets["cpm_error"][:1]:
                for rec in (getattr(f, "evidence", []) or [])[:2]:
                    ev.append(Evidence(
                        text=(getattr(rec, "raw", None) or
                              rec.message or "").strip()[:200],
                        strength=EvidenceStrength.DIRECT_QUOTE,
                        source_file=(rec.source_path.name
                                     if hasattr(rec.source_path, "name")
                                     else None),
                        ts=getattr(rec, "timestamp", None),
                    ))
            causes.append(RootCause(
                id=f"RC-{n}",
                title="Captive Portal Module entered error state",
                mechanism=(
                    "ZCPM uses HTTP probes to a Zscaler-hosted endpoint "
                    "(``gateway.<cloud>.net/zcc_conn_test``) — a 204 "
                    "response is healthy. When ZCPM enters error state, "
                    "either the probe failed to return ANY response "
                    "(local DNS dead, gateway unreachable) or the "
                    "probe-recovery logic itself crashed. Both block "
                    "tunnel establishment."
                ),
                evidence=ev,
            ))

        if "tray_detected" in self._buckets or "probe_non_204" in self._buckets:
            n += 1
            bucket = (
                self._buckets.get("tray_detected", [])
                + self._buckets.get("probe_non_204", [])
            )
            causes.append(RootCause(
                id=f"RC-{n}",
                title="Captive portal detected — user must sign in to Wi-Fi",
                mechanism=(
                    "An HTTP middlebox (the captive portal) intercepted "
                    "ZCC's probe. ZCPM correctly entered fail-open mode "
                    "and surfaced the prompt to the user. Tunnel will "
                    "resume after the user completes the portal sign-in. "
                    f"Detected on {len(bucket)} occasion(s) in this "
                    "bundle."
                ),
            ))

        if "cpm_failopen" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="ZCC traffic flowed UNPROTECTED during captive-portal window",
                mechanism=(
                    "While ZCPM was waiting for the user to complete "
                    "captive-portal sign-in, ZCC allowed traffic to flow "
                    "directly (fail-open). This is the documented "
                    "default, but means web traffic was NOT going "
                    "through ZIA inspection during that window. "
                    "Customer security policy may prefer fail-CLOSE on "
                    "captive-portal-detected — review the App Profile."
                ),
            ))

        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        return []

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        if not self.findings:
            return []
        return [
            ImpactMetric("Total captive-portal findings", str(len(self.findings))),
            ImpactMetric(
                "ZCPM error states (block tunnel entirely)",
                str(len(self._buckets.get("cpm_error", []))),
                highlight=(len(self._buckets.get("cpm_error", [])) > 0),
            ),
            ImpactMetric(
                "Detected portal events (normal Wi-Fi sign-in pattern)",
                str(len(self._buckets.get("tray_detected", []))
                    + len(self._buckets.get("probe_non_204", []))),
            ),
            ImpactMetric(
                "Fail-open windows (unprotected traffic)",
                str(len(self._buckets.get("cpm_failopen", []))),
                highlight=(len(self._buckets.get("cpm_failopen", [])) > 0),
            ),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes = []
        if "cpm_error" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="ZCC admin",
                title="Investigate ZCPM error state",
                body=(
                    "ZCPM hit an error while probing for a portal. "
                    "Verify:"
                ),
                bullets=[
                    "Local DNS resolution works on the affected network",
                    "gateway.<cloud>.net is reachable when no portal is present",
                    "ZCC version is current — older builds had ZCPM bugs",
                ],
                effect="ZCPM can recover and tunnel resumes after sign-in.",
            ))
        if "cpm_failopen" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.MEDIUM,
                owner="ZCC admin (App Profile)",
                title="Review fail-open policy for captive portals",
                body=(
                    "Default ZCC behaviour is to fail-OPEN during "
                    "captive-portal sign-in (so the user can complete "
                    "the portal). If the customer's security policy "
                    "requires fail-CLOSED for ALL traffic, the App "
                    "Profile setting can be flipped — at the cost of "
                    "the user being unable to use untrusted Wi-Fi at "
                    "all."
                ),
            ))
        return fixes

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if self.findings:
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    "Was the user on guest / hotel / public Wi-Fi during "
                    "the affected window? Captive portal events are "
                    "expected on those networks."
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no captive-portal findings"
        if "cpm_error" in self._buckets:
            return "High — ZCPM error blocks tunnel"
        if "cpm_failopen" in self._buckets:
            return "Medium — fail-open windows may violate customer policy"
        return "Low — expected captive-portal detection events"
