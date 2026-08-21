"""
ZPA re-authentication RCA synthesizer (Phase 49a, 2026-06-24).

Activates the Phase 47 RCA framework + Phase 48 correlators for the
``zpa_reauth_loop`` detector. Produces output structurally identical
to the hand-built Example Tenant A RCA — Timeline classified by event type,
Root Causes with mechanism + observed sequence, Contributing Factors
with hypothesis flagging, Fix recommendations bucketed by horizon,
Verification Plan, Open Questions, Bundle Facts.

Architecture:
  1. Constructor receives ``BundleSummary``, the streaming detector's
     Findings, and the parsed log records (for correlator input).
  2. ``build()`` (inherited from ``RCASynthesizer``) calls each
     ``_build_*`` hook in order and returns an ``RCAReport``.
  3. Each hook is small and testable — the hard work is in Phase 48
     correlators (which were already validated against Example Tenant A).

The synthesizer is INFORMATION-DRIVEN, not template-driven. Static
prose for Root Causes / Fixes / Verification is acceptable because
those are the same for every ZPA re-auth investigation regardless of
bundle. Contributing Factors are gated on bundle data (CF-1 only
emitted if symptoms suggest autoReauthForOnTrusted=false; CF-3 only
if device is Standalone Workstation; etc.).
"""

from __future__ import annotations

import statistics
from datetime import timedelta, timezone
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


class ZpaReauthSynthesizer(RCASynthesizer):
    """RCA synthesis for the zpa_reauth_loop detector."""

    synthesizer_id = "zpa_reauth_loop"
    synthesizer_version = "1.1"  # Phase 44: explicit sleep-vs-IdP split
    issue_title = "ZPA Re-Authentication Disruptions"

    def __init__(self, summary, findings, correlators):
        """
        Arguments:
          summary       — BundleSummary (re-derived per bundle)
          findings      — List of Finding objects from zpa_reauth_loop
          correlators   — Dict with keys:
              "modern_standby_cycles"  : List[ModernStandbyCycle]
              "force_reauth_summary"   : ForceReauthSummary
              "auth_state_events"      : List[AuthStateEvent]
              "mtunnel_closes"         : List[MtunnelClose]
              "polling_cadences"       : Dict[str, PollingCadence]
              "service_starts"         : List[ServiceStart]
              "prt_availability"       : PRTAvailability
        """
        super().__init__(summary, findings, correlators)
        self._auth_events = correlators.get("auth_state_events") or []
        self._standby_cycles = correlators.get("modern_standby_cycles") or []
        self._force_reauths = correlators.get("force_reauth_summary")
        self._mtunnel_closes = correlators.get("mtunnel_closes") or []
        self._polling = correlators.get("polling_cadences") or {}
        self._service_starts = correlators.get("service_starts") or []
        self._prt = correlators.get("prt_availability")
        # Memoized: count auth events by classification
        self._timeline_cache: Optional[List[TimelineEvent]] = None

    # ──────────────────────────────────────────────── helpers

    def _service_start_before(self, ts):
        """Find the most recent FRESH service start before ts."""
        from ...correlators.service_lifecycle import ServiceStartKind
        candidates = [
            s for s in self._service_starts
            if s.kind == ServiceStartKind.FRESH_PROCESS_START and s.ts <= ts
        ]
        return candidates[-1] if candidates else None

    def _is_recent_fresh_start(self, ts) -> bool:
        """True if a ZSATunnel fresh start happened within
        FRESH_START_WINDOW_SECONDS of `ts`. Used to classify auth events
        as PRE_WORK_FRESH_START."""
        from ...correlators.service_lifecycle import FRESH_START_WINDOW_SECONDS
        start = self._service_start_before(ts)
        if not start:
            return False
        return (ts - start.ts).total_seconds() <= FRESH_START_WINDOW_SECONDS

    def _matched_standby_cycle(self, ts):
        """Return the ModernStandbyCycle whose force_reauth fired near ts
        (within ~5 minutes — the lazy-reauth-on-next-zpa-attempt window
        documented in Phase 48 analysis)."""
        if not self._force_reauths:
            return None
        # Find force_reauth events that PRECEDED ts by up to 15 minutes
        for fr_event in self._force_reauths.events:
            delta = (ts - fr_event.ts).total_seconds()
            if 0 <= delta <= 900:  # 0–15 minutes (lazy reauth surfaces later)
                return fr_event.matched_standby_cycle
        return None

    def _mtunnels_severed_in_window(
        self, lost_ts, recovered_ts,
    ) -> List:
        """Find CLOSED_FROM_ASSISTANT mtunnel closes within the auth
        recovery window — these are the active sessions the user lost."""
        from ...correlators.mtunnel import MtunnelCloseReason
        if recovered_ts is None:
            recovered_ts = lost_ts + timedelta(minutes=10)
        # Account for ZCC tearing down mtunnels slightly before AUTH_REQUIRED
        # state fires (Phase 48 observation: tear-down at 18:12:51, auth
        # state at 18:16:21 — same event, 4-min spread).
        window_start = lost_ts - timedelta(minutes=5)
        return [
            c for c in self._mtunnel_closes
            if (c.reason == MtunnelCloseReason.CLOSED_FROM_ASSISTANT
                and window_start <= c.close_ts <= recovered_ts)
        ]

    def _was_pre_existing_session(self, mtunnel_close, force_reauth_ts) -> bool:
        """True if this mtunnel was OPENED BEFORE the force_reauth signal —
        i.e., it was an in-flight session that got severed, not a NEW
        attempt that ZCC rejected.

        This is the actual distinguishing signal between
        MID_WORK_ACTIVE_SESSION_SEVERED and POST_STANDBY_BACKGROUND_BLIP.
        Phase 49 validation against Example Tenant A found that byte-flow tracking
        was too strict — Citrix Workspace polls open mtunnels that don't
        emit data-log lines but ARE legitimately active sessions.

        If open_ts is None (correlator didn't see the open), we conservatively
        treat the mtunnel as NEW (post-reauth) — better to under-flag
        severe events than over-flag.
        """
        if mtunnel_close.open_ts is None or force_reauth_ts is None:
            return False
        return mtunnel_close.open_ts < force_reauth_ts

    def _classify_event(self, auth_event) -> EventClassification:
        """Decide whether an auth event is PRE_WORK_FRESH_START,
        MID_WORK_ACTIVE_SESSION_SEVERED, POST_STANDBY_BACKGROUND_BLIP,
        POST_STANDBY_FOREGROUND_BLIP, or IDP_FORCED_REAUTH.

        Phase 49 validation: the distinguishing signal between
        MID_WORK_ACTIVE and POST_STANDBY_BACKGROUND is NOT byte-flow
        before close (Citrix Workspace poll connections don't emit data
        log lines at ZCC's default verbosity) — it's whether the
        mtunnel was OPEN BEFORE the force_reauth signal fired. A
        mtunnel opened pre-reauth and torn down is a severed session;
        a mtunnel opened post-reauth (a new attempt that ZCC rejected
        because it knew auth was needed) is just a background blip.
        """
        # First: was this a fresh ZSATunnel start within FRESH_START_WINDOW?
        if self._is_recent_fresh_start(auth_event.lost_ts):
            return EventClassification.PRE_WORK_FRESH_START

        # Second: did a Modern Standby cycle precede this event?
        cycle = self._matched_standby_cycle(auth_event.lost_ts)
        if cycle:
            # Find the force_reauth event that paired with this cycle
            force_reauth_ts = None
            if self._force_reauths:
                for fr in self._force_reauths.events:
                    if fr.matched_standby_cycle is cycle:
                        force_reauth_ts = fr.ts
                        break
            severed = self._mtunnels_severed_in_window(
                auth_event.lost_ts, auth_event.recovered_ts,
            )
            # PRE-EXISTING sessions (opened before force_reauth) =
            # MID_WORK_ACTIVE_SESSION_SEVERED. NEW attempts post-reauth
            # don't represent user disruption — they're ZCC's own
            # background polls hitting the closed door.
            pre_existing = [
                c for c in severed
                if self._was_pre_existing_session(c, force_reauth_ts)
            ]
            if pre_existing:
                return EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED
            return EventClassification.POST_STANDBY_BACKGROUND_BLIP

        # No fresh start, no Modern Standby — IdP probably fired the
        # re-auth based on Sign-in Frequency policy.
        return EventClassification.IDP_FORCED_REAUTH

    def _tunnel_impact_text(self, auth_event) -> str:
        """Build the 'Tunnel impact' column for the timeline table."""
        severed = self._mtunnels_severed_in_window(
            auth_event.lost_ts, auth_event.recovered_ts,
        )
        if severed:
            unique_tags = len({c.tag_id for c in severed})
            return f"{unique_tags} mtunnels CLOSED_FROM_ASSISTANT"
        # Pre-work events typically have N broker setup rejections during
        # recovery — count those.
        from ...correlators.mtunnel import MtunnelCloseReason
        rejected = [
            c for c in self._mtunnel_closes
            if (c.reason == MtunnelCloseReason.SETUP_FAIL_SAML_EXPIRED
                and auth_event.lost_ts <= c.close_ts
                <= (auth_event.recovered_ts or auth_event.lost_ts
                    + timedelta(minutes=10)))
        ]
        if rejected:
            return f"{len(rejected)} broker setup rejections during recovery"
        return "—"

    # ──────────────────────────────────────────────── section hooks

    def _build_timeline(self) -> List[TimelineEvent]:
        if self._timeline_cache is not None:
            return self._timeline_cache
        result = []
        for auth_event in self._auth_events:
            classification = self._classify_event(auth_event)
            recovery = auth_event.recovery_seconds
            # ts_utc derivation — assume the lost_ts is a tz-aware
            # datetime; if not, we can't render UTC. Best-effort.
            ts_local = auth_event.lost_ts
            try:
                ts_utc = ts_local.astimezone(timezone.utc)
            except (TypeError, ValueError):
                ts_utc = ts_local
            severed = self._mtunnels_severed_in_window(
                auth_event.lost_ts, auth_event.recovered_ts,
            )
            unique_severed = len({c.tag_id for c in severed})
            cycle = self._matched_standby_cycle(auth_event.lost_ts)
            sleep_dur = cycle.duration_seconds if cycle else None
            result.append(TimelineEvent(
                ts_local=ts_local,
                ts_utc=ts_utc,
                classification=classification,
                recovery_seconds=recovery,
                tunnel_impact=self._tunnel_impact_text(auth_event),
                mtunnels_severed=unique_severed,
                sleep_duration_seconds=sleep_dur,
            ))
        self._timeline_cache = result
        return result

    def _build_summary(self) -> List[str]:
        timeline = self._build_timeline()
        total = len(timeline)
        if total == 0:
            return ["No ZPA re-authentication events observed in this bundle."]
        mid_work = sum(
            1 for e in timeline
            if e.classification == EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED
        )
        pre_work = sum(
            1 for e in timeline
            if e.classification == EventClassification.PRE_WORK_FRESH_START
        )
        post_standby = sum(
            1 for e in timeline
            if e.classification in (
                EventClassification.POST_STANDBY_BACKGROUND_BLIP,
                EventClassification.POST_STANDBY_FOREGROUND_BLIP,
            )
        )
        idp_only = sum(
            1 for e in timeline
            if e.classification == EventClassification.IDP_FORCED_REAUTH
        )
        worst = max(
            (e for e in timeline if e.recovery_seconds is not None),
            key=lambda e: e.recovery_seconds,
            default=None,
        )

        # Phase 44 (2026-06-24): explicit sleep-driven vs IdP-driven
        # split. Every event with a matched ModernStandbyCycle is
        # sleep-driven; the remainder are IdP-driven (Sign-in Frequency
        # policy, manual re-auth, or other non-sleep triggers). The
        # split lets the engineer target the right fix: ZCC App Profile
        # for sleep, Entra CA for IdP.
        sleep_driven = post_standby + mid_work
        idp_driven = pre_work + idp_only
        split_summary = (
            f"**Cadence split — {sleep_driven} of {total} events were "
            f"sleep-driven** (Modern Standby exit → force_reauth), "
            f"{idp_driven} were IdP-driven (fresh-start SAML expiry or "
            f"Sign-in Frequency policy)."
        )

        paras: List[str] = []
        if mid_work > 0:
            worst_text = worst.recovery_text if worst else "n/a"
            paras.append(
                f"In the observation window, {self._user()} experienced "
                f"{total} ZPA re-authentication events. **{mid_work} of them "
                f"forcibly tore down active mtunnels** (BRK_MT_CLOSED_FROM_ASSISTANT) "
                f"and locked the user out for up to {worst_text}. "
                f"{pre_work} were pre-work fresh-starts (brief), and "
                f"{post_standby} were post-Modern-Standby auth blips."
            )
        else:
            paras.append(
                f"In the observation window, {self._user()} experienced "
                f"{total} ZPA re-authentication events — all brief "
                f"({pre_work} pre-work fresh-starts, {post_standby} "
                f"post-Modern-Standby auth blips). No active sessions "
                f"were severed."
            )

        paras.append(split_summary)

        # Tailor the root cause line to which side of the split dominates.
        if sleep_driven >= idp_driven and sleep_driven > 0:
            paras.append(
                "**Root cause (dominant):** Modern Standby (Connected "
                "Standby) firing brief, user-invisible sleep cycles, "
                "combined with what appears to be a ZCC App Profile "
                "configuration that requires interactive re-auth on "
                "wake instead of silent SAML refresh."
            )
        elif idp_driven > 0:
            paras.append(
                "**Root cause (dominant):** Microsoft Entra Conditional "
                "Access Sign-in Frequency policy. Each cached SAML "
                "assertion expires per the IdP-side timer and ZCC "
                "must re-authenticate the user."
            )

        paras.append(
            "**Fix priorities derived from the cadence split:**"
        )
        fix_lines = []
        if sleep_driven > 0:
            fix_lines.append(
                f"- For the {sleep_driven} sleep-driven event(s): set "
                "`autoReauthForOnTrusted = true` in the ZCC App Profile "
                "and apply an Intune no-sleep policy."
            )
        if idp_driven > 0:
            fix_lines.append(
                f"- For the {idp_driven} IdP-driven event(s): review "
                "Entra Conditional Access Sign-in Frequency on the "
                "Zscaler PA enterprise app (recommend 12-24h)."
            )
        paras.append("\n".join(fix_lines))
        paras.append("Verification plan in §9.")
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes: List[RootCause] = []
        timeline = self._build_timeline()

        # RC-1 only fires if we have post-standby events
        post_standby_events = [
            e for e in timeline
            if e.classification in (
                EventClassification.POST_STANDBY_BACKGROUND_BLIP,
                EventClassification.POST_STANDBY_FOREGROUND_BLIP,
                EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED,
            )
        ]
        if post_standby_events and self._standby_cycles:
            cycles_summary = ", ".join(
                f"{c.entry_ts.strftime('%a %H:%M:%S')}→{c.exit_ts.strftime('%H:%M:%S')} "
                f"({c.duration_seconds:.0f}s)"
                for c in self._standby_cycles
                if c.is_complete
            )
            seq = []
            for c in self._standby_cycles:
                if not c.is_complete:
                    continue
                seq.append(
                    f"{c.entry_ts.strftime('%a %H:%M:%S')} — Modern Standby entry"
                )
                seq.append(
                    f"{c.exit_ts.strftime('%a %H:%M:%S')} — Modern Standby exit + force_reauth (same ms)"
                )
            evid = []
            for c in self._standby_cycles[:2]:
                if c.exit_record:
                    evid.append(Evidence(
                        text=(c.exit_record.message or "").strip(),
                        strength=EvidenceStrength.DIRECT_QUOTE,
                        source_file=getattr(c.exit_record.source_path, "name", None),
                        ts=c.exit_ts,
                    ))
            causes.append(RootCause(
                id="RC-1",
                title="Force-reauth on Modern Standby wake",
                mechanism=(
                    "Windows 11 Modern Standby (S0ix / Connected Standby) "
                    "fires sleep/wake events even for short periods the "
                    "user does not perceive. ZCC's wake hook responds to "
                    "every exit by raising zcc_zpa_force_reauth_sleep_trigger "
                    "(same millisecond as Modern Standby exit). If the App "
                    "Profile requires interactive re-auth, ZCC tears down "
                    "all active mtunnels via BRK_MT_CLOSED_FROM_ASSISTANT "
                    "and waits for the user to complete the AAD prompt."
                ),
                observed_sequence=seq,
                evidence=evid,
            ))

        # RC-2 fires if we have any pre-work fresh-start events
        fresh_start_events = [
            e for e in timeline
            if e.classification == EventClassification.PRE_WORK_FRESH_START
        ]
        if fresh_start_events:
            seq = []
            for s in self._service_starts:
                from ...correlators.service_lifecycle import ServiceStartKind
                if s.kind != ServiceStartKind.FRESH_PROCESS_START:
                    continue
                seq.append(
                    f"{s.ts.strftime('%a %m-%d %H:%M:%S')} — ZSATunnel fresh start "
                    f"(PID {s.pid})"
                )
                if len(seq) >= 4:
                    break
            causes.append(RootCause(
                id="RC-2",
                title="Overnight SAML token expiry on fresh ZCC startup",
                mechanism=(
                    "When the user closes ZCC at end of day, the cached SAML "
                    "assertion held by the ZSATunnel service is lost (in-memory "
                    "state). On next-morning startup, ZCC presents whatever "
                    "cached on-disk SAML it has to the broker. If older than "
                    "the IdP's allowed Sign-in Frequency window, the broker "
                    "rejects with BRK_MT_SETUP_FAIL_SAML_EXPIRED and ZCC "
                    "triggers fresh AAD interactive sign-in. Independent of "
                    "the autoReauthForOnTrusted setting — that flag only "
                    "helps when ZCC is already running."
                ),
                observed_sequence=seq,
                evidence=[],
            ))

        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        factors: List[ContributingFactor] = []
        timeline = self._build_timeline()
        has_post_standby = any(
            e.classification in (
                EventClassification.POST_STANDBY_BACKGROUND_BLIP,
                EventClassification.POST_STANDBY_FOREGROUND_BLIP,
                EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED,
            )
            for e in timeline
        )

        if has_post_standby:
            factors.append(ContributingFactor(
                id="CF-1",
                title="autoReauthForOnTrusted appears to be set to false",
                body=(
                    "When set to true, ZCC silently refreshes the SAML "
                    "assertion on wake/network-change events using the "
                    "device's existing AAD primary refresh token (PRT). "
                    "No user prompt; no mtunnel teardown. The bundle does "
                    "not directly expose the App Profile JSON, but the "
                    "observed symptoms (interactive AAD prompt on every "
                    "wake, mtunnels torn down via CLOSED_FROM_ASSISTANT) "
                    "are consistent with this flag being false. The "
                    "customer should verify the current value in the ZCC "
                    "Admin Portal App Profile UI."
                ),
                is_hypothesis=True,
            ))

        if any(e.classification == EventClassification.PRE_WORK_FRESH_START
               for e in timeline):
            factors.append(ContributingFactor(
                id="CF-2",
                title='Microsoft Entra Conditional Access "Sign-in Frequency"',
                body=(
                    "Governs how long a SAML assertion remains valid before "
                    "requiring a new interactive sign-in. Drives the morning "
                    'pre-work re-auth. If set to "Every time" or sub-hour, no '
                    "ZCC change can eliminate the morning re-auth — the IdP "
                    "enforces it regardless of how ZCC handles cached tokens."
                ),
                is_hypothesis=False,
            ))

        # CF-3 only if device is Standalone Workstation. We approximate
        # this via summary.os details when available.
        os_info = self.summary.os or {}
        domain = (os_info.get("domain") or "").lower()
        if domain and "workgroup" in domain or os_info.get(
            "domain_join_status", ""
        ).lower() == "standalone workstation":
            factors.append(ContributingFactor(
                id="CF-3",
                title="No-sleep AD GPO does not reach this Standalone Workstation",
                body=(
                    "If the customer pushes a no-sleep policy via Active "
                    "Directory GPO, gpresult would show 'OS Configuration: "
                    "Standalone Workstation' and 'Applied Group Policy "
                    "Objects: N/A' — the GPO does not apply. The Intune "
                    "Management Extension may be installed but the no-sleep "
                    "policy must be republished via Intune Settings Catalog "
                    "rather than AD GPO to reach this user cohort."
                ),
                is_hypothesis=False,
            ))

        # CF-4: catalog-drift, if the catalog_drift detector emitted findings
        bm_drift = (self.bm.get("catalog_drift_hosts") or [])
        if bm_drift:
            factors.append(ContributingFactor(
                id="CF-4",
                title=f"{len(bm_drift)} internal hosts monitored by ZDX are missing from the ZPA App Catalog",
                body=(
                    "Adjacent operational gap worth fixing in the same change "
                    "window. ZDX is actively probing these hosts; users will "
                    "eventually try to reach them and DNS will fail because "
                    "no ZPA App Segment is configured."
                ),
                is_hypothesis=False,
            ))

        # CF-5: PRT availability uncertain
        if self._prt:
            from ...correlators.prt_availability import PRTConfidence
            if self._prt.confidence == PRTConfidence.LIKELY_ABSENT:
                factors.append(ContributingFactor(
                    id="CF-5",
                    title="AAD Primary Refresh Token likely not available on this device",
                    body=(
                        "ZCC's silent SAML refresh on wake requires an Azure AD "
                        "Primary Refresh Token (PRT) in Windows. The PRT is "
                        "issued when the device is Entra-joined, Hybrid Entra-"
                        "joined, or has a Workplace-joined Work Account. Bundle "
                        "evidence suggests this device may not have a usable "
                        "PRT — which means even setting autoReauthForOnTrusted=true "
                        "may not enable silent refresh. Customer should run "
                        "`dsregcmd /status` on the affected device to confirm "
                        "join state before applying the Immediate fix."
                    ),
                    is_hypothesis=False,
                ))
            elif self._prt.confidence == PRTConfidence.UNCERTAIN:
                factors.append(ContributingFactor(
                    id="CF-5",
                    title="AAD PRT availability could not be determined from this bundle",
                    body=(
                        "ZCC's silent SAML refresh requires an Azure AD PRT, "
                        "which is issued only for Entra-joined / Hybrid-joined "
                        "/ Workplace-joined devices. This bundle does not "
                        "contain a dsregcmd /status dump, so PRT availability "
                        "is unknown. Customer should confirm via dsregcmd "
                        "before relying on autoReauthForOnTrusted=true."
                    ),
                    is_hypothesis=True,
                ))

        return factors

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        timeline = self._build_timeline()
        if not timeline:
            return []
        mid_work = sum(
            1 for e in timeline
            if e.classification == EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED
        )
        post_standby = sum(
            1 for e in timeline
            if e.classification in (
                EventClassification.POST_STANDBY_BACKGROUND_BLIP,
                EventClassification.POST_STANDBY_FOREGROUND_BLIP,
            )
        )
        pre_work = sum(
            1 for e in timeline
            if e.classification == EventClassification.PRE_WORK_FRESH_START
        )
        total_severed = sum(e.mtunnels_severed for e in timeline)
        recoveries = [
            e.recovery_seconds for e in timeline
            if e.recovery_seconds is not None
        ]
        mean_text = (
            f"{statistics.mean(recoveries):.1f} s"
            if recoveries else "—"
        )
        worst = max(recoveries, default=None)
        best = min(recoveries, default=None)
        worst_text = f"{worst:.1f} s" if worst else "—"
        best_text = f"{best:.1f} s" if best else "—"

        # Phase 44 (2026-06-24): explicit split
        sleep_driven_count = post_standby + mid_work
        idp_driven_count = pre_work + sum(
            1 for e in timeline
            if e.classification == EventClassification.IDP_FORCED_REAUTH
        )

        metrics = [
            ImpactMetric("Total re-auth events", str(len(timeline))),
            ImpactMetric(
                "Sleep-driven (Modern Standby exit → force_reauth)",
                str(sleep_driven_count),
                highlight=(sleep_driven_count >= idp_driven_count),
            ),
            ImpactMetric(
                "IdP-driven (Sign-in Frequency / fresh-start expiry)",
                str(idp_driven_count),
                highlight=(idp_driven_count > sleep_driven_count),
            ),
            ImpactMetric(
                "Active-session teardown events (high impact)",
                str(mid_work),
                highlight=(mid_work > 0),
            ),
            ImpactMetric("Background-activity auth blips", str(post_standby)),
            ImpactMetric("Pre-work fresh-start events", str(pre_work)),
            ImpactMetric(
                "Mtunnels torn down by ZCC (CLOSED_FROM_ASSISTANT)",
                str(total_severed),
            ),
            ImpactMetric("Best recovery", best_text),
            ImpactMetric("Mean recovery", mean_text),
            ImpactMetric(
                "Worst recovery", worst_text,
                highlight=(worst is not None and worst > 60),
            ),
        ]
        return metrics

    def _build_fixes(self) -> List[FixRecommendation]:
        """Static fix list — same for every ZPA re-auth investigation."""
        return [
            FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="ZCC admin",
                title="Set autoReauthForOnTrusted = true in App Profile",
                body=(
                    "Verify the current value in the ZCC Admin Portal first "
                    "(the bundle does not expose it). If false, set:"
                ),
                bullets=[
                    "autoReauthForOnTrusted = true",
                    "autoReauthForOnTrustedSplitVpn = true",
                    "autoReauthForOffTrusted = true (if users transition between trusted/untrusted networks)",
                    "autoReauthForOnTrustedVpn = true (if users run third-party VPNs alongside ZCC)",
                ],
                effect=(
                    "ZCC silently refreshes the SAML assertion on wake events "
                    "using the device's existing AAD PRT. No user prompt, no "
                    "mtunnel teardown. Eliminates the mid-work disruption."
                ),
            ),
            FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Entra admin",
                title="Review Conditional Access Sign-in Frequency on the Zscaler PA app",
                body=(
                    'Review the CA policy targeting the "Zscaler Private '
                    'Access" enterprise application:'
                ),
                bullets=[
                    "Sign-in Frequency value? Recommended: 12-24h for trusted endpoints",
                    "Persistent browser sessions? Recommended: Always for trusted devices",
                    "Any device-state conditions that re-evaluate on every wake event?",
                ],
                effect="Reduces the morning fresh-start re-auth cadence.",
            ),
            FixRecommendation(
                horizon=FixHorizon.MEDIUM,
                owner="Intune admin",
                title="Push no-sleep policy via Settings Catalog (not AD GPO)",
                body=(
                    "AD GPO doesn't reach Standalone Workstations. Use Intune "
                    "for this user cohort:"
                ),
                bullets=[
                    'Power → Sleep Settings → "Sleep timeout (AC) = Never"',
                    'Power → "Lid Close Action = Do Nothing"',
                    'Power → "Allow Standby States" — set thoughtfully',
                ],
                effect=(
                    "Verify with `powercfg /a` — should report Standby (S3) "
                    "and/or Standby (S0 Low Power Idle) as unavailable."
                ),
            ),
            FixRecommendation(
                horizon=FixHorizon.LONG,
                owner="Intune / ZPA admins",
                title="Disable Modern Standby + add missing internal hosts to ZPA Catalog",
                body=(
                    "Two independent improvements for the next change window:"
                ),
                bullets=[
                    "Disable Modern Standby via Intune OMA-URI: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PlatformAoAcOverride = 0",
                    "Add any ZDX-monitored internal hosts to the ZPA App Catalog (see CF-4 / Phase 42b catalog-drift findings)",
                ],
                effect=(
                    "Forces classic S3 sleep fallback (only fires on user-"
                    "intended sleep); restores reachability for internal hosts."
                ),
            ),
        ]

    def _build_verifications(self) -> List[VerificationStep]:
        return [
            VerificationStep(
                after_fix="After applying RC-1 fix (App Profile)",
                action="Capture fresh 48-hour ZCC bundle from test device",
                expected=(
                    "Zero BRK_MT_CLOSED_FROM_ASSISTANT events triggered by "
                    "zcc_zpa_force_reauth_sleep_trigger. The Modern Standby "
                    "Power Change Event lines will still appear; no mtunnels "
                    "are torn down on wake."
                ),
            ),
            VerificationStep(
                after_fix="After applying CF-2 fix (Entra CA review)",
                action=(
                    "Cross-reference Microsoft Entra Sign-in Logs for the user "
                    "over a 48-hour period"
                ),
                expected=(
                    "At most one SAML sign-in per workday (morning fresh-"
                    "start), not 3-4."
                ),
            ),
            VerificationStep(
                after_fix="Combined target outcome",
                action="48-hour ZCC bundle post-both-fixes",
                expected=(
                    "≤1 brief pre-work re-auth per workday, 0 mid-work "
                    "disruptions, 0 mtunnel teardowns triggered by Modern "
                    "Standby exits."
                ),
            ),
        ]

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = [
            OpenQuestion(
                id="Q1",
                question=(
                    'What is the current value of `autoReauthForOnTrusted` '
                    "in the App Profile applied to this user/device?"
                ),
                why_it_matters=(
                    "Hypothesis: false. Bundle cannot confirm directly."
                ),
            ),
            OpenQuestion(
                id="Q2",
                question=(
                    'What is the Microsoft Entra Conditional Access '
                    '"Sign-in Frequency" value on the Zscaler PA '
                    "enterprise application?"
                ),
            ),
        ]
        if self._prt:
            from ...correlators.prt_availability import PRTConfidence
            if self._prt.confidence in (
                PRTConfidence.LIKELY_ABSENT, PRTConfidence.UNCERTAIN
            ):
                questions.append(OpenQuestion(
                    id="Q3",
                    question=(
                        "Run `dsregcmd /status` on the affected device. "
                        "Is it Entra-joined, Hybrid Entra-joined, or has a "
                        "Workplace-joined Work Account? Without a PRT the "
                        "Immediate fix won't enable silent refresh."
                    ),
                ))
        return questions

    def _severity_label(self) -> str:
        timeline = self._build_timeline()
        mid_work = sum(
            1 for e in timeline
            if e.classification == EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED
        )
        if mid_work > 0:
            return f"High — {mid_work} active session(s) severed in observation window"
        if timeline:
            return f"Medium — {len(timeline)} brief re-auth event(s), no active disruption"
        return "Low — no re-auth activity observed"
