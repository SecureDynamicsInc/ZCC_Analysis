"""
zpa_auth_failures RCA synthesizer (Phase 49c, 2026-06-24).

Third synthesizer after zpa_reauth_loop (49a) and tunnel_not_established
(49b). Distinct from zpa_reauth_loop:

  * zpa_reauth_loop = cadence-based ("user re-authenticating too often")
  * zpa_auth_failures = error-code-based ("auth is BROKEN, here's why")

Finding codes mapped to Root Cause buckets:

  cert_issue       — DEVICE_CERT_EXPIRED, STALE_CERT_IN_TRUSTSTORE
  saml_issue       — BRK_MT_SETUP_FAIL_SAML_EXPIRED (when grouped with others)
  broker_auth      — BRK_MT_AUTH_* family (broker-side auth rejection)
  zpn_err          — ZPN_ERR_* family (generic ZPN errors)
  enrollment       — 42000..42048, 2008 (documented enrollment error codes)
  state_flap       — AUTH_STATE_FLAPPED
  other            — anything unrecognized
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
)
from ..synthesizer_base import RCASynthesizer


def _bucket_for_code(code: str) -> str:
    """Classify a zpa_auth_failures finding code into a Root Cause bucket."""
    code = (code or "").upper()
    if code in ("DEVICE_CERT_EXPIRED", "STALE_CERT_IN_TRUSTSTORE"):
        return "cert_issue"
    if code == "AUTH_STATE_FLAPPED":
        return "state_flap"
    if "SAML" in code:
        return "saml_issue"
    if code.startswith("BRK_MT_AUTH_"):
        return "broker_auth"
    if code.startswith("ZPN_ERR_"):
        return "zpn_err"
    if code.startswith("BRK_MT_SETUP_FAIL_"):
        return "broker_setup_fail"
    # Numeric enrollment codes — Zscaler documents 2008 + 42000..42048
    digits = "".join(ch for ch in code if ch.isdigit())
    if digits in ("2008",) or (digits.isdigit()
                                and digits.startswith("42")
                                and len(digits) == 5):
        return "enrollment"
    return "other"


class ZpaAuthFailuresSynthesizer(RCASynthesizer):
    """RCA synthesis for the zpa_auth_failures detector."""

    synthesizer_id = "zpa_auth_failures"
    synthesizer_version = "1.0"
    issue_title = "ZPA Authentication Failures"

    def __init__(self, summary, findings, correlators):
        super().__init__(summary, findings, correlators)
        self._buckets: Dict[str, List] = {}
        for f in self.findings:
            b = _bucket_for_code(getattr(f, "code", "") or "")
            self._buckets.setdefault(b, []).append(f)

    # ──────────────────────────────────────────────── section hooks

    def _build_timeline(self) -> List[TimelineEvent]:
        """One TimelineEvent per finding (chronological)."""
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
            # Phase 58e-H6 (2026-07-08): ZPA auth failures are neither
            # inherently IdP-driven nor mid-work. Use UNKNOWN as the
            # neutral default — the zpa_reauth synthesizer is the one
            # place we have enough context (power_change + mtunnel
            # activity) to make the pre/mid/post determination. Prior
            # code labeled every event IDP_FORCED_REAUTH which
            # double-counted on the tray legend.
            code = (getattr(f, "code", "") or "").upper()
            classification = EventClassification.UNKNOWN
            if "CERT_EXPIRED" in code:
                # Certificate expiry is a hard error, not a reauth event.
                # Tag MID_WORK to reflect "active user impact."
                classification = EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED
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
            return ["No ZPA authentication failures emitted for this bundle."]
        n = len(self.findings)
        bucket_names = list(self._buckets.keys())
        paras = [
            f"The zpa_auth_failures detector emitted **{n} finding(s)** "
            f"across these buckets: `{', '.join(bucket_names)}`."
        ]
        if "cert_issue" in self._buckets:
            paras.append(
                "**Certificate issue** detected — a ZCC client certificate "
                "has expired or a stale trust-store entry is intercepting "
                "the broker handshake. This is a hard failure that "
                "blocks all ZPA traffic until the cert is rotated. See "
                "RC-1 for evidence + fix."
            )
        if "broker_auth" in self._buckets:
            paras.append(
                "**Broker auth rejection** detected — the Zscaler broker "
                "rejected ZCC's auth challenge for a documented reason "
                "(BRK_MT_AUTH_*). Check the per-code description in the "
                "Detected Issues view to identify the exact rejection cause."
            )
        if "enrollment" in self._buckets:
            paras.append(
                "**Enrollment error** detected — one of the documented "
                "42xxx / 2008 enrollment codes appeared. These map to "
                "specific provisioning issues (clock skew, missing user, "
                "duplicate device, expired SAML IdP). See the Status "
                "Code Reference module for the per-code remedy."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes: List[RootCause] = []
        n = 0

        if "cert_issue" in self._buckets:
            n += 1
            bucket = self._buckets["cert_issue"]
            ev = []
            for f in bucket[:2]:
                for rec in (getattr(f, "evidence", []) or [])[:1]:
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
                title="ZCC client certificate issue",
                mechanism=(
                    "ZCC presents a client certificate during the ZPA "
                    "broker handshake. DEVICE_CERT_EXPIRED means the "
                    "presented cert is past its NotAfter date; "
                    "STALE_CERT_IN_TRUSTSTORE means a Windows trust store "
                    "is offering an old CA that no longer matches the "
                    "currently-deployed root. Either prevents tunnel "
                    "establishment entirely."
                ),
                evidence=ev,
            ))

        if "broker_auth" in self._buckets:
            n += 1
            bucket = self._buckets["broker_auth"]
            distinct_codes = sorted({
                getattr(f, "code", "") for f in bucket
            })
            causes.append(RootCause(
                id=f"RC-{n}",
                title=f"Broker rejected auth ({len(distinct_codes)} distinct reason(s))",
                mechanism=(
                    f"The Zscaler broker returned BRK_MT_AUTH_* on "
                    f"{len(bucket)} setup attempt(s). Codes observed: "
                    f"{', '.join(distinct_codes)}. Each code is "
                    "documented — engineer should look up the specific "
                    "rejection reason in the Status Code Reference "
                    "module and follow the corresponding remediation."
                ),
            ))

        if "saml_issue" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="SAML assertion problem",
                mechanism=(
                    "The broker rejected a SAML assertion (typically "
                    "expired, signature mismatch, or audience mismatch). "
                    "Investigate the IdP configuration — most often this "
                    "is a CA Sign-in Frequency policy that's too "
                    "aggressive, or an IdP signing certificate that has "
                    "rotated without updating the Zscaler SP."
                ),
            ))

        if "enrollment" in self._buckets:
            n += 1
            bucket = self._buckets["enrollment"]
            codes = sorted({getattr(f, "code", "") for f in bucket})
            causes.append(RootCause(
                id=f"RC-{n}",
                title=f"Enrollment failure — codes {', '.join(codes)}",
                mechanism=(
                    "Zscaler documents the 42xxx / 2008 enrollment "
                    "error codes verbatim. Each maps to a specific "
                    "provisioning failure: clock skew (42016), missing "
                    "user (42024), duplicate device, expired IdP SAML, "
                    "etc. Look up each code in the Status Code Reference "
                    "module — the description includes the exact admin "
                    "remediation."
                ),
            ))

        if "state_flap" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="ZPA auth state flapped repeatedly",
                mechanism=(
                    "The ZPA auth state machine transitioned in/out of "
                    "AUTHENTICATED multiple times during the capture. "
                    "Often correlated with sleep/wake (the lifecycle "
                    "downgrader handles that case) or with network "
                    "instability. If neither correlates, suspect a "
                    "broker-side issue (cloud DR active, broker upgrade, "
                    "rate limiting)."
                ),
            ))

        if "broker_setup_fail" in self._buckets:
            n += 1
            bucket = self._buckets["broker_setup_fail"]
            distinct_codes = sorted({
                getattr(f, "code", "") for f in bucket
            })
            causes.append(RootCause(
                id=f"RC-{n}",
                title=(
                    f"Broker setup failures "
                    f"({len(distinct_codes)} distinct reason(s))"
                ),
                mechanism=(
                    "BRK_MT_SETUP_FAIL_* codes mean the broker refused "
                    "to set up an mtunnel for a specific reason. Common "
                    "reasons: NO_POLICY_FOUND (app segment missing), "
                    "REJECTED_BY_POLICY (access policy denies the user), "
                    "SAML_EXPIRED (separate from SAML issue — this one "
                    "is the broker telling ZCC to refresh)."
                ),
            ))

        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        factors = []
        # No specific CFs we surface based on buckets — the synthesizer
        # for this detector is more direct than zpa_reauth_loop. Add CFs
        # when patterns warrant.
        if "zpn_err" in self._buckets and "broker_auth" in self._buckets:
            factors.append(ContributingFactor(
                id="CF-1",
                title=(
                    "Multiple ZPN_ERR_* codes coincide with broker auth "
                    "rejections — investigate as one cluster"
                ),
                body=(
                    "ZCC layers ZPN_ERR_* (transport / protocol-level) "
                    "errors on top of BRK_MT_AUTH_* (auth-level). When "
                    "both appear in the same window, the underlying "
                    "problem is usually auth — the ZPN errors are "
                    "downstream symptoms. Focus diagnosis on the "
                    "BRK_MT_AUTH_* codes."
                ),
                is_hypothesis=False,
            ))
        return factors

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        if not self.findings:
            return []
        return [
            ImpactMetric("Total auth-failure findings", str(len(self.findings))),
            ImpactMetric("Buckets affected", str(len(self._buckets))),
            ImpactMetric(
                "Certificate issues",
                str(len(self._buckets.get("cert_issue", []))),
                highlight=(len(self._buckets.get("cert_issue", [])) > 0),
            ),
            ImpactMetric(
                "Broker auth rejections",
                str(len(self._buckets.get("broker_auth", []))),
            ),
            ImpactMetric(
                "Enrollment errors",
                str(len(self._buckets.get("enrollment", []))),
            ),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes: List[FixRecommendation] = []
        if "cert_issue" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="ZCC admin / IT",
                title="Rotate or refresh the ZCC client certificate",
                body=(
                    "For DEVICE_CERT_EXPIRED: re-enrol the device or "
                    "re-issue the client cert. For "
                    "STALE_CERT_IN_TRUSTSTORE: clean the user/computer "
                    "trust store and re-deploy the current Zscaler root."
                ),
                bullets=[
                    "Identify which cert is offering (certutil / openssl)",
                    "If expired: re-enrol via ZCC portal or push new cert via MDM",
                    "If stale: remove stale CA from trust store, push current root",
                ],
                effect="Tunnel establishment can proceed.",
            ))
        if "broker_auth" in self._buckets or "broker_setup_fail" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Zscaler admin",
                title="Look up each BRK_MT_* code in the Status Code Reference",
                body=(
                    "The Status Code Reference module documents every "
                    "BRK_MT_AUTH_* and BRK_MT_SETUP_FAIL_* code with its "
                    "intended admin remediation. Each code has a "
                    "different fix — there's no single answer."
                ),
                effect=(
                    "Per-code remediation eliminates the corresponding "
                    "failure type."
                ),
            ))
        if "enrollment" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Zscaler admin",
                title="Resolve the 42xxx / 2008 enrollment error",
                body=(
                    "Zscaler documents each enrollment code with the "
                    "exact remediation. Pull each unique code from the "
                    "Detected Issues view and follow the linked SOP."
                ),
                bullets=[
                    "42016 clock skew — sync device NTP",
                    "42024 user not found — verify the user exists in the IdP and Zscaler tenant",
                    "Other 42xxx — see Status Code Reference module",
                ],
            ))
        if "saml_issue" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="IdP admin (Entra / Okta / etc.)",
                title="Review the IdP / SAML configuration for Zscaler",
                body=(
                    "Check: IdP signing cert has not silently rotated; "
                    "the Zscaler SP audience matches the IdP "
                    "configuration; CA Sign-in Frequency isn't shorter "
                    "than the realistic re-enrol cadence."
                ),
                effect=(
                    "Eliminates SAML rejection by the broker on the "
                    "next tunnel-setup attempt."
                ),
            ))
        return fixes

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if "enrollment" in self._buckets:
            codes = sorted({getattr(f, "code", "") for f in self._buckets["enrollment"]})
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    f"Which exact enrollment code(s) fired — {', '.join(codes)}? "
                    "Each has a different documented remedy."
                ),
                why_it_matters=(
                    "Determines whether the admin should fix the IdP, the "
                    "device clock, or the Zscaler user provisioning."
                ),
            ))
        if "cert_issue" in self._buckets:
            questions.append(OpenQuestion(
                id="Q2",
                question=(
                    "When was the ZCC client certificate last rotated? "
                    "Is the customer using ZCC-issued certs or their own "
                    "PKI-signed certs?"
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no ZPA auth-failure findings"
        if "cert_issue" in self._buckets:
            return "High — certificate failure blocks all ZPA traffic"
        if "enrollment" in self._buckets:
            return f"High — {len(self._buckets['enrollment'])} enrollment error(s)"
        if "broker_auth" in self._buckets:
            return f"Medium — {len(self._buckets['broker_auth'])} broker auth rejection(s)"
        return f"Medium — {len(self.findings)} auth-failure finding(s)"
