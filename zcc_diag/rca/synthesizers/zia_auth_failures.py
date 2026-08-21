"""
zia_auth_failures RCA synthesizer (Phase 49d, 2026-06-24).

ZIA counterpart to zpa_auth_failures (49c). Same general pattern,
different code family — ZIA auth uses Mobile API (keepAlive, policy
download, unregister), OneID device registration, HTTP 407 from
service edges, SAML fingerprint validation.

Finding codes mapped to Root Cause buckets:

  mobile_api_error    — MOBILE_API_ERROR_{sub}_{code}   (HTTP errors on Mobile API)
  mobile_api_http     — MOBILE_API_HTTP_{code}          (Mac-specific HTTP codes)
  oneid_reg           — ONEID_DEVICE_REG_FAIL_{prod}_{code}
  oneid_keepalive     — ONEID_KEEPALIVE_401              (token expired)
  http_407_sme        — HTTP_407_FROM_SME                (service edge unreachable / auth required)
  saml_fp             — ZPA_SAML_FINGERPRINT_MISMATCH   (SP misconfigured)
  sme_proxy_bad       — SME_PROXY_BAD_STATE             (assigned proxy in bad state)
  other               — anything unrecognized
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
    """Classify a zia_auth_failures finding code into a Root Cause bucket."""
    code = (code or "").upper()
    if code.startswith("MOBILE_API_ERROR_"):
        return "mobile_api_error"
    if code.startswith("MOBILE_API_HTTP_"):
        return "mobile_api_http"
    if code.startswith("ONEID_DEVICE_REG_FAIL_"):
        return "oneid_reg"
    if code == "ONEID_KEEPALIVE_401":
        return "oneid_keepalive"
    if code == "HTTP_407_FROM_SME":
        return "http_407_sme"
    if "SAML_FINGERPRINT" in code:
        return "saml_fp"
    if code == "SME_PROXY_BAD_STATE":
        return "sme_proxy_bad"
    return "other"


class ZiaAuthFailuresSynthesizer(RCASynthesizer):
    """RCA synthesis for the zia_auth_failures detector."""

    synthesizer_id = "zia_auth_failures"
    synthesizer_version = "1.0"
    issue_title = "ZIA Authentication Failures"

    def __init__(self, summary, findings, correlators):
        super().__init__(summary, findings, correlators)
        self._buckets: Dict[str, List] = {}
        for f in self.findings:
            b = _bucket_for_code(getattr(f, "code", "") or "")
            self._buckets.setdefault(b, []).append(f)

    # ──────────────────────────────────────────────── section hooks

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
            # Phase 58e-H6 (2026-07-08): most ZIA auth codes don't tell
            # us whether the user was mid-session or freshly logging in.
            # Use UNKNOWN as the neutral default; SME-level codes still
            # promote to MID_WORK because those are hard proxy breakages
            # that WILL be visible to any active session.
            classification = EventClassification.UNKNOWN
            if code in ("HTTP_407_FROM_SME", "SME_PROXY_BAD_STATE"):
                # SME-level — affects all ZIA traffic. High user impact.
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
            return ["No ZIA authentication failures emitted for this bundle."]
        n = len(self.findings)
        bucket_names = list(self._buckets.keys())
        paras = [
            f"The zia_auth_failures detector emitted **{n} finding(s)** "
            f"across these buckets: `{', '.join(bucket_names)}`."
        ]
        if "http_407_sme" in self._buckets or "sme_proxy_bad" in self._buckets:
            paras.append(
                "**Service edge issues** detected — ZCC's assigned SMEs "
                "returned HTTP 407 (auth required) or entered a bad "
                "state. This blocks ALL ZIA web traffic until the SME "
                "issue clears. See RC-1 for fix."
            )
        if "oneid_reg" in self._buckets:
            paras.append(
                "**OneID device registration failed** — ZCC could not "
                "register the device with the OneID identity service. "
                "This blocks ZIA tunnel establishment. The specific "
                "ONEID_DEVICE_REG_FAIL_*_<code> error gives the exact "
                "reason; consult the Status Code Reference."
            )
        if "saml_fp" in self._buckets:
            paras.append(
                "**SAML fingerprint mismatch** — the Zscaler SP is "
                "rejecting SAML assertions because the IdP signing "
                "certificate hash doesn't match what the SP has stored. "
                "Typical cause: IdP cert rotated without updating the "
                "Zscaler tenant config."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes: List[RootCause] = []
        n = 0

        if "http_407_sme" in self._buckets:
            n += 1
            bucket = self._buckets["http_407_sme"]
            ev = []
            for f in bucket[:1]:
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
                title="Service edge returned HTTP 407 (auth required)",
                mechanism=(
                    "An assigned Zscaler service edge responded HTTP 407 "
                    "to ZCC's tunnel-setup request. The SME is "
                    "reachable, but the auth handshake is being "
                    "rejected. Common causes: customer's user/tenant "
                    "isn't authorised for this cloud, IdP isn't "
                    "responding to the SP for SAML validation, or the "
                    "user account is locked/disabled in the tenant."
                ),
                evidence=ev,
            ))

        if "sme_proxy_bad" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="SME proxy in bad state",
                mechanism=(
                    "ZCC observed an SME consistently rejecting tunnel "
                    "setup or returning malformed responses. The SME "
                    "may be in a maintenance window or experiencing "
                    "a regional outage. Engineer should check the "
                    "Zscaler status page for the assigned cloud + DC."
                ),
            ))

        if "oneid_reg" in self._buckets:
            n += 1
            bucket = self._buckets["oneid_reg"]
            codes = sorted({getattr(f, "code", "") for f in bucket})
            causes.append(RootCause(
                id=f"RC-{n}",
                title=f"OneID device registration failure ({len(codes)} variant(s))",
                mechanism=(
                    f"The OneID identity service returned a documented "
                    f"failure code on device registration. Codes: "
                    f"{', '.join(codes[:5])}"
                    f"{', …' if len(codes) > 5 else ''}. "
                    "Each code maps to a specific provisioning issue — "
                    "check the Status Code Reference for the per-code "
                    "admin remedy."
                ),
            ))

        if "oneid_keepalive" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="OneID keepAlive returning HTTP 401",
                mechanism=(
                    "ZCC's periodic keepAlive to OneID returned HTTP 401 "
                    "with `INVALID TOKEN`. The session token has expired "
                    "or been revoked. ZCC will re-register on the next "
                    "auth cycle. If this happens repeatedly without "
                    "explicit user action, suspect a clock skew, an "
                    "IdP-side session revocation, or a token-lifetime "
                    "policy that's set too aggressively."
                ),
            ))

        if "saml_fp" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="SAML fingerprint mismatch",
                mechanism=(
                    "The Zscaler SP rejected a SAML assertion because "
                    "the IdP's signing certificate fingerprint doesn't "
                    "match what the SP has stored. Cause: the IdP "
                    "signing cert rotated, but the Zscaler tenant's IdP "
                    "configuration still references the old fingerprint."
                ),
            ))

        if "mobile_api_error" in self._buckets or "mobile_api_http" in self._buckets:
            n += 1
            bucket = (
                self._buckets.get("mobile_api_error", [])
                + self._buckets.get("mobile_api_http", [])
            )
            distinct_codes = sorted({
                getattr(f, "code", "") for f in bucket
            })
            causes.append(RootCause(
                id=f"RC-{n}",
                title=f"Mobile API errors ({len(distinct_codes)} distinct variant(s))",
                mechanism=(
                    "ZCC's Mobile API call (keepAlive, policyDownload, "
                    "unregister) returned an HTTP error. Codes observed: "
                    f"{', '.join(distinct_codes[:5])}"
                    f"{', …' if len(distinct_codes) > 5 else ''}. "
                    "5xx codes typically indicate transient SME-side "
                    "issues; 4xx codes indicate ZCC-side or auth-state "
                    "issues (401/403)."
                ),
            ))

        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        factors = []
        if "saml_fp" in self._buckets:
            factors.append(ContributingFactor(
                id="CF-1",
                title="Verify IdP signing-cert rotation hasn't broken multiple tenants",
                body=(
                    "When the IdP signing cert rotates, every Zscaler SP "
                    "that integrates with that IdP needs its stored "
                    "fingerprint refreshed. If this customer is one of "
                    "several, check whether others are also failing."
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
                "Service-edge issues (HTTP 407 / SME bad state)",
                str(len(self._buckets.get("http_407_sme", []))
                    + len(self._buckets.get("sme_proxy_bad", []))),
                highlight=(
                    len(self._buckets.get("http_407_sme", [])) > 0
                    or len(self._buckets.get("sme_proxy_bad", [])) > 0
                ),
            ),
            ImpactMetric(
                "OneID registration failures",
                str(len(self._buckets.get("oneid_reg", []))),
            ),
            ImpactMetric(
                "Mobile API errors",
                str(len(self._buckets.get("mobile_api_error", []))
                    + len(self._buckets.get("mobile_api_http", []))),
            ),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes: List[FixRecommendation] = []
        if "http_407_sme" in self._buckets or "sme_proxy_bad" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="Zscaler / IdP admin",
                title="Resolve service-edge auth rejection",
                body=(
                    "HTTP 407 from the SME means the auth handshake "
                    "failed at the edge. Check:"
                ),
                bullets=[
                    "User is enabled in the Zscaler tenant + assigned the right cloud",
                    "IdP is reachable and responding to SAML requests",
                    "User account isn't locked / disabled / pending password reset",
                    "Customer's authorised SME range hasn't shifted (re-issue cert)",
                ],
                effect="ZIA tunnel can establish.",
            ))
        if "oneid_reg" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Zscaler admin",
                title="Look up each ONEID_DEVICE_REG_FAIL_* code",
                body=(
                    "Each OneID registration error has a documented "
                    "admin remediation in the Status Code Reference "
                    "module. The 4-digit code at the end of each "
                    "finding name maps directly."
                ),
            ))
        if "saml_fp" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="Zscaler tenant admin",
                title="Update IdP signing-cert fingerprint in Zscaler config",
                body=(
                    "Pull the current IdP signing cert and update the "
                    "Zscaler tenant's IdP configuration to match. "
                    "Document the fingerprint rotation date for future "
                    "reference."
                ),
                effect=(
                    "SAML assertions validate; auth handshake "
                    "succeeds."
                ),
            ))
        if "oneid_keepalive" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.MEDIUM,
                owner="IdP admin",
                title="Review token-lifetime policy",
                body=(
                    "If keepAlive 401s are recurring without user "
                    "action, the IdP's session/token lifetime is "
                    "shorter than the keepAlive cadence. Extend the "
                    "lifetime or enable refresh-token rotation."
                ),
            ))
        return fixes

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if "http_407_sme" in self._buckets:
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    "Is the user enabled in the Zscaler tenant for the "
                    "cloud they're assigned to? Are they in the right "
                    "OU / group?"
                ),
            ))
        if "saml_fp" in self._buckets:
            questions.append(OpenQuestion(
                id="Q2",
                question=(
                    "When was the IdP signing certificate last rotated? "
                    "Has the Zscaler tenant config been updated since?"
                ),
            ))
        if "oneid_keepalive" in self._buckets:
            questions.append(OpenQuestion(
                id="Q3",
                question=(
                    "What is the IdP's session lifetime / token expiry? "
                    "Is it shorter than ZCC's keepAlive cadence?"
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no ZIA auth-failure findings"
        if "http_407_sme" in self._buckets or "sme_proxy_bad" in self._buckets:
            return "High — service edge issues block all ZIA traffic"
        if "saml_fp" in self._buckets:
            return "High — SAML rejection blocks new auth handshakes"
        if "oneid_reg" in self._buckets:
            return f"High — {len(self._buckets['oneid_reg'])} OneID registration failure(s)"
        return f"Medium — {len(self.findings)} ZIA auth-failure finding(s)"
