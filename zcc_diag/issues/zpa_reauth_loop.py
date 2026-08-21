"""
Detector: ZPA re-authentication loop.

Phase 34 first cut (2026-06-19). Phase 40 rewrite (2026-06-19, same
day) after Example Tenant A-bundle deep-dive surfaced a fundamental signal
selection error in the first cut:

  - Phase 34 counted `ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED` RPC
    notifications. That RPC fires on every failed mtunnel setup —
    the broker can emit it many times PER auth expiry (one per
    failed tag_id). On the Example Tenant A bundle it produced 88 events with
    a 13.5-min median, which was the broker's *retry* rate, not
    the IdP's *expiry* rate.

  - The real signal lives one layer up in ZSATray:
        "ZPA Auth state changed, From: AUTHENTICATED
         To: AUTHENTICATION_REQUIRED"
    That transition fires exactly once per IdP session expiry —
    18 events on the Example Tenant A bundle with a clean 90-min median, time-
    of-day clustered at 13:00 (the user's login hour) every day.

Phase 40 switches the primary signal source to state transitions
and adds three diagnostic columns the first cut was missing:

  1. Per-day breakdown — see whether the cadence is consistent or
     just spiky on one day. The Example Tenant A case had 2/8/6/2 events per
     day across Jun 15-18, all anchored at the same 13:00 login.

  2. Time-of-day clustering — when the first expiry of every day
     fires at the same hour across multiple days, that's a strong
     signal that the customer's IdP has a "sign-in frequency"
     policy keyed to login time, not to ZPA's timers.

  3. IdP identification by URL — Azure AD, Okta, ADFS, OneLogin,
     Ping. Drives a tailored set of recommendations (Azure CA
     sign-in frequency policy, Okta sign-on policy access-token
     lifetime, etc.) instead of the generic "check your IdP."

  4. Tray-crash correlation — when an expiry coincides with a
     ZSATray crash dump (timestamps within 60s), surface that
     explicitly. The Example Tenant A bundle had two crash dumps exactly at
     20:25 and 21:25 on Jun 17 ↔ EXPIRED events at 20:25:23 and
     21:25:40. Means the tray crashed handling the auth-required
     RPC — user never saw the prompt.
"""

from __future__ import annotations

import re
import statistics
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Primary signal — the ZSATray state-machine transition. Fires once
# per IdP session expiry, so its cadence is the true re-auth rate.
_RE_AUTH_STATE_TO_REQUIRED = re.compile(
    r"ZPA Auth state changed.*To:\s*AUTHENTICATION_REQUIRED",
)

# Recovery transition — used to compute "user response time."
_RE_AUTH_STATE_TO_AUTHENTICATED = re.compile(
    r"ZPA Auth state changed.*"
    r"From:\s*AUTHENTICATION_REQUIRED\s*To:\s*AUTHENTICATED",
)

# RPC notification — secondary noise signal, NOT used for cadence
# (broker retries inflate count). Kept as supplementary evidence.
_RE_REAUTH_RPC = re.compile(
    r"ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED",
)

# IdP identification by URL substring. Order matters — most-specific
# first. Each URL pattern maps to an IdP family with tailored
# recommendations downstream.
_IDP_URL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"login\.microsoftonline\.com"), "azure_ad"),
    (re.compile(r"sts\.windows\.net"),            "azure_ad"),
    (re.compile(r"login\.live\.com"),             "azure_ad"),
    (re.compile(r"\.okta\.com"),                  "okta"),
    (re.compile(r"\.oktapreview\.com"),           "okta"),
    (re.compile(r"adfs"),                         "adfs"),
    (re.compile(r"\.onelogin\.com"),              "onelogin"),
    (re.compile(r"\.pingidentity\.com"),          "ping"),
    (re.compile(r"sso\.connect\.pingidentity"),   "ping"),
    (re.compile(r"\.duosecurity\.com"),           "duo"),
    (re.compile(r"jumpcloud\.com"),               "jumpcloud"),
]

# IdP-family display labels + the URL ZCC redirected to (captured at
# finalize() time from the tray-log scan). Drives the per-IdP
# recommendation block.
_IDP_RECS: Dict[str, Tuple[str, List[str]]] = {
    "azure_ad": (
        "Azure AD / Microsoft Entra ID",
        [
            "In **Entra ID admin center** → Protect → Conditional "
            "Access → Policies, look for any policy targeting the "
            "Zscaler app (or the user's group) with **Session "
            "controls → Sign-in frequency** configured. If it's set "
            "below ZPA's Idle Timeout, that's the source.",
            "If no Sign-in frequency override exists, check the "
            "tenant-wide token lifetime: "
            "`Get-AzureADPolicy | Where-Object "
            "{$_.Type -eq 'TokenLifetimePolicy'}` — a custom policy "
            "applied to the Zscaler service principal can shorten "
            "the access-token lifetime below the AAD default "
            "(1 hour ID, 90-day refresh).",
            "Confirm whether the customer's IdP requires MFA on "
            "every sign-in for this app (MFA-on-sign-in + short "
            "session = the observed pattern).",
            "Recommended fix: align Sign-in frequency to 8h / 12h / "
            "24h depending on the customer's compliance posture, OR "
            "rely on AAD's default behavior (no custom policy).",
        ],
    ),
    "okta": (
        "Okta",
        [
            "In Okta admin → Security → API → Authorization Servers "
            "→ select the server used by the Zscaler app → Access "
            "Policies → check the Rule's **Access token lifetime**. "
            "Okta default is 1 hour; some orgs shorten to 15-90 min.",
            "Check Security → Authentication Policies → the policy "
            "applied to the Zscaler app — look for **Re-authenticate "
            "after** with a short interval.",
            "Okta sign-on policies under Admin → Security → "
            "Authentication can also enforce per-session MFA "
            "re-challenge. Confirm none target the Zscaler app.",
        ],
    ),
    "adfs": (
        "ADFS (Active Directory Federation Services)",
        [
            "Run `Get-AdfsRelyingPartyTrust -Name '<zscaler RP>' | "
            "fl TokenLifetime` on the ADFS server. Default is "
            "0 (use the global setting). Custom values force "
            "re-auth at that interval.",
            "Check `Get-AdfsProperties | fl SsoLifetime` — the "
            "global SSO lifetime. Default is 480 min (8 hours).",
            "Confirm the customer hasn't enabled "
            "`WindowsAuthenticationOnPrem` requiring re-auth.",
        ],
    ),
    "onelogin": (
        "OneLogin",
        [
            "In OneLogin admin → Applications → the Zscaler app → "
            "SSO → check **Session lifetime** under Advanced.",
        ],
    ),
    "ping": (
        "Ping Identity",
        [
            "Check the Ping access policy applied to the Zscaler "
            "Service Provider Connection for session lifetime "
            "and re-authentication settings.",
        ],
    ),
    "duo": (
        "Duo Security",
        [
            "Duo enforces an MFA challenge cadence separate from "
            "the primary IdP session. Check the Duo Application "
            "Policy applied to Zscaler for **MFA Remembered Devices "
            "Expiration**.",
        ],
    ),
    "jumpcloud": (
        "JumpCloud",
        [
            "JumpCloud SSO session lifetime is configured per "
            "Application Authorization Policy. Check the policy "
            "applied to the Zscaler app.",
        ],
    ),
    "unknown": (
        "an unknown IdP",
        [
            "Identify the IdP from any `https://...` URLs in the "
            "tray log around the auth state change. Common "
            "vendors: Microsoft Entra ID, Okta, ADFS, OneLogin, "
            "Ping, Duo. Once identified, audit that vendor's "
            "session-lifetime / sign-in-frequency policy for the "
            "Zscaler app.",
        ],
    ),
}

# An inter-event gap larger than this between consecutive auth-state
# transitions is treated as a session boundary (laptop sleep,
# overnight, user-not-logged-in window), not a re-auth cadence
# event. Excluded from the cadence median.
_SESSION_BOUNDARY_SECONDS = 6 * 3600.0   # 6 hours

# Window around an auth state change where a co-occurring tray crash
# dump file is considered correlated.
_TRAY_CRASH_WINDOW_SECONDS = 60.0

EVIDENCE_CAP = 30


@register
class ZpaReauthLoopDetector(IssueDetector):
    id = "zpa_reauth_loop"
    title = "ZPA re-authentication loop"
    sop_file = "zpa_reauth_loop.md"

    # Primary signal lives in ZSATray (state-machine transitions).
    wants_tray_logs = True
    applies_to_suite = ("zpa",)
    applies_to_os = None
    # Phase 40: the prematch_substrings list now drives BOTH the
    # state-transition match and the IdP URL scan. We need any tray
    # line that contains either marker — broad enough to let the
    # IdP URL detection pass.
    prematch_substrings = (
        "Auth state changed",
        "AUTHENTICATION_REQUIRED",
        "login.microsoftonline.com",
        ".okta.com",
        "adfs",
        ".onelogin.com",
        ".pingidentity.com",
        ".duosecurity.com",
        "jumpcloud.com",
    )

    def __init__(self) -> None:
        super().__init__()
        # AUTHENTICATED → AUTHENTICATION_REQUIRED transitions (primary
        # signal — true IdP expiry rate).
        self._expiries: List[LogLine] = []
        # AUTHENTICATION_REQUIRED → AUTHENTICATED recoveries — used
        # to compute "user response time" + flag never-recovered
        # expiries (tray-crash signal).
        self._recoveries: List[LogLine] = []
        # RPC notification count — supplementary noise tally.
        self._rpc_count: int = 0
        # IdP URL hits keyed by family — first-seen URL per family
        # wins, captured for evidence + reporting.
        self._idp_urls: Dict[str, str] = {}

    # --- IssueDetector overrides ---------------------------------

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        # Auth-state transitions (the GOOD signal).
        if _RE_AUTH_STATE_TO_REQUIRED.search(msg):
            self._expiries.append(record)
            return
        if _RE_AUTH_STATE_TO_AUTHENTICATED.search(msg):
            self._recoveries.append(record)
            return
        # RPC noise — count but don't use for cadence.
        if _RE_REAUTH_RPC.search(msg):
            self._rpc_count += 1
        # IdP URL identification. The same line may contain a URL
        # we recognize.
        for pat, family in _IDP_URL_PATTERNS:
            if pat.search(msg):
                # First match wins for each family. Capture the URL
                # span (up to 200 chars) for evidence.
                if family not in self._idp_urls:
                    m = re.search(r"https?://[^\s\"'>]+", msg)
                    self._idp_urls[family] = (
                        m.group(0) if m else "(URL match)"
                    )
                break

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        # Sort by timestamp — multiplexer feeds tray records in file
        # order which is usually but not strictly monotonic across
        # rotated logs.
        expiries = sorted(self._expiries, key=lambda r: r.timestamp)
        # Dedupe: same instant + same tray-log restart = ZCC echoing
        # the existing AUTH_REQUIRED state. Collapse rapid duplicates
        # (within 15 seconds of the prior event) into one logical
        # expiry. This is the noise the first cut never filtered.
        if len(expiries) >= 2:
            cleaned: List[LogLine] = [expiries[0]]
            for prev_idx, rec in enumerate(expiries[1:], start=0):
                last = cleaned[-1]
                gap = (rec.timestamp - last.timestamp).total_seconds()
                if gap >= 15.0:
                    cleaned.append(rec)
            expiries = cleaned

        n_real = len(expiries)
        if n_real < 3:
            return []

        # ---- Cadence stats (excluding session boundaries) ----
        intervals: List[float] = []
        for i in range(len(expiries) - 1):
            dt = (expiries[i + 1].timestamp
                  - expiries[i].timestamp).total_seconds()
            if 0 < dt < _SESSION_BOUNDARY_SECONDS:
                intervals.append(dt)

        if not intervals:
            return []

        median_s = statistics.median(intervals)
        median_min = median_s / 60.0
        mean_min = sum(intervals) / len(intervals) / 60.0

        # ---- Per-day breakdown ----
        per_day: Dict[Any, List[LogLine]] = {}
        for rec in expiries:
            d = rec.timestamp.date()
            per_day.setdefault(d, []).append(rec)

        # ---- Time-of-day clustering ----
        # If the FIRST expiry of every day clusters within the same
        # hour, that's a strong "IdP sign-in-frequency at login"
        # signal. Compute the mode hour-of-day of first-of-day
        # events.
        first_of_day_hours: List[int] = []
        for d, evs in per_day.items():
            first_of_day_hours.append(evs[0].timestamp.hour)
        tod_cluster: Optional[Tuple[int, int]] = None
        if len(first_of_day_hours) >= 3:
            from collections import Counter
            c = Counter(first_of_day_hours)
            top_hour, top_count = c.most_common(1)[0]
            if top_count >= max(2, len(first_of_day_hours) // 2):
                tod_cluster = (top_hour, top_count)

        # ---- Recovery time + never-recovered count ----
        recoveries = sorted(
            self._recoveries, key=lambda r: r.timestamp,
        )
        recovery_times_s: List[float] = []
        never_recovered = 0
        rec_idx = 0
        for exp in expiries:
            while (
                rec_idx < len(recoveries)
                and recoveries[rec_idx].timestamp < exp.timestamp
            ):
                rec_idx += 1
            if rec_idx >= len(recoveries):
                never_recovered += 1
                continue
            r = recoveries[rec_idx]
            gap = (r.timestamp - exp.timestamp).total_seconds()
            if gap < _SESSION_BOUNDARY_SECONDS:
                recovery_times_s.append(gap)
                rec_idx += 1
            else:
                never_recovered += 1

        median_recovery_min = (
            statistics.median(recovery_times_s) / 60.0
            if recovery_times_s else None
        )

        # ---- IdP identification ----
        idp_family = "unknown"
        idp_url = ""
        # Pick the most-specific match if multiple families saw
        # hits. Azure_ad wins over generic, etc. The order in
        # _IDP_URL_PATTERNS already encodes specificity; first
        # family that has at least one URL match wins here.
        for _, family in _IDP_URL_PATTERNS:
            if family in self._idp_urls:
                idp_family = family
                idp_url = self._idp_urls[family]
                break

        # ---- Tray-crash correlation ----
        # Pull tray-crash timestamps from the summary's bundle_meta
        # if the bundle scanner captured them. Otherwise infer from
        # source file mtimes (best effort).
        crash_correlations = self._correlate_tray_crashes(
            expiries, summary,
        )

        # ---- Severity ----
        severity = self._classify(n_real, median_s, never_recovered)
        if severity is None:
            return []

        # ---- Build the finding ----
        idp_label, idp_recs = _IDP_RECS.get(
            idp_family, _IDP_RECS["unknown"],
        )

        # Title — leads with the cadence and IdP if known.
        title_idp = (
            f" (IdP: {idp_label})"
            if idp_family != "unknown" else ""
        )
        title = (
            f"ZPA re-auth loop — {n_real} IdP expiries, "
            f"median cadence {median_min:.0f} min{title_idp}"
        )

        # Description — leads with the structured observation, then
        # the per-day + time-of-day evidence, then the targeted
        # IdP recommendations.
        desc_parts: List[str] = []
        desc_parts.append(
            f"ZCC's tray-log state machine logged **{n_real} "
            f"AUTHENTICATED → AUTHENTICATION_REQUIRED transitions** "
            f"(distinct IdP expiries — duplicate echoes within 15 s "
            f"were collapsed). Inter-event intervals "
            f"(excluding gaps >6 h, which are session boundaries) "
            f"have a **median of {median_min:.0f} minutes** "
            f"(mean {mean_min:.0f} min)."
        )

        if tod_cluster is not None:
            hh, n_at = tod_cluster
            desc_parts.append(
                f"**Time-of-day pattern:** the first expiry of "
                f"the day fired in the **{hh:02d}:00 hour on "
                f"{n_at} of {len(first_of_day_hours)} days**. That "
                f"alignment with the user's login time is a "
                f"signature of an IdP sign-in-frequency policy "
                f"anchored to the user's session start."
            )

        # Per-day breakdown — compact one-line summary
        day_lines = []
        for d in sorted(per_day):
            day_lines.append(
                f"  • {d} ({d.strftime('%a')}): "
                f"{len(per_day[d])} expir{'y' if len(per_day[d]) == 1 else 'ies'}"
            )
        desc_parts.append(
            "**Per-day breakdown:**\n" + "\n".join(day_lines)
        )

        # Recovery characterisation
        if median_recovery_min is not None:
            desc_parts.append(
                f"**Recovery time:** when the user re-authenticates, "
                f"median time to AUTHENTICATED is "
                f"{median_recovery_min:.1f} min — meaning the user "
                f"IS responsive when they see the prompt. The "
                f"frequency, not the user, is the problem."
            )
        if never_recovered > 0:
            desc_parts.append(
                f"**{never_recovered} of {n_real} expir"
                f"{'y' if never_recovered == 1 else 'ies'} never "
                f"recovered in the bundle's log window.** This "
                f"usually means either the ZCC session ended (machine "
                f"sleep / logoff) OR the tray crashed handling the "
                f"auth-required RPC and the user never saw the prompt."
            )

        # Tray-crash correlation
        if crash_correlations:
            crash_lines = []
            for exp_ts, crash_label in crash_correlations:
                crash_lines.append(
                    f"  • {exp_ts.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"EXPIRED ↔ {crash_label}"
                )
            desc_parts.append(
                f"**Correlated tray crashes** (auth event within "
                f"60 s of a `ZSATray.exe.<pid>.dmp` file mtime):\n"
                + "\n".join(crash_lines)
                + "\nThis means the tray was crashing while "
                "handling the auth-required RPC. Worth escalating "
                "to Zscaler support as a tray-side bug — collect "
                "the dump files."
            )

        # IdP identification
        if idp_family != "unknown":
            desc_parts.append(
                f"**Identified IdP:** {idp_label}. Observed redirect "
                f"target: `{idp_url[:120]}`."
            )
        else:
            desc_parts.append(
                "**IdP not identified from tray logs.** Look at any "
                "`https://...` URLs in the tray log around the "
                "auth state changes to figure out which IdP the "
                "customer is using before applying recommendations."
            )

        # Recommendations — tailored to the identified IdP.
        rec_block = "\n".join(
            f"{i + 1}. {step}" for i, step in enumerate(idp_recs)
        )
        desc_parts.append(
            f"**Recommended next steps ({idp_label}):**\n{rec_block}"
        )

        # Supplementary RPC noise tally — calibration aid.
        if self._rpc_count:
            desc_parts.append(
                f"_For context: {self._rpc_count} "
                f"`ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED` RPC "
                f"notifications were observed across all sessions. "
                f"The RPC is the broker's per-tag_id retry signal "
                f"(many per actual expiry), so the **{n_real} "
                f"state-machine transitions** above are the truer "
                f"count of IdP-driven re-auth events._"
            )

        f = self._bucket(
            "ZPA_REAUTH_LOOP",
            severity,
            title,
            "\n\n".join(desc_parts),
            sop_anchor="#azure-ad-conditional-access-sign-in-frequency",
        )
        for rec in expiries[:EVIDENCE_CAP]:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        f.count = n_real
        return [f]

    # --- helpers ----------------------------------------------

    @staticmethod
    def _classify(
        n: int, median_s: float, never_recovered: int,
    ) -> Optional[Severity]:
        """Map (count, median interval, never-recovered count) to a
        severity bucket. Now calibrated against state-transition
        cadence (~90 min for Example Tenant A), not RPC noise.

        - CRITICAL: ≥5 expiries with median < 6h AND at least one
          unrecovered expiry, OR ≥10 expiries regardless.
        - WARNING: ≥4 expiries with median < 4h.
        - INFO: ≥3 expiries with median < 12h.
        - None: below floor.
        """
        if n >= 10 and median_s < 6 * 3600.0:
            return Severity.CRITICAL
        if n >= 5 and median_s < 6 * 3600.0 and never_recovered >= 1:
            return Severity.CRITICAL
        if n >= 4 and median_s < 4 * 3600.0:
            return Severity.WARNING
        if n >= 3 and median_s < 12 * 3600.0:
            return Severity.INFO
        return None

    @staticmethod
    def _correlate_tray_crashes(
        expiries: List[LogLine],
        summary: BundleSummary,
    ) -> List[Tuple[datetime, str]]:
        """If the bundle summary captured tray-crash dump timestamps,
        match each one against the auth expiries within 60 s and
        return the (expiry_ts, crash_label) pairs.

        BundleSummary's bundle_meta is the conventional carrier; we
        accept either ``tray_crash_dumps`` (list of dicts with
        ``ts`` + ``filename``) or ``tray_crashes`` (same shape).
        Falls back to empty list if nothing is captured.
        """
        bm = getattr(summary, "bundle_meta", {}) or {}
        crashes_raw = (
            bm.get("tray_crash_dumps")
            or bm.get("tray_crashes")
            or []
        )
        crashes: List[Tuple[datetime, str]] = []
        for c in crashes_raw:
            if not isinstance(c, dict):
                continue
            ts = c.get("ts") or c.get("timestamp")
            name = c.get("filename") or c.get("name") or "tray crash dump"
            if isinstance(ts, datetime):
                crashes.append((ts, name))
        if not crashes:
            return []
        out: List[Tuple[datetime, str]] = []
        for exp in expiries:
            for crash_ts, label in crashes:
                if abs(
                    (crash_ts - exp.timestamp).total_seconds()
                ) <= _TRAY_CRASH_WINDOW_SECONDS:
                    out.append((exp.timestamp, label))
                    break
        return out

    @staticmethod
    def _get_policy_seconds(
        summary: BundleSummary,
        *keys: str,
    ) -> Optional[float]:
        """Best-effort lookup of a policy timeout (in seconds) from
        the BundleSummary. Same as Phase 34. Currently unused by
        the rewrite but kept for any caller that imports it."""
        bm = getattr(summary, "bundle_meta", {}) or {}
        policy = bm.get("app_profile") or bm.get("policy") or {}
        if not isinstance(policy, dict):
            return None
        for k in keys:
            v = policy.get(k)
            if v is None:
                continue
            try:
                f = float(v)
                if f > 0:
                    return f
            except (TypeError, ValueError):
                continue
        return None
