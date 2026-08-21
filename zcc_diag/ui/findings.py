"""
Finding rendering — cards, lists, TL;DR, drill-down, Copy-as-Markdown.

Everything that turns a Finding dict into pixels lives here. The data
side (clustering, root-cause families, detector groups) is in
``zcc_diag.ui.clustering`` — keeping data and presentation separate
prevents the import cycle that would arise if clustering tried to
import the render helpers.

Public API (legacy underscore names are kept as aliases at the bottom
so existing call sites in ``zcc_diag_ui.py`` keep working):

  * ``real_findings(findings)``         — exclude DETECTOR_SKIPPED_FOR_OS
  * ``skipped_findings(findings)``      — only DETECTOR_SKIPPED_FOR_OS
  * ``consolidate_dupes(findings)``     — merge findings sharing (detector_id, code)
  * ``finding_as_markdown(f)``          — Slack/JIRA-ready Markdown block
  * ``render_tldr(findings, label)``    — top-of-page severity-counted panel
  * ``render_finding_detail(f)``        — drill-down view of one finding
  * ``render_finding_card(f, *, default_open)`` — bordered severity card
  * ``render_root_cause_cluster(c)``    — primary card + supporting signals
  * ``render_finding_list(findings, empty)`` — full grouped+clustered list
"""

from __future__ import annotations

from typing import Any, Dict, List

import streamlit as st

from zcc_diag.issues import Severity
from zcc_diag.wizard import _next_step_for
from zcc_diag.ui.severity import _sev_badge_html, _SEV_CLS, SEV_WORD
from zcc_diag.ui.redact import redact
from zcc_diag.ui.clustering import (
    _DETECTOR_GROUPS,
    _cluster_by_root_cause,
)
from zcc_diag.data import (
    get_session_code, get_auth_error,
    get_tray_status, get_zcc_error,
    get_policy_reason,
    get_zia_auth_error,
    get_zdx_web_probe_error,
    get_zdx_cloud_path_error,
    get_zdx_remediation_error,
    get_zdx_managed_probe_error,
)


# ----------------------------------------------------------------------
# Documented-category chip helper (2026-06-12 phase 2 UI).
#
# Given a finding's code, look up whether it corresponds to a documented
# Zscaler status code and return an HTML chip indicating the documentation
# category. The chip surfaces three facts that engineers otherwise had
# to deduce from reading the description:
#
#   1. "Info Code · No action required" — the event is in the Info
#      Codes table of the Zscaler documentation, documented as normal closure.
#      Surfaced so engineers don't waste time triaging non-incidents.
#
#   2. "Error Code" — the event is in the Error Codes table, documented
#      as a real failure. Reinforces the severity badge.
#
#   3. "Policy Block · Working as designed" — the event is in the Policy
#      Block table, an intentional service decision rather than a
#      failure. Helps engineers reframe customer complaints about
#      "Zscaler blocking me" as "Zscaler enforcing your configured
#      policy".
#
# Returns an empty string for codes that aren't in the data module
# (LOG-EVIDENCE detectors, customer-grounded patterns, etc.) so the
# header doesn't get cluttered when the documented category is unknown.
# Detector-internal code → documented Zscaler code alias map.
# Some detectors bucket findings under a friendlier internal name
# (e.g. ZpaAppSessionsDetector uses "ZPA_APP_SESSION_CLOSED" because
# the documented code "BRK_MT_CLOSED_FROM_ASSISTANT" is verbose and
# its semantics have a separate detector-side framing). The chip
# lookup is over DOCUMENTED codes, so without an alias the chip
# never appears. Caught by sandbox test 2026-06-12; fixed by mapping
# detector-internal codes back to their documented equivalents.
_DETECTOR_CODE_ALIASES = {
    "ZPA_APP_SESSION_CLOSED": "BRK_MT_CLOSED_FROM_ASSISTANT",
}


def _chip_html(kind: str, label: str, tooltip: str) -> str:
    """Render one category-chip HTML span.

    kind:  "info" | "error" | "policy"  (maps to CSS class suffix)
    label: visible chip text
    tooltip: hover-help text
    """
    return (
        f'<span class="zd-cat-chip zd-cat-{kind}" '
        f'title="{tooltip}">'
        f'{label}'
        f'</span>'
    )


def _documented_category_chip_html(code: str) -> str:
    """Return the HTML for the documented-category chip, or an empty
    string when the code isn't a documented status code.

    The lookup strips compound suffixes that the broker_assistant_close
    detector uses (e.g. ``ZPA_APP_SESSION_CLOSED::salesforce.com``) so
    the underlying documented code is still recognized.
    """
    # Strip our compound suffixes (after ``::``) — the detector
    # bucket-keys app names onto codes; the documented part is on the
    # left.
    bare = code.split("::", 1)[0] if "::" in code else code

    # Apply detector-internal → documented alias map. Caught by
    # sandbox test 2026-06-12 — ZPA_APP_SESSION_CLOSED is the
    # detector-internal name for BRK_MT_CLOSED_FROM_ASSISTANT and
    # was not getting a chip without this translation.
    bare = _DETECTOR_CODE_ALIASES.get(bare, bare)

    # Some detector bucket keys are *derived* from documented codes by
    # stripping the BRK_MT_SETUP_FAIL_ / BRK_MT_AUTH_ / ZPN_ERR_ prefix
    # at emission time. Try both the bare code AND the obvious
    # documented prefixes to maximize hit rate.
    candidates = [bare]

    info = None
    for cand in candidates:
        info = get_session_code(cand)
        if info is not None:
            break

    if info is None:
        # Maybe it's an auth error code (42xxx)?
        if bare.startswith("PA_ERROR_"):
            err_code = bare[len("PA_ERROR_"):]
            ae = get_auth_error(err_code)
            if ae is not None:
                # All 42xxx codes are documented errors.
                return (
                    '<span class="zd-cat-chip zd-cat-error" '
                    'title="Documented in the Zscaler Private Access '
                    'Authentication Errors documentation. This is a real '
                    'enrollment failure requiring action.">'
                    'Error Code'
                    '</span>'
                )

        # Phase 4: maybe it's a tray-status name (DRIVER_ERROR,
        # ENDPOINT_FW_AV_ERROR, etc.)? Detectors often emit codes
        # derived from the tray status — try a few translations.
        tray_candidates = [
            bare.replace("_", " ").title(),  # DRIVER_ERROR -> Driver Error
            bare.replace("_", " "),
            bare,
        ]
        for cand in tray_candidates:
            ts = get_tray_status(cand)
            if ts is not None:
                cat = ts.get("category", "")
                if cat == "info":
                    return _chip_html("info",
                        "Info Code · No action required",
                        "Documented in ZCC Connection Status Errors documentation as no-action-required.")
                if cat == "warning":
                    return _chip_html("policy",
                        "Documented warning",
                        "Documented in ZCC Connection Status Errors documentation.")
                return _chip_html("error", "Error Code",
                    "Documented in ZCC Connection Status Errors documentation.")

        # Phase 4: maybe it's a numeric ZCC error code referenced by
        # the finding (e.g. code "3049", "10108")? Detectors that
        # store the literal code string would match here.
        ze = get_zcc_error(bare)
        if ze is not None:
            return _chip_html("error",
                f"ZCC Error {bare}",
                f"Documented in ZCC Errors documentation (series: {ze.get('series', 'unknown')}).")

        # Phase 6: maybe it's a ZIA Policy Reason string (e.g. a
        # finding whose code literally is "Blocked due to Server Probe
        # Failure" or similar)? These come from Insights/NSS so they
        # rarely appear as detector codes today, but the lookup is
        # cheap and future-proofs us.
        pr = get_policy_reason(code)  # try exact case first
        if pr is None:
            pr = get_policy_reason(bare)
        if pr is not None:
            cat = pr.get("category", "policy_block")
            feature = pr.get("feature", "")
            if cat == "info":
                return _chip_html("info",
                    "Allow (ZIA Policy)",
                    f"Documented ZIA allow action ({feature}).")
            if cat == "warning":
                return _chip_html("policy",
                    "Caution (ZIA Policy)",
                    f"Documented ZIA caution / quarantine ({feature}).")
            if cat == "error":
                return _chip_html("error",
                    "ZIA System Error",
                    f"Documented ZIA system error ({feature}) — Service Edge ↔ CA path issue.")
            return _chip_html("policy",
                "Policy Block (ZIA)",
                f"Documented ZIA policy block ({feature}) — working as designed.")

        # Phase 7 (2026-06-17): maybe it's a ZIA authentication error
        # code? Four categories — Generic (211000/421000), AD-LDAP Sync
        # (100..116), Kerberos (391000/441000/461000/451000/471000/
        # 48100/491000/501000/510000), and Identity Proxy (0x1388..
        # 0x13D2). User-facing codes shown on the Zscaler error page
        # when ZIA auth fails. Done LAST in the cascade because a
        # numeric LDAP code like "100" could in principle collide with
        # arbitrary numeric tokens — checking earlier sources first
        # (ZPA session, ZPA auth, tray, ZCC error, ZIA policy reason)
        # keeps disambiguation tight.
        zae = get_zia_auth_error(code) or get_zia_auth_error(bare)
        if zae is not None:
            cat = zae.get("category", "")
            sev_hint = zae.get("severity_hint", "warning")
            # Map category to a friendly chip label.
            cat_label_map = {
                "generic": "ZIA Auth (Generic)",
                "ldap_sync": "ZIA Auth (AD-LDAP)",
                "kerberos": "ZIA Auth (Kerberos)",
                "identity_proxy": "ZIA Auth (Identity Proxy)",
            }
            label = cat_label_map.get(cat, "ZIA Auth Error")
            tooltip = (
                f"Documented in the ZIA Authentication Error Codes documentation "
                f"({cat.replace('_', ' ')}). "
                + ("Real failure requiring action."
                   if sev_hint == "critical"
                   else "Retry / transient flag — see action text.")
            )
            kind = "error" if sev_hint == "critical" else "policy"
            return _chip_html(kind, label, tooltip)

        # Phase 8 (2026-06-17): ZDX (Digital Experience Monitoring)
        # cascades. Four sources covering Web Probe, Cloud Path,
        # Remediation, and Managed Probe. ZDX codes are typically
        # message strings (e.g. "TCP connection was reset") rather
        # than symbolic codes, so we match against both the identifier
        # slug AND the documented error_message via each helper's tolerant
        # lookup. Order: Web Probe → Cloud Path → Remediation (prefix
        # ZUPM_WORKFLOW_E_CODE_ is unmistakable) → Managed Probe.

        zdx_w = get_zdx_web_probe_error(code) or get_zdx_web_probe_error(bare)
        if zdx_w is not None:
            phase = zdx_w.get("probe_phase", "")
            sev_hint = zdx_w.get("severity_hint", "warning")
            kind = ("error" if sev_hint == "critical"
                    else "info" if sev_hint == "info" else "policy")
            label = f"ZDX Web Probe ({phase.replace('_', ' ')})"
            return _chip_html(kind, label,
                "Documented in the ZDX Web Probe Errors documentation.")

        zdx_cp = get_zdx_cloud_path_error(code) or get_zdx_cloud_path_error(bare)
        if zdx_cp is not None:
            phase = zdx_cp.get("probe_phase", "")
            sev_hint = zdx_cp.get("severity_hint", "warning")
            zpa_via = zdx_cp.get("zpa_via_zdx", False)
            kind = ("error" if sev_hint == "critical"
                    else "info" if sev_hint == "info" else "policy")
            label = ("ZDX Cloud Path (ZPA-via-ZDX)" if zpa_via
                     else f"ZDX Cloud Path ({phase.replace('_', ' ')})")
            return _chip_html(kind, label,
                "Documented in the ZDX Cloud Path Errors documentation.")

        # Remediation prefix is unmistakable — short-circuit on prefix
        # check before the helper for clarity.
        if bare.startswith("ZUPM_WORKFLOW_E_CODE_") or code.startswith("ZUPM_WORKFLOW_E_CODE_"):
            zdx_r = get_zdx_remediation_error(code) or get_zdx_remediation_error(bare)
            if zdx_r is not None:
                fam = zdx_r.get("family", "")
                sev_hint = zdx_r.get("severity_hint", "warning")
                kind = ("error" if sev_hint == "critical"
                        else "info" if sev_hint == "info" else "policy")
                label = f"ZDX Remediation ({fam})"
                return _chip_html(kind, label,
                    "Documented in the ZDX Remediation Errors documentation.")
        else:
            zdx_r = get_zdx_remediation_error(code) or get_zdx_remediation_error(bare)
            if zdx_r is not None:
                fam = zdx_r.get("family", "")
                sev_hint = zdx_r.get("severity_hint", "warning")
                kind = ("error" if sev_hint == "critical"
                        else "info" if sev_hint == "info" else "policy")
                label = f"ZDX Remediation ({fam})"
                return _chip_html(kind, label,
                    "Documented in the ZDX Remediation Errors documentation.")

        zdx_mp = get_zdx_managed_probe_error(code) or get_zdx_managed_probe_error(bare)
        if zdx_mp is not None:
            ptype = zdx_mp.get("probe_type", "")
            cat = zdx_mp.get("category", "")
            sev_hint = zdx_mp.get("severity_hint", "warning")
            kind = ("error" if sev_hint == "critical"
                    else "info" if sev_hint == "info" else "policy")
            label = f"ZDX Managed Probe ({ptype.replace('_', ' ')})"
            return _chip_html(kind, label,
                f"Documented in the ZDX Zscaler Managed Probe Errors documentation ({cat}).")

        return ""

    category = info.get("category", "")
    if category == "info":
        return (
            '<span class="zd-cat-chip zd-cat-info" '
            'title="Documented in the Info Codes table of the Zscaler '
            'Session Status Codes documentation. Per docs, no action required — '
            'this is the normal session lifecycle.">'
            'Info Code · No action required'
            '</span>'
        )
    if category == "policy_block":
        return (
            '<span class="zd-cat-chip zd-cat-policy" '
            'title="Documented in the Policy Block Codes table. This '
            'is an intentional service decision (policy enforcement, '
            'timeout policy, etc.), not a failure. The configured '
            'behaviour is working.">'
            'Policy Block · Working as designed'
            '</span>'
        )
    if category == "error":
        return (
            '<span class="zd-cat-chip zd-cat-error" '
            'title="Documented in the Error Codes table. Real failure '
            'per Zscaler docs — action required.">'
            'Error Code'
            '</span>'
        )
    return ""


def _documented_category_label(code: str) -> str:
    """Plain-text variant of the chip helper, suitable for the
    Markdown export. Returns a documented-category label or an empty
    string when the code isn't recognized.
    """
    bare = code.split("::", 1)[0] if "::" in code else code
    # Apply detector-internal alias map (same as the chip helper).
    bare = _DETECTOR_CODE_ALIASES.get(bare, bare)

    # First: ZPA session status codes (Phase 2).
    info = get_session_code(bare)
    if info is not None:
        category = info.get("category", "")
        if category == "info":
            return "Info Code (no action required per Zscaler docs)"
        if category == "policy_block":
            return "Policy Block (working as designed per Zscaler docs)"
        if category == "error":
            return "Error Code (action required per Zscaler docs)"

    # Second: ZPA 42xxx auth errors (Phase 2).
    if bare.startswith("PA_ERROR_"):
        err_code = bare[len("PA_ERROR_"):]
        if get_auth_error(err_code) is not None:
            return "Error Code (PA Authentication Errors documentation)"

    # Third: ZCC tray status messages (Phase 4).
    for cand in (
        bare.replace("_", " ").title(),
        bare.replace("_", " "),
        bare,
    ):
        ts = get_tray_status(cand)
        if ts is not None:
            cat = ts.get("category", "")
            if cat == "info":
                return "Info (no action required per ZCC Connection Status documentation)"
            if cat == "warning":
                return "Documented warning (ZCC Connection Status documentation)"
            return "Error Code (ZCC Connection Status documentation)"

    # Fourth: numeric ZCC error codes (Phase 4).
    ze = get_zcc_error(bare)
    if ze is not None:
        series = ze.get("series", "unknown")
        return f"ZCC Error {bare} ({series} series, ZCC Errors documentation)"

    # Fifth: ZIA Policy Reasons (Phase 6).
    pr = get_policy_reason(code) or get_policy_reason(bare)
    if pr is not None:
        feature = pr.get("feature", "")
        cat = pr.get("category", "policy_block")
        if cat == "info":
            return f"Allow (ZIA Policy Reasons documentation, {feature})"
        if cat == "warning":
            return f"Caution (ZIA Policy Reasons documentation, {feature})"
        if cat == "error":
            return f"ZIA System Error (ZIA Policy Reasons documentation, {feature})"
        return f"Policy Block (ZIA Policy Reasons documentation, {feature})"

    # Sixth: ZIA Authentication Error Codes (Phase 7).
    zae = get_zia_auth_error(code) or get_zia_auth_error(bare)
    if zae is not None:
        cat = zae.get("category", "")
        cat_label_map = {
            "generic": "Generic",
            "ldap_sync": "AD-LDAP Sync",
            "kerberos": "Kerberos",
            "identity_proxy": "Identity Proxy",
        }
        nice = cat_label_map.get(cat, cat)
        sev_hint = zae.get("severity_hint", "warning")
        suffix = ("action required" if sev_hint == "critical"
                  else "retry / transient")
        return f"ZIA Auth Error · {nice} ({suffix} per ZIA Auth Error Codes documentation)"

    # Seventh: ZDX Web Probe (Phase 8).
    zdx_w = get_zdx_web_probe_error(code) or get_zdx_web_probe_error(bare)
    if zdx_w is not None:
        phase = zdx_w.get("probe_phase", "")
        return f"ZDX Web Probe · {phase.replace('_', ' ')} (ZDX Web Probe Errors documentation)"

    # Eighth: ZDX Cloud Path (Phase 8).
    zdx_cp = get_zdx_cloud_path_error(code) or get_zdx_cloud_path_error(bare)
    if zdx_cp is not None:
        zpa_via = zdx_cp.get("zpa_via_zdx", False)
        if zpa_via:
            return "ZDX Cloud Path · ZPA-via-ZDX (cross-suite, ZDX Cloud Path Errors documentation)"
        phase = zdx_cp.get("probe_phase", "")
        return f"ZDX Cloud Path · {phase.replace('_', ' ')} (ZDX Cloud Path Errors documentation)"

    # Ninth: ZDX Remediation (Phase 8). ZUPM_WORKFLOW_E_CODE_* prefix.
    zdx_r = get_zdx_remediation_error(code) or get_zdx_remediation_error(bare)
    if zdx_r is not None:
        fam = zdx_r.get("family", "")
        return f"ZDX Remediation · {fam} (ZDX Remediation Errors documentation)"

    # Tenth: ZDX Managed Probe (Phase 8).
    zdx_mp = get_zdx_managed_probe_error(code) or get_zdx_managed_probe_error(bare)
    if zdx_mp is not None:
        ptype = zdx_mp.get("probe_type", "")
        cat = zdx_mp.get("category", "")
        return f"ZDX Managed Probe · {ptype.replace('_', ' ')} / {cat} (ZDX Managed Probe Errors documentation)"

    return ""


# ----------------------------------------------------------------------
# Pure-data helpers
# ----------------------------------------------------------------------

_SKIP_MARKER_CODES = frozenset({
    "DETECTOR_SKIPPED_FOR_OS",
    # Phase 29-A (2026-06-17): also exclude suite-skipped markers.
    # These were appearing in the user-visible Findings tabs as
    # "Info" entries telling the operator a ZPA detector was
    # skipped because ZPA isn't enrolled — useful for traceability,
    # but noise on the triage path. Surface them only via the
    # Overview's "Detector coverage" expander (which uses
    # skipped_findings() to fetch them).
    "DETECTOR_SKIPPED_FOR_SUITE",
})


def real_findings(findings):
    """All findings EXCEPT the OS/suite-skipped marker findings.

    Those exist for traceability but shouldn't be counted as 'findings'
    in any UI surface (they're noise to the operator — they just mean
    'this detector is for a different OS / suite').
    """
    return [
        f for f in findings if f["code"] not in _SKIP_MARKER_CODES
    ]


def skipped_findings(findings):
    """Inverse of :func:`real_findings` — only the skipped markers
    (both OS-skipped and suite-skipped, since they share the same
    "this detector didn't run, here's why" role)."""
    return [
        f for f in findings if f["code"] in _SKIP_MARKER_CODES
    ]


def consolidate_dupes(findings):
    """Group findings by (detector_id, code) and merge duplicates.

    Some detectors emit one Finding per occurrence rather than one
    bucket per code (legacy behavior). Renderers shouldn't have to know
    that — this collapses ``N`` findings sharing a (detector_id, code)
    into a single representative card with ``count = sum``, time range
    spanning all, and severity = max across the group.
    """
    sev_rank = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for f in findings:
        key = (f["detector_id"], f["code"])
        groups.setdefault(key, []).append(f)

    out = []
    for key, group in groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        # Pick the most-severe finding as base, merge counters from rest.
        base = min(group, key=lambda x: sev_rank.get(x["severity"], 9))
        merged = dict(base)
        merged["count"] = sum(f.get("count", 0) for f in group)
        t_ranges = [f.get("time_range") for f in group if f.get("time_range")]
        if t_ranges:
            merged["time_range"] = (
                min(tr[0] for tr in t_ranges),
                max(tr[1] for tr in t_ranges),
            )
        # Title: prefix with N× to make consolidation visible.
        merged["title"] = (
            f"{len(group)}× {base['title'].split(' — ', 1)[-1]}"
            if len(group) > 1 else base["title"]
        )
        # Merge evidence (cap at 20 to avoid bloat).
        ev = []
        for f in group:
            ev.extend(f.get("evidence") or [])
        merged["evidence"] = ev[:20]
        # Description: append a consolidation note.
        merged["description"] = (
            base.get("description", "")
            + f"\n\n[Consolidated from {len(group)} duplicate finding(s) "
            f"sharing the same detector::code.]"
        )
        out.append(merged)
    return out


def finding_as_markdown(f: Dict[str, Any]) -> str:
    """Render a finding as a self-contained Markdown block suitable
    for pasting into Slack, JIRA, Notion, or a status doc."""
    sev_label = {
        Severity.CRITICAL: "CRITICAL",
        Severity.WARNING: "WARNING",
        Severity.INFO: "INFO",
    }.get(f["severity"], "")

    # Documented-category banner — same data source as the UI chip.
    # Surface in the Markdown export so engineers pasting into Slack
    # / JIRA see the documented category context too.
    cat_label = _documented_category_label(f.get("code", ""))

    # Phase 60a-Task-7 (2026-07-10): include the confidence signal in
    # the Markdown export so the recipient sees credibility next to
    # severity. Computed on-demand if the finding doesn't carry it
    # yet (e.g. Markdown copy triggered before any card rendered).
    conf_label_txt = ""
    try:
        from zcc_diag.ui.confidence import label_for as _conf_label
        _lvl, _score, _ = _conf_label(f)
        conf_label_txt = f"  ·  **Confidence:** {_lvl.display_name} ({_score}/100)"
    except Exception:
        pass

    lines = [
        f"## {sev_label}: {f['title']}",
        "",
        f"**Detector:** `{f['detector_id']}::{f['code']}`  ·  "
        f"**Count:** {f['count']}"
        + conf_label_txt
        + (f"  ·  **Documented category:** {cat_label}" if cat_label else ""),
    ]
    if f.get("time_range"):
        t0, t1 = f["time_range"]
        if t0 == t1 or not t1:
            lines.append(f"**Time:** `{t0.isoformat()}`")
        else:
            lines.append(
                f"**Time range:** `{t0.isoformat()}` → "
                f"`{t1.isoformat()}`"
            )
    next_step = _next_step_for(f["detector_id"])
    if next_step and not next_step.startswith("See SOP"):
        lines.append("")
        lines.append(f"**Next step:** {next_step}")

    desc = (f.get("description") or "").strip()
    if desc:
        lines.append("")
        lines.append("**Description:**")
        lines.append("> " + desc.replace("\n", "\n> "))

    # First 3 evidence lines so the recipient has SOMETHING to verify.
    if f.get("evidence"):
        lines.append("")
        lines.append("**Evidence (first 3 of "
                     f"{len(f['evidence'])}):**")
        for ev in f["evidence"][:3]:
            line_no = ev.get("line_no") or "?"
            raw = (ev.get("raw") or "").strip()[:200]
            # Apply PII redaction to both the path (may have user
            # directories) and the log-line preview.
            lines.append(
                f"- `{redact(ev['src'])}:{line_no}` — {redact(raw)}"
            )

    lines.append("")
    lines.append("_Surfaced by zcc_diag — see SOP for full triage._")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Render helpers — these all assume Streamlit is in an active context.
# ----------------------------------------------------------------------

def render_tldr(findings, label="Triage TL;DR"):
    """Severity-counted top-of-output panel. Plain-text section
    headers use the sentence-case ``SEV_WORD`` vocabulary
    (Critical / Warning / Info); the coloured HTML pill badge
    appears only in markdown-rendered text."""
    st.subheader(label)
    crit = [f for f in findings if f["severity"] == Severity.CRITICAL]
    warn = [f for f in findings if f["severity"] == Severity.WARNING]
    info = [f for f in findings if f["severity"] == Severity.INFO
            and f["code"] != "DETECTOR_SKIPPED_FOR_OS"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("CRITICAL", len(crit))
    c2.metric("WARNING", len(warn))
    c3.metric("INFO", len(info))
    c4.metric("Total findings", len(findings))

    top_pool = crit or warn or info
    if top_pool:
        top = top_pool[0]
        # Use markdown with unsafe_allow_html so the badge renders.
        st.markdown(
            f"### {_sev_badge_html(top['severity'])} "
            f"Most likely root issue: {top['title']}",
            unsafe_allow_html=True,
        )
        if top.get("time_range"):
            t0 = top["time_range"][0]
            st.caption(f"When: {t0.isoformat()}")
        st.markdown(
            f"**Detector:** `{top['detector_id']}`  \n"
            f"**Next step:** {_next_step_for(top['detector_id'])}"
        )

    others = [
        f for f in (crit + warn)
        if f is not (top_pool[0] if top_pool else None)
    ][:4]
    if others:
        st.markdown("**Other findings worth reviewing**")
        for f in others:
            st.markdown(
                f"- {_sev_badge_html(f['severity'])} **{f['title']}**  \n"
                f"  *Next step:* {_next_step_for(f['detector_id'])}",
                unsafe_allow_html=True,
            )

    if not findings:
        st.success(
            "No findings fired. Bundle looks healthy on the detector "
            "axes that were checked."
        )


def render_finding_detail(f):
    """Drill-down for a single finding. Called inside an already-open
    expander, so do NOT put the title-badge HTML in the expander label.
    """
    st.markdown(
        f"### {_sev_badge_html(f['severity'])} {f['title']}",
        unsafe_allow_html=True,
    )
    meta = []
    meta.append(f"`{f['detector_id']}::{f['code']}`")
    meta.append(f"Count: {f['count']}")
    if f.get("time_range"):
        t0, t1 = f["time_range"]
        meta.append(f"When: {t0.isoformat()}")
        if t0 != t1:
            meta.append(f"→ {t1.isoformat()}")
    st.caption(" · ".join(meta))

    next_step = _next_step_for(f["detector_id"])
    if next_step and not next_step.startswith("See SOP"):
        st.info(f"**Next step:** {next_step}")

    st.markdown("**Description**")
    st.text(f["description"])

    if f.get("evidence"):
        with st.expander(
            f"Evidence ({len(f['evidence'])} sample(s))",
            expanded=True,
        ):
            for ev in f["evidence"]:
                line_no = ev.get("line_no") or "?"
                # Redact both the source path and the raw log line —
                # both can carry hostnames / usernames / public IPs.
                st.code(
                    f"[{ev['ts'].isoformat()}]  "
                    f"{redact(ev['src'])}:{line_no}\n"
                    f"  {redact(ev['raw'])}",
                    language="text",
                )

    if f.get("sop"):
        with st.expander("SOP guidance", expanded=False):
            st.text(f["sop"])

    if f.get("correlation"):
        c = f["correlation"]
        with st.expander(
            f"Surrounding log activity (+/- 5 min, "
            f"{c['total']} records, {len(c['errs'])} ERROR/WARN)",
            expanded=False,
        ):
            if c["errs"]:
                for err in c["errs"]:
                    st.code(
                        f"[{err['ts'].isoformat()}]  {err['src']}\n"
                        f"  {err['raw']}",
                        language="text",
                    )
            else:
                st.write("(no ERROR/WARN records in window)")


def render_finding_card(
    f: Dict[str, Any], *, default_open: bool = False,
):
    """Severity-coloured finding card with hierarchical info + lazy
    sub-section expanders for evidence / SOP / correlation.

    Each card is wrapped in a Streamlit container so the full block
    (header + next-step + expanders) sits inside a single bordered
    box. Previously the head was a styled div but the expanders below
    it weren't visually contained, so a subsequent INFO card looked
    like it was nested under the preceding CRITICAL card.
    """
    cls = _SEV_CLS.get(f["severity"], "")
    badge = _sev_badge_html(f["severity"])
    code = f"{f['detector_id']}::{f['code']}"

    # Phase 60a-Task-7 (2026-07-10): compute a per-finding confidence
    # signal if the detector didn't set one explicitly. Confidence is
    # ORTHOGONAL to severity — a CRITICAL finding with 1 evidence line
    # and no documented code is still credible-but-shaky; a WARNING
    # with 200 evidence lines matching a documented broker code is
    # rock-solid. The existing pill renderer below reads
    # ``f.get("confidence")`` (lowercase "high"/"medium"/"low") and the
    # existing ``zd-conf-*`` CSS classes; we just fill in the value.
    if not f.get("confidence"):
        try:
            from zcc_diag.ui.confidence import label_for as _conf_label
            _lvl, _score, _reason = _conf_label(f)
            # ``_lvl.value`` is lowercase — slots directly into CSS class
            f["confidence"] = _lvl.value
            # Store the numeric score + reason on the finding too, so the
            # tooltip below can surface the "why" text and Markdown export
            # can carry the exact number.
            f["_confidence_score"] = _score
            f["_confidence_reason"] = _reason
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "confidence computation failed; skipping pill"
            )

    # Two-row header layout (Batch 1.3):
    #   Row 1 (prominent):  [badge]  title text                     [count chip]
    #   Row 2 (caption):    detector::code  ·  timestamp  ·  confidence
    when_caption = ""
    if f.get("time_range"):
        t0, _ = f["time_range"]
        when_caption = (
            f'<span class="zd-finding-when">· {t0.isoformat()}</span>'
        )
    count_chip = (
        f'<span class="zd-finding-count">×{f["count"]}</span>'
        if f.get("count", 0) > 1 else ""
    )
    # Confidence pill — small subtle tag in the metadata row. Tells
    # the engineer how *credible* the signal is, orthogonal to
    # severity. "Critical + low confidence" means real-but-might-be-
    # noise; "Critical + high confidence" means act now. Hidden when
    # the finding has no computed confidence (older cached bundles).
    confidence = f.get("confidence")
    confidence_pill = ""
    if confidence:
        # Prefer the rich reason from the confidence module when
        # available (e.g. "Confidence 92/100 · severity=Critical · 211
        # evidence line(s) · code 'BRK_MT_...' is documented"). Falls
        # back to the generic tooltip for detectors that set
        # confidence themselves without the score / reason fields.
        score = f.get("_confidence_score")
        reason = f.get("_confidence_reason") or (
            "Signal credibility (orthogonal to severity). Derived from "
            "occurrence count, observation span, and match against "
            "documented ZCC error codes."
        )
        # Show the numeric score in the pill when we have it — turns
        # "Medium confidence" into "Medium · 68" which is a much
        # sharper signal for the operator.
        pill_label = (
            f"{confidence} · {score}" if score is not None else f"{confidence} confidence"
        )
        # Escape quotes in the tooltip (we build it in-memory so no
        # untrusted content, but reason may contain codes with quotes).
        safe_reason = str(reason).replace('"', "&quot;")
        confidence_pill = (
            f'<span class="zd-finding-conf zd-conf-{confidence}" '
            f'title="{safe_reason}">'
            f'· {pill_label}</span>'
        )
    # Lifecycle-downgrade chip. When the sleep/wake correlator
    # downgrades a finding from Critical/Warning -> Info, the original
    # severity is preserved in ``_lifecycle_downgraded_from``. Surface
    # it inline next to the (now Info) badge so the engineer sees the
    # context: "originally Critical, downgraded because of system
    # wake". Otherwise the Info badge would understate the raw signal.
    downgrade_chip = ""
    orig_sev = f.get("_lifecycle_downgraded_from")
    if orig_sev:
        downgrade_chip = (
            f'<span class="zd-downgrade-chip" '
            f'title="This finding was originally {orig_sev}, '
            f'auto-downgraded to Info because its evidence correlated '
            f'with a system sleep/wake event. Open Description for the '
            f'matched event timestamp.">'
            f'&darr; from <b>{orig_sev.lower()}</b> · lifecycle'
            f'</span>'
        )

    # Documented-category chip (2026-06-12 phase 2 UI). Appears next
    # to the title when the finding's code corresponds to a documented
    # Zscaler status code. Hidden for log-evidence-only patterns.
    category_chip = _documented_category_chip_html(f.get("code", ""))

    head = (
        f'<div class="zd-finding {cls}">'
        f'<div class="zd-finding-head">'
        f'  {badge}'
        f'  <span class="zd-finding-title">{f["title"]}</span>'
        f'  {category_chip}'
        f'  {downgrade_chip}'
        f'  {count_chip}'
        f'  <div class="zd-finding-meta-row">'
        f'    <span class="zd-finding-code">{code}</span>'
        f'    {when_caption}'
        f'    {confidence_pill}'
        f'  </div>'
        f'</div>'
        f'</div>'
    )

    # Streamlit 1.29+ supports st.container(border=True). Fall back
    # gracefully on older versions.
    try:
        card = st.container(border=True)
    except TypeError:
        card = st.container()
    with card:
        st.markdown(head, unsafe_allow_html=True)

        next_step = _next_step_for(f["detector_id"])
        if next_step and not next_step.startswith("See SOP"):
            st.info(f"**Next step:** {next_step}")

        with st.expander("Description", expanded=default_open):
            st.text(f["description"])

        if f.get("evidence"):
            n = len(f["evidence"])
            with st.expander(
                f"Evidence — {n} sample line(s)", expanded=False,
            ):
                from zcc_diag.ui.log_context import surrounding_lines
                from zcc_diag.ui.tz_display import format_ts_with_tz
                for ev_i, ev in enumerate(f["evidence"]):
                    line_no = ev.get("line_no") or "?"
                    # Redact both the source path and the raw log
                    # line — both can carry PII. Timestamp gets the
                    # bundle's TZ offset appended so wall-clock matches
                    # what the customer reported.
                    st.code(
                        f"[{format_ts_with_tz(ev['ts'])}]  "
                        f"{redact(ev['src'])}:{line_no}\n"
                        f"  {redact(ev['raw'])}",
                        language="text",
                    )
                    # Per-evidence "Show context" — pulls +-5 lines
                    # from the same source file around line_no using
                    # the in-memory log_index. Closed by default
                    # because most engineers only want the matched
                    # line; open when troubleshooting needs the full
                    # local context (e.g. SAML failure -> which
                    # broker state preceded it?).
                    if ev.get("line_no") is not None:
                        with st.expander(
                            "Show +/- 5 surrounding lines from this file",
                            expanded=False,
                        ):
                            ctx = surrounding_lines(
                                ev["src"], ev.get("line_no"), radius=5,
                            )
                            if not ctx:
                                st.caption(
                                    "_Context not available — this file is "
                                    "not in the in-memory log index "
                                    "(typically because it's outside the "
                                    "tunnel/tray/service/upm log family)._"
                                )
                            else:
                                lines_out = []
                                for cl in ctx:
                                    is_match = cl.line_no == ev.get("line_no")
                                    marker = ">>" if is_match else "  "
                                    lines_out.append(
                                        f"{marker} [{format_ts_with_tz(cl.ts)}] "
                                        f"{redact(cl.source_file)}:"
                                        f"{cl.line_no}  {cl.level}  "
                                        f"{redact(cl.body)[:240]}"
                                    )
                                st.code(
                                    "\n".join(lines_out),
                                    language="text",
                                )

        if f.get("sop"):
            with st.expander("SOP guidance", expanded=False):
                st.text(f["sop"])

        # ---- Export affordance (de-emphasised) ---------------------
        # Engineers occasionally want a Slack/JIRA-ready Markdown
        # paste of the finding. Kept available but moved behind a
        # tiny secondary "Export" expander so it doesn't compete
        # with Description / Evidence / SOP for attention. Labelled
        # generically so we can add CSV / JSON exports here later
        # without renaming.
        with st.expander("Export", expanded=False):
            st.caption(
                "Markdown block — paste into Slack, JIRA, "
                "or a status doc."
            )
            st.code(
                finding_as_markdown(f),
                language="markdown",
            )


def render_root_cause_cluster(cluster: Dict[str, Any]):
    """Render one root-cause cluster card. If multiple findings share
    the family, show the primary as the headline and list the
    supporting signals collapsed underneath."""
    primary = cluster["primary"]
    supporting = cluster["supporting"]
    if not supporting:
        render_finding_card(primary)
        return

    # Multi-signal cluster: render primary card, then a compact
    # "Supporting signals" sub-card with the other codes.
    render_finding_card(primary)
    with st.expander(
        f"Related signals from this same event "
        f"({len(supporting)} additional observation(s) — "
        "same root cause, same SOP)",
        expanded=False,
    ):
        rows = []
        for f in supporting:
            sev_label = SEV_WORD.get(f["severity"], "?")
            when = ""
            if f.get("time_range"):
                when = f["time_range"][0].isoformat()
            rows.append({
                "severity": sev_label,
                "code": f"{f['detector_id']}::{f['code']}",
                "count": f.get("count", 0),
                "when": when,
                "title": f["title"],
            })
        st.dataframe(rows, hide_index=True, use_container_width=True)
        st.caption(
            "These are different sensors reporting the same underlying "
            "event (state machine, zEvent bus, SME failure counter, etc). "
            "Refer to the primary finding above for the consolidated "
            "triage steps."
        )


def render_finding_list(findings, empty="No findings."):
    """Render findings, clustering by root-cause family and grouping
    by detector family. Hierarchy: detector family > root-cause
    cluster > primary finding + supporting signals.

    De-duplicates by (detector_id, code) as a safety net first.

    Phase 60a-Task-6 (2026-07-10): when the Triage Wizard has been
    filled with a specific complaint category, prepend a "🎯 Most
    relevant to reported issue" section pinning the top-5 findings
    ranked by relevance to the customer complaint. Pinned findings
    are removed from the main grouped list to avoid double-render.
    Falls back to the plain grouped view when intake is skipped/empty.
    """
    if not findings:
        st.success(empty)
        return
    findings = consolidate_dupes(findings)
    sev_rank = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}

    # ---- Pinned "Most relevant to reported issue" section -----------
    #
    # Read intake from session_state at render time — the wizard writes
    # to it live, so this always reflects the operator's latest choice.
    # Legacy behavior is preserved when intake is skipped/empty (the
    # ranker returns severity-only scores → the pinned section is
    # skipped and the code below runs unchanged).
    pinned_ids: set = set()
    try:
        from zcc_diag.intake import get_intake
        from zcc_diag.ui.relevance import (
            has_complaint_relevance,
            top_n_relevant,
        )

        intake = get_intake(st.session_state)
        if has_complaint_relevance(intake):
            top5 = top_n_relevant(findings, intake, n=5)
            # Only pin findings whose detector-id is actually in the
            # complaint-relevant set — otherwise the pinned section
            # would just show the same top-5 by severity, defeating the
            # point. top_n_relevant already ranks correctly; we drop
            # anything that didn't get the +COMPLAINT_MATCH_BONUS.
            from zcc_diag.ui.relevance import (
                relevant_detector_ids, score_finding,
            )
            rel = relevant_detector_ids(intake.complaint_category)
            pinned = [
                f for f in top5
                if f.get("detector_id") in rel
            ]
            if pinned:
                st.markdown(
                    "#### 🎯 Most relevant to reported issue"
                )
                st.caption(
                    "Ranked by relevance to the customer complaint "
                    "(complaint match beats severity — see the wizard "
                    "header above for the current scope)."
                )
                for f in pinned:
                    render_finding_card(f, default_open=True)
                    pinned_ids.add(id(f))
                st.divider()
                # Fall through — non-pinned findings still render below.
    except Exception:
        # Never let the intake-ranker layer break the rest of the
        # findings render. Log and continue with pure legacy behavior.
        import logging
        logging.getLogger(__name__).exception(
            "intake-ranker pinning failed; falling back to plain list"
        )
        pinned_ids = set()

    if pinned_ids:
        # Rebuild the working `findings` list without the pinned ones.
        findings = [f for f in findings if id(f) not in pinned_ids]
        if not findings:
            # Everything was already pinned — nothing left to group.
            return

    # Group by detector_id family.
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        g = _DETECTOR_GROUPS.get(f["detector_id"], "Other")
        groups.setdefault(g, []).append(f)

    # Group display order: most-critical groups first.
    def _group_priority(items):
        return min(
            (sev_rank.get(f["severity"], 9) for f in items),
            default=9,
        )
    ordered = sorted(
        groups.items(),
        key=lambda kv: (_group_priority(kv[1]), kv[0]),
    )

    for group_label, group_items in ordered:
        clusters = _cluster_by_root_cause(group_items)
        # Sort clusters within the group by severity rank
        clusters.sort(key=lambda c: c["worst_rank"])
        # Group's worst severity badge
        worst = min(
            (c["worst_rank"] for c in clusters),
            default=9,
        )
        worst_tag = (
            "Critical" if worst == 0 else
            "Warning" if worst == 1 else
            "Info"
        )
        # Count distinct root causes (clusters), not raw findings
        n_distinct = len(clusters)
        n_signals = sum(c["member_count"] for c in clusters)
        if n_distinct == n_signals:
            count_str = f"{n_distinct} finding(s)"
        else:
            count_str = (
                f"{n_distinct} distinct issue(s), {n_signals} signal(s)"
            )
        heading = f"{worst_tag}  {group_label}  —  {count_str}"
        with st.expander(heading, expanded=(worst <= 1)):
            for cluster in clusters:
                render_root_cause_cluster(cluster)


# ----------------------------------------------------------------------
# Backwards-compat underscore aliases — kept so existing call sites in
# zcc_diag_ui.py keep working unchanged. New code should prefer the
# public names above.
# ----------------------------------------------------------------------
_real_findings = real_findings
_skipped_findings = skipped_findings
_consolidate_dupes = consolidate_dupes
_finding_as_markdown = finding_as_markdown
_render_tldr = render_tldr
_render_finding_detail = render_finding_detail
_render_finding_card = render_finding_card
_render_root_cause_cluster = render_root_cause_cluster
_render_finding_list = render_finding_list
