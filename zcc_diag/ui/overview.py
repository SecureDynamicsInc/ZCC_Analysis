"""
Overview module — the landing page after a bundle loads.

Two surfaces share this module:

1. **Question-led picker** at the top — "What brought you here?". Five
   chips (Just exploring / It's slow / Can't connect / Auth failing /
   App broken) map to a curated set of detectors. Picking one narrows
   the page to the findings that matter for that triage path.

2. **Browse mode** ("Just exploring", the default) — a collapsible
   summary of severity counts, top clustered findings, ZDX path
   health, network identity, and a Policy & Config quick-look.

The rationale for the chip-led entry is that engineers arrive with
ONE question in mind, not five. Surfacing every section by default
made them filter mentally. Asking the question up front and showing
ONLY relevant data is the faster triage.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import streamlit as st

from zcc_diag.issues import Severity
from zcc_diag.ui.clustering import _cluster_by_root_cause
from zcc_diag.ui.findings import (
    _real_findings,
    _skipped_findings,
    _render_finding_list,
    _render_root_cause_cluster,
)
from zcc_diag.ui.policy import (
    _consolidate_policy_rows,
    _filter_customer_bypass,
    _is_zscaler_infra_host,
)
from zcc_diag.ui.symptoms import (
    _scope_slowness_findings,
    _build_slowness_narrative,
)
from zcc_diag.ui.path_health import _ztr_status
from zcc_diag.ui.timeline import render_timeline as _render_timeline
from zcc_diag.ui.patterns import render_patterns as _render_patterns


# Symptom catalogue used by the focus picker. Each entry maps a
# customer-facing question to the detector IDs that matter for it.
# Keep this aligned with the Symptom Triage catalogue in wizard.py.
_OVERVIEW_FOCUS_OPTIONS = [
    {
        "key": "explore",
        "label": "Just exploring",
        "detectors": [],
        "blurb": "Show the full dashboard.",
    },
    {
        "key": "slow",
        "label": "It's slow",
        "detectors": ["slowness", "tunnel_not_established",
                      "adapter_instability"],
        "blurb": (
            "Page loads slow / app laggy / video stalling. "
            "We'll localize the bottleneck and tell you whether it's "
            "real Zscaler slowness or transit noise."
        ),
    },
    {
        "key": "noconnect",
        "label": "Can't connect",
        "detectors": ["tunnel_not_established", "captive_portal",
                      "driver_error", "endpoint_fw_av",
                      "endpoint_fw_av_mac", "network_error",
                      "adapter_instability"],
        "blurb": (
            "Tunnel won't come up / no internet through ZCC / "
            "captive portal stuck. We'll surface the failed stage "
            "and any FW/AV/driver interference."
        ),
    },
    {
        "key": "authfail",
        "label": "Auth / SSO failing",
        "detectors": ["zia_auth_failures", "zpa_auth_failures",
                      "idp_redirect_fail"],
        "blurb": (
            "Login won't complete / 401-403 / SAML redirect breaks. "
            "We'll show the failed handshake and the upstream IdP / "
            "Service Edge response."
        ),
    },
    {
        "key": "appbroken",
        "label": "A specific app is broken",
        "detectors": ["zpa_app_not_reachable", "zpa_dns_check_not_found",
                      "bypass_misconfiguration", "hostfile_interference",
                      "wildcard_app_segment_purge",
                      "cert_pinned_saas_inspection",
                      "p2p_app_blocked"],
        "blurb": (
            "App reachable in browser but broken in another client / "
            "ZPA app failing / bypass not honoured. We'll check "
            "policy, hostfile, and bypass config."
        ),
    },
]


def render_overview_focus_picker(findings, data) -> Optional[Dict[str, Any]]:
    """Render the question-led entry chips. Returns the selected focus
    dict — or ``None`` when "Just exploring" is chosen, so the caller
    knows to fall back to the full dashboard."""
    st.markdown(
        '<div class="zd-section">What brought you here?</div>',
        unsafe_allow_html=True,
    )
    labels = [opt['label'] for opt in _OVERVIEW_FOCUS_OPTIONS]
    pick = st.radio(
        "focus", labels, horizontal=True, index=0,
        label_visibility="collapsed",
        key="overview_focus",
    )
    chosen = _OVERVIEW_FOCUS_OPTIONS[labels.index(pick)]
    st.caption(chosen["blurb"])
    if chosen["key"] == "explore":
        return None
    return chosen


def render_overview_focused(focus: Dict[str, Any],
                             all_findings: List[Dict[str, Any]],
                             data: Dict[str, Any]) -> None:
    """Render the FOCUSED Overview view — scoped to one symptom.

    Layout:
      1. Headline verdict card (was this symptom actually observed?)
      2. Optional slowness narrative card (only for ``"It's slow"``).
      3. Relevant findings (clustered).
      4. Quick network identity strip (cloud, public IP, primary SME).
      5. Informational signals collapsed in a quiet footer.
    """
    detectors = set(focus["detectors"])
    candidates = [f for f in all_findings
                  if f["detector_id"] in detectors]

    # For the slowness symptom: apply the same time-window scoping the
    # Symptoms module uses so we don't show stale tunnel events that
    # aren't actually contributing to slowness.
    if focus["key"] == "slow":
        candidates = _scope_slowness_findings(candidates)

    # Split actionable (CRIT + WARN) from informational. A focused
    # triage view should LEAD with actionable signals — INFO findings
    # like ``ZCC_ZIA_STATE_FLAP_UP`` (literally "tunnel recovered")
    # are the OPPOSITE of "can't connect" and drown out the real
    # problem if shown alongside criticals. INFO items still appear,
    # just collapsed into a footer disclosure so they don't compete
    # for attention.
    actionable = [f for f in candidates
                  if f["severity"] in (Severity.CRITICAL, Severity.WARNING)]
    informational = [f for f in candidates
                     if f["severity"] == Severity.INFO]
    relevant = actionable

    crit_n = sum(1 for f in actionable if f["severity"] == Severity.CRITICAL)
    warn_n = sum(1 for f in actionable if f["severity"] == Severity.WARNING)

    # ---- Headline verdict ----
    if crit_n or warn_n:
        verdict_class = "bad" if crit_n else "warn"
        headline = (
            f"{focus['label']}: {crit_n} critical "
            f"+ {warn_n} warning finding(s) match this symptom"
            if crit_n
            else f"{focus['label']}: {warn_n} warning finding(s) "
                 f"match this symptom"
        )
        body = (
            f"Findings below are scoped to the detectors most "
            f"relevant to **{focus['label'].lower()}**. Open each "
            f"card for evidence + the SOP step."
        )
    elif informational:
        verdict_class = "ok"
        headline = (
            f"{focus['label']}: no actionable findings "
            f"({len(informational)} informational signal(s) only)"
        )
        body = (
            f"The detectors associated with "
            f"**{focus['label'].lower()}** didn't surface anything "
            f"critical or warning-level. There are "
            f"{len(informational)} informational signal(s) below "
            f"(state recoveries, environment notes) — context, not "
            f"action items."
        )
    else:
        verdict_class = "ok"
        headline = (
            f"{focus['label']}: no matching findings in this bundle"
        )
        body = (
            f"The detectors associated with **{focus['label'].lower()}** "
            f"didn't fire. If your customer is still reporting this, "
            f"either (a) re-export during a live event, (b) check "
            f"**Search** for specific hosts / URLs, or (c) try a "
            f"different symptom — the issue may live elsewhere."
        )

    st.markdown(
        f'<div class="zd-finding-card zd-sev-{verdict_class}">'
        f'<div class="zd-finding-title">{headline}</div>'
        f'<div class="zd-finding-meta">{body}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ---- Slowness-specific narrative card ----
    if focus["key"] == "slow":
        app_rows = data["summary"].bundle_meta.get("app_health") or []
        narrative = _build_slowness_narrative(relevant, app_rows)
        if narrative and narrative.get("verdict_class") != verdict_class:
            st.markdown(
                f'<div class="zd-finding-card '
                f'zd-sev-{narrative["verdict_class"]}">'
                f'<div class="zd-finding-title">'
                f'{narrative["headline"]}</div>'
                f'<div class="zd-finding-meta">'
                f'{narrative["body"]}</div></div>',
                unsafe_allow_html=True,
            )

    # ---- Relevant findings (clustered) ----
    if relevant:
        st.markdown(
            '<div class="zd-section">Findings matching this symptom</div>',
            unsafe_allow_html=True,
        )
        _render_finding_list(
            relevant,
            empty=(f"Nothing matched the **{focus['label'].lower()}** "
                   f"detectors."),
        )

    # ---- Quick network identity strip ----
    si = data.get("session_info") or {}
    cloud = (data["summary"].cloud and data["summary"].cloud.main_cloud) or "?"
    public_ip = si.get("Public IP (egress)") or "?"
    primary_sme = si.get("SME (Service Edge) IP") or "?"
    if any(v != "?" for v in (cloud, public_ip, primary_sme)):
        st.markdown(
            '<div class="zd-section">Connection context</div>',
            unsafe_allow_html=True,
        )
        c1, c2, c3 = st.columns(3)
        c1.metric("Cloud", cloud)
        c2.metric("Public IP", public_ip)
        c3.metric("Primary SME", primary_sme)

    # ---- Informational signals (quiet footer) ----
    if informational:
        with st.expander(
            f"+ {len(informational)} informational signal(s) in "
            f"this category  ·  context, not action items",
            expanded=False,
        ):
            _render_finding_list(
                informational,
                empty="No informational findings.",
            )


def module_overview(data: Dict[str, Any]) -> None:
    """At-a-glance dashboard.

    Top-of-page is a question-led entry point ("What brought you
    here?") that lets the engineer scope the rest of the Overview
    to ONE symptom — e.g. Slow, Can't connect, Auth failing. When a
    symptom is picked, the page narrows to the findings, network
    context, and path-health rows that are relevant to that triage
    path. Picking "Just exploring" (the default) shows the full
    dashboard.
    """
    findings = _real_findings(data["findings"])
    crit = [f for f in findings if f["severity"] == Severity.CRITICAL]
    warn = [f for f in findings if f["severity"] == Severity.WARNING]
    info = [f for f in findings if f["severity"] == Severity.INFO]

    # ---- Question-led entry point ----
    focus = render_overview_focus_picker(findings, data)
    if focus is not None:
        render_overview_focused(focus, findings, data)
        st.divider()
        st.caption(
            "Want the full dashboard? Reset the picker above to "
            "**\"Just exploring\"** or use the sidebar nav to jump "
            "to a specific module."
        )
        return

    # ---- Verdict: one-line auto-headline at the top ----
    # Sits ABOVE everything else because the engineer's first question
    # opening a bundle is "what is wrong with this thing?" — and that's
    # exactly what the verdict answers. Pure-function builder lives in
    # ui/verdict.py so it's unit-testable without Streamlit.
    from zcc_diag.ui.verdict import (
        build_verdict, render_verdict, render_health_check,
    )
    verdict = build_verdict(data)
    render_verdict(verdict)
    # Clean/lifecycle-only bundles get an affirmative "what's working"
    # block below the verdict — flips the framing from "we found
    # nothing" to "here's what's verified working." Silent on incident
    # bundles.
    render_health_check(verdict, data)

    # ---- Phase 20 launchpad (2026-06-17): replaces the 11-section
    # dashboard with 3 focused cards so the engineer can decide where
    # to go without scrolling.

    st.caption(
        "Decision launchpad — the four cards below answer 'what's "
        "important, where do I go next'. For deep-dives, use the "
        "sidebar modules. For a symptom-led triage, pick a chip above."
    )

    _render_launchpad_critical_findings(crit, warn)
    # Phase 26 (2026-06-17): Bundle Vitals was 100% redundant with the
    # header strip (every field overlapped). Replaced with a "what
    # this bundle covers" card that surfaces info the header strip
    # CAN'T show — capture window, activity counts, suite presence.
    _render_launchpad_bundle_coverage(data)
    _render_launchpad_where_to_go(data, len(crit), len(warn), len(info))
    # Phase 27 (2026-06-17): triage-export was buried in the sidebar.
    # Surface it on the Dashboard with a copy-friendly preview pane.
    _render_launchpad_triage_summary(data)

    # Power-user escape hatch: the old full dashboard is preserved
    # under a fold for anyone who wants timeline / patterns / network
    # identity / policy quick-look / detector coverage in one place.
    with st.expander("Full dashboard (legacy view)", expanded=False):
        _render_full_dashboard_legacy(data, findings, crit, warn, info)


def _render_launchpad_critical_findings(crit, warn) -> None:
    """Top-of-launchpad card: up to 3 highest-severity findings as a
    tight list. No expanders, no clustering — just the raw most-
    important signals."""
    st.markdown(
        '<div class="zd-section">Most important findings</div>',
        unsafe_allow_html=True,
    )
    pool = crit if crit else warn[:3] if warn else []
    if not pool:
        st.success(
            "No critical or warning findings in this bundle. Either "
            "the toolkit verifies things are healthy, or the bundle "
            "was captured outside the failure window."
        )
        return
    top = pool[:3]
    sev_label = {
        Severity.CRITICAL: "CRIT",
        Severity.WARNING: "WARN",
        Severity.INFO: "INFO",
    }
    for f in top:
        sev = sev_label.get(f["severity"], "?")
        sev_cls = {
            Severity.CRITICAL: "zd-cat-error",
            Severity.WARNING: "zd-cat-policy",
            Severity.INFO: "zd-cat-info",
        }.get(f["severity"], "zd-cat-info")
        title = f.get("title", "(no title)")
        det = f.get("detector_title", f.get("detector_id", ""))
        count = f.get("count", 0)
        tr = f.get("time_range")
        when = ""
        if tr:
            t0, t1 = tr
            when = f" · {t0.strftime('%Y-%m-%d %H:%M')}" if t0 else ""
        st.markdown(
            f'<div class="zd-launchpad-finding">'
            f'  <span class="zd-cat-chip {sev_cls}">{sev}</span>'
            f'  <span class="zd-launchpad-finding-title">'
            f'    {title}'
            f'  </span>'
            f'  <span class="zd-launchpad-finding-meta">'
            f'    {det} · {count}× occurrences{when}'
            f'  </span>'
            f'</div>',
            unsafe_allow_html=True,
        )
    extra = len(pool) - len(top)
    if extra > 0:
        st.caption(
            f"_+ {extra} more — see the **Issues** module for the "
            f"full list._"
        )


def _render_launchpad_bundle_coverage(data) -> None:
    """What this bundle actually contains — info the header strip
    can't surface. Three buckets:

      * Capture window — earliest log line → latest log line +
        duration. Tells the engineer "is this bundle long enough to
        cover the incident".
      * Activity counts — tunnel lines, ZPA sessions, ZDX traces,
        pcap files. Tells "is there enough signal to triage".
      * Suite presence — which Zscaler suites the bundle has data
        for. Tells "should I look at ZIA, ZPA, or ZDX".

    Phase 26 (2026-06-17): replaces the older "Bundle vitals" card
    which duplicated the header strip's identity / cloud / IP info.
    """
    summary = data["summary"]
    bm = summary.bundle_meta if summary else {}

    # ---- Capture window -----------------------------------------
    log_index = data.get("log_index")
    window_str = "—"
    duration_str = "—"
    if log_index is not None and getattr(log_index, "lines", None):
        try:
            ts_list = [ln.ts for ln in log_index.lines if ln.ts]
            if ts_list:
                t0 = min(ts_list)
                t1 = max(ts_list)
                d = (t1 - t0).total_seconds()
                if d < 60:
                    duration_str = f"{d:.0f}s"
                elif d < 3600:
                    duration_str = f"{d / 60:.1f} min"
                elif d < 86400:
                    duration_str = f"{d / 3600:.1f} hr"
                else:
                    duration_str = f"{d / 86400:.1f} days"
                window_str = (
                    f"{t0.strftime('%Y-%m-%d %H:%M')} → "
                    f"{t1.strftime('%H:%M')}"
                )
                if t0.date() != t1.date():
                    window_str = (
                        f"{t0.strftime('%Y-%m-%d %H:%M')} → "
                        f"{t1.strftime('%Y-%m-%d %H:%M')}"
                    )
        except Exception:
            pass

    # ---- Activity counts ----------------------------------------
    n_log_lines = 0
    if log_index is not None and getattr(log_index, "lines", None):
        n_log_lines = len(log_index.lines)
    n_zpa = len(data.get("zpa_sessions") or [])
    n_findings = len([
        f for f in data.get("findings") or []
        if f.get("code") != "DETECTOR_SKIPPED_FOR_OS"
    ])
    n_pcaps = len(data.get("pcaps") or [])
    n_ztr = len(bm.get("ztraceroute_traces") or [])

    # ---- Suite presence (tri-state from policy_extract) ---------
    zia_state = bm.get("zia_enrolled")  # True | False | None
    zpa_state = bm.get("zpa_enrolled")
    zdx_state = bm.get("has_ztraceroute_file")  # bool
    has_zpa_sessions = bool(data.get("zpa_sessions"))

    def _state_chip(label: str, present: bool, ambiguous: bool = False) -> str:
        if present:
            return (
                f'<span class="zd-cat-chip zd-cat-info">{label}</span>'
            )
        if ambiguous:
            return (
                f'<span class="zd-cat-chip">{label} (unknown)</span>'
            )
        return (
            f'<span class="zd-cat-chip zd-cat-error">{label} (not in use)</span>'
        )

    zia_chip = _state_chip(
        "ZIA",
        present=(zia_state is True),
        ambiguous=(zia_state is None),
    )
    zpa_chip = _state_chip(
        "ZPA",
        present=(zpa_state is True or has_zpa_sessions),
        ambiguous=(zpa_state is None and not has_zpa_sessions),
    )
    zdx_chip = _state_chip(
        "ZDX",
        present=bool(zdx_state),
        # ZDX is opt-in (Diagnostic Route Collection); absence is
        # the common case, not an ambiguity — show it as "not in use".
        ambiguous=False,
    )

    # ---- Render --------------------------------------------------
    st.markdown(
        '<div class="zd-section">What this bundle covers</div>',
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    # Left column — capture window + suite presence chips
    c1.markdown(
        f'<div class="zd-vital-tile">'
        f'  <div class="zd-vital-label">Capture window</div>'
        f'  <div class="zd-vital-value">{window_str}</div>'
        f'</div>'
        f'<div class="zd-vital-tile">'
        f'  <div class="zd-vital-label">Duration</div>'
        f'  <div class="zd-vital-value">{duration_str}</div>'
        f'</div>'
        f'<div class="zd-vital-tile">'
        f'  <div class="zd-vital-label">Suites with data</div>'
        f'  <div class="zd-vital-value">'
        f'    {zia_chip} {zpa_chip} {zdx_chip}'
        f'  </div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    # Right column — activity counts
    c2.markdown(
        f'<div class="zd-vital-tile">'
        f'  <div class="zd-vital-label">Log lines parsed</div>'
        f'  <div class="zd-vital-value">{n_log_lines:,}</div>'
        f'</div>'
        f'<div class="zd-vital-tile">'
        f'  <div class="zd-vital-label">ZPA sessions reconstructed</div>'
        f'  <div class="zd-vital-value">{n_zpa:,}</div>'
        f'</div>'
        f'<div class="zd-vital-tile">'
        f'  <div class="zd-vital-label">'
        f'    Findings · ZDX traces · pcap files</div>'
        f'  <div class="zd-vital-value">'
        f'    {n_findings} · {n_ztr} · {n_pcaps}'
        f'  </div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _render_launchpad_where_to_go(
    data, n_crit: int, n_warn: int, n_info: int,
) -> None:
    """Where-to-go-next: action tiles linking to each module with
    finding-count badges so the engineer sees scope before clicking."""
    summary = data["summary"]
    bm = (summary.bundle_meta if summary else {}) or {}
    zia_e = bm.get("zia_enrolled")
    zpa_e = bm.get("zpa_enrolled")
    has_zia = zia_e is not False
    has_zpa = (
        zpa_e is not False
        or bool(data.get("zpa_sessions"))
        or bool(bm.get("zpa_apps"))
    )
    has_ztr = bool(data.get("ztr_health"))
    has_pcap = bool(data.get("pcaps"))

    # Per-module finding counts (uses the Phase 15 suite_scope tag).
    by_suite = {"zia": 0, "zpa": 0, "zdx": 0}
    cross = 0
    findings = _real_findings(data["findings"])
    for f in findings:
        scope = f.get("suite_scope")
        if scope is None:
            cross += 1
            continue
        for s in scope:
            if s in by_suite:
                by_suite[s] += 1

    st.markdown(
        '<div class="zd-section">Where to go next</div>',
        unsafe_allow_html=True,
    )

    # Build module-tile list dynamically so we hide irrelevant suites.
    # Phase 58e-H1 (2026-07-08): labels now match the Phase-54a
    # sidebar workspaces (Bundle Overview / ZIA / ZPA / ZDX / Platform
    # & Device / Investigate / Reference). Previously the launchpad
    # advertised pre-Phase-54a labels ("Detected Issues", "Internet
    # Traffic", "Private Access Sessions", "Find & Follow" etc.) that
    # the user could no longer find in the sidebar.
    tiles = []
    tiles.append({
        "label": "Bundle Overview",
        "badge": (
            f"{n_crit} crit · {n_warn} warn"
            if (n_crit or n_warn) else
            f"{n_info} info" if n_info else "all clean"
        ),
        "desc": (
            "Verdict + top findings + timeline + cross-cutting "
            "patterns. Also holds the All-Findings and Guided-Triage "
            "tabs."
        ),
        "tone": (
            "tone-crit" if n_crit else
            "tone-warn" if n_warn else
            "tone-ok"
        ),
    })
    if has_zia:
        tiles.append({
            "label": "ZIA Workspace",
            "badge": f"{by_suite['zia']} issue(s)",
            "desc": (
                "Health, RCA reports, Sessions & DNS, Configuration "
                "(PAC / bypass / service edges), Diagnostics — all "
                "ZIA-scoped."
            ),
            "tone": "tone-warn" if by_suite["zia"] else "tone-ok",
        })
    if has_zpa:
        n_sess = len(data.get("zpa_sessions") or [])
        tiles.append({
            "label": "ZPA Workspace",
            "badge": (
                f"{n_sess} session(s)"
                if n_sess else f"{by_suite['zpa']} issue(s)"
            ),
            "desc": (
                "Health, RCA reports, Brokers & Sessions, "
                "Configuration, Diagnostics — all ZPA-scoped."
            ),
            "tone": "tone-warn" if by_suite["zpa"] else "tone-ok",
        })
    if has_ztr:
        tiles.append({
            "label": "ZDX Workspace",
            "badge": f"{by_suite['zdx']} issue(s)",
            "desc": (
                "Path Health (traceroute + reachability), Telemetry, "
                "App Catalog, RCA — the ZDX drill-down."
            ),
            "tone": "tone-warn" if by_suite["zdx"] else "tone-ok",
        })
    tiles.append({
        "label": "Platform & Device",
        "desc": (
            "OS events (Modern Standby / power), Endpoint Security "
            "(LWF, WFP, AV/EDR), Tunnel State Machine, Device Trust, "
            "Tenant Config — the cross-suite / platform story."
        ),
        "tone": "tone-neutral",
    })
    tiles.append({
        "label": "Investigate",
        "badge": (
            f"{len(data.get('pcaps') or [])} pcap(s)" if has_pcap
            else None
        ),
        "desc": (
            "Ticket Investigation (paste customer prompt), Free-text "
            "Search, Packet Captures, Bundle Inventory. "
            "Wireshark-style stream follow lives here."
        ),
        "tone": "tone-neutral",
    })
    tiles.append({
        "label": "Reference",
        "desc": (
            "Code Lookup (documented ZS status codes), SOPs, About / "
            "versions. Out-of-flow reference tier."
        ),
        "tone": "tone-neutral",
    })

    # Render as a 3-column grid using a single markdown blob — avoids
    # Streamlit's per-column padding mess.
    grid_html = ['<div class="zd-where-grid">']
    for t in tiles:
        badge = (
            f'<span class="zd-where-badge">{t["badge"]}</span>'
            if t.get("badge") else ""
        )
        grid_html.append(
            f'<div class="zd-where-tile {t["tone"]}">'
            f'  <div class="zd-where-head">'
            f'    <span class="zd-where-label">{t["label"]}</span>'
            f'    {badge}'
            f'  </div>'
            f'  <div class="zd-where-desc">{t["desc"]}</div>'
            f'</div>'
        )
    grid_html.append('</div>')
    st.markdown("\n".join(grid_html), unsafe_allow_html=True)
    st.caption(
        "_Click a workspace in the sidebar to open it._"
    )


def _render_full_dashboard_legacy(
    data, findings, crit, warn, info,
) -> None:
    """The pre-Phase-20 full dashboard, preserved behind a fold. All
    eleven sections from the old Overview live here so power users
    who want the at-a-glance density still have it. Body is the
    original section sequence — see git history for the rationale
    behind each section."""

    # ---- Timeline: when did things happen? --------------------------
    # Leads the dashboard because it's the question an engineer asks
    # first when they open a bundle. Self-skips when there are fewer
    # than 2 dated findings (a single-bar timeline is just noise).
    _render_timeline(findings, data)

    # ---- Patterns: cross-finding meta-analysis ----------------------
    # Sits right after the timeline because patterns are insights
    # *derived from* the timeline data. Self-skips when no patterns
    # fire so we don't carry an empty section.
    _render_patterns(findings, data)

    # ---- Severity overview (bubble tiles in collapsed expander) ----
    def _tile(label: str, n: int, cls: str) -> str:
        active = "has-value" if n > 0 else ""
        return (
            f'<div class="zd-sev-tile {cls} {active}">'
            f'  <div class="zd-sev-tile-label">{label}</div>'
            f'  <div class="zd-sev-tile-value">{n}</div>'
            f'</div>'
        )

    sev_chips = []
    if len(crit): sev_chips.append(f"{len(crit)} critical")
    if len(warn): sev_chips.append(f"{len(warn)} warning")
    if len(info): sev_chips.append(f"{len(info)} info")
    sev_summary = (
        "  ·  ".join(sev_chips)
        if sev_chips else "no findings"
    )
    with st.expander(
        f"Severity overview  ·  {sev_summary}  ·  "
        f"{len(findings)} total",
        expanded=False,
    ):
        st.markdown(
            '<div class="zd-sev-tiles">'
            + _tile("Critical", len(crit), "zd-tile-crit")
            + _tile("Warning",  len(warn), "zd-tile-warn")
            + _tile("Info",     len(info), "zd-tile-info")
            + _tile("Total",    len(findings), "zd-tile-total")
            + '</div>',
            unsafe_allow_html=True,
        )

    # ---- Top findings (clustered, severity-honest) ----
    top_pool = crit or warn or info
    if top_pool:
        clustered = _cluster_by_root_cause(top_pool)
        clustered.sort(
            key=lambda c: (-c["member_count"], c["worst_rank"]),
        )
        top_three = clustered[:3]
        worst_rank = min((c["worst_rank"] for c in top_three), default=9)
        head_emoji = {0: "Critical", 1: "Warning",
                      2: "Info"}.get(worst_rank, "—")
        with st.expander(
            f"{head_emoji} Highest-severity findings  ·  "
            f"top {len(top_three)} cluster(s) shown",
            expanded=False,
        ):
            st.caption(
                "These are the most severe signals the toolkit found. "
                "Whether any of them is the **root cause** depends on "
                "the symptom you're triaging. Sustained / repeating "
                "signals (higher **count**) are usually more "
                "meaningful than single transient events."
            )
            for cl in top_three:
                _render_root_cause_cluster(cl)

    # ---- Slowness picture (path-health summary) ----
    ztr_health = data.get("ztr_health") or []
    zs_dcs = [r for r in ztr_health if r.get("dc_name")]
    if zs_dcs:
        worst_status = "ok"
        for r in zs_dcs:
            s = _ztr_status(r.get("loss_median_pct"),
                            r.get("latency_p90_ms"))
            if s == "bad":
                worst_status = "bad"
                break
            if s == "warn" and worst_status != "bad":
                worst_status = "warn"
        verdict_emoji = {"ok": "Healthy", "warn": "Degraded",
                         "bad": "Critical"}[worst_status]
        verdict_text = {
            "ok": "all clean",
            "warn": "degraded path",
            "bad": "critical loss / latency",
        }[worst_status]
        with st.expander(
            f"{verdict_emoji} Path to Zscaler DC(s) — {verdict_text} "
            f"({len(zs_dcs)} DC{'s' if len(zs_dcs) != 1 else ''} probed)",
            expanded=False,
        ):
            rows = []
            for r in zs_dcs:
                status = _ztr_status(r.get("loss_median_pct"),
                                     r.get("latency_p90_ms"))
                rows.append({
                    "status": {"ok": "Healthy", "warn": "Degraded",
                               "bad": "Critical"}[status],
                    "DC": r["dc_name"],
                    "SME IP": r["destination_ip"],
                    "median ms": (
                        float(r["latency_median_ms"])
                        if r.get("latency_median_ms") is not None else None
                    ),
                    "p90 ms": (
                        float(r["latency_p90_ms"])
                        if r.get("latency_p90_ms") is not None else None
                    ),
                    "loss %": (
                        float(r["loss_median_pct"])
                        if (r.get("loss_median_pct") or -1) >= 0 else None
                    ),
                    "probes": r["trace_count"],
                })
            st.dataframe(
                rows, hide_index=True, use_container_width=True,
                column_config={
                    "median ms":
                        st.column_config.NumberColumn(format="%.0f"),
                    "p90 ms":
                        st.column_config.NumberColumn(format="%.0f"),
                    "loss %":
                        st.column_config.NumberColumn(format="%.1f%%"),
                },
            )
            st.caption(
                "Per-Zscaler-DC end-to-end latency and packet loss "
                "from ZTraceroute. Full hop-by-hop drill-down is in "
                "the **App Path Analysis (ZDX)** module."
            )

    # ---- Network identity ----
    si = data.get("session_info") or {}
    if si:
        relevant_keys = (
            "Public IP (egress)",
            "SME (Service Edge) IP",
            "Secondary SME (other channel)",
            "Zscaler DNS resolver",
            "Tunnel MTU",
        )
        rows = [
            {"field": k, "value": str(si[k])}
            for k in relevant_keys if k in si
        ]
        if rows:
            with st.expander(
                f"Network identity — {len(rows)} field(s)",
                expanded=False,
            ):
                st.dataframe(rows, hide_index=True,
                             use_container_width=False)

    # ---- Policy & Config quick-look ----
    policy = data.get("policy") or {}
    pac_info = data.get("pac_info") or {}
    bypass_resolutions = data.get("bypass_resolutions") or {}
    s_summary = data["summary"]
    if policy or pac_info or bypass_resolutions:
        bypass_total = (
            len(bypass_resolutions)
            + len([b for b in (s_summary.bypass_cache or [])
                   if b not in bypass_resolutions])
        )
        label = (
            f"Policy & Config — Tenant: "
            f"{policy.get('Customer domain') or '?'} · "
            f"PAC: {pac_info.get('type') or 'none'} · "
            f"Bypass: {bypass_total} entries"
        )
        with st.expander(label, expanded=False):
            if policy:
                policy_pol = _consolidate_policy_rows(policy)
                pol_rows = []
                for k in ("ZIA status", "ZPA status", "OneID enabled"):
                    if k in policy_pol:
                        pol_rows.append({"field": k,
                                         "value": str(policy_pol[k])})
                if pol_rows:
                    st.markdown(
                        '<div class="zd-section">'
                        'ZIA / ZPA status</div>',
                        unsafe_allow_html=True,
                    )
                    st.dataframe(pol_rows, hide_index=True,
                                 use_container_width=False)
            if pac_info:
                st.markdown(
                    '<div class="zd-section">PAC file</div>',
                    unsafe_allow_html=True,
                )
                st.dataframe(
                    [
                        {"field": "Type",
                         "value": pac_info.get("type", "?")},
                        {"field": "Path / URL",
                         "value": pac_info.get("data_path", "")},
                    ],
                    hide_index=True, use_container_width=False,
                )
            customer_bypass_o = _filter_customer_bypass(bypass_resolutions)
            customer_cache_o = [
                b for b in (s_summary.bypass_cache or [])
                if not _is_zscaler_infra_host(b)
            ]
            infra_dropped_o = (
                len(bypass_resolutions) - len(customer_bypass_o)
            )
            if customer_cache_o or customer_bypass_o:
                st.markdown(
                    '<div class="zd-section">'
                    'Customer bypass list (top 20)</div>',
                    unsafe_allow_html=True,
                )
                bp_rows = []
                resolved_hosts = set()
                for host, ips in customer_bypass_o.items():
                    bp_rows.append({
                        "host": host,
                        "resolved_ips": ", ".join(ips) if ips else "",
                        "ip_count": len(ips),
                    })
                    resolved_hosts.add(host)
                for entry in customer_cache_o:
                    if entry in resolved_hosts:
                        continue
                    bp_rows.append({
                        "host": entry,
                        "resolved_ips": "",
                        "ip_count": 0,
                    })
                st.dataframe(bp_rows[:20], hide_index=True,
                             use_container_width=True)
                if infra_dropped_o:
                    st.caption(
                        f"_{infra_dropped_o} Zscaler-infrastructure "
                        f"entries hidden (ZCC-managed)._"
                    )
                if len(bp_rows) > 20:
                    st.caption(
                        f"Showing 20 of {len(bp_rows)} — see the "
                        "**Policy & Config** module for full list."
                    )

    # ---- Detector coverage ----
    skipped = _skipped_findings(data["findings"])
    if skipped:
        os_family = (data["summary"].os or {}).get("family", "unknown")
        with st.expander(
            f"Detector coverage — {len(skipped)} detector(s) "
            f"skipped (not applicable to {os_family})",
            expanded=False,
        ):
            st.caption(
                "These detectors look for OS-specific signatures that "
                "only appear on the other platform. They didn't run on "
                "this bundle, which is correct — they wouldn't produce "
                "useful findings."
            )
            cov_rows = [
                {"detector": s["detector_id"],
                 "reason": s["title"]}
                for s in skipped
            ]
            st.dataframe(cov_rows, hide_index=True,
                         use_container_width=True)


# ----------------------------------------------------------------------
# Backwards-compat aliases.
# ----------------------------------------------------------------------
_render_overview_focus_picker = render_overview_focus_picker
_render_overview_focused = render_overview_focused
_module_overview = module_overview
