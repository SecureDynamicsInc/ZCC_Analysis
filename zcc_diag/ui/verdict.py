"""
Verdict generator — a single auto-headline that answers "what's going
on with this bundle?" in one sentence.

Why this exists
---------------
The toolkit produces a lot of signal: detector findings, patterns,
correlations, lifecycle events, downgrades. Until now the Overview
showed all of it as equal-citizen sections and the engineer had to
*scan* before they could form a view of the bundle. The Verdict is
the top-of-page line that lets a tech-support engineer read in 3
seconds and either say "yep, that's what the customer is calling
about" or "no, you're missing something."

What it isn't
-------------
- Not a diagnosis. It doesn't say "fix X". It describes what the bundle
  shows.
- Not a confidence claim about the cause. It's a confidence claim about
  *the signal* — how credible the dominant pattern is given the
  evidence count, span, and finding-supplied confidence.
- Not personalised. It doesn't know the customer's environment, doesn't
  know which symptoms they reported. It just summarises what the data
  says.

Pure function
-------------
``build_verdict(data)`` takes the analyse() result dict and returns a
plain dict. No Streamlit calls, no rendering. The Overview module
renders the dict. Tests can call build_verdict() directly on a
synthetic data dict and assert the headline string is what's expected.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from zcc_diag.issues import Severity


# Rank for sorting. Higher = more attention-worthy.
_SEV_RANK = {
    Severity.CRITICAL: 3,
    Severity.WARNING:  2,
    Severity.INFO:     1,
}
_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "": 0, None: 0}


# Headline templates per detector_id. The placeholder ``{span}`` gets
# substituted with a human-readable duration ("2.3 hours", "45
# minutes"); ``{when}`` with the start time ("between 08:14 and
# 10:32"); ``{count}`` with the event count. Templates fall back to a
# generic shape if a detector_id isn't here yet.
_HEADLINE_TEMPLATES: Dict[str, str] = {
    "zia_auth_failures":
        "ZIA authentication failing — {count} event(s) {when}",
    "zpa_auth_failures":
        "ZPA authentication failing — {count} event(s) {when}",
    "tunnel_not_established":
        "Tunnel could not stay connected — {count} flap(s) {when}",
    "adapter_instability":
        "Network adapter unstable — {count} LUID alias change(s) {when}",
    "captive_portal":
        "Captive portal detected — {count} sign-in event(s) {when}",
    "driver_error":
        "ZCC driver failed to load — kernel filter unavailable {when}",
    "endpoint_fw_av":
        "Endpoint firewall / AV interfering with ZCC — {count} block(s) {when}",
    "network_error":
        "Network error -8 family fired — {count} event(s) {when}",
    "slowness":
        "Performance / bandwidth degradation indicators present {when}",
    "system_lifecycle":
        "{count} system sleep/wake event(s) — laptop lifecycle, not an incident",
}

# Generic fallback when the detector_id isn't in the table.
_GENERIC_HEADLINE = "{title} — {count} event(s) {when}"


def build_verdict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Build the verdict dict from an ``analyse()`` result.

    Returns a dict with keys:
      headline       : str — one-sentence summary
      severity       : Severity (the picked finding's severity, or INFO
                       if the bundle is clean)
      confidence     : str ("high" | "medium" | "low" | "")
      time_window    : Optional[(datetime, datetime)] from the picked
                       finding; None if no findings.
      supporting     : List[str] — detector_id/code strings of the
                       findings that contributed to this verdict.
      lifecycle_note : Optional[str] — explanatory line about
                       sleep/wake downgrades, populated when any
                       finding has ``_lifecycle_downgraded_from``.
      severity_counts: Dict[str, int] — total/critical/warning/info.
      kind           : "clean" | "incident" | "lifecycle_only" — used
                       by the UI to pick a layout variant. "clean"
                       means no Critical or Warning findings; "lifecycle_only"
                       means the only findings are the auto-emitted
                       lifecycle ones; "incident" means something the
                       engineer should actually triage.
    """
    # Phase 29-A: use the shared _SKIP_MARKER_CODES frozenset from
    # ui.findings so OS-skipped AND suite-skipped detectors are
    # excluded uniformly. Previously this site only excluded the OS
    # marker, leaking suite-skipped detectors into the verdict count.
    from zcc_diag.ui.findings import _SKIP_MARKER_CODES as _skip_codes
    findings = data.get("findings") or []
    real_findings = [
        f for f in findings
        if f.get("code") not in _skip_codes
    ]

    counts = _count_by_severity(real_findings)
    bundle_window = _bundle_window(real_findings, data)
    lifecycle_count = sum(
        1 for f in real_findings
        if f.get("_lifecycle_downgraded_from")
    )

    # Pick the dominant finding. Maximise (severity_rank, confidence_rank,
    # count) so a Critical-high-confidence-many-events finding wins
    # over a Critical-low-confidence-one-event finding even when both
    # exist.
    triageable = [
        f for f in real_findings
        if f.get("severity") != Severity.INFO
        and f.get("code") not in (
            "SYSTEM_SLEEP_EVENT", "SYSTEM_WAKE_EVENT",
        )
    ]

    if not triageable:
        # No Critical or Warning findings = clean bundle (modulo info
        # signals like system lifecycle events). Distinguish "clean"
        # from "lifecycle_only" so the UI can phrase it as "looks
        # healthy, only routine sleep/wake activity" vs "no signals at
        # all".
        if lifecycle_count or any(
            f.get("code") in ("SYSTEM_SLEEP_EVENT", "SYSTEM_WAKE_EVENT")
            for f in real_findings
        ):
            return {
                "headline":
                    "No incidents detected. Routine system sleep/wake "
                    "activity only.",
                "severity": Severity.INFO,
                "confidence": "high",
                "time_window": bundle_window,
                "supporting": [],
                "lifecycle_note": _lifecycle_note(lifecycle_count),
                "severity_counts": counts,
                "kind": "lifecycle_only",
            }
        return {
            "headline": "No incidents detected in this bundle.",
            "severity": Severity.INFO,
            "confidence": "high",
            "time_window": bundle_window,
            "supporting": [],
            "lifecycle_note": None,
            "severity_counts": counts,
            "kind": "clean",
        }

    triageable.sort(
        key=lambda f: (
            -_SEV_RANK.get(f.get("severity"), 0),
            -_CONF_RANK.get(f.get("confidence"), 0),
            -int(f.get("count") or 0),
        ),
    )
    top = triageable[0]

    # Co-supporting findings: same detector_id as the top, OR severity
    # equally high. These get listed beneath the headline as "also
    # firing".
    supporting: List[str] = []
    for f in triageable[:5]:
        supporting.append(f"{f.get('detector_id', '')}/{f.get('code', '')}")

    headline = _format_headline(top)

    return {
        "headline": headline,
        "severity": top.get("severity") or Severity.INFO,
        "confidence": top.get("confidence") or "",
        "time_window": top.get("time_range"),
        "supporting": supporting,
        "lifecycle_note": _lifecycle_note(lifecycle_count),
        "severity_counts": counts,
        "kind": "incident",
    }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"total": 0, "critical": 0, "warning": 0, "info": 0}
    for f in findings:
        counts["total"] += 1
        sev = f.get("severity")
        if sev == Severity.CRITICAL: counts["critical"] += 1
        elif sev == Severity.WARNING: counts["warning"] += 1
        elif sev == Severity.INFO: counts["info"] += 1
    return counts


def _bundle_window(
    findings: List[Dict[str, Any]],
    data: Dict[str, Any],
) -> Optional[Tuple[datetime, datetime]]:
    """The widest time_range across all findings. Used when the picked
    finding has no time_range of its own."""
    bounds: List[datetime] = []
    for f in findings:
        tr = f.get("time_range")
        if tr and tr[0] is not None and tr[1] is not None:
            bounds.append(tr[0])
            bounds.append(tr[1])
    if not bounds:
        return None
    return (min(bounds), max(bounds))


def _format_headline(top: Dict[str, Any]) -> str:
    """Render the headline string from a finding dict using
    `_HEADLINE_TEMPLATES` keyed on detector_id."""
    det_id = top.get("detector_id", "")
    tpl = _HEADLINE_TEMPLATES.get(det_id, _GENERIC_HEADLINE)
    span_str = _format_span(top.get("time_range"))
    when_str = _format_when(top.get("time_range"))
    return tpl.format(
        title=top.get("title") or "(no title)",
        count=int(top.get("count") or 0),
        span=span_str,
        when=when_str,
    )


def _format_when(time_range) -> str:
    """Build the 'between HH:MM and HH:MM' fragment, or
    'at HH:MM:SS' for a single-instant finding."""
    if not time_range or time_range[0] is None:
        return ""
    t0, t1 = time_range[0], time_range[1] or time_range[0]
    if t0 == t1:
        return f"at {t0.strftime('%H:%M:%S')}"
    return f"between {t0.strftime('%H:%M')} and {t1.strftime('%H:%M')}"


def _format_span(time_range) -> str:
    """Build a '2.3 hours' / '45 minutes' / '12 seconds' fragment."""
    if not time_range or time_range[0] is None or time_range[1] is None:
        return ""
    secs = (time_range[1] - time_range[0]).total_seconds()
    if secs < 60:
        return f"{int(secs)} seconds"
    if secs < 3600:
        return f"{int(secs / 60)} minutes"
    hours = secs / 3600
    if hours < 24:
        return f"{hours:.1f} hours"
    return f"{int(hours / 24)} days"


def _lifecycle_note(n: int) -> Optional[str]:
    """Explanatory line when downgrades happened."""
    if n <= 0:
        return None
    if n == 1:
        return (
            "1 finding was auto-downgraded to Info because it correlated "
            "with a system sleep/wake event (expected laptop lifecycle, "
            "not an incident)."
        )
    return (
        f"{n} findings were auto-downgraded to Info because they "
        f"correlated with system sleep/wake events (expected laptop "
        f"lifecycle, not incidents)."
    )


# ──────────────────────────────────────────────────────────────────────
# Rendering
# ──────────────────────────────────────────────────────────────────────

def render_verdict(verdict: Dict[str, Any]) -> None:
    """Render the verdict block at the top of the Overview.

    Layout:
      * Severity-tinted left border + larger headline font.
      * Below the headline: confidence pill + time window + lifecycle note.
      * Severity-count tiles on the right.

    Streamlit-side function — kept separate from ``build_verdict`` so
    the verdict logic stays unit-testable without a Streamlit runtime.
    """
    import streamlit as st

    sev = verdict.get("severity") or Severity.INFO
    kind = verdict.get("kind", "incident")

    # Border colour mirrors severity. CSS classes already defined in
    # ui/styles.py (.zd-crit / .zd-warn / .zd-info).
    cls_map = {
        Severity.CRITICAL: "zd-verdict zd-crit",
        Severity.WARNING:  "zd-verdict zd-warn",
        Severity.INFO:     "zd-verdict zd-info",
    }
    cls = cls_map.get(sev, "zd-verdict zd-info")
    # Override for the friendly "clean / lifecycle_only" cases — they
    # use a neutral green-ish tint instead of the warning amber that
    # plain Info would suggest.
    if kind in ("clean", "lifecycle_only"):
        cls = "zd-verdict zd-verdict-clean"

    counts = verdict.get("severity_counts") or {}
    conf = verdict.get("confidence") or ""
    headline = verdict.get("headline", "")

    # Confidence pill — same shape as finding cards already use.
    conf_pill = ""
    if conf:
        conf_pill = (
            f'<span class="zd-finding-conf zd-conf-{conf}" '
            f'title="Signal credibility (orthogonal to severity).">'
            f'{conf} confidence</span>'
        )

    # Time window line — "between 08:14 and 10:32 on 2026-06-12".
    win_line = ""
    tw = verdict.get("time_window")
    if tw and tw[0] is not None and tw[1] is not None:
        t0, t1 = tw
        if t0 == t1:
            win_line = (
                f'<span class="zd-verdict-when">'
                f'at {t0.strftime("%H:%M:%S")} on {t0.strftime("%Y-%m-%d")}'
                f'</span>'
            )
        else:
            same_day = t0.date() == t1.date()
            if same_day:
                win_line = (
                    f'<span class="zd-verdict-when">'
                    f'{t0.strftime("%H:%M")}–{t1.strftime("%H:%M")} on '
                    f'{t0.strftime("%Y-%m-%d")}</span>'
                )
            else:
                win_line = (
                    f'<span class="zd-verdict-when">'
                    f'{t0.strftime("%Y-%m-%d %H:%M")} → '
                    f'{t1.strftime("%Y-%m-%d %H:%M")}</span>'
                )

    # Severity tile cluster — compact inline. Reuses existing tile CSS.
    tiles_html = (
        f'<div class="zd-verdict-tiles">'
        f'  <span class="zd-vtile zd-vt-crit">'
        f'    <b>{counts.get("critical", 0)}</b> crit'
        f'  </span>'
        f'  <span class="zd-vtile zd-vt-warn">'
        f'    <b>{counts.get("warning", 0)}</b> warn'
        f'  </span>'
        f'  <span class="zd-vtile zd-vt-info">'
        f'    <b>{counts.get("info", 0)}</b> info'
        f'  </span>'
        f'</div>'
    )

    meta_bits = [bit for bit in (conf_pill, win_line) if bit]
    meta_line = (
        f'<div class="zd-verdict-meta">{" · ".join(meta_bits)}</div>'
        if meta_bits else ""
    )

    block = (
        f'<div class="{cls}">'
        f'  <div class="zd-verdict-row">'
        f'    <div class="zd-verdict-text">'
        f'      <div class="zd-verdict-headline">{headline}</div>'
        f'      {meta_line}'
        f'    </div>'
        f'    {tiles_html}'
        f'  </div>'
        f'</div>'
    )
    st.markdown(block, unsafe_allow_html=True)

    lifecycle_note = verdict.get("lifecycle_note")
    if lifecycle_note:
        st.caption(f"_{lifecycle_note}_")


def render_health_check(verdict: Dict[str, Any],
                        data: Dict[str, Any]) -> None:
    """Render the "looks healthy" affirmative report for clean
    bundles. Only meaningful when verdict.kind is "clean" or
    "lifecycle_only". Lists what's working — tunnel up, ZIA/ZPA
    enrolled, recent successful sessions, clean ZPA app catalog —
    so the engineer can confirm the toolkit didn't miss anything
    rather than chase a non-existent incident.

    Renders below the verdict block when applicable.
    """
    import streamlit as st

    kind = verdict.get("kind", "")
    if kind not in ("clean", "lifecycle_only"):
        return

    s = data.get("summary")
    if s is None:
        return

    st.markdown(
        '<div class="zd-verdict zd-verdict-clean" '
        'style="margin-top:8px;">'
        '<div class="zd-verdict-headline" '
        'style="font-size:1rem;">'
        'What\'s working in this bundle'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    bits = []
    bm = s.bundle_meta or {}

    # ZIA / ZPA enrollment + tunnel-up state.
    policy = data.get("policy") or {}
    zia_enrolled = (
        str(policy.get("ZIA enrolled", "")).lower() in ("true", "yes", "1")
    )
    zpa_enrolled = (
        str(policy.get("ZPA enrolled", "")).lower() in ("true", "yes", "1")
    )
    if zia_enrolled:
        bits.append("ZIA is enrolled")
    if zpa_enrolled:
        bits.append("ZPA is enrolled")

    # ZPA broker DC observed = ZPA reached its broker pool.
    broker_info = bm.get("zpa_broker_dcs") or {}
    if broker_info.get("primary_dc"):
        bits.append(
            f"ZPA broker reachable in **{broker_info['primary_dc']}** "
            f"(observed {len(broker_info.get('broker_hostnames') or [])} "
            f"broker host(s))"
        )

    # ZPA app catalog — successfully pushed by the broker.
    zpa_apps_info = bm.get("zpa_apps") or {}
    n_apps = len(zpa_apps_info.get("apps") or [])
    if n_apps:
        bits.append(
            f"ZPA pushed **{n_apps} application(s)** to this client"
        )

    # ZPA sessions — successfully established mtunnels.
    sessions = data.get("zpa_sessions") or []
    if sessions:
        n_closed = sum(1 for sess in sessions if sess.outcome == "closed")
        if n_closed:
            bits.append(
                f"**{n_closed} ZPA session(s)** completed normally "
                f"(of {len(sessions)} total)"
            )

    # Lifecycle context.
    lifecycle_note = verdict.get("lifecycle_note")
    if lifecycle_note:
        bits.append(
            "System sleep/wake events were the only signal — these are "
            "expected laptop lifecycle, not incidents"
        )

    if not bits:
        bits.append(
            "No critical or warning findings fired across any detector. "
            "If the customer is still reporting an issue, "
            "either the symptom is outside the toolkit's current "
            "coverage, or it didn't occur during the bundle's capture "
            "window. Re-export during an active incident to capture more "
            "signal."
        )

    for bit in bits:
        st.markdown(f"- {bit}")


# Backwards-compat aliases.
_build_verdict = build_verdict
_render_verdict = render_verdict
_render_health_check = render_health_check
