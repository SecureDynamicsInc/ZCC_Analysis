"""
Markdown renderer for RCAReport.

Output matches the exact layout the team agreed on for customer-facing
RCAs (see feedback-rca-format-default-output memory). The renderer is
intentionally simple — all formatting decisions live in the data model
(EventClassification → emoji, EvidenceStrength → framing words).
"""

from __future__ import annotations

from enum import Enum
from typing import List

from .model import (
    ContributingFactor,
    Evidence,
    EvidenceStrength,
    FixHorizon,
    FixRecommendation,
    RCAReport,
    RootCause,
    TimelineEvent,
)


class RCAView(str, Enum):
    """How verbose to make the output. The data model carries everything
    — the view just filters what the renderer emits.

    BRIEF    — Summary + Fix only. ~15 lines. For chat answers and
               Slack pings. The format Shameel pushed back on the
               "everything" view for.
    STANDARD — Summary + Timeline + Root Causes + Contributing Factors
               + Fix. ~40 lines. For ticket replies and escalation
               notes (Zscaler support, etc.).
    FULL     — All 10 sections including Evidence, Impact metrics,
               Verification Plan, Open Questions, Bundle Facts. ~100
               lines. For the formal customer-facing docx.
    """
    BRIEF = "brief"
    STANDARD = "standard"
    FULL = "full"


_HORIZON_LABEL = {
    FixHorizon.IMMEDIATE: "Immediate",
    FixHorizon.SHORT: "Short-term",
    FixHorizon.MEDIUM: "Medium-term",
    FixHorizon.LONG: "Long-term",
}


def _ev_prefix(ev: Evidence) -> str:
    """Framing word so the reader can tell a quote from a hypothesis."""
    return {
        EvidenceStrength.DIRECT_QUOTE: "",
        EvidenceStrength.LOG_INFERENCE: "(inference) ",
        EvidenceStrength.HYPOTHESIS: "(hypothesis) ",
        EvidenceStrength.CUSTOMER_STATED: "(customer-stated, unverified) ",
    }.get(ev.strength, "")


def _render_evidence_bullet(ev: Evidence) -> str:
    prefix = _ev_prefix(ev)
    txt = ev.text.strip()
    if ev.source_file and ev.line_no:
        return f"- {prefix}{txt}  *({ev.source_file}:{ev.line_no})*"
    if ev.source_file:
        return f"- {prefix}{txt}  *({ev.source_file})*"
    return f"- {prefix}{txt}"


def _render_root_cause(rc: RootCause) -> List[str]:
    lines = [f"**{rc.id} — {rc.title}**", "", rc.mechanism, ""]
    if rc.observed_sequence:
        lines.append("Observed sequence:")
        for step in rc.observed_sequence:
            lines.append(f"- {step}")
        lines.append("")
    if rc.evidence:
        lines.append("Evidence:")
        for ev in rc.evidence:
            lines.append(_render_evidence_bullet(ev))
        lines.append("")
    return lines


def _render_contrib(cf: ContributingFactor) -> List[str]:
    head = f"**{cf.id} — {cf.title}**"
    if cf.is_hypothesis:
        head += " *(hypothesis — customer to verify)*"
    lines = [head, "", cf.body, ""]
    if cf.evidence:
        for ev in cf.evidence:
            lines.append(_render_evidence_bullet(ev))
        lines.append("")
    return lines


def _render_fix(fx: FixRecommendation) -> List[str]:
    lines = [
        f"### {_HORIZON_LABEL[fx.horizon]} — {fx.owner}",
        "",
        f"**{fx.title}**",
        "",
        fx.body,
        "",
    ]
    if fx.bullets:
        for b in fx.bullets:
            lines.append(f"- {b}")
        lines.append("")
    if fx.effect:
        lines.append(f"*Effect:* {fx.effect}")
        lines.append("")
    return lines


def _render_timeline(timeline: List[TimelineEvent]) -> List[str]:
    if not timeline:
        return []
    rows = [
        "| # | When (local) | UTC | Class | Recovery | Tunnel impact |",
        "|---|---|---|---|---|---|",
    ]
    for i, ev in enumerate(timeline, 1):
        local = ev.ts_local.strftime("%a %b %d %H:%M:%S")
        utc = ev.ts_utc.strftime("%H:%M:%S")
        cls = f"{ev.severity_emoji} {ev.classification.value.replace('_',' ').title()}"
        rows.append(
            f"| {i} | {local} | {utc} UTC | {cls} | {ev.recovery_text} | {ev.tunnel_impact} |"
        )
    rows.append("")
    return rows


def _render_brief_fix(fx: FixRecommendation, n: int) -> str:
    """Compact one-line-per-fix renderer for the BRIEF view."""
    horizon = _HORIZON_LABEL[fx.horizon]
    return f"{n}. **{fx.owner}** ({horizon}) — {fx.title}"


def _render_brief(report: RCAReport) -> str:
    """BRIEF view: ~15 lines. Summary + Fix only.

    Used in chat answers and Slack pings where the reader needs
    'what broke, why, what to fix' without scrolling.
    """
    out: List[str] = []

    # Compact header. Phase 58e (2026-07-08): honor report.issue_title
    # so non-ZPA-reauth RCAs (network_error, driver_error, captive_portal,
    # zia_auth_failures, etc.) don't ship with the ZPA headline.
    title = (report.issue_title or "").strip() or "Issue"
    head = f"**{report.customer} — {report.user} — {title}**"
    out.append(head)
    if report.severity_label:
        out.append(f"Severity: {report.severity_label}")
    out.append("")

    # What happened — collapse all summary paragraphs into one block
    if report.summary_paragraphs:
        out.append("**What happened:**")
        for p in report.summary_paragraphs:
            out.append(p)
        out.append("")

    # Fix — numbered list, compact form
    if report.fixes:
        out.append("**Fix:**")
        for i, fx in enumerate(report.fixes, 1):
            out.append(_render_brief_fix(fx, i))
            # Show key bullets inline for fixes that need parameters
            if fx.bullets and fx.horizon == FixHorizon.IMMEDIATE:
                for b in fx.bullets[:2]:
                    out.append(f"   - `{b}`")
        out.append("")

    # First open question, if any (the highest-priority customer ask)
    if report.open_questions:
        q = report.open_questions[0]
        out.append(f"**Open Q for customer:** {q.question}")
        out.append("")

    if report.synthesizer_id:
        out.append(
            f"*Generated by BundleScope `{report.synthesizer_id}` "
            f"v{report.synthesizer_version} — for the full RCA, use `view=full`*"
        )

    return "\n".join(out)


def _render_standard(report: RCAReport) -> str:
    """STANDARD view: ~40 lines. Summary + Timeline + Root Causes +
    Contributing Factors + Fix.

    Used for ticket replies and escalation notes where the reader needs
    enough mechanism to forward to Zscaler support, but not the formal
    Evidence / Verification / Open-Q / Facts sections.
    """
    out: List[str] = []

    # Standard header. Phase 58e (2026-07-08): use report.issue_title.
    _title_std = (report.issue_title or "").strip() or "Issue"
    out.append(f"# RCA — {report.customer} — {_title_std}")
    out.append("")
    out.append(
        f"**User:** {report.user}  **Device:** {report.device}  "
        f"**ZCC:** {report.zcc_version}"
    )
    if report.severity_label:
        out.append(f"**Severity:** {report.severity_label}")
    out.append("")

    if report.summary_paragraphs:
        out.append("## Summary")
        for p in report.summary_paragraphs:
            out.append(p)
            out.append("")

    if report.timeline:
        out.append("## Timeline")
        out.append("")
        out.extend(_render_timeline(report.timeline))

    if report.root_causes:
        out.append("## Root Causes")
        out.append("")
        for rc in report.root_causes:
            out.extend(_render_root_cause(rc))

    if report.contributing_factors:
        out.append("## Contributing Factors")
        out.append("")
        for cf in report.contributing_factors:
            out.extend(_render_contrib(cf))

    if report.fixes:
        out.append("## Fix")
        out.append("")
        for fx in report.fixes:
            out.extend(_render_fix(fx))

    if report.synthesizer_id:
        out.append("")
        out.append(
            f"*Generated by BundleScope `{report.synthesizer_id}` "
            f"v{report.synthesizer_version}*"
        )
    return "\n".join(out)


def _render_full(report: RCAReport) -> str:
    """FULL view: all 10 sections. ~100 lines.

    Used for the formal customer-facing docx and any context where the
    written record matters (audit trail, post-incident review).
    """
    out: List[str] = []

    # Phase 58e (2026-07-08): honor issue_title in full-tier renderer.
    _title_full = (report.issue_title or "").strip() or "Issue"
    out.append(f"# RCA — {report.customer} — {_title_full}")
    out.append("")
    out.append(
        f"**Customer:** {report.customer}  **User:** {report.user}  "
        f"**Device:** {report.device}"
    )
    out.append(
        f"**Bundle:** {report.bundle_filename} (exported {report.bundle_exported})  "
        f"**ZCC:** {report.zcc_version}"
    )
    out.append(
        f"**Prepared by:** {report.prepared_by}  **Date:** {report.report_date}"
    )
    if report.severity_label:
        out.append(f"**Severity / Status:** {report.severity_label}")
    out.append("")
    out.append("---")
    out.append("")

    if report.summary_paragraphs:
        out.append("## Summary")
        out.append("")
        for p in report.summary_paragraphs:
            out.append(p)
            out.append("")
        out.append("---")
        out.append("")

    if report.timeline:
        out.append("## Timeline")
        out.append("")
        out.extend(_render_timeline(report.timeline))
        out.append("---")
        out.append("")

    if report.root_causes:
        out.append("## Root Causes")
        out.append("")
        for rc in report.root_causes:
            out.extend(_render_root_cause(rc))
        out.append("---")
        out.append("")

    if report.contributing_factors:
        out.append("## Contributing Factors")
        out.append("")
        for cf in report.contributing_factors:
            out.extend(_render_contrib(cf))
        out.append("---")
        out.append("")

    if report.evidence_quotes:
        out.append("## Evidence")
        out.append("")
        for heading, lines in report.evidence_quotes:
            out.append(f"**{heading}**")
            out.append("")
            out.append("```")
            for ln in lines:
                out.append(ln)
            out.append("```")
            out.append("")
        out.append("---")
        out.append("")

    if report.impact_metrics:
        out.append("## Impact")
        out.append("")
        out.append("| Metric | Value |")
        out.append("|---|---|")
        for m in report.impact_metrics:
            label = f"**{m.label}**" if m.highlight else m.label
            value = f"**{m.value}**" if m.highlight else m.value
            out.append(f"| {label} | {value} |")
        out.append("")
        out.append("---")
        out.append("")

    if report.fixes:
        out.append("## Fix")
        out.append("")
        for fx in report.fixes:
            out.extend(_render_fix(fx))
        out.append("---")
        out.append("")

    if report.verifications:
        out.append("## Verification Plan")
        out.append("")
        for v in report.verifications:
            out.append(f"**{v.after_fix}:**")
            out.append(f"- {v.action}")
            out.append(f"- *Expected:* {v.expected}")
            out.append("")
        out.append("---")
        out.append("")

    if report.open_questions:
        out.append("## Open Questions for Customer")
        out.append("")
        for q in report.open_questions:
            line = f"{q.id} — {q.question}"
            if q.why_it_matters:
                line += f"  *({q.why_it_matters})*"
            out.append(line)
            out.append("")
        out.append("---")
        out.append("")

    if report.bundle_facts:
        out.append("## Bundle Facts (verified from this bundle)")
        out.append("")
        out.append("| | |")
        out.append("|---|---|")
        for f in report.bundle_facts:
            out.append(f"| {f.label} | {f.value} |")
        out.append("")

    if report.synthesizer_id:
        out.append("")
        out.append(
            f"*Generated by BundleScope `{report.synthesizer_id}` "
            f"v{report.synthesizer_version}*"
        )

    return "\n".join(out)


def render_markdown(report: RCAReport, view: RCAView = RCAView.BRIEF) -> str:
    """Render an RCAReport to markdown at the chosen verbosity.

    Default is BRIEF — chat / Slack / quick-answer context. Use STANDARD
    for ticket replies, FULL for the customer-facing docx.

    The data model carries everything; the view only filters what the
    renderer emits, so the same RCAReport can be rendered three ways
    without rebuilding it.
    """
    if view == RCAView.BRIEF:
        return _render_brief(report)
    if view == RCAView.STANDARD:
        return _render_standard(report)
    return _render_full(report)
