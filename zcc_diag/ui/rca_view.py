"""
RCA View Streamlit module — render rca_reports in the UI.

Phase 50a (2026-06-24). Activates the Phase 49 synthesizer output for
customer-facing engineers.

Workflow:
  1. analyse() populates ``data["rca_reports"]`` with one RCAReport
     per detector that has a synthesizer registered (Phase 49).
  2. This module renders that dict — engineer picks a detector and a
     verbosity (Brief / Standard / Full) and reads the rendered RCA.
  3. A "Copy as Markdown" code block lets the engineer paste straight
     into a ticket reply, Slack, or email — no manual reformatting.

UI choices:
  * Brief is the default. Chat-grade — Summary + Fix + first Open Q.
    ~15 lines. The format Shameel signed off on for chat replies.
  * Standard adds Timeline + Root Causes + Contributing Factors.
    ~40 lines. For Zscaler-support escalation notes.
  * Full is all 10 sections. ~100 lines. The formal customer-facing
    deliverable — same shape as the Example Tenant A docx.

Empty state: when no detector has a synthesizer registered (or none of
the registered ones emitted findings), the module renders an empty-
state card pointing the engineer at the Detected Issues module instead.
"""

from __future__ import annotations

from typing import Any, Dict

import streamlit as st


_VIEW_OPTIONS = [
    ("Brief", "brief", "~15 lines — chat / Slack reply"),
    ("Standard", "standard", "~40 lines — ticket reply / Zscaler-support escalation"),
    ("Full", "full", "~100 lines — formal customer-facing record"),
]


def module_rca_view(
    data: Dict[str, Any], suite_filter: str = "",
) -> None:
    """Streamlit entry point for the RCA View module.

    ``suite_filter`` (Phase 54a) — when set to "zia", "zpa", or "zdx",
    only show RCA reports whose synthesizer_id starts with that prefix.
    Empty string shows every report (the legacy behaviour).
    """
    st.markdown(
        '<div class="zd-section">Root Cause Analysis</div>',
        unsafe_allow_html=True,
    )

    rca_reports = data.get("rca_reports") or {}
    if suite_filter:
        sf = suite_filter.lower()
        rca_reports = {
            did: rep for did, rep in rca_reports.items()
            if sf in (did or "").lower()
            or sf in ((getattr(rep, "synthesizer_id", "") or "").lower())
        }
    if not rca_reports:
        _render_empty_state(data)
        return

    # Header — quick summary of what's available.
    st.caption(
        f"{len(rca_reports)} detector(s) in this bundle have RCA-grade "
        "output available. Pick a detector and a verbosity below; the "
        "rendered RCA is also available as raw Markdown for copy/paste."
    )

    # Two columns: detector picker (left) + view-verbosity picker (right).
    col_det, col_view = st.columns([2, 1])

    with col_det:
        # Sort by severity_label heuristic (High first), then alphabetical.
        # Severity isn't directly on the report dict — we infer from the
        # report.severity_label string having "High" at the front for the
        # mid-work-severed case.
        detector_ids = sorted(
            rca_reports.keys(),
            key=lambda did: (
                0 if "High" in (rca_reports[did].severity_label or "")
                else 1 if "Medium" in (rca_reports[did].severity_label or "")
                else 2,
                did,
            ),
        )
        # Build display labels with severity hints so the engineer picks
        # the right one quickly.
        labels = []
        for did in detector_ids:
            report = rca_reports[did]
            sev = report.severity_label or ""
            sev_short = ""
            if sev.startswith("High"):
                sev_short = "🔴 "
            elif sev.startswith("Medium"):
                sev_short = "🟠 "
            elif sev.startswith("Low"):
                sev_short = "🟡 "
            labels.append(f"{sev_short}{report.issue_title or did}")

        chosen_label = st.radio(
            "Detector",
            labels,
            index=0,
            help="One RCA per detector that emitted findings AND has a registered synthesizer.",
        )
        chosen_det_id = detector_ids[labels.index(chosen_label)]

    with col_view:
        view_label = st.radio(
            "Verbosity",
            [opt[0] for opt in _VIEW_OPTIONS],
            index=0,  # Brief default
            help="Brief for chat, Standard for tickets, Full for formal RCA docs.",
        )
        view_key = next(
            opt[1] for opt in _VIEW_OPTIONS if opt[0] == view_label
        )
        view_caption = next(
            opt[2] for opt in _VIEW_OPTIONS if opt[0] == view_label
        )
        st.caption(view_caption)

    report = rca_reports[chosen_det_id]

    # Severity banner at the top of the rendered report.
    sev = report.severity_label or ""
    if sev.startswith("High"):
        st.error(f"Severity: {sev}")
    elif sev.startswith("Medium"):
        st.warning(f"Severity: {sev}")
    elif sev.startswith("Low"):
        st.info(f"Severity: {sev}")

    # Render the markdown.
    try:
        md = report.to_markdown(view=view_key)
    except Exception as exc:
        st.error(
            f"Failed to render RCA: {type(exc).__name__}: {exc}. "
            "The synthesizer may have produced a malformed report; "
            "check the extractor warnings panel."
        )
        return

    # Two tabs: rendered (pretty) and raw markdown (copy-friendly).
    tab_rendered, tab_raw = st.tabs(["Rendered", "Raw Markdown"])
    with tab_rendered:
        st.markdown(md, unsafe_allow_html=True)
    with tab_raw:
        st.caption(
            "Copy the text below and paste into a ticket reply, Slack, "
            "or email. Streamlit's built-in copy button is at the top-"
            "right corner of the code block on hover."
        )
        # Use a code block so the copy-button appears and whitespace
        # is preserved verbatim.
        st.code(md, language="markdown")

    # Extractor warnings — if any failed silently during the run, the
    # engineer should know before sending this to a customer.
    summary = data.get("summary")
    warnings = (
        getattr(summary, "bundle_meta", {}).get("extractor_warnings")
        if summary else None
    )
    if warnings:
        st.divider()
        st.caption(
            f"{len(warnings)} extractor(s) failed silently during analysis. "
            "These could affect the RCA's completeness. Review before sending:"
        )
        for w in warnings[:10]:
            st.markdown(
                f"- **{w.get('extractor', '?')}**: "
                f"{w.get('exception_class', '?')}: "
                f"{w.get('message', '?')}"
            )


def _render_empty_state(data: Dict[str, Any]) -> None:
    """Show a helpful empty-state card when no RCA reports are available."""
    findings = data.get("findings") or []
    if not findings:
        st.info(
            "No findings emitted by detectors for this bundle. The RCA "
            "view shows synthesized root-cause reports for detected "
            "issues — if there are no issues, there's nothing to "
            "synthesize. Try the **Detected Issues** module to confirm."
        )
        return

    # There ARE findings, but none have a synthesizer registered.
    try:
        from zcc_diag.rca.synthesizers import available_synthesizers
        registered = list(available_synthesizers().keys())
    except ImportError:
        registered = []

    detected_ids = sorted({f.get("detector_id") for f in findings if f.get("detector_id")})
    overlap = set(detected_ids) & set(registered)

    if registered and not overlap:
        st.info(
            "RCA synthesizers are registered for the following detectors, "
            "but none of them fired on this bundle:\n\n"
            + "\n".join(f"- `{did}`" for did in registered)
            + "\n\nDetectors that DID fire (visible in the **Detected "
              "Issues** module): "
            + ", ".join(f"`{did}`" for did in detected_ids[:8])
            + (" …" if len(detected_ids) > 8 else "")
            + "\n\nMore synthesizers are queued — Phase 49b onwards. For "
            "now, use the **Detected Issues** module to read the raw "
            "findings."
        )
        return

    # No synthesizers registered at all (shouldn't happen in a normal
    # checkout, but defensive).
    st.info(
        "RCA reports are not available — no synthesizers are registered "
        "in this build. Use the **Detected Issues** module to read raw "
        "findings for now."
    )
