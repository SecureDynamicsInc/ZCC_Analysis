"""
Investigate Issue module — prompt-driven re-investigation UI.

Phase 39 (2026-06-19). Wraps the deterministic
``zcc_diag.issue_investigator`` core in a Streamlit page so the
engineer can paste a customer-ticket description and get back a
structured Markdown investigation report.

Workflow:

  1. Engineer pastes the ticket description into a text area.
  2. BundleScope parses the prompt — extracts time window, suite,
     symptoms, hosts/IPs/apps.
  3. Engineer clicks Run Investigation.
  4. The investigator filters findings + sessions + log lines to the
     prompt's scope, correlates related events, and renders a
     Markdown report.
  5. Engineer can:
     - Read the rendered report in the UI
     - Copy the Markdown text (via the standard Streamlit code-block
       copy button) to paste into a ticket / Slack / email
     - Tweak the prompt and re-run

The UI is intentionally minimal — the value is in the structured
report, not the form chrome. One text area, one button, one rendered
report.
"""

from __future__ import annotations

from typing import Any, Dict

import streamlit as st


def module_investigate(data: Dict[str, Any]) -> None:
    """Streamlit entry point for the Investigate Issue module."""
    st.markdown(
        '<div class="zd-section">Investigate Issue</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Paste the customer's ticket description below. BundleScope "
        "parses the prompt, filters the bundle to that scope, "
        "correlates the related log events, and emits a Markdown "
        "report you can paste straight into a ticket reply."
    )

    # --- Inputs ---
    #
    # Phase 58e-H11 (2026-07-08): honor `ts_from` / `ts_to` query
    # params from the drill-down "Open in Correlate Events" button.
    # Previously the button wrote these params but no reader consumed
    # them — user landed on Investigate with a blank prompt despite
    # the button advertising "time window pre-loaded". Now we seed
    # the prompt with an ISO-form window on FIRST render (marked via
    # a session-state guard so subsequent user edits stick).
    ts_from_qp = st.query_params.get("ts_from", "")
    ts_to_qp = st.query_params.get("ts_to", "")
    _seed_key = "_investigate_seed_applied"
    seeded_prompt = None
    if ts_from_qp and ts_to_qp and not st.session_state.get(_seed_key):
        seeded_prompt = (
            f"Correlate log activity between {ts_from_qp} and "
            f"{ts_to_qp} (UTC)."
        )
        st.session_state["_investigate_last_prompt"] = seeded_prompt
        st.session_state[_seed_key] = True
        # Clear the params so a manual reload doesn't re-seed.
        try:
            del st.query_params["ts_from"]
            del st.query_params["ts_to"]
        except (KeyError, AttributeError):
            pass

    default_prompt = st.session_state.get("_investigate_last_prompt", "")
    prompt = st.text_area(
        "Issue description",
        value=default_prompt,
        height=140,
        placeholder=(
            "e.g.  user couldn't login to ZPA around 2pm yesterday\n"
            "      salesforce keeps disconnecting on Jun 17 afternoon\n"
            "      DNS resolution fails for storefront.corp-a.example\n"
            "      tray keeps crashing 2026-06-17 between 19:00 and 22:00\n"
            "      WPAD broken at 14:30"
        ),
    )
    if seeded_prompt:
        st.caption(
            f"_Prompt pre-loaded from drill-down: "
            f"`{ts_from_qp}` → `{ts_to_qp}` UTC. Edit or click Run "
            "Investigation._"
        )

    col_a, col_b = st.columns([1, 4])
    run = col_a.button(
        "Run Investigation",
        type="primary",
        disabled=not prompt.strip(),
    )
    show_context = col_b.checkbox(
        "Show parsed context (for verification)",
        value=False,
        help=(
            "Expand to see exactly how BundleScope parsed your "
            "prompt — useful when the report misses something you "
            "expected to see."
        ),
    )

    if not run and "_investigate_last_report" not in st.session_state:
        st.info(
            "Type an issue description above and click Run "
            "Investigation. The longer / more specific the prompt, "
            "the better the filtering — but a bare phrase like "
            "'SAML expired loop' works too."
        )
        return

    # Re-run only when the button is pressed; otherwise re-render the
    # cached report (so the engineer can toggle "show context" or
    # scroll without losing the result).
    if run:
        st.session_state["_investigate_last_prompt"] = prompt
        report, rendered = _run_investigation(data, prompt)
        st.session_state["_investigate_last_report"] = report
        st.session_state["_investigate_last_md"] = rendered

    report = st.session_state.get("_investigate_last_report")
    rendered = st.session_state.get("_investigate_last_md")
    if report is None or rendered is None:
        return

    # --- Parsed context (collapsible) ---
    if show_context:
        with st.expander("Parsed context", expanded=True):
            inv = report.investigation
            ctx = {
                "raw_prompt": inv.raw_prompt,
                "time_window": (
                    [t.isoformat() for t in report.window]
                    if report.window else None
                ),
                "time_description": report.window_description,
                "suites": inv.suites,
                "symptoms": inv.symptoms,
                "hosts": inv.hosts,
                "ip_addresses": inv.ip_addresses,
                "apps": inv.apps,
                "keywords": inv.keywords,
            }
            st.json(ctx)

    # Phase 57c (2026-07-02): Zero-overlap guard.
    # When the user's parsed window contains ZERO log lines, that
    # almost always means the window was inferred outside the bundle's
    # actual coverage (like an engineer typing "5am MST" for a bundle
    # that starts at 11:04 MDT). Silently returning zeros makes the
    # report look "clean" when in reality we couldn't check anything.
    # Warn, and offer a one-click "search the whole bundle instead"
    # fallback that clears the time window and re-runs.
    lines_scanned = sum(report.log_kind_counts.values())
    bundle_win = _bundle_window_from_data(data)
    query_win = report.window
    if lines_scanned == 0 and query_win and bundle_win:
        overlap_start = max(query_win[0], bundle_win[0])
        overlap_end = min(query_win[1], bundle_win[1])
        no_overlap = overlap_start > overlap_end
        if no_overlap:
            st.error(
                f"**Your query time is outside this bundle's log "
                f"window.** Query: `{query_win[0].strftime('%Y-%m-%d %H:%M')}` – "
                f"`{query_win[1].strftime('%Y-%m-%d %H:%M')}`  ·  "
                f"Bundle covers: "
                f"`{bundle_win[0].strftime('%Y-%m-%d %H:%M')}` – "
                f"`{bundle_win[1].strftime('%Y-%m-%d %H:%M')}`.  "
                f"Either the reported time / timezone is wrong, or "
                f"the events belong to a prior ZCC install whose logs "
                f"were overwritten. **Recommended: re-run without a "
                f"time filter to scan the whole bundle.**"
            )
            if st.button(
                "🔄 Re-run without time filter (scan whole bundle)",
                key="investigate_rerun_no_window",
                type="secondary",
            ):
                # Strip any clock/date/tz words from the prompt and re-run
                stripped = _strip_time_expressions(prompt)
                report2, rendered2 = _run_investigation(data, stripped)
                st.session_state["_investigate_last_prompt"] = stripped
                st.session_state["_investigate_last_report"] = report2
                st.session_state["_investigate_last_md"] = rendered2
                st.rerun()

    # --- Headline metrics strip ---
    cols = st.columns(4)
    cols[0].metric(
        "Lines scanned",
        f"{sum(report.log_kind_counts.values()):,}",
        delta=(
            "in window"
            if report.window else "whole bundle"
        ),
        delta_color="off",
    )
    cols[1].metric(
        "Matched sessions",
        len(report.matched_sessions),
    )
    cols[2].metric(
        "Broker errors",
        sum(report.broker_error_counts.values()),
        delta=(
            f"{len(report.broker_error_counts)} distinct"
            if report.broker_error_counts else "none"
        ),
        delta_color=(
            "inverse" if report.broker_error_counts else "off"
        ),
    )
    cols[3].metric(
        "ZPA re-auth prompts",
        report.reauth_event_count,
        delta_color=(
            "inverse" if report.reauth_event_count else "off"
        ),
    )

    st.divider()

    # --- The Markdown report ---
    # st.markdown renders the prose. st.code(language='markdown')
    # below it gives the engineer a one-click copy button for the
    # raw Markdown to paste into a ticket.
    st.markdown(rendered)

    st.divider()
    with st.expander(
        "Copy Markdown for ticket / Slack / email",
        expanded=False,
    ):
        st.caption(
            "Click the copy icon in the top-right of the code block "
            "below to copy the full report."
        )
        st.code(rendered, language="markdown")


def _run_investigation(data: Dict[str, Any], prompt: str):
    """Glue function — assembles the inputs the investigator needs
    and runs it. Returns (InvestigationReport, markdown_str)."""
    # Local imports keep the page load cheap when the module isn't
    # actually being rendered (Streamlit re-runs the whole script on
    # every interaction).
    from zcc_diag.issue_investigator import (
        parse_prompt, investigate, render_report,
    )

    summary = data.get("summary")
    bm = (summary and getattr(summary, "bundle_meta", {})) or {}
    # Phase 58e-C9 (2026-07-08): hoist log_index unconditionally so the
    # `if log_index is not None` check below never hits UnboundLocalError.
    # The prior code bound `log_index` only inside the `else` branch,
    # crashing whenever `bundle_meta['capture_window']` is populated.
    log_index = data.get("log_index")
    # Bundle capture window — used to anchor relative time phrases.
    bundle_window = None
    cap = bm.get("capture_window") if isinstance(bm, dict) else None
    if isinstance(cap, (list, tuple)) and len(cap) == 2 and all(cap):
        bundle_window = (cap[0], cap[1])
    else:
        # Fall back: derive from log_index if available.
        if log_index and getattr(log_index, "lines", None):
            ts_first = None
            ts_last = None
            for ln in log_index.lines:
                ts = getattr(ln, "ts", None)
                if ts is None:
                    continue
                if ts_first is None or ts < ts_first:
                    ts_first = ts
                if ts_last is None or ts > ts_last:
                    ts_last = ts
            if ts_first and ts_last:
                bundle_window = (ts_first, ts_last)

    # Parse the prompt. Phase 58c (2026-07-02): pass the bundle's
    # local-offset ("-0600" etc) so the parser can convert user-typed
    # local clocks to UTC before matching against the log.
    bundle_local_offset = None
    if log_index is not None:
        bundle_local_offset = getattr(log_index, "bundle_tz_offset", None)
    inv = parse_prompt(
        prompt,
        bundle_window=bundle_window,
        bundle_local_offset=bundle_local_offset,
    )

    # Pull the rest of the bundle data for the investigator.
    findings = data.get("findings") or []
    zpa_sessions = data.get("zpa_sessions") or []
    # Phase 57d (2026-07-02): pipe RCA + correlator output into the
    # investigator so top-tier findings and cross-stream events show
    # up as first-class hits, not just raw log matches.
    rca_reports = data.get("rca_reports") or {}
    correlators = data.get("correlators") or {}

    # Run.
    report = investigate(
        summary, findings, zpa_sessions, log_index, inv,
        rca_reports=rca_reports,
        correlators=correlators,
    )
    md = render_report(report)
    return report, md


# ─────────────────────────────── Phase 57c helpers

def _bundle_window_from_data(data: Dict[str, Any]):
    """Return (start, end) of the bundle's log window, or None.

    Prefers the pcap-captured range in summary; falls back to
    scanning log_index for its min/max timestamps.
    """
    summary = data.get("summary")
    if summary is not None:
        cap = getattr(summary, "capture_time_range", None)
        if cap and len(cap) == 2:
            return (cap[0], cap[1])
    log_index = data.get("log_index")
    if log_index is not None:
        ts_first = None
        ts_last = None
        for ln in log_index.lines:
            ts = getattr(ln, "ts", None)
            if ts is None:
                continue
            if ts_first is None or ts < ts_first:
                ts_first = ts
            if ts_last is None or ts > ts_last:
                ts_last = ts
        if ts_first and ts_last:
            return (ts_first, ts_last)
    return None


import re as _re_strip
_TIME_STRIP_PATTERNS = [
    _re_strip.compile(
        r"\b\d{1,2}(?::[0-5]\d)?\s*(?:a\.?m\.?|p\.?m\.?|am|pm)\b",
        _re_strip.IGNORECASE,
    ),
    _re_strip.compile(r"\b[0-2]?\d:[0-5]\d\b"),
    _re_strip.compile(r"\b20\d{2}-\d{2}-\d{2}\b"),
    _re_strip.compile(
        r"\b(?:yesterday|today|this morning|this afternoon|tonight|"
        r"overnight|last night|day before yesterday)\b",
        _re_strip.IGNORECASE,
    ),
    _re_strip.compile(
        r"\b(?:mst|mdt|est|edt|pst|pdt|cst|cdt|utc|gmt|"
        r"eastern|central|mountain|pacific)\b",
        _re_strip.IGNORECASE,
    ),
]


def _strip_time_expressions(text: str) -> str:
    """Remove clock / date / TZ words from text so re-running the
    Investigate module falls back to a bundle-wide scan.
    """
    out = text
    for pat in _TIME_STRIP_PATTERNS:
        out = pat.sub(" ", out)
    return _re_strip.sub(r"\s+", " ", out).strip()


# Backwards-compat alias.
_module_investigate = module_investigate
