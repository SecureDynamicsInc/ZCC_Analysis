"""
Finding drill-down expander (Phase 55c, 2026-06-26).

Renders the FindingRelations object produced by ``zcc_diag.relations``
as a four-section expander that lives *below every finding row* in
every workspace's findings list.

Sections rendered:

  * ⬆️  Triggers (causal upstream)
  * ⬇️  Effects (causal downstream)
  * ↔️  Co-occurring findings
  * 🧭 Config context

Plus an action-button row for routing into deeper tools:

  * "Open in Correlate Events" — pre-loads Investigate → Free-text
    Search with the finding's ±5min time window.
  * "Show ±5min log context" — inline expander with surrounding lines.
  * "Compare to known cases" — Phase 56 known-case matcher.

The module has NO business logic — everything comes from
FindingRelations. If a section is empty, we render a specific caption
explaining why (rather than a generic "no data" that confuses).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import streamlit as st

from zcc_diag.relations import (
    FindingRelations, get_relations,
)


def render_drilldown(
    finding: Dict[str, Any],
    data: Dict[str, Any],
    key_prefix: str = "",
) -> None:
    """Render the drill-down expander for a single finding.

    ``key_prefix`` — unique-ish prefix for st widget keys (e.g. the
    workspace name + finding index) so multiple expanders on the same
    page don't collide on Streamlit's stateful widget registry.
    """
    try:
        from zcc_diag_ui import _PIPELINE_VERSION as _pv
    except Exception:
        _pv = "unknown"

    code = finding.get("code", "") or "?"
    expander_label = f"⚙  Correlations & context — {code}"

    # Phase 55a.1 (2026-07-02): wrap get_relations in a try/except so
    # a mixed-tz edge case or any other correlator hiccup degrades the
    # expander to a caption instead of crashing the whole workspace.
    try:
        relations = get_relations(finding, data, pipeline_version=_pv)
    except Exception as e:  # noqa: BLE001
        with st.expander(expander_label, expanded=False):
            st.warning(
                "Drill-down failed to compute correlations for this "
                f"finding: `{type(e).__name__}: {e}`. "
                "The finding itself is still valid — this only "
                "affects the neighbour panel. Please share the log "
                "output with the BundleScope team."
            )
        return

    with st.expander(expander_label, expanded=False):
        _render_triggers(relations)
        st.markdown("---")
        _render_effects(relations)
        st.markdown("---")
        _render_co_occurring(relations)
        st.markdown("---")
        _render_config_snapshot(relations)
        st.markdown("---")
        _render_action_buttons(relations, key_prefix=key_prefix or code)


# ───────────────────────────────────────────────── section renderers

def _render_triggers(rel: FindingRelations) -> None:
    st.markdown("### ⬆️ Triggers (causal upstream)")
    if not rel.triggers:
        st.caption(
            "_No upstream causal events found within the finding's "
            f"time window ±{rel.window_seconds}s. Either the finding "
            "is a root cause itself, or the trigger isn't yet covered "
            "by the Phase 48 correlators (power_change / force_reauth / "
            "service_lifecycle)._"
        )
        return
    for t in rel.triggers:
        ts_str = t.ts.isoformat() if t.ts else "?"
        line = f"- **{t.label}** — `{ts_str}`"
        if t.source_file:
            src = t.source_file.split("/")[-1]
            line += f"  ·  `{src}"
            if t.line_no:
                line += f":{t.line_no}"
            line += "`"
        if t.correlator_id:
            line += f"  ·  _via {t.correlator_id}_"
        st.markdown(line)
        if t.paired_with:
            st.markdown(f"    └─ paired with: `{t.paired_with}`")


def _render_effects(rel: FindingRelations) -> None:
    st.markdown("### ⬇️ Effects (causal downstream)")
    if not rel.effects:
        st.caption(
            "_No downstream events attributed to this finding within "
            "±5min. The finding may not have severed any active "
            "sessions (background-only impact)._"
        )
        return
    # Group by label for readability when there are many mtunnel closes
    by_label: Dict[str, List] = {}
    for e in rel.effects:
        by_label.setdefault(e.label, []).append(e)
    for label, events in by_label.items():
        st.markdown(f"**{label}** — {len(events)} event(s)")
        for e in events[:8]:
            ts_str = e.ts.isoformat() if e.ts else "?"
            detail = f" · {e.detail}" if e.detail else ""
            src = e.source_file.split("/")[-1] if e.source_file else ""
            src_bit = f"  ·  `{src}`" if src else ""
            st.markdown(f"- `{ts_str}`{detail}{src_bit}")
        if len(events) > 8:
            st.caption(f"_… {len(events) - 8} more_")


def _render_co_occurring(rel: FindingRelations) -> None:
    st.markdown("### ↔️ Co-occurring findings")
    if not rel.co_occurring:
        st.caption(
            f"_No other findings overlapped this finding's time "
            f"window (±{rel.window_seconds * 5}s). This is an "
            "isolated event._"
        )
        return
    st.markdown(f"**{len(rel.co_occurring)} finding(s)** overlap this time window:")
    for f in rel.co_occurring[:12]:
        sev = f.get("severity", "INFO")
        c = f.get("code", "")
        t = f.get("title") or (f.get("description", "") or "")[:100]
        st.markdown(f"- **{sev}** · `{c}` — {t}")
    if len(rel.co_occurring) > 12:
        st.caption(f"_… {len(rel.co_occurring) - 12} more_")


def _render_config_snapshot(rel: FindingRelations) -> None:
    st.markdown("### 🧭 Config context (snapshot at event time)")
    if not rel.config_snapshot:
        st.caption("_No config values surfaced for this finding._")
        return
    rows = []
    open_questions = []
    for item in rel.config_snapshot:
        if not item.verified:
            open_questions.append(item)
            continue
        rows.append({
            "field": item.label,
            "value": item.value,
            "source": item.source,
        })
    if rows:
        st.dataframe(rows, hide_index=True, use_container_width=True)
    if open_questions:
        st.markdown("**Open questions** (bundle didn't carry these):")
        for oq in open_questions:
            st.markdown(
                f"- ⚠️  **{oq.label}** — need to confirm out-of-band "
                f"({oq.source})"
            )


def _render_action_buttons(
    rel: FindingRelations, key_prefix: str,
) -> None:
    """Row of action buttons routing into deeper tools.

    Streamlit doesn't have native routing so we use ``st.query_params``
    updates which trigger a rerun with the pre-loaded state.
    """
    cols = st.columns(2)
    with cols[0]:
        if st.button(
            "🔍 Open in Correlate Events",
            key=f"{key_prefix}_open_search",
            help="Jump to Investigate → Free-text Search with this "
                 "finding's time window pre-loaded.",
        ):
            _route_to_investigate_with_window(rel)
    with cols[1]:
        if st.button(
            "📜 Show ±5min log context",
            key=f"{key_prefix}_log_context",
            help="Inline expander with the surrounding log lines.",
        ):
            # Toggle a session-state flag; the actual rendering is done
            # by the parent workspace (Phase 55d wiring).
            st.session_state[f"show_context_{key_prefix}"] = True
    # Customer findings are never compared with or added to a retained case
    # library.  Only the current run's surrounding evidence is available.
    if st.session_state.get(f"show_context_{key_prefix}"):
        _render_inline_log_context(rel)


def _route_to_investigate_with_window(rel: FindingRelations) -> None:
    """Set query params + workspace to route the engineer into
    Investigate → Free-text Search with this finding's window."""
    link = rel.action_links.get("open_in_search") or ""
    if not link:
        st.warning(
            "No time-range on this finding — can't pre-populate the "
            "search window."
        )
        return
    # Parse the query-string convention we set in relations.py.
    from urllib.parse import parse_qs
    qs = link.lstrip("?")
    parsed = parse_qs(qs)
    st.query_params["ws"] = "Investigate"
    if "ts_from" in parsed:
        st.query_params["ts_from"] = parsed["ts_from"][0]
    if "ts_to" in parsed:
        st.query_params["ts_to"] = parsed["ts_to"][0]
    # Streamlit auto-reruns on query_param write. Also set the sidebar
    # picker's session state so the picker's index resolves correctly.
    st.session_state["zd_workspace"] = "Investigate"
    st.rerun()


def _render_inline_log_context(rel: FindingRelations) -> None:
    """Lightweight inline surrounding-log-lines view.

    Full-featured version is in Investigate → Correlate Events. This
    is just an in-place teaser to save a workspace hop for shallow
    reads.
    """
    st.markdown("---")
    st.markdown("**Surrounding log context (±5min)**")
    st.caption(
        "_Phase 55d placeholder — the deep view is one click away in "
        "Investigate → Correlate Events. Coming: inline top-N "
        "surrounding lines here._"
    )
