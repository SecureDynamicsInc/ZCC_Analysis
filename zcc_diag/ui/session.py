"""Session view — Slice 3 of the Log-Analyzer rebuild (2026-08-07).

Two modes, both fed from the LogIndex:

1. **Browse by tag** — the IDs Inventory panel lists every distinct
   identifier the parser recognised in the log bodies (tag_id,
   mtunnel_id, broker_session, conn_id, session_id, err_code,
   symbolic_code, app, broker, sme_host, ipv4, http_status).
   Pick a tag type, pick an ID from the counts table, jump into
   the reconstruction.

2. **Type an ID directly** — text input for power users who already
   know the identifier they want to trace. Auto-detects type or
   accepts an explicit override.

Both modes call `session_recon.reconstruct_session()` and render
the same phase-labeled timeline, file footprint, related-ID panel,
and per-row surrounding-context drilldown.

Zero interpretation. Everything shown is either directly matched to
the queried ID or extracted from the same lines with rigid regexes.
"""

from __future__ import annotations

from typing import List, Optional

import streamlit as st

from ..log_index import LogIndex, IndexedLine
from ..session_recon import (
    ReconLine,
    SessionRecon,
    group_lines_by_component,
    guess_id_type,
    reconstruct_session,
)
from ..id_inventory import IdInventory, build_inventory, group_by_component
from ._components import KV, fmt_duration, fmt_ts, inject_css, kv_grid


# --------------------------------------------------------------------------
# Cached inventory build — one pass across the LogIndex is enough
# --------------------------------------------------------------------------

_INV_SS_KEY = "_slice3_inventory"  # gitleaks:allow -- UI state identifier
_ID_SELECT_KEY = "_slice3_selected_id"
_ID_TYPE_SELECT_KEY = "_slice3_selected_type"


def _cached_inventory(cache_key: str, _idx: LogIndex) -> IdInventory:
    """Streamlit-cached inventory. cache_key is the same one used by the
    top-level bundle-load cache, so a new bundle rebuilds the inventory.

    `_idx` is underscore-prefixed to opt out of Streamlit's argument
    hashing — hashing a LogIndex means walking millions of IndexedLine
    objects on every rerun, which costs more than the cached work.
    """
    return build_inventory(_idx)


# --------------------------------------------------------------------------
# Public entry
# --------------------------------------------------------------------------

def render_session(idx: LogIndex, cache_key: str,
                   inv: Optional[IdInventory] = None) -> None:
    """Top-level Session view. `cache_key` shares the bundle's cache key
    so the inventory can be memoized alongside the LogIndex.

    `inv` — pass a pre-built IdInventory (e.g. shared with the Facts tab)
    to skip rebuilding it here. If omitted, builds and caches its own.
    """
    inject_css()
    st.subheader("Session reconstruction")

    if inv is None:
        with st.spinner("Building ID inventory (one-time per bundle)..."):
            inv = _cached_inventory(cache_key, idx)

    mode = st.radio(
        "Choose ID source",
        options=["Browse by tag", "Browse by module", "Type an ID"],
        horizontal=True,
        key="_slice3_mode",
        help=(
            "Browse by tag: every distinct value of one identifier type "
            "(tag_id, zia_cloud, zpa_cloud, dc, username, ...), from "
            "anywhere in the bundle. Browse by module: pick a log module "
            "first (tunnel/service/tray/upm), then see what THAT module "
            "told you."
        ),
    )

    if mode == "Browse by tag":
        _render_browser(inv)
    elif mode == "Browse by module":
        _render_module_browser(inv)
    else:
        _render_manual_entry()

    selected_id = st.session_state.get(_ID_SELECT_KEY)
    selected_type = st.session_state.get(_ID_TYPE_SELECT_KEY)

    if not selected_id:
        st.caption("Pick an ID above to see its reconstructed lifecycle.")
        return

    st.markdown("---")
    with st.spinner(f"Reconstructing `{selected_id}` ..."):
        recon = reconstruct_session(idx, selected_id, id_type=selected_type)
    _render_recon(idx, recon)


# --------------------------------------------------------------------------
# Browser panel
# --------------------------------------------------------------------------

def _render_browser(inv: IdInventory) -> None:
    tag_types = inv.tag_types()
    if not tag_types:
        st.warning("No identifiers were extracted from this bundle.")
        return

    counts = inv.total_by_type()
    labels = [f"{t}  ({counts[t]:,})" for t in tag_types]

    c1, c2 = st.columns([1, 3])
    with c1:
        chosen_label = st.selectbox(
            "Tag type",
            options=labels,
            index=0,
            key="_slice3_tag_type_select",
        )
        tag_type = tag_types[labels.index(chosen_label)]
        sort = st.selectbox(
            "Sort by",
            options=["count", "value", "first_ts", "last_ts"],
            index=0,
            key="_slice3_sort",  # gitleaks:allow -- Streamlit widget identifier
        )
        row_limit = st.slider(
            "Max rows shown",
            10, 5000, 200, step=10,
            key="_slice3_browse_row_limit",  # gitleaks:allow -- widget identifier
        )

    with c2:
        stats = inv.values_for(tag_type, sort=sort)
        total = len(stats)
        stats = stats[:row_limit]

        st.caption(
            f"**{tag_type}** — {total:,} distinct values, "
            f"showing {len(stats):,}"
        )
        rows = []
        for s in stats:
            first = s.first_ts.strftime("%Y-%m-%d %H:%M:%S") if s.first_ts else "-"
            last = s.last_ts.strftime("%Y-%m-%d %H:%M:%S") if s.last_ts else "-"
            rows.append({
                "value": s.value,
                "count": s.count,
                "first (UTC)": first,
                "last (UTC)": last,
                "files": len(s.files),
                "components": ", ".join(sorted(s.components)) or "-",
            })
        st.dataframe(rows, hide_index=True, use_container_width=True)

        # Explicit picker for the value the user wants to reconstruct.
        # Streamlit's dataframe doesn't yield click events, so we use a
        # separate selectbox with the same values.
        if stats:
            picker_labels = [f"{s.value}   ({s.count:,})" for s in stats]
            chosen = st.selectbox(
                "Reconstruct this ID",
                options=picker_labels,
                index=0,
                key="_slice3_value_select",
            )
            picked_value = stats[picker_labels.index(chosen)].value
            if st.button("Reconstruct", type="primary", key="_slice3_go_browse"):
                st.session_state[_ID_SELECT_KEY] = picked_value
                # Force id_type to match the browser's tag type.
                # `broker_session` and `data_channel` map to broker_session
                # semantics in session_recon; anything else uses the raw name.
                st.session_state[_ID_TYPE_SELECT_KEY] = _tag_type_to_recon_type(
                    tag_type
                )


def _render_module_browser(inv: IdInventory) -> None:
    """Browse identifiers grouped by MODULE (tunnel/service/tray/upm)
    first, then tag type. Cloud name / username / org id / device
    hostname show up almost exclusively in tray logs; DC / broker /
    mtunnel IDs show up almost exclusively in tunnel logs — browsing
    module-first surfaces that separation instead of mixing everything
    under one tag-type list.
    """
    by_module = group_by_component(inv)
    modules = sorted(by_module.keys())
    if not modules:
        st.warning("No identifiers were extracted from this bundle.")
        return

    c1, c2 = st.columns([1, 3])
    with c1:
        mod_labels = [
            f"{m}  ({sum(len(v) for v in by_module[m].values()):,} values)"
            for m in modules
        ]
        chosen_mod_label = st.selectbox(
            "Module", options=mod_labels, index=0,
            key="_slice3b_module_select",
        )
        module = modules[mod_labels.index(chosen_mod_label)]

        tag_types = sorted(by_module[module].keys())
        counts = {t: len(by_module[module][t]) for t in tag_types}
        tag_labels = [f"{t}  ({counts[t]:,})" for t in tag_types]
        chosen_tag_label = st.selectbox(
            "Tag type (in this module)",
            options=tag_labels, index=0,
            key="_slice3b_module_tag_select",  # gitleaks:allow -- widget identifier
        )
        tag_type = tag_types[tag_labels.index(chosen_tag_label)]
        row_limit = st.slider(
            "Max rows shown", 10, 5000, 200, step=10,
            key="_slice3b_row_limit",  # gitleaks:allow -- widget identifier
        )

    with c2:
        all_stats = by_module[module][tag_type]
        stats = all_stats[:row_limit]
        st.caption(
            f"**{module} → {tag_type}** — "
            f"{len(all_stats):,} distinct values, showing {len(stats):,}"
        )
        rows = []
        for s in stats:
            first = s.first_ts.strftime("%Y-%m-%d %H:%M:%S") if s.first_ts else "-"
            last = s.last_ts.strftime("%Y-%m-%d %H:%M:%S") if s.last_ts else "-"
            other_modules = sorted(c for c in s.components if c != module)
            rows.append({
                "value": s.value,
                "count": s.count,
                "first (UTC)": first,
                "last (UTC)": last,
                "also seen in": ", ".join(other_modules) or "-",
            })
        st.dataframe(rows, hide_index=True, use_container_width=True)

        if stats:
            picker_labels = [f"{s.value}   ({s.count:,})" for s in stats]
            chosen = st.selectbox(
                "Reconstruct this ID",
                options=picker_labels, index=0,
                key="_slice3b_value_select",
            )
            picked_value = stats[picker_labels.index(chosen)].value
            if st.button("Reconstruct", type="primary", key="_slice3b_go"):
                st.session_state[_ID_SELECT_KEY] = picked_value
                st.session_state[_ID_TYPE_SELECT_KEY] = _tag_type_to_recon_type(
                    tag_type
                )


def _tag_type_to_recon_type(tag_type: str) -> Optional[str]:
    """Map an id_inventory tag type to a session_recon id_type."""
    if tag_type in ("tag_id", "conn_id", "session_id",
                     "mtunnel_id", "broker_session"):
        return tag_type
    if tag_type == "data_channel":
        return "broker_session"  # semantically similar: substring on body
    # For err_code / symbolic_code / app / broker / sme_host / ipv4 /
    # http_status we can't offer a lifecycle in the same sense, but the
    # substring match will surface every line where the value appears,
    # which is exactly what "reconstruct" means for these.
    return "free"


# --------------------------------------------------------------------------
# Manual-entry panel
# --------------------------------------------------------------------------

def _render_manual_entry() -> None:
    c1, c2, c3 = st.columns([3, 1, 1])
    with c1:
        typed = st.text_input(
            "ID",
            key="_slice3_manual_id",
            placeholder="e.g. 65660  or  z5FN...  or  z5FN...,DATA...  "
                        "or  aabbccdd-1122-3344-5566-778899aabbcc",
        )
    with c2:
        force = st.selectbox(
            "Force type",
            options=["auto", "tag_id", "session_id", "mtunnel_id",
                     "broker_session", "conn_id", "free"],
            index=0,
            key="_slice3_manual_force",
        )
    with c3:
        st.write("")
        st.write("")
        if st.button("Reconstruct", type="primary", key="_slice3_go_manual"):
            if not typed.strip():
                st.error("Please enter an ID.")
            else:
                st.session_state[_ID_SELECT_KEY] = typed.strip()
                st.session_state[_ID_TYPE_SELECT_KEY] = (
                    None if force == "auto" else force
                )

    if typed and force == "auto":
        detected = guess_id_type(typed.strip())
        st.caption(f"Auto-detected type: `{detected}`")


# --------------------------------------------------------------------------
# Reconstruction render
# --------------------------------------------------------------------------

def _render_recon(idx: LogIndex, recon: SessionRecon) -> None:
    st.markdown(
        f"### Reconstruction of `{recon.query_id}`  "
        f"({recon.id_type})"
    )

    if recon.line_count == 0:
        st.warning("No lines matched this ID.")
        return

    # ---- Header ----------------------------------------------------
    # kv_grid rather than st.metric: a 19-character timestamp overflows
    # a quarter-width metric tile at metric's oversized value font.
    kv_grid([
        KV("Lines", f"{recon.line_count:,}"),
        KV("First (UTC)", fmt_ts(recon.first_ts)),
        KV("Last (UTC)", fmt_ts(recon.last_ts)),
        KV("Duration", fmt_duration(recon.duration_seconds)),
    ], columns=4)

    # ---- Phase histogram + file/component breakdown ----------------
    c_left, c_right = st.columns(2)
    with c_left:
        st.caption("**Phase histogram**")
        rows = sorted(
            recon.phase_histogram.items(),
            key=lambda kv: -kv[1],
        )
        st.dataframe(
            [{"phase": k, "lines": v} for k, v in rows],
            hide_index=True, use_container_width=True,
        )
    with c_right:
        st.caption("**Files touched**")
        rows = sorted(recon.files_touched.items(), key=lambda kv: -kv[1])
        st.dataframe(
            [{"source_file": k, "lines": v} for k, v in rows],
            hide_index=True, use_container_width=True,
        )

    # ---- Related IDs -----------------------------------------------
    if recon.related_id_summary:
        with st.expander(
            f"Related identifiers seen on these lines "
            f"({sum(len(v) for v in recon.related_id_summary.values())} distinct)",
            expanded=False,
        ):
            rows = []
            for tag_type, vals in sorted(recon.related_id_summary.items()):
                rows.append({"type": tag_type, "values": ", ".join(vals)})
            st.dataframe(rows, hide_index=True, use_container_width=True)

    # ---- Timeline table --------------------------------------------
    st.subheader("Timeline")
    group_mode = st.radio(
        "Group lines by",
        options=["Time (chronological)", "Component (module)"],
        horizontal=True,
        key="_slice3_group_mode",
        help=(
            "Component groups every line by which log module wrote it "
            "(tunnel/service/tray/upm), keeping chronological order "
            "within each group — useful when interleaved-by-time makes "
            "one process's own narrative hard to follow."
        ),
    )
    # A reconstruction can legitimately be tiny — an Example Tenant A tag_id that
    # dies at BRK_MT_SETUP_FAIL_NO_POLICY_FOUND has ~4 lines. A slider
    # hardcoded to min_value=10 raises StreamlitAPIException whenever
    # max_value falls below it, so only offer the slider when there's a
    # range to pick from.
    limit = _row_limit_control(
        recon.line_count,
        label="Rows to show (per group when grouping by component)",
        key="_slice3_row_limit",
    )

    if group_mode == "Time (chronological)":
        st.dataframe(
            _lines_to_rows(recon.lines[:limit]),
            hide_index=True, use_container_width=True,
        )
    else:
        grouped = group_lines_by_component(recon)
        ordered_comps = sorted(grouped, key=lambda c: -len(grouped[c]))
        st.caption(
            f"{len(grouped)} component(s): "
            + ", ".join(f"{c} ({len(v):,})" for c, v in
                        sorted(grouped.items(), key=lambda kv: -len(kv[1])))
        )
        for i, comp in enumerate(ordered_comps):
            comp_lines = grouped[comp][:limit]
            with st.expander(
                f"{comp}  ({len(grouped[comp]):,} lines, "
                f"showing {len(comp_lines):,})",
                expanded=(i == 0),
            ):
                st.dataframe(
                    _lines_to_rows(comp_lines),
                    hide_index=True, use_container_width=True,
                )

    # ---- Row drilldown ----------------------------------------------
    if recon.line_count > 0:
        st.subheader("Row drilldown")
        st.caption(
            "Row # always refers to the full chronological timeline "
            "(1 = earliest line), regardless of the grouping chosen above."
        )
        drill_ix = st.number_input(
            "Show surrounding context for row #",
            min_value=1,
            max_value=min(limit, recon.line_count),
            value=1,
            step=1,
            key="_slice3_drill_ix",
        )
        radius = st.slider(
            "Context radius (lines before/after)", 1, 30, 5,
            key="_slice3_drill_radius",
        )
        row = recon.lines[int(drill_ix) - 1]
        ctx = idx.surrounding_lines(row.source_file, row.line_no, radius=radius)
        _render_context(row, ctx)


def _render_context(row: ReconLine, ctx: List[IndexedLine]) -> None:
    st.caption(
        f"Context around **{row.source_file}:{row.line_no}** "
        f"({row.component} - {row.level} - {row.phase}) — "
        f"{row.ts.strftime('%Y-%m-%d %H:%M:%S UTC') if row.ts else '-'}"
    )
    rows = []
    for ln in ctx:
        marker = "->" if ln.line_no == row.line_no else " "
        rows.append({
            "": marker,
            "ts": ln.ts.strftime("%H:%M:%S.%f")[:-3] if ln.ts else "-",
            "line_no": ln.line_no,
            "level": ln.level or "",
            "body": (ln.body or "")[:400],
        })
    st.dataframe(rows, hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _row_limit_control(available: int, label: str, key: str,
                       default: int = 500, cap: int = 5000) -> int:
    """A row-count slider that degrades safely when there's nothing to
    slide over.

    `st.slider` raises if `min_value > max_value` or if `value` falls
    outside the range, and both happen naturally here: a session with 3
    matching lines can't offer a 10..N range. Below the step size we
    just return the count and render a caption instead of a control.
    """
    if available <= 10:
        st.caption(f"Showing all {available:,} row(s).")
        return max(1, available)
    upper = min(cap, available)
    return int(st.slider(
        label,
        min_value=10,
        max_value=upper,
        value=min(default, upper),
        step=10,
        key=key,
    ))


def _lines_to_rows(lines: List[ReconLine]) -> List[dict]:
    """Shared row-shape builder for the Timeline table, used by both the
    chronological and component-grouped render paths so they stay
    visually identical."""
    rows = []
    for i, ln in enumerate(lines):
        rows.append({
            "#": i + 1,
            "ts (UTC)": ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-",
            "phase": ln.phase,
            "level": ln.level or "",
            "component": ln.component or "",
            "source": f"{ln.source_file}:{ln.line_no}",
            "body": (ln.body or "")[:400],
        })
    return rows


# Duration/timestamp formatting now comes from ._components so every
# tab renders them identically (there used to be three separate copies).
