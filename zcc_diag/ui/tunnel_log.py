"""Raw ZSATunnel log view — the whole current tunnel log, in one window.

Its own tab, in both Novice and Pro. The paged raw viewer answers "show me the
matching records"; this answers "what happened around them". Nothing is filtered
out by default, because the records above and below a failure are usually what
explain it.

Rendering a whole log in one block is only viable because of two choices:
every row is one element with ``content-visibility: auto``, so the browser skips
layout and paint for offscreen rows, and the window scrolls internally at a
fixed height instead of growing the page to the length of the log.
"""

from __future__ import annotations

import html
from typing import Any, List

import streamlit as st

from zcc_diag.raw_view import (
    DEFAULT_CSS,
    LEVEL_SCOPE_ALL,
    LEVEL_SCOPES,
    SEVERITY_CRITICAL,
    SEVERITY_MEDIUM,
    content_columns,
    filter_by_level,
    level_html,
    severity_counts,
    to_raw_lines,
)
from zcc_diag.synthetic_ip import DOC_URL, notes_in, range_summary
from zcc_diag.tunnel_log import (
    MAX_RENDERED_RECORDS,
    critical_anchors,
    load_tunnel_records,
    select_current_tunnel_log,
)

_VIEW_CSS = """
<style>
/* One scroll window, fixed height, so the page does not grow to the length of
 * the log. `content-visibility: auto` is what makes a full log affordable:
 * offscreen rows are skipped for layout and paint, and the intrinsic-size hint
 * keeps the scrollbar honest while they are skipped. */
/* No `scroll-behavior: smooth` here on purpose. A full tunnel log gives this
 * container a scroll height in the millions of pixels, and an animated jump
 * across that distance reads as a frozen page — measured at 80,000 records,
 * where the window is ~3,000,000px tall. Anchor jumps have to be instant. */
.la-tunnel-window {
    max-height: 78vh; overflow: auto;
    border-radius: 10px;
}
.la-tunnel-window .row {
    content-visibility: auto;
    /* Longhands, not `contain-intrinsic-size: auto 19px`: the shorthand's single
     * length applies to BOTH axes, so every skipped row claimed 19px of width
     * and the scroller never learned the real line length — horizontal
     * scrolling stopped a few pixels in. Width comes from the measured column
     * count; height keeps the remembered-size behaviour. */
    contain-intrinsic-width: calc(var(--la-cols, 220) * 1ch);
    contain-intrinsic-height: auto 19px;
    scroll-margin-top: 42vh;   /* a jumped-to record lands mid-window, in context */
}
/* Wrapping means no horizontal axis, so the explicit width must not apply. */
.la-tunnel-window.la-raw-wrap [data-testid="stMarkdownPre"],
.la-tunnel-window.la-raw-wrap pre { width: 100%; }
.la-tunnel-window.la-raw-wrap .row { contain-intrinsic-width: auto 100%; }
.la-tunnel-jump {
    max-height: 190px; overflow: auto; margin: 0 0 8px;
    border: 1px solid rgba(148, 163, 184, .16); border-radius: 8px; padding: 6px 4px;
}
.la-tunnel-jump a {
    display: block; padding: 2px 8px; font-size: 11.5px; text-decoration: none;
    color: #F0A0A0 !important;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.la-tunnel-jump a:hover { background: rgba(239, 68, 68, .12); }
.la-raw-light .la-tunnel-jump a, .la-tunnel-jump.la-light a { color: #A8323C !important; }
</style>
"""


def _render_window(rows: List[Any], *, wrap: bool, light: bool) -> None:
    wrap_cls = " la-raw-wrap" if wrap else ""
    light_cls = " la-raw-light" if light else ""
    # --la-cols drives both the block's width and each skipped row's intrinsic
    # width, which is what makes horizontal scrolling reach the long lines.
    columns = content_columns(rows)
    parts = [
        f'<div class="la-raw la-tunnel-window{wrap_cls}{light_cls}" '
        f'style="--la-cols: {columns}"><pre>'
    ]
    for row in rows:
        classes = ["row"]
        if row.severity:
            classes.append(f"sev-{row.severity}")
        title = f' title="{html.escape(row.severity_why)}"' if row.severity_why else ""
        anchor = f' id="zt-{row.line_no}"' if row.severity == SEVERITY_CRITICAL else ""
        parts.append(
            f'<span class="{" ".join(classes)}"{anchor}{title}>'
            f'<span class="ln">{row.line_no}</span>'
            f'{row.ts_iso}  {level_html(row.level)}  {row.highlighted}</span>\n'
        )
    parts.append("</pre></div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def _prepared_rows(cache_key: str, source_file: str, _idx: Any):
    """Load and classify the log once per bundle.

    Severity classification is cheap per line but not free over a whole log, and
    every tab body executes on every rerun, so without this the log would be
    re-read and re-classified each time any widget on the page moved. ``_idx``
    is underscore-prefixed to opt out of hashing — ``cache_key`` already
    identifies the bundle, and hashing the store would cost more than the work.
    """
    records, dropped = load_tunnel_records(_idx, source_file)
    return to_raw_lines(records), dropped


def render_tunnel_log_view(
    idx: Any, *, pro_mode: bool = True, cache_key: str = "",
) -> None:
    """The current ZSATunnel.log in full, coloured by severity."""
    choice = select_current_tunnel_log(idx)
    if choice is None:
        st.markdown("## Raw ZSATunnel log")
        st.info(
            "No tunnel log was found in this bundle, so there is nothing to show "
            "here. `ZSATunnel.log` is the log that records tunnel status, the data "
            "centers the client connected to, and policy downloads — collect it "
            "with the support bundle, or on its own for the fastest check."
        )
        return

    _render_body(idx, choice, pro_mode=pro_mode, cache_key=cache_key)


def _render_body(idx: Any, choice, *, pro_mode: bool, cache_key: str) -> None:
    """Run the view inside a fragment where the runtime supports one.

    Every tab body executes on every rerun, and this one emits megabytes of
    markup for a full log. A fragment scopes reruns to this view, so toggling
    wrap here — or moving a control on another tab — does not rebuild it.
    """
    fragment = getattr(st, "fragment", None)
    if callable(fragment):
        fragment(lambda: _body(idx, choice, pro_mode=pro_mode, cache_key=cache_key))()
    else:  # pragma: no cover - older Streamlit
        _body(idx, choice, pro_mode=pro_mode, cache_key=cache_key)


def _body(idx: Any, choice, *, pro_mode: bool, cache_key: str) -> None:
    st.markdown("## Raw ZSATunnel log")
    st.caption(
        "The whole current tunnel log, in order, with nothing filtered out. The "
        "records either side of a failure are usually what explain it."
        if pro_mode else
        "The whole connection log, in order. Red rows are errors that matter; "
        "orange rows are warnings. The lines around a red row usually explain it."
    )

    with st.spinner("Reading the tunnel log…"):
        rows, dropped = _prepared_rows(cache_key, choice.source_file, idx)
    counts = severity_counts(rows)

    st.caption(
        f"**{html.escape(choice.source_file)}** · {choice.records:,} records · "
        f"{choice.span_label} · {choice.reason}."
    )

    metrics = st.columns(4)
    metrics[0].metric("Critical", f"{counts.get(SEVERITY_CRITICAL, 0):,}")
    metrics[1].metric("Medium", f"{counts.get(SEVERITY_MEDIUM, 0):,}")
    metrics[2].metric("Other", f"{counts.get('other', 0):,}")
    metrics[3].metric("Records shown", f"{len(rows):,}")

    if dropped:
        st.warning(
            f"This log holds {choice.records:,} records, more than the "
            f"{MAX_RENDERED_RECORDS:,} one window can carry. The **most recent** "
            f"{len(rows):,} are shown and the oldest {dropped:,} are not. Use "
            "**Deep evidence → Raw** to page through the whole file."
        )

    controls = st.columns([2, 2, 3])
    with controls[0]:
        wrap = st.checkbox(
            "Wrap long lines", value=False, key="_tunnel_wrap",
            help="Off keeps one record per line and scrolls sideways.",
        )
    with controls[1]:
        level_scope = st.segmented_control(
            "Show levels",
            LEVEL_SCOPES,
            default=LEVEL_SCOPE_ALL,
            key="_tunnel_level_scope",
            help="Filters by the level the client logged. Line numbers stay the "
                 "record's own, so a filtered view still tells you where you are. "
                 "All records is the default: the lines around a failure are "
                 "usually what explain it.",
        ) or LEVEL_SCOPE_ALL
    with controls[2]:
        st.markdown(
            '<div class="la-raw-legend">'
            '<span><i class="k-critical"></i>critical</span>'
            '<span><i class="k-medium"></i>medium</span>'
            '<span>from the documented catalog and the record level</span>'
            '</div>',
            unsafe_allow_html=True,
        )

    anchors = critical_anchors(rows)
    if anchors:
        with st.expander(
            f"Jump to a critical record ({counts.get(SEVERITY_CRITICAL, 0):,} in this log)",
            expanded=False,
        ):
            st.caption(
                "Each link scrolls the window to that record with the surrounding "
                "log still around it, rather than filtering the log down to it."
            )
            links = "".join(
                f'<a href="#zt-{line_no}">{line_no:>7}  {html.escape(label)}</a>'
                for line_no, label, _sev in anchors
            )
            st.markdown(f'<div class="la-tunnel-jump">{links}</div>', unsafe_allow_html=True)
            if counts.get(SEVERITY_CRITICAL, 0) > len(anchors):
                st.caption(
                    f"First {len(anchors)} shown of "
                    f"{counts.get(SEVERITY_CRITICAL, 0):,} critical records."
                )

    # Synthetic addresses present in this log, explained once here as well as on
    # each occurrence, because "why can't I reach 100.64.0.6" is a question that
    # sends people to the network team when the answer is local.
    synthetic = {}
    for row in rows[:20000]:
        synthetic.update(notes_in(row.body))
    if synthetic:
        with st.expander(
            f"About the 100.64.x.x addresses in this log ({len(synthetic)} seen)",
            expanded=False,
        ):
            st.markdown(range_summary())
            st.caption(
                "Each occurrence in the log is underlined; hover it for the note. "
                "Roles marked observed come from the bundles this analyzer was "
                "measured on, not from Zscaler documentation."
            )
            st.dataframe(
                [
                    {
                        "Address": note.address,
                        "What it is": note.headline,
                        "Basis": note.basis,
                        "Detail": note.detail,
                    }
                    for note in sorted(synthetic.values(), key=lambda n: n.address)
                ],
                hide_index=True,
                use_container_width=True,
                column_config={"Detail": st.column_config.TextColumn(width="large")},
            )
            st.caption(f"Reference: {DOC_URL}")

    visible = filter_by_level(rows, level_scope)
    if not visible:
        st.success(
            f"No records at {level_scope} in this log. Switch back to "
            f"**{LEVEL_SCOPE_ALL}** to read it in full."
        )
        return
    if level_scope != LEVEL_SCOPE_ALL:
        st.caption(
            f"Showing {len(visible):,} of {len(rows):,} records · {level_scope} · "
            "line numbers are the record's own position in the file."
        )

    _render_window(
        visible, wrap=wrap, light=bool(st.session_state.get("light_mode")),
    )
    st.caption(
        "Scroll the window to read the log in order. Severity marks a single "
        "record: a red row is not automatically the cause. **What we found** is "
        "where the evidence is weighed."
    )

    st.caption(
        "This log is displayed only in the current run. Export is disabled to "
        "prevent customer evidence from being copied into a project folder."
    )


def inject_tunnel_css() -> None:
    """Emit the raw-view stylesheet plus the window rules."""
    st.markdown(DEFAULT_CSS + _VIEW_CSS, unsafe_allow_html=True)
