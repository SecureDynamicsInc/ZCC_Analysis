"""Raw log viewer — Slice 7 of the Log-Analyzer rebuild (2026-08-07).

File-by-file browser over the parsed LogIndex. Pick a source file,
paginate through it with N lines per page, jump to a line number,
filter with substring or regex, and see well-known tokens inline-
highlighted (err_code / symbolic codes / timestamps / levels /
broker hosts / IPv4).

Zero interpretation. Every rendered line came directly from the
LogIndex; the only transform is HTML-escaping + regex-driven
`<span class="hl-...">` wrapping around documented tokens.
"""

from __future__ import annotations

import html
import re
from typing import List

import streamlit as st

from ..log_index import LogIndex
from ..raw_view import (
    DEFAULT_CSS,
    SEVERITY_CRITICAL,
    SEVERITY_MEDIUM,
    find_line_index,
    get_file_lines,
    list_source_files,
    content_columns,
    level_html,
    paginate,
    severity_counts,
    to_raw_lines,
)


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------

def render_raw(idx: LogIndex) -> None:
    st.subheader("Raw log viewer")

    files = list_source_files(idx)
    if not files:
        st.warning("No parsed lines in this bundle.")
        return

    # Inject the highlight CSS once. Streamlit deduplicates identical
    # blocks by content.
    st.markdown(DEFAULT_CSS, unsafe_allow_html=True)

    # ---- File picker + filter row ---------------------------------
    c1, c2, c3 = st.columns([3, 3, 2])
    with c1:
        labels = [f"{name}  ({count:,} lines)" for name, count in files]
        chosen_label = st.selectbox(
            "Source file",
            options=labels,
            index=0,
            key="_slice7_file",
        )
        chosen_file = files[labels.index(chosen_label)][0]
    with c2:
        query = st.text_input(
            "Filter (substring)",
            key="_slice7_substring",
            placeholder="e.g. SAML_EXPIRED",
        )
    with c3:
        # 25k/50k exist because reading a log means scrolling it, not clicking
        # through it. The whole page is rendered as one HTML block, so the cost
        # is linear and a 50k page stays responsive; severity classification
        # over 50k lines measures 0.2 s.
        page_size = st.selectbox(
            "Page size",
            options=[100, 200, 500, 1000, 5000, 10000, 25000, 50000],
            index=4,
            key="_slice7_page_size",
        )

    # ---- Fetch lines ---------------------------------------------
    file_lines = get_file_lines(
        idx, chosen_file,
        substring=query.strip() if query.strip() else None,
    )
    if not file_lines:
        st.info(
            f"No lines in `{chosen_file}` matching filter `{query}`."
            if query else f"No lines in `{chosen_file}`."
        )
        return

    total_lines = len(file_lines)

    # ---- Page + jump controls ------------------------------------
    c4, c5, c6 = st.columns([2, 2, 2])
    with c4:
        # Compute total pages here for the input's max
        _, _, total_pages = paginate(file_lines, 1, page_size)
        # The page widget's key must vary with (file, filter, page size)
        # — otherwise session_state keeps a stale page number when you
        # switch to a smaller file or tighten the filter, and Streamlit
        # raises "The value 40 is greater than the max_value 2". Folding
        # the current bounds into the key gives each distinct view its
        # own page counter starting at 1.
        page_key = (
            f"_slice7_page::{chosen_file}::{page_size}::{total_pages}"
        )
        page = st.number_input(
            f"Page (of {total_pages:,})",
            min_value=1, max_value=int(total_pages),
            value=1, step=1,
            key=page_key,
        )
    with c5:
        jump_ln = st.number_input(
            "Jump to line number",
            min_value=0, value=0, step=1,
            key="_slice7_jump",
            help="Enter the parsed-log line number to jump to. 0 disables.",
        )
    with c6:
        highlight_current = st.checkbox(
            "Highlight current line",
            value=True,
            key="_slice7_hl_current",
        )

    # ---- Severity + display controls -----------------------------
    c7, c8, c9 = st.columns([3, 2, 2])
    with c7:
        severity_filter = st.segmented_control(
            "Show",
            ["All records", "Critical + medium", "Critical only"],
            default="All records",
            key="_slice7_sev_filter",
            help="Severity comes from the documented error catalog and the record's own level.",
        ) or "All records"
    with c8:
        wrap_lines = st.checkbox(
            "Wrap long lines", value=False, key="_slice7_wrap",
            help="Off keeps one record per line and scrolls sideways, as an editor does.",
        )
    with c9:
        show_timestamp = st.checkbox(
            "Show timestamp column", value=True, key="_slice7_show_ts",
        )

    # If jump requested, override page.
    if jump_ln > 0:
        idx_in_list = find_line_index(file_lines, int(jump_ln))
        if idx_in_list is not None:
            page = (idx_in_list // page_size) + 1
        else:
            st.warning(f"Line {jump_ln} not found in `{chosen_file}` "
                       f"(after filters).")

    slice_lines, current_page, total_pages = paginate(
        file_lines, int(page), int(page_size),
    )
    raws = to_raw_lines(slice_lines)

    # Severity is classified on the page, so the filter applies to what is
    # rendered rather than re-querying the store.
    counts = severity_counts(raws)
    if severity_filter == "Critical only":
        raws = [line for line in raws if line.severity == SEVERITY_CRITICAL]
    elif severity_filter == "Critical + medium":
        raws = [line for line in raws if line.severity]

    # ---- Header banner ------------------------------------------
    st.caption(
        f"File: **{chosen_file}**  |  "
        f"Matches: **{total_lines:,}** lines  |  "
        f"Page: **{current_page}** / {total_pages:,}  |  "
        f"Showing lines {slice_lines[0].line_no if slice_lines else 0} "
        f"– {slice_lines[-1].line_no if slice_lines else 0}"
    )
    st.markdown(
        '<div class="la-raw-legend">'
        f'<span><i class="k-critical"></i>{counts.get(SEVERITY_CRITICAL, 0):,} critical</span>'
        f'<span><i class="k-medium"></i>{counts.get(SEVERITY_MEDIUM, 0):,} medium</span>'
        f'<span><i class="k-other"></i>{counts.get("other", 0):,} other</span>'
        '<span>on this page · from the documented catalog and the record level</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not raws:
        st.success(
            "No critical or medium records on this page. Widen **Show**, or move to "
            "another page."
        )
        return

    # ---- Rendered lines ------------------------------------------
    _render_lines_html(
        raws, jump_ln if highlight_current else 0,
        query=query.strip(), wrap=wrap_lines, show_timestamp=show_timestamp,
    )

    # ---- Download button ----------------------------------------
    with st.expander("Export", expanded=False):
        # Building the export used to run the full highlighter over
        # every line in the file on EVERY rerun, just to have `data=`
        # ready for a button nobody had clicked — on a 200k-line
        # rotation that dominated each keystroke. Gate it behind an
        # explicit checkbox, and format from the raw IndexedLines
        # directly so the export path never touches `highlight_tokens`
        # (it produces HTML, which a .txt export doesn't want anyway).
        st.caption(
            f"{total_lines:,} line(s) in the current view "
            f"(file + filter, all pages)."
        )
        st.caption(
            "Export is disabled. Customer-derived views exist only for this run."
        )


def _mark_matches(highlighted: str, query: str) -> str:
    """Wrap filter hits in the already-highlighted HTML.

    Only text outside a tag is considered, so a query that happens to collide
    with a class name (``ts``, ``level``, ``hl``) cannot corrupt the markup.
    """
    if not query:
        return highlighted
    lowered_query = query.lower()
    out: List[str] = []
    for chunk in re.split(r"(<[^>]*>)", highlighted):
        if chunk.startswith("<") or not chunk:
            out.append(chunk)
            continue
        cursor = 0
        lowered = chunk.lower()
        while True:
            found = lowered.find(lowered_query, cursor)
            if found < 0:
                out.append(chunk[cursor:])
                break
            out.append(chunk[cursor:found])
            out.append(
                f'<span class="match">{chunk[found:found + len(query)]}</span>'
            )
            cursor = found + len(query)
    return "".join(out)


def _render_lines_html(
    raws, current_ln: int, *, query: str = "",
    wrap: bool = False, show_timestamp: bool = True,
) -> None:
    """Render the raw lines as a single HTML block. Faster than one
    st.markdown per line, and lets the highlight CSS style them
    consistently."""
    wrap_cls = " la-raw-wrap" if wrap else ""
    # The app tracks its theme in this one session flag; `inject_css` reads the
    # same thing, so the viewer can never disagree with the rest of the page.
    light_cls = " la-raw-light" if st.session_state.get("light_mode") else ""
    columns = content_columns(raws)
    parts = [
        f'<div class="la-raw{wrap_cls}{light_cls}" style="--la-cols: {columns}"><pre>'
    ]
    for r in raws:
        classes = ["row"]
        if r.severity:
            classes.append(f"sev-{r.severity}")
        if current_ln and r.line_no == current_ln:
            classes.append("current")
        title = f' title="{html.escape(r.severity_why)}"' if r.severity_why else ""
        stamp = f"{r.ts_iso}  " if show_timestamp else ""
        parts.append(
            f'<span class="{" ".join(classes)}"{title}>'
            f'<span class="ln">{r.line_no}</span>'
            f'{stamp}{level_html(r.level)}  {_mark_matches(r.highlighted, query)}</span>\n'
        )
    parts.append("</pre></div>")
    st.markdown("".join(parts), unsafe_allow_html=True)
