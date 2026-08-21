"""Search view — Slice 2 of the Log-Analyzer rebuild (2026-08-07).

Query input + result table + one-click surrounding context. Zero
interpretation — everything shown is a matched IndexedLine or its
surrounding lines from the same source file.

The query language is documented in `zcc_diag/query.py`. This view
just plumbs the string into `find_matches()` and renders results.

Replaces the pre-Slice-0 findings-driven "Search" module (was two-mode
free-text-plus-session-correlation). That module is archived; this
one is the pure log analyzer's search surface.
"""

from __future__ import annotations

from typing import List, Optional

import streamlit as st

from ..log_index import LogIndex, IndexedLine
from ..query import (
    QueryError,
    find_matches,
    known_events,
)


# --------------------------------------------------------------------------
# Query cache — repeatedly evaluating the same query on the same index
# during a Streamlit rerun is wasteful, so we memoize in session_state.
#
# The cached payload carries the `cache_key` of the bundle it was run
# against. Without that, uploading a second bundle left the previous
# bundle's IndexedLine objects sitting in session_state and rendering
# against the NEW index — so the row/context drill-down silently
# returned lines from the wrong bundle. Results whose key doesn't match
# the current bundle are discarded rather than displayed.
# --------------------------------------------------------------------------

_CACHE_KEY = "_slice2_query_result"


def _run_query(idx: LogIndex, query: str, limit: int) -> List[IndexedLine]:
    """Execute the query with the given limit. Cheap for small limits; the
    caller decides when to bump this."""
    return list(find_matches(idx, query, limit=limit))


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------

def render_search(idx: LogIndex, cache_key: str = "") -> None:
    """Top-level Search view."""
    st.subheader("Search")
    _render_help_expander()

    query = st.text_input(
        "Query",
        key="slice2_query_input",
        placeholder=(
            "e.g. event:saml_expired AND time:2026-07-07T18:00..2026-07-07T19:00"
        ),
    )

    c1, c2, _ = st.columns([1, 1, 4])
    with c1:
        limit = st.selectbox(
            "Result limit",
            options=[100, 500, 1000, 5000, 25000],
            index=1,
            key="_slice2_limit",
        )
    with c2:
        run = st.button("Run query", type="primary", key="_slice2_run")

    # Drop any cached result that belongs to a different bundle.
    cached = st.session_state.get(_CACHE_KEY)
    if cached is not None and cached.get("cache_key") != cache_key:
        del st.session_state[_CACHE_KEY]
        cached = None

    if not query:
        st.caption("Enter a query above to search this bundle.")
        return

    if not run and cached is None:
        st.caption("Press Run query to execute.")
        return

    if run:
        payload = {
            "cache_key": cache_key,
            "query": query,
            "limit": limit,
            "total_scanned": len(idx.lines),
            "results": [],
            "error": None,
        }
        try:
            payload["results"] = _run_query(idx, query, limit)
        except QueryError as e:
            payload["error"] = str(e)
        st.session_state[_CACHE_KEY] = payload

    _render_results(idx)


def _render_help_expander() -> None:
    with st.expander("Query syntax", expanded=False):
        st.markdown(
            """
**Fields**
- `component:tunnel` `component:service` `component:tray` `component:upm`
- `level:INFO|WARN|ERROR|DEBUG|TRACE|VERBOSE|FATAL`
- `pid:1234` `tid:5678`
- `session_id:abc` `host:filesvc-a.corp-a.example` `source_file:ZSATunnel_1.log`

**Time**
- `time:2026-07-07T18:00..2026-07-07T19:00` — explicit range
- `time:2026-07-07T18:02:18 ± 5min` — centre + window (or `+-`, `+/-`)
- Timestamps are UTC. Formats: `YYYY-MM-DD`, `YYYY-MM-DD HH:MM`,
  `YYYY-MM-DD HH:MM:SS`, `YYYY-MM-DDTHH:MM:SS`.

**Body**
- Bare word or `"quoted phrase"` -> case-insensitive substring on the line body
- `/regex/` -> regex match on the line body
- `re:pattern` -> regex match on the line body (alias)
- `contains:text` -> substring match on the line body (alias)

**ZCC-native shortcuts**
- `err_code:5008` -> matches `err_code=5008` or `error 5008`
- `code:BRK_MT_SETUP_FAIL_SAML_EXPIRED` -> whole-token match on a symbolic code
- `event:<name>` — well-known event class regex. Known:
            """
        )
        events = known_events()
        st.code(", ".join(events))

        st.markdown(
            """
**Combinators**
- `AND` (implicit — two adjacent atoms) | `OR` | `NOT` | `( ... )`

**Examples**
```
event:saml_expired AND time:2026-07-07T18:00..2026-07-07T19:00
component:tunnel level:ERR NOT event:mtunnel_close
(err_code:5008 OR err_code:5027) AND host:example-tenant-a2
/BRK_MT_SETUP_FAIL_.*EXPIRED/
```
            """
        )


def _render_results(idx: LogIndex) -> None:
    state = st.session_state.get(_CACHE_KEY)
    if state is None:
        return

    if state["error"]:
        st.error(f"Query error: {state['error']}")
        return

    results = state["results"]
    query = state["query"]
    limit = state["limit"]
    total = state["total_scanned"]

    hit_limit = len(results) == limit
    if hit_limit:
        st.warning(
            f"Showing the first **{limit:,}** matches (query hit the limit). "
            f"Increase the limit if you need to see more."
        )
    st.caption(
        f"Query: `{query}`  |  Matches: **{len(results):,}**  |  "
        f"Scanned: {total:,} lines"
    )

    if not results:
        st.info("No matches.")
        return

    # ---- Result table ---------------------------------------------
    rows = []
    for i, ln in enumerate(results):
        rows.append({
            "#": i + 1,
            "ts (UTC)": ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-",
            "level": ln.level or "",
            "component": ln.component or "",
            "source_file": ln.source_file or "",
            "line_no": ln.line_no,
            "body": (ln.body or "")[:400],
        })
    st.dataframe(rows, hide_index=True, use_container_width=True)

    # ---- Row drilldown ---------------------------------------------
    st.subheader("Row drilldown")
    drill_ix = st.number_input(
        "Show surrounding context for row #",
        min_value=1,
        max_value=len(results),
        value=1,
        step=1,
    )
    radius = st.slider("Context radius (lines before/after)", 1, 30, 5)
    row = results[int(drill_ix) - 1]
    ctx = idx.surrounding_lines(row.source_file, row.line_no, radius=radius)
    _render_context(row, ctx)


def _render_context(row: IndexedLine, ctx: List[IndexedLine]) -> None:
    st.caption(
        f"Context around **{row.source_file}:{row.line_no}** "
        f"({row.component} - {row.level}) — "
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
