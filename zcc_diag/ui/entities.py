"""Entities view — Slice 10 (2026-08-14).

Every distinct entity the parser observed, one sub-tab per kind, each a
real sortable table with counts and time span.

Why this is its own tab. Facts previously rendered these with
`st.write(list_of_2412_session_ids)`, and Streamlit's default renderer
turns a long list into a collapsible JSON tree chunked into
`[0-99] [100-199] …` buckets. That produced a screen-high column of
range accordions that overlapped the neighbouring column, told you
nothing, and buried the actual values behind two clicks each. Counts
belong on Facts; the *values* belong here, in tables you can sort and
search.

Every row is backed by counted log evidence — value, occurrences, first
and last seen, which log module(s) and file(s) produced it. Nothing is
inferred.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import streamlit as st

from ..id_inventory import IdInventory, IdStat
from ..log_index import LogIndex
from ._components import KV, chips, fmt_ts, inject_css, kv_grid, section


# --------------------------------------------------------------------------
# Entity kinds sourced directly from the parsed line fields
# --------------------------------------------------------------------------

@dataclass
class EntityRow:
    value: str
    count: int
    first_ts: Optional[datetime]
    last_ts: Optional[datetime]
    detail: str = ""


def _rows_from_line_field(idx: LogIndex, field: str) -> List[EntityRow]:
    """Aggregate one `IndexedLine` attribute (pid / component /
    session_id / host / source_file / level) into counted rows."""
    counts: Counter = Counter()
    first: Dict[str, datetime] = {}
    last: Dict[str, datetime] = {}
    extra: Dict[str, set] = defaultdict(set)

    for ln in idx.lines:
        val = getattr(ln, field, None)
        if not val:
            continue
        val = str(val)
        counts[val] += 1
        ts = ln.ts
        if ts is not None:
            if val not in first or ts < first[val]:
                first[val] = ts
            if val not in last or ts > last[val]:
                last[val] = ts
        # A useful secondary axis per kind: which component a PID or
        # host belongs to, or which file a component was seen in.
        if field in ("pid", "session_id", "host"):
            if ln.component:
                extra[val].add(ln.component)
        elif field == "component":
            if ln.source_file:
                extra[val].add(ln.source_file)

    out: List[EntityRow] = []
    for val, n in counts.items():
        detail = ", ".join(sorted(extra.get(val, ())))
        if field == "component" and len(extra.get(val, ())) > 3:
            detail = f"{len(extra[val])} files"
        out.append(EntityRow(
            value=val, count=n,
            first_ts=first.get(val), last_ts=last.get(val),
            detail=detail,
        ))
    out.sort(key=lambda r: (-r.count, r.value))
    return out


def _rows_from_inventory(inv: Optional[IdInventory],
                         tag_type: str) -> List[EntityRow]:
    """Aggregate one IdInventory tag type into the same row shape."""
    if inv is None:
        return []
    bucket = inv.groups.get(tag_type) or {}
    out = [
        EntityRow(
            value=s.value, count=s.count,
            first_ts=s.first_ts, last_ts=s.last_ts,
            detail=", ".join(sorted(s.components)),
        )
        for s in bucket.values()
    ]
    out.sort(key=lambda r: (-r.count, r.value))
    return out


# --------------------------------------------------------------------------
# Catalogue of what this tab can show
#   (label, source, key)  where source is "line" or "inv"
# --------------------------------------------------------------------------

_LINE_KINDS: List[Tuple[str, str]] = [
    ("Processes (PID)", "pid"),
    ("Log components", "component"),
    ("Session IDs", "session_id"),
    ("Hosts contacted", "host"),
    ("Source files", "source_file"),
]

_INV_KINDS: List[Tuple[str, str]] = [
    ("ZPA tag IDs", "tag_id"),
    ("mtunnel IDs", "mtunnel_id"),
    ("Broker sessions", "broker_session"),
    ("Data channels", "data_channel"),
    ("Connection IDs", "conn_id"),
    ("Brokers", "broker"),
    ("SME hosts", "sme_host"),
    ("Applications", "app"),
    ("Error codes", "err_code"),
    ("Symbolic codes", "symbolic_code"),
    ("HTTP statuses", "http_status"),
    ("IPv4 addresses", "ipv4"),
    ("ZIA clouds", "zia_cloud"),
    ("ZPA clouds", "zpa_cloud"),
    ("Data centers", "dc"),
    ("Usernames", "username"),
    ("Device hostnames", "device_hostname"),
    ("Org / tenant IDs", "org_id"),
    ("ZCC versions", "zcc_version"),
]


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------

def render_entities(idx: LogIndex, cache_key: str,
                    inv: Optional[IdInventory] = None) -> None:
    inject_css()
    st.caption(
        "Every distinct entity the parser observed, with occurrence "
        "counts and time span. Pick a kind, sort or filter the table."
    )

    kinds = _available_kinds(idx, cache_key, inv)
    if not kinds:
        st.warning("No entities extracted from this bundle.")
        return

    section("Overview")
    chips([(label, n) for label, n, _, _ in kinds])

    section("Browse")
    c1, c2, c3 = st.columns([2, 2, 1])
    with c1:
        labels = [f"{label}  ({n:,})" for label, n, _, _ in kinds]
        chosen = st.selectbox("Entity kind", labels, index=0,
                              key="_slice10_kind")
        label, _n, source, key = kinds[labels.index(chosen)]
    with c2:
        needle = st.text_input("Filter (substring)", key="_slice10_filter",
                               placeholder="optional")
    with c3:
        sort_by = st.selectbox("Sort", ["count", "value", "first seen",
                                        "last seen"],
                               index=0, key="_slice10_sort")

    rows = (_rows_from_line_field(idx, key) if source == "line"
            else _rows_from_inventory(inv, key))

    if needle.strip():
        q = needle.strip().lower()
        rows = [r for r in rows if q in r.value.lower()]

    if sort_by == "value":
        rows.sort(key=lambda r: r.value)
    elif sort_by == "first seen":
        rows.sort(key=lambda r: (r.first_ts is None, r.first_ts))
    elif sort_by == "last seen":
        rows.sort(key=lambda r: (r.last_ts is None, r.last_ts), reverse=True)

    if not rows:
        st.info("Nothing matches this filter.")
        return

    total_hits = sum(r.count for r in rows)
    kv_grid([
        KV("Kind", label),
        KV("Distinct values", f"{len(rows):,}"),
        KV("Total occurrences", f"{total_hits:,}"),
        KV("Source", "parsed line field" if source == "line"
                     else "ID inventory (regex)"),
    ], columns=4)

    detail_header = {
        "pid": "components", "component": "files",
        "session_id": "components", "host": "components",
    }.get(key, "modules")

    st.dataframe(
        [
            {
                "value": r.value,
                "lines": r.count,
                "first (UTC)": fmt_ts(r.first_ts) or "—",
                "last (UTC)": fmt_ts(r.last_ts) or "—",
                detail_header: r.detail or "—",
            }
            for r in rows
        ],
        hide_index=True, use_container_width=True, height=460,
    )

    st.caption(
        f"{len(rows):,} row(s) in the current view. Export is disabled; "
        "customer-derived inventories are never retained."
    )


def _cached_counts(cache_key: str, _idx: LogIndex) -> Dict[str, int]:
    """Distinct-count per line-field kind. Cached because it walks every
    line once per kind and the selectbox labels need all of them up
    front. `_idx` is underscore-prefixed to skip Streamlit's argument
    hashing (it would walk the whole index on every rerun)."""
    out: Dict[str, int] = {}
    for _label, key in _LINE_KINDS:
        seen = set()
        for ln in _idx.lines:
            v = getattr(ln, key, None)
            if v:
                seen.add(str(v))
        out[key] = len(seen)
    return out


def _available_kinds(idx: LogIndex, cache_key: str,
                     inv: Optional[IdInventory]
                     ) -> List[Tuple[str, int, str, str]]:
    """Return `(label, distinct_count, source, key)` for every kind that
    actually has values in this bundle. Empty kinds are omitted rather
    than shown as zero — a kind with no values is an absence of
    evidence, not a fact worth a row."""
    counts = _cached_counts(cache_key, idx)
    out: List[Tuple[str, int, str, str]] = []
    for label, key in _LINE_KINDS:
        n = counts.get(key, 0)
        if n:
            out.append((label, n, "line", key))
    if inv is not None:
        for label, key in _INV_KINDS:
            n = len(inv.groups.get(key) or {})
            if n:
                out.append((label, n, "inv", key))
    return out
