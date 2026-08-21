"""Timeline view — Slice 4 of the Log-Analyzer rebuild (2026-08-07).

Pick a centre timestamp + radius, see every log line in that window
grouped by lane (auth / mtunnel / broker / power / network / service /
policy / cert / kerberos / tray / data). Renders as a swim-lane
scatter chart on top and a chronological table underneath.

Diff mode: pick a second timestamp, get side-by-side lane counts and
per-tag-type new/gone identifier tables.

Replaces the pre-Slice-0 finding-driven timeline. The old timeline
was clustered-by-detector; this one is grouped-by-lane and driven
purely by classified log-line phases.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import streamlit as st

from ..log_index import LogIndex
from ..timeline import (
    LANE_ORDER,
    TimelineWindow,
    WindowDiff,
    build_timeline,
    diff_windows,
    flatten_events,
)
from ._components import KV, fmt_ts, inject_css, kv_grid


# --------------------------------------------------------------------------
# Cached window build
# --------------------------------------------------------------------------

def _cached_window(_idx: LogIndex, cache_sig: str,
                   centre: datetime, radius: timedelta,
                   lanes_key: str) -> TimelineWindow:
    """`build_timeline` is a full O(lines) scan that additionally runs
    the related-ID regex battery over every in-window line — and
    Streamlit re-executes the whole script on every widget change, so
    without this it re-ran on each keystroke (twice in diff mode).

    `_idx` is underscore-prefixed to skip hashing the index; the caller
    passes an explicit `cache_sig` that identifies the bundle instead.
    `lanes_key` is a stable string form of the lane selection because a
    list isn't hashable as a cache argument.
    """
    lanes = lanes_key.split(",") if lanes_key else None
    return build_timeline(_idx, centre, radius, lanes=lanes)


def _lanes_key(lanes) -> str:
    return ",".join(sorted(lanes)) if lanes else ""


# --------------------------------------------------------------------------
# Renderer entry
# --------------------------------------------------------------------------

def render_timeline(idx: LogIndex, cache_key: str = "") -> None:
    inject_css()
    st.subheader("Timeline")

    mode = st.radio(
        "Mode",
        options=["Single window", "Diff two windows"],
        horizontal=True,
        key="_slice4_mode",
    )

    if mode == "Single window":
        _render_single(idx, cache_key)
    else:
        _render_diff(idx, cache_key)


# --------------------------------------------------------------------------
# Shared controls
# --------------------------------------------------------------------------

def _bundle_bounds(idx: LogIndex) -> Optional[tuple]:
    """First and last timestamp in the bundle.

    Safe to read positionally because `build_index` now sorts
    `idx.lines` chronologically. Before that fix the list was ordered by
    filename descending, so this returned a reversed pair and the
    computed default centre could land outside the bundle entirely —
    opening the tab on an empty window. Kept as min/max rather than
    [0]/[-1] so a future ordering change can't silently reintroduce it.
    """
    if not idx.lines:
        return None
    first = idx.lines[0].ts
    last = idx.lines[-1].ts
    if first > last:
        first, last = last, first
    return (first, last)


def _ts_input(label: str, default: datetime, key: str) -> Optional[datetime]:
    """Text input for a UTC timestamp. Accepts YYYY-MM-DD HH:MM:SS or the
    T-separated form. Returns None on parse error; the caller renders
    an st.error."""
    default_txt = default.strftime("%Y-%m-%d %H:%M:%S")
    txt = st.text_input(
        label, value=default_txt, key=key,
        help="UTC. Formats: YYYY-MM-DD HH:MM:SS or YYYY-MM-DDTHH:MM:SS",
    )
    txt = txt.strip()
    if not txt:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M",
                "%Y-%m-%d"):
        try:
            return datetime.strptime(txt, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    st.error(f"Could not parse timestamp: {txt!r}")
    return None


_RADIUS_OPTIONS = {
    "1 minute": timedelta(minutes=1),
    "5 minutes": timedelta(minutes=5),
    "15 minutes": timedelta(minutes=15),
    "30 minutes": timedelta(minutes=30),
    "1 hour": timedelta(hours=1),
    "3 hours": timedelta(hours=3),
    "12 hours": timedelta(hours=12),
    "1 day": timedelta(days=1),
}


def _radius_input(label: str, key: str, default: str = "5 minutes") -> timedelta:
    choice = st.selectbox(
        label,
        options=list(_RADIUS_OPTIONS),
        index=list(_RADIUS_OPTIONS).index(default),
        key=key,
    )
    return _RADIUS_OPTIONS[choice]


def _lane_selector(key: str) -> Optional[List[str]]:
    """Multi-select for lanes. Returns None if all lanes selected
    (semantically 'no filter')."""
    lanes = st.multiselect(
        "Lanes",
        options=LANE_ORDER,
        default=LANE_ORDER,
        key=key,
    )
    if not lanes:
        return []
    if set(lanes) == set(LANE_ORDER):
        return None
    return lanes


# --------------------------------------------------------------------------
# Single-window render
# --------------------------------------------------------------------------

def _render_single(idx: LogIndex, cache_key: str = "") -> None:
    bounds = _bundle_bounds(idx)
    if bounds is None:
        st.warning("Bundle has no timestamps; timeline unavailable.")
        return

    first_ts, last_ts = bounds
    default_centre = first_ts + (last_ts - first_ts) / 2
    st.caption(
        f"Bundle spans {fmt_ts(first_ts)} → {fmt_ts(last_ts)}. "
        "Centre defaults to the midpoint."
    )

    c1, c2, c3 = st.columns([2, 1, 2])
    with c1:
        centre = _ts_input("Centre (UTC)", default_centre, key="_slice4_centre")
    with c2:
        radius = _radius_input("Window ±", "_slice4_radius")
    with c3:
        lanes = _lane_selector("_slice4_lanes")

    if centre is None:
        return
    if lanes == []:
        st.info("No lanes selected — pick at least one lane to see events.")
        return

    with st.spinner("Building timeline window..."):
        window = _cached_window(idx, cache_key, centre, radius,
                                _lanes_key(lanes))

    _render_window(window)


def _render_window(window: TimelineWindow) -> None:
    _render_header(window)
    _render_lane_bars(window)
    _render_swimlane_chart(window)
    _render_events_table(window)
    _render_ids_seen(window)


def _render_header(window: TimelineWindow) -> None:
    # kv_grid rather than st.metric — the timestamp and span strings
    # overflow a quarter-width metric tile at metric's value font.
    kv_grid([
        KV("Centre (UTC)", fmt_ts(window.centre_ts)),
        KV("Radius", f"±{window.radius}"),
        KV("Total events", f"{window.total_events:,}"),
        KV("Span (UTC)",
           f"{window.start_ts.strftime('%H:%M:%S')} → "
           f"{window.end_ts.strftime('%H:%M:%S')}"),
    ], columns=4)


def _render_lane_bars(window: TimelineWindow) -> None:
    """Bar chart of lane_counts."""
    st.caption("Lane counts")
    data = [
        {"lane": lane, "events": window.lane_counts.get(lane, 0)}
        for lane in LANE_ORDER
    ]
    st.dataframe(data, hide_index=True, use_container_width=True)


def _render_swimlane_chart(window: TimelineWindow) -> None:
    """Scatter chart: X=time, Y=lane. One dot per event."""
    if window.total_events == 0:
        return
    events = flatten_events(window)
    if not events:
        st.caption("No events in the selected lanes for this window.")
        return
    rows = [
        {
            "ts": e.ts,
            "lane": e.lane,
            "phase": e.phase,
            "component": e.component,
            "level": e.level,
            "body_preview": (e.body or "")[:120],
        }
        for e in events
    ]
    # Try Altair for a proper strip chart; fall back to scatter if it's
    # not importable.
    try:
        import pandas as pd
        import altair as alt
        df = pd.DataFrame(rows)
        chart = (
            alt.Chart(df)
            .mark_circle(size=80, opacity=0.75)
            .encode(
                x=alt.X("ts:T", title="Time (UTC)"),
                y=alt.Y(
                    "lane:N",
                    sort=LANE_ORDER,
                    title="Lane",
                ),
                color=alt.Color("phase:N", legend=alt.Legend(title="Phase")),
                tooltip=["ts:T", "lane", "phase", "component", "level",
                         "body_preview"],
            )
            .properties(height=350)
        )
        st.altair_chart(chart, use_container_width=True)
    except ImportError:
        # Altair/pandas genuinely absent — degrade to the event table
        # that follows this section.
        st.caption(
            "Chart needs `altair` + `pandas`; showing the event table only."
        )
    except Exception as exc:  # noqa: BLE001
        # Anything else is a real charting failure. Reporting it as
        # "Altair unavailable" (the old behaviour) sent people looking
        # for a missing dependency that was installed the whole time.
        st.caption(f"Could not render the swim-lane chart: "
                   f"{exc.__class__.__name__}: {exc}")


def _render_events_table(window: TimelineWindow) -> None:
    st.subheader("Chronological events")
    events = flatten_events(window)
    if not events:
        return
    # A quiet window legitimately holds fewer than 10 events. The old
    # slider floored max_value at 10 but not `value`, so 3 events gave
    # min=10, max=10, value=3 → StreamlitAPIException. Skip the control
    # entirely when there's no range to choose from.
    if len(events) <= 10:
        st.caption(f"Showing all {len(events):,} event(s).")
        limit = len(events)
    else:
        upper = min(5000, len(events))
        limit = int(st.slider(
            "Rows to show",
            min_value=10, max_value=upper,
            value=min(500, upper), step=10,
            key="_slice4_row_limit",
        ))
    rows = []
    for i, e in enumerate(events[:limit]):
        rows.append({
            "#": i + 1,
            "ts (UTC)": e.ts.strftime("%Y-%m-%d %H:%M:%S"),
            "lane": e.lane,
            "phase": e.phase,
            "level": e.level,
            "component": e.component,
            "source": f"{e.source_file}:{e.line_no}",
            "body": (e.body or "")[:400],
        })
    st.dataframe(rows, hide_index=True, use_container_width=True)


def _render_ids_seen(window: TimelineWindow) -> None:
    if not window.ids_seen:
        return
    with st.expander(
        f"IDs seen in this window "
        f"({sum(len(v) for v in window.ids_seen.values())} distinct)",
        expanded=False,
    ):
        rows = []
        for tag_type, vals in sorted(window.ids_seen.items()):
            rows.append({
                "tag_type": tag_type,
                "count": len(vals),
                "values": ", ".join(sorted(vals))[:400],
            })
        st.dataframe(rows, hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------
# Diff render
# --------------------------------------------------------------------------

def _render_diff(idx: LogIndex, cache_key: str = "") -> None:
    bounds = _bundle_bounds(idx)
    if bounds is None:
        st.warning("Bundle has no timestamps; timeline unavailable.")
        return
    first_ts, last_ts = bounds
    default_a = first_ts + (last_ts - first_ts) / 3
    default_b = first_ts + 2 * (last_ts - first_ts) / 3
    st.caption(
        f"Bundle spans {fmt_ts(first_ts)} → {fmt_ts(last_ts)}. "
        "Centres default to the 1/3 and 2/3 marks."
    )

    c1, c2, c3, c4 = st.columns([2, 2, 1, 2])
    with c1:
        centre_a = _ts_input(
            "Centre A (UTC)", default_a, key="_slice4_diff_a",
        )
    with c2:
        centre_b = _ts_input(
            "Centre B (UTC)", default_b, key="_slice4_diff_b",
        )
    with c3:
        radius = _radius_input(
            "Shared window ±", "_slice4_diff_radius", default="15 minutes",
        )
    with c4:
        # Diff mode previously had no lane selector, so it couldn't be
        # scoped the way single-window can — you got all 11 lanes or
        # nothing.
        lanes = _lane_selector("_slice4_diff_lanes")

    if centre_a is None or centre_b is None:
        return
    if lanes == []:
        st.info("No lanes selected — pick at least one lane to diff.")
        return

    lk = _lanes_key(lanes)
    with st.spinner("Building windows and computing diff..."):
        w_a = _cached_window(idx, cache_key, centre_a, radius, lk)
        w_b = _cached_window(idx, cache_key, centre_b, radius, lk)
        d = diff_windows(w_a, w_b)

    _render_diff_body(d)


def _render_diff_body(d: WindowDiff) -> None:
    a, b = d.window_a, d.window_b

    # ---- Side-by-side headers -----
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(
            f"**A** — {a.centre_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}  "
            f"(± {a.radius})"
        )
        st.metric("Total events", f"{a.total_events:,}")
    with col_b:
        st.markdown(
            f"**B** — {b.centre_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}  "
            f"(± {b.radius})"
        )
        st.metric("Total events", f"{b.total_events:,}")

    st.markdown("---")

    # ---- Lane delta table -----
    st.caption("Lane counts A vs B")
    rows = []
    for ld in d.lane_deltas:
        arrow = "0"
        if ld.delta > 0:
            arrow = f"+{ld.delta}"
        elif ld.delta < 0:
            arrow = str(ld.delta)
        rows.append({
            "lane": ld.lane,
            "A": ld.count_a,
            "B": ld.count_b,
            "delta (B-A)": arrow,
        })
    st.dataframe(rows, hide_index=True, use_container_width=True)

    # ---- ID deltas -----
    st.caption("Identifier deltas per tag type")
    if not d.id_deltas:
        st.info("No identifiers extracted in either window.")
        return
    rows = []
    for idd in d.id_deltas:
        rows.append({
            "tag_type": idd.tag_type,
            "only in A": ", ".join(idd.only_in_a)[:200] or "-",
            "only in B": ", ".join(idd.only_in_b)[:200] or "-",
            "in both": ", ".join(idd.in_both)[:200] or "-",
        })
    st.dataframe(rows, hide_index=True, use_container_width=True)
