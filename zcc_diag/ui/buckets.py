"""Buckets view — Slice 9 (2026-08-14).

Every parsed line in the bundle, classified on two axes (service ×
subsystem) and browsable either way, plus an honest coverage account.

Three panels:

  1. **Coverage** — how much of the bundle each axis actually resolved,
     and how much of that came from a body-text match versus a weaker
     component-derived fallback. This is deliberately the first thing
     shown: a bucket view that silently drops a third of the log is
     worse than no bucket view, so the number that says "we classified
     X%" leads.

  2. **Distribution** — service totals, subsystem totals, and the
     service × subsystem matrix.

  3. **Browse** — pick a service and/or subsystem, read the lines.

  4. **Unclassified shapes** — the recurring templates behind lines that
     matched nothing, most frequent first. This is the to-do list for
     extending the classifier, and it's surfaced rather than buried
     because unknown-unknowns are the failure mode that matters here.
"""

from __future__ import annotations

from typing import List, Optional

import streamlit as st

from ..line_buckets import (
    SERVICES,
    SUBSYSTEMS,
    BucketReport,
    build_buckets,
)
from ..log_index import LogIndex
from ._components import bar, chips, fmt_count, inject_css, kv_grid, KV, section

_ANY = "(any)"


def _cached_buckets(cache_key: str, _idx: LogIndex) -> BucketReport:
    """Classification is a single O(lines) pass but that's still seconds
    on a multi-million-line bundle — cache per bundle so tab switches
    stay instant."""
    return build_buckets(_idx)


def render_buckets(idx: LogIndex, cache_key: str) -> None:
    inject_css()
    st.caption(
        "Every parsed line classified by **service** (which Zscaler "
        "product) and **subsystem** (what it's about). The two axes are "
        "independent — a line is tagged on both."
    )

    with st.spinner("Classifying every line (one-time per bundle)..."):
        rep = _cached_buckets(cache_key, idx)

    if rep.total_lines == 0:
        st.warning("No parsed lines in this bundle.")
        return

    _render_coverage(rep)
    _render_distribution(rep)
    _render_browser(rep)
    _render_unclassified(rep)


# --------------------------------------------------------------------------
# Coverage
# --------------------------------------------------------------------------

def _render_coverage(rep: BucketReport) -> None:
    section("Coverage")

    svc_pct = rep.service_coverage_pct()
    sub_pct = rep.subsystem_coverage_pct()

    svc_matched = rep.service_via_counts.get("matched", 0)
    svc_comp = rep.service_via_counts.get("component", 0)
    sub_matched = rep.subsystem_via_counts.get("matched", 0)
    sub_comp = rep.subsystem_via_counts.get("component", 0)

    kv_grid([
        KV("Lines classified", fmt_count(rep.total_lines)),
        KV("Service resolved", f"{svc_pct:.1f}%",
           f"{svc_matched:,} by pattern · {svc_comp:,} by log module"),
        KV("Subsystem resolved", f"{sub_pct:.1f}%",
           f"{sub_matched:,} by pattern · {sub_comp:,} by log module"),
        KV("Neither axis resolved", fmt_count(rep.unclassified_both),
           f"{100.0 * rep.unclassified_both / rep.total_lines:.1f}% of bundle"),
    ], columns=4)

    c1, c2 = st.columns(2)
    with c1:
        st.caption(f"Service coverage — {svc_pct:.1f}%")
        bar(svc_pct)
    with c2:
        st.caption(f"Subsystem coverage — {sub_pct:.1f}%")
        bar(sub_pct)

    st.caption(
        "“By pattern” means the line body matched a documented marker. "
        "“By log module” is the weaker fallback — the line carried no "
        "product marker, so the bucket was taken from which component "
        "(tunnel / service / tray / upm) emitted it. Treat those as "
        "context, not evidence."
    )


# --------------------------------------------------------------------------
# Distribution
# --------------------------------------------------------------------------

def _render_distribution(rep: BucketReport) -> None:
    section("Distribution")

    c1, c2 = st.columns(2)
    with c1:
        st.caption("By service")
        chips(sorted(rep.by_service.items(), key=lambda kv: -kv[1]))
    with c2:
        st.caption("By subsystem")
        chips(sorted(rep.by_subsystem.items(), key=lambda kv: -kv[1]))

    with st.expander("Service × subsystem matrix", expanded=True):
        services = [s for s in SERVICES if s in rep.by_service]
        rows = []
        for sub in SUBSYSTEMS:
            if sub not in rep.by_subsystem:
                continue
            row = {"subsystem": sub}
            total = 0
            for svc in services:
                n = rep.by_pair.get((svc, sub), 0)
                row[svc] = n
                total += n
            row["total"] = total
            rows.append(row)
        rows.sort(key=lambda r: -r["total"])
        if rows:
            st.dataframe(rows, hide_index=True, use_container_width=True)
        else:
            st.caption("No classified pairs.")


# --------------------------------------------------------------------------
# Browser
# --------------------------------------------------------------------------

def _render_browser(rep: BucketReport) -> None:
    section("Browse lines")

    c1, c2, c3, c4 = st.columns([1.2, 1.2, 1.4, 1])
    with c1:
        svc_opts = [_ANY] + [
            f"{s} ({rep.by_service[s]:,})"
            for s in SERVICES if s in rep.by_service
        ]
        svc_choice = st.selectbox("Service", svc_opts, index=0,
                                  key="_slice9_svc")
    with c2:
        sub_opts = [_ANY] + [
            f"{s} ({rep.by_subsystem[s]:,})"
            for s in SUBSYSTEMS if s in rep.by_subsystem
        ]
        sub_choice = st.selectbox("Subsystem", sub_opts, index=0,
                                  key="_slice9_sub")
    with c3:
        substring = st.text_input("Filter (substring)", key="_slice9_filter",
                                  placeholder="optional")
    with c4:
        limit = st.selectbox("Max rows", [200, 500, 1000, 5000], index=1,
                             key="_slice9_limit")

    service = None if svc_choice == _ANY else svc_choice.split(" (")[0]
    subsystem = None if sub_choice == _ANY else sub_choice.split(" (")[0]

    lines = rep.lines_for(service=service, subsystem=subsystem)
    if substring.strip():
        q = substring.strip().lower()
        lines = [ln for ln in lines if q in (ln.body or "").lower()]

    if not lines:
        st.info("No lines match this selection.")
        return

    st.caption(
        f"**{len(lines):,}** matching line(s); showing up to {limit:,}."
    )
    rows = []
    for ln in lines[:int(limit)]:
        rows.append({
            "ts (UTC)": ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "—",
            "service": ln.service,
            "subsystem": ln.subsystem,
            "via": f"{ln.service_via[:1]}/{ln.subsystem_via[:1]}",
            "level": ln.level,
            "component": ln.component,
            "source": f"{ln.source_file}:{ln.line_no}",
            "body": (ln.body or "")[:400],
        })
    st.dataframe(rows, hide_index=True, use_container_width=True)
    st.caption(
        "`via` column: first letter is how the service was decided, "
        "second is the subsystem — **m**atched / **c**omponent / "
        "**u**nresolved."
    )

    st.caption(
        f"Selection holds {len(lines):,} line(s). Export is disabled; the view "
        "is destroyed with the current run."
    )


# --------------------------------------------------------------------------
# Unclassified
# --------------------------------------------------------------------------

def _render_unclassified(rep: BucketReport) -> None:
    if not rep.top_unclassified_shapes:
        return

    section("Unclassified line shapes")
    st.caption(
        f"**{rep.unclassified_subsystem:,}** line(s) "
        f"({100.0 * rep.unclassified_subsystem / max(1, rep.total_lines):.1f}%) "
        f"matched no **subsystem** pattern. Bodies are normalised into "
        f"recurring templates (numbers, IPs, GUIDs, hex and quoted "
        f"strings replaced with placeholders) and counted, so the "
        f"highest-count rows are the most valuable patterns to add next. "
        f"This list keys on the subsystem axis deliberately — the service "
        f"axis is resolved for nearly every line by the component "
        f"fallback, so an \"unclassified on both axes\" list reads as "
        f"empty even when a quarter of the bundle has no subsystem."
    )
    rows = [
        {"lines": count, "shape": shape or "(empty body)"}
        for shape, count in rep.top_unclassified_shapes
    ]
    st.dataframe(rows, hide_index=True, use_container_width=True)
