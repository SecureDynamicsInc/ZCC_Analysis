"""Searchable, offline reference for every bundled Zscaler code family."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, List, Mapping, Sequence
from urllib.parse import urlencode

import streamlit as st

from zcc_diag.error_catalog import CatalogEntry, catalog_entries


_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def filter_catalog(
    entries: Sequence[CatalogEntry], *, product: str = "All",
    severity: str = "All", families: Sequence[str] = (), query: str = "",
) -> List[CatalogEntry]:
    needle = query.strip().casefold()
    selected_families = set(families)
    rows = []
    for entry in entries:
        if product != "All" and entry.product != product:
            continue
        if severity != "All" and entry.severity != severity.casefold():
            continue
        if selected_families and entry.family not in selected_families:
            continue
        haystack = "\n".join((entry.code, *entry.aliases, entry.label,
                               entry.description, entry.resolution, entry.component,
                               entry.category)).casefold()
        if needle and needle not in haystack:
            continue
        rows.append(entry)
    return rows


def _issue_url(entry: CatalogEntry | None = None) -> str:
    details = ""
    if entry is not None:
        details = f"\n\nRelated catalog entry: {entry.product} / {entry.family} / {entry.code}"
    query = urlencode({
        "template": "missing_error_code.yml",
        "title": "Missing or incorrect Zscaler error code",
        "body": (
            "Please include the exact code or message, the Zscaler product, "
            "and one fully redacted sample log line. Do not attach customer-sensitive logs."
            + details
        ),
    })
    return f"https://github.com/SecureDynamicsInc/ZCC_Analysis/issues/new?{query}"


def render_error_reference(signals: Any = None) -> None:
    entries = list(catalog_entries())
    counts = Counter(getattr(signals, "code_counts", {}) or {})

    st.markdown("## Known error reference")
    st.caption(
        f"{len(entries):,} locally bundled, source-backed Zscaler errors and statuses. "
        "Use the filters to audit coverage or find a likely fix without uploading logs."
    )

    product = st.segmented_control(
        "Product", ["All", "ZCC", "ZIA", "ZPA", "ZDX"], default="All",
        key="reference_product",
    ) or "All"
    severity = st.segmented_control(
        "Severity", ["All", "Critical", "Warning", "Info"], default="All",
        key="reference_severity",
        help="Severity is an analyzer triage hint derived from the documented impact, not a Zscaler support priority.",
    ) or "All"

    available_families = sorted({e.family for e in entries if product == "All" or e.product == product})
    families = st.multiselect(
        "Reference families", available_families, placeholder="All families",
        key="reference_families",
    )
    query = st.text_input(
        "Search codes, messages, symptoms, or fixes",
        placeholder="Examples: BRK_MT_SETUP, DNS resolution, TCP reset, 42016",
        key="reference_search",
    )
    filtered = filter_catalog(
        entries, product=product, severity=severity, families=families, query=query,
    )
    filtered.sort(key=lambda e: (
        0 if counts.get(e.code) else 1,
        _SEVERITY_ORDER.get(e.severity, 9), e.product, e.family, e.code,
    ))

    st.caption(f"Showing {len(filtered):,} of {len(entries):,} entries")
    if not filtered:
        st.info("No catalog entries match these filters.")
        st.markdown(f"[Report a missing code to SecureDynamics]({_issue_url()})")
        return

    table = [{
        "Found": counts.get(entry.code, 0) or "",
        "Severity": entry.severity.title(),
        "Product": entry.product,
        "Code or identifier": entry.code,
        "Meaning": entry.label,
        "Family": entry.family,
        "Component": entry.component,
    } for entry in filtered]
    st.dataframe(table, width="stretch", hide_index=True, height=440)

    choices = {f"{e.product} · {e.code} · {e.label}": e for e in filtered}
    selected_label = st.selectbox(
        "Open an entry", list(choices), key="reference_selected",
    )
    selected = choices[selected_label]
    found = counts.get(selected.code, 0)
    heading = f"{selected.code} · {selected.label}"
    with st.expander(heading, expanded=True):
        if found:
            st.error(f"Found {found:,} matching record(s) in the current logs.")
        st.markdown(f"**Product / family:** {selected.product} · {selected.family}")
        st.markdown(f"**Analyzer severity:** {selected.severity.title()}")
        if selected.description and selected.description != selected.label:
            st.markdown(f"**What it means:** {selected.description}")
        if selected.resolution:
            st.markdown(f"**Likely next step:** {selected.resolution}")
        st.markdown(f"[Open the official Zscaler reference]({selected.source_url})")

    st.markdown(f"[Report a missing or incorrect code to SecureDynamics]({_issue_url(selected)})")
    st.caption(
        "Include the exact code and one redacted sample line. Submit an issue or pull request; "
        "do not commit customer logs or sensitive data."
    )
