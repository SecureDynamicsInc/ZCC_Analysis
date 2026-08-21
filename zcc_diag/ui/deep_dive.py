"""Deferred views over the Slice 15 and Slice 18 deep-analysis libraries."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import streamlit as st

from ..flow_ledger import build_ledger
from ..setupapi_extract import (
    find_setupapi_logs,
    network_driver_events,
    parse_file,
)
from ._components import KV, fmt_bytes, fmt_count, fmt_ts, kv_grid, section


def _build_flow_ledger(cache_key: str, _store):
    return build_ledger(_store, lifetime=True)


def _parse_setupapi(cache_key: str, _paths: Sequence[str]):
    return tuple(parse_file(path) for path in _paths)


def _flow_rows(rows):
    return [
        {
            "Destination": row.key,
            "Flows": row.flows,
            "Client bytes": row.client_bytes,
            "Server bytes": row.server_bytes,
            "Total bytes": row.total_bytes,
            "First (UTC)": row.first_ts,
            "Last (UTC)": row.last_ts,
        }
        for row in rows
    ]


def _render_connections(store, cache_key: str) -> None:
    st.markdown(
        "Reconstructs closed TCP and UDP flows from final byte carriers. "
        "Running counters and keepalives are deliberately excluded so bytes "
        "cannot be counted repeatedly."
    )
    ready_key = f"deep-ledger-ready:{cache_key}"
    if not st.session_state.get(ready_key):
        if st.button("Build connection ledger", type="primary", key=f"build-ledger:{cache_key}"):
            st.session_state[ready_key] = True
            st.rerun()
        st.caption("Built on demand because a full ledger can contain millions of flows.")
        return

    with st.spinner("Reconstructing closed connections and byte totals..."):
        ledger = _build_flow_ledger(cache_key, store)
    totals = ledger.totals()
    section("Connection accounting")
    kv_grid([
        KV("Closed flows", fmt_count(totals["flows"])),
        KV("TCP / UDP", f"{totals['tcp_flows']:,} / {totals['udp_flows']:,}"),
        KV("Transferred", fmt_bytes(totals["total_bytes"])),
        KV("Without destination", fmt_count(totals["flows_without_destination"])),
        KV("First close", fmt_ts(totals["first_ts"])),
        KV("Last close", fmt_ts(totals["last_ts"])),
        KV("Reused connection IDs", fmt_count(ledger.conn_ids_reused)),
        KV("Unmatched candidates", fmt_count(ledger.unmatched_candidates)),
    ], columns=4)

    if ledger.source_files_duplicated:
        st.warning(
            f"The bundle contains {ledger.source_files_duplicated:,} duplicated source "
            "files. Those records remain visible and can duplicate flow totals."
        )
    if not ledger.flows:
        st.info("No verified final flow-accounting records were found in the selected logs.")
        return

    group = st.segmented_control(
        "Group traffic by",
        options=["Destination", "Hour", "Protocol"],
        default="Destination",
        key=f"ledger-group:{cache_key}",
    )
    if group == "Hour":
        rows = ledger.by_hour()
    elif group == "Protocol":
        rows = ledger.by_proto()
    else:
        rows = ledger.by_destination(top=1000)
    st.dataframe(
        _flow_rows(rows),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Client bytes": st.column_config.NumberColumn(format="localized"),
            "Server bytes": st.column_config.NumberColumn(format="localized"),
            "Total bytes": st.column_config.NumberColumn(format="localized"),
        },
    )
    st.caption(
        "Traffic is bucketed on the connection close timestamp. Destination values "
        "are shown exactly as recorded; the explorer does not resolve or normalize them."
    )


def _render_drivers(extracted, cache_key: str) -> None:
    paths = find_setupapi_logs(str(extracted.root))
    if not paths:
        st.info(
            "No setupapi.dev.log was present. This view is available for Windows "
            "bundles that include SetupAPI device-install history."
        )
        return

    st.markdown(
        f"Found **{len(paths)}** SetupAPI log file(s). This view dates Windows "
        "network-driver staging, install, update, removal, and signing results."
    )
    ready_key = f"deep-drivers-ready:{cache_key}"
    if not st.session_state.get(ready_key):
        if st.button("Parse driver history", type="primary", key=f"build-drivers:{cache_key}"):
            st.session_state[ready_key] = True
            st.rerun()
        return

    with st.spinner("Parsing Windows driver and device history..."):
        parsed = _parse_setupapi(cache_key, tuple(paths))
        events = network_driver_events(parsed)

    section("SetupAPI coverage")
    kv_grid([
        KV("Files", fmt_count(len(parsed))),
        KV("Lines", fmt_count(sum(log.total_lines for log in parsed))),
        KV("Sections", fmt_count(sum(log.section_count for log in parsed))),
        KV("Network events", fmt_count(len(events))),
    ], columns=4)

    if not events:
        st.info("SetupAPI was present, but no network-driver events were identified.")
        return
    rows = [
        {
            "When (device local time)": event.when_local,
            "Action": event.action,
            "Name": event.name,
            "Vendor": event.vendor,
            "Version": event.driver_version,
            "Provider": event.provider,
            "Service": event.service,
            "Succeeded": event.succeeded,
            "Exit status": event.exit_status,
            "Source": Path(event.source).name,
            "Line": event.header_line,
        }
        for event in events
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.caption(
        "SetupAPI timestamps are device-local wall clock. Runtime WFP sublayers, "
        "including Microsoft SenseNdr, do not pass through SetupAPI and cannot be "
        "proven absent from this view."
    )


def render_deep_dive(extracted, store, cache_key: str) -> None:
    section("Deep evidence")
    connections, drivers = st.tabs(["Connection ledger", "Driver history"])
    with connections:
        _render_connections(store, cache_key)
    with drivers:
        _render_drivers(extracted, cache_key)
