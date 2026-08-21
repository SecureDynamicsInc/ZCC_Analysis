"""Problem-first packet-capture workbench with stream following."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

import streamlit as st

from zcc_diag.pcap_review import follow_streams
from zcc_diag.ui.pcap import render_pcap_tab
from zcc_diag.wireshark_filters import (
    FILTER_LIBRARY,
    WIRESHARK_FILTER_GUIDE,
    ZCC_PACKET_CAPTURE_GUIDE,
    FilterRecipe,
    detected_pcap_filters,
    endpoint_display_filter,
)


def _follow(path: str, query: str):
    return follow_streams(Path(path), query)


def _ip_from_endpoint(value: str) -> str:
    value = value.split(" -> ", 1)[-1].strip()
    match = re.match(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", value)
    return match.group("ip") if match else value.split(":", 1)[0]


def _suggestions(pcap: Dict[str, Any]) -> List[str]:
    suggestions: List[str] = []
    for key in (pcap.get("dns_nxdomain") or {}):
        qname = key.split("  [", 1)[0]
        suggestions.append(f"DNS failure · {qname}")
    for key in (pcap.get("tcp_resets") or {}):
        suggestions.append(f"TCP reset · {_ip_from_endpoint(key)}")
    for key in (pcap.get("tls_alert_endpoints") or {}):
        suggestions.append(f"TLS alert · {_ip_from_endpoint(key)}")
    for key in (pcap.get("tcp_retransmits") or {}):
        suggestions.append(f"Retransmissions · {_ip_from_endpoint(key)}")
    return list(dict.fromkeys(suggestions))[:25]


def _query_from_suggestion(value: str) -> str:
    return value.split(" · ", 1)[1] if " · " in value else value


def _render_streams(streams: List[Any]) -> None:
    if not streams:
        st.info("No complete TCP or UDP stream matched this filter in the selected capture.")
        return
    for stream in streams:
        title = (
            f"{stream.proto.upper()} stream {stream.stream_id} · "
            f"{stream.endpoint_a} ↔ {stream.endpoint_b} · "
            f"{stream.packet_count:,} packets · {stream.duration_s:.2f}s"
        )
        reset_count = sum(1 for packet in stream.packets if "RST" in packet.tcp_flags)
        with st.expander(title, expanded=bool(reset_count)):
            st.caption(f"Matched by {stream.matched_by} · {stream.bytes_total:,} IP bytes")
            if reset_count:
                st.warning(
                    f"This captured stream includes {reset_count} TCP RST packet(s). "
                    "Check the Direction, Source, and Destination columns to identify the sender."
                )
            rows = []
            for packet in stream.packets:
                rows.append({
                    "Time": packet.ts.isoformat(),
                    "Direction": packet.direction,
                    "Source": f"{packet.src_ip}:{packet.src_port}",
                    "Destination": f"{packet.dst_ip}:{packet.dst_port}",
                    "Flags": packet.tcp_flags,
                    "Bytes": packet.length,
                    "Payload preview": packet.payload_preview,
                })
            st.dataframe(
                rows,
                hide_index=True,
                width="stretch",
                height=min(520, 40 + 35 * min(len(rows), 14)),
                column_config={
                    "Source": st.column_config.TextColumn(width="large"),
                    "Destination": st.column_config.TextColumn(width="large"),
                    "Payload preview": st.column_config.TextColumn(width="large"),
                },
            )
            if stream.packet_count > len(stream.packets):
                st.caption(
                    f"Showing the first {len(stream.packets):,} of {stream.packet_count:,} packets in this stream."
                )


def _render_filter_recipe(recipe: FilterRecipe, *, expanded: bool = False) -> None:
    with st.expander(f"{recipe.category} · {recipe.title}", expanded=expanded):
        st.markdown(f"**Use it when:** {recipe.use_when}")
        st.markdown("**Wireshark display filter — copy and paste:**")
        st.code(recipe.display_filter, language=None, wrap_lines=True)
        st.markdown(f"**What to inspect:** {recipe.inspect}")


def _render_wireshark_filters(pcap: Dict[str, Any]) -> None:
    detected = detected_pcap_filters(pcap)
    st.markdown("### Verify in Wireshark")
    st.caption(
        "Open this `.pcapng` file in Wireshark and paste a filter into the "
        "Display Filter bar. These are display filters, not capture filters."
    )
    if detected:
        st.markdown("#### Filters built from this capture")
        for recipe in detected:
            _render_filter_recipe(recipe, expanded=True)
    else:
        st.info("No DNS failure, reset, retransmission, TLS alert, or unmatched-SYN filter was generated from this capture.")

    with st.expander("Zscaler Wireshark display-filter library"):
        categories = ["All"] + list(dict.fromkeys(recipe.category for recipe in FILTER_LIBRARY))
        selected_category = st.segmented_control(
            "Filter category", categories, default="All", key="wireshark_filter_category",
        ) or "All"
        search = st.text_input(
            "Search the filter library", placeholder="DNS, reset, SNI, CONNECT, UDP 443…",
            key="wireshark_filter_search",
        ).strip().casefold()
        recipes = [
            recipe for recipe in FILTER_LIBRARY
            if (selected_category == "All" or recipe.category == selected_category)
            and (not search or search in " ".join((
                recipe.category, recipe.title, recipe.use_when,
                recipe.inspect, recipe.display_filter,
            )).casefold())
        ]
        st.caption(f"Showing {len(recipes)} of {len(FILTER_LIBRARY)} tested recipes")
        for recipe in recipes:
            _render_filter_recipe(recipe)

        endpoint = st.text_input(
            "Build a filter for one observed IPv4 or IPv6 address",
            placeholder="198.51.100.25 or 2001:db8::25",
            key="wireshark_endpoint_filter",
        ).strip()
        if endpoint:
            try:
                generated = endpoint_display_filter(endpoint)
            except ValueError:
                st.warning("Enter one complete IPv4 or IPv6 address.")
            else:
                st.code(generated, language=None, wrap_lines=True)

        st.caption(
            "ZCC can capture at the network-adapter and packet-filter-driver layers. "
            "An absent packet in one capture is not proof that it never existed."
        )
        st.markdown(
            f"[Wireshark display-filter syntax]({WIRESHARK_FILTER_GUIDE}) · "
            f"[ZCC packet-capture guidance]({ZCC_PACKET_CAPTURE_GUIDE})"
        )


def render_packet_capture_workbench(pcaps: List[Dict[str, Any]]) -> None:
    st.markdown("## Packet capture")
    st.caption(
        "Use packet evidence to confirm DNS response failures, reset sender, retransmissions, "
        "TLS alerts, and the exact conversation behind a destination."
    )
    if not pcaps:
        st.info(
            "No packet capture was found. ZCC tunnel-log analysis still works. When DNS, "
            "transport, MTU, or firewall behavior remains unclear, reproduce the problem with "
            "ZCC **More > Troubleshoot > Start Packet Capture**, then export a new support ZIP."
        )
        return

    by_name = {pcap["name"]: pcap for pcap in pcaps}
    selected_name = st.selectbox("Capture", list(by_name))
    selected = by_name[selected_name]
    _render_wireshark_filters(selected)
    st.divider()
    st.markdown("### Follow a matching stream locally")
    suggestions = _suggestions(selected)
    s1, s2 = st.columns([2, 3])
    with s1:
        chosen = st.selectbox(
            "Suggested problem stream",
            ["Choose a detected problem…"] + suggestions,
            disabled=not suggestions,
        )
    with s2:
        manual = st.text_input(
            "Or enter an application, hostname, IP, or port",
            placeholder="e.g. payroll.internal, 10.20.30.40, 443",
        ).strip()
    query = manual or (_query_from_suggestion(chosen) if chosen != "Choose a detected problem…" else "")
    if st.button("Follow matching streams", type="primary", disabled=not query):
        with st.spinner(f"Following streams that reference {query}…"):
            streams = _follow(selected["path"], query)
        st.session_state["pcap_stream_result"] = (selected["path"], query, streams)
    result = st.session_state.get("pcap_stream_result")
    if result and result[0] == selected["path"]:
        st.markdown(f"### Streams matching `{result[1]}`")
        _render_streams(result[2])

    st.divider()
    st.markdown("### Capture health and destinations")
    render_pcap_tab([selected])
