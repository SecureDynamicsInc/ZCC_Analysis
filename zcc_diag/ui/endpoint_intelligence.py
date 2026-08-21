"""Problem-endpoint table with local-only hostname and MaxMind enrichment."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Mapping, Sequence

import streamlit as st

from zcc_diag.endpoint_intel import (
    ENDPOINT_SCOPES,
    build_endpoint_statistics,
    build_resolution_rows,
    combine_hostname_maps,
    endpoint_scope_counts,
    lookup_ips,
    split_endpoint,
)
from zcc_diag.ui.geoip_status import (
    readiness,
    render_setup_panel,
    render_status_line,
)


def _sum_maps(pcaps: Sequence[Mapping[str, Any]], key: str) -> Dict[str, int]:
    totals: Dict[str, int] = defaultdict(int)
    for pcap in pcaps:
        for endpoint, count in (pcap.get(key) or {}).items():
            totals[endpoint] += int(count or 0)
    return dict(totals)


def build_endpoint_rows(pcaps: Sequence[Mapping[str, Any]], *, include_healthy: bool = False) -> List[dict]:
    bytes_by = _sum_maps(pcaps, "bytes_per_endpoint")
    packets_by = _sum_maps(pcaps, "endpoints")
    syns = _sum_maps(pcaps, "tcp_syns")
    syn_acks = _sum_maps(pcaps, "tcp_syn_acks")
    resets = _sum_maps(pcaps, "tcp_reset_endpoints")
    retransmits = _sum_maps(pcaps, "tcp_retransmits")
    tls_alerts = _sum_maps(pcaps, "tls_alert_endpoints")
    names = combine_hostname_maps(pcaps)
    endpoints = set(bytes_by) | set(syns) | set(syn_acks) | set(resets) | set(retransmits) | set(tls_alerts)
    ips = [split_endpoint(endpoint)[0] for endpoint in endpoints]
    geo = lookup_ips(ips)

    rows: List[dict] = []
    for endpoint in endpoints:
        ip, proto, port = split_endpoint(endpoint)
        unanswered = max(syns.get(endpoint, 0) - syn_acks.get(endpoint, 0), 0)
        endpoint_resets = resets.get(endpoint, 0)
        endpoint_retx = retransmits.get(endpoint, 0)
        endpoint_tls = tls_alerts.get(endpoint, 0)
        issues = []
        if unanswered:
            issues.append(f"{unanswered} SYN without captured SYN-ACK")
        if endpoint_resets:
            issues.append(f"{endpoint_resets} TCP reset")
        if endpoint_retx:
            issues.append(f"{endpoint_retx} retransmit")
        if endpoint_tls:
            issues.append(f"{endpoint_tls} TLS alert")
        if not issues and not include_healthy:
            continue
        record = geo.get(ip)
        rows.append({
            "Status": "Investigate" if issues else "Observed",
            "IP": ip,
            "Port": port,
            "Protocol": proto.upper() if proto else "",
            "Hostname": ", ".join(names.get(ip, [])[:3]),
            "Issue signals": "; ".join(issues) if issues else "No explicit failure signal",
            "SYN": syns.get(endpoint, 0),
            "SYN-ACK": syn_acks.get(endpoint, 0),
            "RST": endpoint_resets,
            "Retransmits": endpoint_retx,
            "TLS alerts": endpoint_tls,
            "Bytes": bytes_by.get(endpoint, 0),
            "Packets to endpoint": packets_by.get(endpoint, 0),
            "Network owner": record.organization if record else "",
            "Provider class": record.provider_class if record else "",
            "ASN": record.asn if record else "",
            "Country": record.country if record else "",
            "City": record.city if record else "",
        })
    return sorted(
        rows,
        key=lambda row: (
            row["Status"] != "Investigate",
            -(row["RST"] + row["Retransmits"] + row["TLS alerts"] + max(row["SYN"] - row["SYN-ACK"], 0)),
            -row["Bytes"],
            row["IP"],
        ),
    )


def _render_maxmind_manager() -> None:
    """Readiness line plus the shared setup panel from ``geoip_status``.

    The landing page shows the same state; both drive one implementation so the
    two views can never disagree about whether ownership is available.
    """
    ready = readiness().ready
    render_status_line(prefix="Endpoint ownership")
    if not ready:
        st.warning(
            "ASN ownership is unavailable, so the table below identifies endpoints by "
            "address only. Save the free **GeoLite2 ASN** database to attribute them."
        )
    with st.expander("Manage local MaxMind databases", expanded=not ready):
        render_setup_panel(key_prefix="endpoints", show_heading=False)


def _render_endpoint_statistics(pcaps: Sequence[Mapping[str, Any]]) -> None:
    """Wireshark's Endpoints view over the bundled captures.

    A segmented control rather than ``st.tabs``: a dataframe first laid out
    inside an inactive tab measures zero width and renders as a collapsed
    column, and tabs would also build every scope's rows — MaxMind lookups
    included — on each rerun instead of only the one being read.
    """
    st.markdown("### Endpoint statistics")
    st.caption(
        "The same columns as Wireshark's **Statistics → Endpoints**, summed across "
        "every capture in this bundle, with the hostname this capture proves and "
        "local MaxMind ASN context. Tx is what the address sent, Rx what it "
        "received, so Tx + Rx equals Packets. Bytes are captured frame lengths."
    )
    counts = endpoint_scope_counts(pcaps)
    labels = [f"{scope} · {counts[scope]}" for scope in ENDPOINT_SCOPES]
    chosen_label = st.segmented_control(
        "Endpoint scope",
        labels,
        default=labels[0],
        key="endpoint_statistics_scope",
        help="IPv4 and IPv6 list addresses. TCP and UDP list address and port, as Wireshark does.",
    ) or labels[0]
    scope = ENDPOINT_SCOPES[labels.index(chosen_label)]

    rows = build_endpoint_statistics(pcaps, scope=scope)
    if not rows:
        st.caption(f"No {scope} endpoints were observed in the bundled captures.")
    else:
        column_config = {
            "Address": st.column_config.TextColumn(width="medium"),
            "Hostname": st.column_config.TextColumn(width="large"),
            "Organization": st.column_config.TextColumn(width="large"),
            "Packets": st.column_config.NumberColumn(format="localized"),
            "Bytes": st.column_config.NumberColumn(format="localized"),
            "Tx Packets": st.column_config.NumberColumn(format="localized"),
            "Tx Bytes": st.column_config.NumberColumn(format="localized"),
            "Rx Packets": st.column_config.NumberColumn(format="localized"),
            "Rx Bytes": st.column_config.NumberColumn(format="localized"),
        }
        if scope in {"TCP", "UDP"}:
            column_config["Port"] = st.column_config.NumberColumn(
                width="small", format="%d",
            )
        st.dataframe(
            rows,
            hide_index=True,
            use_container_width=True,
            height=min(650, 40 + 35 * min(len(rows), 17)),
            column_config=column_config,
        )
    if not readiness().ready:
        st.caption(
            "Country, City, and Organization stay empty until a local GeoLite2 "
            "database is saved. Every other column comes from the capture itself."
        )
    st.caption(
        "Ethernet endpoints are not listed: MAC addresses are not extracted, they "
        "carry no ASN, geography, or hostname context, and they would add a "
        "hardware identifier to exports."
    )


def _render_dns_resolutions(pcaps: Sequence[Mapping[str, Any]]) -> None:
    """Captured hostnames with the addresses they actually resolved to."""
    st.markdown("### Captured hostnames and resolved addresses")
    rows = build_resolution_rows(pcaps)
    if not rows:
        st.caption(
            "No A or AAAA answer was captured. Encrypted DNS (DoH/DoT), a cached "
            "lookup, or a resolver exchange outside the capture window leaves no "
            "address answer to record."
        )
        return

    families = sorted({row["Family"] for row in rows})
    hosts = len({row["Hostname"] for row in rows})
    st.caption(
        f"{hosts:,} hostname(s) resolved to {len(rows):,} address(es) "
        f"({', '.join(families)}) in the bundled captures. One row per "
        "hostname/address pair, because owner and geography can differ between "
        "the addresses behind one name."
    )
    chosen = st.segmented_control(
        "Address family",
        ["All", *families],
        default="All",
        key="dns_resolution_family",
    ) or "All"
    visible = rows if chosen == "All" else [row for row in rows if row["Family"] == chosen]
    st.dataframe(
        visible,
        hide_index=True,
        use_container_width=True,
        height=min(650, 40 + 35 * min(len(visible), 17)),
        column_config={
            "Hostname": st.column_config.TextColumn(width="large"),
            "Address": st.column_config.TextColumn(width="medium"),
            "Family": st.column_config.TextColumn(width="small"),
            "Organization": st.column_config.TextColumn(width="large"),
            "Packets": st.column_config.NumberColumn(format="localized"),
            "Bytes": st.column_config.NumberColumn(format="localized"),
        },
    )
    st.caption(
        "Addresses come only from A and AAAA records observed in the capture; no "
        "reverse DNS or external lookup is performed. Packets and Bytes count all "
        "traffic to and from that address in the capture, which may include flows "
        "unrelated to this hostname when an address is shared."
    )


def render_endpoint_intelligence(pcaps: Sequence[Mapping[str, Any]]) -> None:
    st.markdown("## Problem endpoints")
    st.caption(
        "Destinations with packet-level connection signals, correlated to captured "
        "DNS/SNI names and optional local MaxMind ASN ownership."
    )
    _render_maxmind_manager()
    if not pcaps:
        st.info(
            "No packet capture was included. Reproduce the issue with ZCC packet capture "
            "enabled to build the endpoint table; tunnel-log conclusions remain available."
        )
        return
    st.markdown("### Endpoints with a connection signal")
    include_healthy = st.toggle(
        "Show endpoints without an explicit failure signal",
        value=False,
        key="endpoint_include_healthy",
    )
    rows = build_endpoint_rows(pcaps, include_healthy=include_healthy)
    if not rows:
        st.success(
            "No endpoint had an unmatched SYN, TCP reset, suspected retransmission, or TLS alert "
            "in the selected capture window. Turn on the toggle to review all observed endpoints."
        )
    else:
        st.dataframe(
            rows,
            hide_index=True,
            use_container_width=True,
            height=min(650, 40 + 35 * min(len(rows), 17)),
            column_config={
                "IP": st.column_config.TextColumn(width="medium"),
                "Hostname": st.column_config.TextColumn(width="large"),
                "Issue signals": st.column_config.TextColumn(width="large"),
                "Network owner": st.column_config.TextColumn(width="large"),
                "Bytes": st.column_config.NumberColumn(format="localized"),
            },
        )
        st.caption(
            "SYN minus SYN-ACK is limited to this capture window and can be affected by capture "
            "start/end boundaries. Hostnames come only from captured DNS answers or TLS SNI. "
            "ASN and geography come only from local MaxMind files."
        )

    st.divider()
    _render_endpoint_statistics(pcaps)
    st.divider()
    _render_dns_resolutions(pcaps)
