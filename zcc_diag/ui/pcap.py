"""
Pcap explorer — DNS / SNI / IP / port view PLUS Phase 30 network-
health analytics (top talkers, TCP resets, retransmits, DNS NXDOMAIN,
TLS handshake failures, connection timeline).

ZCC only writes ``.pcapng`` files when explicitly triggered (e.g. a
``zcc collect`` with the pcap flag, or a SR-driven capture). Most
bundles don't have any, in which case the module collapses to a
single "no pcaps in this bundle" info card.

Each pcap that is present gets:

  1. A health-summary chip strip at the top showing transport-level
     error counts at a glance — RST, retransmit, NXDOMAIN, TLS fatal.
     If all four are zero, that's surfaced too (network plumbing
     looks healthy).
  2. The classic 4-table view: DNS queries, TLS SNI, destination
     IPs, endpoints. Substring filter scopes all four.
  3. Phase 30 health sections:
       - Top Talkers by Bytes
       - TCP Errors (resets per direction, retransmits per endpoint)
       - DNS Failures (NXDOMAIN + other non-zero RCODEs)
       - TLS Handshake Failures (Alert records by type)
       - Connection Timeline (top-N longest-lived flows)

**Provenance principle**: every Phase 30 metric ties to a specific
packet field in the capture. The UI caption tells the engineer where
the data came from. We never count an inferred or estimated value
here — every number is a real packet observation. See [[feedback-
provenance-first-ui]].
"""

from __future__ import annotations

from typing import Any, Dict, List

import streamlit as st

from zcc_diag.endpoint_intel import (
    hostname_map,
    lookup_ips,
    provider_class,
    split_endpoint,
)


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def _fmt_bytes_simple(n: int) -> str:
    """Render a byte count as ``"1.2 MB"`` / ``"34 KB"`` / ``"512 B"``.
    Triage-grade — uses 1024-base because operators usually compare
    against MTU / firewall packet caps in binary units."""
    n = int(n or 0)
    if n < 1024:
        return f"{n} B"
    kb = n / 1024.0
    if kb < 1024:
        return f"{kb:.1f} KB"
    mb = kb / 1024.0
    if mb < 1024:
        return f"{mb:.1f} MB"
    gb = mb / 1024.0
    return f"{gb:.2f} GB"


# --------------------------------------------------------------------
# Section renderers
# --------------------------------------------------------------------


def _render_health_chips(p: Dict[str, Any]) -> None:
    """Top-of-pcap strip: RST / retransmit / NXDOMAIN / TLS-alert
    counts. Each chip is a real-packet count with the source field
    in the help text.

    Provenance: every count is the sum of a dict populated by the
    packet parser — see PcapSummary fields documented in
    pcap_review.py.
    """
    n_rst = sum((p.get("tcp_resets") or {}).values())
    n_retx = sum((p.get("tcp_retransmits") or {}).values())
    n_nx = sum((p.get("dns_nxdomain") or {}).values())
    # Only count FATAL alerts in the chip — warnings (close_notify)
    # are normal and would pollute the signal.
    n_tls_fatal = 0
    for label, count in (p.get("tls_alerts") or {}).items():
        if label.startswith("fatal/"):
            n_tls_fatal += count

    healthy = (n_rst == 0 and n_retx == 0 and n_nx == 0 and n_tls_fatal == 0)
    if healthy:
        st.success(
            "**No explicit transport failure observed.** No TCP RSTs, no "
            "retransmits, no DNS NXDOMAIN responses, and no fatal "
            "TLS alerts were found in this capture window. This does not "
            "rule out uncaptured loss, latency, MTU, routing, or "
            "application-layer issues.",
            icon="✅",
        )
        return

    chip_cols = st.columns(4)
    chip_cols[0].metric(
        "TCP RST",
        f"{n_rst:,}",
        delta=("sent in capture" if n_rst else "none"),
        delta_color="inverse" if n_rst else "off",
        help=(
            "Count of TCP packets with the RST flag (header byte 13, "
            "bit 0x04) set. Sender, timing, and stream state determine "
            "whether a reset is expected teardown or evidence of a "
            "failed connection."
        ),
    )
    chip_cols[1].metric(
        "Retransmits",
        f"{n_retx:,}",
        delta=("suspected dupes" if n_retx else "none"),
        delta_color="inverse" if n_retx else "off",
        help=(
            "Count of TCP segments whose (seq + payload_len) is "
            "<= the high-water mark for that direction. Wireshark's "
            "standard retransmission heuristic. High counts indicate "
            "lossy path or congestion."
        ),
    )
    chip_cols[2].metric(
        "DNS NXDOMAIN+",
        f"{n_nx:,}",
        delta=("failures" if n_nx else "none"),
        delta_color="inverse" if n_nx else "off",
        help=(
            "Count of DNS responses with a non-zero RCODE field "
            "(byte 3, bottom 4 bits). Includes NXDOMAIN (3), "
            "SERVFAIL (2), REFUSED (5), etc. — see the DNS Failures "
            "section below for the breakdown."
        ),
    )
    chip_cols[3].metric(
        "TLS fatal alerts",
        f"{n_tls_fatal:,}",
        delta=("handshakes aborted" if n_tls_fatal else "none"),
        delta_color="inverse" if n_tls_fatal else "off",
        help=(
            "TLS Alert records (record type 0x15) with level=2 "
            "(fatal). Common codes: 40 handshake_failure, 48 "
            "unknown_ca, 70 protocol_version, 112 unrecognized_name."
        ),
    )


def _render_top_talkers(p: Dict[str, Any], pat: str) -> None:
    """Top remote endpoints by total bytes. Attribution: the side of
    the flow with the lower port number is treated as the 'server'.
    This way request + response bytes land on the same row.

    Provenance: bytes are summed from the IPv4/IPv6 ``total_len``
    field on every parsed packet — IPv4 bytes 2-3, IPv6 bytes 4-5
    plus the 40-byte fixed header.
    """
    bpe = p.get("bytes_per_endpoint") or {}
    if pat:
        bpe = {k: v for k, v in bpe.items() if pat in k.lower()}
    if not bpe:
        st.caption(
            "_Top talkers_: no data " +
            ("(no matches for filter)" if pat else
             "(pcap had no parseable IP packets)")
        )
        return

    rows = []
    selected = list(bpe.items())[:20]
    names = hostname_map(p)
    endpoint_ips = [split_endpoint(endpoint)[0] for endpoint, _ in selected]
    geo = lookup_ips(endpoint_ips)
    for ep, total_bytes in selected:
        ip, _proto, _port = split_endpoint(ep)
        record = geo.get(ip)
        rows.append({
            "endpoint": ep,
            "hostname": ", ".join(names.get(ip, [])[:3]),
            "owner": record.organization if record else "",
            "provider": (
                record.provider_class if record else provider_class("", ip)
            ),
            "asn": record.asn if record else "",
            "bytes": _fmt_bytes_simple(total_bytes),
            "bytes_raw": int(total_bytes),
        })
    st.markdown("**Top talkers by bytes**")
    st.caption(
        "Sum of IP `total_len` per remote endpoint (server side = "
        "lower port). Direction-agnostic — request + response bytes "
        "merged onto one row. Hostnames are correlated only from captured DNS "
        "answers or TLS SNI; ownership uses local MaxMind data. Top 20 shown."
    )
    st.dataframe(
        rows, hide_index=True, use_container_width=True,
        height=min(450, 38 + 35 * min(len(rows), 12)),
        column_config={
            "endpoint": st.column_config.TextColumn(
                "Remote endpoint (ip:proto/port)", width="large"
            ),
            "hostname": st.column_config.TextColumn(
                "Captured hostname", width="large",
                help="Hostname observed in a DNS answer or TLS SNI for this IP.",
            ),
            "owner": st.column_config.TextColumn(
                "Network owner", width="large",
                help="Local MaxMind GeoLite2 ASN organization, when available.",
            ),
            "provider": st.column_config.TextColumn(
                "Provider class", width="medium",
                help="Convenience classification derived from the MaxMind ASN organization.",
            ),
            "bytes": st.column_config.TextColumn(
                "Bytes (human)", width="small"
            ),
            "bytes_raw": st.column_config.NumberColumn(
                "Bytes (raw)",
                help="Total IP-payload bytes summed across both "
                     "directions for this endpoint. Source: IP "
                     "total_len field (IPv4 bytes 2-3 / IPv6 bytes "
                     "4-5 + 40).",
            ),
        },
    )


def _render_tcp_errors(p: Dict[str, Any], pat: str) -> None:
    """TCP RSTs (who sent to whom) + retransmits (per endpoint).

    Provenance:
      - RST: TCP header byte 13, bit 0x04. Key shows direction so
        the operator can tell client-RST from server-RST.
      - Retransmit: a TCP segment whose seq+payload_len is <= the
        running watermark for that (flow, direction). Wireshark's
        "Retransmission" heuristic, no SACK refinement.
    """
    resets = p.get("tcp_resets") or {}
    retx = p.get("tcp_retransmits") or {}
    if pat:
        resets = {k: v for k, v in resets.items() if pat in k.lower()}
        retx = {k: v for k, v in retx.items() if pat in k.lower()}

    if not resets and not retx:
        st.caption(
            "_TCP errors_: none " +
            ("(no matches for filter)" if pat else
             "in this capture window")
        )
        return

    st.markdown("**TCP errors**")
    cols = st.columns(2)

    with cols[0]:
        st.caption("**TCP RST** — sender to receiver")
        if resets:
            rst_rows = [
                {"direction": k, "rst_packets": v}
                for k, v in list(resets.items())[:15]
            ]
            st.dataframe(
                rst_rows, hide_index=True, use_container_width=True,
                height=min(380, 38 + 35 * min(len(rst_rows), 10)),
                column_config={
                    "direction": st.column_config.TextColumn(
                        "src → dst", width="large",
                        help="Direction of the RST: who sent it. "
                             "If the sender is a remote server during "
                             "handshake, suspect firewall block.",
                    ),
                    "rst_packets": st.column_config.NumberColumn(
                        "Packets",
                        help="TCP packets with the RST flag set "
                             "(header byte 13, bit 0x04).",
                    ),
                },
            )
        else:
            st.caption("(none)")

    with cols[1]:
        st.caption("**Retransmits** — by destination endpoint")
        if retx:
            retx_rows = [
                {"endpoint": k, "retransmits": v}
                for k, v in list(retx.items())[:15]
            ]
            st.dataframe(
                retx_rows, hide_index=True, use_container_width=True,
                height=min(380, 38 + 35 * min(len(retx_rows), 10)),
                column_config={
                    "endpoint": st.column_config.TextColumn(
                        "Endpoint", width="large",
                        help="Server-side endpoint of the flow. "
                             "Retransmits attributed here regardless "
                             "of direction.",
                    ),
                    "retransmits": st.column_config.NumberColumn(
                        "Count",
                        help="TCP segments where seq+payload_len was "
                             "<= the watermark for that direction.",
                    ),
                },
            )
        else:
            st.caption("(none)")


def _render_dns_failures(p: Dict[str, Any], pat: str) -> None:
    """DNS responses with non-zero RCODE. Each row shows the qname
    and the rcode label — NXDOMAIN (3), SERVFAIL (2), REFUSED (5),
    etc.

    Provenance: DNS header byte 3, bottom 4 bits (RCODE), on packets
    where byte 2 bit 0x80 (QR flag) is set.
    """
    nx = p.get("dns_nxdomain") or {}
    if pat:
        nx = {k: v for k, v in nx.items() if pat in k.lower()}

    if not nx:
        st.caption(
            "_DNS failures_: none " +
            ("(no matches for filter)" if pat else
             "(every DNS response in this capture had RCODE=0)")
        )
        return

    st.markdown("**DNS failures** (NXDOMAIN, SERVFAIL, REFUSED, …)")
    st.caption(
        "DNS responses with non-zero RCODE. NXDOMAIN means the name "
        "doesn't exist; SERVFAIL means the resolver failed to answer; "
        "REFUSED means the server declined to answer. Each row shows "
        "the query name and rcode."
    )
    # PII redaction — DNS qnames can identify the user's tenant.
    from zcc_diag.ui.redact import redact
    rows = []
    for key, count in list(nx.items())[:30]:
        # key is "qname  [RCODE_NAME]"; split for redact-on-qname-only.
        if "  [" in key and key.endswith("]"):
            qname, rname = key.rsplit("  [", 1)
            rname = rname.rstrip("]")
        else:
            qname, rname = key, ""
        rows.append({
            "qname": redact(qname),
            "rcode": rname,
            "responses": count,
        })
    st.dataframe(
        rows, hide_index=True, use_container_width=True,
        height=min(420, 38 + 35 * min(len(rows), 12)),
        column_config={
            "qname": st.column_config.TextColumn(
                "Query name", width="large",
            ),
            "rcode": st.column_config.TextColumn(
                "RCODE",
                help="Bottom 4 bits of DNS header byte 3 on a "
                     "response packet.",
            ),
            "responses": st.column_config.NumberColumn(
                "Response packets",
                help="Count of DNS responses with this (qname, rcode) "
                     "combination.",
            ),
        },
    )


def _render_tls_failures(p: Dict[str, Any], pat: str) -> None:
    """TLS Alert records seen in the capture. Fatal alerts mean the
    handshake aborted; warnings (close_notify) are normal teardown
    signals and shown separately so the operator can distinguish.

    Provenance: TLS record type byte = 0x15 (Alert). Level byte
    (1=warning, 2=fatal) and description byte are at offsets 5 and
    6 of the record.
    """
    alerts = p.get("tls_alerts") or {}
    alert_eps = p.get("tls_alert_endpoints") or {}
    if pat:
        alerts = {k: v for k, v in alerts.items() if pat in k.lower()}
        alert_eps = {k: v for k, v in alert_eps.items() if pat in k.lower()}

    fatal_alerts = {k: v for k, v in alerts.items() if k.startswith("fatal/")}
    warn_alerts = {k: v for k, v in alerts.items() if not k.startswith("fatal/")}

    if not alerts:
        st.caption(
            "_TLS handshake failures_: none " +
            ("(no matches for filter)" if pat else
             "(no Alert records seen in this capture)")
        )
        return

    st.markdown("**TLS handshake / Alert records**")
    st.caption(
        "TLS records with content type 0x15. Fatal alerts (level=2) "
        "abort the handshake — common causes: cert validation, SNI "
        "policy mismatch, unsupported TLS version. Warning alerts "
        "(level=1, close_notify) are normal teardown."
    )

    cols = st.columns(2)
    with cols[0]:
        st.caption("**Alert types seen**")
        if alerts:
            rows = [
                {"alert": k, "records": v}
                for k, v in list(alerts.items())[:15]
            ]
            st.dataframe(
                rows, hide_index=True, use_container_width=True,
                height=min(380, 38 + 35 * min(len(rows), 10)),
                column_config={
                    "alert": st.column_config.TextColumn(
                        "Level / description", width="large",
                        help="level (fatal|warning) / RFC 5246 §A.3 "
                             "or RFC 8446 §6 description name.",
                    ),
                    "records": st.column_config.NumberColumn(
                        "Records",
                        help="Count of TLS Alert records of this "
                             "(level, description) pair.",
                    ),
                },
            )
        else:
            st.caption("(none)")
    with cols[1]:
        st.caption("**Endpoints with alerts**")
        if alert_eps:
            ep_rows = [
                {"endpoint": k, "alerts": v}
                for k, v in list(alert_eps.items())[:15]
            ]
            st.dataframe(
                ep_rows, hide_index=True, use_container_width=True,
                height=min(380, 38 + 35 * min(len(ep_rows), 10)),
                column_config={
                    "endpoint": st.column_config.TextColumn(
                        "Server endpoint", width="large",
                        help="Server side (lower port) of the flow "
                             "carrying the Alert. Cross-reference "
                             "with SNI hosts to identify the service.",
                    ),
                    "alerts": st.column_config.NumberColumn(
                        "Records",
                        help="Count of Alert records on flows to or "
                             "from this endpoint.",
                    ),
                },
            )
        else:
            st.caption("(none)")

    if fatal_alerts and not warn_alerts:
        st.warning(
            f"All {sum(fatal_alerts.values())} alert records were "
            "FATAL — every TLS handshake in this capture window "
            "aborted. Cross-reference the failing endpoints against "
            "the SNI hosts table.",
            icon="⚠️",
        )


def _render_connection_timeline(p: Dict[str, Any], pat: str) -> None:
    """Top flows by total bytes, with their first/last timestamps
    and lifetime. Lets the operator see who was active when in the
    capture window.

    Provenance: per-flow first_ts and last_ts are the timestamps of
    the first and last packets matching that flow_key (canonical
    endpoint pair). bytes = sum of IP total_len across both
    directions.
    """
    flows = p.get("flow_intervals") or []
    if pat:
        flows = [f for f in flows if pat in (f.get("flow") or "").lower()]

    if not flows:
        st.caption(
            "_Connection timeline_: no flows " +
            ("matching filter" if pat else "parsed from this capture")
        )
        return

    st.markdown("**Connection timeline** — flows sorted by bytes")
    st.caption(
        "Each row is one flow (canonical endpoint pair). first/last "
        "timestamps come from the actual first/last packet of that "
        "flow in the capture. Lifetime is end−start; bytes is the "
        "sum of IP total_len across both directions."
    )
    rows = []
    for f in flows[:30]:
        ts_first = f.get("first_ts")
        ts_last = f.get("last_ts")
        rows.append({
            "flow": f.get("flow") or "—",
            "first_seen": ts_first.strftime("%H:%M:%S.%f")[:-3] if ts_first else "—",
            "last_seen": ts_last.strftime("%H:%M:%S.%f")[:-3] if ts_last else "—",
            "lifetime_s": f"{f.get('duration_s', 0):.2f} s",
            "bytes": _fmt_bytes_simple(f.get("bytes", 0)),
        })
    st.dataframe(
        rows, hide_index=True, use_container_width=True,
        height=min(500, 38 + 35 * min(len(rows), 15)),
        column_config={
            "flow": st.column_config.TextColumn(
                "Flow (endpoint A ↔ endpoint B)", width="large",
            ),
            "first_seen": st.column_config.TextColumn(
                "First packet",
                help="Timestamp of the first packet in this flow.",
            ),
            "last_seen": st.column_config.TextColumn(
                "Last packet",
                help="Timestamp of the last packet in this flow.",
            ),
            "lifetime_s": st.column_config.TextColumn(
                "Lifetime",
                help="last_seen − first_seen. Real packet observation, "
                     "not a connect/disconnect estimate.",
            ),
            "bytes": st.column_config.TextColumn(
                "Bytes",
                help="Sum of IP total_len across both directions.",
            ),
        },
    )


# --------------------------------------------------------------------
# Module entry
# --------------------------------------------------------------------


def render_pcap_tab(pcaps: List[Dict[str, Any]]) -> None:
    """Pcap explorer with health summary + Phase 30 analytics."""
    if not pcaps:
        st.info(
            "This bundle didn't include any packet captures. ZCC only "
            "writes .pcapng when explicitly triggered; that's normal "
            "for most bundles. Log-based triage still works.",
        )
        return

    pattern = st.text_input(
        "Filter pcap data by substring (matches DNS / SNI / dest IP / "
        "endpoint port / qname / flow)",
        placeholder="e.g. remotedesktop, salesforce, 198.14, 443, tcp/445",
    )
    pat = pattern.strip().lower() if pattern else ""

    for p in pcaps:
        st.subheader(p["name"])
        st.caption(
            f"{p['total_packets']} packets · "
            f"{p['ts_first']} → {p['ts_last']} · "
            f"{p['duration_s']:.0f}s"
        )

        # ---- Phase 30 health summary ----
        _render_health_chips(p)

        # ---- Phase 30 analytics sections (collapsed by default
        # except top talkers which is the most-used) ----
        with st.expander("Top talkers by bytes", expanded=True):
            _render_top_talkers(p, pat)

        # Auto-expand TCP errors / DNS failures / TLS failures
        # if any are present — the operator's eye should land
        # there when something is wrong.
        has_tcp_err = bool(
            (p.get("tcp_resets") or {}) or (p.get("tcp_retransmits") or {})
        )
        with st.expander(
            "TCP errors (RST + retransmit)",
            expanded=has_tcp_err,
        ):
            _render_tcp_errors(p, pat)

        has_dns_fail = bool(p.get("dns_nxdomain") or {})
        with st.expander(
            "DNS failures (NXDOMAIN, SERVFAIL, …)",
            expanded=has_dns_fail,
        ):
            _render_dns_failures(p, pat)

        has_tls_fail = bool(p.get("tls_alerts") or {})
        with st.expander(
            "TLS handshake alerts",
            expanded=has_tls_fail,
        ):
            _render_tls_failures(p, pat)

        with st.expander("Connection timeline", expanded=False):
            _render_connection_timeline(p, pat)

        # ---- Classic per-pcap dataframes (DNS / SNI / IPs / endpoints) ----
        st.markdown("**Raw tables**")
        for key, label in (
            ("dns", "DNS queries"),
            ("sni", "TLS SNI hosts"),
            ("dest_ips", "Destination IPs"),
            ("endpoints",
             "Endpoints (ip:proto/port)  — searchable by port number"),
        ):
            items = list((p.get(key) or {}).items())
            if pat:
                items = [(k, v) for k, v in items if pat in k.lower()]
            with st.expander(
                f"{label}  ({len(items)} entries)",
                expanded=bool(pat) and bool(items),
            ):
                if items:
                    # PII redaction. DNS queries + TLS SNI hosts + dest
                    # IPs are customer-side identifiers — the redact()
                    # toggle masks them when the engineer wants to
                    # share a screenshot externally. Zscaler-infra
                    # hosts (zscaler.net, zpath.net) are allowlisted
                    # inside redact() so they stay visible.
                    from zcc_diag.ui.redact import redact
                    if key == "dns":
                        # A query name on its own cannot be joined to an
                        # endpoint row. Carrying the A and AAAA answers the
                        # resolver actually returned makes the DNS table and
                        # the address tables the same evidence.
                        resolutions = p.get("dns_resolutions") or {}
                        rows = []
                        for host, count in items:
                            answers = [str(ip) for ip in (resolutions.get(host) or [])]
                            v4 = [ip for ip in answers if ":" not in ip]
                            v6 = [ip for ip in answers if ":" in ip]
                            rows.append({
                                "value": redact(host),
                                "packets": count,
                                "IPv4 answers": ", ".join(redact(ip) for ip in v4),
                                "IPv6 answers": ", ".join(redact(ip) for ip in v6),
                                "answers": len(answers),
                            })
                    else:
                        rows = [
                            {"value": redact(k), "packets": v}
                            for k, v in items
                        ]
                    st.dataframe(
                        rows, hide_index=True, use_container_width=True,
                        height=min(400, 38 + 35 * min(len(rows), 10)),
                    )
                    if key == "dns":
                        st.caption(
                            "Answers come only from A and AAAA records observed in this "
                            "capture. An empty cell means no address answer was captured "
                            "for that name — a cached lookup, a DNS-over-HTTPS or "
                            "DNS-over-TLS resolution, or a response outside the capture "
                            "window leaves no record here."
                        )
                else:
                    st.caption("(no matches)" if pat else "(none)")


def module_pcap(data: Dict[str, Any]) -> None:
    """Pcap explorer module — only shown if pcaps exist."""
    pcaps = data.get("pcaps") or []
    if not pcaps:
        st.info(
            "This bundle didn't include any packet captures. ZCC "
            "only writes .pcapng when explicitly triggered; that's "
            "normal for most bundles. Log-based triage still works.",
        )
        return
    render_pcap_tab(pcaps)


# Backwards-compat aliases.
_render_pcap_tab = render_pcap_tab
_module_pcap = module_pcap
