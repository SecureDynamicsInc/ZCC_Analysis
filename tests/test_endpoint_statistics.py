"""Wireshark-format endpoint statistics and DNS answer correlation.

The accounting in these tests was cross-checked against
``tshark -q -z endpoints,ip`` on a generated capture: Tx is what the address
sent, Rx what it received, and Tx + Rx equals Packets on every row.
"""

from __future__ import annotations

import pytest

from zcc_diag.endpoint_intel import (
    GeoRecord,
    address_family,
    build_endpoint_statistics,
    build_resolution_rows,
    combine_hostname_maps,
    resolution_map,
    sort_addresses,
)
from zcc_diag.pcap_review import _bump_endpoint, _format_ipv6, _parse_dns_address_answers


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def _dns_response(name: str, qtype: int, rdata: bytes) -> bytes:
    header = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    question = _qname(name) + qtype.to_bytes(2, "big") + b"\x00\x01"
    answer = (
        b"\xc0\x0c"
        + qtype.to_bytes(2, "big")
        + b"\x00\x01"
        + b"\x00\x00\x00\x3c"
        + len(rdata).to_bytes(2, "big")
        + rdata
    )
    return header + question + answer


# One capture, shaped like the generated fixture that was compared to tshark.
PCAP = {
    "address_stats": {
        "10.0.0.5": {
            "packets": 11, "bytes": 952,
            "tx_packets": 6, "tx_bytes": 425,
            "rx_packets": 5, "rx_bytes": 527,
        },
        "160.79.104.10": {
            "packets": 5, "bytes": 430,
            "tx_packets": 2, "tx_bytes": 228,
            "rx_packets": 3, "rx_bytes": 202,
        },
        "2607:6bc0::10": {
            "packets": 2, "bytes": 148,
            "tx_packets": 1, "tx_bytes": 74,
            "rx_packets": 1, "rx_bytes": 74,
        },
    },
    "transport_stats": {
        "160.79.104.10:tcp/443": {
            "packets": 5, "bytes": 430,
            "tx_packets": 2, "tx_bytes": 228,
            "rx_packets": 3, "rx_bytes": 202,
        },
        "10.0.0.1:udp/53": {
            "packets": 6, "bytes": 522,
            "tx_packets": 3, "tx_bytes": 299,
            "rx_packets": 3, "rx_bytes": 223,
        },
        "2607:6bc0::10:tcp/443": {
            "packets": 2, "bytes": 148,
            "tx_packets": 1, "tx_bytes": 74,
            "rx_packets": 1, "rx_bytes": 74,
        },
    },
    "dns_resolutions": {
        "api.anthropic.com": ["160.79.104.10", "160.79.104.11", "2607:6bc0::10"],
        "claude.ai": ["104.18.32.7"],
    },
    "dns_answers": {
        "160.79.104.10": ["api.anthropic.com"],
        "2607:6bc0::10": ["api.anthropic.com"],
    },
    "sni_to_ips": {},
}


@pytest.fixture(autouse=True)
def _offline_geo(monkeypatch):
    """Never read the workstation's MaxMind files during tests."""
    monkeypatch.setattr(
        "zcc_diag.endpoint_intel.discover_databases", lambda: {}
    )


def test_ipv6_answers_and_packet_addresses_use_one_canonical_form():
    packed = bytes.fromhex("26076bc0" + "00" * 10 + "0010")

    assert _format_ipv6(packed) == "2607:6bc0::10"
    # The DNS path and the frame path must agree, or an IPv6 hostname could
    # never be joined to its endpoint row.
    assert _parse_dns_address_answers(_dns_response("api.anthropic.com", 28, packed)) == [
        ("api.anthropic.com", "2607:6bc0::10")
    ]


def test_endpoint_counters_split_tx_and_rx_by_direction():
    table: dict = {}
    _bump_endpoint(table, "10.0.0.5", sent=True, size=100)
    _bump_endpoint(table, "10.0.0.5", sent=False, size=40)
    _bump_endpoint(table, "10.0.0.5", sent=False, size=60)

    row = table["10.0.0.5"]
    assert row["packets"] == 3
    assert row["bytes"] == 200
    assert (row["tx_packets"], row["tx_bytes"]) == (1, 100)
    assert (row["rx_packets"], row["rx_bytes"]) == (2, 100)
    assert row["tx_packets"] + row["rx_packets"] == row["packets"]


def test_ipv4_rows_match_wireshark_endpoint_columns():
    rows = build_endpoint_statistics([PCAP], scope="IPv4")

    assert [row["Address"] for row in rows] == ["10.0.0.5", "160.79.104.10"]
    top = rows[0]
    assert top["Packets"] == 11 and top["Bytes"] == 952
    assert top["Tx Packets"] == 6 and top["Tx Bytes"] == 425
    assert top["Rx Packets"] == 5 and top["Rx Bytes"] == 527
    for row in rows:
        assert row["Tx Packets"] + row["Rx Packets"] == row["Packets"]
        assert row["Tx Bytes"] + row["Rx Bytes"] == row["Bytes"]


def test_scope_selects_the_matching_wireshark_tab():
    assert [r["Address"] for r in build_endpoint_statistics([PCAP], scope="IPv6")] == [
        "2607:6bc0::10"
    ]
    tcp = build_endpoint_statistics([PCAP], scope="TCP")
    assert {(r["Address"], r["Port"]) for r in tcp} == {
        ("160.79.104.10", 443), ("2607:6bc0::10", 443),
    }
    udp = build_endpoint_statistics([PCAP], scope="UDP")
    assert [(r["Address"], r["Port"]) for r in udp] == [("10.0.0.1", 53)]


def test_endpoint_rows_carry_the_hostname_the_capture_proves():
    rows = {row["Address"]: row for row in build_endpoint_statistics([PCAP], scope="IPv4")}

    assert rows["160.79.104.10"]["Hostname"] == "api.anthropic.com"
    # A client address no DNS answer named stays blank rather than guessing.
    assert rows["10.0.0.5"]["Hostname"] == ""


def test_resolution_map_reads_both_answer_families():
    resolved = resolution_map([PCAP])

    assert resolved["api.anthropic.com"] == [
        "160.79.104.10", "160.79.104.11", "2607:6bc0::10",
    ]
    assert resolved["claude.ai"] == ["104.18.32.7"]


def test_resolution_rows_give_one_row_per_hostname_address_pair():
    rows = build_resolution_rows([PCAP])

    pairs = [(row["Hostname"], row["Address"], row["Family"]) for row in rows]
    assert pairs == [
        ("api.anthropic.com", "160.79.104.10", "IPv4"),
        ("api.anthropic.com", "160.79.104.11", "IPv4"),
        ("api.anthropic.com", "2607:6bc0::10", "IPv6"),
        ("claude.ai", "104.18.32.7", "IPv4"),
    ]
    by_address = {row["Address"]: row for row in rows}
    assert by_address["160.79.104.10"]["Packets"] == 5
    # Answered but never contacted inside the capture: reported as zero traffic,
    # not omitted, so the operator can see the address was offered.
    assert by_address["160.79.104.11"]["Packets"] == 0


def test_hostname_map_merges_forward_and_reverse_dns_evidence():
    forward_only = {
        "dns_resolutions": {"only-forward.example.test": ["198.51.100.7"]},
        "dns_answers": {},
        "sni_to_ips": {},
    }

    assert combine_hostname_maps([forward_only])["198.51.100.7"] == [
        "only-forward.example.test"
    ]


def test_address_family_and_sorting_put_ipv4_before_ipv6():
    assert address_family("10.0.0.5") == "IPv4"
    assert address_family("2607:6bc0::10") == "IPv6"
    assert address_family("not-an-address") == ""
    assert sort_addresses(
        ["2607:6bc0::10", "10.0.0.9", "10.0.0.10", "bogus"]
    ) == ["10.0.0.9", "10.0.0.10", "2607:6bc0::10", "bogus"]


def test_geo_columns_are_filled_from_local_data_when_present(monkeypatch):
    monkeypatch.setattr(
        "zcc_diag.endpoint_intel.lookup_ips",
        lambda ips, databases=None: {
            ip: GeoRecord(
                asn="AS22616", organization="ZSCALER-SJC1",
                provider_class="Zscaler", country="US", city="Los Angeles",
            )
            for ip in ips
        },
    )
    row = build_endpoint_statistics([PCAP], scope="IPv4")[0]

    assert (row["Country"], row["City"]) == ("US", "Los Angeles")
    assert (row["Organization"], row["ASN"]) == ("ZSCALER-SJC1", "AS22616")


# --------------------------------------------------------------------------
# End-to-end: a real capture through the real scanner.
#
# The expected values below are tshark's output for this exact byte sequence
# (`tshark -q -z endpoints,ip`), so a regression in our accounting shows up as
# a disagreement with Wireshark rather than with our own assumptions.
# --------------------------------------------------------------------------

_CLIENT_MAC = bytes.fromhex("020000000001")
_ROUTER_MAC = bytes.fromhex("020000000002")


def _frame(src_mac: bytes, dst_mac: bytes, etype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + etype.to_bytes(2, "big") + payload


def _ipv4(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    import struct
    octets = lambda text: bytes(int(part) for part in text.split("."))
    header = struct.pack(
        "!BBHHHBBH", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0
    ) + octets(src) + octets(dst)
    return header + l4


def _tcp(sport: int, dport: int, seq: int, flags: int, payload: bytes = b"") -> bytes:
    import struct
    return struct.pack(
        "!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 8192, 0, 0
    ) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    import struct
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _pcapng(frames) -> bytes:
    import struct

    def block(btype: int, body: bytes) -> bytes:
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return (
            struct.pack("<II", btype, total) + body + b"\x00" * pad
            + struct.pack("<I", total)
        )

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", 1, 0, 262144))
    for index, frame in enumerate(frames):
        stamp = 1_755_600_000_000_000 + index * 1000
        body = struct.pack(
            "<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, len(frame), len(frame)
        ) + frame
        out += block(0x00000006, body + b"\x00" * ((-len(frame)) % 4))
    return out


def test_scan_pcap_endpoint_totals_match_wireshark(tmp_path):
    client, resolver, server = "10.0.0.5", "10.0.0.1", "160.79.104.10"
    to_router = lambda payload: _frame(_CLIENT_MAC, _ROUTER_MAC, 0x0800, payload)
    to_client = lambda payload: _frame(_ROUTER_MAC, _CLIENT_MAC, 0x0800, payload)

    frames = [
        to_router(_ipv4(client, resolver, 17, _udp(
            51000, 53, b"\x11\x11\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + _qname("api.anthropic.com") + b"\x00\x01\x00\x01"))),
        to_client(_ipv4(resolver, client, 17, _udp(
            53, 51000,
            _dns_response("api.anthropic.com", 1, bytes([160, 79, 104, 10]))))),
        to_router(_ipv4(client, server, 6, _tcp(44001, 443, 1, 0x02))),
        to_client(_ipv4(server, client, 6, _tcp(443, 44001, 100, 0x12))),
        to_router(_ipv4(client, server, 6, _tcp(44001, 443, 2, 0x18, b"x" * 40))),
    ]
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(_pcapng(frames))

    from zcc_diag.pcap_review import scan_pcap
    from zcc_diag.rapid_triage import pcap_summaries_to_ui

    summary = scan_pcap(capture)
    assert summary.parse_errors == []
    assert summary.total_packets == 5
    assert summary.dns_resolutions == {"api.anthropic.com": {"160.79.104.10"}}

    rows = {
        row["Address"]: row
        for row in build_endpoint_statistics(pcap_summaries_to_ui([summary]), scope="IPv4")
    }
    # `tshark -q -z endpoints,ip` on these exact bytes reports:
    #   10.0.0.5        5 packets  372 bytes  tx 3/225  rx 2/147
    #   160.79.104.10   3 packets  202 bytes  tx 1/54   rx 2/148
    server_row = rows["160.79.104.10"]
    assert (server_row["Packets"], server_row["Bytes"]) == (3, 202)
    assert (server_row["Tx Packets"], server_row["Tx Bytes"]) == (1, 54)
    assert (server_row["Rx Packets"], server_row["Rx Bytes"]) == (2, 148)
    assert server_row["Hostname"] == "api.anthropic.com"
    assert (rows[client]["Packets"], rows[client]["Bytes"]) == (5, 372)
    assert (rows[client]["Tx Packets"], rows[client]["Tx Bytes"]) == (3, 225)


def test_grep_keeps_ipv6_transport_rows_for_a_matching_hostname():
    from zcc_diag.pcap_review import PcapSummary
    from pathlib import Path

    summary = PcapSummary(path=Path("sample.pcapng"))
    summary.dns_answers = {"2607:6bc0::10": {"api.anthropic.com"}}
    summary.address_stats = {"2607:6bc0::10": dict.fromkeys(["packets"], 2)}
    summary.transport_stats = {"2607:6bc0::10:tcp/443": dict.fromkeys(["packets"], 2)}

    filtered = summary.grep("anthropic")

    # rsplit on the last colon, so an IPv6 key is not cut at "2607".
    assert "2607:6bc0::10:tcp/443" in filtered.transport_stats
    assert "2607:6bc0::10" in filtered.address_stats


def test_scope_counts_avoid_building_full_rows():
    from zcc_diag.endpoint_intel import ENDPOINT_SCOPES, endpoint_scope_counts

    counts = endpoint_scope_counts([PCAP])

    assert counts == {"IPv4": 2, "IPv6": 1, "TCP": 2, "UDP": 1}
    # Counts and rows must never disagree, or the selector labels lie.
    for scope in ENDPOINT_SCOPES:
        assert counts[scope] == len(build_endpoint_statistics([PCAP], scope=scope))
