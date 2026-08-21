"""
Synthetic-data test for ``zcc_diag.pcap_review``.

We build a tiny pcapng file from raw bytes in a temp directory and
walk the parser over it. This pins:

  - the pcapng block walker (SHB / IDB / EPB)
  - Ethernet/IPv4/UDP/TCP framing
  - DNS qname extraction
  - TLS ClientHello SNI extraction
  - PcapSummary.grep() filter view
  - PcapSummary.covers() window check
  - render_summary() and render_correlation()

Run: ``python test_pcap_review.py``

No external dependencies.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from zcc_diag.pcap_review import (
    PcapSummary,
    render_correlation,
    render_summary,
    scan_pcap,
)


# --------------------------------------------------------------------
# Synthetic pcapng builder
# --------------------------------------------------------------------


def _shb() -> bytes:
    """Section Header Block (little-endian, no options)."""
    # block_type(4) + total_length(4) + BOM(4) + major(2) + minor(2)
    # + section_length(8) + total_length(4)
    body = struct.pack("<IHHQ", 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF)
    total = 4 + 4 + len(body) + 4
    return struct.pack("<II", 0x0A0D0D0A, total) + body + struct.pack("<I", total)


def _idb() -> bytes:
    """Interface Description Block, link-type 1 (Ethernet), snaplen 65535,
    with if_tsresol=6 (microseconds)."""
    # body: linktype(2) + reserved(2) + snaplen(4)
    body = struct.pack("<HHI", 1, 0, 65535)
    # option: if_tsresol code=9, len=1, value=6 (10^6 = microseconds)
    body += struct.pack("<HHB", 9, 1, 6) + b"\x00\x00\x00"  # padded to 4
    # opt_endofopt
    body += struct.pack("<HH", 0, 0)
    # pad body to 4-byte boundary
    pad = (-len(body)) & 3
    body += b"\x00" * pad
    total = 4 + 4 + len(body) + 4
    return struct.pack("<II", 0x00000001, total) + body + struct.pack("<I", total)


def _epb(ts_us: int, frame: bytes, iface: int = 0) -> bytes:
    """Enhanced Packet Block."""
    ts_high = (ts_us >> 32) & 0xFFFFFFFF
    ts_low = ts_us & 0xFFFFFFFF
    cap_len = len(frame)
    orig_len = len(frame)
    body = struct.pack("<IIIII", iface, ts_high, ts_low, cap_len, orig_len) + frame
    pad = (-len(body)) & 3
    body += b"\x00" * pad
    total = 4 + 4 + len(body) + 4
    return struct.pack("<II", 0x00000006, total) + body + struct.pack("<I", total)


def _eth_ipv4_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    """Build an Ethernet/IPv4/UDP frame with ``payload`` as the UDP body."""
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    dst_mac = b"\x66\x77\x88\x99\xAA\xBB"
    eth_type = b"\x08\x00"  # IPv4
    eth = dst_mac + src_mac + eth_type

    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0) + payload  # checksum=0 (legal for v4)

    ihl_words = 5  # no options
    total_len = ihl_words * 4 + udp_len
    src = bytes(int(o) for o in src_ip.split("."))
    dst = bytes(int(o) for o in dst_ip.split("."))
    ip = (
        bytes([0x45])                # version + IHL
        + bytes([0])                 # DSCP/ECN
        + struct.pack(">H", total_len)
        + struct.pack(">H", 0x1234)  # ID
        + struct.pack(">H", 0)       # flags+frag
        + bytes([64])                # TTL
        + bytes([17])                # proto = UDP
        + struct.pack(">H", 0)       # checksum (zero, parser doesn't validate)
        + src + dst
    )
    return eth + ip + udp


def _eth_ipv4_tcp(
    src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes,
) -> bytes:
    """Build an Ethernet/IPv4/TCP frame with ``payload`` as the TCP body."""
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    dst_mac = b"\x66\x77\x88\x99\xAA\xBB"
    eth_type = b"\x08\x00"
    eth = dst_mac + src_mac + eth_type

    data_offset_words = 5
    tcp = (
        struct.pack(">HH", sport, dport)
        + struct.pack(">I", 0)               # seq
        + struct.pack(">I", 0)               # ack
        + bytes([data_offset_words << 4])    # data offset, reserved
        + bytes([0x18])                      # flags: PSH+ACK
        + struct.pack(">H", 65535)           # window
        + struct.pack(">H", 0)               # checksum (skip)
        + struct.pack(">H", 0)               # urgent ptr
        + payload
    )
    total_len = 20 + len(tcp)
    src = bytes(int(o) for o in src_ip.split("."))
    dst = bytes(int(o) for o in dst_ip.split("."))
    ip = (
        bytes([0x45]) + bytes([0])
        + struct.pack(">H", total_len)
        + struct.pack(">H", 0x5678)
        + struct.pack(">H", 0)
        + bytes([64]) + bytes([6])           # TCP
        + struct.pack(">H", 0)
        + src + dst
    )
    return eth + ip + tcp


def _dns_query_payload(qname: str) -> bytes:
    """Tiny DNS query message asking for ``qname`` (A record).

    Header: id=0x1234, flags=0x0100, qd=1, others=0
    """
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    parts = qname.encode("ascii").split(b".")
    body = b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"
    body += struct.pack(">HH", 1, 1)  # qtype=A, qclass=IN
    return header + body


def _tls_clienthello_payload(sni: str) -> bytes:
    """Minimal TLS 1.2 ClientHello with one extension (SNI).
    Returns the bytes from the TLS record header (0x16 ...) through
    the entire handshake. Enough for the SNI parser to bite on.
    """
    # Build extensions: just SNI.
    sni_bytes = sni.encode("ascii")
    # server_name list: list_len(2) + name_type(1) + name_len(2) + name
    sn_list = (
        struct.pack(">H", 1 + 2 + len(sni_bytes))  # list length
        + bytes([0])                                # host_name type
        + struct.pack(">H", len(sni_bytes))
        + sni_bytes
    )
    ext_sni = struct.pack(">HH", 0, len(sn_list)) + sn_list  # type 0 = server_name
    extensions = ext_sni
    ext_total = struct.pack(">H", len(extensions)) + extensions

    # ClientHello body
    body = (
        struct.pack(">H", 0x0303)            # version TLS 1.2
        + b"\x00" * 32                       # random
        + bytes([0])                         # session_id length = 0
        + struct.pack(">H", 2) + b"\x00\x2f" # cipher suites (1 entry: TLS_RSA_WITH_AES_128_CBC_SHA)
        + bytes([1]) + b"\x00"               # compression methods (null)
        + ext_total
    )
    # Handshake header: type(1) + length(3)
    hs_len = len(body)
    handshake = bytes([0x01]) + bytes([
        (hs_len >> 16) & 0xFF,
        (hs_len >> 8) & 0xFF,
        hs_len & 0xFF,
    ]) + body

    # TLS record: content_type(1) + version(2) + length(2)
    tls = bytes([0x16]) + b"\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    return tls


def build_synthetic_pcap(path: Path) -> None:
    """Write a small but realistic pcapng to ``path``.

    Contents:
      - Packet 1: UDP DNS query for ``remotedesktop.google.com`` to 8.8.8.8
      - Packet 2: TCP TLS ClientHello with SNI ``app.ninjarmm.com`` to 35.160.227.202
      - Packet 3: UDP DNS query for ``app.ninjarmm.com`` to 1.1.1.1
      - Packet 4: garbage Ethernet (not IPv4/IPv6) — should not crash the parser.

    Timestamps span 5 seconds starting at a fixed UTC instant.
    """
    # 2026-05-26 12:00:00 UTC
    base_us = int(datetime(2026, 5, 26, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1_000_000)

    pkts = [
        # DNS for remotedesktop.google.com
        _eth_ipv4_udp(
            "192.168.1.10", "8.8.8.8", 53124, 53,
            _dns_query_payload("remotedesktop.google.com"),
        ),
        # TLS ClientHello to app.ninjarmm.com on 443
        _eth_ipv4_tcp(
            "192.168.1.10", "35.160.227.202", 50001, 443,
            _tls_clienthello_payload("app.ninjarmm.com"),
        ),
        # DNS for app.ninjarmm.com
        _eth_ipv4_udp(
            "192.168.1.10", "1.1.1.1", 53125, 53,
            _dns_query_payload("app.ninjarmm.com"),
        ),
        # Garbage frame (zero-padded)
        b"\x00" * 60,
    ]
    blob = _shb() + _idb()
    for i, frame in enumerate(pkts):
        blob += _epb(base_us + i * 1_000_000, frame)
    path.write_bytes(blob)


# --------------------------------------------------------------------
# Test cases
# --------------------------------------------------------------------


def assert_eq(label, got, want):
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def assert_in(label, needle, haystack):
    ok = needle in haystack
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        looking for: {needle!r}")
        print(f"        in: {haystack!r}")
    return ok


def main() -> int:
    failed = 0

    with tempfile.TemporaryDirectory() as td:
        pcap_path = Path(td) / "synthetic.pcapng"
        build_synthetic_pcap(pcap_path)

        s = scan_pcap(pcap_path)

        # ---- Case 1: parser captures the expected counts ----
        if not assert_eq("4 packets walked", s.total_packets, 4):
            failed += 1
        if not assert_eq("no parse errors", s.parse_errors, []):
            failed += 1
        if not assert_eq(
            "DNS queries extracted",
            set(s.dns_queries.keys()),
            {"remotedesktop.google.com", "app.ninjarmm.com"},
        ):
            failed += 1
        if not assert_eq(
            "SNI hosts extracted",
            set(s.sni_hosts.keys()),
            {"app.ninjarmm.com"},
        ):
            failed += 1
        if not assert_eq(
            "sni_to_ips mapping built",
            sorted(s.sni_to_ips["app.ninjarmm.com"]),
            ["35.160.227.202"],
        ):
            failed += 1

        # Destination IPs include all IPv4 packets (DNS x2 + TLS).
        # The garbage frame is not IPv4 so should not contribute.
        if not assert_in(
            "dest IP 8.8.8.8 (DNS google) present",
            "8.8.8.8",
            set(s.dest_ips.keys()),
        ):
            failed += 1
        if not assert_in(
            "dest IP 35.160.227.202 (TLS) present",
            "35.160.227.202",
            set(s.dest_ips.keys()),
        ):
            failed += 1

        # ---- Case 2: timestamps are in the right ballpark ----
        if s.ts_first is None:
            print("  FAIL  ts_first should not be None")
            failed += 1
        else:
            expected = datetime(2026, 5, 26, 12, 0, 0, tzinfo=timezone.utc)
            if abs((s.ts_first - expected).total_seconds()) > 1:
                print(f"  FAIL  ts_first {s.ts_first} != {expected}")
                failed += 1
            else:
                print(f"  OK    ts_first matches expected (within 1s)")

        # ---- Case 3: grep() filter narrows to only matching keys ----
        view = s.grep("remotedesktop")
        if not assert_eq(
            "grep 'remotedesktop' filters DNS to 1 entry",
            set(view.dns_queries.keys()),
            {"remotedesktop.google.com"},
        ):
            failed += 1
        if not assert_eq(
            "grep 'remotedesktop' filters SNI to 0 entries (it's DNS-only)",
            set(view.sni_hosts.keys()),
            set(),
        ):
            failed += 1

        # ---- Case 4: covers() window check ----
        inside = datetime(2026, 5, 26, 12, 0, 2, tzinfo=timezone.utc)
        before = datetime(2026, 5, 26, 11, 59, 59, tzinfo=timezone.utc)
        after = datetime(2026, 5, 26, 12, 1, 0, tzinfo=timezone.utc)
        if not assert_eq("covers(): inside pcap window", s.covers(inside), True):
            failed += 1
        if not assert_eq("covers(): just before pcap window", s.covers(before), False):
            failed += 1
        if not assert_eq("covers(): after pcap window", s.covers(after), False):
            failed += 1

        # ---- Case 5: render_summary() runs without crashing and mentions
        # the expected hosts ----
        rendered = render_summary(s)
        if not assert_in(
            "render_summary contains DNS line",
            "remotedesktop.google.com",
            rendered,
        ):
            failed += 1
        if not assert_in(
            "render_summary contains SNI line",
            "app.ninjarmm.com",
            rendered,
        ):
            failed += 1
        if not assert_in(
            "render_summary shows packet count",
            "4",
            rendered,
        ):
            failed += 1

        # ---- Case 6: render_correlation() distinguishes covered vs not ----
        covered_ts = datetime(2026, 5, 26, 12, 0, 2, tzinfo=timezone.utc)
        outside_ts = datetime(2026, 5, 26, 13, 0, 0, tzinfo=timezone.utc)
        corr = render_correlation(
            [s],
            [("INSIDE_FINDING", covered_ts), ("OUTSIDE_FINDING", outside_ts)],
        )
        if not assert_in("correlation marks COVERED BY", "COVERED BY", corr):
            failed += 1
        if not assert_in("correlation reports distance for outside", "not covered", corr):
            failed += 1

        # ---- Case 7: nonexistent file path -> parse_errors populated ----
        bad = scan_pcap(Path(td) / "does_not_exist.pcapng")
        if not assert_eq("missing file -> 0 packets", bad.total_packets, 0):
            failed += 1
        if not bad.parse_errors:
            print("  FAIL  missing file should populate parse_errors")
            failed += 1
        else:
            print("  OK    missing file populates parse_errors")

    print()
    if failed:
        print(f"FAILED ({failed} test case(s))")
        return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
