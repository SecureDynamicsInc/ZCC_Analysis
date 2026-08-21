# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Pcap review for ZCC support bundles.

Both Windows and macOS ZCC bundles ship two packet captures:
  * ``CaptureAdapters_<ts>.pcapng`` -- captured at the OS network-
    adapter layer.
  * ``CaptureLWF_<ts>.pcapng`` -- captured at ZCC's Lightweight
    Filter (Windows) / Packet Filter (Mac) layer, post-policy.

The captures are usually short (60-300 seconds) and timestamped at
bundle-creation time, so they line up with the very end of the
tunnel-log window. Comparing what ZCC's tunnel logs say vs. what was
actually on the wire is high-leverage triage.

This module is pure stdlib. We parse the pcapng container, the
Ethernet/IPv4/IPv6/TCP/UDP layers, and extract:

  - DNS query names
  - TLS ClientHello SNI hostnames
  - Destination IP / packet counts
  - Capture start/end timestamps

The output is a ``PcapSummary`` dataclass. The CLI surfaces it via
``--pcap`` and ``--pcap-filter <pattern>``.

Pcapng reference: https://datatracker.ietf.org/doc/html/draft-tuexen-opsawg-pcapng

Block layout (all multi-byte fields in the byte order of the section
header's BYTE_ORDER_MAGIC):

  Section Header Block      (0x0A0D0D0A) -- first block of a section
  Interface Description     (0x00000001) -- one per capture interface
  Enhanced Packet Block     (0x00000006) -- the actual packets
  Simple Packet Block       (0x00000003) -- (rare, no timestamp)

We tolerate parse failures aggressively. If a single packet has a
malformed TLS Client Hello we skip it and keep walking; we never raise
out of the loop. A pcap file we can't open at all becomes a single
``PcapSummary`` with ``parse_errors`` populated.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


def _format_ipv6(raw: bytes) -> str:
    """RFC 5952 form for 16 raw address bytes, e.g. ``2600:1f18::1:2``.

    Every IPv6 address in this module goes through here. Two reasons it has to
    be one function: the displayed address has to match what Wireshark shows,
    and the DNS answer map is joined to the packet-address map by string key —
    if the two sites formatted addresses differently, every IPv6 hostname
    correlation would silently miss.
    """
    try:
        return ipaddress.ip_address(bytes(raw)).compressed
    except ValueError:
        return ":".join(
            f"{int.from_bytes(raw[i:i + 2], 'big'):x}" for i in range(0, len(raw), 2)
        )


# --------------------------------------------------------------------
# Public data shape
# --------------------------------------------------------------------


@dataclass
class PcapSummary:
    """Result of scanning one pcapng file."""

    path: Path
    total_packets: int = 0
    ts_first: Optional[datetime] = None
    ts_last: Optional[datetime] = None
    dns_queries: Dict[str, int] = field(default_factory=dict)
    sni_hosts: Dict[str, int] = field(default_factory=dict)
    dest_ips: Dict[str, int] = field(default_factory=dict)
    # SNI host -> set of destination IPs we saw it talk to. Useful
    # for correlating an SNI back to the IP family it actually
    # negotiated with.
    sni_to_ips: Dict[str, set] = field(default_factory=dict)
    # DNS answer IP -> qnames observed in successful response records.
    # This supplies evidence-backed hostnames for endpoint tables without
    # performing live reverse DNS or sending customer IPs off-box.
    dns_answers: Dict[str, set] = field(default_factory=dict)
    # The same evidence read the other way: query name -> the A and AAAA
    # addresses the resolver actually returned. The reverse map above answers
    # "who is this address?"; this one answers "what did this name resolve
    # to?", which is what makes a DNS row joinable to an endpoint row.
    dns_resolutions: Dict[str, set] = field(default_factory=dict)
    # Wireshark "Statistics -> Endpoints" accounting.
    #
    # address_stats is keyed by bare IP, transport_stats by "ip:proto/port",
    # matching Wireshark's IPv4/IPv6 and TCP/UDP endpoint tabs. Tx is what
    # that address *sent*, Rx what it *received*, so Tx + Rx == Packets.
    # This is per-address and direction-split, which the existing
    # bytes_per_endpoint cannot express: that field deliberately folds both
    # directions onto the server-side endpoint of a flow.
    #
    # Bytes are captured frame lengths, the same quantity Wireshark's Bytes
    # column reports, so the two can be compared directly. A capture taken
    # with a short snaplen truncates frames and therefore both tools' counts.
    address_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)
    transport_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # Per-endpoint counts, keyed by "ip:proto/port" (e.g.
    # "198.14.91.254:tcp/443"). Lets the operator search by port,
    # which the bare dest_ips view can't support.
    dest_endpoints: Dict[str, int] = field(default_factory=dict)
    parse_errors: List[str] = field(default_factory=list)
    # ---- Phase 30 (2026-06-19) network-health additions ----
    #
    # Provenance for every field below: the parsing function and the
    # specific packet-byte location is documented in the function
    # where the field is populated. Every count is a real packet
    # count from the pcap, not an inferred or estimated value.
    #
    # bytes_per_endpoint: total IP-payload bytes attributed to each
    # remote endpoint ("server side" heuristic — whichever side of
    # the flow has the lower port). Source: IP total-length field
    # summed per (remote_ip, proto, remote_port) tuple.
    bytes_per_endpoint: Dict[str, int] = field(default_factory=dict)
    # tcp_resets: count of packets with the TCP RST flag bit (0x04)
    # set, keyed by "src_ip:sport -> dst_ip:dport" so the operator
    # can see who sent the RST. Source: TCP header byte 13, bit 0x04.
    tcp_resets: Dict[str, int] = field(default_factory=dict)
    # Reset counts attributed to the server-side endpoint, for aggregation.
    tcp_reset_endpoints: Dict[str, int] = field(default_factory=dict)
    # TCP handshake observations attributed to the server-side endpoint.
    # An excess of SYN over SYN-ACK is a bounded capture-window signal, not
    # proof that every unmatched SYN failed.
    tcp_syns: Dict[str, int] = field(default_factory=dict)
    tcp_syn_acks: Dict[str, int] = field(default_factory=dict)
    # tcp_retransmits: count of suspected TCP retransmits, keyed by
    # endpoint ("ip:proto/port"). Heuristic: a TCP segment whose
    # sequence number plus its payload length is <= the highest
    # (seq + len) we've already seen for the same (flow, direction),
    # with payload_len > 0. Mirrors Wireshark's "Retransmission"
    # expert (minus the SACK refinement). Source: TCP header bytes
    # 4-7 (seq) and IP total_len minus headers (payload).
    tcp_retransmits: Dict[str, int] = field(default_factory=dict)
    # dns_nxdomain: DNS query names that received an NXDOMAIN
    # response (RCODE=3), with response counts. Source: DNS header
    # byte 3, bottom 4 bits, on packets with QR=1.
    dns_nxdomain: Dict[str, int] = field(default_factory=dict)
    # tls_alerts: TLS Alert records seen, keyed by
    # "level/description" -> count. Level 2 (fatal) means a
    # handshake aborted. Description 40 = handshake_failure, 48 =
    # unknown_ca, 70 = protocol_version, etc. Source: TLS record
    # type 0x15.
    tls_alerts: Dict[str, int] = field(default_factory=dict)
    # tls_alert_endpoints: which remote endpoints we saw fatal
    # alerts to/from. Lets the operator pinpoint the SNI/IP that
    # failed handshake. Source: same TLS Alert records, attributed
    # by 5-tuple.
    tls_alert_endpoints: Dict[str, int] = field(default_factory=dict)
    # flow_intervals: per-flow (first_ts, last_ts, bytes) for the
    # connection timeline. Keyed by canonical endpoint pair string.
    # Source: aggregated from every parsed packet's IP total_len.
    flow_intervals: Dict[str, Tuple[datetime, datetime, int]] = field(
        default_factory=dict,
    )

    @property
    def duration_s(self) -> float:
        if self.ts_first and self.ts_last:
            return (self.ts_last - self.ts_first).total_seconds()
        return 0.0

    def covers(self, ts: datetime) -> bool:
        """Does this pcap's capture window contain ``ts``?"""
        if not self.ts_first or not self.ts_last:
            return False
        return self.ts_first <= ts <= self.ts_last

    def grep(self, pattern: str) -> "PcapSummary":
        """Return a filtered view: keep only DNS / SNI / IP entries
        that contain ``pattern`` (case-insensitive substring).

        Destination IP filter is a literal substring against the dotted
        form, so ``--pcap-filter 198.14`` matches all 198.14.x.x.

        Counts and timestamps are preserved; this is a read-only
        projection of the original summary.
        """
        p = pattern.lower()
        out = PcapSummary(
            path=self.path,
            total_packets=self.total_packets,
            ts_first=self.ts_first,
            ts_last=self.ts_last,
            parse_errors=self.parse_errors,
        )
        out.dns_queries = {k: v for k, v in self.dns_queries.items() if p in k.lower()}
        out.sni_hosts = {k: v for k, v in self.sni_hosts.items() if p in k.lower()}
        out.dest_ips = {k: v for k, v in self.dest_ips.items() if p in k.lower()}
        out.sni_to_ips = {
            k: v for k, v in self.sni_to_ips.items() if p in k.lower()
        }
        out.dest_endpoints = {
            k: v for k, v in self.dest_endpoints.items() if p in k.lower()
        }
        out.dns_resolutions = {
            k: v for k, v in self.dns_resolutions.items() if p in k.lower()
        }
        out.dns_answers = {
            k: v for k, v in self.dns_answers.items()
            if p in k.lower() or any(p in str(name).lower() for name in v)
        }
        # An address filter should keep a row whether the pattern matches the
        # address or a hostname that resolved to it.
        resolved = {
            ip for ip, names in self.dns_answers.items()
            if any(p in str(name).lower() for name in names)
        }
        out.address_stats = {
            k: dict(v) for k, v in self.address_stats.items()
            if p in k.lower() or k in resolved
        }
        out.transport_stats = {
            k: dict(v) for k, v in self.transport_stats.items()
            # rsplit, not split: an IPv6 key is "2600:1f18::1:tcp/443" and
            # splitting on the first colon would yield "2600".
            if p in k.lower() or k.rsplit(":", 1)[0] in resolved
        }
        return out


# --------------------------------------------------------------------
# Pcapng reader (pure stdlib)
# --------------------------------------------------------------------


_BLOCK_SECTION_HEADER = 0x0A0D0D0A
_BLOCK_INTERFACE_DESC = 0x00000001
_BLOCK_ENHANCED_PACKET = 0x00000006
_BLOCK_SIMPLE_PACKET = 0x00000003
_BLOCK_PACKET = 0x00000002  # legacy

# Magic for section header that tells us byte order.
_BOM_LE = 0x1A2B3C4D
_BOM_BE = 0x4D3C2B1A


def _iter_blocks(fp) -> Iterator[Tuple[int, bytes, str]]:
    """Yield ``(block_type, body, endian_char)`` for each pcapng block
    in ``fp``. The endian char is ``"<"`` or ``">"`` for use with
    ``struct``.

    Raises StopIteration on EOF. Raises ValueError if a block is
    malformed in a way we can't recover from.
    """
    endian = "<"
    while True:
        hdr = fp.read(8)
        if not hdr:
            return
        if len(hdr) < 8:
            raise ValueError("Truncated block header")
        # Block type comes in the SHB's byte order, but we don't know
        # what that is until we read the SHB. Heuristic: SHB type is
        # 0x0A0D0D0A which is a palindrome, so both endians give the
        # same value. Length is the same number in either order if it
        # happens to be palindromic too; otherwise we'll detect the BOM
        # within the SHB body and adjust if needed.
        btype = int.from_bytes(hdr[:4], "little")
        blen = int.from_bytes(hdr[4:8], "little")
        # Sanity: block length must be >= 12 (type + len + len) and
        # a multiple of 4.
        if blen < 12 or blen % 4 != 0 or blen > 64 * 1024 * 1024:
            # Try the other endian before giving up.
            btype_be = int.from_bytes(hdr[:4], "big")
            blen_be = int.from_bytes(hdr[4:8], "big")
            if 12 <= blen_be <= 64 * 1024 * 1024 and blen_be % 4 == 0:
                btype, blen, endian = btype_be, blen_be, ">"
            else:
                raise ValueError(
                    f"Implausible block: type=0x{btype:08x} len={blen}"
                )
        body_len = blen - 12
        body = fp.read(body_len)
        if len(body) < body_len:
            # Truncated tail; surface as the parse-error and stop.
            raise ValueError("Truncated block body")
        trailer = fp.read(4)
        if len(trailer) < 4:
            raise ValueError("Missing block trailer")
        # If this is the SHB, peek at the BOM and lock endian.
        if btype == _BLOCK_SECTION_HEADER and len(body) >= 4:
            bom = int.from_bytes(body[:4], "little")
            if bom == _BOM_LE:
                endian = "<"
            elif bom == _BOM_BE:
                endian = ">"
            # If neither, keep whatever heuristic gave us a sane length.
        yield btype, body, endian


def _parse_interface_description(body: bytes, endian: str) -> int:
    """Return the IDB's timestamp resolution (ticks per second).

    The IDB carries an optional `if_tsresol` option (code 9) holding
    a single byte:
      - high bit clear: power-of-10 resolution (value=6 => microseconds)
      - high bit set:   power-of-2 resolution (value=20 => 2^20)

    Default if absent: microseconds (10^6 ticks/sec).
    """
    if len(body) < 8:
        return 1_000_000
    # Skip link_type(2) + reserved(2) + snaplen(4) = first 8 bytes.
    o = 8
    ticks = 1_000_000
    while o + 4 <= len(body):
        opt_code = int.from_bytes(body[o:o + 2], "little" if endian == "<" else "big")
        opt_len = int.from_bytes(body[o + 2:o + 4], "little" if endian == "<" else "big")
        o += 4
        if opt_code == 0:  # opt_endofopt
            break
        if opt_code == 9 and opt_len >= 1:  # if_tsresol
            v = body[o]
            if v & 0x80:
                ticks = 1 << (v & 0x7F)
            else:
                ticks = 10 ** (v & 0x7F)
        # options are padded to 4-byte boundary
        o += (opt_len + 3) & ~3


    return ticks


def _read_pcapng(path: Path) -> Iterator[Tuple[datetime, bytes]]:
    """Yield ``(timestamp, ethernet_frame_bytes)`` for each Enhanced /
    Simple Packet Block.
    """
    if_ticks: List[int] = []  # index = interface_id
    with open(path, "rb") as fp:
        for btype, body, endian in _iter_blocks(fp):
            if btype == _BLOCK_INTERFACE_DESC:
                if_ticks.append(_parse_interface_description(body, endian))
            elif btype == _BLOCK_ENHANCED_PACKET:
                if len(body) < 20:
                    continue
                # EPB body: interface_id(4) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4) + data
                fmt = endian + "IIIII"
                iface, ts_high, ts_low, cap_len, _orig_len = struct.unpack(fmt, body[:20])
                ticks = if_ticks[iface] if iface < len(if_ticks) else 1_000_000
                ts_ticks = (ts_high << 32) | ts_low
                ts_sec = ts_ticks / ticks
                ts = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
                frame = body[20:20 + cap_len]
                yield ts, frame
            elif btype == _BLOCK_SIMPLE_PACKET:
                # Simple packets don't carry their own timestamp.
                # We skip them; ZCC's captures always use EPB.
                continue
            elif btype == _BLOCK_PACKET:
                # Legacy packet block; we don't see these in ZCC bundles.
                continue


# --------------------------------------------------------------------
# Frame parsing (Ethernet -> IPv4/IPv6 -> TCP/UDP -> DNS / TLS-SNI)
# --------------------------------------------------------------------


def _parse_frame(frame: bytes) -> Optional[Tuple[str, str, int, int, bytes]]:
    """Return ``(proto, dst_ip_str, src_port, dst_port, l4_payload)`` or None.

    ``proto`` is ``"tcp"`` or ``"udp"``.
    """
    try:
        if len(frame) < 14:
            return None
        # Ethernet
        etype = (frame[12] << 8) | frame[13]
        hdr_len = 14
        if etype == 0x8100 and len(frame) >= 18:  # 802.1Q VLAN
            etype = (frame[16] << 8) | frame[17]
            hdr_len = 18
        if etype == 0x0800:  # IPv4
            return _parse_ipv4(frame[hdr_len:])
        if etype == 0x86DD:  # IPv6
            return _parse_ipv6(frame[hdr_len:])
        return None
    except Exception:
        return None


def _parse_ipv4(buf: bytes) -> Optional[Tuple[str, str, int, int, bytes]]:
    if len(buf) < 20:
        return None
    ver_ihl = buf[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        return None
    proto = buf[9]
    dst = ".".join(str(b) for b in buf[16:20])
    l4 = buf[ihl:]
    return _parse_l4(proto, dst, l4)


def _parse_ipv6(buf: bytes) -> Optional[Tuple[str, str, int, int, bytes]]:
    if len(buf) < 40:
        return None
    if (buf[0] >> 4) != 6:
        return None
    nxt = buf[6]
    dst = _format_ipv6(buf[24:40])
    l4 = buf[40:]
    # Hop-by-hop / routing / etc extension headers — skip the common ones.
    while nxt in (0, 43, 44, 50, 51, 60) and len(l4) >= 2:
        nxt = l4[0]
        ext_len = (l4[1] + 1) * 8
        l4 = l4[ext_len:]
    return _parse_l4(nxt, dst, l4)


def _parse_l4(proto_num: int, dst: str, l4: bytes) -> Optional[Tuple[str, str, int, int, bytes]]:
    if proto_num == 6 and len(l4) >= 20:  # TCP
        sport = (l4[0] << 8) | l4[1]
        dport = (l4[2] << 8) | l4[3]
        thl = (l4[12] >> 4) * 4
        if thl < 20 or len(l4) < thl:
            return ("tcp", dst, sport, dport, b"")
        return ("tcp", dst, sport, dport, l4[thl:])
    if proto_num == 17 and len(l4) >= 8:  # UDP
        sport = (l4[0] << 8) | l4[1]
        dport = (l4[2] << 8) | l4[3]
        return ("udp", dst, sport, dport, l4[8:])
    return None


def _parse_dns_qname(payload: bytes) -> Optional[str]:
    """Pull the first DNS query name out of a DNS message. Tolerant
    of truncation. Compressed names (RFC 1035 §4.1.4) are followed
    once -- if the pointer would loop we bail."""
    if len(payload) < 12:
        return None
    qdcount = (payload[4] << 8) | payload[5]
    if qdcount < 1:
        return None
    o = 12
    labels = []
    seen_ptr = False
    safety = 64
    while safety > 0 and o < len(payload):
        safety -= 1
        ln = payload[o]
        if ln == 0:
            break
        if (ln & 0xC0) == 0xC0:
            if seen_ptr or o + 1 >= len(payload):
                return None
            seen_ptr = True
            o = ((ln & 0x3F) << 8) | payload[o + 1]
            continue
        o += 1
        if o + ln > len(payload):
            return None
        labels.append(payload[o:o + ln].decode("ascii", errors="replace"))
        o += ln
    if not labels:
        return None
    return ".".join(labels).lower().rstrip(".")


def _parse_tls_sni(tcp_payload: bytes) -> Optional[str]:
    """Pull the SNI out of a TLS ClientHello. Returns None on any
    parse failure -- TLS is fragile to half-captured frames and we
    skip aggressively."""
    if len(tcp_payload) < 5:
        return None
    # TLS record: type(1) + version(2) + length(2)
    if tcp_payload[0] != 0x16:  # not Handshake
        return None
    rec_len = (tcp_payload[3] << 8) | tcp_payload[4]
    if rec_len < 4 or len(tcp_payload) < 5 + rec_len:
        # Could be a fragmented handshake; bail rather than gamble.
        return None
    hs = tcp_payload[5:5 + rec_len]
    if not hs or hs[0] != 0x01:  # not ClientHello
        return None
    # ClientHello: type(1) + length(3) + version(2) + random(32) + sid_len(1) + sid + cs_len(2) + cs + cm_len(1) + cm + ext_len(2) + ext
    try:
        o = 4 + 2 + 32  # past type/len/version/random
        sid_len = hs[o]
        o += 1 + sid_len
        cs_len = (hs[o] << 8) | hs[o + 1]
        o += 2 + cs_len
        cm_len = hs[o]
        o += 1 + cm_len
        if o + 2 > len(hs):
            return None
        ext_total_len = (hs[o] << 8) | hs[o + 1]
        o += 2
        ext_end = o + ext_total_len
        while o + 4 <= ext_end and o + 4 <= len(hs):
            etype = (hs[o] << 8) | hs[o + 1]
            elen = (hs[o + 2] << 8) | hs[o + 3]
            o += 4
            if etype == 0:  # server_name
                # SNI extension: list_len(2) + name_type(1) + name_len(2) + name
                if elen < 5:
                    return None
                name_type = hs[o + 2]
                if name_type != 0:  # host_name
                    return None
                name_len = (hs[o + 3] << 8) | hs[o + 4]
                name = hs[o + 5:o + 5 + name_len]
                return name.decode("ascii", errors="replace").lower().rstrip(".")
            o += elen
    except Exception:
        return None
    return None


# --------------------------------------------------------------------
# Phase 30 (2026-06-19) — packet-level health parsers.
#
# Helpers that pull RCODE / TLS Alert / TCP flags out of a single
# parsed L4 payload or frame. Each helper is tolerant of truncation
# (returns None / 0) — we never want a malformed packet to crash
# the whole scan.
# --------------------------------------------------------------------


# DNS RCODE values we care about. The full list is in RFC 6895 §2.3
# but for triage we surface only the failure codes.
_DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def _parse_dns_response(payload: bytes) -> Optional[Tuple[int, str]]:
    """If ``payload`` is a DNS *response* (QR=1), return ``(rcode,
    qname)`` where rcode is the bottom 4 bits of header byte 3 and
    qname is the first question name (lowercased, no trailing dot).
    Returns None for queries or malformed payloads.

    Source bytes:
      - Byte 2, bit 0x80 = QR (1 = response)
      - Byte 3, bits 0x0F = RCODE
    """
    if len(payload) < 12:
        return None
    if (payload[2] & 0x80) == 0:  # QR=0 means query, skip
        return None
    rcode = payload[3] & 0x0F
    qname = _parse_dns_qname(payload) or ""
    return rcode, qname


def _dns_skip_name(payload: bytes, offset: int) -> Optional[int]:
    """Return the offset after one DNS name, tolerating compression pointers."""
    steps = 0
    while offset < len(payload) and steps < 128:
        steps += 1
        length = payload[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2 if offset + 1 < len(payload) else None
        if length & 0xC0:
            return None
        offset += 1 + length
    return None


def _parse_dns_address_answers(payload: bytes) -> List[Tuple[str, str]]:
    """Return ``(qname, IP)`` pairs for A/AAAA answers in a DNS response."""
    if len(payload) < 12 or (payload[2] & 0x80) == 0:
        return []
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    qname = _parse_dns_qname(payload) or ""
    offset = 12
    for _ in range(qdcount):
        offset = _dns_skip_name(payload, offset)
        if offset is None or offset + 4 > len(payload):
            return []
        offset += 4

    answers: List[Tuple[str, str]] = []
    for _ in range(ancount):
        offset = _dns_skip_name(payload, offset)
        if offset is None or offset + 10 > len(payload):
            break
        rtype = int.from_bytes(payload[offset:offset + 2], "big")
        rclass = int.from_bytes(payload[offset + 2:offset + 4], "big")
        rdlen = int.from_bytes(payload[offset + 8:offset + 10], "big")
        offset += 10
        if offset + rdlen > len(payload):
            break
        rdata = payload[offset:offset + rdlen]
        offset += rdlen
        if rclass != 1 or not qname:
            continue
        if rtype == 1 and rdlen == 4:
            answers.append((qname, ".".join(str(byte) for byte in rdata)))
        elif rtype == 28 and rdlen == 16:
            answers.append((qname, _format_ipv6(rdata)))
    return answers


# TLS Alert descriptions (RFC 8446 §6 + RFC 5246 §A.3). We name the
# common fatal handshake failures; unknown values render as "code-N".
_TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    60: "export_restriction",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    111: "certificate_unobtainable",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
}


def _parse_tls_alert(tcp_payload: bytes) -> Optional[Tuple[int, int]]:
    """If ``tcp_payload`` starts with a TLS Alert record, return
    ``(level, description)``. Otherwise None.

    Source bytes:
      - Byte 0 = 0x15 (TLS Alert content type)
      - Bytes 1-2 = TLS version (0x0301-0x0304)
      - Bytes 3-4 = record length
      - Byte 5 = level (1=warning, 2=fatal)
      - Byte 6 = description
    """
    if len(tcp_payload) < 7:
        return None
    if tcp_payload[0] != 0x15:  # not an Alert record
        return None
    # Quick sanity: TLS major version is always 3 (SSLv3 / TLS 1.0-1.3).
    if tcp_payload[1] != 0x03:
        return None
    return tcp_payload[5], tcp_payload[6]


def _format_tls_alert(level: int, desc: int) -> str:
    """Human label like ``"fatal/handshake_failure"`` or
    ``"warning/code-99"`` for unknown codes."""
    level_name = "fatal" if level == 2 else ("warning" if level == 1 else f"l{level}")
    desc_name = _TLS_ALERT_DESCRIPTIONS.get(desc, f"code-{desc}")
    return f"{level_name}/{desc_name}"


def _server_side_endpoint(
    proto: str,
    src_ip: str, sport: int,
    dst_ip: str, dport: int,
) -> str:
    """Pick the 'server side' of a connection for top-talkers
    attribution. Heuristic: the side with the LOWER port — well-known
    ports (<1024) and registered ports (<49152) are more likely the
    server than ephemeral ports. Ties broken by lexicographic order
    on (ip, port). Returns "ip:proto/port".
    """
    if sport == dport:
        # Pathological case; canonicalize lexicographically.
        if (src_ip, sport) <= (dst_ip, dport):
            return f"{src_ip}:{proto}/{sport}"
        return f"{dst_ip}:{proto}/{dport}"
    if sport < dport:
        return f"{src_ip}:{proto}/{sport}"
    return f"{dst_ip}:{proto}/{dport}"


ENDPOINT_STAT_KEYS = (
    "packets", "bytes", "tx_packets", "tx_bytes", "rx_packets", "rx_bytes",
)


def _bump_endpoint(
    table: Dict[str, Dict[str, int]], key: str, *, sent: bool, size: int,
) -> None:
    """Add one packet to a Wireshark-style endpoint row.

    ``sent`` is from the perspective of ``key``: True when this address was the
    source of the packet. Every packet is counted twice overall — once as Tx on
    its source and once as Rx on its destination — which is exactly how
    Wireshark's Endpoints table reaches Tx + Rx == Packets per row.
    """
    row = table.get(key)
    if row is None:
        row = table[key] = dict.fromkeys(ENDPOINT_STAT_KEYS, 0)
    row["packets"] += 1
    row["bytes"] += size
    if sent:
        row["tx_packets"] += 1
        row["tx_bytes"] += size
    else:
        row["rx_packets"] += 1
        row["rx_bytes"] += size


# --------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------


def scan_pcap(path: Path, max_packets: int = 250_000) -> PcapSummary:
    """Scan one pcapng file and return a ``PcapSummary``.

    ``max_packets`` caps the work in case a customer ships a giant
    capture. The cap is conservative -- ZCC's bundles are usually
    well under 100k packets.

    Phase 30 (2026-06-19): switched from the lossy ``_parse_frame``
    to ``_parse_frame_full`` so we have access to TCP flags, source
    IP, and the IP total_len field. This unlocks: TCP RST counting,
    retransmit detection, top-talkers-by-bytes, DNS RCODE parsing
    (NXDOMAIN), TLS Alert detection, and per-flow timelines. Every
    new metric is documented in PcapSummary with its source bytes.
    """
    s = PcapSummary(path=Path(path))

    # Phase 30: per-(flow, direction) "highest seq+len seen so far".
    # A TCP segment whose payload is non-empty and whose seq+len is
    # <= this watermark is a retransmit. Bounded at 10k flows to
    # cap memory on huge captures.
    seq_watermark: Dict[Any, int] = {}
    seq_watermark_cap = 10000

    try:
        for ts, frame in _read_pcapng(path):
            if s.total_packets >= max_packets:
                s.parse_errors.append(
                    f"Stopped at packet cap ({max_packets})"
                )
                break
            s.total_packets += 1
            if s.ts_first is None:
                s.ts_first = ts
            s.ts_last = ts
            parsed = _parse_frame_full(frame)
            if not parsed:
                continue
            (proto, src_ip, dst_ip, sport, dport,
             total_len, flags, payload) = parsed

            # ---- Legacy fields (unchanged shape) ----
            s.dest_ips[dst_ip] = s.dest_ips.get(dst_ip, 0) + 1
            endpoint_key = f"{dst_ip}:{proto}/{dport}"
            s.dest_endpoints[endpoint_key] = (
                s.dest_endpoints.get(endpoint_key, 0) + 1
            )

            # ---- Wireshark-style endpoint accounting ----
            # Frame length rather than IP total_len, so the Bytes column can be
            # compared directly against Wireshark's own Endpoints table.
            frame_len = len(frame)
            _bump_endpoint(s.address_stats, src_ip, sent=True, size=frame_len)
            _bump_endpoint(s.address_stats, dst_ip, sent=False, size=frame_len)
            _bump_endpoint(
                s.transport_stats, f"{src_ip}:{proto}/{sport}",
                sent=True, size=frame_len,
            )
            _bump_endpoint(
                s.transport_stats, f"{dst_ip}:{proto}/{dport}",
                sent=False, size=frame_len,
            )

            # ---- Phase 30: top talkers by bytes ----
            # Attribute every packet's IP total_len to the server-
            # side endpoint of the conversation. This way both
            # request and response bytes land on the same row, so
            # the row reflects "total chatter with that server".
            server_ep = _server_side_endpoint(
                proto, src_ip, sport, dst_ip, dport,
            )
            s.bytes_per_endpoint[server_ep] = (
                s.bytes_per_endpoint.get(server_ep, 0) + total_len
            )

            # ---- Phase 30: connection timeline ----
            # Per-flow (canonical endpoint pair) interval. Key is
            # lexicographic so A->B and B->A merge.
            ep_a = f"{src_ip}:{proto}/{sport}"
            ep_b = f"{dst_ip}:{proto}/{dport}"
            flow_key = f"{ep_a} <-> {ep_b}" if ep_a <= ep_b else f"{ep_b} <-> {ep_a}"
            prev = s.flow_intervals.get(flow_key)
            if prev is None:
                s.flow_intervals[flow_key] = (ts, ts, total_len)
            else:
                first_ts, _last_ts, total_bytes = prev
                s.flow_intervals[flow_key] = (
                    first_ts, ts, total_bytes + total_len,
                )

            # ---- TCP-specific health signals ----
            if proto == "tcp":
                # RST: TCP flag bit 0x04. Captured per-direction
                # ("src->dst") so the operator can see who emitted
                # the RST. A server-side RST during handshake
                # usually means firewall block; client-side RST
                # during teardown is normal.
                if flags & 0x04:
                    rst_key = (
                        f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                    )
                    s.tcp_resets[rst_key] = (
                        s.tcp_resets.get(rst_key, 0) + 1
                    )
                    s.tcp_reset_endpoints[server_ep] = (
                        s.tcp_reset_endpoints.get(server_ep, 0) + 1
                    )

                if flags & 0x02:
                    target = s.tcp_syn_acks if flags & 0x10 else s.tcp_syns
                    target[server_ep] = target.get(server_ep, 0) + 1

                # Retransmit detection. Need the TCP header to grab
                # seq (bytes 4-7) and the actual TCP-payload length.
                # `_parse_frame_full` returns the post-TCP-header
                # payload as `payload`, so payload length is the
                # effective TCP-segment payload.
                if payload:
                    # Reach back into the frame for the raw TCP seq.
                    # We re-parse minimally — cheaper than threading
                    # seq through _parse_frame_full's tuple.
                    seq = _extract_tcp_seq(frame)
                    if seq is not None:
                        dir_key = (
                            ep_a, ep_b,  # ordered: src perspective
                        )
                        payload_len = len(payload)
                        seq_end = (seq + payload_len) & 0xFFFFFFFF
                        wm = seq_watermark.get(dir_key)
                        if wm is None:
                            # First seen in this direction; record
                            # the watermark but don't count as a
                            # retransmit.
                            if len(seq_watermark) < seq_watermark_cap:
                                seq_watermark[dir_key] = seq_end
                        else:
                            # Standard Wireshark heuristic: if
                            # seq_end <= watermark we've already
                            # acked this byte range (modulo 32-bit
                            # wrap, which we ignore for short
                            # ZCC captures).
                            if seq_end <= wm:
                                # Attribute the retransmit to the
                                # server-side endpoint so it
                                # aggregates by destination.
                                s.tcp_retransmits[server_ep] = (
                                    s.tcp_retransmits.get(server_ep, 0) + 1
                                )
                            else:
                                seq_watermark[dir_key] = seq_end

                # TLS Alert detection (port 443 OR any port whose
                # first byte looks like a TLS Alert record). We
                # check on every TCP packet with payload; the
                # _parse_tls_alert helper rejects non-Alert quickly.
                if payload:
                    alert = _parse_tls_alert(payload)
                    if alert is not None:
                        level, desc = alert
                        label = _format_tls_alert(level, desc)
                        s.tls_alerts[label] = (
                            s.tls_alerts.get(label, 0) + 1
                        )
                        # Attribute to the server side so the
                        # operator can see which SNI/IP failed.
                        s.tls_alert_endpoints[server_ep] = (
                            s.tls_alert_endpoints.get(server_ep, 0) + 1
                        )

                # TLS ClientHello SNI (existing behaviour) — only
                # on dst port 443 to keep the cost bounded.
                if dport == 443 and payload:
                    sni = _parse_tls_sni(payload)
                    if sni:
                        s.sni_hosts[sni] = s.sni_hosts.get(sni, 0) + 1
                        s.sni_to_ips.setdefault(sni, set()).add(dst_ip)

            # ---- UDP DNS (query + response) ----
            elif proto == "udp" and (dport == 53 or sport == 53):
                # Existing: query qnames.
                q = _parse_dns_qname(payload)
                if q:
                    s.dns_queries[q] = s.dns_queries.get(q, 0) + 1
                # Phase 30: response RCODE.
                resp = _parse_dns_response(payload)
                if resp is not None:
                    rcode, qname = resp
                    if rcode != 0 and qname:
                        # NXDOMAIN is rcode 3; we record any non-zero
                        # rcode but key by qname + rcode-name so the
                        # UI can show NXDOMAIN vs SERVFAIL vs REFUSED
                        # separately.
                        rname = _DNS_RCODE_NAMES.get(rcode, f"rcode-{rcode}")
                        key = f"{qname}  [{rname}]"
                        # For backwards compat, the dns_nxdomain dict
                        # holds ALL non-success rcodes; the UI labels
                        # them appropriately via the [RNAME] suffix.
                        s.dns_nxdomain[key] = (
                            s.dns_nxdomain.get(key, 0) + 1
                        )
                for qname, answer_ip in _parse_dns_address_answers(payload):
                    s.dns_answers.setdefault(answer_ip, set()).add(qname)
                    s.dns_resolutions.setdefault(qname, set()).add(answer_ip)
    except ValueError as e:
        s.parse_errors.append(f"pcapng read error: {e}")
    except FileNotFoundError as e:
        s.parse_errors.append(f"file not found: {e}")
    except OSError as e:
        s.parse_errors.append(f"OS error: {e}")
    return s


def _extract_tcp_seq(frame: bytes) -> Optional[int]:
    """Pull the TCP sequence number out of a parsed Ethernet frame,
    or None if the frame doesn't carry TCP / is malformed.

    Source bytes:
      - Ethernet header: 14 bytes (18 if VLAN tagged)
      - IPv4: bytes 9 of IP = protocol, bytes 4*(byte0 & 0x0F) of IP = IHL
      - IPv6: byte 6 of IP = next-header
      - TCP: bytes 4-7 = sequence number (big-endian)
    """
    try:
        if len(frame) < 14:
            return None
        etype = (frame[12] << 8) | frame[13]
        ip_off = 14
        if etype == 0x8100 and len(frame) >= 18:
            etype = (frame[16] << 8) | frame[17]
            ip_off = 18
        ip = frame[ip_off:]
        if etype == 0x0800:
            if len(ip) < 20:
                return None
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 6 or ihl < 20 or len(ip) < ihl + 8:
                return None
            t = ip[ihl:]
        elif etype == 0x86DD:
            if len(ip) < 40 or ip[6] != 6 or len(ip) < 48:
                return None
            t = ip[40:]
        else:
            return None
        if len(t) < 8:
            return None
        return int.from_bytes(t[4:8], "big")
    except Exception:
        return None


def scan_bundle(root: Path) -> List[PcapSummary]:
    """Walk a bundle root and scan every ``*.pcapng`` file under it.

    Returns a list of ``PcapSummary`` sorted by capture start time.
    """
    results: List[PcapSummary] = []
    for p in Path(root).rglob("*.pcapng"):
        if p.is_file():
            results.append(scan_pcap(p))
    results.sort(
        key=lambda s: s.ts_first or datetime.fromtimestamp(0, tz=timezone.utc)
    )
    return results


# --------------------------------------------------------------------
# Phase 18 (2026-06-17) — stream-follow.
#
# Wireshark-style "Follow Stream" in pure stdlib: identify every
# TCP/UDP flow (4-tuple, direction-agnostic) that has at least one
# packet matching a search term, then return every packet in that
# flow. Lets the Search UI take a URL / hostname / IP query and show
# the engineer the COMPLETE conversation context, not just the
# matching packet in isolation.
# --------------------------------------------------------------------


@dataclass
class StreamPacket:
    """One packet in a followed stream."""
    ts: datetime
    direction: str       # "->" (a→b) or "<-" (b→a), relative to canonical flow
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str           # "tcp" | "udp"
    length: int          # IP payload length (L4 header + payload)
    tcp_flags: str       # "SYN" / "SYN ACK" / "FIN" etc; "" for UDP
    payload_preview: str # First 60 chars of printable L4 payload


@dataclass
class StreamMatch:
    """One TCP/UDP flow that matched a search query."""
    stream_id: int               # Synthetic 0-indexed (matches Wireshark tcp.stream)
    proto: str                   # "tcp" | "udp"
    endpoint_a: str              # Canonical: lexicographically smaller (ip:port)
    endpoint_b: str              # The other endpoint
    first_ts: datetime
    last_ts: datetime
    packet_count: int
    bytes_total: int
    matched_by: str              # What in the stream matched the query
    packets: List[StreamPacket]  # Capped at max_packets_per_stream

    @property
    def duration_s(self) -> float:
        if self.first_ts and self.last_ts:
            return (self.last_ts - self.first_ts).total_seconds()
        return 0.0


def _parse_frame_full(
    frame: bytes,
) -> Optional[Tuple[str, str, str, int, int, int, int, bytes]]:
    """Like ``_parse_frame`` but also returns src_ip and TCP flags.

    Returns (proto, src_ip, dst_ip, src_port, dst_port, total_len,
             tcp_flags_byte, l4_payload) or None.
    """
    try:
        if len(frame) < 14:
            return None
        etype = (frame[12] << 8) | frame[13]
        hdr_len = 14
        if etype == 0x8100 and len(frame) >= 18:
            etype = (frame[16] << 8) | frame[17]
            hdr_len = 18
        ip = frame[hdr_len:]
        if etype == 0x0800:  # IPv4
            if len(ip) < 20:
                return None
            ver_ihl = ip[0]
            if (ver_ihl >> 4) != 4:
                return None
            ihl = (ver_ihl & 0x0F) * 4
            if ihl < 20 or len(ip) < ihl:
                return None
            proto_num = ip[9]
            src_ip = ".".join(str(b) for b in ip[12:16])
            dst_ip = ".".join(str(b) for b in ip[16:20])
            total_len = (ip[2] << 8) | ip[3]
            l4 = ip[ihl:]
        elif etype == 0x86DD:  # IPv6
            if len(ip) < 40:
                return None
            if (ip[0] >> 4) != 6:
                return None
            proto_num = ip[6]
            src_ip = _format_ipv6(ip[8:24])
            dst_ip = _format_ipv6(ip[24:40])
            total_len = 40 + ((ip[4] << 8) | ip[5])
            l4 = ip[40:]
            # Walk past extension headers (best-effort; same patterns
            # as _parse_ipv6).
            while proto_num in (0, 43, 44, 50, 51, 60) and len(l4) >= 2:
                proto_num = l4[0]
                ext_len = (l4[1] + 1) * 8
                l4 = l4[ext_len:]
        else:
            return None
        if proto_num == 6 and len(l4) >= 20:  # TCP
            sport = (l4[0] << 8) | l4[1]
            dport = (l4[2] << 8) | l4[3]
            flags = l4[13]
            thl = (l4[12] >> 4) * 4
            payload = l4[thl:] if thl >= 20 and len(l4) >= thl else b""
            return ("tcp", src_ip, dst_ip, sport, dport, total_len, flags, payload)
        if proto_num == 17 and len(l4) >= 8:  # UDP
            sport = (l4[0] << 8) | l4[1]
            dport = (l4[2] << 8) | l4[3]
            return ("udp", src_ip, dst_ip, sport, dport, total_len, 0, l4[8:])
        return None
    except Exception:
        return None


def _format_tcp_flags(flags_byte: int) -> str:
    """Render the TCP-flags byte as a short space-separated string."""
    if flags_byte == 0:
        return ""
    parts = []
    if flags_byte & 0x02:
        parts.append("SYN")
    if flags_byte & 0x10:
        parts.append("ACK")
    if flags_byte & 0x08:
        parts.append("PSH")
    if flags_byte & 0x01:
        parts.append("FIN")
    if flags_byte & 0x04:
        parts.append("RST")
    if flags_byte & 0x20:
        parts.append("URG")
    return " ".join(parts)


def _printable_preview(payload: bytes, limit: int = 60) -> str:
    """Return the first ``limit`` printable chars of ``payload``."""
    if not payload:
        return ""
    out = []
    for b in payload[:limit * 2]:  # over-fetch then trim
        if 32 <= b < 127:
            out.append(chr(b))
        elif b in (9, 10, 13):
            out.append(" ")
        else:
            out.append(".")
        if len(out) >= limit:
            break
    return "".join(out).rstrip()


def follow_streams(
    path: Path,
    query: str,
    *,
    max_packets_per_stream: int = 200,
    max_streams: int = 10,
    max_packets_scanned: int = 500_000,
) -> List[StreamMatch]:
    """Find TCP/UDP flows in ``path`` whose packets reference ``query``,
    then return every packet in those flows (Wireshark-style follow).

    Matching is case-insensitive substring against:
      * source IP, destination IP
      * source port, destination port (literal digits)
      * any printable byte in the L4 payload (handles HTTP host
        headers, DNS qnames, TLS SNI, etc — anything visible in the
        packet)

    The function does TWO passes:
      1. First pass — accumulate packets into per-flow lists, capped
         at ``max_packets_per_stream`` per flow.
      2. Second pass — keep only flows where at least one packet
         matched the query. Returns up to ``max_streams`` flows,
         sorted by first-seen timestamp.

    Memory: bounded — at most max_streams * max_packets_per_stream
    StreamPacket objects on the heap at once.
    """
    q = (query or "").strip().lower()
    if not q:
        return []

    # flow_key = (proto, frozenset({(ip_a, port_a), (ip_b, port_b)}))
    flows: Dict[Any, Dict[str, Any]] = {}
    matched_flows: set = set()
    matched_by: Dict[Any, str] = {}
    pkt_count = 0

    try:
        for ts, frame in _read_pcapng(path):
            pkt_count += 1
            if pkt_count > max_packets_scanned:
                break
            parsed = _parse_frame_full(frame)
            if parsed is None:
                continue
            (proto, src_ip, dst_ip, sport, dport,
             total_len, flags, payload) = parsed

            # Canonical flow key: lexicographic order of (ip, port)
            # pairs so A→B and B→A share a key.
            a = (src_ip, sport)
            b = (dst_ip, dport)
            canonical = tuple(sorted([a, b]))
            flow_key = (proto, canonical)

            flow = flows.get(flow_key)
            if flow is None:
                flow = {
                    "proto": proto,
                    "endpoint_a": f"{canonical[0][0]}:{canonical[0][1]}",
                    "endpoint_b": f"{canonical[1][0]}:{canonical[1][1]}",
                    "first_ts": ts,
                    "last_ts": ts,
                    "packet_count": 0,
                    "bytes_total": 0,
                    "packets": [],
                }
                flows[flow_key] = flow
            flow["last_ts"] = ts
            flow["packet_count"] += 1
            flow["bytes_total"] += total_len

            # Check for query match — once per flow is enough.
            if flow_key not in matched_flows:
                hit = ""
                if q in src_ip.lower() or q in dst_ip.lower():
                    hit = f"IP {src_ip} or {dst_ip}"
                elif q.isdigit() and q in (str(sport), str(dport)):
                    hit = f"port {sport}/{dport}"
                elif payload:
                    preview = _printable_preview(payload, limit=300)
                    if q in preview.lower():
                        # Find the matching window for the operator's
                        # context.
                        i = preview.lower().find(q)
                        snip = preview[max(0, i - 20):i + len(q) + 20]
                        hit = f"payload: …{snip}…"
                if hit:
                    matched_flows.add(flow_key)
                    matched_by[flow_key] = hit

            # Always append to the per-flow packet list (capped).
            if len(flow["packets"]) < max_packets_per_stream:
                direction = "->" if a == canonical[0] else "<-"
                flow["packets"].append(StreamPacket(
                    ts=ts,
                    direction=direction,
                    src_ip=src_ip,
                    src_port=sport,
                    dst_ip=dst_ip,
                    dst_port=dport,
                    proto=proto,
                    length=total_len,
                    tcp_flags=_format_tcp_flags(flags),
                    payload_preview=_printable_preview(payload),
                ))
    except Exception:
        # Best-effort: any parse failure stops the walk but we keep
        # whatever flows we've already accumulated.
        pass

    # Build the result list.
    out: List[StreamMatch] = []
    for i, flow_key in enumerate(sorted(
        matched_flows,
        key=lambda k: flows[k]["first_ts"],
    )):
        if len(out) >= max_streams:
            break
        f = flows[flow_key]
        out.append(StreamMatch(
            stream_id=i,
            proto=f["proto"],
            endpoint_a=f["endpoint_a"],
            endpoint_b=f["endpoint_b"],
            first_ts=f["first_ts"],
            last_ts=f["last_ts"],
            packet_count=f["packet_count"],
            bytes_total=f["bytes_total"],
            matched_by=matched_by.get(flow_key, ""),
            packets=f["packets"],
        ))
    return out


# --------------------------------------------------------------------
# CLI rendering helpers
# --------------------------------------------------------------------


def render_summary(s: PcapSummary, max_rows: int = 15) -> str:
    """Render a single PcapSummary as a human-readable block of text."""
    lines: List[str] = []
    lines.append(f"=== {s.path.name} ===")
    if s.parse_errors:
        for e in s.parse_errors:
            lines.append(f"  ! {e}")
    if s.total_packets == 0:
        lines.append("  (no packets parsed)")
        return "\n".join(lines)
    lines.append(
        f"  Packets: {s.total_packets}    "
        f"Window: {s.ts_first}  ->  {s.ts_last}   ({s.duration_s:.1f}s)"
    )

    def _block(label: str, m: Dict[str, int], cap: int) -> None:
        if not m:
            return
        lines.append(f"  {label} ({len(m)}):")
        # Sort by count desc, then by name for stability.
        for k, v in sorted(m.items(), key=lambda kv: (-kv[1], kv[0]))[:cap]:
            extra = ""
            if label == "SNI hosts":
                ips = sorted(s.sni_to_ips.get(k, set()))
                if ips:
                    extra = f"  ->  {', '.join(ips[:3])}"
                    if len(ips) > 3:
                        extra += f" (+{len(ips) - 3} more)"
            lines.append(f"    {v:8d}  {k}{extra}")
        if len(m) > cap:
            lines.append(f"    ... (+{len(m) - cap} more)")

    _block("DNS queries", s.dns_queries, max_rows)
    _block("SNI hosts", s.sni_hosts, max_rows)
    _block("Destination IPs", s.dest_ips, max_rows)
    return "\n".join(lines)


def render_correlation(
    summaries: Iterable[PcapSummary],
    finding_times: Iterable[Tuple[str, datetime]],
) -> str:
    """Cross-reference each finding's timestamp against pcap windows.

    ``finding_times`` is an iterable of ``(label, ts)`` -- ``label``
    is whatever the caller wants to show (typically the finding code).
    """
    summaries = list(summaries)
    if not summaries:
        return "(no pcaps in bundle)"
    finding_times = list(finding_times)
    if not finding_times:
        return "(no time-anchored findings to correlate)"
    lines: List[str] = ["Finding -> pcap-coverage cross-reference:"]
    for label, ts in finding_times:
        hits = [s.path.name for s in summaries if s.covers(ts)]
        if hits:
            lines.append(f"  [{ts}]  {label}  COVERED BY: {', '.join(hits)}")
        else:
            # Show distance to nearest pcap.
            best = None
            for s in summaries:
                if not s.ts_first or not s.ts_last:
                    continue
                if ts < s.ts_first:
                    d = (s.ts_first - ts).total_seconds()
                elif ts > s.ts_last:
                    d = (ts - s.ts_last).total_seconds()
                else:
                    d = 0
                if best is None or d < best[0]:
                    best = (d, s.path.name)
            if best:
                lines.append(
                    f"  [{ts}]  {label}  not covered "
                    f"({best[0]:.0f}s away from {best[1]})"
                )
            else:
                lines.append(
                    f"  [{ts}]  {label}  no pcap window available"
                )
    return "\n".join(lines)
