"""Ready-to-copy Wireshark display filters for ZCC investigations.

These are display filters (``-Y``), not capture filters (``-f``).  Static field
names are validated against Wireshark's display-filter reference.  Tailored
filters add only addresses and DNS names observed in the selected capture.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence, Tuple


WIRESHARK_FILTER_GUIDE = (
    "https://www.wireshark.org/docs/wsug_html_chunked/"
    "ChWorkBuildDisplayFilterSection.html"
)
ZCC_PACKET_CAPTURE_GUIDE = (
    "https://help.zscaler.com/zscaler-client-connector/"
    "enabling-packet-capture-zscaler-client-connector"
)


@dataclass(frozen=True)
class FilterRecipe:
    key: str
    category: str
    title: str
    display_filter: str
    use_when: str
    inspect: str


FILTER_LIBRARY: Tuple[FilterRecipe, ...] = (
    FilterRecipe("dns_failures", "DNS", "All unsuccessful DNS responses",
                 "(dns.flags.response == 1) && (dns.flags.rcode != 0)",
                 "A hostname failed, timed out, or returned a non-success response.",
                 "Expand Domain Name System and compare the query name, response code, resolver, and timing."),
    FilterRecipe("dns_nxdomain", "DNS", "DNS name does not exist (NXDOMAIN)",
                 "(dns.flags.response == 1) && (dns.flags.rcode == 3)",
                 "The application hostname might be wrong, stale, or unavailable in the active DNS view.",
                 "Confirm the exact qname, resolver address, CNAME chain, and whether another resolver succeeds."),
    FilterRecipe("dns_servfail", "DNS", "DNS server failure (SERVFAIL)",
                 "(dns.flags.response == 1) && (dns.flags.rcode == 2)",
                 "The resolver could not complete the lookup.",
                 "Check the responding resolver, recursion path, DNSSEC/forwarder behavior, and repeated attempts."),
    FilterRecipe("dns_slow", "DNS", "Slow DNS responses over one second",
                 "dns.time > 1",
                 "Name resolution is suspected of delaying tunnel or application setup.",
                 "Sort by dns.time and compare the slow names, resolvers, retries, and response codes."),
    FilterRecipe("tcp_syn", "TCP", "Initial TCP connection attempts",
                 "(tcp.flags.syn == 1) && (tcp.flags.ack == 0)",
                 "You need to identify new connections and check whether a SYN-ACK follows.",
                 "Use Conversations or follow the TCP stream; a SYN alone is not proof of failure."),
    FilterRecipe("tcp_resets", "TCP", "TCP resets",
                 "tcp.flags.reset == 1",
                 "A connection was explicitly reset.",
                 "Check source/destination to identify the sender, then inspect the packets immediately before the RST."),
    FilterRecipe("tcp_retransmissions", "TCP", "Suspected TCP retransmissions",
                 "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission",
                 "Loss, delay, reordering, or a capture artifact might be affecting a stream.",
                 "Follow the stream and compare sequence numbers, duplicate ACKs, RTT, and which direction retransmits."),
    FilterRecipe("tcp_window", "TCP", "TCP receive-window pressure",
                 "tcp.analysis.zero_window || tcp.analysis.window_full",
                 "The receiver or application may not be consuming data quickly enough.",
                 "Identify the endpoint advertising the constrained window and correlate it with host load."),
    FilterRecipe("tls_fatal", "TLS", "Fatal TLS alerts",
                 "tls.alert_message.level == 2",
                 "A TLS handshake or encrypted session was explicitly aborted.",
                 "Inspect the alert description, sender, SNI, certificate chain, and preceding handshake messages."),
    FilterRecipe("tls_handshake_failure", "TLS", "TLS handshake_failure alerts",
                 "(tls.alert_message.level == 2) && (tls.alert_message.desc == 40)",
                 "Client and server could not agree on or complete the TLS handshake.",
                 "Compare protocol version, cipher suites, extensions, certificate exchange, and alert sender."),
    FilterRecipe("tls_sni", "TLS", "TLS ClientHello server names",
                 "tls.handshake.extensions_server_name",
                 "You need to map a TLS connection to the requested hostname.",
                 "Add the Server Name column or inspect the ClientHello before following the stream."),
    FilterRecipe("http_connect", "Proxy", "HTTP proxy CONNECT requests and responses",
                 "http.request.method == \"CONNECT\" || http.response.code",
                 "A PAC/local-proxy path or upstream proxy tunnel is suspected.",
                 "Match CONNECT authority to the response code and then follow that TCP stream."),
    FilterRecipe("udp_443", "Tunnel", "UDP 443 tunnel transport",
                 "udp.port == 443",
                 "Z-Tunnel transport selection, UDP reachability, or fallback is under review.",
                 "Confirm bidirectional packets, destination, timing, ICMP errors, and whether TCP 443 follows."),
    FilterRecipe("tcp_443", "Tunnel", "TCP/TLS 443 tunnel transport",
                 "(tcp.port == 443) && (tls || tcp.flags.syn == 1 || tcp.flags.reset == 1)",
                 "You need to inspect TLS-based tunnel setup or fallback on port 443.",
                 "Check the handshake, SNI, TLS alerts, resets, retransmissions, and connection timing."),
    FilterRecipe("icmp_errors", "Path", "IPv4 and IPv6 path errors",
                 "icmp || icmpv6",
                 "Routing, MTU, unreachable, or time-exceeded behavior is suspected.",
                 "Inspect type/code, quoted original packet, sender, and affected destination."),
)


def _addresses_from_endpoint_keys(keys: Iterable[str]) -> Tuple[str, ...]:
    addresses = []
    for value in keys:
        raw = str(value).split(" -> ", 1)[-1].strip()
        if ":tcp/" in raw or ":udp/" in raw:
            raw = raw.rsplit(":", 1)[0]
        elif raw.count(":") == 1 and "." in raw:
            raw = raw.split(":", 1)[0]
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            continue
        addresses.append(raw)
    return tuple(dict.fromkeys(addresses))


def _address_clause(addresses: Iterable[str]) -> str:
    clauses = []
    for value in dict.fromkeys(addresses):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        field = "ipv6.addr" if address.version == 6 else "ip.addr"
        clauses.append(f"{field} == {address}")
    return " || ".join(clauses)


def _with_addresses(base: str, addresses: Iterable[str]) -> str:
    clause = _address_clause(addresses)
    return f"({base}) && ({clause})" if clause else base


def _dns_name(value: str) -> str:
    return str(value).split("  [", 1)[0].strip().rstrip(".")


def dns_failure_filter(qnames: Iterable[str] = ()) -> str:
    base = "(dns.flags.response == 1) && (dns.flags.rcode != 0)"
    names = [_dns_name(name) for name in dict.fromkeys(qnames) if _dns_name(name)]
    if not names:
        return base
    clauses = [f'dns.qry.name == "{name.replace(chr(34), "").replace(chr(92), "")}"'
               for name in names[:8]]
    return f"({base}) && ({' || '.join(clauses)})"


def tcp_reset_filter(endpoint_keys: Iterable[str] = ()) -> str:
    return _with_addresses("tcp.flags.reset == 1", _addresses_from_endpoint_keys(endpoint_keys))


def tcp_retransmission_filter(endpoint_keys: Iterable[str] = ()) -> str:
    base = "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission"
    return _with_addresses(base, _addresses_from_endpoint_keys(endpoint_keys))


def tls_fatal_filter(endpoint_keys: Iterable[str] = ()) -> str:
    return _with_addresses("tls.alert_message.level == 2", _addresses_from_endpoint_keys(endpoint_keys))


def tcp_syn_filter(endpoint_keys: Iterable[str] = ()) -> str:
    base = "(tcp.flags.syn == 1) && (tcp.flags.ack == 0)"
    return _with_addresses(base, _addresses_from_endpoint_keys(endpoint_keys))


def endpoint_display_filter(value: str) -> str:
    """Generate a valid dual-protocol endpoint filter from an IP address."""
    address = ipaddress.ip_address((value or "").strip())
    field = "ipv6.addr" if address.version == 6 else "ip.addr"
    return f"{field} == {address}"


def detected_pcap_filters(pcap: Mapping[str, Any]) -> Tuple[FilterRecipe, ...]:
    """Return tailored recipes only for signals actually present."""
    recipes = []
    dns = pcap.get("dns_nxdomain") or {}
    if sum(dns.values()):
        recipes.append(FilterRecipe(
            "detected_dns", "DNS", f"Failed DNS names found ({sum(dns.values()):,})",
            dns_failure_filter(dns.keys()), "The analyzer found failed DNS responses in this capture.",
            "Compare qname, RCODE, resolver, CNAME chain, and timing for the listed names.",
        ))
    resets = pcap.get("tcp_reset_endpoints") or pcap.get("tcp_resets") or {}
    if sum(resets.values()):
        recipes.append(FilterRecipe(
            "detected_rst", "TCP", f"TCP resets found ({sum(resets.values()):,})",
            tcp_reset_filter(resets.keys()), "The analyzer found RST packets involving these endpoints.",
            "Identify the RST sender and inspect the request, response, or handshake immediately before it.",
        ))
    retransmits = pcap.get("tcp_retransmits") or {}
    if sum(retransmits.values()):
        recipes.append(FilterRecipe(
            "detected_retx", "TCP", f"Suspected retransmissions found ({sum(retransmits.values()):,})",
            tcp_retransmission_filter(retransmits.keys()), "The analyzer found repeated TCP sequence ranges.",
            "Follow the affected stream and distinguish loss from reordering, duplicate capture, or capture boundaries.",
        ))
    alerts = pcap.get("tls_alert_endpoints") or {}
    if sum(alerts.values()):
        recipes.append(FilterRecipe(
            "detected_tls", "TLS", f"Fatal TLS alerts found ({sum(alerts.values()):,})",
            tls_fatal_filter(alerts.keys()), "The analyzer found fatal TLS Alert records.",
            "Identify the sender and alert description, then inspect SNI, certificate, protocol, and cipher context.",
        ))
    syns = pcap.get("tcp_syns") or {}
    syn_acks = pcap.get("tcp_syn_acks") or {}
    unanswered = {key: max(int(count) - int(syn_acks.get(key, 0)), 0)
                  for key, count in syns.items()}
    unanswered = {key: count for key, count in unanswered.items() if count}
    if unanswered:
        recipes.append(FilterRecipe(
            "detected_syn", "TCP", f"SYN attempts without captured SYN-ACK ({sum(unanswered.values()):,})",
            tcp_syn_filter(unanswered.keys()), "The capture contains more SYN than SYN-ACK observations for these endpoints.",
            "Follow each conversation and check for later SYN-ACK, RST, ICMP, capture boundaries, or another adapter.",
        ))
    return tuple(recipes)
