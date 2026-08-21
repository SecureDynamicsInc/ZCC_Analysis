"""What a 100.64.x.x address in a ZCC log actually is.

An address in this range is almost never a real destination, and treating it as
one sends an investigation the wrong way — engineers try to ping it, or ask the
network team why it is unreachable. It is a *synthetic* address the client
fabricates locally.

Documented behaviour
    ``100.64.0.0/16`` is the default **Zscaler Client Connector Synthetic IP
    Range**, used for Private Access applications, and it is configurable per
    tenant. When a DNS request matches a Private Access application segment the
    client answers it with an address from this pool and then captures traffic
    sent there into the tunnel. A tenant whose LAN overlaps the range can turn
    on *Drop Non-Zscaler Packets in Synthetic IP Range*.
    -- help.zscaler.com/zscaler-client-connector/configuring-zscaler-client-connector-synthetic-ip-range

    The wider ``100.64.0.0/10`` is CGNAT space (RFC 6598), which is why Zscaler
    can use it without colliding with routable customer addressing.

Roles of individual addresses
    Zscaler does not publish a per-address map, and this module does not invent
    one. Two low addresses do have roles that are *observed* in the measured
    corpus this analyzer was built from, and those are labelled as observed
    rather than documented so the distinction survives into the UI. Everything
    else in the range is reported as what it provably is: a synthetic address
    standing in for whatever hostname the client resolved to it.

    The reliable way to learn which application a synthetic address represents
    is the log itself — the DNS interception record that handed it out names the
    hostname. The note points the reader there instead of guessing.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, Optional

#: RFC 6598 shared address space. Zscaler's synthetic range sits inside it.
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

#: Default ZCC synthetic IP range for Private Access applications. Configurable
#: per tenant, so a bundle may legitimately use something else.
DEFAULT_SYNTHETIC_NETWORK = ipaddress.ip_network("100.64.0.0/16")

DOC_URL = (
    "https://help.zscaler.com/zscaler-client-connector/"
    "configuring-zscaler-client-connector-synthetic-ip-range"
)


@dataclass(frozen=True)
class SyntheticNote:
    """What to tell the reader about one address."""

    address: str
    headline: str
    detail: str
    #: "documented" when Zscaler publishes it, "observed" when it comes from the
    #: measured corpus instead. The UI shows the difference.
    basis: str

    @property
    def title(self) -> str:
        """Single-line form for a hover title."""
        qualifier = "" if self.basis == "documented" else " (observed, not vendor-documented)"
        return f"{self.headline}{qualifier} — {self.detail}"


# Addresses whose role is visible in the measured corpus. Kept deliberately
# short: an entry earns its place by appearing in real bundles with an
# unambiguous purpose, not by being plausible.
_OBSERVED_ROLES: Dict[str, tuple] = {
    "100.64.0.6": (
        "ZIA tunnel health check",
        "The client's own TCP echo probe target — bundles show "
        "checkTunTcpEchoServerUpImpl connecting to 100.64.0.6:80 to test that the "
        "internet tunnel is up. A refusal or timeout here is a local interception "
        "or endpoint-firewall problem, not an unreachable server.",
    ),
    "100.64.0.8": (
        "Client probe target",
        "Seen in bundles as a probe destination (port 9090). Treat a failure here "
        "the same way: local, not remote.",
    ),
}


def _is_synthetic(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.version == 4 and address in CGNAT_NETWORK


def describe_address(value: str) -> Optional[SyntheticNote]:
    """Return a note for a synthetic address, or ``None`` for anything else."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not _is_synthetic(address):
        return None

    text = str(address)
    observed = _OBSERVED_ROLES.get(text)
    if observed:
        headline, detail = observed
        return SyntheticNote(text, headline, detail, "observed")

    in_default = address in DEFAULT_SYNTHETIC_NETWORK
    if in_default:
        return SyntheticNote(
            text,
            "ZCC synthetic IP (Private Access)",
            "Not a real destination. The client answered a DNS request for a "
            "Private Access application with this address from its synthetic pool "
            "(default 100.64.0.0/16) and captures traffic sent here into the "
            "tunnel. To find which application it stands for, look for the DNS "
            "record in this log that handed it out.",
            "documented",
        )
    return SyntheticNote(
        text,
        "Shared address space (RFC 6598)",
        "Inside 100.64.0.0/10 but outside the default synthetic range, so either "
        "the tenant configured a different synthetic range or this is carrier "
        "NAT addressing. Not a routable customer address either way.",
        "documented",
    )


_IPV4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b"
)


def notes_in(text: str) -> Dict[str, SyntheticNote]:
    """Every distinct synthetic address mentioned in ``text``."""
    found: Dict[str, SyntheticNote] = {}
    for match in _IPV4_RE.finditer(text or ""):
        note = describe_address(match.group(0))
        if note is not None:
            found[note.address] = note
    return found


def range_summary() -> str:
    """One-paragraph explanation for a legend or caption."""
    return (
        "Addresses in **100.64.0.0/10** are shared address space (RFC 6598), not "
        "routable customer addresses. Zscaler Client Connector's default "
        "**synthetic IP range is 100.64.0.0/16**: when DNS matches a Private "
        "Access application, the client answers with an address from this pool and "
        "captures traffic sent there into the tunnel. So a failure to reach one of "
        "these is a local interception problem, never an unreachable server. The "
        "range is configurable per tenant."
    )
