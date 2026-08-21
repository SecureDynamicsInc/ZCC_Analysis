# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Generic ZCC log grammar used by deterministic parsers.

These are product-format definitions, not customer observations.  This module
must never contain prevalence counts, customer-derived thresholds, case facts,
or content copied from an uploaded diagnostic run.
"""

from __future__ import annotations

import re


RE_TCP_CONN_CLOSE = re.compile(
    r"ID=(?P<conn>[0-9a-fA-Fx]+),?\s*~ZTCPServerConnection\s+"
    r"state=(?P<state>\w+)\s+ServerConnections=(?P<open>\d+)\s+"
    r"clt_bytes=(?P<clt>\d+),?\s*srv_bytes=(?P<srv>\d+)",
    re.I,
)

RE_UDP_CONN_CLOSE = re.compile(
    r"UDP Proxy: ID: (?P<conn>\d+) Connection closed\..*?"
    r"Local Port: (?P<lport>\d+)\s+Dst Addr: (?P<dst>\S+)\s+"
    r"Tx Bytes: (?P<tx>\d+)\s+TX packets: (?P<txp>\d+)\s+"
    r"Rx Bytes: (?P<rx>\d+)",
    re.I,
)

RE_FLOW_DESTRUCTOR = re.compile(
    r"ID=(?P<conn>[0-9a-fA-Fx]+),\s*ZS(?P<kind>TCP|UDP)FlowHandler "
    r"destructor!!\s*tx bytes\s*=\s*(?P<tx>\d+),\s*"
    r"rx_byptes\s*=\s*(?P<rx>\d+)",
    re.I,
)

RE_ZPA_TAG_BYTES = re.compile(
    r"(?:Zpn client socket written bytes|processResponse rxBytes):\s*"
    r"(?P<bytes>\d+).*?[Tt]ag id:\s*(?P<tag>\d+)",
    re.I,
)

ROUTE_ROW_LABELS = (
    "IP", "Mask", "Adapter", "Type", "SRC_PORT", "DST_PORT",
    "Protocol", "ACTION", "IP_PROTO", "Direction",
)
RE_ROUTE_ROW_ANCHOR = re.compile(r"^\[\s*(?P<idx>\d+)\]\s+IP:")
_ROUTE_LABEL_RE = re.compile(r"\b(" + "|".join(ROUTE_ROW_LABELS) + r"):\s*")


def parse_route_row(line: str) -> dict | None:
    """Parse one complete forwarding-filter row by its named labels."""
    match = RE_ROUTE_ROW_ANCHOR.match(line)
    if not match:
        return None
    result: dict = {"idx": int(match.group("idx"))}
    parts = list(_ROUTE_LABEL_RE.finditer(line))
    for index, part in enumerate(parts):
        end = parts[index + 1].start() if index + 1 < len(parts) else len(line)
        result[part.group(1)] = re.sub(r"\s+", " ", line[part.end():end].strip())
    return result
