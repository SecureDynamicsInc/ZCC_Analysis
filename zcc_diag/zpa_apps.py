"""
ZPA application registry extractor.

What this is
------------
At ZPA tunnel-up time, the broker pushes a list of every ZPA app
segment configured for the user. Each segment appears in the tunnel
log as a control-message JSON payload:

    {"zpn_client_app":{
        "app_domain":"rds.corp-a.example",
        "ingress_port_ranges":[443,443, 3389,3389],
        "tcp_port_ranges":[443,443, 3389,3389],
        "udp_port_ranges":[443,443, 3389,3389],
        "deleted":0,
        "bypass":0,
        "icmp_access_type":"PING",
        "bypass_on_reauth":0,
        "double_encrypt":0,
        "bypass_type":"NEVER",
        "has_next":1
    }}

This module walks the tunnel logs and reconstructs the ZPA app
catalog — what apps were configured at the time of the bundle, what
ports they cover, whether they're bypassed, whether ICMP is allowed,
double-encrypt status, and the bypass-on-reauth flag.

Why this matters
----------------
1. The triage engineer can verify "is the app the customer is trying
   to reach actually configured?". Without this they have to ask
   the customer to send a screenshot of the ZPA Admin Console.
2. When the broker closes an mtunnel for a specific App Name (the
   BRK_MT_CLOSED_FROM_ASSISTANT detector), cross-referencing the App
   Name against this registry tells us whether the app is BYPASSED
   (shouldn't be going through the broker at all) or DELETED (the
   app was removed but the client's cache still has a session).
3. The bypass list shows what's deliberately not going through ZPA —
   useful when a customer complains "X isn't working through ZPA"
   and the answer is "because you've configured it as ALWAYS bypass".

Pure function — takes a bundle log_index, returns a list of dicts.
The caller (analyse.py) stashes the result on
``summary.bundle_meta["zpa_apps"]``.

Limitations
-----------
- The catalog is a snapshot at the time the broker last pushed config.
  If the customer added an app AFTER the bundle was exported, it
  won't appear here.
- The bundle can carry multiple pushes (one per broker connect /
  reauth). We deduplicate by app_domain, keeping the most recent
  entry per domain — so the catalog reflects the LATEST known state.
- A ``deleted:1`` entry means the broker told the client to forget
  this app. We keep these in the registry too (separately flagged) so
  the engineer can see "this app was here, then removed at HH:MM".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# Regex that scopes us to just the JSON envelope of a zpn_client_app
# event. We then json.loads() the captured object — more robust than
# field-by-field regex against the keys, which Zscaler is free to add
# or reorder over time.
_RE_ZPA_APP_JSON = re.compile(
    r'\{"zpn_client_app":(?P<payload>\{[^}]*\})\}'
)


@dataclass
class ZpaApp:
    """One entry in the ZPA app catalog as it appeared in the bundle."""
    app_domain: str
    tcp_port_ranges: List[int] = field(default_factory=list)
    udp_port_ranges: List[int] = field(default_factory=list)
    ingress_port_ranges: List[int] = field(default_factory=list)
    bypass: bool = False
    bypass_type: str = ""           # NEVER / ALWAYS / ON_NET / etc.
    icmp_access_type: str = ""      # NONE / PING / FULL
    bypass_on_reauth: bool = False
    double_encrypt: bool = False
    deleted: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    push_count: int = 0  # how many config pushes mentioned this app


def _summarise_port_ranges(ranges: List[int]) -> str:
    """The JSON gives port ranges as pairs of [low, high, low, high, ...].
    Render as a human-readable string: "443, 3389" or "8000-8099, 9000"."""
    if not ranges or len(ranges) % 2 != 0:
        return ""
    out = []
    for i in range(0, len(ranges), 2):
        lo, hi = ranges[i], ranges[i + 1]
        if lo == hi:
            out.append(str(lo))
        else:
            out.append(f"{lo}-{hi}")
    return ", ".join(out)


def extract_zpa_apps(log_index) -> Dict[str, Any]:
    """Walk the tunnel-log line index for zpn_client_app events and
    build the app catalog. Returns a dict ready to be merged into
    ``summary.bundle_meta``.

    Output shape::

        {
            "apps": [ZpaApp, ZpaApp, ...],   # all unique app_domains
            "total_pushes": N,               # total number of JSON events seen
            "push_windows": [(t0, t1), ...], # time spans of config pushes
        }

    Apps are returned sorted by (deleted ascending, app_domain ascending)
    so live apps come first and deleted ones at the bottom.
    """
    apps: Dict[str, ZpaApp] = {}
    pushes: List[datetime] = []

    if log_index is None or not getattr(log_index, "lines", None):
        return {"apps": [], "total_pushes": 0, "push_windows": []}

    for ln in log_index.lines:
        body = ln.body if hasattr(ln, "body") else ""
        if "zpn_client_app" not in body:
            continue
        m = _RE_ZPA_APP_JSON.search(body)
        if not m:
            continue
        try:
            data = json.loads(m.group("payload"))
        except (json.JSONDecodeError, ValueError):
            continue

        domain = (data.get("app_domain") or "").strip()
        if not domain:
            continue

        ts = getattr(ln, "ts", None) or getattr(ln, "timestamp", None)
        pushes.append(ts) if ts is not None else None

        existing = apps.get(domain)
        if existing is None:
            existing = ZpaApp(app_domain=domain, first_seen=ts, last_seen=ts)
            apps[domain] = existing
        # Always overwrite mutable fields with the most recent push so
        # the catalog reflects current state.
        existing.tcp_port_ranges = list(data.get("tcp_port_ranges") or [])
        existing.udp_port_ranges = list(data.get("udp_port_ranges") or [])
        existing.ingress_port_ranges = list(data.get("ingress_port_ranges") or [])
        existing.bypass = bool(data.get("bypass") or 0)
        existing.bypass_type = (data.get("bypass_type") or "").strip()
        existing.icmp_access_type = (data.get("icmp_access_type") or "").strip()
        existing.bypass_on_reauth = bool(data.get("bypass_on_reauth") or 0)
        existing.double_encrypt = bool(data.get("double_encrypt") or 0)
        existing.deleted = bool(data.get("deleted") or 0)
        existing.push_count += 1
        if ts is not None:
            if existing.first_seen is None or ts < existing.first_seen:
                existing.first_seen = ts
            if existing.last_seen is None or ts > existing.last_seen:
                existing.last_seen = ts

    sorted_apps = sorted(
        apps.values(),
        key=lambda a: (1 if a.deleted else 0, a.app_domain.lower()),
    )

    push_windows = []
    if pushes:
        pushes.sort()
        # Group pushes that arrive within 5s of each other into a single
        # "push window" — a broker config push typically dumps 50+ apps
        # in a few hundred ms.
        cur_start = pushes[0]
        cur_end = pushes[0]
        for t in pushes[1:]:
            if (t - cur_end).total_seconds() <= 5:
                cur_end = t
            else:
                push_windows.append((cur_start, cur_end))
                cur_start = t
                cur_end = t
        push_windows.append((cur_start, cur_end))

    return {
        "apps": sorted_apps,
        "total_pushes": len(pushes),
        "push_windows": push_windows,
    }


def find_app_for_domain(
    apps: List[ZpaApp],
    domain: str,
) -> Optional[ZpaApp]:
    """Look up a ZpaApp by domain (case-insensitive). Returns the most
    specific match if multiple exist. Used by other modules (e.g. the
    broker-assistant-close finding card) to cross-reference an App Name
    against the registry."""
    if not domain or not apps:
        return None
    d = domain.lower().strip()
    # Exact match first.
    for a in apps:
        if a.app_domain.lower() == d:
            return a
    # Fall back to a suffix match (the App Name in the BRK_MT line is
    # often a sub-host like "storefront.corp-a.example" while the registry
    # has "*.corp-a.example" — match by domain suffix).
    for a in apps:
        rad = a.app_domain.lower().lstrip("*.").lstrip(".")
        if rad and d.endswith(rad):
            return a
    return None


# ──────────────────────────────────────────────────────────────────────
# Broker DC extraction
# ──────────────────────────────────────────────────────────────────────

# Broker hostname formats — TWO variants seen in Zscaler infra docs:
#   broker<pool>-<idx>.<DC>.prod.zpath.net  (e.g. broker6-2.den3.*)
#   broker<pool><letter>.<DC>.prod.zpath.net (e.g. broker1b.was2.*)
#
# Validated 2026-06-12 via help.zscaler.com documentation references
# (search: "ZPA broker hostname prod.zpath.net"). The <DC> field is
# the ZPA Public Service Edge region code (den3, sjc1, was1, was2,
# sha1, etc).
_RE_BROKER_HOST = re.compile(
    r"broker\d+(?:[a-z]+|-\d+)\.(?P<dc>[a-z]+\d+)\.prod\.zpath\.net",
    re.IGNORECASE,
)


def extract_zpa_broker_dcs(log_index) -> Dict[str, Any]:
    """Walk the log_index for ZPA broker hostnames and extract the
    unique DC codes seen. Returns a dict ready to merge into
    summary.bundle_meta.

    The DC code identifies the ZPA Public Service Edge region that
    the client connected to (den3 = Denver-3, sjc1 = San Jose-1, etc).
    Useful in the Header strip so engineers can validate the user is
    hitting the expected region.

    Output shape::

        {
            "dcs": ["den3", "sjc1"],
            "broker_hostnames": ["broker6-2.den3.prod.zpath.net", ...],
            "primary_dc": "den3",   # most-frequent DC across observations
        }
    """
    if log_index is None or not getattr(log_index, "lines", None):
        return {"dcs": [], "broker_hostnames": [], "primary_dc": ""}

    from collections import Counter
    dc_counts: Counter = Counter()
    seen_hosts: set = set()

    for ln in log_index.lines:
        body = ln.body if hasattr(ln, "body") else ""
        if "zpath.net" not in body:
            continue
        for m in _RE_BROKER_HOST.finditer(body):
            host = m.group(0).lower()
            seen_hosts.add(host)
            dc_counts[m.group("dc").lower()] += 1

    dcs_sorted = [dc for dc, _ in dc_counts.most_common()]
    primary = dcs_sorted[0] if dcs_sorted else ""
    return {
        "dcs": dcs_sorted,
        "broker_hostnames": sorted(seen_hosts),
        "primary_dc": primary,
    }


def format_port_summary(app: ZpaApp) -> str:
    """One-liner for table rendering: 'TCP 443, 3389  UDP 443, 3389'."""
    bits = []
    tcp = _summarise_port_ranges(app.tcp_port_ranges)
    if tcp:
        bits.append(f"TCP {tcp}")
    udp = _summarise_port_ranges(app.udp_port_ranges)
    if udp and udp != tcp:
        bits.append(f"UDP {udp}")
    return "  ".join(bits) if bits else "(none)"
