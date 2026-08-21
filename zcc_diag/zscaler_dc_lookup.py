"""
Zscaler DC lookup from the reviewed inline Cloud Enforcement Node ranges.

Resolves a Zscaler Service Edge (SME) IP to its DC airport code (DFW2,
AMS3, LON5, etc.) by checking the IP against the CIDR ranges published
at https://api.config.zscaler.com/<cloud>/cenr/json.

The app does not download or persist a range database at runtime. Updates to
the reviewed public reference table must arrive through a normal pull request.

This module is the *authoritative* tier for SME → DC resolution:
- A Zscaler-allocated /23 always maps to exactly one DC
- The /24 and /16 heuristics are best-effort and sometimes mislabel
  (e.g. two DCs in the same /16 across regions)

When CENR is loaded, ``label_sme_ip()`` checks here FIRST, before the
heuristics, so the answer is always grounded in Zscaler's own routing
table.

Schema (compact form, schema "2.0-compact"):
    {
      "_meta": {...},
      "clouds":     ["zscaler.net", "zscalertwo.net", ...],
      "codes":      ["AMS2", "AMS3", "DFW2", ...],
      "cities":     ["Amsterdam II", "Dallas II", ...],
      "continents": ["NAMER", "EMEA", "APAC"],
      "ranges": [
         # [cidr, cloud_idx, code_idx, city_idx, continent_idx, lat, lon]
         ["136.226.74.0/23", 0, 12, 7, 1, 32.7767, -96.7970],
         ...
      ]
    }

Lookup uses Python's stdlib ``ipaddress`` module — no third-party deps.
Initial CIDR network parsing is cached in memory after the first
lookup so subsequent lookups are O(log n) over a pre-sorted list.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple


# ----- In-memory cache -----------------------------------------------
#
# Parsed once per process. Each entry is a tuple:
#   (network_obj, cloud, code, city, continent, lat, lon)
# Stored as a flat list sorted by network_obj.network_address so we can
# binary-search the candidate /24 or /16 block.

_CACHE: Optional[List[Tuple]] = None
_LOAD_ERROR: Optional[str] = None


def _load() -> List[Tuple]:
    """Load the version-controlled public reference table into memory."""
    global _CACHE, _LOAD_ERROR
    if _CACHE is not None:
        return _CACHE

    out: List[Tuple] = []
    try:
        from . import zscaler_dc_inline
        for cidr, cloud, code, city, cont, lat, lon in \
                zscaler_dc_inline.INLINE_RANGES:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            out.append((net, cloud, code, city, cont, lat, lon))
    except Exception as exc:  # pragma: no cover -- inline missing
        _LOAD_ERROR = f"Inline starter failed: {exc}"

    out.sort(key=lambda t: int(t[0].network_address))
    _CACHE = out
    if out:
        _LOAD_ERROR = None
    if not out and not _LOAD_ERROR:
        _LOAD_ERROR = "No CENR data available."
    return _CACHE


# ----- Public API ----------------------------------------------------


def is_available() -> bool:
    """Return True iff the CENR data file is loaded and non-empty."""
    return bool(_load())


def load_status() -> str:
    """Return a human-readable status for the reviewed inline table."""
    cache = _load()
    if not cache:
        return _LOAD_ERROR or "CENR data not loaded"
    clouds = len({t[1] for t in cache})
    return f"CENR loaded — reviewed inline table ({len(cache)} ranges across {clouds} clouds)"


def lookup_dc_by_ip(ip: str) -> Optional[Dict[str, object]]:
    """Resolve a single IP address to its Zscaler DC.

    Returns a dict ``{cloud, code, city, continent, lat, lon, cidr}``
    on match, or ``None`` if the IP doesn't fall inside any known
    CENR range (i.e. it's not a Zscaler IP, or our data file is stale).

    IPv6 addresses are accepted but the shipped data set is IPv4-only,
    so they'll typically return None until the fetch script is enhanced.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None

    cache = _load()
    if not cache:
        return None

    # Linear scan first — the data set is small (~1800 ranges) and
    # the per-lookup overhead of constructing a bisect bracket isn't
    # worth it. If profiling later shows this is hot, replace with a
    # patricia trie.
    for net, cloud, code, city, cont, lat, lon in cache:
        if net.version != addr.version:
            continue
        if addr in net:
            return {
                "cidr": str(net),
                "cloud": cloud,
                "code": code,
                "city": city,
                "continent": cont,
                "lat": lat,
                "lon": lon,
            }
    return None


def reload_data() -> str:
    """Force-reload the reviewed inline table (primarily for tests)."""
    global _CACHE, _LOAD_ERROR
    _CACHE = None
    _LOAD_ERROR = None
    return load_status()
