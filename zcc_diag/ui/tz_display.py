"""
Timezone-aware timestamp rendering for the UI.

Phase 58b (2026-07-02) — semantics flipped.
==========================================

Zscaler support-bundle log lines look like::

    2026-06-12 17:50:20.572790(-0600)[14608:17148] INF ...

Prior to Phase 58a we treated the numeric HH:MM:SS as wall-clock-local
in the device's timezone and applied ``(-0600)`` to compute UTC. That
was **wrong**: the numeric portion is already UTC, and the ``(-HHMM)``
is metadata telling you the device's local offset. See the module
docstring of :mod:`zcc_diag.log_parser` for the proof trail (filename
timestamp + Linux file mtime cross-check).

**After Phase 58a**, every ``LogLine.timestamp`` and ``IndexedLine.ts``
is a ``datetime`` with ``tzinfo=timezone.utc``. The helpers in this
module all take a UTC datetime and render it as ``UTC + local``
side-by-side so the engineer can cross-reference either way.

Public helpers:
  * :func:`get_bundle_tz_offset` — the ``-0600`` string.
  * :func:`get_bundle_tz_label`  — the ``UTC-06:00`` label.
  * :func:`derive_tz_label`      — offset → tz abbrev ("MDT").
  * :func:`to_local`             — UTC datetime → local wall-clock.
  * :func:`format_dual`          — canonical dual-render:
      "13:51:26 UTC (07:51 MDT)". Use this everywhere.
  * :func:`format_ts_with_tz`    — legacy: full-precision dual ISO.
  * :func:`format_ts_with_tz_and_utc` — legacy: kept as alias to
      :func:`format_dual` for backward-compat callers.

Old ``to_utc`` (local→UTC) is now a no-op identity because timestamps
are already UTC. Kept for API stability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


def get_bundle_tz_offset() -> Optional[str]:
    """Return the active bundle's TZ offset (e.g. "-0600"), or None
    when no bundle is loaded / the log_index didn't capture one."""
    from zcc_diag.ui.log_context import get_log_index
    idx = get_log_index()
    if idx is None:
        return None
    return getattr(idx, "bundle_tz_offset", None)


def get_bundle_tz_label() -> Optional[str]:
    """Return the human label form, e.g. "UTC-06:00"."""
    from zcc_diag.ui.log_context import get_log_index
    idx = get_log_index()
    if idx is None:
        return None
    return getattr(idx, "bundle_tz_label", None)


def format_ts_with_tz(ts: Any) -> str:
    """Full-precision dual-render: ``UTC ISO / LOCAL ISO``.

    Phase 58b (2026-07-02): ``ts`` is now expected to be a tz-aware
    UTC datetime. We keep the offset suffix on the UTC form and add
    a bracketed local form for engineers who need to match wall-clock
    references from customer tickets.

    Examples:
      ts = datetime(2026,6,12,17,50,20,572790, tzinfo=UTC)
      offset = "-0600"
        -> "2026-06-12T17:50:20.572790+00:00 (2026-06-12T11:50:20-06:00 MDT)"
      offset = None
        -> "2026-06-12T17:50:20.572790+00:00"
    """
    if ts is None:
        return ""
    if not isinstance(ts, datetime):
        return str(ts)
    # Ensure UTC-aware for the UTC half.
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    utc_iso = ts.astimezone(timezone.utc).isoformat()
    offset = get_bundle_tz_offset()
    if not offset or len(offset) != 5:
        return utc_iso
    local = to_local(ts, offset)
    if local is None:
        return utc_iso
    sign = offset[0]
    local_iso = (
        local.replace(tzinfo=None).isoformat()
        + f"{sign}{offset[1:3]}:{offset[3:5]}"
    )
    label = derive_tz_label(offset)
    return f"{utc_iso} ({local_iso} {label})" if label else \
        f"{utc_iso} ({local_iso})"


# Phase 45 (2026-06-24): tz-name derivation + UTC equivalent.
#
# Background: a customer in Eastern time reports an incident "around
# 11am EST." In June, the wall-clock-local offset is actually -0400
# (EDT, not EST). Windows AppInfo.xml reports the STANDARD offset
# year-round ("(UTC-05:00) Eastern Time") which is misleading during
# DST. The log line carries the OBSERVED offset on every line —
# trust the log line. Memory note:
# [[feedback-tz-offset-from-log-line]].
#
# Adding the UTC equivalent matters because Microsoft Entra Sign-in
# Logs store events in UTC. When the customer admin pulls Entra logs
# to cross-reference, they need to search for UTC timestamps, not
# wall-clock-local.

# Common offset → human tz name map. Covers the offsets we've seen
# in real bundles. Anything not in this map renders as "(UTC±HH:MM)".
# Each entry: offset → (DST name, STD name, "DST" or "STD" disambiguator
# requires month-of-year — see _tz_name_for_offset).
_OFFSET_NAMES = {
    "-0500": ("EDT", "CDT", "EST", "CDT"),   # ambiguous — see below
    "-0400": ("EDT", None, None, None),
    "-0700": ("MDT", "PDT", "MST", "PDT"),
    "-0600": ("MDT", "CST", "MST", "CDT"),
    "-0800": ("PST", None, "PST", None),
    "+0000": ("UTC", None, "UTC", None),
    "+0100": ("CET", "BST", "CET", "BST"),
    "+0530": ("IST", None, "IST", None),   # India
    "+0900": ("JST", "KST", "JST", "KST"),
    "+1000": ("AEST", None, "AEST", None),
    "+1100": ("AEDT", None, "AEDT", None),
}

# US-Eastern: STD=EST=-0500, DST=EDT=-0400. Resolve via offset only
# (the offset already tells us which one is observed).
_OFFSET_SIMPLE_NAMES = {
    "-0400": "EDT", "-0500": "EST",
    "-0600": "CST", "-0700": "MST",   # could be CDT/MDT in DST; both -0600/-0700 → ambiguous
    "-0800": "PST",
    "+0000": "UTC",
    "+0100": "CET",   # could be BST in DST
    "+0530": "IST",
    "+0900": "JST",
    "+1000": "AEST",
    "+1100": "AEDT",
}


def derive_tz_label(offset: Optional[str]) -> str:
    """Map a log-line offset string ("-0400") to a human tz label
    ("EDT", "UTC-04:00"). Falls back to "UTC±HH:MM" if the offset is
    not in the well-known map.

    The label is intended for the Bundle Facts section of the RCA
    and the Header strip — short, recognisable, unambiguous.
    """
    if not offset or len(offset) != 5:
        return ""
    name = _OFFSET_SIMPLE_NAMES.get(offset)
    if name:
        return name
    sign = offset[0]
    return f"UTC{sign}{offset[1:3]}:{offset[3:5]}"


def _offset_to_timedelta(offset: str):
    """Parse "-0400" into a timedelta of -4 hours. Returns None on
    malformed input."""
    from datetime import timedelta
    if not offset or len(offset) != 5:
        return None
    try:
        sign = -1 if offset[0] == "-" else 1
        hh = int(offset[1:3])
        mm = int(offset[3:5])
        return timedelta(hours=sign * hh, minutes=sign * mm)
    except (ValueError, IndexError):
        return None


def to_utc(ts: Any, offset: Optional[str] = None):
    """Phase 58b (2026-07-02): timestamps are already UTC, so this is
    now effectively identity — kept for API stability.

    Ensures the returned datetime is tz-aware UTC. If ts is naive we
    attach ``timezone.utc``; if it has a different tz we convert.
    Returns None if ts is None or not a datetime.
    """
    if ts is None or not isinstance(ts, datetime):
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def to_local(ts: Any, offset: Optional[str] = None):
    """Convert a UTC datetime into wall-clock local using ``offset``.

    ``offset`` is the log-line form ("-0600"). If None, falls back to
    the active bundle's offset.

    Returns a tz-naive datetime whose YMDHMS fields are the local
    wall-clock (matches how customers phrase issue times). Returns
    None on parse errors.
    """
    if ts is None or not isinstance(ts, datetime):
        return None
    if offset is None:
        offset = get_bundle_tz_offset()
    delta = _offset_to_timedelta(offset)
    if delta is None:
        return None
    utc = ts.replace(tzinfo=None) if ts.tzinfo is None else \
        ts.astimezone(timezone.utc).replace(tzinfo=None)
    # Local = UTC + offset. For "-0600" delta is -6h, so add it.
    return utc + delta


def format_dual(ts: Any, *, seconds: bool = True) -> str:
    """Canonical dual-render: ``HH:MM:SS UTC (HH:MM:SS TZ)``.

    Phase 58b (2026-07-02) — the format engineers should see everywhere
    they need to correlate against customer-reported wall-clock times.
    UTC comes first because it's the source of truth in the log and
    the reference used by IdP admin consoles (Entra, Okta) for
    Sign-in Logs.

    Examples:
      ts = 13:51:26 UTC, offset = "-0600"
        seconds=True  -> "13:51:26 UTC (07:51:26 MDT)"
        seconds=False -> "13:51 UTC (07:51 MDT)"
      ts = 13:51:26 UTC, offset = None
        -> "13:51:26 UTC"
    """
    if ts is None:
        return ""
    if not isinstance(ts, datetime):
        return str(ts)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    fmt = "%H:%M:%S" if seconds else "%H:%M"
    utc_str = ts.astimezone(timezone.utc).strftime(fmt) + " UTC"
    offset = get_bundle_tz_offset()
    if not offset:
        return utc_str
    local = to_local(ts, offset)
    if local is None:
        return utc_str
    label = derive_tz_label(offset)
    local_str = local.strftime(fmt)
    if label:
        return f"{utc_str} ({local_str} {label})"
    return f"{utc_str} ({local_str})"


def format_ts_with_tz_and_utc(ts: Any) -> str:
    """Legacy name for :func:`format_dual`. Semantics flipped in
    Phase 58b to put UTC first (source-of-truth first)."""
    return format_dual(ts, seconds=True)


# Backwards-compat aliases.
_get_bundle_tz_offset = get_bundle_tz_offset
_get_bundle_tz_label = get_bundle_tz_label
_format_ts_with_tz = format_ts_with_tz
