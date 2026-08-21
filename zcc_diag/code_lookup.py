"""Reference-code lookup — Slice 5 (2026-08-07).

Unified search across the `data/` package. Given a code query
(symbolic or numeric), find every documented entry across:

    zpa_session_codes.CODES        (SessionStatusCode)
    zpa_auth_errors.ERRORS         (AuthError)
    zia_auth_errors.ERRORS         (ZiaAuthError)
    zia_policy_reasons.REASONS     (PolicyReason)
    zcc_errors.ERRORS              (ZccError)
    zcc_connection_status.STATUSES (ConnStatus)
    zdx_web_probe_errors.ERRORS    (ZdxWebProbeError)
    zdx_cloud_path_errors.ERRORS   (ZdxCloudPathError)
    zdx_managed_probe_errors.ERRORS (ZdxManagedProbeError)
    zdx_remediation_errors.ERRORS  (ZdxRemediationError)

Query semantics:
    * Exact match on `code` field wins outright.
    * Case-insensitive substring match on `code` is second-priority.
    * Full-body substring match (across all string fields) is a
      last-resort catch-all.

Each hit is normalised into a `LookupHit` dataclass so the caller
doesn't care which data module it came from.

Pure library. CLI-shared.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from zcc_diag.error_catalog import catalog_sources, lookup_entries


# --------------------------------------------------------------------------
# Data-module descriptors — everything we know how to look up
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class _Source:
    """Which data module + which symbol + which fields hold what."""
    module: str
    symbol: str
    code_field: str
    label: str


_SOURCES: List[_Source] = []  # retained for import compatibility


# --------------------------------------------------------------------------
# LookupHit dataclass
# --------------------------------------------------------------------------

@dataclass
class LookupHit:
    """One documented entry that matches the query."""
    source: str            # human label (e.g. "ZPA Session Status")
    module: str            # dotted module path
    match_reason: str      # "exact_code" | "substring_code" | "body_substring"
    code: str
    fields: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Loader with caching
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Search entry points
# --------------------------------------------------------------------------

def lookup_code(query: str, limit: Optional[int] = None) -> List[LookupHit]:
    """Search for `query` across every data source. Results ordered by
    match strength (exact > substring on code > body substring).

    `limit` — cap on total hits returned; None for all.
    """
    hits = []
    for entry, reason in lookup_entries(query, limit=limit):
        fields = dict(entry.fields)
        fields.update({
            "_product": entry.product, "_severity": entry.severity,
            "_category": entry.category, "_component": entry.component,
            "_source_url": entry.source_url, "_label": entry.label,
            "_description": entry.description, "_resolution": entry.resolution,
        })
        hits.append(LookupHit(
            source=entry.family, module=entry.module, match_reason=reason,
            code=entry.code, fields=fields,
        ))
    return hits


def known_sources() -> List[str]:
    return list(catalog_sources())
