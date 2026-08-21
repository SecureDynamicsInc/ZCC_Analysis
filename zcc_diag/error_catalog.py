"""Normalized, source-backed Zscaler error and status catalog.

The project keeps the documented rows in small Python data modules so it can
work entirely offline.  This module is the single adapter between those rows
and callers that need lookup, log matching, severity, or reference metadata.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


@dataclass(frozen=True)
class _Source:
    module: str
    symbol: str
    product: str
    family: str
    code_fields: Tuple[str, ...]
    label_fields: Tuple[str, ...]
    description_fields: Tuple[str, ...]
    resolution_fields: Tuple[str, ...]
    component_fields: Tuple[str, ...]
    source_url: str
    phrase_match: bool = True


_SOURCES: Tuple[_Source, ...] = (
    _Source("zpa_session_codes", "CODES", "ZPA", "ZPA Session Status", ("code",),
            ("session_status",), ("description",), ("resolution",), ("component",),
            "https://help.zscaler.com/zpa/understanding-zpa-session-status-codes", False),
    _Source("zpa_auth_errors", "ERRORS", "ZPA", "ZPA Authentication", ("code",),
            ("error_message",), ("error_description",), ("resolution",), ("group",),
            "https://help.zscaler.com/zscaler-client-connector/zscaler-client-connector-zpa-authentication-errors"),
    _Source("zia_auth_errors", "ERRORS", "ZIA", "ZIA Authentication", ("code",),
            ("error_description",), ("error_when",), ("recommended_action",), ("category",),
            "https://help.zscaler.com/zia/zia-authentication-error-codes"),
    _Source("zia_policy_reasons", "REASONS", "ZIA", "ZIA Policy Reasons", ("name",),
            ("name",), ("description",), (), ("feature",),
            "https://help.zscaler.com/zia/policy-reasons", False),
    _Source("zcc_errors", "ERRORS", "ZCC", "ZCC Errors", ("code",),
            ("error_message",), ("error_description",), ("resolution",), ("series",),
            "https://help.zscaler.com/zscaler-client-connector/zscaler-client-connector-errors"),
    _Source("zcc_connection_status", "STATUSES", "ZCC", "ZCC Connection Status", ("name",),
            ("name",), ("explanation",), ("required_action",), ("scope",),
            "https://help.zscaler.com/zscaler-client-connector/zscaler-client-connector-connection-status-errors"),
    _Source("zdx_web_probe_errors", "ERRORS", "ZDX", "ZDX Web Probe", ("identifier", "error_message"),
            ("error_message",), ("error_description",), ("recommended_action",), ("probe_phase",),
            "https://help.zscaler.com/zdx/web-probe-errors"),
    _Source("zdx_cloud_path_errors", "ERRORS", "ZDX", "ZDX Cloud Path", ("identifier", "error_message"),
            ("error_message",), ("error_description",), ("recommended_action",), ("probe_phase",),
            "https://help.zscaler.com/zdx/cloud-path-errors"),
    _Source("zdx_managed_probe_errors", "ERRORS", "ZDX", "ZDX Managed Probe", ("identifier", "error_message"),
            ("error_message",), ("error_description",), ("recommended_action",), ("probe_type", "category"),
            "https://help.zscaler.com/zdx/zscaler-managed-probe-errors"),
    _Source("zdx_remediation_errors", "ERRORS", "ZDX", "ZDX Remediation", ("code",),
            ("error_message",), ("error_description",), ("recommended_action",), ("family",),
            "https://help.zscaler.com/zdx/remediation-errors"),
)


@dataclass(frozen=True)
class CatalogEntry:
    catalog_id: str
    product: str
    family: str
    code: str
    aliases: Tuple[str, ...]
    label: str
    description: str
    resolution: str
    severity: str
    category: str
    component: str
    source_url: str
    module: str
    fields: Mapping[str, Any]


def _first(row: Mapping[str, Any], names: Sequence[str]) -> str:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value).strip()
    return ""


@lru_cache(maxsize=1)
def catalog_entries() -> Tuple[CatalogEntry, ...]:
    entries: List[CatalogEntry] = []
    for source in _SOURCES:
        module_name = f"zcc_diag.data.{source.module}"
        rows = list(getattr(importlib.import_module(module_name), source.symbol))
        for number, raw in enumerate(rows, start=1):
            row = dict(raw)
            aliases = tuple(dict.fromkeys(
                str(row.get(field, "")).strip()
                for field in source.code_fields
                if str(row.get(field, "")).strip()
            ))
            if not aliases:
                continue
            code = aliases[0]
            label = _first(row, source.label_fields) or code.replace("_", " ").title()
            category = str(row.get("category") or row.get("group") or "").strip()
            component = _first(row, source.component_fields)
            entries.append(CatalogEntry(
                catalog_id=f"{source.module}:{number}",
                product=source.product,
                family=source.family,
                code=code,
                aliases=aliases,
                label=label,
                description=_first(row, source.description_fields),
                resolution=_first(row, source.resolution_fields),
                severity=str(row.get("severity_hint") or "info").lower(),
                category=category,
                component=component,
                source_url=source.source_url,
                module=module_name,
                fields=row,
            ))
    return tuple(entries)


def catalog_sources() -> Tuple[str, ...]:
    return tuple(source.family for source in _SOURCES)


def lookup_entries(query: str, limit: int | None = None) -> List[Tuple[CatalogEntry, str]]:
    """Return entries as ``(entry, match_reason)`` in relevance order."""
    q = (query or "").strip().casefold()
    if not q:
        return []
    exact, partial, body = [], [], []
    for entry in catalog_entries():
        aliases = [alias.casefold() for alias in entry.aliases]
        if q in aliases:
            exact.append((entry, "exact_code"))
        elif any(q in alias for alias in aliases):
            partial.append((entry, "substring_code"))
        elif q in "\n".join((entry.label, entry.description, entry.resolution,
                              entry.category, entry.component)).casefold():
            body.append((entry, "body_substring"))
    results = exact + partial + body
    return results if limit is None else results[:limit]


_SYMBOLIC_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){1,}\b", re.IGNORECASE)
_HEX_RE = re.compile(r"(?i)\b0x[0-9a-f]{2,8}\b")
_NUMERIC_RE = re.compile(
    r"(?i)\b(?:error[ _-]?code|err(?:or)?[ _-]?code|err_code|returned[ _-]?code)"
    r"\b\s*[:=]?\s*(?P<code>-?\d{1,6})\b"
)
_PA_RE = re.compile(r"(?i)\bPA_ERROR_(?P<code>\d{4,6})\b")
_WORD_RE = re.compile(r"[a-z0-9_]{5,}")


@lru_cache(maxsize=1)
def _alias_index() -> Dict[str, Tuple[CatalogEntry, ...]]:
    index: Dict[str, List[CatalogEntry]] = {}
    for entry in catalog_entries():
        for alias in entry.aliases:
            index.setdefault(alias.casefold(), []).append(entry)
    return {key: tuple(value) for key, value in index.items()}


@lru_cache(maxsize=1)
def _phrase_index() -> Dict[str, Tuple[Tuple[str, CatalogEntry], ...]]:
    """Index documented operator-visible messages by a distinctive anchor."""
    enabled = {source.family for source in _SOURCES if source.phrase_match}
    phrases: Dict[str, List[CatalogEntry]] = {}
    for entry in catalog_entries():
        if entry.family not in enabled or entry.severity == "info":
            continue
        for phrase in dict.fromkeys((entry.label, *entry.aliases[1:])):
            clean = " ".join(phrase.casefold().split())
            words = _WORD_RE.findall(clean)
            if len(clean) < 12 or not words:
                continue
            phrases.setdefault(clean, []).append(entry)
    index: Dict[str, List[Tuple[str, CatalogEntry]]] = {}
    for clean, matches in phrases.items():
        # Many documented numeric codes intentionally share a generic screen
        # message. Without the number, assigning one of them would be a guess.
        if len({entry.code.casefold() for entry in matches}) != 1:
            continue
        words = _WORD_RE.findall(clean)
        anchor = max(words, key=len)
        for entry in matches:
            index.setdefault(anchor, []).append((clean, entry))
    return {key: tuple(value) for key, value in index.items()}


def explicit_codes(body: str) -> Iterable[str]:
    """Yield code-shaped tokens while keeping bare numbers contextual."""
    text = body or ""
    yield from _SYMBOLIC_RE.findall(text)
    yield from _HEX_RE.findall(text)
    for match in _NUMERIC_RE.finditer(text):
        yield match.group("code")
    for match in _PA_RE.finditer(text):
        yield match.group("code")


def match_known_codes(body: str) -> List[CatalogEntry]:
    """Match documented identifiers and high-confidence literal messages."""
    text = body or ""
    lower = " ".join(text.casefold().split())
    found: Dict[str, CatalogEntry] = {}
    aliases = _alias_index()
    for token in explicit_codes(text):
        for entry in aliases.get(token.casefold(), ()):
            found[entry.catalog_id] = entry
    phrase_index = _phrase_index()
    for word in set(_WORD_RE.findall(lower)):
        for phrase, entry in phrase_index.get(word, ()):
            if phrase in lower:
                found[entry.catalog_id] = entry
    return list(found.values())
