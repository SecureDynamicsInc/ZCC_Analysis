"""Detect and explain documented Zscaler error and session codes."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, List, Sequence

from zcc_diag.code_lookup import LookupHit, lookup_code
from zcc_diag.error_catalog import explicit_codes, match_known_codes


_NUMERIC_CODE_RE = re.compile(
    r"(?i)\b(?:error[ _-]?code|err(?:or)?code|err_code|returned[ _-]?code)"
    r"\b\s*[:=]?\s*(?P<code>-?\d{1,6})\b"
)
_PA_CODE_RE = re.compile(r"(?i)\bPA_ERROR_(?P<code>\d{4,6})\b")

_SOURCE_URLS = {
    "ZCC Error": "https://help.zscaler.com/zscaler-client-connector/zscaler-client-connector-errors",
    "ZCC Connection Status": "https://help.zscaler.com/zscaler-client-connector/zscaler-client-connector-connection-status-errors",
    "ZPA Session Status": "https://help.zscaler.com/zpa/understanding-zpa-session-status-codes",
    "ZPA Auth": "https://help.zscaler.com/zscaler-client-connector/zscaler-client-connector-zpa-authentication-errors",
    "ZIA Auth": "https://help.zscaler.com/zia/internet-saas-authentication-error-codes",
    "ZIA Policy Reason": "https://help.zscaler.com/zia/policy-reasons",
}


@dataclass(frozen=True)
class CodeExplanation:
    code: str
    source: str
    label: str
    description: str
    resolution: str
    source_url: str
    occurrences: int = 0
    product: str = ""
    severity: str = "info"
    category: str = ""
    component: str = ""


def _first(fields: dict, *names: str) -> str:
    for name in names:
        value = fields.get(name)
        if value:
            return str(value)
    return ""


def explanation_from_hit(hit: LookupHit, occurrences: int = 0) -> CodeExplanation:
    fields = hit.fields
    label = _first(
        fields, "session_status", "error_message", "name", "status",
        "reason", "description", "error_description",
    ) or hit.code.replace("_", " ").title()
    description = _first(
        fields, "error_description", "explanation", "description", "error_when",
    )
    resolution = _first(
        fields, "resolution", "recommended_action", "required_action",
    )
    return CodeExplanation(
        code=hit.code,
        source=hit.source,
        label=label,
        description=description,
        resolution=resolution,
        source_url=_first(fields, "_source_url") or _SOURCE_URLS.get(hit.source, ""),
        occurrences=occurrences,
        product=_first(fields, "_product"),
        severity=_first(fields, "_severity", "severity_hint") or "info",
        category=_first(fields, "_category", "category", "group"),
        component=_first(fields, "_component", "component", "feature"),
    )


def explain_code(query: str, limit: int = 12) -> List[CodeExplanation]:
    """Return documented explanations, preferring exact code matches."""
    hits = lookup_code(query, limit=None)
    exact = [hit for hit in hits if hit.match_reason == "exact_code"]
    selected = exact or hits
    return [explanation_from_hit(hit) for hit in selected[:limit]]


def explicit_numeric_codes(body: str) -> Iterable[str]:
    """Yield numeric codes only when the record explicitly labels them."""
    for match in _NUMERIC_CODE_RE.finditer(body or ""):
        yield match.group("code")
    for match in _PA_CODE_RE.finditer(body or ""):
        yield match.group("code")


def _line_bodies(log_index: Any) -> Iterable[str]:
    for line in getattr(log_index, "lines", ()):
        body = getattr(line, "body", "") or getattr(line, "message", "") or ""
        if body:
            yield body


def detect_documented_codes(
    log_index: Any,
    sessions: Sequence[Any] = (),
    signal_counts: Any = None,
) -> List[CodeExplanation]:
    """Find codes that logs identify explicitly, then attach documented help.

    Numeric matching is deliberately contextual. A bare ``1`` or ``5`` in a
    log is not treated as a ZCC code unless it follows an error-code label.
    """
    counts: Counter[str] = Counter()
    if signal_counts is not None:
        counts.update({str(k): int(v) for k, v in signal_counts.items()})

    session_counts: Counter[str] = Counter()
    for session in sessions:
        code = str(
            getattr(session, "ack_error", "")
            or getattr(session, "end_error", "")
            or ""
        ).strip()
        if code:
            session_counts[code] += 1
    for code, count in session_counts.items():
        if code not in counts:
            counts[code] = count

    # The guided pipeline supplies counts from its existing one-pass tunnel
    # scan. Standalone callers without those counts still get safe detection.
    if signal_counts is None:
        for body in _line_bodies(log_index):
            matched = match_known_codes(body)
            for entry in matched:
                counts[entry.code] += 1

    found: List[CodeExplanation] = []
    for code, count in counts.items():
        exact = [
            hit for hit in lookup_code(code, limit=None)
            if hit.match_reason == "exact_code"
        ]
        for hit in exact:
            found.append(explanation_from_hit(hit, occurrences=count))

    return sorted(
        found,
        key=lambda item: (
            {"critical": 0, "warning": 1, "info": 2}.get(item.severity, 3),
            -item.occurrences, item.source, item.code,
        ),
    )
