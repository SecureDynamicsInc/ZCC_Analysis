"""
Per-finding confidence scoring — how strongly the log evidence supports
the finding, rendered as a chip next to the severity badge.

Phase 60a-Task-7 (2026-07-10, slice 1b add-on). Independent of the
Triage Wizard intake — confidence measures ONE thing: how sure the
detector is about the pattern it fired on. Intake (relevance) measures
a different thing: how well the finding matches the customer complaint.

Signals used (all read-only from an existing Finding — no detector
changes required):

  1. **Evidence count.** More corroborating log lines = higher
     confidence. ``count > 10`` is strong; ``count == 1`` is weak.
  2. **Severity.** CRITICAL detectors are wired against high-specificity
     patterns (documented error codes, JSON payload matches); INFO
     tends to be threshold-breach heuristics. Base score bumps with
     severity.
  3. **Documented-code match.** If the finding's ``code`` matches an
     entry in one of the data modules (``zcc_errors``,
     ``zpa_auth_errors``, ``zpa_session_codes``, ``zia_auth_errors``,
     ``zdx_*_errors``), that's a "direct quote" signal — highest
     confidence bump. This is the same lookup ``ui/findings.py`` uses
     to render the "documented category" chip.
  4. **Time-range span.** A finding with ``time_range`` spanning
     multiple minutes/hours means the pattern is sustained, not a
     single blip. Non-trivial span → small confidence bump.

Formula (all values clamped to [0, 100]):

    base = 70 if CRITICAL else 50 if WARNING else 30
    + min(evidence_count * 2, 20)     # corroboration bonus
    + 15 if documented_code_match     # direct-quote bonus
    +  5 if time_range_span >= 60s    # sustained-pattern bonus
    - 15 if count == 1 and not doc    # single-line penalty
    = confidence

Labels:

    >= 80: "High"    — direct evidence of a known ZCC error / heavy corroboration
    50-79: "Medium"  — clear pattern but heuristic or lightly corroborated
     < 50: "Low"     — one-off signal; worth checking evidence before acting

Rendered as an HTML chip via ``chip_html()``; a plain-text label + score
via ``label_for()`` for Markdown export.
"""

from __future__ import annotations

from datetime import timedelta
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class ConfidenceLevel(str, Enum):
    # Values are lowercase so they slot directly into the existing
    # ``zd-conf-{value}`` CSS class in ui/styles.py without extra
    # translation. Callers that need a Title-Case display label use
    # ``level.display_name``.
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def display_name(self) -> str:
        return self.value.title()


# --------------------------------------------------------------------
# Documented-code lookup
# --------------------------------------------------------------------
#
# Delegates to zcc_diag.data.get_*_code helpers — same lookup path used
# by ui/findings.py's category chip cascade. Wrapped so a missing
# data module (unlikely, but conceivable during refactor) never
# crashes confidence rendering.


def _has_documented_code(code: str) -> bool:
    """True if ``code`` corresponds to a documented ZCC / ZPA / ZIA /
    ZDX status code. Used as the direct-quote signal."""
    if not code:
        return False
    try:
        from zcc_diag.data import (
            get_session_code, get_auth_error, get_tray_status,
            get_zcc_error, get_zia_auth_error,
            get_zdx_web_probe_error, get_zdx_cloud_path_error,
            get_zdx_remediation_error, get_zdx_managed_probe_error,
        )
    except ImportError:
        return False
    for fn in (
        get_session_code, get_auth_error, get_tray_status,
        get_zcc_error, get_zia_auth_error,
        get_zdx_web_probe_error, get_zdx_cloud_path_error,
        get_zdx_remediation_error, get_zdx_managed_probe_error,
    ):
        try:
            if fn(code):
                return True
        except Exception:
            continue
    return False


# --------------------------------------------------------------------
# Field accessors (dict / dataclass tolerant)
# --------------------------------------------------------------------


def _get(finding: Any, key: str, default: Any = None) -> Any:
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _severity_str(finding: Any) -> str:
    sev = _get(finding, "severity")
    if sev is None:
        return "INFO"
    return str(getattr(sev, "value", sev)).upper()


def _time_span_seconds(finding: Any) -> float:
    """Total seconds spanned by finding.time_range, or 0."""
    tr = _get(finding, "time_range")
    if not tr:
        return 0.0
    if isinstance(tr, (list, tuple)) and len(tr) == 2:
        a, b = tr
        try:
            return abs((b - a).total_seconds())
        except (TypeError, AttributeError):
            return 0.0
    return 0.0


# --------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------


def score_finding(finding: Any) -> int:
    """Compute the confidence score (0-100) for a single finding."""
    sev = _severity_str(finding)
    if sev == "CRITICAL":
        base = 70
    elif sev == "WARNING":
        base = 50
    else:
        base = 30

    count = int(_get(finding, "count", 0) or 0)
    corroboration_bonus = min(count * 2, 20)

    code = str(_get(finding, "code", "") or "")
    doc_match = _has_documented_code(code)
    doc_bonus = 15 if doc_match else 0

    span_bonus = 5 if _time_span_seconds(finding) >= 60 else 0

    single_line_penalty = -15 if (count == 1 and not doc_match) else 0

    score = base + corroboration_bonus + doc_bonus + span_bonus + single_line_penalty
    return max(0, min(100, score))


def label_for(finding: Any) -> Tuple[ConfidenceLevel, int, str]:
    """Return (level, score, tooltip) for a finding.

    Tooltip is a short sentence explaining WHY we assigned that level —
    used as the ``title`` attribute on the chip so operators can hover
    to see the reasoning.
    """
    score = score_finding(finding)
    if score >= 80:
        level = ConfidenceLevel.HIGH
    elif score >= 50:
        level = ConfidenceLevel.MEDIUM
    else:
        level = ConfidenceLevel.LOW

    # Build the "why" tooltip from the observed signals
    reasons = []
    sev = _severity_str(finding)
    reasons.append(f"severity={sev.title()}")
    count = int(_get(finding, "count", 0) or 0)
    reasons.append(f"{count} evidence line(s)")
    code = str(_get(finding, "code", "") or "")
    if code and _has_documented_code(code):
        reasons.append(f"code {code!r} is documented")
    span_s = _time_span_seconds(finding)
    if span_s >= 60:
        m = span_s / 60.0
        if m < 60:
            reasons.append(f"sustained ~{m:.0f}m")
        elif m < 60 * 24:
            reasons.append(f"sustained ~{m/60:.1f}h")
        else:
            reasons.append(f"sustained ~{m/60/24:.1f}d")

    tooltip = f"Confidence {score}/100 · " + " · ".join(reasons)
    return level, score, tooltip


# --------------------------------------------------------------------
# HTML chip rendering
# --------------------------------------------------------------------
#
# Colors match the existing severity palette used elsewhere in ui/*.py:
#   High   → green  (#2f7a3e / rgba variants)
#   Medium → amber  (#c58800)
#   Low    → gray   (#6f6f6f)
#
# Chip HTML mirrors the shape of ``_chip_html()`` in ui/findings.py so
# they align visually on the same row as the severity badge.


_LEVEL_COLORS: Dict[ConfidenceLevel, Tuple[str, str]] = {
    # (bg-color, text-color) — bg is a soft tint, text is the strong shade
    ConfidenceLevel.HIGH: ("#e0f2e5", "#1e6b32"),
    ConfidenceLevel.MEDIUM: ("#fdf1d6", "#8a5a00"),
    ConfidenceLevel.LOW: ("#eeeeee", "#555555"),
}


def chip_html(finding: Any) -> str:
    """Return an HTML span rendering the confidence chip.

    Safe to embed inline with the severity badge. Uses ``title=``
    attribute for the hover tooltip so operators can see WHY.
    """
    level, score, tooltip = label_for(finding)
    bg, fg = _LEVEL_COLORS[level]
    # ``·`` is a middle-dot; keeps the chip compact and readable.
    return (
        f'<span title="{_esc(tooltip)}" '
        f'style="display: inline-block; '
        f'background: {bg}; color: {fg}; '
        f'font-size: 11px; font-weight: 600; '
        f'padding: 2px 8px; border-radius: 10px; '
        f'margin-left: 6px; vertical-align: middle; '
        f'letter-spacing: 0.02em;">'
        f'{level.value} · {score}'
        f'</span>'
    )


def _esc(s: str) -> str:
    """Minimal HTML attribute escaping — we control the source, so we
    only need to guard the ``title=`` attribute against quotes."""
    return (s or "").replace('"', "&quot;").replace("<", "&lt;")


def markdown_label(finding: Any) -> str:
    """Plain-text label for Markdown export (Slack / JIRA replies).

    Renders as e.g. ``[Confidence: High · 92]``.
    """
    level, score, _ = label_for(finding)
    return f"[Confidence: {level.value} · {score}]"
