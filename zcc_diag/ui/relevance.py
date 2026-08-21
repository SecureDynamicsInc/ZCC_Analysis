"""
Relevance ranker — turns intake context into a per-finding score so the
UI can pin the customer-complaint-relevant findings above severity-only
ordering.

Phase 60a-Task-3 (2026-07-10). Consumed by ``ui/findings.py`` and
``ui/overview.py`` to render a "Most relevant to reported issue" pinned
section at the top of every findings list.

Design principles:

  * **Complaint dominates severity.** Per Shameel's 2026-07-10 decision:
    "whatever user complained about should be number 1." A complaint-
    relevant INFO finding outranks an unrelated CRITICAL. Enforced by a
    +500 complaint bonus vs. severity weights of 100/50/10.
  * **Legacy-safe fallback.** When intake is empty or skipped,
    ``score_finding()`` returns the severity-only weight — identical
    to pre-Phase-60 ordering. The ranker is a no-op unless the user
    filled the wizard.
  * **Pure function, no I/O.** Every helper takes plain arguments;
    no session-state, no Streamlit. Trivially unit-testable against
    the corpus we've already analyzed.
  * **Dict-shaped finding compatibility.** ``ui/analyse.py``'s
    ``_finding_to_dict`` produces dict findings, but the RCA framework
    and some detectors still hand around ``Finding`` dataclass
    instances. Scoring works with both — helpers use ``getattr`` /
    ``dict.get`` uniformly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..intake import ComplaintCategory, IntakeContext, TimeScopeKind


# --------------------------------------------------------------------
# Scoring weights
# --------------------------------------------------------------------
#
# The magnitude of each bonus is deliberate:
#
#   * severity: 100 / 50 / 10  — spread wide enough that CRITICAL clearly
#     dominates WARNING/INFO within the same relevance bucket.
#   * complaint match: +500 — larger than the widest severity range so
#     a complaint-relevant INFO (510) still outranks an unrelated
#     CRITICAL (100). This is Shameel's product decision.
#   * time-scope match: +30 — meaningful nudge but doesn't override
#     complaint bucketing.
#   * user match: +20 — smallest bump; identity signals are the
#     weakest (many findings don't carry user context in their evidence
#     lines and we don't want to demote them for being generic).
#
# All bonuses are additive. A finding with all three bonuses at CRITICAL
# scores 650; a bare CRITICAL scores 100.

SEVERITY_WEIGHT: Dict[str, int] = {
    "CRITICAL": 100,
    "WARNING": 50,
    "INFO": 10,
}

COMPLAINT_MATCH_BONUS = 500
TIME_WINDOW_BONUS = 30
USER_MATCH_BONUS = 20


# --------------------------------------------------------------------
# Complaint → relevant detector IDs
# --------------------------------------------------------------------
#
# These are the detector ``id`` values (matching what
# ``zcc_diag.issues.all_detectors()`` reports) whose findings should be
# pinned when the operator picks the corresponding tile. Overlap
# between categories is intentional — e.g. ``zia_auth_failures`` is in
# both WEB_SLOW_OR_BLOCKED and REAUTH_OR_DISCONNECT because it's
# relevant to both symptom pictures.
#
# GENERAL intentionally has an empty set: the "not sure" tile falls
# back to severity-only ordering.

_COMPLAINT_TO_DETECTORS: Dict[ComplaintCategory, Set[str]] = {
    ComplaintCategory.INTERNAL_ACCESS: {
        "zpa_missing_ad_srv_segment",
        "zpa_broker_assistant_close",
        "zpa_dns_check_not_found",
        "zpa_app_not_reachable",
        "zpa_machine_tunnel_config_missing",
        "zpa_mtunnel_reconnect_loop",
        "zpa_data_plane_resets",
        "zpa_auth_failures",
        # Endpoint firewall / AV can silently block ZPA connectors too
        "endpoint_fw_av", "endpoint_fw_av_mac",
        "driver_error", "driver_error_mac",
        "fw_av_mac",
    },
    ComplaintCategory.WEB_SLOW_OR_BLOCKED: {
        "slowness",
        "zia_auth_failures",
        "captive_portal",
        "network_error",
        "cert_pinned_saas_inspection",
        "bypass_misconfiguration",
        "wildcard_app_segment_purge",
        "hostfile_interference",
        "p2p_app_blocked",
        "idp_redirect_fail",
    },
    ComplaintCategory.REAUTH_OR_DISCONNECT: {
        "zpa_reauth_loop",
        "zpa_auth_failures",
        "zia_auth_failures",
        "tunnel_not_established",
        "system_lifecycle",
        "idp_redirect_fail",
        "network_transitions",
        "adapter_instability",
        "ncsi_false_negative",
        "ncsi_false_negative_mac",
        "captive_portal",
    },
    ComplaintCategory.FIRST_RUN_BROKEN: {
        "driver_error", "driver_error_mac",
        "endpoint_fw_av", "endpoint_fw_av_mac",
        "fw_av_mac",
        "zpa_machine_tunnel_config_missing",
        "zia_auth_failures",
        "zpa_auth_failures",
        "zcc_client_version_drift",
        "ai_cli_pin",
        "rmm_agent_pin",
        "zphm_force_stop_loop",
        "tunnel_not_established",
    },
    ComplaintCategory.REALTIME_PERF: {
        "slowness",
        "adapter_instability",
        "network_error",
        "network_transitions",
        "zdx_zpa_catalog_drift",
        "chronic_memory_pressure",
        "zcc_tray_instability",
    },
    ComplaintCategory.GENERAL: set(),   # no bias
}


def relevant_detector_ids(cat: ComplaintCategory) -> Set[str]:
    """Public read-only accessor for the map. Returns a fresh copy so
    callers can't mutate the module-level state."""
    return set(_COMPLAINT_TO_DETECTORS.get(cat, set()))


# --------------------------------------------------------------------
# Finding-field accessors (dict / dataclass tolerant)
# --------------------------------------------------------------------


def _get(finding: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a finding regardless of whether it's a dict or
    a ``Finding`` dataclass instance."""
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _severity_str(finding: Any) -> str:
    """Normalize severity to an upper-case string."""
    sev = _get(finding, "severity")
    if sev is None:
        return "INFO"
    # Handle both ``Severity`` enum instances and raw strings/dicts
    val = getattr(sev, "value", sev)
    return str(val).upper()


def _detector_id(finding: Any) -> str:
    """Detector-id lookup. Dict findings from ``_finding_to_dict``
    store it as ``detector_id``; ``Finding`` dataclass instances
    don't carry it directly — the parent ``Findings`` object does.
    Callers of ``sort_by_relevance`` that iterate over a flattened
    finding list should attach the detector id first."""
    # Try common attribute names in priority order
    for key in ("detector_id", "issue_id", "_detector_id"):
        v = _get(finding, key)
        if v:
            return str(v)
    return ""


def _time_range(finding: Any) -> Optional[Tuple[Optional[datetime], Optional[datetime]]]:
    """Read the finding's time_range if present."""
    tr = _get(finding, "time_range")
    if tr is None:
        return None
    # Dict findings may serialize as a list [start_iso, end_iso]
    if isinstance(tr, (list, tuple)) and len(tr) == 2:
        return (_to_dt(tr[0]), _to_dt(tr[1]))
    return None


def _to_dt(v: Any) -> Optional[datetime]:
    """Best-effort datetime coercion."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            return None
    return None


def _evidence_text_blob(finding: Any) -> str:
    """Concatenate title + description + up to a few evidence lines so
    the user-match check has something to grep against."""
    parts: List[str] = []
    for key in ("title", "description"):
        v = _get(finding, key)
        if v:
            parts.append(str(v))
    ev = _get(finding, "evidence") or []
    if isinstance(ev, list):
        for item in ev[:5]:
            if isinstance(item, dict):
                for k in ("raw", "message", "body", "line"):
                    v = item.get(k)
                    if v:
                        parts.append(str(v))
                        break
            elif isinstance(item, str):
                parts.append(item)
            else:
                # Log-record dataclass instance
                for attr in ("raw", "message", "body"):
                    v = getattr(item, attr, None)
                    if v:
                        parts.append(str(v))
                        break
    return " ".join(parts)


# --------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------


def score_finding(
    finding: Any,
    intake: IntakeContext,
    bundle_window: Optional[Tuple[Optional[datetime], Optional[datetime]]] = None,
) -> float:
    """Compute a relevance score for a single finding.

    Higher score = more relevant. Callers sort DESCENDING by this value.

    Empty / skipped intake → returns the severity weight (legacy
    behavior; sort by severity only).

    Args:
        finding: A finding dict (post-``_finding_to_dict``) or a
            ``Finding`` dataclass instance. Both shapes are accepted.
        intake: The current ``IntakeContext``.
        bundle_window: Optional (start, end) tuple used to interpret
            the ``LAST_30_MIN`` and ``SINCE_LAST_BOOT`` time-scope
            kinds. If not provided, those kinds degrade gracefully to
            "no time bonus applied."
    """
    sev = _severity_str(finding)
    base = SEVERITY_WEIGHT.get(sev, 0)

    # No intake → just severity ordering
    if intake.skipped or intake.is_empty():
        return float(base)

    total = float(base)

    # ---- Complaint category match ----
    relevant = _COMPLAINT_TO_DETECTORS.get(intake.complaint_category, set())
    if relevant:
        did = _detector_id(finding)
        if did and did in relevant:
            total += COMPLAINT_MATCH_BONUS

    # ---- Time-scope overlap ----
    if _time_overlaps(finding, intake, bundle_window):
        total += TIME_WINDOW_BONUS

    # ---- User match ----
    if intake.user.strip() and _mentions_user(finding, intake.user):
        total += USER_MATCH_BONUS

    return total


def _time_overlaps(
    finding: Any,
    intake: IntakeContext,
    bundle_window: Optional[Tuple[Optional[datetime], Optional[datetime]]],
) -> bool:
    """Return True when the finding's time range overlaps the intake
    time scope. Defensive: any missing / unparseable value returns
    False rather than raising."""
    scope = intake.time_scope
    if scope.kind == TimeScopeKind.WHOLE_BUNDLE:
        # Whole-bundle scope means "everything qualifies" — no bonus,
        # since no finding is more time-relevant than any other.
        return False

    finding_range = _time_range(finding)
    if not finding_range:
        return False
    f_start, f_end = finding_range
    if f_start is None and f_end is None:
        return False
    # Normalize single-point findings
    f_start = f_start or f_end
    f_end = f_end or f_start

    # Compute the intake window (start, end)
    win: Optional[Tuple[datetime, datetime]] = None
    if scope.kind == TimeScopeKind.SPECIFIC_TIMESTAMP:
        if scope.anchor_utc is not None:
            half = timedelta(minutes=scope.window_min)
            win = (scope.anchor_utc - half, scope.anchor_utc + half)
    elif scope.kind == TimeScopeKind.LAST_30_MIN:
        if bundle_window and bundle_window[1] is not None:
            end = bundle_window[1]
            win = (end - timedelta(minutes=30), end)
    elif scope.kind == TimeScopeKind.SINCE_LAST_BOOT:
        # Best-effort: if the caller passed bundle_window, treat "since
        # last boot" as the full bundle window (a boot-anchored
        # correlator would refine this in Phase 60b). For now this
        # matches WHOLE_BUNDLE semantically — no bonus.
        return False

    if win is None:
        return False

    # Interval overlap: [f_start, f_end] ∩ [w_start, w_end] != ∅
    try:
        return f_start <= win[1] and f_end >= win[0]
    except TypeError:
        # aware/naive mismatch — bail cleanly rather than crash.
        return False


def _mentions_user(finding: Any, user: str) -> bool:
    """Case-insensitive substring check across the finding's textual
    surface. Cheap; O(n) over ~500-char blob."""
    u = user.strip().lower()
    if not u:
        return False
    blob = _evidence_text_blob(finding).lower()
    return u in blob


# --------------------------------------------------------------------
# Sorting + top-N helpers
# --------------------------------------------------------------------


def sort_by_relevance(
    findings: Iterable[Any],
    intake: IntakeContext,
    bundle_window: Optional[Tuple[Optional[datetime], Optional[datetime]]] = None,
) -> List[Any]:
    """Return the input findings sorted DESCENDING by relevance score.

    Ties broken by original list order (Python's sort is stable). This
    means when intake is empty, the return order equals input order
    for equal-severity findings — same as pre-Phase-60 behavior.
    """
    scored: List[Tuple[float, int, Any]] = []
    for idx, f in enumerate(findings):
        scored.append((score_finding(f, intake, bundle_window), idx, f))
    # Descending by score; ascending by original index preserves stable
    # order within equal-score groups.
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [f for _, _, f in scored]


def top_n_relevant(
    findings: Iterable[Any],
    intake: IntakeContext,
    n: int = 5,
    bundle_window: Optional[Tuple[Optional[datetime], Optional[datetime]]] = None,
) -> List[Any]:
    """Return the top-N findings ranked by relevance.

    When intake is empty, returns the top-N by severity (same as
    legacy sort). When intake is filled, complaint-relevant findings
    dominate.
    """
    ranked = sort_by_relevance(findings, intake, bundle_window)
    return ranked[:n]


def has_complaint_relevance(intake: IntakeContext) -> bool:
    """True if the intake has a non-GENERAL complaint category that
    would produce a non-trivial ranking. Used by the UI to decide
    whether to render the 'Most relevant to reported issue' pinned
    section header."""
    if intake.skipped or intake.is_empty():
        return False
    return bool(_COMPLAINT_TO_DETECTORS.get(intake.complaint_category, set()))
