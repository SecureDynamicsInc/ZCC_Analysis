"""
Finding-relations service (Phase 55a, 2026-06-26).

For any Finding in a bundle, compute the four kinds of neighbour every
senior engineer wants to see when drilling into an issue:

  * **Triggers** (causal upstream)  — events that CAUSED the finding
    to fire. Modern Standby exits paired to force_reauth_sleep_trigger,
    service restarts within the finding's window, etc.

  * **Effects** (causal downstream) — what the finding BROKE. mtunnel
    closes attributed to CLOSED_FROM_ASSISTANT, broker rejections
    during recovery, auth-state transitions during the finding.

  * **Co-occurring** (temporal siblings) — OTHER findings whose
    time_range overlaps with this finding's ± window_seconds.

  * **Config-context** — a snapshot of the relevant policy state at
    the time of the event. MVP: uses BundleSummary as a single
    point-in-time snapshot (which it is — captured at bundle export).
    Future: trace tray-policy reloads to produce time-windowed
    configs.

The service is PURE LOGIC. No Streamlit, no rendering. The UI in
``ui/finding_drilldown.py`` (Phase 55c) consumes ``FindingRelations``
dataclasses and renders the four sections.

Cache: ``get_relations(finding, data)`` result is memoised by
``(finding_id, pipeline_version)`` — the drill-down expander is called
per-render and this keeps click latency near-zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────── dataclasses

@dataclass
class TriggerEvent:
    """One upstream event identified by a correlator as causal."""
    ts: Optional[datetime]
    label: str                    # human summary, e.g. "Modern Standby exit"
    source_file: str = ""
    line_no: Optional[int] = None
    correlator_id: str = ""       # which correlator produced this
    paired_with: str = ""         # brief description of the paired event
    delta_ms: Optional[float] = None  # ms between this event and its pair


@dataclass
class EffectEvent:
    """One downstream event caused by the finding's time range."""
    ts: Optional[datetime]
    label: str                    # e.g. "mtunnel CLOSED_FROM_ASSISTANT"
    detail: str = ""              # broker host, tag_id, etc.
    source_file: str = ""
    line_no: Optional[int] = None
    correlator_id: str = ""


@dataclass
class ConfigSnapshotItem:
    """One relevant config value at the time of the event."""
    label: str
    value: str                    # already formatted for display
    source: str = ""              # e.g., "AppInfo.xml TrayPolicy JSON"
    verified: bool = True         # False → "not in bundle" — open question


@dataclass
class FindingRelations:
    """Every neighbour a drill-down expander needs to render."""
    finding_code: str
    finding_title: str
    window_seconds: int
    triggers: List[TriggerEvent] = field(default_factory=list)
    effects: List[EffectEvent] = field(default_factory=list)
    co_occurring: List[Dict[str, Any]] = field(default_factory=list)
    config_snapshot: List[ConfigSnapshotItem] = field(default_factory=list)
    action_links: Dict[str, str] = field(default_factory=dict)
    """action_links: keys like ``open_in_search`` → pre-populated query.

    The UI reads these to build routing buttons ("Open in Correlate
    Events with this time window pre-filled")."""


# ─────────────────────────────────────────────── helpers

def _finding_time_range(
    finding: Dict[str, Any],
) -> Optional[Tuple[datetime, datetime]]:
    """Return (start, end) datetime tuple for a finding, or None if the
    finding carries no time information."""
    tr = finding.get("time_range")
    if not tr:
        return None
    if isinstance(tr, (list, tuple)) and len(tr) == 2:
        start, end = tr
        if isinstance(start, datetime) and isinstance(end, datetime):
            return start, end
    return None


def _finding_id(finding: Dict[str, Any]) -> str:
    """Stable identifier for a finding for caching + linking."""
    code = finding.get("code") or ""
    tr = _finding_time_range(finding)
    if tr:
        return f"{code}@{tr[0].isoformat()}"
    return code or "unknown"


def _ts_of(event: Any) -> Optional[datetime]:
    """Best-effort timestamp extraction for a correlator event.

    Correlator payloads come in a few shapes (dict / dataclass /
    LogLine record). We try common attribute names in order.
    """
    if event is None:
        return None
    if isinstance(event, datetime):
        return event
    for attr in ("ts", "timestamp", "time", "at"):
        if isinstance(event, dict):
            v = event.get(attr)
        else:
            v = getattr(event, attr, None)
        if isinstance(v, datetime):
            return v
    return None


def _source_file_of(event: Any) -> str:
    """Best-effort source-file extraction."""
    if event is None:
        return ""
    for attr in ("source_file", "src_file", "file", "path"):
        if isinstance(event, dict):
            v = event.get(attr)
        else:
            v = getattr(event, attr, None)
        if isinstance(v, str) and v:
            return v
    return ""


def _line_no_of(event: Any) -> Optional[int]:
    for attr in ("line_no", "lineno", "line"):
        if isinstance(event, dict):
            v = event.get(attr)
        else:
            v = getattr(event, attr, None)
        if isinstance(v, int):
            return v
    return None


def _naive(ts: Optional[datetime]) -> Optional[datetime]:
    """Return a tz-naive copy of ``ts``.

    Phase 55a.1 (2026-07-02): the drill-down crashed with
    ``TypeError: can't compare offset-naive and offset-aware datetimes``
    because finding.time_range carried tz-aware timestamps (parsed
    with offset from the log line) while some correlator events emitted
    tz-naive ones (constructed from ``datetime.fromtimestamp`` or
    string parsing without offset).

    Phase 58e-M3 (2026-07-08): Phase 58a normalized every log-derived
    timestamp to aware UTC and a codebase-wide audit confirmed no
    correlator now emits naive datetimes. That means this helper is
    now DEFENSIVE-ONLY — if a future contributor forgets to attach
    ``tzinfo=timezone.utc`` to a new correlator's events, the drill-down
    will still work rather than crash on the ``sort()`` call. Since
    every real timestamp is UTC anyway, stripping tz doesn't lose
    information — the wall-clock ordering is preserved.

    Kept because the cost (one attribute check + one call) is trivial
    and the failure mode it prevents is a hard user-visible crash in
    the Investigate workspace.
    """
    if ts is None:
        return None
    if ts.tzinfo is not None:
        return ts.replace(tzinfo=None)
    return ts


def _in_window(
    ts: Optional[datetime],
    window: Tuple[datetime, datetime],
    slack_seconds: int = 0,
) -> bool:
    """True if ``ts`` falls within [window[0] - slack, window[1] + slack].

    Both operands are compared as tz-naive to avoid mixed-offset
    TypeError when the bundle mixes tz-aware log timestamps with
    tz-naive correlator-event timestamps.
    """
    ts = _naive(ts)
    if ts is None:
        return False
    start = _naive(window[0])
    end = _naive(window[1])
    if start is None or end is None:
        return False
    if slack_seconds:
        start = start - timedelta(seconds=slack_seconds)
        end = end + timedelta(seconds=slack_seconds)
    return start <= ts <= end


# ─────────────────────────────────────────── neighbour extractors

def get_triggers(
    finding: Dict[str, Any],
    correlators: Dict[str, Any],
    window_seconds: int = 60,
) -> List[TriggerEvent]:
    """Return upstream causal events for the finding.

    Currently reads: modern_standby_cycles, force_reauth_summary,
    service_starts. Each entry that falls within (finding_time_range
    ± window_seconds) is emitted as a TriggerEvent with a paired-with
    description explaining why the correlator paired it.
    """
    out: List[TriggerEvent] = []
    tr = _finding_time_range(finding)
    if not tr or not correlators:
        return out

    # --- Modern Standby exits (Windows) — the canonical trigger for
    #     the ZPA-reauth loop family of findings.
    for cycle in correlators.get("modern_standby_cycles") or []:
        # A cycle dict typically has {"exit_ts": datetime, ...}
        exit_ts = _ts_of(cycle) or (
            cycle.get("exit_ts") if isinstance(cycle, dict) else None
        )
        if isinstance(exit_ts, datetime) and _in_window(
            exit_ts, tr, slack_seconds=window_seconds,
        ):
            paired = ""
            if isinstance(cycle, dict) and cycle.get("force_reauth_ts"):
                fr = cycle["force_reauth_ts"]
                if isinstance(fr, datetime):
                    delta = (fr - exit_ts).total_seconds() * 1000
                    paired = (
                        f"force_reauth_sleep_trigger @ "
                        f"{fr.isoformat()} (±{delta:.0f}ms)"
                    )
            out.append(TriggerEvent(
                ts=exit_ts,
                label="Modern Standby exit",
                source_file=_source_file_of(cycle),
                line_no=_line_no_of(cycle),
                correlator_id="power_change",
                paired_with=paired,
            ))

    # --- force_reauth events (both sleep-driven and IdP-driven) —
    #     surface those not already paired to a Modern Standby exit.
    fr_summary = correlators.get("force_reauth_summary")
    if fr_summary:
        events = (
            fr_summary.get("events")
            if isinstance(fr_summary, dict) else None
        ) or getattr(fr_summary, "events", []) or []
        for ev in events:
            ev_ts = _ts_of(ev)
            if not _in_window(ev_ts, tr, slack_seconds=window_seconds):
                continue
            # Only emit as a trigger if this event ISN'T already the
            # partner of a Modern Standby exit we already added.
            # Phase 55a.1: normalize to naive for arithmetic so we
            # don't blow up when one side is tz-aware and the other
            # is naive.
            ev_ts_n = _naive(ev_ts)
            already = any(
                (t.ts and ev_ts_n
                 and abs((_naive(t.ts) - ev_ts_n).total_seconds()) < 1.0)
                for t in out
            )
            if already:
                continue
            kind = (
                ev.get("kind") if isinstance(ev, dict)
                else getattr(ev, "kind", "")
            ) or "force_reauth"
            out.append(TriggerEvent(
                ts=ev_ts,
                label=f"force_reauth ({kind})",
                source_file=_source_file_of(ev),
                line_no=_line_no_of(ev),
                correlator_id="force_reauth",
                paired_with="",
            ))

    # --- Service starts — a fresh ZSAService restart within the window
    #     is a plausible cause for tunnel state findings.
    for start_ev in correlators.get("service_starts") or []:
        s_ts = _ts_of(start_ev)
        if _in_window(s_ts, tr, slack_seconds=window_seconds):
            out.append(TriggerEvent(
                ts=s_ts,
                label="ZSAService restart",
                source_file=_source_file_of(start_ev),
                line_no=_line_no_of(start_ev),
                correlator_id="service_lifecycle",
                paired_with="",
            ))

    # Sort by naive form so aware/naive don't collide with datetime.min.
    out.sort(key=lambda t: _naive(t.ts) or datetime.min)
    return out


def get_effects(
    finding: Dict[str, Any],
    correlators: Dict[str, Any],
    window_seconds: int = 300,
) -> List[EffectEvent]:
    """Return downstream events attributed to the finding.

    Reads mtunnel_closes (CLOSED_FROM_ASSISTANT + broker-rejection),
    auth_state_events (BROKER_AUTH → REAUTH transitions during
    recovery). All within finding_time_range + slack.
    """
    out: List[EffectEvent] = []
    tr = _finding_time_range(finding)
    if not tr or not correlators:
        return out

    for close_ev in correlators.get("mtunnel_closes") or []:
        c_ts = _ts_of(close_ev)
        if not _in_window(c_ts, tr, slack_seconds=window_seconds):
            continue
        reason = (
            close_ev.get("reason") if isinstance(close_ev, dict)
            else getattr(close_ev, "reason", "")
        ) or ""
        broker = (
            close_ev.get("broker_host") if isinstance(close_ev, dict)
            else getattr(close_ev, "broker_host", "")
        ) or ""
        tag = (
            close_ev.get("tag_id") if isinstance(close_ev, dict)
            else getattr(close_ev, "tag_id", "")
        )
        detail_bits = []
        if broker: detail_bits.append(broker)
        if tag: detail_bits.append(f"tag {tag}")
        out.append(EffectEvent(
            ts=c_ts,
            label=f"mtunnel close ({reason or 'unknown reason'})",
            detail=" · ".join(detail_bits),
            source_file=_source_file_of(close_ev),
            line_no=_line_no_of(close_ev),
            correlator_id="mtunnel",
        ))

    # Auth-state transitions during recovery
    for state_ev in correlators.get("auth_state_events") or []:
        s_ts = _ts_of(state_ev)
        if not _in_window(s_ts, tr, slack_seconds=window_seconds):
            continue
        transition = (
            state_ev.get("transition") if isinstance(state_ev, dict)
            else getattr(state_ev, "transition", "")
        ) or "auth transition"
        out.append(EffectEvent(
            ts=s_ts,
            label=f"auth-state: {transition}",
            detail="",
            source_file=_source_file_of(state_ev),
            line_no=_line_no_of(state_ev),
            correlator_id="auth_state",
        ))

    out.sort(key=lambda e: _naive(e.ts) or datetime.min)
    return out


def get_co_occurring(
    finding: Dict[str, Any],
    all_findings: List[Dict[str, Any]],
    window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """Return OTHER findings whose time_range overlaps this finding's
    time_range within ± window_seconds. Excludes the finding itself.
    """
    tr = _finding_time_range(finding)
    if not tr:
        return []
    # Phase 55a.1 (2026-07-02): normalize to tz-naive on both sides
    # of the overlap check to avoid TypeError when the bundle mixes
    # aware / naive timestamps.
    tr0, tr1 = _naive(tr[0]), _naive(tr[1])
    if tr0 is None or tr1 is None:
        return []
    start_slack = tr0 - timedelta(seconds=window_seconds)
    end_slack = tr1 + timedelta(seconds=window_seconds)
    self_id = _finding_id(finding)
    out = []
    for other in all_findings or []:
        if not isinstance(other, dict):
            continue
        if _finding_id(other) == self_id:
            continue
        other_tr = _finding_time_range(other)
        if not other_tr:
            continue
        o0, o1 = _naive(other_tr[0]), _naive(other_tr[1])
        if o0 is None or o1 is None:
            continue
        # Overlap check: intervals overlap if start1 <= end2 AND start2 <= end1
        if o0 <= end_slack and start_slack <= o1:
            out.append(other)
    return out


def get_config_at_time(
    ts: Optional[datetime],
    summary: Any,
    bundle_meta: Dict[str, Any],
    finding_code: str = "",
) -> List[ConfigSnapshotItem]:
    """Return the config values relevant to a given event time.

    MVP (Phase 55b, 2026-06-26): BundleSummary is treated as a single
    snapshot valid throughout the bundle window (which is what it is —
    the TrayPolicy JSON is captured once at bundle export). Which
    fields we surface depends on the finding_code — a ZPA reauth
    finding cares about broker, posture, and reauth-on-trust flags;
    a ZIA finding cares about PAC and bypass list.

    Fields marked ``verified=False`` are ones the bundle didn't carry;
    they surface as Open Questions in the drill-down UI.
    """
    items: List[ConfigSnapshotItem] = []
    if summary is None:
        return items
    bm = bundle_meta or {}

    # Universal facts every finding benefits from.
    def _add(label, value, source, verified=True):
        if value:
            items.append(ConfigSnapshotItem(
                label=label, value=str(value),
                source=source, verified=verified,
            ))

    _add("ZCC version",
         (getattr(summary, "versions", None) and
          getattr(summary.versions, "components", {}).get("ZSAService") or
          bm.get("zcc_version")),
         "ZSAService log banner")
    _add("Log timezone",
         bm.get("log_tz_label") or bm.get("tz_offset"),
         "log line offset")
    _add("Boot time",
         bm.get("boot_time_str"),
         "AppInfo.xml")

    # Family-specific fields.
    fc = (finding_code or "").upper()
    if "ZPA" in fc or "BROKER" in fc or "REAUTH" in fc or "MTUNNEL" in fc:
        broker = bm.get("zpa_broker_active") or ""
        _add("ZPA broker (data path)", broker, "ZSATunnel zpnBrokerRedirectCb")
        _add("Entra tenant ID", bm.get("idp_tenant_id"),
             "ZSATray SAML URL")
        _add("SAML SP (auth path)", bm.get("zpa_saml_sp"),
             "ZSATunnel SAML redirect")
        _add("Posture profile bound", bm.get("posture_profile_name"),
             "TrayPolicy JSON")
        _add("Reauth-on-trust-change",
             bm.get("reauth_on_trust_change"),
             "TrayPolicy JSON",
             verified=("reauth_on_trust_change" in bm))
        _add("autoReauthForOnTrusted",
             bm.get("autoReauthForOnTrusted"),
             "TrayPolicy JSON",
             verified=("autoReauthForOnTrusted" in bm))
    if "ZIA" in fc or "SME" in fc or "BYPASS" in fc or "PROXY" in fc:
        _add("ZIA cloud", bm.get("zia_cloud") or
             (getattr(summary, "cloud", None) and
              getattr(summary.cloud, "main_cloud", None)),
             "AppInfo.xml / log banner")
        _add("MA host", bm.get("ma_host") or
             (getattr(summary, "cloud", None) and
              getattr(summary.cloud, "ma_host", None)),
             "TrayPolicy JSON")
        _add("Forwarding profile", bm.get("forwarding_profile_name"),
             "TrayPolicy JSON")
        _add("App profile", bm.get("app_profile_name"),
             "TrayPolicy JSON")
    if "ZDX" in fc or "PROBE" in fc or "SLOWNESS" in fc:
        _add("ZDX cloud",
             (getattr(summary, "cloud", None) and
              getattr(summary.cloud, "zdx_cloud", None)),
             "ZDX log banner")

    return items


# ────────────────────────────────────── main entry point


def get_relations(
    finding: Dict[str, Any],
    data: Dict[str, Any],
    pipeline_version: str = "",
    window_seconds: int = 60,
) -> FindingRelations:
    """Return relations computed only from the current run's objects."""

    correlators = data.get("correlators") or {}
    all_findings = data.get("findings") or []
    summary = data.get("summary")
    bm = (getattr(summary, "bundle_meta", None) or {}) if summary else {}
    tr = _finding_time_range(finding)

    triggers = get_triggers(finding, correlators, window_seconds)
    effects = get_effects(finding, correlators, window_seconds * 5)
    co_occ = get_co_occurring(finding, all_findings, window_seconds * 5)
    config = get_config_at_time(
        tr[0] if tr else None,
        summary, bm,
        finding_code=finding.get("code") or "",
    )

    # Build action-link query strings so the UI can route to Investigate
    # → Free-text Search with the finding's time window pre-filtered.
    action_links: Dict[str, str] = {}
    if tr:
        # Convention: ?ws=Investigate&tab=Search&ts_from=<>&ts_to=<>
        action_links["open_in_search"] = (
            f"?ws=Investigate&ts_from={tr[0].isoformat()}"
            f"&ts_to={tr[1].isoformat()}"
        )
        action_links["log_context_pm5"] = (
            f"?ws=Investigate&ts_from="
            f"{(tr[0] - timedelta(minutes=5)).isoformat()}"
            f"&ts_to={(tr[1] + timedelta(minutes=5)).isoformat()}"
        )

    rel = FindingRelations(
        finding_code=finding.get("code") or "",
        finding_title=finding.get("title") or "",
        window_seconds=window_seconds,
        triggers=triggers,
        effects=effects,
        co_occurring=co_occ,
        config_snapshot=config,
        action_links=action_links,
    )
    return rel
