"""
Cross-finding pattern detection — meta-analysis layer over the
finding list.

The timeline shows *when* events happened in wall-clock terms. The
detectors say *what* event happened. Neither answers "is there a
shape to when this happens?" — and that question is often the one
that points at root cause. Examples the timeline can't show on its
own:

  * **Time-of-day cluster.** 5 tunnel flaps over 3 days, all
    between 09:00–10:00. Suggests a morning IdP login storm /
    schedule-triggered cert rotation / shift-start network surge.
  * **Burst.** 10 SSL errors in 30 seconds — not a sustained
    condition, a sudden cascade. Suggests a single triggering
    event (e.g. SSL inspection policy push, cert chain change).
  * **Cross-lane co-occurrence.** Multiple detector groups firing
    within the same minute. Hints at a causal chain the toolkit
    doesn't model directly yet.

This module is a thin infrastructure layer plus the time-of-day
detector for MVP. New patterns slot in by adding a function that
returns ``Optional[Pattern]`` and registering it in
``detect_patterns``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st


@dataclass
class Pattern:
    """A surfaced pattern. ``severity`` drives the visual class on the
    rendered card (matches the ``zd-sev-*`` palette used elsewhere).

    Attributes
    ----------
    key
        Stable identifier for the pattern kind (``time_of_day``,
        ``burst``, ...). Useful when patterns get filtered or muted.
    title
        One-line headline displayed as the card title.
    detail
        Body paragraph — explains WHY the pattern matters and what
        the engineer should consider. Plain prose, no markup needed.
    finding_codes
        Detector codes involved in the pattern. Helps the engineer
        cross-reference back to the affected finding cards.
    severity
        ``info`` / ``warn`` / ``bad`` — drives card colour. Tune per
        pattern's strength: a 50% cluster is info, a 90% cluster is
        warn (something is structurally wrong).
    """
    key: str
    title: str
    detail: str
    finding_codes: List[str] = field(default_factory=list)
    severity: str = "info"


# Minimum-evidence thresholds. A pattern from 2 events is just two
# events; below these floors we don't claim a "pattern".
_MIN_EVENTS_FOR_TOD = 4
_MIN_BUNDLE_HOURS_FOR_TOD = 4.0
# Cluster strength bands.
_TOD_CLUSTER_INFO_PCT = 0.50  # 50%+ in one hour → info pattern
_TOD_CLUSTER_WARN_PCT = 0.70  # 70%+ → bump to warn

# Burst-detector thresholds.
_BURST_MIN_EVENTS = 5            # ≥5 events of the same code within...
_BURST_WINDOW_S = 60.0           # ...60s = a burst
_BURST_MAX_REPORT = 5            # cap reported bursts so the section
                                 # doesn't drown out other patterns

# Cross-lane co-occurrence thresholds.
_COOCCUR_WINDOW_S = 60.0         # events within 60s = "together"
_COOCCUR_MIN_EVENTS = 3          # need at least 3 events in window
_COOCCUR_MIN_LANES = 2           # spanning ≥2 detector families
_COOCCUR_MAX_REPORT = 3          # cap reports — top 3 by lane count


def _collect_all_event_ts(
    findings: List[Dict[str, Any]],
) -> List[Tuple[datetime, str]]:
    """Flatten the evidence ts across every actionable finding into
    ``[(ts, code), ...]``. OS-skipped marker findings are dropped —
    they don't represent real events and would skew counts."""
    out: List[Tuple[datetime, str]] = []
    for f in findings:
        if f.get("code") == "DETECTOR_SKIPPED_FOR_OS":
            continue
        for ev in (f.get("evidence") or []):
            ts = ev.get("ts")
            if isinstance(ts, datetime):
                out.append((ts, f["code"]))
    return out


def detect_time_of_day_cluster(
    findings: List[Dict[str, Any]],
) -> List[Pattern]:
    """Flag a pattern when ≥50% of all event timestamps fall in a
    single hour-of-day across the bundle window.

    Only fires when:
      * There are ≥ {_MIN_EVENTS_FOR_TOD} events total. Below that
        the "cluster" is too small to claim significance.
      * The bundle observation window is ≥ {_MIN_BUNDLE_HOURS_FOR_TOD}
        hours. For sub-window-day bundles, "time of day" doesn't
        mean anything — every event is at the same hour.

    The hour comparison uses each timestamp's own timezone (offsets
    are preserved through parsing), so a bundle from Riyadh shows
    local Riyadh hours, not UTC.

    Returns a list (0 or 1 element) for shape consistency with the
    other pattern detectors.
    """
    ts_list = _collect_all_event_ts(findings)
    if len(ts_list) < _MIN_EVENTS_FOR_TOD:
        return []

    min_ts = min(t[0] for t in ts_list)
    max_ts = max(t[0] for t in ts_list)
    bundle_hours = (max_ts - min_ts).total_seconds() / 3600.0
    if bundle_hours < _MIN_BUNDLE_HOURS_FOR_TOD:
        return []

    # Count events per hour-of-day (0-23). ``ts.hour`` uses the
    # timestamp's local tz if it's tz-aware, naive hour otherwise.
    hour_counts: Counter = Counter(t[0].hour for t in ts_list)
    dominant_hour, dominant_count = hour_counts.most_common(1)[0]
    total = len(ts_list)
    pct = dominant_count / total

    if pct < _TOD_CLUSTER_INFO_PCT:
        return []

    # Codes whose events landed in the dominant hour — useful so the
    # engineer can cross-reference back to specific finding cards.
    codes = sorted({
        code for ts, code in ts_list if ts.hour == dominant_hour
    })

    severity = "warn" if pct >= _TOD_CLUSTER_WARN_PCT else "info"

    # Choose a human label for the hour. Avoid showing "12:00–13:00"
    # when one timestamp is 12:59 — explicitly state both endpoints.
    end_hour = (dominant_hour + 1) % 24
    window_label = f"{dominant_hour:02d}:00–{end_hour:02d}:00"

    # Editorial: explain what kinds of issues commonly cluster at
    # specific hours so the engineer has a starting hypothesis. The
    # hints below are conservative — they're "consider X" not "X is
    # the cause".
    hint = _time_of_day_hint(dominant_hour, codes)

    detail = (
        f"{dominant_count} of {total} event(s) "
        f"({pct:.0%}) happened in the {window_label} hour across "
        f"a {bundle_hours:.1f}-hour bundle window. "
        f"{hint}"
    )

    return [Pattern(
        key="time_of_day",
        title=f"Events cluster at {window_label} (local time)",
        detail=detail,
        finding_codes=codes,
        severity=severity,
    )]


def _time_of_day_hint(hour: int, codes: List[str]) -> str:
    """Generate a starting-hypothesis sentence based on the dominant
    hour. Editorial — these are starting points, not prescriptions."""
    # Morning hint — auth burst is the classic 9am pattern.
    if 7 <= hour <= 10:
        if any("auth" in c.lower() or "saml" in c.lower()
               or "mobile_api" in c.lower() for c in codes):
            return (
                "Morning auth-storm pattern: users arriving + "
                "scheduled re-auth windows overlap. Check IdP "
                "(Entra / Okta) load and any scheduled cert / "
                "token rotation around this hour."
            )
        return (
            "Morning cluster — typically users arriving and "
            "establishing tunnels in parallel. Consider IdP load, "
            "captive-portal sign-in cascades, or backup tasks "
            "scheduled at shift-start."
        )
    # Lunch hint — VPN backhaul congestion is common 12-13.
    if 11 <= hour <= 13:
        return (
            "Midday cluster — coincides with lunchtime mobile / "
            "off-network usage and noon-scheduled backup tasks. "
            "Consider VPN backhaul congestion or scheduled jobs."
        )
    # End-of-day — Internet egress peak.
    if 16 <= hour <= 18:
        return (
            "End-of-day cluster — coincides with shift change, "
            "personal-traffic peak, and any scheduled overnight "
            "task setup. Internet egress is busiest in this window."
        )
    # Overnight — sleep/wake transitions, scheduled tasks.
    if hour <= 5 or hour >= 22:
        return (
            "Overnight cluster — consider laptop sleep/wake "
            "transitions, scheduled OS updates / AV scans, "
            "certificate-renewal cron jobs."
        )
    # Other hours.
    return (
        "Cluster falls outside the usual shift-change / lunch / "
        "EoD windows. Likely tied to a scheduled task or a "
        "customer-specific event at that hour — worth asking."
    )


def detect_burst_patterns(
    findings: List[Dict[str, Any]],
) -> List[Pattern]:
    """For each detector code, find clusters of ≥{_BURST_MIN_EVENTS}
    evidence timestamps within {_BURST_WINDOW_S}s of each other.

    A burst usually indicates one upstream trigger — a policy push,
    a cert rotation, a single network outage — cascading into N
    log signals. Surfacing the burst window lets the engineer ask
    "what happened just before this?" rather than scrolling through
    N near-identical finding cards.

    Reports at most :data:`_BURST_MAX_REPORT` bursts; if the bundle
    has more, they'll show up via the underlying finding cards but
    the patterns section stays uncluttered.
    """
    # Group evidence ts by detector code. Code-level grouping (not
    # detector_id) is intentional — the same code is the same kind
    # of event; bursts of distinct codes are *not* the same shape.
    from collections import defaultdict
    code_to_ts: Dict[str, List[datetime]] = defaultdict(list)
    for f in findings:
        if f.get("code") == "DETECTOR_SKIPPED_FOR_OS":
            continue
        for ev in (f.get("evidence") or []):
            ts = ev.get("ts")
            if isinstance(ts, datetime):
                code_to_ts[f["code"]].append(ts)

    bursts: List[Pattern] = []
    for code, ts_list in code_to_ts.items():
        if len(ts_list) < _BURST_MIN_EVENTS:
            continue
        ts_list.sort()
        # Sliding-window scan. Greedy: the first N events forming a
        # tight window become "the burst" for this code, then we
        # extend that window forward as long as additional events
        # stay within _BURST_WINDOW_S of the first. We don't report
        # a second burst of the same code — the existing card surfaces
        # the same data once already.
        for i in range(len(ts_list) - _BURST_MIN_EVENTS + 1):
            window_end = i + _BURST_MIN_EVENTS - 1
            span = (ts_list[window_end] - ts_list[i]).total_seconds()
            if span > _BURST_WINDOW_S:
                continue
            # Extend forward to capture the full burst.
            j = window_end + 1
            while (j < len(ts_list)
                   and (ts_list[j] - ts_list[i]).total_seconds()
                       <= _BURST_WINDOW_S):
                j += 1
            burst = ts_list[i:j]
            burst_span = (burst[-1] - burst[0]).total_seconds()
            bursts.append(Pattern(
                key=f"burst_{code}",
                title=(
                    f"Burst — {len(burst)} `{code}` events in "
                    f"{burst_span:.0f}s at "
                    f"{burst[0].strftime('%H:%M:%S')}"
                ),
                detail=(
                    f"{len(burst)} events of `{code}` fired between "
                    f"{burst[0].strftime('%H:%M:%S')} and "
                    f"{burst[-1].strftime('%H:%M:%S')}. Bursts of "
                    f"identical signals usually indicate a single "
                    f"upstream trigger — a policy push, a cert "
                    f"rotation, a single network outage — cascading "
                    f"into N nearly-identical log entries. Look at "
                    f"what happened immediately before "
                    f"{burst[0].strftime('%H:%M:%S')} for the cause."
                ),
                finding_codes=[code],
                severity="warn",
            ))
            break  # one burst per code is plenty
    # Sort by size desc so the highest-impact bursts surface first.
    bursts.sort(
        key=lambda p: -int(p.title.split()[2])
        if p.title.split()[2].isdigit() else 0
    )
    return bursts[:_BURST_MAX_REPORT]


def detect_cross_lane_co_occurrence(
    findings: List[Dict[str, Any]],
) -> List[Pattern]:
    """Find time windows where ≥{_COOCCUR_MIN_LANES} different
    detector families fire within {_COOCCUR_WINDOW_S}s of each other.

    The closest the toolkit gets to causal-chain detection without
    doing real graph analysis. When multiple lanes fire together,
    one event most likely triggered the others — common shapes:

      * Tunnel-state flap → ZIA-auth retries (the flap broke the
        in-flight auth, the client retried, the IdP returned
        unexpected results).
      * SSL inspection policy change → app reachability failures
        (the new inspection broke TLS pinning on some apps).
      * Captive portal detected → all subsequent failures (the
        portal intercepts every TCP connection until sign-in).

    The pattern doesn't *claim* causality — it surfaces the
    temporal coincidence and lets the engineer judge.
    """
    # Lazy import to avoid circular dependency on the ui package
    # import order (clustering itself is already imported elsewhere).
    from zcc_diag.ui.clustering import _DETECTOR_GROUPS

    # Collect (ts, code, lane) tuples across every actionable finding.
    events: List[Tuple[datetime, str, str]] = []
    for f in findings:
        if f.get("code") == "DETECTOR_SKIPPED_FOR_OS":
            continue
        lane = _DETECTOR_GROUPS.get(f["detector_id"], "Other")
        for ev in (f.get("evidence") or []):
            ts = ev.get("ts")
            if isinstance(ts, datetime):
                events.append((ts, f["code"], lane))

    if len(events) < _COOCCUR_MIN_EVENTS:
        return []

    events.sort(key=lambda x: x[0])

    # Walk events; for each, gather all events within
    # _COOCCUR_WINDOW_S forward. If the gathered set spans
    # _COOCCUR_MIN_LANES distinct lanes AND has _COOCCUR_MIN_EVENTS
    # total, it's a co-occurrence. Skip past the cluster after
    # reporting so the same events don't generate overlapping
    # patterns.
    co_patterns: List[Pattern] = []
    i = 0
    while i < len(events):
        cluster_end = i
        while (cluster_end + 1 < len(events)
               and (events[cluster_end + 1][0] - events[i][0])
                   .total_seconds() <= _COOCCUR_WINDOW_S):
            cluster_end += 1
        cluster = events[i:cluster_end + 1]
        lanes_in_cluster = sorted({ev[2] for ev in cluster})
        if (len(cluster) >= _COOCCUR_MIN_EVENTS
                and len(lanes_in_cluster) >= _COOCCUR_MIN_LANES):
            window_s = (cluster[-1][0] - cluster[0][0]).total_seconds()
            codes_seen = sorted({ev[1] for ev in cluster})
            co_patterns.append(Pattern(
                key=(
                    f"cooccur_"
                    f"{cluster[0][0].isoformat(timespec='seconds')}"
                ),
                title=(
                    f"Multi-lane co-occurrence at "
                    f"{cluster[0][0].strftime('%H:%M:%S')} — "
                    f"{len(lanes_in_cluster)} detector families "
                    f"fired together"
                ),
                detail=(
                    f"{len(cluster)} events from "
                    f"[{', '.join(lanes_in_cluster)}] fired within "
                    f"{window_s:.0f}s of each other (between "
                    f"{cluster[0][0].strftime('%H:%M:%S')} and "
                    f"{cluster[-1][0].strftime('%H:%M:%S')}). "
                    f"This pattern usually indicates a causal chain "
                    f"— one event triggered cascading symptoms "
                    f"across the stack. Common shapes: tunnel flap "
                    f"→ auth retries; SSL inspection change → app "
                    f"reachability failures; captive portal → "
                    f"all subsequent failures."
                ),
                finding_codes=codes_seen,
                severity="warn",
            ))
            # Skip past the cluster so events that were already in
            # one co-occurrence don't anchor another overlapping one.
            i = cluster_end + 1
        else:
            i += 1

    # Sort by lane breadth desc — wider lane spread = more likely a
    # real causal chain (vs two co-occurring events that happened
    # to be in different lanes).
    co_patterns.sort(
        key=lambda p: -len(
            [ln for ln in (p.detail.split('[', 1)[-1]
                          .split(']', 1)[0]
                          .split(', '))]
        )
    )
    return co_patterns[:_COOCCUR_MAX_REPORT]


def detect_patterns(
    findings: List[Dict[str, Any]],
) -> List[Pattern]:
    """Run every registered pattern detector. Returns the flagged
    patterns only (no placeholders for non-matches). Order is the
    same as the detector registration list below.

    All registered detectors return ``List[Pattern]`` (empty when
    nothing matches). One-shot detectors that only ever emit zero
    or one pattern still return a list for shape consistency.
    """
    out: List[Pattern] = []
    for detector in (
        detect_time_of_day_cluster,
        detect_burst_patterns,
        detect_cross_lane_co_occurrence,
    ):
        try:
            patterns = detector(findings)
            out.extend(patterns)
        except Exception:
            # Pattern detection is best-effort; one buggy detector
            # must not break the whole section.
            continue
    return out


def render_patterns(
    findings: List[Dict[str, Any]],
    data: Optional[Dict[str, Any]] = None,
) -> None:
    """Render the "Patterns observed" section in Overview. Self-skips
    when no patterns fire — no point in an empty section that looks
    like dead UI real-estate."""
    patterns = detect_patterns(findings)
    if not patterns:
        return

    st.markdown(
        '<div class="zd-section">Patterns observed</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Cross-finding meta-analysis: shapes the timeline alone "
        "can't show. Each card below is one pattern derived from "
        "the bundle's events; not all of them imply a problem, but "
        "all of them are worth a moment of attention."
    )

    for p in patterns:
        sev_class = p.severity
        # Affected-detectors row: small code chips so the engineer
        # can hop to the matching finding cards. Empty list is fine
        # — the card stays useful with just title + detail.
        codes_html = ""
        if p.finding_codes:
            chips = ", ".join(
                f"<code>{c}</code>" for c in p.finding_codes
            )
            codes_html = (
                f'<div class="zd-finding-meta">'
                f'Affected detectors: {chips}'
                f'</div>'
            )
        st.markdown(
            f'<div class="zd-finding-card zd-sev-{sev_class}">'
            f'<div class="zd-finding-title">{p.title}</div>'
            f'<div class="zd-finding-meta">{p.detail}</div>'
            f'{codes_html}'
            f'</div>',
            unsafe_allow_html=True,
        )


# Backwards-compat aliases — module is new, but keep the underscore
# naming option so external callers can import either form.
_detect_patterns = detect_patterns
_render_patterns = render_patterns
