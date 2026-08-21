"""
Polling cadence learner.

For each application (Storefront, etc.), look at the inter-mtunnel-open
intervals. If the intervals cluster around a periodic value, that
application is being polled (Citrix Workspace 15-min Storefront poll,
SSO health probes, etc.) and individual mtunnel events on that cadence
should be classified as "background polling" rather than "user action."

Reverse-engineering audit finding M-6: don't hardcode 15 min — learn
the cadence from the data. Citrix Workspace cadence is configurable;
SSO probes are different again.

Method:
  1. Group mtunnel opens by app_name.
  2. For each app with >=3 opens, compute inter-event intervals.
  3. Take the IQR-median (robust against outliers).
  4. Count what fraction of intervals fall within ±10% of the median.
  5. If that fraction is >=0.7, declare the app "polled" with the
     learned cadence; flag opens that match the cadence as polling.

Returns a PollingCadence per app that the synthesizer can use to
classify each mtunnel-open event.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from ..log_parser import LogLine
from .mtunnel import _RE_TAG_ID, _RE_APP_NAME, _RE_MTUNNEL_REQUEST  # reuse regexes


# Minimum opens before we'll even try to detect a cadence.
MIN_OPENS_FOR_CADENCE = 4

# Fraction of intervals within ±10% of median to declare "polled".
CADENCE_CONFIDENCE_THRESHOLD = 0.70

# How tightly an individual interval must match the learned cadence
# to flag the corresponding mtunnel-open as polling.
CADENCE_MATCH_TOLERANCE = 0.10  # ±10%

# Citrix Workspace (and similar SSO/probe clients) typically open multiple
# mtunnels in rapid succession per poll cycle — e.g., two TCP connections
# 80ms apart for redundancy. We collapse opens within this window into a
# single "poll event" before measuring inter-poll intervals.
# Found during Phase 48 validation: Storefront opened mtunnels at
# 15:43:48.356 + 15:43:48.438 (paired ~80ms apart) → naive interval math
# yielded 0.04s instead of the real 900s (15-min) cadence.
POLL_CLUSTER_WINDOW = 5.0   # seconds

# Cross-session gap above this is treated as a session boundary, not a
# polling interval (used for inter-poll median calculation).
SESSION_BOUNDARY_SECONDS = 3600  # 1 hour


@dataclass
class PollingCadence:
    """Learned cadence for one application."""
    app_name: str
    open_count: int
    median_interval_seconds: Optional[float]
    confidence: float  # fraction of intervals within ±10% of median
    is_polled: bool    # True if confidence >= threshold
    open_timestamps: List[datetime] = field(default_factory=list)

    def is_polling_open(self, open_ts: datetime,
                        prior_open_ts: Optional[datetime]) -> bool:
        """Decide whether a specific mtunnel-open is part of the polling
        cadence (vs. a user-initiated action that happened to coincide
        with the same app).

        prior_open_ts is the most recent previous open for the same app.
        """
        if not self.is_polled or self.median_interval_seconds is None:
            return False
        if prior_open_ts is None:
            # First open of the day — ambiguous; default to "polling" if
            # this app's cadence was learned.
            return True
        delta = (open_ts - prior_open_ts).total_seconds()
        lo = self.median_interval_seconds * (1 - CADENCE_MATCH_TOLERANCE)
        hi = self.median_interval_seconds * (1 + CADENCE_MATCH_TOLERANCE)
        return lo <= delta <= hi


def learn_polling_cadence(
    records: Iterable[LogLine],
) -> Dict[str, PollingCadence]:
    """Walk records, collect mtunnel-open timestamps per app_name,
    and learn a cadence per app.

    NOTE on line structure: `App Name=...` appears on the "ZPN Connection
    local:X->Y App Name=Z, ... TAG-ID=N" line, NOT on the subsequent
    "zpn_mtunnel_request" / "zpn_mtunnel_request_ack" lines. So we
    record the app→tag association whenever we see App Name on ANY line,
    then count mtunnel-open events using that tag→app lookup.

    Returns dict keyed by app_name. Apps with fewer than
    MIN_OPENS_FOR_CADENCE opens still get an entry (is_polled=False).
    """
    # First pass: build tag_id → app_name map by walking every record
    # with an "App Name=" hit (typically the ZPN Connection line).
    tag_to_app: Dict[int, str] = {}
    for r in records:
        msg = r.message or ""
        am = _RE_APP_NAME.search(msg)
        if not am:
            continue
        tm = _RE_TAG_ID.search(msg)
        if not tm:
            # Some "App Name=" lines use TAG-ID= (dash), not tag_id=
            tm = re.search(r'TAG[-_]ID["\s:=]*([0-9]+)', msg, re.IGNORECASE)
            if not tm:
                continue
        tag = int(tm.group(1))
        # Most-recent wins, in case the same tag was reused across sessions.
        tag_to_app[tag] = am.group(1)

    # Second pass: collect mtunnel-open timestamps grouped by app_name.
    opens_by_app: Dict[str, List[datetime]] = {}
    seen_keys: set = set()

    for r in records:
        msg = r.message or ""
        if not _RE_MTUNNEL_REQUEST.search(msg):
            continue
        tag_match = _RE_TAG_ID.search(msg)
        if not tag_match:
            continue
        tag_id = int(tag_match.group(1))
        # Dedupe — same tag_id may appear in multiple log lines per open.
        key = (tag_id, r.timestamp)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        app = tag_to_app.get(tag_id)
        if not app:
            continue
        opens_by_app.setdefault(app, []).append(r.timestamp)

    result: Dict[str, PollingCadence] = {}
    for app, ts_list in opens_by_app.items():
        ts_list = sorted(ts_list)
        if len(ts_list) < MIN_OPENS_FOR_CADENCE:
            result[app] = PollingCadence(
                app_name=app, open_count=len(ts_list),
                median_interval_seconds=None, confidence=0.0,
                is_polled=False, open_timestamps=ts_list,
            )
            continue

        # Cluster opens within POLL_CLUSTER_WINDOW into a single
        # "poll event" so paired mtunnels (Citrix Workspace dual-TCP)
        # don't dominate the median.
        clusters: List[datetime] = [ts_list[0]]
        for ts in ts_list[1:]:
            if (ts - clusters[-1]).total_seconds() > POLL_CLUSTER_WINDOW:
                clusters.append(ts)
        # Take inter-cluster intervals — but ONLY within the same session
        # (skip session-boundary gaps from per-day cadence measurement).
        intervals_within_session = [
            (clusters[i] - clusters[i-1]).total_seconds()
            for i in range(1, len(clusters))
            if (clusters[i] - clusters[i-1]).total_seconds() < SESSION_BOUNDARY_SECONDS
        ]
        if len(intervals_within_session) < MIN_OPENS_FOR_CADENCE - 1:
            result[app] = PollingCadence(
                app_name=app, open_count=len(ts_list),
                median_interval_seconds=None, confidence=0.0,
                is_polled=False, open_timestamps=ts_list,
            )
            continue

        # MODE-based cadence detection (median was too noise-sensitive).
        # Found during Phase 48 validation: Storefront polling on the
        # Example Tenant A bundle had a clean 15-min mode (45 intervals) but the
        # median was 670s because noise (retries, errors, manual launches)
        # pulled it down. Mode is robust to that.
        #
        # We bin intervals at minute granularity and find the most-common
        # bin. If that bin (plus ±1 min neighbours, since real cadences
        # have natural jitter) contains a high fraction of intervals,
        # the app is polled at that cadence.
        binned = [round(v / 60) for v in intervals_within_session]
        from collections import Counter
        bin_counts = Counter(binned)
        if not bin_counts:
            result[app] = PollingCadence(
                app_name=app, open_count=len(ts_list),
                median_interval_seconds=None, confidence=0.0,
                is_polled=False, open_timestamps=ts_list,
            )
            continue

        mode_min, mode_count = bin_counts.most_common(1)[0]
        # Be generous: a poll cadence will have most hits at mode_min
        # but also some at mode_min±1 from natural network jitter.
        # We sum the mode bin + immediate neighbours.
        adjacent = bin_counts[mode_min - 1] + bin_counts[mode_min + 1]
        cadence_hits = mode_count + adjacent
        confidence = cadence_hits / len(intervals_within_session)

        median_for_display = mode_min * 60.0  # report the mode as the
                                              # cadence, not the noisy median
        result[app] = PollingCadence(
            app_name=app, open_count=len(ts_list),
            median_interval_seconds=median_for_display,
            confidence=confidence,
            is_polled=(
                confidence >= CADENCE_CONFIDENCE_THRESHOLD
                or (mode_count >= 10 and confidence >= 0.35)
            ),
            # Second clause: a strong mode-hit with moderate confidence
            # is still a polling signal — common in noisy bundles where
            # retries dilute the band but the underlying cadence is real.
            open_timestamps=ts_list,
        )

    return result
