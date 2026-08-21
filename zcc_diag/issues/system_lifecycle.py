"""
Detector: System Lifecycle (sleep / wake correlation).

What this catches
-----------------
ZCC tunnel disconnects + auth resyncs are not always incidents. When a
user closes their laptop lid, the OS sends a sleep notification, the
tunnel tears down cleanly, the user opens the lid an hour later, the
tunnel comes back up — three findings get raised by other detectors
(state flap, broker reconnect, OneID keep-alive miss). All of them are
expected behaviour for a sleeping laptop.

This detector parses the OS-side sleep + wake markers so a separate
downgrader pass (``ui.analyse._downgrade_lifecycle_correlated``) can
re-label tunnel-flap-family findings that fall in a sleep/wake window
as Info — telling the engineer "this is laptop lifecycle, not an
incident" — instead of leaving them at Critical.

What this is NOT
----------------
- It doesn't predict whether the user *intended* to sleep (lid close
  vs power button vs OS-scheduled sleep). All sleep events look the
  same to the toolkit.
- It doesn't try to detect lid-only-network-stayed-on transitions
  (modern standby / S0). Those don't produce sleep markers but also
  don't tear down the tunnel.
- It doesn't downgrade FINDINGS itself — the downgrader is a separate
  pass that consumes this detector's output and modifies other
  detectors' findings.

Signal sources
--------------
The signals live in three different log kinds depending on platform:

  Mac WAKE:
    * Tunnel logs: ``wake notification recvd: NSWorkspaceDidWakeNotification``
    * Tray logs:   ``INF receiveWakeNote: NSWorkspaceDidWakeNotification``
    * Tunnel logs: ``INF wake: notification recvd``, ``INF wake: Tunnel ...``
  Mac SLEEP:
    * UPM logs:    ``INF system is going to sleep.``
  Windows WAKE:
    * Service:     ``DBG processComputerWakeEvent``
  Windows SLEEP:
    * Not consistently emitted in any single log kind. We infer windows
      around each WAKE event and treat the WAKE itself as the
      lifecycle-signal anchor; if a paired SLEEP marker isn't present,
      the downgrader still has a usable anchor.

The detector opts in to ``wants_tray_logs`` AND
``wants_extra_log_kinds`` (service + upm + upm_controller) — three of
the four signals live outside tunnel logs, which is the only log kind
the multiplexer walks by default.

Findings emitted
----------------
One ``SYSTEM_LIFECYCLE_EVENTS`` finding per bundle that contains any
sleep/wake markers. Severity is always INFO — the lifecycle events
themselves are not problems. The interesting data lives in the
finding's ``evidence`` list (one LogLine per event, capped at 20).
The downgrader reads ``finding.evidence`` to extract event timestamps
for correlation. Bursts (e.g. laptop bouncing in/out of sleep in a
30-minute window) are deliberately kept verbose-uncapped in
``finding.count`` so the engineer sees the full lifecycle volume even
when only 20 are surfaced in evidence.

CALIBRATION
-----------
- Scenario Windows B's bundle has 11 Windows wake events across 4 days — every
  expected, no sleep marker.
- Scenario macOS A's bundle has 50+ Mac wake events + 100+ "system is going to
  sleep" UPM lines across a week. Laptop in a bag, opening/closing
  many times.
- Both produced INFO-only findings as designed.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# Mac WAKE — three variants seen in real bundles.
_RE_MAC_WAKE_NS = re.compile(
    r"\bNSWorkspaceDidWakeNotification\b",
)
# Tunnel/service-log specific "INF wake:" prefix that signals the
# tunnel itself reacting to a wake. Captures the broader wake event
# even if the NS notification line is in a different file we don't
# walk.
_RE_MAC_WAKE_PREFIX = re.compile(
    r"^\s*wake:\s+(?:trial|Tunnel|notification|ZIA)",
    re.IGNORECASE,
)

# Mac SLEEP — single canonical phrase in UPM logs.
_RE_MAC_SLEEP = re.compile(
    r"\bsystem is going to sleep\b",
    re.IGNORECASE,
)

# Windows WAKE — debug-level event in ZSAService.
_RE_WIN_WAKE = re.compile(
    r"\bprocessComputerWakeEvent\b",
)

# Windows SLEEP — best-effort. ZSAService doesn't reliably log a
# matching sleep event; we accept these phrases when they appear.
_RE_WIN_SLEEP = re.compile(
    r"\b(?:processComputerSleepEvent|System(?:\s+is)?\s+entering\s+sleep|"
    r"power\s+state\s+change\s+to\s+(?:suspend|sleep|standby))\b",
    re.IGNORECASE,
)


# Evidence cap. Lifecycle events on a heavy-use laptop can be 50+ per
# day; 20 is plenty for the downgrader to do its job (it uses ALL
# timestamps via finding.count, not just evidence).
EVIDENCE_CAP = 20


# --- Detector ---------------------------------------------------------

@register
class SystemLifecycleDetector(IssueDetector):
    id = "system_lifecycle"
    title = "System sleep / wake events"
    sop_file = ""  # No SOP — these are informational, not a triage step.
    # Cross-suite: OS-level lifecycle events are suite-agnostic.
    applies_to_suite = None

    # Opt-in to tray AND service/upm log kinds. The three patterns
    # above live in different files depending on platform.
    wants_tray_logs = True
    wants_extra_log_kinds = ("service", "upm", "upm_controller")

    # Cross-platform — runs on every bundle. The patterns themselves
    # are platform-specific, so a Mac-only bundle won't false-fire the
    # Windows regex and vice versa.
    applies_to_os = None

    # Hot-path skip: every signal phrase contains one of these
    # substrings, so we can pre-filter records before doing regex work.
    prematch_substrings = (
        "wake",
        "Wake",
        "sleep",
        "Sleep",
        "processComputer",
        "NSWorkspaceDid",
    )

    # --- IssueDetector overrides ---------------------------------

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        """Tunnel logs — Mac wake markers also appear here."""
        self._scan(record)

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        """Tray logs — receiveWakeNote: NSWorkspaceDidWakeNotification."""
        self._scan(record)

    def feed_extra(
        self,
        record: LogLine,
        summary: BundleSummary,
        kind: str,
    ) -> None:
        """Service logs (Win wake) + UPM logs (Mac sleep)."""
        self._scan(record)

    # --- Internal -----------------------------------------------------

    def _scan(self, record: LogLine) -> None:
        msg = record.message
        if _RE_MAC_WAKE_NS.search(msg) or _RE_MAC_WAKE_PREFIX.search(msg):
            self._add("wake", record)
        elif _RE_WIN_WAKE.search(msg):
            self._add("wake", record)
        elif _RE_MAC_SLEEP.search(msg):
            self._add("sleep", record)
        elif _RE_WIN_SLEEP.search(msg):
            self._add("sleep", record)

    def _add(self, kind: str, record: LogLine) -> None:
        """Append a lifecycle event to the appropriate bucket. ``kind``
        is "sleep" or "wake"."""
        f = self._bucket(
            code=f"SYSTEM_{kind.upper()}_EVENT",
            severity=Severity.INFO,
            title=(
                f"System {kind} events"
            ),
            description=(
                f"OS-level {kind} events detected in the bundle. These "
                f"are informational — sleep/wake on laptops is expected "
                f"behaviour. Other detectors' tunnel-flap findings "
                f"within +/- 60s of these timestamps are likely a "
                f"consequence of the lifecycle, not an incident, and "
                f"will be auto-downgraded to Info."
            ),
        )
        f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        """Emit one Finding per kind (sleep / wake) that actually fired.

        Order: sleep first, wake second. Both are INFO so the order
        only affects the engineer-facing presentation, not any
        ranking logic.
        """
        out: List[Finding] = []
        for code in ("SYSTEM_SLEEP_EVENT", "SYSTEM_WAKE_EVENT"):
            f = self._buckets.get(code)
            if f is None or not f.evidence:
                continue
            # Title polish: include the count so engineers know how
            # noisy the lifecycle was without opening the finding.
            kind_word = "sleep" if "SLEEP" in code else "wake"
            f.title = f"{f.count} system {kind_word} event(s) detected"
            out.append(f)
        return out
