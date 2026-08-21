"""
ZCC tray instability detector (Phase 51, 2026-06-24).

Cross-reference check, NOT a streaming detector. Reads ZDX device-
event counts from ``summary.bundle_meta["zdx_telemetry"]`` and flags
bundles with high ``zcc_tray_stopped`` rates independent of the
chronic_memory_pressure cross-check.

Grounded in the Example Tenant A bundle inspection (2026-06-24): 81 zcc_tray_stopped
events over ~4 days (~20/day). The chronic_memory_pressure detector
correctly did NOT escalate to CRITICAL on this bundle because memory
was healthy (avg 45%), but the tray crash rate ITSELF is anomalous and
worth flagging.

Severity thresholds (per-day, normalized by bundle window):
  * < 2 / day    → no finding (clean shutdowns + occasional crash)
  * 2-5 / day    → INFO (a few tray restarts per day, possibly benign)
  * 5-15 / day   → WARNING (consistent tray instability)
  * > 15 / day   → CRITICAL (severe tray crash loop)

Future enhancement (when we have ZSATray crash-dump correlation):
distinguish clean stops (zcc_stop_traymanager) from real crashes
(zcc_tray_stopped without a matching graceful stop). For v1 we just
count the raw event.

Post-extractor pattern (matches Phase 42b/c): runs from ui/analyse.py
after the ZDX telemetry is populated. See
``issues.POST_EXTRACTORS`` for registration.
"""

from __future__ import annotations

from typing import List

from . import Finding, Findings, Severity
from ..summary import BundleSummary


# Per-day rate thresholds (count / days). Calibrated against the Example Tenant A
# baseline of ~20/day, which is clearly elevated. Customers with healthy
# tray instances see < 1/day in our reference bundles.
_INFO_RATE_PER_DAY = 2.0
_WARNING_RATE_PER_DAY = 5.0
_CRITICAL_RATE_PER_DAY = 15.0

_TRAY_STOP_EVENT = "zcc_tray_stopped"
_TRAY_GRACEFUL_STOP_EVENT = "zcc_stop_traymanager"
_TRAY_START_EVENT = "zcc_start_traymanager"


def _bundle_window_days(telemetry) -> float:
    """Estimate the bundle's observation window in days from the
    memory time series or any time-series start/end. Returns 1.0 if
    we can't determine — caller treats raw count as if it's a 1-day rate."""
    ts_map = getattr(telemetry, "time_series", None) or {}
    for metric in ts_map.values():
        first = getattr(metric, "first_ts", None)
        last = getattr(metric, "last_ts", None)
        if first and last:
            secs = (last - first).total_seconds()
            if secs > 0:
                return max(secs / 86400, 0.1)  # never return < 0.1 day
    return 1.0


def _run_check(summary: BundleSummary) -> List[Finding]:
    bm = getattr(summary, "bundle_meta", {}) or {}
    telemetry = bm.get("zdx_telemetry")
    if telemetry is None:
        return []

    event_counts = getattr(telemetry, "device_event_counts", {}) or {}
    tray_stops = event_counts.get(_TRAY_STOP_EVENT, 0)
    if tray_stops < 1:
        return []

    graceful_stops = event_counts.get(_TRAY_GRACEFUL_STOP_EVENT, 0) or 0
    tray_starts = event_counts.get(_TRAY_START_EVENT, 0) or 0
    window_days = _bundle_window_days(telemetry)
    rate_per_day = tray_stops / window_days

    if rate_per_day < _INFO_RATE_PER_DAY:
        # Below threshold — don't emit a finding (signal indistinguishable
        # from normal logon/logoff and the occasional crash).
        return []

    if rate_per_day >= _CRITICAL_RATE_PER_DAY:
        severity = Severity.CRITICAL
        sev_text = "CRITICAL"
    elif rate_per_day >= _WARNING_RATE_PER_DAY:
        severity = Severity.WARNING
        sev_text = "WARNING"
    else:
        severity = Severity.INFO
        sev_text = "INFO"

    description_parts: List[str] = []
    description_parts.append(
        f"ZDX's `upm_device_events.EVENTS` table recorded "
        f"**{tray_stops:,} `{_TRAY_STOP_EVENT}` event(s)** over an "
        f"approximately {window_days:.1f}-day observation window — "
        f"**{rate_per_day:.1f} per day**, exceeding the "
        f"{sev_text} threshold."
    )
    description_parts.append(
        f"**Context:** observed {tray_starts:,} `{_TRAY_START_EVENT}` "
        f"(starts) and {graceful_stops:,} `{_TRAY_GRACEFUL_STOP_EVENT}` "
        f"(graceful stops) in the same window. The tray restarts "
        f"on every Windows login + on every WebView2 auth-dialog "
        f"dismiss, so some volume is expected — but rates above "
        f"{_INFO_RATE_PER_DAY:.0f}/day suggest the tray is being "
        f"terminated unexpectedly."
    )
    description_parts.append(
        "**Likely causes (in order of frequency):**\n"
        "1. Memory pressure → tray gets killed by Windows OOM. "
        "Cross-check chronic_memory_pressure finding (if present, "
        "memory is the dominant driver).\n"
        "2. AV / EDR product terminating the tray as a false-positive "
        "(seen with overly-aggressive process-protection policies).\n"
        "3. WebView2 runtime crash bringing the tray down with it "
        "(check Windows Event Viewer → Application log for "
        "WebView2 or .NET unhandled exception entries near each "
        "tray-stopped timestamp).\n"
        "4. ZCC self-update mid-session leaving the tray in an "
        "inconsistent state."
    )
    description_parts.append(
        "**Recommended next steps:**\n"
        "1. Check the Windows Application event log on the affected "
        "device for crash dumps around the tray-stopped timestamps "
        "(`Get-WinEvent -LogName Application -MaxEvents 200`).\n"
        "2. If chronic_memory_pressure also fired, address that "
        "first — it's the upstream cause.\n"
        "3. Inventory the AV/EDR product set on the device. Confirm "
        "Zscaler's process names (ZSATray.exe / ZSATrayManager.exe) "
        "are in the AV exclusion list.\n"
        "4. Update WebView2 runtime to the latest version (Microsoft "
        "ships standalone evergreen updates outside Windows Update)."
    )

    return [Finding(
        code="ZCC_TRAY_INSTABILITY",
        severity=severity,
        title=(
            f"ZCC tray restarting {rate_per_day:.1f} times/day "
            f"({tray_stops} events over {window_days:.1f} days)"
        ),
        description="\n\n".join(description_parts),
        count=tray_stops,
        sop_anchor="#zcc-tray-instability",
    )]


def derive_tray_instability_findings(
    summary: BundleSummary,
) -> Findings:
    """Public entry — returns a Findings container the caller appends
    to the analyse-output findings list."""
    return Findings(
        issue_id="zcc_tray_instability",
        issue_title="ZCC tray restarting at elevated rate",
        sop_path=None,
        findings=_run_check(summary),
    )
