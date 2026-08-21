"""
Chronic memory pressure detector (Phase 42c, 2026-06-19).

Reads the Phase 42a ZdxTelemetry's ``memory_pct_used`` time series
and flags bundles where the device sat at >=85% memory utilization
for >=50% of the bundle window. That threshold separates "the
machine spiked briefly" (normal) from "this machine is chronically
memory-starved" (operational issue worth flagging).

Grounded in Example Tenant A bundle 2026-06-18 where:
  - 3,638 memory samples over a ~6-day window
  - mean 88.7%, p50 89%, p95 94%, max 97%
  - 3,269/3,638 samples (~90%) were >=85%
  - Two ZSATray hard-crash dumps in the window

Severity:
  - CRITICAL: chronic (>=50% of samples >=85%) AND correlated with
    at least one ``zcc_tray_stopped`` event in upm_device_events.
    The combination is the smoking gun for "tray crashed under
    memory pressure."
  - WARNING:  chronic without confirmed tray-side correlation.
  - None:    spotty / brief (<50% of samples) — no finding.

Post-extractor (not a streaming detector) — runs from ui/analyse.py
after the ZdxTelemetry is on bundle_meta. Same architectural shape
as the catalog-drift cross-reference (Phase 42b).
"""

from __future__ import annotations

from typing import List

from . import Finding, Findings, Severity
from ..summary import BundleSummary


# Threshold: 85% memory utilization is the WAR floor; below this
# we don't consider the machine "pressured."
_MEMORY_THRESHOLD = 85.0

# Fraction of samples that must exceed the threshold to call it
# "chronic." 50% = the engineer can paste "your machine spent the
# majority of the bundle window above 85% memory used" with
# confidence.
_CHRONIC_FRACTION = 50.0

# Tray-crash signal — appears as an event name in
# upm_device_events.EVENTS. The combination of chronic memory
# pressure + tray_stopped events is the CRITICAL escalation.
_TRAY_STOP_EVENT = "zcc_tray_stopped"


def _run_check(summary: BundleSummary) -> List[Finding]:
    """Cross-reference memory-pressure time-series with
    tray-stop event count. Returns 0 or 1 Finding."""
    bm = getattr(summary, "bundle_meta", {}) or {}
    telemetry = bm.get("zdx_telemetry")
    if telemetry is None:
        return []

    ts_map = getattr(telemetry, "time_series", None) or {}
    mem_ts = ts_map.get("memory_pct_used")
    if mem_ts is None or not getattr(mem_ts, "samples", 0):
        return []

    threshold_pct = getattr(mem_ts, "threshold_pct", None)
    if threshold_pct is None or threshold_pct < _CHRONIC_FRACTION:
        return []

    event_counts = getattr(telemetry, "device_event_counts", {}) or {}
    tray_stops = event_counts.get(_TRAY_STOP_EVENT, 0)

    mean = getattr(mem_ts, "mean", 0) or 0
    p50 = getattr(mem_ts, "p50", 0) or 0
    p95 = getattr(mem_ts, "p95", 0) or 0
    mx = getattr(mem_ts, "max", 0) or 0
    samples = getattr(mem_ts, "samples", 0) or 0
    threshold_count = getattr(mem_ts, "threshold_count", 0) or 0

    severity = Severity.CRITICAL if tray_stops else Severity.WARNING
    severity_label = "CRITICAL" if severity is Severity.CRITICAL else "WARNING"

    desc_parts: List[str] = []
    desc_parts.append(
        f"ZDX's `upm_device_stats.tbl_memory_usage` table recorded "
        f"**{samples:,} memory-utilization samples** during the "
        f"bundle window. **{threshold_count:,} of them "
        f"({threshold_pct:.0f}%) were at or above "
        f"{_MEMORY_THRESHOLD:.0f}% memory used** — the machine was "
        f"chronically memory-pressured, not just occasionally "
        f"spiking."
    )
    desc_parts.append(
        f"**Distribution:** mean {mean:.1f}%, p50 {p50:.1f}%, "
        f"p95 {p95:.1f}%, max {mx:.1f}%."
    )

    if tray_stops:
        desc_parts.append(
            f"**Correlation with tray stability:** "
            f"`upm_device_events` recorded **{tray_stops} "
            f"`{_TRAY_STOP_EVENT}` event(s)** in the same window. "
            "Tray crashes under chronic memory pressure are a "
            "well-known pattern — ZSATray's WebView2-embedded auth "
            "UI is heap-heavy and the tray is one of the first "
            "processes the kernel reclaims pages from when memory "
            "is tight."
        )
    else:
        desc_parts.append(
            "No `zcc_tray_stopped` events were observed in this "
            "bundle window, so the memory pressure has not (yet) "
            "manifested as a tray crash. The risk remains elevated."
        )

    desc_parts.append(
        "**Recommended next steps:**\n"
        "1. Check the machine's RAM — is it sized correctly for "
        "the user's workload? The Example Tenant A-style 8 GB Lenovo running "
        "Windows 11 + Citrix + Office + ZCC is borderline; 16 GB "
        "removes the pressure.\n"
        "2. Audit which processes are leaking. ZDX's "
        "`upm_device_stats.tbl_mon_processes` table records "
        "per-process CPU/memory; cross-reference against the top "
        "consumers.\n"
        "3. If RAM can't be increased, consider tuning Windows "
        "memory-compression settings (`Get-MMAgent` / "
        "`Enable-MMAgent`) and confirming Modern Standby is "
        "behaving — multiple sleep/wake cycles without a clean "
        "page-pool reset can accumulate fragmentation."
    )

    return [Finding(
        code="CHRONIC_MEMORY_PRESSURE",
        severity=severity,
        title=(
            f"Chronic memory pressure — "
            f"{threshold_pct:.0f}% of {samples:,} samples >=85% used"
            + (f" + {tray_stops} tray stop(s)" if tray_stops else "")
        ),
        description="\n\n".join(desc_parts),
        count=threshold_count,
        sop_anchor="#chronic-memory-pressure",
    )]


def derive_memory_pressure_findings(
    summary: BundleSummary,
) -> Findings:
    """Public entry — returns a Findings container the caller appends
    to the analyse-output findings list."""
    return Findings(
        issue_id="chronic_memory_pressure",
        issue_title="Chronic memory pressure on the user's machine",
        sop_path=None,
        findings=_run_check(summary),
    )
