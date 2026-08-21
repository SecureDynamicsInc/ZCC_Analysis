"""
ZDX SQLite telemetry extractor.

Phase 42a (2026-06-19). Reads the ``upm_*.db`` SQLite databases ZDX
maintains inside every ZCC bundle (under ``log-<hash>/``) and turns
them into a structured ``ZdxTelemetry`` dataclass the rest of
BundleScope can consume.

These databases are pure ZDX telemetry — they're the on-device cache
of everything ZCC has measured and reported (or is queued to report)
to the ZDX cloud. Until Phase 42 they were *completely ignored* by
the toolkit. The bundle a senior engineer should be reading line by
line includes:

  - upm_device_stats     CPU / memory / disk / battery / network
                          throughput time series (~3600 samples on
                          a typical 6-day bundle)
  - upm_device_events    Categorized ZCC event log: zpa_state,
                          zia_state, zdx_upload_success/failure,
                          zcc_tray_stopped, zcc_user_zpa_
                          authenticate_now_request, posture results,
                          OS sleep/wake/lock events, Windows-update
                          install success/failure, anti-tamper
                          starts, ... (~2,000 events)
  - upm_device_inventory Installed software snapshot + recent
                          install/uninstall events with timestamps
  - upm_device_profile   System hardware + OS + interface snapshots
                          over time
  - upm_webload          Per-app web-load monitoring: URLs, DNS time,
                          page-fetch time, availability
  - upm_traceroute       Per-app traceroute sessions and hop latency
  - upm_upload_stats     Actual ZDX cloud-upload payloads (the raw
                          telemetry sent to Zscaler)
  - upm_ssit             Self-Service Issue Triage engine state
  - upm_rum              Real-User-Monitoring snapshots
  - upm_workflows        ZDX remediation-workflow state
  - upm_bandwidth_test   Speedtest results

What the extractor surfaces (the high-value subset):

  * ZDX-monitored URLs with per-URL sample count, availability
    percentage, and "has_unresolved_ip" flag — set when the
    traceroute pass couldn't resolve the host at all. That marker is
    the smoking gun for the Example Tenant A-style case: ZDX is told this app
    matters, but DNS/ZPA can't actually reach it.
  * Traceroute targets with resolved IPs (or blank, which is also a
    finding).
  * Device-event counts by name, plus the recent failure-flavored
    events with their JSON metrics.
  * Compact time-series stats (min/mean/p50/p95/max) for memory,
    CPU, battery, disk, plus per-metric threshold-tagged counts
    (e.g. "samples where memory ≥85% used").
  * Top CPU-consuming processes over the bundle window.
  * Installed-software inventory + recent install / uninstall events
    (timestamped). The Example Tenant A bundle's "Microsoft Edge WebView2
    Runtime uninstalled at Jun 16 13:06" event is exactly the kind of
    finding that explains otherwise-mysterious auth-UI failures.
  * ZDX upload counts + failure rate.

Pure-stdlib (``sqlite3`` is in the Python stdlib). Best-effort: any
single DB that fails to open or read is logged as a diagnostic and
the extractor continues with the rest. Designed so a malformed DB
never breaks ``analyse()``.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# --------------------------------------------------------------------
# Data shapes
# --------------------------------------------------------------------


@dataclass
class MonitoredUrl:
    """One URL ZDX is actively probing via the WebData web-load
    monitor. ``has_unresolved_ip`` is set during the traceroute pass
    when the host couldn't be resolved at all — a strong "this app
    is broken at the network layer" signal."""
    url: str
    app_id: Optional[int] = None
    mon_id: Optional[int] = None
    is_predefined: bool = False
    sample_count: int = 0
    mean_dns_ns: Optional[float] = None
    mean_pageload_ns: Optional[float] = None
    # ZDX stores availability as a fraction × 10000 (basis points).
    # We surface it normalized to 0-100 percent for the UI.
    availability_pct: Optional[float] = None
    has_unresolved_ip: bool = False

    @property
    def host(self) -> str:
        """Hostname only — useful for cross-referencing with ZPA app
        catalog or DNS failure lists."""
        u = self.url or ""
        for prefix in ("https://", "http://"):
            if u.startswith(prefix):
                u = u[len(prefix):]
                break
        return u.split("/")[0].split(":")[0]


@dataclass
class TimeSeriesStats:
    """Compact summary of one device-stats time series."""
    metric: str
    samples: int
    min: Optional[float] = None
    max: Optional[float] = None
    mean: Optional[float] = None
    p50: Optional[float] = None
    p95: Optional[float] = None
    threshold_value: Optional[float] = None
    threshold_count: int = 0
    threshold_pct: Optional[float] = None


@dataclass
class DeviceEvent:
    """One row from upm_device_events.EVENTS or REM_EVENTS — the
    structured event log ZCC keeps for ZDX cloud upload."""
    ts: datetime
    name: str
    category: int
    module: int
    metrics_json: Optional[str] = None


@dataclass
class InstalledApp:
    """One row from upm_device_inventory.tbl_last_snapshot."""
    name: str
    version: str
    publisher: str
    install_date: Optional[str] = None
    source: str = ""


@dataclass
class InventoryEvent:
    """Install or uninstall event timestamped to the second."""
    ts: datetime
    kind: str                 # "install" | "uninstall"
    name: str
    version: str
    publisher: str = ""


@dataclass
class ZdxTelemetry:
    """Everything Phase 42 pulls from the upm_*.db files.

    Phase 43k (2026-06-24) — memory-footprint audit:
    The architecture review flagged ZdxTelemetry as a candidate cache-
    bloat source because the upm_*.db files can hold thousands of
    samples (e.g. 3,638 memory samples on Example Tenant A). However, this
    dataclass ALREADY stores summary stats only — TimeSeriesStats
    has min/max/mean/p50/p95/threshold_count, not the raw samples.
    Other fields are bounded by extraction logic:

      device_events_recent : capped at 100 (per LIMIT clause in
                              _extract_device_events query)
      process_top_cpu       : top-N, bounded by query LIMIT
      inventory_apps        : unbounded but rarely >2000 entries
      inventory_recent_*    : capped at most-recent N
      monitored_urls        : bounded by URLs ZDX monitors (~tens)

    Worst-case footprint on a real bundle (Example Tenant A): ~150 KB per
    ZdxTelemetry. Streamlit's @cache_data limit is far higher.
    The audit concern was theoretical, not measured — but the
    bounds documented above guarantee it stays that way.
    """
    monitored_urls: List[MonitoredUrl] = field(default_factory=list)
    traceroute_targets: List[Tuple[str, str]] = field(default_factory=list)
    device_event_counts: Dict[str, int] = field(default_factory=dict)
    device_events_recent: List[DeviceEvent] = field(default_factory=list)
    time_series: Dict[str, TimeSeriesStats] = field(default_factory=dict)
    process_top_cpu: List[Tuple[str, float, float]] = field(
        default_factory=list,
    )
    inventory_apps: List[InstalledApp] = field(default_factory=list)
    inventory_recent_installs: List[InventoryEvent] = field(
        default_factory=list,
    )
    inventory_recent_uninstalls: List[InventoryEvent] = field(
        default_factory=list,
    )
    upload_count: int = 0
    upload_failure_count: int = 0
    diagnostics: List[str] = field(default_factory=list)

    @property
    def has_data(self) -> bool:
        return bool(
            self.monitored_urls or self.traceroute_targets
            or self.device_event_counts or self.time_series
            or self.inventory_apps
        )

    def estimate_memory_bytes(self) -> int:
        """Best-effort estimate of this dataclass's in-memory footprint.
        Diagnostic helper — for verifying the cache-bloat claim and for
        future regressions if someone adds an unbounded list.

        Uses ``sys.getsizeof`` recursively on the typed containers.
        Not exact (Python's object overhead varies by interpreter) —
        the goal is to flag order-of-magnitude growth, not precision.
        """
        import sys
        total = sys.getsizeof(self)
        for collection in (
            self.monitored_urls, self.traceroute_targets,
            self.device_event_counts, self.device_events_recent,
            self.process_top_cpu, self.inventory_apps,
            self.inventory_recent_installs,
            self.inventory_recent_uninstalls, self.diagnostics,
        ):
            total += sys.getsizeof(collection)
            for item in collection:
                total += sys.getsizeof(item)
                # For dataclass items, include the slotted/dict attrs
                if hasattr(item, "__dict__"):
                    total += sys.getsizeof(item.__dict__)
                    for v in item.__dict__.values():
                        total += sys.getsizeof(v)
        # time_series dict + its values
        total += sys.getsizeof(self.time_series)
        for stats in self.time_series.values():
            total += sys.getsizeof(stats)
            if hasattr(stats, "__dict__"):
                total += sys.getsizeof(stats.__dict__)
        return total

    @property
    def unresolved_zdx_hosts(self) -> List[str]:
        """ZDX-monitored hostnames whose traceroute couldn't resolve
        an IP. High-signal for the "ZDX knows about it, ZPA can't
        reach it" finding."""
        return [u.host for u in self.monitored_urls if u.has_unresolved_ip]


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def _ms_to_dt(ms: Any) -> datetime:
    """Convert epoch milliseconds to UTC datetime, defensively."""
    try:
        return datetime.fromtimestamp(float(ms) / 1000.0, tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _percentile(sorted_vals: List[float], p: float) -> Optional[float]:
    """Linear interpolation percentile on a pre-sorted list."""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    if lo == hi:
        return float(sorted_vals[lo])
    return float(
        sorted_vals[lo]
        + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)
    )


# Mapping of normalized base name → DB filename component. ZDX names
# its databases ``upm_<basename>_<bundle-hash>.db``. The hash is
# the same across all DBs in one bundle (it's the per-machine ID).
_DB_BASES = (
    "webload", "traceroute", "device_events", "device_stats",
    "device_inventory", "device_profile", "upload_stats",
    "ssit", "rum", "workflows", "bandwidth_test",
)


def _find_upm_dbs(log_dir: Path) -> Dict[str, Path]:
    """Return ``{base_name → full path}`` for every upm_*.db under
    ``log_dir``. Handles the trailing ``_<hash>.db`` suffix."""
    out: Dict[str, Path] = {}
    try:
        names = os.listdir(log_dir)
    except OSError:
        return out
    for name in names:
        if not (name.startswith("upm_") and name.endswith(".db")):
            continue
        body = name[len("upm_"):-len(".db")]
        # body is e.g. "device_stats_6DADD2..." — strip the trailing
        # hash if present.
        if "_" in body:
            parts = body.rsplit("_", 1)
            if len(parts) == 2 and len(parts[1]) >= 20 and all(
                c in "0123456789abcdefABCDEF" for c in parts[1]
            ):
                body = parts[0]
        if body in _DB_BASES:
            out[body] = Path(log_dir) / name
    return out


def _safe_open(path: Path) -> Optional[sqlite3.Connection]:
    """Open a SQLite file read-only via URI to avoid accidental writes.
    Returns None on any DatabaseError so callers can fall through."""
    try:
        # ``mode=ro`` opens read-only; ``immutable=1`` tells SQLite
        # we promise not to write so it skips locking/journal setup.
        # Falls back to plain Connect if URI mode isn't supported.
        return sqlite3.connect(
            f"file:{path}?mode=ro&immutable=1", uri=True,
        )
    except sqlite3.DatabaseError:
        try:
            return sqlite3.connect(str(path))
        except sqlite3.DatabaseError:
            return None


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    )
    return cur.fetchone() is not None


# --------------------------------------------------------------------
# Per-DB extractors
# --------------------------------------------------------------------


def _extract_webload(
    conn: sqlite3.Connection, telemetry: ZdxTelemetry,
) -> None:
    """Per-URL aggregates from upm_webload.WebData."""
    if not _table_exists(conn, "WebData"):
        return
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT URL, AppID, MonID, IsPredefinedMon,
                   COUNT(*), AVG(DNSTime_ns), AVG(PageFetchTime_ns),
                   AVG(Availability)
            FROM WebData
            GROUP BY URL
        """)
        for row in cur.fetchall():
            url, app_id, mon_id, is_pre, cnt, avg_dns, avg_pl, avg_av = row
            # Availability lives in basis points (×10000). Normalize.
            avail_pct = None
            if avg_av is not None:
                try:
                    raw = float(avg_av)
                    # Heuristic: if value is in 0-1 range, multiply
                    # by 100; if 0-10000 range, divide by 100.
                    if raw <= 1.0:
                        avail_pct = raw * 100.0
                    elif raw <= 100.0:
                        avail_pct = raw
                    else:
                        avail_pct = raw / 100.0
                except (TypeError, ValueError):
                    pass
            telemetry.monitored_urls.append(MonitoredUrl(
                url=url or "",
                app_id=app_id,
                mon_id=mon_id,
                is_predefined=bool(is_pre),
                sample_count=cnt or 0,
                mean_dns_ns=float(avg_dns) if avg_dns is not None else None,
                mean_pageload_ns=(
                    float(avg_pl) if avg_pl is not None else None
                ),
                availability_pct=avail_pct,
            ))
    except sqlite3.DatabaseError as e:
        telemetry.diagnostics.append(f"webload: {e}")


def _extract_traceroute(
    conn: sqlite3.Connection, telemetry: ZdxTelemetry,
) -> None:
    """Per-target rollup from upm_traceroute.trmain — sets the
    ``has_unresolved_ip`` flag on any matching monitored URL."""
    if not _table_exists(conn, "trmain"):
        return
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT domain, MAX(COALESCE(resolvedip, '')) AS ip
            FROM trmain
            WHERE domain IS NOT NULL AND domain <> ''
            GROUP BY domain
        """)
        for domain, ip in cur.fetchall():
            telemetry.traceroute_targets.append((domain, ip or ""))
            if not ip:
                # Mark matching monitored URL.
                dl = domain.lower()
                for u in telemetry.monitored_urls:
                    if u.host.lower() == dl:
                        u.has_unresolved_ip = True
    except sqlite3.DatabaseError as e:
        telemetry.diagnostics.append(f"traceroute: {e}")


def _extract_device_events(
    conn: sqlite3.Connection, telemetry: ZdxTelemetry,
) -> None:
    """Event name counts + recent failure-flavored events."""
    if not _table_exists(conn, "EVENTS"):
        return
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT EVENT_NAME, COUNT(*)
            FROM EVENTS
            GROUP BY EVENT_NAME
            ORDER BY COUNT(*) DESC
        """)
        for name, n in cur.fetchall():
            if name:
                telemetry.device_event_counts[name] = n
        # Recent failure-flavored events for surfacing in the UI.
        cur.execute("""
            SELECT EVENT_TIME, EVENT_NAME, EVENT_CATEGORY, EVENT_MODULE,
                   ZEVENT_METRICS
            FROM EVENTS
            WHERE EVENT_NAME LIKE '%fail%' OR EVENT_NAME LIKE '%error%'
               OR EVENT_NAME LIKE '%stopped%'
               OR EVENT_NAME LIKE '%uninstall%'
               OR EVENT_NAME LIKE '%denied%' OR EVENT_NAME LIKE '%crash%'
               OR EVENT_NAME LIKE '%dropped%'
            ORDER BY EVENT_TIME DESC
            LIMIT 100
        """)
        for ts_ms, name, cat, mod, metrics in cur.fetchall():
            telemetry.device_events_recent.append(DeviceEvent(
                ts=_ms_to_dt(ts_ms),
                name=name or "",
                category=cat or 0,
                module=mod or 0,
                metrics_json=metrics if isinstance(metrics, str) else None,
            ))
    except sqlite3.DatabaseError as e:
        telemetry.diagnostics.append(f"device_events: {e}")


# Time-series specs: (metric_name, table, column, threshold_or_None)
_TS_SPECS = (
    ("memory_pct_used",      "tbl_memory_usage", "pct_used", 85.0),
    ("cpu_pct_total",        "tbl_cpu_usage",    "pct_total", 80.0),
    ("battery_level_pct",    "tbl_battery_status", "level_pct", None),
    ("disk_pct_used",        "tbl_disk_io",      "pct_used", 90.0),
)


def _extract_device_stats(
    conn: sqlite3.Connection, telemetry: ZdxTelemetry,
) -> None:
    cur = conn.cursor()
    for metric_name, table, col, threshold in _TS_SPECS:
        if not _table_exists(conn, table):
            continue
        try:
            cur.execute(f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL")
            vals: List[float] = []
            for r in cur.fetchall():
                try:
                    vals.append(float(r[0]))
                except (TypeError, ValueError):
                    continue
            if not vals:
                continue
            vals.sort()
            ts = TimeSeriesStats(
                metric=metric_name, samples=len(vals),
                min=vals[0], max=vals[-1],
                mean=sum(vals) / len(vals),
                p50=_percentile(vals, 50),
                p95=_percentile(vals, 95),
            )
            if threshold is not None:
                ts.threshold_value = threshold
                ts.threshold_count = sum(1 for v in vals if v >= threshold)
                ts.threshold_pct = (
                    100.0 * ts.threshold_count / len(vals)
                    if vals else None
                )
            telemetry.time_series[metric_name] = ts
        except sqlite3.DatabaseError as e:
            telemetry.diagnostics.append(
                f"device_stats {metric_name}: {e}"
            )

    if _table_exists(conn, "tbl_mon_processes"):
        try:
            cur.execute("""
                SELECT name, AVG(cpu_total_pct), MAX(cpu_total_pct),
                       COUNT(*)
                FROM tbl_mon_processes
                WHERE cpu_total_pct IS NOT NULL AND name IS NOT NULL
                GROUP BY name
                ORDER BY AVG(cpu_total_pct) DESC
                LIMIT 15
            """)
            for name, avg_cpu, max_cpu, _ in cur.fetchall():
                try:
                    telemetry.process_top_cpu.append((
                        name or "?",
                        float(avg_cpu or 0),
                        float(max_cpu or 0),
                    ))
                except (TypeError, ValueError):
                    continue
        except sqlite3.DatabaseError as e:
            telemetry.diagnostics.append(f"mon_processes: {e}")


def _extract_inventory(
    conn: sqlite3.Connection, telemetry: ZdxTelemetry,
) -> None:
    cur = conn.cursor()
    if _table_exists(conn, "tbl_last_snapshot"):
        try:
            cur.execute("""
                SELECT name, version, publisher, install_date, source
                FROM tbl_last_snapshot
                WHERE name IS NOT NULL AND name <> ''
                ORDER BY name
            """)
            for name, ver, pub, idate, src in cur.fetchall():
                telemetry.inventory_apps.append(InstalledApp(
                    name=name, version=ver or "",
                    publisher=pub or "",
                    install_date=idate or None,
                    source=src or "",
                ))
        except sqlite3.DatabaseError as e:
            telemetry.diagnostics.append(f"inventory snapshot: {e}")

    for table, kind, target in (
        ("tbl_installations", "install",
         telemetry.inventory_recent_installs),
        ("tbl_uninstallations", "uninstall",
         telemetry.inventory_recent_uninstalls),
    ):
        if not _table_exists(conn, table):
            continue
        try:
            cur.execute(f"""
                SELECT timestamp, name, version, publisher
                FROM {table}
                ORDER BY timestamp DESC
                LIMIT 25
            """)
            for ts_ms, name, ver, pub in cur.fetchall():
                target.append(InventoryEvent(
                    ts=_ms_to_dt(ts_ms), kind=kind,
                    name=name or "", version=ver or "",
                    publisher=pub or "",
                ))
        except sqlite3.DatabaseError as e:
            telemetry.diagnostics.append(f"inventory {table}: {e}")


def _extract_upload_stats(
    conn: sqlite3.Connection, telemetry: ZdxTelemetry,
) -> None:
    """ZDX cloud-upload count + failure count from
    upm_upload_stats.upload_data."""
    if not _table_exists(conn, "upload_data"):
        return
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN status <> 1 THEN 1 ELSE 0 END)
            FROM upload_data
        """)
        n, fails = cur.fetchone()
        telemetry.upload_count = n or 0
        telemetry.upload_failure_count = fails or 0
    except sqlite3.DatabaseError as e:
        telemetry.diagnostics.append(f"upload_stats: {e}")


_HANDLERS = {
    "webload": _extract_webload,
    "traceroute": _extract_traceroute,
    "device_events": _extract_device_events,
    "device_stats": _extract_device_stats,
    "device_inventory": _extract_inventory,
    "upload_stats": _extract_upload_stats,
}

# Process order — webload must run before traceroute so traceroute can
# mark monitored URLs whose host failed to resolve.
_HANDLER_ORDER = (
    "webload", "traceroute", "device_events", "device_stats",
    "device_inventory", "upload_stats",
)


# --------------------------------------------------------------------
# Public entry
# --------------------------------------------------------------------


def extract_zdx_telemetry(log_dir: Path) -> ZdxTelemetry:
    """Walk every ``upm_*.db`` under ``log_dir`` and return a
    ``ZdxTelemetry``. Defensive: any single DB failing leaves the
    rest intact and records a diagnostic."""
    telemetry = ZdxTelemetry()
    dbs = _find_upm_dbs(Path(log_dir))
    if not dbs:
        return telemetry

    for kind in _HANDLER_ORDER:
        if kind not in dbs:
            continue
        conn = _safe_open(dbs[kind])
        if conn is None:
            telemetry.diagnostics.append(f"{kind}: could not open DB")
            continue
        try:
            _HANDLERS[kind](conn, telemetry)
        except Exception as e:
            telemetry.diagnostics.append(
                f"{kind} handler exception: {e}"
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return telemetry


def find_log_subdir(bundle) -> Optional[Path]:
    """Locate the bundle's ``log-<hash>/`` subdirectory. ZCC writes
    the SQLite DBs (and per-bundle event/event-log XML) there, not
    at the bundle root."""
    for p in getattr(bundle, "files", []):
        # Each file's parent is the dir we want when the parent name
        # starts with "log-".
        parent = p.parent
        if parent.name.startswith("log-"):
            return parent
    # Fall back: walk bundle.root if available.
    root = getattr(bundle, "root", None)
    if root is None:
        return None
    try:
        for entry in os.listdir(root):
            if entry.startswith("log-") and os.path.isdir(
                os.path.join(root, entry)
            ):
                return Path(root) / entry
    except OSError:
        pass
    return None


def extract_from_bundle(bundle) -> ZdxTelemetry:
    """Convenience wrapper: locate the bundle's ``log-<hash>/``
    directory and run the extractor against it. Returns an empty
    ZdxTelemetry if the directory can't be located."""
    log_dir = find_log_subdir(bundle)
    if log_dir is None:
        return ZdxTelemetry()
    return extract_zdx_telemetry(log_dir)
