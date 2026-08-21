"""Facts extractor — Slice 1 of the Log-Analyzer rebuild (2026-08-07).

Fold an ExtractedBundle + LogIndex into a `FactsSnapshot` — pure aggregate
facts, zero interpretation. This is what powers the Facts view.

Design contract:
    * Every field must be a directly-verifiable count / distinct set /
      config value pulled from the log evidence.
    * If extraction of a best-effort field fails, we set it to None (or
      an empty list / dict) and press on. The Facts view is never
      allowed to crash on a real bundle.
    * No detectors, no findings, no severity, no ranking, no
      interpretation of what any of these numbers mean.

The `derive_facts()` orchestrator is the single entry point.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .bundle import ExtractedBundle
from .log_index import LogIndex

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Snapshot dataclass
# --------------------------------------------------------------------------

@dataclass
class FactsSnapshot:
    """Pure aggregate facts about one parsed bundle. No interpretation."""

    # ---- Bundle metadata --------------------------------------------
    bundle_name: str
    bundle_bytes: int
    bundle_file_count: int          # every extracted file, any type
    bundle_log_file_count: int      # .log files only

    # ---- Parse stats ------------------------------------------------
    total_lines: int
    bytes_scanned: int
    lines_skipped_unparseable: int
    files_scanned: int

    # ---- Time / TZ --------------------------------------------------
    first_ts: Optional[datetime]
    last_ts: Optional[datetime]
    duration_seconds: Optional[float]
    bundle_tz_offset: Optional[str]      # e.g. "-0600"
    bundle_tz_label: Optional[str]       # e.g. "UTC-06:00"

    # ---- Per-axis line counts ---------------------------------------
    lines_by_component: Dict[str, int] = field(default_factory=dict)
    lines_by_level: Dict[str, int] = field(default_factory=dict)
    lines_by_source_file: Dict[str, int] = field(default_factory=dict)

    # ---- Distinct sets (sorted) -------------------------------------
    distinct_pids: List[str] = field(default_factory=list)
    distinct_components: List[str] = field(default_factory=list)
    distinct_source_files: List[str] = field(default_factory=list)
    distinct_session_ids: List[str] = field(default_factory=list)
    distinct_hosts: List[str] = field(default_factory=list)

    # ---- Bundle config snapshots (best-effort) ----------------------
    app_profile: Dict[str, Any] = field(default_factory=dict)
    app_profile_source: Optional[str] = None      # path we pulled it from
    posture_profile_names: List[str] = field(default_factory=list)
    trust_condition_names: List[str] = field(default_factory=list)

    # ---- Identity (best-effort) -------------------------------------
    user_login: Optional[str] = None
    user_hostname: Optional[str] = None
    zcc_version: Optional[str] = None
    os_family: Optional[str] = None  # "windows" | "macos" | "linux" | ...

    # ---- Extraction diagnostics -------------------------------------
    extract_errors: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _tally_lines(idx: LogIndex) -> Dict[str, Dict[str, int]]:
    """Group IndexedLine counts by component, level, and source_file."""
    by_component: Counter = Counter()
    by_level: Counter = Counter()
    by_source_file: Counter = Counter()
    for ln in idx.lines:
        if ln.component:
            by_component[ln.component] += 1
        if ln.level:
            by_level[ln.level] += 1
        by_source_file[ln.source_file] += 1
    return {
        "component": dict(by_component),
        "level": dict(by_level),
        "source_file": dict(by_source_file),
    }


def _distinct_sets(idx: LogIndex) -> Dict[str, List[str]]:
    pids: set = set()
    components: set = set()
    files: set = set()
    sessions: set = set()
    hosts: set = set()
    for ln in idx.lines:
        if ln.pid:
            pids.add(ln.pid)
        if ln.component:
            components.add(ln.component)
        if ln.source_file:
            files.add(ln.source_file)
        if ln.session_id:
            sessions.add(ln.session_id)
        if ln.host:
            hosts.add(ln.host)
    return {
        "pids": sorted(pids),
        "components": sorted(components),
        "source_files": sorted(files),
        "session_ids": sorted(sessions),
        "hosts": sorted(hosts),
    }


def _infer_os_family(bundle: ExtractedBundle) -> Optional[str]:
    """Use the evidence-ranked OS detector, then a narrow filename fallback.

    ``ZSATray_*`` is not a safe macOS discriminator: current Windows bundles
    can carry it beside ``ZSATrayManager_*``. The old two-flag heuristic called
    those bundles ``mixed`` even when AppInfo.xml explicitly said Windows.
    """
    try:
        from .os_detect import detect_os
        detected = detect_os(bundle)
        if detected.os_family != "unknown":
            return detected.os_family
    except Exception:  # noqa: BLE001 - Facts remains best-effort
        pass

    windows_marker = False
    macos_marker = False
    for p in bundle.files:
        name = p.name
        # Windows: ZSATrayManager_*, ZSATunnel_*, ZSAUpm_*
        if name.startswith("ZSATrayManager") or "TRPTunnel" in name:
            windows_marker = True
        # macOS launchd/service names are platform-specific. A bare
        # ZSATray_* name is intentionally not enough evidence.
        if name.startswith("com.zscaler."):
            macos_marker = True
    if windows_marker and not macos_marker:
        return "windows"
    if macos_marker and not windows_marker:
        return "macos"
    if windows_marker and macos_marker:
        return "mixed"
    return None


def _best_effort_app_profile(bundle: ExtractedBundle,
                             errors: List[str]) -> Dict[str, Any]:
    """Try policy_extract.extract_app_profile. Never raise."""
    try:
        from .policy_extract import extract_app_profile
        return extract_app_profile(bundle) or {}
    except Exception as e:  # noqa: BLE001
        errors.append(f"app_profile: {e.__class__.__name__}: {e}")
        return {}


def _best_effort_posture(bundle: ExtractedBundle,
                         errors: List[str]) -> Dict[str, List[str]]:
    """Try posture_extract.extract_posture. Never raise. Returns a dict
    with 'profile_names' and 'trust_condition_names' — flat name lists,
    no config interpretation.

    Two shape bugs used to make this return empty lists on every bundle,
    which is why the UI read "Posture profiles (0) / Trust conditions
    (0)" on bundles that plainly contained both:

      1. `PostureExtraction.profiles` is a **Dict[udid, PostureProfile]**,
         not a list. Iterating it yields the udid *strings*, so
         `getattr(prof, "name", None)` was called on a str and always
         returned None.
      2. The field is `trust_condition` (**singular**, one object with
         `or_groups`), not `trust_conditions`. `getattr(...,
         "trust_conditions", [])` therefore always fell through to the
         default `[]`.

    Both are now read against the real dataclass shape.
    """
    try:
        from .posture_extract import extract_posture
        result = extract_posture(bundle)
        if result is None:
            return {"profile_names": [], "trust_condition_names": []}

        # ---- Posture profiles: dict VALUES carry the objects ----
        profile_names: List[str] = []
        profiles = getattr(result, "profiles", None) or {}
        values = profiles.values() if isinstance(profiles, dict) else profiles
        for prof in values:
            name = getattr(prof, "name", None)
            if name:
                profile_names.append(str(name))

        # ---- Trust condition: singular object holding OR/AND groups ----
        trust_names: List[str] = []
        tc = getattr(result, "trust_condition", None)
        if tc is not None:
            for group in getattr(tc, "or_groups", None) or []:
                for cond in group or []:
                    if isinstance(cond, dict):
                        name = cond.get("name")
                    else:
                        name = getattr(cond, "name", None)
                    if name:
                        trust_names.append(str(name))

        return {
            "profile_names": sorted(set(profile_names)),
            "trust_condition_names": sorted(set(trust_names)),
        }
    except Exception as e:  # noqa: BLE001
        errors.append(f"posture: {e.__class__.__name__}: {e}")
        return {"profile_names": [], "trust_condition_names": []}


def _pluck_identity(app_profile: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Pull login / hostname / ZCC version out of an app_profile dict.
    Trusts what's there; returns None for anything absent.

    Key naming matters here and got this wrong for a while:
    `policy_extract.extract_app_profile()` does NOT return the raw
    TrayPolicy JSON keys — it maps them through `_POLICY_FIELDS` and
    returns **human labels** ("Login name", "MA host", "ZIA cloud").
    Looking up `loginName` / `hostName` / `clientVersion` therefore
    always missed, and these three fields were permanently None no
    matter what the bundle contained.

    Both spellings are now tried: the label first (what the extractor
    actually emits), then the raw key as a fallback in case a caller
    hands us an unmapped blob.
    """
    if not app_profile:
        return {"user_login": None, "user_hostname": None, "zcc_version": None}

    def _first(*keys):
        for k in keys:
            v = app_profile.get(k)
            if v not in (None, ""):
                return v
        return None

    login = _first("Login name", "loginName", "login_name",
                   "userName", "upn")
    host = _first("Device hostname", "hostName", "hostname",
                  "computerName", "host_name")
    ver = _first("ZCC version", "clientVersion", "appVersion",
                 "zccVersion", "ZCCVersion")
    # Treat sanitised placeholders as missing (feedback_treat_sanitized_loginName)
    def _clean(v):
        if v is None:
            return None
        s = str(v).strip()
        if not s or s in {"###", "null", "None"}:
            return None
        return s
    return {
        "user_login": _clean(login),
        "user_hostname": _clean(host),
        "zcc_version": _clean(ver),
    }


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def derive_facts(bundle: ExtractedBundle,
                 idx: LogIndex) -> FactsSnapshot:
    """Assemble a FactsSnapshot from an ExtractedBundle + already-built
    LogIndex. Best-effort on config extraction; parse counts are exact.
    """
    errors: List[str] = []

    # ---- Line counts / distinct sets ----
    tallies = _tally_lines(idx)
    distincts = _distinct_sets(idx)

    lines = idx.lines
    first_ts = lines[0].ts if lines else None
    last_ts = lines[-1].ts if lines else None
    duration = None
    if first_ts is not None and last_ts is not None:
        duration = (last_ts - first_ts).total_seconds()

    # ---- Bundle metadata ----
    bundle_bytes = 0
    log_file_count = 0
    for p in bundle.files:
        try:
            bundle_bytes += p.stat().st_size
        except OSError:
            pass
        if p.suffix == ".log":
            log_file_count += 1

    # ---- Config snapshots (best-effort) ----
    app_profile = _best_effort_app_profile(bundle, errors)
    posture = _best_effort_posture(bundle, errors)
    identity = _pluck_identity(app_profile)
    os_family = _infer_os_family(bundle)

    return FactsSnapshot(
        bundle_name=bundle.source_zip.name if bundle.source_zip else "(unknown)",
        bundle_bytes=bundle_bytes,
        bundle_file_count=len(bundle.files),
        bundle_log_file_count=log_file_count,
        total_lines=len(lines),
        bytes_scanned=idx.bytes_scanned,
        lines_skipped_unparseable=idx.lines_skipped_unparseable,
        files_scanned=idx.files_scanned,
        first_ts=first_ts,
        last_ts=last_ts,
        duration_seconds=duration,
        bundle_tz_offset=idx.bundle_tz_offset,
        bundle_tz_label=idx.bundle_tz_label,
        lines_by_component=tallies["component"],
        lines_by_level=tallies["level"],
        lines_by_source_file=tallies["source_file"],
        distinct_pids=distincts["pids"],
        distinct_components=distincts["components"],
        distinct_source_files=distincts["source_files"],
        distinct_session_ids=distincts["session_ids"],
        distinct_hosts=distincts["hosts"],
        app_profile=app_profile,
        app_profile_source=None,  # policy_extract doesn't currently expose this
        posture_profile_names=posture["profile_names"],
        trust_condition_names=posture["trust_condition_names"],
        user_login=identity["user_login"],
        user_hostname=identity["user_hostname"],
        zcc_version=identity["zcc_version"],
        os_family=os_family,
        extract_errors=errors,
    )
