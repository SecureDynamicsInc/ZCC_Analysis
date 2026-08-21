"""Bundle config + artifact snapshots — Slice 5 (2026-08-07).

Compose the surviving extractors (policy_extract, posture_extract,
pcap_review, zdx_db_extract) into a single `BundleSnapshots`
dataclass so the UI + CLI can render "everything the parser and
extractors know about this bundle's config and non-log artifacts"
without each caller redoing the wiring.

Design contract:
    * Every section is best-effort. If an extractor raises, we
      capture the message in `extract_errors` and press on with an
      empty section.
    * Zero interpretation. We return raw dicts / lists as the
      extractors emit them.
    * PCAPs and UPM DBs are inventoried (metadata only) — actual
      analysis is deferred to Slice 5's future PCAP time-slicing
      button.

Pure library — no streamlit deps. CLI-shared.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .bundle import ExtractedBundle
from .log_index import LogIndex

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# BundleSnapshots dataclass
# --------------------------------------------------------------------------

@dataclass
class PcapEntry:
    """One row in the PCAP inventory. Metadata only — no packet-level
    analysis is materialised in the snapshot itself."""
    path: str
    filename: str
    size_bytes: int
    packet_count: int
    ts_first: Optional[datetime]
    ts_last: Optional[datetime]
    duration_seconds: Optional[float]
    top_dns: List[str] = field(default_factory=list)
    top_sni: List[str] = field(default_factory=list)
    top_dest_ips: List[str] = field(default_factory=list)


@dataclass
class UpmDbEntry:
    """One row in the UPM SQLite inventory."""
    path: str
    filename: str
    size_bytes: int
    tables: Dict[str, int] = field(default_factory=dict)  # table -> row count


@dataclass
class NonLogArtifact:
    """One row in the "other files" inventory (XML, GPO reports, etc.)."""
    path: str
    filename: str
    size_bytes: int


@dataclass
class BundleSnapshots:
    """The composite view: config snapshots + non-log artifact inventories."""

    # ---- Config snapshots (best-effort) ----
    app_profile: Dict[str, Any] = field(default_factory=dict)
    profile_details: Dict[str, Any] = field(default_factory=dict)
    posture_profiles: List[Dict[str, Any]] = field(default_factory=list)
    trust_conditions: List[Dict[str, Any]] = field(default_factory=list)
    configured_bypass: Dict[str, Any] = field(default_factory=dict)
    session_info: Dict[str, Any] = field(default_factory=dict)

    # ---- Non-log artifact inventories ----
    pcaps: List[PcapEntry] = field(default_factory=list)
    upm_dbs: List[UpmDbEntry] = field(default_factory=list)
    xml_events: List[NonLogArtifact] = field(default_factory=list)
    other_files: List[NonLogArtifact] = field(default_factory=list)

    # ---- Diagnostics ----
    extract_errors: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Best-effort wrappers around each extractor
# --------------------------------------------------------------------------

def _try_app_profile(bundle: ExtractedBundle,
                     errors: List[str]) -> Dict[str, Any]:
    try:
        from .policy_extract import extract_app_profile
        return extract_app_profile(bundle) or {}
    except Exception as e:  # noqa: BLE001
        errors.append(f"app_profile: {e.__class__.__name__}: {e}")
        return {}


def _try_profile_details(bundle: ExtractedBundle,
                         os_family: Optional[str],
                         errors: List[str]) -> Dict[str, Any]:
    try:
        from .policy_extract import extract_profile_details
        return extract_profile_details(bundle, os_family=os_family) or {}
    except Exception as e:  # noqa: BLE001
        errors.append(f"profile_details: {e.__class__.__name__}: {e}")
        return {}


def _try_posture(bundle: ExtractedBundle,
                 errors: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Return {'profiles': [...], 'trust_conditions': [...]} as plain
    dicts (dataclasses converted). Never raises.

    Reads `PostureExtraction` against its real shape. Two mismatches
    used to make this return empty lists on every bundle — the same
    pair that broke `facts_extract._best_effort_posture`:

      * `.profiles` is a **Dict[udid, PostureProfile]**. Iterating it
        yields udid *strings*, and `_dataclass_to_dict(str)` produced
        junk rather than a profile row.
      * The field is `.trust_condition` (**singular**) — one object
        holding `or_groups` — not `.trust_conditions`. The plural
        lookup always fell through to `[]`.

    Trust conditions are flattened one row per condition (with its OR
    group index) because that's what renders usefully in a table; the
    nested OR/AND structure is preserved via the `or_group` column.
    """
    try:
        from .posture_extract import extract_posture
        result = extract_posture(bundle)
        if result is None:
            return {"profiles": [], "trust_conditions": []}

        # ---- Profiles: iterate dict VALUES ----
        profiles: List[Dict[str, Any]] = []
        raw_profiles = getattr(result, "profiles", None) or {}
        values = (raw_profiles.values()
                  if isinstance(raw_profiles, dict) else raw_profiles)
        for prof in values:
            profiles.append(_dataclass_to_dict(prof))

        # ---- Trust condition: flatten the singular object ----
        conds: List[Dict[str, Any]] = []
        tc = getattr(result, "trust_condition", None)
        if tc is not None:
            for gi, group in enumerate(getattr(tc, "or_groups", None) or []):
                for cond in group or []:
                    if isinstance(cond, dict):
                        conds.append({
                            "or_group": gi,
                            "id": cond.get("id"),
                            "name": cond.get("name"),
                            "udid": cond.get("udid"),
                        })
                    else:
                        conds.append({"or_group": gi,
                                      **_dataclass_to_dict(cond)})

        return {"profiles": profiles, "trust_conditions": conds}
    except Exception as e:  # noqa: BLE001
        errors.append(f"posture: {e.__class__.__name__}: {e}")
        return {"profiles": [], "trust_conditions": []}


def _try_bypass(log_index: LogIndex,
                errors: List[str]) -> Dict[str, Any]:
    try:
        from .policy_extract import extract_configured_bypass_csv_from_index
        return extract_configured_bypass_csv_from_index(log_index) or {}
    except Exception as e:  # noqa: BLE001
        errors.append(f"configured_bypass: {e.__class__.__name__}: {e}")
        return {}


def _try_session_info(bundle: ExtractedBundle,
                      errors: List[str]) -> Dict[str, Any]:
    try:
        from .policy_extract import extract_session_info
        return extract_session_info(bundle) or {}
    except Exception as e:  # noqa: BLE001
        errors.append(f"session_info: {e.__class__.__name__}: {e}")
        return {}


def _try_pcap_inventory(bundle: ExtractedBundle,
                        errors: List[str]) -> List[PcapEntry]:
    try:
        from .pcap_review import scan_bundle
        summaries = scan_bundle(bundle.root) or []
    except Exception as e:  # noqa: BLE001
        errors.append(f"pcap_scan: {e.__class__.__name__}: {e}")
        return []

    out: List[PcapEntry] = []
    for s in summaries:
        try:
            path = Path(getattr(s, "path", ""))
            size = 0
            if path.is_file():
                try:
                    size = path.stat().st_size
                except OSError:
                    pass
            dur = None
            first = getattr(s, "ts_first", None)
            last = getattr(s, "ts_last", None)
            if first and last:
                dur = (last - first).total_seconds()
            top_dns = _top_n(getattr(s, "dns_queries", {}) or {}, 10)
            top_sni = _top_n(getattr(s, "sni_hosts", {}) or {}, 10)
            top_ips = _top_n(getattr(s, "dest_ips", {}) or {}, 10)
            out.append(PcapEntry(
                path=str(path),
                filename=path.name,
                size_bytes=size,
                packet_count=getattr(s, "total_packets", 0) or 0,
                ts_first=first, ts_last=last,
                duration_seconds=dur,
                top_dns=top_dns, top_sni=top_sni,
                top_dest_ips=top_ips,
            ))
        except Exception as e:  # noqa: BLE001
            errors.append(f"pcap_entry: {e.__class__.__name__}: {e}")
    return out


def _try_upm_inventory(bundle: ExtractedBundle,
                       errors: List[str]) -> List[UpmDbEntry]:
    """Scan for SQLite files under the bundle. We DON'T call
    zdx_db_extract's full extractor (that's a data pull, not an
    inventory) — instead we just list the .db files and enumerate their
    tables + row counts."""
    out: List[UpmDbEntry] = []
    try:
        import sqlite3
    except Exception as e:  # noqa: BLE001
        errors.append(f"sqlite3 unavailable: {e.__class__.__name__}: {e}")
        return []

    for p in Path(bundle.root).rglob("*.db"):
        if not p.is_file():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        tables: Dict[str, int] = {}
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=1.0)
            try:
                cur = con.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' ORDER BY name"
                )
                table_names = [r[0] for r in cur.fetchall()]
                for tn in table_names:
                    try:
                        cur = con.execute(f'SELECT COUNT(*) FROM "{tn}"')
                        (n,) = cur.fetchone()
                        tables[tn] = int(n)
                    except Exception:  # noqa: BLE001
                        tables[tn] = -1
            finally:
                con.close()
        except Exception as e:  # noqa: BLE001
            errors.append(f"upm[{p.name}]: {e.__class__.__name__}: {e}")
        out.append(UpmDbEntry(
            path=str(p), filename=p.name,
            size_bytes=size, tables=tables,
        ))
    return out


def _try_xml_inventory(bundle: ExtractedBundle,
                       errors: List[str]) -> List[NonLogArtifact]:
    return _list_by_glob(bundle, "*.xml", errors)


def _try_other_inventory(bundle: ExtractedBundle,
                         errors: List[str]) -> List[NonLogArtifact]:
    """Return every extension we DON'T already cover elsewhere. Small
    catch-all so the operator can see what's in the bundle."""
    out: List[NonLogArtifact] = []
    skip_ext = {".log", ".pcapng", ".xml", ".db"}
    for p in Path(bundle.root).rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in skip_ext:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        out.append(NonLogArtifact(
            path=str(p), filename=p.name, size_bytes=size,
        ))
    out.sort(key=lambda a: a.filename)
    return out


def _list_by_glob(bundle: ExtractedBundle,
                  pattern: str,
                  errors: List[str]) -> List[NonLogArtifact]:
    out: List[NonLogArtifact] = []
    try:
        for p in Path(bundle.root).rglob(pattern):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            out.append(NonLogArtifact(
                path=str(p), filename=p.name, size_bytes=size,
            ))
        out.sort(key=lambda a: a.filename)
    except Exception as e:  # noqa: BLE001
        errors.append(f"glob[{pattern}]: {e.__class__.__name__}: {e}")
    return out


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _dataclass_to_dict(obj: Any) -> Dict[str, Any]:
    """Convert a dataclass instance to a plain dict, best-effort. Falls
    back to reading __dict__ or vars()."""
    try:
        from dataclasses import asdict, is_dataclass
        if is_dataclass(obj):
            return asdict(obj)
    except Exception:  # noqa: BLE001
        pass
    try:
        return dict(vars(obj))
    except Exception:  # noqa: BLE001
        return {"repr": repr(obj)}


def _top_n(d: Dict[str, int], n: int) -> List[str]:
    """Return the top-N keys of a count dict formatted as '<count> <key>'."""
    items = sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))
    return [f"{v} {k}" for k, v in items[:n]]


# --------------------------------------------------------------------------
# Orchestrator entry point
# --------------------------------------------------------------------------

def build_snapshots(bundle: ExtractedBundle,
                    log_index: LogIndex,
                    os_family: Optional[str] = None) -> BundleSnapshots:
    """Compose every best-effort extractor into a BundleSnapshots.
    Never raises — everything problematic ends up in `extract_errors`."""
    errors: List[str] = []
    app_profile = _try_app_profile(bundle, errors)
    profile_details = _try_profile_details(bundle, os_family, errors)
    posture = _try_posture(bundle, errors)
    bypass = _try_bypass(log_index, errors)
    session_info = _try_session_info(bundle, errors)
    pcaps = _try_pcap_inventory(bundle, errors)
    upm_dbs = _try_upm_inventory(bundle, errors)
    xml_events = _try_xml_inventory(bundle, errors)
    other = _try_other_inventory(bundle, errors)

    return BundleSnapshots(
        app_profile=app_profile,
        profile_details=profile_details,
        posture_profiles=posture["profiles"],
        trust_conditions=posture["trust_conditions"],
        configured_bypass=bypass,
        session_info=session_info,
        pcaps=pcaps,
        upm_dbs=upm_dbs,
        xml_events=xml_events,
        other_files=other,
        extract_errors=errors,
    )
