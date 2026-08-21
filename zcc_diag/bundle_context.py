"""
Typed view over BundleSummary.bundle_meta (Phase 43e, 2026-06-24).

Phase 43's Critical-1 finding: ``BundleSummary.bundle_meta`` is a
``Dict[str, Any]`` with 40+ string keys written across the codebase.
Reading a misspelled key silently returns None and the UI shows a
blank section. Adding a key requires hunting through extractors,
detectors, the multiplexer, and the UI to find all the writers/readers.

BundleContext is a backwards-compatible typed view:

  * **Existing writers keep working.** ``summary.bundle_meta["zdx_telemetry"] = x``
    still does what it always did. No mass migration needed.

  * **New readers can be typed.** ``summary.context.zdx_telemetry``
    returns the same data but via a documented, schema-pinned property.
    Misspell ``zdx_telmetry`` → AttributeError (loud) instead of
    silent None.

  * **Schema discoverability.** The full list of bundle_meta keys is
    documented in one place — this module. Adding a new key is a one-
    line property addition + a comment about when it's populated.

Migration plan (incremental, low risk):
  1. ✅ Phase 43e: define this class + add ``summary.context`` lazy property.
  2. New writers prefer ``ctx.field = ...`` over ``bundle_meta["field"] = ...``
     where they're already touching that callsite.
  3. New readers prefer ``ctx.field`` over ``bundle_meta.get("field")``.
  4. Eventually: deprecation pass to remove the raw dict access. Not
     forced — bundle_meta stays as the underlying storage indefinitely.

The class uses descriptor-like ``@property`` for each known key so
auto-complete works and unknown keys raise AttributeError on read.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from .summary import BundleSummary


# Sentinel for the "no default given" case — distinct from None which
# is a valid stored value for some keys (e.g., zdx_enrolled).
_UNSET = object()


class BundleContext:
    """Typed accessor over ``BundleSummary.bundle_meta``.

    Instantiate via ``BundleSummary.context`` (lazy property). The
    instance holds a weak reference to its summary and reads/writes
    pass through to ``summary.bundle_meta``. No data duplication.
    """

    __slots__ = ("_summary",)

    def __init__(self, summary: "BundleSummary"):
        self._summary = summary

    # ------------------------------------------------------------------
    # Raw escape hatch
    # ------------------------------------------------------------------

    @property
    def _meta(self) -> Dict[str, Any]:
        """Direct access to the underlying dict — for the rare case where
        a key isn't yet documented as a typed property. Prefer adding
        the typed property over using this."""
        return self._summary.bundle_meta

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-style fallback. Equivalent to ``bundle_meta.get(key, default)``.
        Use only when the property name isn't known statically (rare)."""
        return self._summary.bundle_meta.get(key, default)

    def has(self, key: str) -> bool:
        return key in self._summary.bundle_meta

    # ------------------------------------------------------------------
    # ZDX — Phase 42a extractor output + ZTraceroute/Webload
    # ------------------------------------------------------------------

    @property
    def zdx_telemetry(self) -> Optional[Any]:
        """ZdxTelemetry dataclass — memory time series, device events,
        monitored URLs. Populated by ``zdx_db_extract.extract_from_bundle``
        in two paths:
          - pre-detector (so detectors can read it in their feed())
          - policy snapshot (so the UI can render the ZDX section)
        Either path may have failed; check ``.context.has('zdx_telemetry')``."""
        return self._meta.get("zdx_telemetry")

    @zdx_telemetry.setter
    def zdx_telemetry(self, value: Any) -> None:
        self._meta["zdx_telemetry"] = value

    @property
    def ztraceroute_traces(self) -> List[Any]:
        """List of parsed ZTraceroute records (slowness diagnostic).
        Empty if no ztraceroute file in the bundle (typically because
        Diagnostic Route Collection isn't enabled in the App Profile)."""
        return self._meta.get("ztraceroute_traces") or []

    @ztraceroute_traces.setter
    def ztraceroute_traces(self, value: List[Any]) -> None:
        self._meta["ztraceroute_traces"] = value

    @property
    def ztraceroute_health(self) -> Optional[Any]:
        """Aggregate trace health (per-hop loss/latency summary)."""
        return self._meta.get("ztraceroute_health")

    @ztraceroute_health.setter
    def ztraceroute_health(self, value: Any) -> None:
        self._meta["ztraceroute_health"] = value

    @property
    def zdx_webloads(self) -> List[Any]:
        """Parsed ZDX webload measurements."""
        return self._meta.get("zdx_webloads") or []

    @zdx_webloads.setter
    def zdx_webloads(self, value: List[Any]) -> None:
        self._meta["zdx_webloads"] = value

    @property
    def has_ztraceroute_file(self) -> bool:
        return bool(self._meta.get("has_ztraceroute_file"))

    @has_ztraceroute_file.setter
    def has_ztraceroute_file(self, value: bool) -> None:
        self._meta["has_ztraceroute_file"] = bool(value)

    @property
    def app_health(self) -> Optional[Any]:
        """ZDX per-app health summary."""
        return self._meta.get("app_health")

    @app_health.setter
    def app_health(self, value: Any) -> None:
        self._meta["app_health"] = value

    @property
    def edge_probes(self) -> Optional[Any]:
        """ZDX edge-probe (service-edge reachability) summary."""
        return self._meta.get("edge_probes")

    @edge_probes.setter
    def edge_probes(self, value: Any) -> None:
        self._meta["edge_probes"] = value

    # ------------------------------------------------------------------
    # ZPA — app catalog + broker info
    # ------------------------------------------------------------------

    @property
    def zpa_apps(self) -> Dict[str, Any]:
        """ZPA app catalog dict. Shape:
          {"apps": [...], "total_pushes": N, "push_windows": [...]}
        On extraction failure: same shape with empty lists/0 counts."""
        return self._meta.get("zpa_apps") or {
            "apps": [], "total_pushes": 0, "push_windows": [],
        }

    @zpa_apps.setter
    def zpa_apps(self, value: Dict[str, Any]) -> None:
        self._meta["zpa_apps"] = value

    @property
    def zpa_broker_dcs(self) -> Optional[Any]:
        """ZPA broker → datacenter mapping (extracted from broker hostnames)."""
        return self._meta.get("zpa_broker_dcs")

    @zpa_broker_dcs.setter
    def zpa_broker_dcs(self, value: Any) -> None:
        self._meta["zpa_broker_dcs"] = value

    # ------------------------------------------------------------------
    # Suite enrollment flags (sidebar gating)
    # ------------------------------------------------------------------

    @property
    def zia_enrolled(self) -> Optional[bool]:
        """Tri-state: True (enrolled), False (explicitly disabled),
        None (could not determine from this bundle)."""
        return self._meta.get("zia_enrolled")

    @zia_enrolled.setter
    def zia_enrolled(self, value: Optional[bool]) -> None:
        self._meta["zia_enrolled"] = value

    @property
    def zpa_enrolled(self) -> Optional[bool]:
        return self._meta.get("zpa_enrolled")

    @zpa_enrolled.setter
    def zpa_enrolled(self, value: Optional[bool]) -> None:
        self._meta["zpa_enrolled"] = value

    @property
    def zdx_enrolled(self) -> Optional[bool]:
        return self._meta.get("zdx_enrolled")

    @zdx_enrolled.setter
    def zdx_enrolled(self, value: Optional[bool]) -> None:
        self._meta["zdx_enrolled"] = value

    @property
    def zia_enrolled_source(self) -> Optional[str]:
        """Provenance string: which extractor/heuristic decided zia_enrolled."""
        return self._meta.get("zia_enrolled_source")

    @zia_enrolled_source.setter
    def zia_enrolled_source(self, value: Optional[str]) -> None:
        self._meta["zia_enrolled_source"] = value

    @property
    def zpa_enrolled_source(self) -> Optional[str]:
        return self._meta.get("zpa_enrolled_source")

    @zpa_enrolled_source.setter
    def zpa_enrolled_source(self, value: Optional[str]) -> None:
        self._meta["zpa_enrolled_source"] = value

    # ------------------------------------------------------------------
    # Cross-suite — extraction stats, log classification, runtime warnings
    # ------------------------------------------------------------------

    @property
    def tunnel_logs_total(self) -> int:
        return int(self._meta.get("tunnel_logs_total") or 0)

    @tunnel_logs_total.setter
    def tunnel_logs_total(self, value: int) -> None:
        self._meta["tunnel_logs_total"] = int(value)

    @property
    def tunnel_logs_scanned(self) -> int:
        return int(self._meta.get("tunnel_logs_scanned") or 0)

    @tunnel_logs_scanned.setter
    def tunnel_logs_scanned(self, value: int) -> None:
        self._meta["tunnel_logs_scanned"] = int(value)

    @property
    def tunnel_bytes_scanned(self) -> int:
        return int(self._meta.get("tunnel_bytes_scanned") or 0)

    @tunnel_bytes_scanned.setter
    def tunnel_bytes_scanned(self, value: int) -> None:
        self._meta["tunnel_bytes_scanned"] = int(value)

    @property
    def log_kinds(self) -> Dict[str, int]:
        """Counter of log-file kinds detected in the bundle.
        Keys are like 'tunnel', 'tray', 'service', 'upm', etc."""
        return self._meta.get("log_kinds") or {}

    @log_kinds.setter
    def log_kinds(self, value: Dict[str, int]) -> None:
        self._meta["log_kinds"] = value

    @property
    def sme_dc_map(self) -> Dict[str, str]:
        """Service-edge IP → DC short-name mapping."""
        return self._meta.get("sme_dc_map") or {}

    @sme_dc_map.setter
    def sme_dc_map(self, value: Dict[str, str]) -> None:
        self._meta["sme_dc_map"] = value

    @property
    def cpt_events(self) -> List[Any]:
        """Captive-portal-trigger events."""
        return self._meta.get("cpt_events") or []

    @cpt_events.setter
    def cpt_events(self, value: List[Any]) -> None:
        self._meta["cpt_events"] = value

    @property
    def extractor_warnings(self) -> List[Dict[str, Any]]:
        """Phase 43b: non-fatal extractor failures. UI surfaces these
        as a yellow banner so engineers don't ship partial RCAs without
        realizing something failed silently."""
        return self._meta.get("extractor_warnings") or []

    @extractor_warnings.setter
    def extractor_warnings(self, value: List[Dict[str, Any]]) -> None:
        self._meta["extractor_warnings"] = value

    # ------------------------------------------------------------------
    # Iteration / introspection
    # ------------------------------------------------------------------

    def keys(self) -> List[str]:
        """Every key currently stored in bundle_meta (typed + untyped)."""
        return list(self._meta.keys())

    def known_typed_keys(self) -> List[str]:
        """The keys this class knows about (has a typed property for).
        Useful for migration tooling — anything in ``keys()`` but not in
        here is candidate for promotion to a typed property."""
        return [
            "zdx_telemetry", "ztraceroute_traces", "ztraceroute_health",
            "zdx_webloads", "has_ztraceroute_file", "app_health",
            "edge_probes", "zpa_apps", "zpa_broker_dcs",
            "zia_enrolled", "zpa_enrolled", "zdx_enrolled",
            "zia_enrolled_source", "zpa_enrolled_source",
            "tunnel_logs_total", "tunnel_logs_scanned",
            "tunnel_bytes_scanned", "log_kinds", "sme_dc_map",
            "cpt_events", "extractor_warnings",
        ]

    def untyped_keys(self) -> List[str]:
        """Keys currently in bundle_meta that have no typed property.
        Useful for `pytest` regression tests that fail when a writer
        adds a new key without documenting it here."""
        typed = set(self.known_typed_keys())
        return [k for k in self._meta if k not in typed]

    def __repr__(self) -> str:
        return (
            f"BundleContext(keys={len(self._meta)} "
            f"untyped={len(self.untyped_keys())})"
        )
