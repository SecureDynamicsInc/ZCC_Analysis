"""
Intake context — user-provided ticket scope that focuses analysis on a
specific customer complaint.

Phase 60a (2026-07-10). The BundleScope wizard collects intake in three
steps (complaint / user + time-scope / bundle upload) and stores it in
Streamlit ``session_state["intake"]``. The relevance ranker
(``ui/relevance.py``) reads it to pin complaint-matching findings above
severity ordering. ``ui/analyse.py`` stores it alongside the analysis
output so the results view can render an "Analyzed under: ..." header
and offer a [Change intake] escape hatch.

Design notes:

  * **Streamlit-free**: this module does not import streamlit so it
    can be unit-tested and used from CLI paths. Session-state helpers
    accept the ``session_state`` object as a parameter — call sites
    pass ``st.session_state``.
  * **Default = legacy**: a fresh ``IntakeContext()`` has
    ``skipped=True`` and ``complaint_category=GENERAL``. That means
    the ranker falls back to severity-only ordering when the user
    hasn't filled the wizard — identical to pre-Phase-60 behavior.
    Safe rollout.
  * **JSON round-trip**: ``to_dict()`` / ``from_dict()`` serialize all
    fields (including enums as their ``.value`` strings and datetimes
    as ISO strings). Used by ``analyse()`` to persist intake alongside
    findings so re-opening the same bundle preserves the intake
    context.
  * **schema_version**: bump when the shape changes; ``from_dict()``
    reads it so future refactors can handle old blobs gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


INTAKE_SCHEMA_VERSION = 1
INTAKE_SESSION_KEY = "intake"


# --------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------


class ComplaintCategory(str, Enum):
    """The six user-facing complaint tiles in the Step-1 grid.

    Order matches the intended tile grid (top-left → bottom-right,
    left-to-right, top-to-bottom). ``GENERAL`` is the fallback tile
    and also the value used when the user skips the wizard entirely.
    """

    INTERNAL_ACCESS = "internal_access"          # tile: shared drives / apps
    WEB_SLOW_OR_BLOCKED = "web_slow_or_blocked"  # tile: website slow/blocked
    REAUTH_OR_DISCONNECT = "reauth_or_disconnect"  # tile: VPN reauth/disconnect
    FIRST_RUN_BROKEN = "first_run_broken"        # tile: new install broken
    REALTIME_PERF = "realtime_perf"              # tile: video/audio choppy
    GENERAL = "general"                          # tile: general/not sure

    @property
    def display_label(self) -> str:
        """Human-facing tile label for the Streamlit wizard."""
        return _CATEGORY_LABELS[self]

    @property
    def helper_text(self) -> str:
        """Sub-text shown under the tile label to disambiguate."""
        return _CATEGORY_HELPERS[self]


_CATEGORY_LABELS: Dict[ComplaintCategory, str] = {
    ComplaintCategory.INTERNAL_ACCESS: "Can't access internal shares or apps",
    ComplaintCategory.WEB_SLOW_OR_BLOCKED: "Website is slow or blocked",
    ComplaintCategory.REAUTH_OR_DISCONNECT: "VPN keeps disconnecting or asking to sign in",
    ComplaintCategory.FIRST_RUN_BROKEN: "New install / fresh laptop broken",
    ComplaintCategory.REALTIME_PERF: "Video or audio calls choppy",
    ComplaintCategory.GENERAL: "General / not sure",
}


_CATEGORY_HELPERS: Dict[ComplaintCategory, str] = {
    ComplaintCategory.INTERNAL_ACCESS: (
        "SMB shares (\\\\server\\share), internal web apps, "
        "\"Windows cannot access\" errors — ZPA-side issues"
    ),
    ComplaintCategory.WEB_SLOW_OR_BLOCKED: (
        "Public site is slow or won't load, downloads stall, "
        "\"This page can't be reached\" — ZIA path / SSL inspection"
    ),
    ComplaintCategory.REAUTH_OR_DISCONNECT: (
        "Tunnel drops, IdP prompt fires repeatedly, tray icon "
        "cycles, session expired every few minutes"
    ),
    ComplaintCategory.FIRST_RUN_BROKEN: (
        "Freshly-imaged laptop, ZCC install failed, driver/kext "
        "not loading, posture check never completes"
    ),
    ComplaintCategory.REALTIME_PERF: (
        "Teams / Zoom / voice calls have jitter, packet loss, "
        "one-way audio; screen shares stall"
    ),
    ComplaintCategory.GENERAL: (
        "Skip narrowing — show me everything ranked by severity"
    ),
}


class TimeScopeKind(str, Enum):
    """Coarse-grained temporal narrowing for the Step-2 picker."""

    WHOLE_BUNDLE = "whole_bundle"          # default
    LAST_30_MIN = "last_30_min"            # last 30 min of the bundle
    SPECIFIC_TIMESTAMP = "specific_ts"     # anchor_utc ± window_min
    SINCE_LAST_BOOT = "since_last_boot"    # anchored to a lifecycle event

    @property
    def display_label(self) -> str:
        return _TIME_SCOPE_LABELS[self]


_TIME_SCOPE_LABELS: Dict[TimeScopeKind, str] = {
    TimeScopeKind.WHOLE_BUNDLE: "Whole bundle window (default)",
    TimeScopeKind.LAST_30_MIN: "Last 30 minutes of the bundle",
    TimeScopeKind.SPECIFIC_TIMESTAMP: "Specific date-time ± window",
    TimeScopeKind.SINCE_LAST_BOOT: "Since the machine's last boot",
}


# --------------------------------------------------------------------
# Data shapes
# --------------------------------------------------------------------


@dataclass
class TimeScope:
    """Temporal narrowing state."""

    kind: TimeScopeKind = TimeScopeKind.WHOLE_BUNDLE
    # Only used when ``kind == SPECIFIC_TIMESTAMP``. UTC-aware.
    anchor_utc: Optional[datetime] = None
    # Only used when ``kind == SPECIFIC_TIMESTAMP``. Half-width in minutes.
    window_min: int = 10


@dataclass
class IntakeContext:
    """User-provided intake collected by the Triage Wizard.

    A fresh instance (``IntakeContext()``) represents the legacy
    "no intake" state — the ranker falls back to severity-only
    ordering. This means the wizard is opt-in: skipping it
    reproduces pre-Phase-60 behavior exactly.
    """

    # ---- Step 1: complaint ----
    complaint_category: ComplaintCategory = ComplaintCategory.GENERAL
    # Optional free-text amplification of the complaint tile. Rendered
    # in the "Analyzed under" header verbatim (truncated to 60 chars).
    complaint_free_text: str = ""

    # ---- Step 2: scope ----
    # Free-form identifier. Wizard populates from bundle metadata
    # (loginName, falling back to hostname per Shameel's 2026-07-10
    # decision) but user can override.
    user: str = ""
    time_scope: TimeScope = field(default_factory=TimeScope)

    # ---- Meta ----
    # True until the user submits at least one non-default value. The
    # wizard sets this to False when it advances past Step 1 (even if
    # the user only picked a tile and left everything else at default).
    skipped: bool = True
    created_utc: Optional[datetime] = None
    schema_version: int = INTAKE_SCHEMA_VERSION

    # ---- Introspection ----

    def is_empty(self) -> bool:
        """True if no narrowing signal is present.

        Used by the ranker to short-circuit relevance scoring — an
        empty intake is equivalent to legacy severity-only ranking.
        """
        return (
            self.complaint_category == ComplaintCategory.GENERAL
            and not self.complaint_free_text.strip()
            and not self.user.strip()
            and self.time_scope.kind == TimeScopeKind.WHOLE_BUNDLE
        )

    def summary_line(self) -> str:
        """One-line 'Analyzed under: ...' header for the results view.

        Returns a legacy-friendly message when the intake is empty or
        skipped, so the results view can render this unconditionally.
        """
        if self.skipped or self.is_empty():
            return "Analyzed with no intake (all findings ranked by severity)"
        parts = [
            f"complaint={self.complaint_category.display_label}"
        ]
        if self.complaint_free_text.strip():
            snippet = self.complaint_free_text.strip()
            if len(snippet) > 60:
                snippet = snippet[:57] + "…"
            parts.append(f'note="{snippet}"')
        if self.user.strip():
            parts.append(f"user={self.user.strip()}")
        if self.time_scope.kind != TimeScopeKind.WHOLE_BUNDLE:
            parts.append(f"time={self.time_scope.kind.display_label}")
        return "Analyzed under: " + " · ".join(parts)

    # ---- Serialization ----

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe dict. Enums → their ``.value`` strings; datetimes
        → ISO 8601 strings. Reversible via ``from_dict``."""
        d: Dict[str, Any] = {
            "complaint_category": self.complaint_category.value,
            "complaint_free_text": self.complaint_free_text,
            "user": self.user,
            "time_scope": {
                "kind": self.time_scope.kind.value,
                "anchor_utc": (
                    self.time_scope.anchor_utc.isoformat()
                    if self.time_scope.anchor_utc is not None
                    else None
                ),
                "window_min": self.time_scope.window_min,
            },
            "skipped": self.skipped,
            "created_utc": (
                self.created_utc.isoformat()
                if self.created_utc is not None
                else None
            ),
            "schema_version": self.schema_version,
        }
        return d

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "IntakeContext":
        """Rebuild an IntakeContext from a ``to_dict`` blob.

        Defensive against missing / mis-typed fields — unknown enum
        values fall back to the safe default (``GENERAL`` /
        ``WHOLE_BUNDLE``), missing timestamps stay None. A None or
        empty dict returns a fresh default instance.
        """
        if not d:
            return cls()

        # Complaint category with safe fallback
        try:
            cat = ComplaintCategory(d.get("complaint_category", "general"))
        except ValueError:
            cat = ComplaintCategory.GENERAL

        # Time scope with safe fallbacks
        raw_ts = d.get("time_scope") or {}
        try:
            kind = TimeScopeKind(raw_ts.get("kind", "whole_bundle"))
        except ValueError:
            kind = TimeScopeKind.WHOLE_BUNDLE

        anchor = raw_ts.get("anchor_utc")
        if isinstance(anchor, str) and anchor:
            try:
                anchor = datetime.fromisoformat(anchor)
            except ValueError:
                anchor = None
        elif not isinstance(anchor, datetime):
            anchor = None

        try:
            window_min = int(raw_ts.get("window_min", 10))
        except (TypeError, ValueError):
            window_min = 10

        time_scope = TimeScope(
            kind=kind, anchor_utc=anchor, window_min=window_min,
        )

        # Created timestamp
        created = d.get("created_utc")
        if isinstance(created, str) and created:
            try:
                created = datetime.fromisoformat(created)
            except ValueError:
                created = None
        elif not isinstance(created, datetime):
            created = None

        try:
            sv = int(d.get("schema_version", INTAKE_SCHEMA_VERSION))
        except (TypeError, ValueError):
            sv = INTAKE_SCHEMA_VERSION

        return cls(
            complaint_category=cat,
            complaint_free_text=str(d.get("complaint_free_text", "") or ""),
            user=str(d.get("user", "") or ""),
            time_scope=time_scope,
            skipped=bool(d.get("skipped", True)),
            created_utc=created,
            schema_version=sv,
        )


# --------------------------------------------------------------------
# Session-state helpers
# --------------------------------------------------------------------
#
# All helpers accept ``session_state`` (a mapping) as a parameter rather
# than importing streamlit. Call sites in ui/*.py pass st.session_state
# directly.


def get_intake(session_state: Any) -> IntakeContext:
    """Read the current intake from session_state, or return a fresh
    default. Tolerates raw dicts (post JSON round-trip) and returns
    a normalized IntakeContext either way."""
    raw = None
    try:
        raw = session_state.get(INTAKE_SESSION_KEY)
    except AttributeError:
        # session_state is not a mapping — bail to default. Should not
        # happen in normal Streamlit flow but keeps helpers robust when
        # called from tests with plain dicts.
        return IntakeContext()

    if raw is None:
        return IntakeContext()
    if isinstance(raw, IntakeContext):
        return raw
    if isinstance(raw, dict):
        return IntakeContext.from_dict(raw)
    # Unknown type — reset defensively.
    return IntakeContext()


def set_intake(session_state: Any, intake: IntakeContext) -> None:
    """Persist an IntakeContext in session_state."""
    session_state[INTAKE_SESSION_KEY] = intake


def clear_intake(session_state: Any) -> None:
    """Reset intake back to the default (empty, skipped=True)."""
    session_state[INTAKE_SESSION_KEY] = IntakeContext()


def mark_skipped(session_state: Any) -> None:
    """Convenience: the user hit 'Skip intake — run everything'.

    Explicit skip differs from 'default state' only in that the results
    view can show a distinct message ("You skipped the wizard") rather
    than "you haven't filled it yet." Both produce identical ranker
    behavior.
    """
    intake = IntakeContext(skipped=True)
    intake.created_utc = _now_utc()
    session_state[INTAKE_SESSION_KEY] = intake


# --------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------


def _now_utc() -> datetime:
    """Isolated for testability — patch this to freeze time in tests."""
    from datetime import timezone
    return datetime.now(timezone.utc)


def resolve_user_from_summary(summary: Any) -> str:
    """Best-effort user identifier from a BundleSummary.

    Order (per Shameel's 2026-07-10 decision):
      1. summary.bundle_meta['loginName'] (non-empty, non-sentinel)
      2. summary.bundle_meta['hostname'] (falls back if loginName absent)
      3. Empty string (caller can leave the wizard field blank)

    The wizard populates the Step-2 user field with this value as its
    default; user can override with any free text.
    """
    if summary is None:
        return ""
    try:
        bm = getattr(summary, "bundle_meta", None) or {}
    except AttributeError:
        return ""

    def _clean(v: Any) -> str:
        if v is None:
            return ""
        s = str(v).strip()
        # Sentinel / redacted values that shouldn't count as a real
        # login. Matches the same sanitized values the Phase-33
        # detection treats as "missing".
        if s in ("", "###", "null", "None", "unknown", "-"):
            return ""
        return s

    login = _clean(bm.get("loginName"))
    if login:
        return login
    hostname = _clean(bm.get("hostname"))
    if hostname:
        return hostname
    # Also try common alternate keys in case future extractors use them
    for key in ("machine_name", "computer_name", "user_id"):
        v = _clean(bm.get(key))
        if v:
            return v
    return ""
