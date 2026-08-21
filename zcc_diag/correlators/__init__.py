"""
Cross-stream correlators (Phase 48, 2026-06-24).

Each correlator is a stateless function that consumes parsed log records
(from log_parser.parse_file) and produces typed events that the Phase 49
RCA synthesizers consume.

The design is informed by the reverse-engineering audit (Phase 47 follow-up):
correlators MUST handle edge cases the Example Tenant A analysis got wrong by hand —
fresh-start-vs-rotation, polling-vs-user, idle-mtunnel-vs-active, ±50ms
clock drift, and missing PRT availability.

  power_change       — Modern Standby entry/exit pairing (M-S cycles + durations)
  force_reauth       — zcc_zpa_force_reauth_sleep_trigger ↔ M-S exit pairing
                       (with UNMATCHED count surfaced separately)
  auth_state         — AUTHENTICATED ↔ AUTHENTICATION_REQUIRED pair events
                       (with unresolved-at-bundle-end handling)
  mtunnel            — BRK_MT_* close classifier + last-byte-time tracking
  polling_cadence    — learn periodic mtunnel cadence from data (not hardcoded)
  service_lifecycle  — fresh-start vs log-rotation, PID-change detection
  prt_availability   — does this device have an AAD PRT for silent SAML refresh?

These are intentionally separate small modules — easier to unit-test, easier
to reason about, and each handles one specific kind of correlation.
"""

from .power_change import find_modern_standby_cycles, ModernStandbyCycle
from .force_reauth import find_force_reauth_events, ForceReauthEvent
from .auth_state import find_auth_state_events, AuthStateEvent, AuthEventOutcome
from .mtunnel import classify_mtunnel_closes, MtunnelClose, MtunnelCloseReason
from .polling_cadence import learn_polling_cadence, PollingCadence
from .service_lifecycle import find_service_starts, ServiceStart, ServiceStartKind
from .prt_availability import detect_prt_availability, PRTAvailability

__all__ = [
    # power_change
    "find_modern_standby_cycles",
    "ModernStandbyCycle",
    # force_reauth
    "find_force_reauth_events",
    "ForceReauthEvent",
    # auth_state
    "find_auth_state_events",
    "AuthStateEvent",
    "AuthEventOutcome",
    # mtunnel
    "classify_mtunnel_closes",
    "MtunnelClose",
    "MtunnelCloseReason",
    # polling_cadence
    "learn_polling_cadence",
    "PollingCadence",
    # service_lifecycle
    "find_service_starts",
    "ServiceStart",
    "ServiceStartKind",
    # prt_availability
    "detect_prt_availability",
    "PRTAvailability",
]
