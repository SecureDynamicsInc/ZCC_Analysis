"""
Normalized Zscaler reference data linked to official documentation.

This package centralizes every documented Zscaler status code / error
code into Python data modules. Detectors load from here instead of
hardcoding code -> meaning mappings in the detector source.

Why a Python package and not YAML/JSON:

  1. Project rule: pure stdlib, no external dependencies. PyYAML is
     third-party.
  2. TypedDict gives us type-checked data structures with editor
     autocomplete.
  3. Grep finds code strings as Python literals — searchable.
  4. No runtime parsing step; the data is just imported.

Data modules in this package:

  * ``zpa_session_codes.py`` -- Every code in the "Understanding
    Private Access Session Status Codes" documentation (Error + Info + Policy
    Block tables). ~100+ codes.

  * ``zpa_auth_errors.py`` -- Every error code in the "Zscaler Client
    Connector: Private Access Authentication Errors" documentation (2008 plus
    42000..42048). ~50 codes.

  * ``zcc_connection_status.py`` -- 17 tray-status messages from the
    "Zscaler Client Connector: Connection Status Errors" documentation (Driver
    Error / Endpoint FW/AV Error / Captive Portal Detected / Network
    Error / etc.).

  * ``zcc_errors.py`` -- ~120 numeric error codes from the "Zscaler
    Client Connector Errors" documentation across four series: Cloud Auth
    (-14..-1), Cloud (1..28 + 1000..1019 + 10060..10112), Admin
    Console (3005..3102), Report-an-Issue (8790..8810).

  * ``zia_policy_reasons.py`` -- ~100 ZIA Insights/NSS policy reason
    strings from the "Internet & SaaS (ZIA): Policy Reasons" documentation.
    These don't typically appear in ZCC tunnel logs but are a
    valuable reference when triaging customer reports that mention
    policy reason strings from the admin console.

  * ``zia_auth_errors.py`` -- ~103 ZIA authentication error codes
    across four categories (Generic / AD-LDAP Sync / Kerberos /
    Identity Proxy) from the "Internet & SaaS Authentication Error
    Codes" documentation (cross-validated against the focused "Kerberos
    Authentication" documentation). User-facing codes shown on the Zscaler
    error page when ZIA auth fails. Some bleed into ZCC tunnel /
    tray logs in mobile-API response bodies.

  * ``zdx_web_probe_errors.py`` -- 24 ZDX Web Probe errors from the
    "ZDX: Web Probe Errors" documentation. Probe phases: domain_dns /
    tcp_connect / http_method / http_connect / http_status /
    http_request / https / timeout / rate_limit.

  * ``zdx_cloud_path_errors.py`` -- 31 ZDX Cloud Path errors from
    the "ZDX: Cloud Path Errors" documentation (20 direct + 11 ZPA-via-ZDX
    cross-suite rows that overlap with ``zpa_session_codes.py``).

  * ``zdx_remediation_errors.py`` -- 41 ZDX Remediation errors
    (ZUPM_WORKFLOW_E_CODE_* prefix) from the "ZDX: Remediation
    Errors" documentation. Five families: workflow / task / script /
    log_fetch / notification. 41 rows = 40 distinct codes + 1
    duplicate (SCRIPT_CERT_VALIDATION_FAILED appears twice with
    different messages per documentation).

  * ``zdx_managed_probe_errors.py`` -- 60 ZDX Managed Probe errors
    from the "ZDX: Zscaler Managed Probe Errors" documentation (9 Web probe
    + 51 Cloud Path probe). "Internal error" appears in both
    sub-tables as distinct rows.

Each module exposes a top-level constant (``CODES`` for session codes,
``ERRORS`` for auth errors) and helper lookup functions.

REFERENCE MAINTENANCE:
    Each module links to its complete external Zscaler Help reference. When
    product documentation changes, update the normalized rows and regression
    tests together. Severity hints are SecureDynamics triage judgments and are
    not official support priorities. See docs/REFERENCE_SOURCES.md.

USAGE:
    from zcc_diag.data import (
        get_session_code, get_auth_error,
        session_code_severity, auth_error_severity,
    )
    info = get_session_code("BRK_MT_CLOSED_FROM_ASSISTANT")
    if info is not None:
        print(info["category"])  # "info"
        print(info["resolution"])  # "No action required."
"""

from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------
# TypedDict shape definitions for editor autocomplete + static type
# checking. We use the literal-string style (TypedDict) rather than
# dataclasses so the data modules can be plain dict literals (more
# readable as data files, less ceremony).

try:
    # Python 3.8+ has TypedDict in typing; 3.11+ has it in builtins.
    from typing import TypedDict, List, Literal
except ImportError:  # pragma: no cover
    # Fallback for very old runtimes — we just lose the type hints.
    TypedDict = dict  # type: ignore
    List = list  # type: ignore
    Literal = lambda *args, **kw: str  # type: ignore


class SessionStatusCode(TypedDict, total=False):
    """One row from the ZPA Session Status Codes documentation.

    Fields:
      code             — the canonical identifier (e.g. ``BRK_MT_SETUP_FAIL_SAML_EXPIRED``)
      component        — "AC" | "CA" | "CLT" | "SE" | "ZPA BA"
      category         — "error" | "info" | "policy_block"
      session_status   — the human-readable name from the documentation's
                         "Session Status" column (without the component prefix)
      description      — documented from the documentation's "Description" column
      resolution       — documented from the documentation's "Resolution" column
      severity_hint    — our derived severity ("critical" | "warning" | "info")
                         based on the category + how the docs frame the code:
                            error      -> critical (default)
                            policy_block -> warning (default; some critical)
                            info       -> info (always)
    """
    code: str
    component: str
    category: str
    session_status: str
    description: str
    resolution: str
    severity_hint: str


class AuthError(TypedDict, total=False):
    """One row from the ZPA Authentication Errors documentation.

    Fields:
      code               — string code (e.g. ``"42016"``)
      error_message      — documented from the documentation's "Error Message" column
      error_description  — documented from the documentation's "Error Description" column
      resolution         — documented from the documentation's "Resolution" column
      group              — our grouping ("user_input" | "tenant_config" |
                           "saml_validation" | "certificate" | "internal")
                           used for SOP routing
      severity_hint      — almost always "critical" (these block enrollment)
    """
    code: str
    error_message: str
    error_description: str
    resolution: str
    group: str
    severity_hint: str


# ---------------------------------------------------------------------
# Lookup helpers. The data modules expose the lists directly; these
# helpers are convenience wrappers for the common "give me the row
# for this code" pattern.

def get_session_code(code: str) -> Optional[SessionStatusCode]:
    """Return the SessionStatusCode row for ``code``, or None if unknown."""
    from .zpa_session_codes import CODES_BY_NAME
    return CODES_BY_NAME.get(code)


def get_auth_error(code: str) -> Optional[AuthError]:
    """Return the AuthError row for ``code``, or None if unknown."""
    from .zpa_auth_errors import ERRORS_BY_CODE
    return ERRORS_BY_CODE.get(code)


def session_code_severity(code: str, default: str = "warning") -> str:
    """Return the derived severity hint for a session code.

    Uses the ``severity_hint`` field set per-code in the data module.
    Falls back to ``default`` for unknown codes.
    """
    info = get_session_code(code)
    if info is None:
        return default
    return info.get("severity_hint", default)


def auth_error_severity(code: str, default: str = "critical") -> str:
    """Return the derived severity hint for an auth error code.

    Almost always ``"critical"`` since these block enrollment.
    """
    info = get_auth_error(code)
    if info is None:
        return default
    return info.get("severity_hint", default)


def all_session_code_names() -> "list[str]":
    """Return the list of every known session code identifier (sorted)."""
    from .zpa_session_codes import CODES_BY_NAME
    return sorted(CODES_BY_NAME.keys())


def all_auth_error_codes() -> "list[str]":
    """Return the list of every known auth error code (sorted)."""
    from .zpa_auth_errors import ERRORS_BY_CODE
    return sorted(ERRORS_BY_CODE.keys())


# ---------------------------------------------------------------------
# Phase 4 (2026-06-12): ZCC Connection Status + numeric ZCC error
# code lookups. Wired through the same convenience-function layer so
# UI / detector code can pull from one place.

def get_tray_status(name: str):
    """Return the tray-status row for ``name`` (case-insensitive), or
    None if unknown. See ``zcc_connection_status`` for the schema."""
    from .zcc_connection_status import get_tray_status as _g
    return _g(name)


def get_zcc_error(code: str):
    """Return the numeric ZCC error row for ``code`` (string form,
    e.g. ``"-8"``, ``"3049"``, ``"10101"``), or None if unknown."""
    from .zcc_errors import get_zcc_error as _g
    return _g(code)


def tray_status_severity(name: str, default: str = "warning") -> str:
    """Return the derived severity hint for a tray status name."""
    info = get_tray_status(name)
    if info is None:
        return default
    return info.get("severity_hint", default)


def zcc_error_severity(code: str, default: str = "warning") -> str:
    """Return the derived severity hint for a numeric ZCC error code."""
    info = get_zcc_error(code)
    if info is None:
        return default
    return info.get("severity_hint", default)


# ---------------------------------------------------------------------
# Phase 6 (2026-06-12): ZIA Policy Reasons lookup. These are Insights/
# NSS-side strings — see zia_policy_reasons.py module docstring for
# why they typically don't appear in tunnel logs but are still useful
# as engineer reference.

def get_policy_reason(name: str):
    """Return the ZIA Policy Reason row for ``name`` (case-insensitive),
    or None if unknown."""
    from .zia_policy_reasons import get_policy_reason as _g
    return _g(name)


def policy_reason_severity(name: str, default: str = "warning") -> str:
    """Return the derived severity hint for a ZIA Policy Reason."""
    info = get_policy_reason(name)
    if info is None:
        return default
    return info.get("severity_hint", default)


# ---------------------------------------------------------------------
# Phase 7 (2026-06-17): ZIA Authentication Error Codes lookup. ~103
# codes across Generic / AD-LDAP Sync / Kerberos / Identity Proxy.
# See zia_auth_errors.py for the schema and category-mapping rationale.

class ZiaAuthError(TypedDict, total=False):
    """One row from the ZIA Authentication Error Codes documentation.

    Fields:
      code                — string code ("211000", "100", "471000",
                            "0x1388")
      category            — generic | ldap_sync | kerberos | identity_proxy
      occurrence          — sub-discriminator for Kerberos codes with
                            multiple documentation rows (471000 has 5, 491000/
                            501000 have 2 each); empty otherwise
      error_description   — documented from documentation Description column
      error_when          — documented from documentation When-It-Occurs column
                            (empty for Identity Proxy rows — that documentation
                            has no When column)
      recommended_action  — documented from documentation What-to-Do column
      severity_hint       — critical | warning | info (our derivation)
    """
    code: str
    category: str
    occurrence: str
    error_description: str
    error_when: str
    recommended_action: str
    severity_hint: str


def get_zia_auth_error(code: str):
    """Return the first ZIA auth error row for ``code``, or None.
    Tolerant of casing/prefix variants ("0x1388" / "0X1388" / "1388")."""
    from .zia_auth_errors import get_zia_auth_error as _g
    return _g(code)


def get_zia_auth_error_all(code: str):
    """Return every documented row for ``code`` — Kerberos codes
    with multiple documentation occurrences return a list of length > 1."""
    from .zia_auth_errors import get_zia_auth_error_all as _g
    return _g(code)


def zia_auth_error_severity(code: str, default: str = "warning") -> str:
    """Return the derived severity hint for a ZIA auth error code."""
    from .zia_auth_errors import zia_auth_error_severity as _s
    return _s(code, default)


def zia_auth_error_category(code: str):
    """Return the category (generic | ldap_sync | kerberos |
    identity_proxy) for ``code``, or None if unknown."""
    from .zia_auth_errors import zia_auth_error_category as _c
    return _c(code)


# ---------------------------------------------------------------------
# Phase 8 (2026-06-17): ZDX (Digital Experience Monitoring) lookups.
# Four data modules covering the ZDX side of the product family:
#   * Web Probe (24 rows)
#   * Cloud Path (31 rows, includes 11 ZPA-via-ZDX cross-suite)
#   * Remediation (40 rows, ZUPM_WORKFLOW_E_CODE_* prefix)
#   * Managed Probe (60 rows, web + cloud_path sub-tables)
#
# See each module's docstring for the schema. All helpers below are
# thin pass-throughs to keep the import-graph lazy.


def get_zdx_web_probe_error(key: str):
    """Return the ZDX Web Probe error row for identifier or documented
    message ``key``, or None if unknown."""
    from .zdx_web_probe_errors import get_zdx_web_probe_error as _g
    return _g(key)


def get_zdx_cloud_path_error(key: str):
    """Return the ZDX Cloud Path error row for identifier or documented
    message ``key``, or None if unknown."""
    from .zdx_cloud_path_errors import get_zdx_cloud_path_error as _g
    return _g(key)


def get_zdx_remediation_error(key: str):
    """Return the ZDX Remediation error row for ZUPM_WORKFLOW_E_CODE_*
    code or documented message ``key``, or None if unknown."""
    from .zdx_remediation_errors import get_zdx_remediation_error as _g
    return _g(key)


def get_zdx_managed_probe_error(key: str, probe_type=None):
    """Return the ZDX Managed Probe error row for identifier or
    documented message ``key``. Pass probe_type="web"|"cloud_path" to
    disambiguate when the message exists in both sub-tables (only
    "Internal error" does today)."""
    from .zdx_managed_probe_errors import get_zdx_managed_probe_error as _g
    return _g(key, probe_type)


def zdx_web_probe_error_severity(key: str, default: str = "warning") -> str:
    """Severity hint for a ZDX Web Probe error."""
    from .zdx_web_probe_errors import zdx_web_probe_error_severity as _s
    return _s(key, default)


def zdx_cloud_path_error_severity(key: str, default: str = "warning") -> str:
    """Severity hint for a ZDX Cloud Path error."""
    from .zdx_cloud_path_errors import zdx_cloud_path_error_severity as _s
    return _s(key, default)


def zdx_remediation_error_severity(key: str, default: str = "warning") -> str:
    """Severity hint for a ZDX Remediation error."""
    from .zdx_remediation_errors import zdx_remediation_error_severity as _s
    return _s(key, default)


def zdx_managed_probe_error_severity(
    key: str, probe_type=None, default: str = "warning",
) -> str:
    """Severity hint for a ZDX Managed Probe error."""
    from .zdx_managed_probe_errors import zdx_managed_probe_error_severity as _s
    return _s(key, probe_type, default)
