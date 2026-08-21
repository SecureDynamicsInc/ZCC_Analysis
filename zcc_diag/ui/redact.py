"""
PII-redaction integration for the BundleScope UI.

Wires the existing ``zcc_diag.pii.Redactor`` into the Streamlit
surface so engineers can safely share screenshots, triage reports,
and exports externally without leaking customer hostnames, users,
public IPs, MACs, or auth tokens.

How it works:

  1. ``_analyse`` constructs a ``Redactor`` per bundle and runs its
     ``prepass`` against ``AppInfo.xml`` / ``SystemInfo.xml`` to
     seed high-confidence mappings (hostname, domain, registered
     owner, logon server). The redactor lives on ``data["redactor"]``
     for the lifetime of the cached bundle.
  2. A sidebar checkbox sets ``st.session_state["pii_redact_enabled"]``.
  3. Render-site helpers call ``redact(value, data)`` to apply the
     scrub when the toggle is ON, or pass through when OFF or when
     no redactor is available (older cached bundles).

Design rules:

  * **Off by default.** The toggle controls behavior; engineers
    opt in when they want to share output externally. The default
    must keep things readable for triage.
  * **Pass-through on missing pieces.** None, empty strings, and
    non-string values are returned untouched. A missing redactor
    (old cache) is also a pass-through — never raises.
  * **Idempotent scrubbing.** Calling ``scrub`` on already-scrubbed
    text is harmless: the token format ``<KIND_NNN>`` doesn't match
    any of the redaction regexes.
  * **Allowlisted topology stays visible.** Zscaler infrastructure
    hostnames, private RFC 1918 IPs, CGNAT 100.64/10, link-local —
    all visible. They're network topology, not PII, and engineers
    need them readable.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import streamlit as st


# Session-state keys the sidebar toggle + dispatcher write to. Read
# by ``redact()`` at every render call. Single source of truth so
# renaming is one place.
_TOGGLE_KEY = "pii_redact_enabled"
_ACTIVE_REDACTOR_KEY = "_active_redactor"


def redact_enabled() -> bool:
    """Return True when the sidebar PII-redact toggle is active."""
    return bool(st.session_state.get(_TOGGLE_KEY, False))


def install_redactor(redactor) -> None:
    """Stash the current bundle's ``Redactor`` in session_state so
    every render-site call to :func:`redact` can find it without
    threading ``data`` through every function in the rendering tree.

    Called once per script-run by the top-level dispatcher after
    ``_analyse`` returns. A no-op when ``redactor`` is None (e.g.
    older cached bundles that pre-date the redactor field).
    """
    if redactor is not None:
        st.session_state[_ACTIVE_REDACTOR_KEY] = redactor


def redact(value: Any, data: Optional[Dict[str, Any]] = None) -> Any:
    """Pass ``value`` through the active ``Redactor`` if the sidebar
    toggle is ON. Returns the value unchanged in any of these cases:

      * Toggle is OFF (default).
      * ``value`` is None or an empty string.
      * ``value`` is not a string (numbers, datetimes, etc.).
      * No redactor available — neither on ``data`` nor in
        ``session_state``.
      * Underlying ``scrub`` raises (best-effort — a redaction
        failure must not break the UI).

    Redactor lookup precedence: explicit ``data["redactor"]`` first
    (caller knows best), then ``session_state[_active_redactor]``
    set by ``install_redactor``. The session-state fallback exists
    because deep render functions (e.g. inside finding cards) don't
    carry ``data`` and threading it through every call site would
    bloat the signatures.
    """
    if value is None or value == "":
        return value
    if not isinstance(value, str):
        return value
    if not redact_enabled():
        return value
    redactor = None
    if data is not None:
        redactor = data.get("redactor")
    if redactor is None:
        redactor = st.session_state.get(_ACTIVE_REDACTOR_KEY)
    if redactor is None:
        return value
    try:
        return redactor.scrub(value)
    except Exception:
        # Never let a redaction failure crash the UI.
        return value


def redact_text(text: str, data: Optional[Dict[str, Any]] = None) -> str:
    """Specialised variant for required-string contexts.

    Same behavior as :func:`redact` but the return type is always a
    string. Useful at sites where downstream code does
    ``str.format`` / concatenation and a None return would explode.
    """
    out = redact(text, data)
    if out is None:
        return ""
    return str(out)


def render_redact_toggle() -> None:
    """Render the sidebar PII-redact checkbox. Place inside the sidebar
    (typically the footer) so it sits below the module nav. Streamlit
    persists checkbox state to ``st.session_state[key]`` automatically;
    no extra wiring needed."""
    st.sidebar.checkbox(
        "Redact PII",
        key=_TOGGLE_KEY,
        help=(
            "Replace hostnames, emails, usernames, public IPs, MACs, "
            "and auth tokens with anonymous tokens (<HOST_001>, "
            "<EMAIL_002>, etc.) in the UI and the triage export. "
            "Useful for sharing screenshots or reports externally. "
            "Zscaler infrastructure and private / CGNAT IPs stay "
            "visible — they're network topology, not PII."
        ),
    )
