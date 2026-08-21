"""
Log-context lookup for finding-card evidence rendering.

Pain point this solves
----------------------
When a customer reports "I got a SAML failure around 9:30am" and the
toolkit fires a Critical finding, the evidence list shows only the
matched lines. The engineer can't see what was happening immediately
before / after on the same file (broker state? network change? sleep
event?) — the surrounding lines often hold the actual cause.

Mechanism
---------
A bundle's parsed-log index (``LogIndex``, ~3M lines for a typical
bundle) is built once at analyse() time. We park a reference to it in
``st.session_state`` so every render site — finding cards, the
search drill-in, the patterns layer — can ask for "±5 lines around
(file, line_no)" without threading the data dict through every
function in the UI.

Memory profile
--------------
The reference is shared — Streamlit's session state holds a Python
object reference, not a copy. So putting log_index here costs zero
extra memory beyond what ``_analyse`` already keeps live for the
duration of the cached bundle.

Mirrors the ``ui.redact`` install/get pattern so the wire-up is
consistent.
"""

from __future__ import annotations

from typing import Any, List, Optional

import streamlit as st


_ACTIVE_LOG_INDEX_KEY = "_active_log_index"


def install_log_index(log_index: Any) -> None:
    """Stash the current bundle's ``LogIndex`` in session_state.
    Called once per script-run by the top-level dispatcher after
    ``_analyse`` returns. No-op when ``log_index`` is None."""
    if log_index is not None:
        st.session_state[_ACTIVE_LOG_INDEX_KEY] = log_index


def get_log_index() -> Optional[Any]:
    """Return the active LogIndex from session_state, or None if no
    bundle is loaded / the analyse pipeline didn't produce one."""
    return st.session_state.get(_ACTIVE_LOG_INDEX_KEY)


def surrounding_lines(
    source_file: str,
    line_no: Optional[int],
    radius: int = 5,
) -> List[Any]:
    """Convenience: ask the active LogIndex for surrounding lines.
    Returns [] when no index is loaded, when line_no is None, or when
    the source_file doesn't appear in the index. Never raises."""
    if line_no is None or not source_file:
        return []
    idx = get_log_index()
    if idx is None or not hasattr(idx, "surrounding_lines"):
        return []
    try:
        return idx.surrounding_lines(source_file, int(line_no), radius=radius)
    except (ValueError, TypeError):
        return []


# Backwards-compat aliases.
_install_log_index = install_log_index
_get_log_index = get_log_index
_surrounding_lines = surrounding_lines
