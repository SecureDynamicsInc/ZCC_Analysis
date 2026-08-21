"""Streamlit notice shown when GitHub main is newer than this installation."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from zcc_diag.update_check import agent_update_prompt, check_for_update, source_repo_path


@st.cache_data(ttl=900, show_spinner=False)
def _cached_check(runtime_root: str):
    return check_for_update(Path(runtime_root))


def render_update_notice(runtime_root: Path, *, pro_mode: bool = False) -> None:
    status = _cached_check(str(runtime_root))
    if status.state == "current":
        if pro_mode:
            st.caption(f"Version check: current with GitHub main · {status.local_sha[:8]}")
        return
    if status.state == "unavailable":
        if pro_mode:
            st.caption("Version check could not reach GitHub. Analysis can continue locally.")
        return

    repo = source_repo_path(runtime_root)
    st.warning(
        "**A newer ZCC Log Explorer version is available on GitHub.** "
        f"Installed baseline `{status.local_sha[:8]}` · GitHub main `{status.latest_sha[:8]}`. "
        "Update before analyzing when practical so conclusions use the newest rules and fixes."
    )
    st.markdown("**Safe updater:**")
    st.code(
        f'"{repo}/scripts/update_install.sh"',
        language="bash",
        wrap_lines=True,
    )
    st.caption(
        "The updater validates local state, tests a fresh clone of official GitHub main, "
        "then warns before replacing and reinstalling the official checkout. It never "
        "merges histories. Preserve custom work in a separate fork or checkout path before "
        "confirming replacement. If it stops, follow its explanation or give the prompt "
        "below to Codex or Claude."
    )
    st.markdown("**Prompt for Codex or Claude:**")
    st.code(agent_update_prompt(repo), language=None, wrap_lines=True)
