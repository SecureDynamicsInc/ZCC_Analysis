"""One-click ZPA M-Tunnel investigation workspace."""

from __future__ import annotations

from typing import Any, List, Sequence

import streamlit as st

from zcc_diag.rapid_triage import session_category, session_code, session_resolution


_FILTERS = [
    "Actionable only",
    "All sessions",
    "Setup failed",
    "Policy blocked",
    "Server reset",
    "No server response",
    "Data dropped",
    "Other failure",
    "Open / incomplete",
    "Normal",
]

_NOVICE_FILTERS = {
    "Problems only": "Actionable only",
    "Could not start": "Setup failed",
    "Blocked by a rule": "Policy blocked",
    "Connection was closed": "Server reset",
    "No reply": "No server response",
    "All connections": "All sessions",
}


def _matches(session: Any, selected: str, query: str, slow_threshold: float) -> bool:
    category = session_category(session)
    if selected == "Actionable only" and category in {"Normal", "Open / incomplete"}:
        return False
    if selected not in {"Actionable only", "All sessions"} and category != selected:
        return False
    if query:
        haystack = " ".join([
            str(getattr(session, "app_name", "") or ""),
            str(getattr(session, "dest_ip", "") or ""),
            str(getattr(session, "dest_port", "") or ""),
            str(getattr(session, "tag_id", "") or ""),
            str(getattr(session, "mtunnel_id", "") or ""),
            session_code(session),
        ]).lower()
        if query.lower() not in haystack:
            return False
    if slow_threshold > 0:
        latency = getattr(session, "setup_latency_s", None)
        if latency is None or latency < slow_threshold:
            return False
    return True


def _row(session: Any) -> dict:
    category = session_category(session)
    code = session_code(session)
    status, resolution, _severity = session_resolution(session)
    when = (
        getattr(session, "request_ts", None)
        or getattr(session, "setup_ts", None)
        or getattr(session, "ack_ts", None)
        or getattr(session, "end_ts", None)
    )
    destination = ""
    if getattr(session, "dest_ip", ""):
        destination = str(session.dest_ip)
        if getattr(session, "dest_port", None) is not None:
            destination += f":{session.dest_port}"
    return {
        "Result": category,
        "When": when.isoformat() if when else "",
        "Application": getattr(session, "app_name", "") or "(unknown)",
        "Destination": destination,
        "What it means": (status or code.replace("_", " ").title()) if code else category,
        "Next action": resolution or "Inspect the session evidence and correlate the complaint time.",
        "Code": code,
        "Tag": getattr(session, "tag_id", ""),
    }


def _novice_row(session: Any) -> dict:
    row = _row(session)
    category = {
        "Setup failed": "Could not start",
        "Policy blocked": "Blocked by a rule",
        "Server reset": "Connection was closed",
        "No server response": "No reply",
        "Data dropped": "Unreliable connection",
        "Open / incomplete": "Still in progress",
        "Other failure": "Connection problem",
        "Normal": "Working",
    }.get(row["Result"], row["Result"])
    return {
        "Problem": category,
        "Application": row["Application"],
        "Destination": row["Destination"],
        "Zscaler code": row["Code"],
        "What happened": row["What it means"],
        "What to try": row["Next action"],
    }


def _state_label(state: str) -> str:
    return state.replace("_", " ").title() if state else "Not observed"


def render_tunnel_apps(
    sessions: Sequence[Any], signals: Any = None, *, pro_mode: bool = True,
    service_scope: str = "All",
) -> None:
    st.markdown("## Tunnels & application failures" if pro_mode else "## Fix a connection")
    if pro_mode:
        st.caption(
            "M-Tunnel attempts reconstructed from explicit setup, acknowledgement, close-code, destination, and byte-flow evidence."
        )
    if signals is not None:
        zia_errors = sum(
            count for state, count in signals.zia_states.items()
            if state.endswith("ERROR")
        )
        zpa_errors = sum(
            count for state, count in signals.zpa_states.items()
            if state.endswith("ERROR")
        )
        if pro_mode and service_scope == "All":
            s1, s2, s3, s4 = st.columns(4)
            s1.metric("Latest Internet tunnel", _state_label(signals.zia_last_state))
            s2.metric("ZIA error states", zia_errors)
            s3.metric("Latest Private Access", _state_label(signals.zpa_last_state))
            s4.metric("ZPA error states", zpa_errors)
            st.caption(
                "Latest values come from explicit `getSmeProxyState` and "
                "`getZpnProxyState` records. Error-state totals can include retries that later recovered."
            )
        elif service_scope == "All":
            s1, s2 = st.columns(2)
            s1.metric("Internet connection", _state_label(signals.zia_last_state))
            s2.metric("Private app connection", _state_label(signals.zpa_last_state))
        elif service_scope == "ZIA":
            s1, s2 = st.columns(2)
            s1.metric("Internet tunnel", _state_label(signals.zia_last_state))
            s2.metric("ZIA error states", zia_errors)
        else:
            s1, s2 = st.columns(2)
            s1.metric("Private Access tunnel", _state_label(signals.zpa_last_state))
            s2.metric("ZPA error states", zpa_errors)

    if service_scope == "ZIA":
        st.info(
            "This view is filtered to Internet & SaaS (ZIA). Use the guided summary "
            "for ZIA tunnel, DNS, TCP, and TLS findings. Switch to All or ZPA to inspect "
            "private-application M-Tunnel sessions."
        )
        return

    if not sessions:
        st.info(
            ("No ZPA M-Tunnel sessions were reconstructed. Upload the full bundle or ZSATunnel.log. "
             "The tunnel-state summary above can still answer a focused ZIA forwarding question.")
            if pro_mode else
            ("No private-app connections were found in these logs. If a private app is the problem, "
             "upload the full support ZIP or ZSATunnel.log.")
        )
        return

    f1, f2, f3 = st.columns([2, 3, 2] if pro_mode else [2, 3, .01])
    with f1:
        novice_selected = st.selectbox(
            "Show", list(_NOVICE_FILTERS), index=0,
            key="novice_tunnel_filter",
        ) if not pro_mode else None
        selected = (
            _NOVICE_FILTERS[novice_selected] if novice_selected
            else st.selectbox("Quick filter", _FILTERS, index=0, key="pro_tunnel_filter")
        )
    with f2:
        query = st.text_input(
            "App, website, or address" if not pro_mode else
            "Application, destination, code, tag, or M-Tunnel ID",
            placeholder="e.g. payroll.internal" if not pro_mode else
            "e.g. payroll.internal, 10.20.30.40, NO_POLICY_FOUND",
            key=f"tunnel_query_{'pro' if pro_mode else 'novice'}",
        ).strip()
    slow_threshold = 0.0
    if pro_mode:
        with f3:
            slow_enabled = st.checkbox("Only slow setup")
            slow_threshold = st.number_input(
                "Setup seconds", min_value=0.1, max_value=60.0, value=2.0, step=0.5,
                disabled=not slow_enabled,
            ) if slow_enabled else 0.0

    visible = [s for s in sessions if _matches(s, selected, query, slow_threshold)]
    total_actionable = sum(
        1 for s in sessions if session_category(s) not in {"Normal", "Open / incomplete"}
    )
    if pro_mode:
        c1, c2, c3 = st.columns(3)
        c1.metric("Sessions shown", len(visible))
        c2.metric("Actionable sessions", total_actionable)
        c3.metric("Applications represented", len({getattr(s, 'app_name', '') for s in visible if getattr(s, 'app_name', '')}))

    if not visible:
        st.info("No sessions match these filters. Clear the search or choose another quick filter.")
        return

    st.dataframe(
        [(_row(s) if pro_mode else _novice_row(s)) for s in visible[:1000]],
        hide_index=True,
        use_container_width=True,
        height=min(560, 40 + 35 * min(len(visible), 15)),
        column_config={
            "When": st.column_config.TextColumn(width="medium"),
            "Application": st.column_config.TextColumn(width="large"),
            "What it means": st.column_config.TextColumn(width="large"),
            "Next action": st.column_config.TextColumn(width="large"),
            "Code": st.column_config.TextColumn(width="large"),
            "What happened": st.column_config.TextColumn(width="large"),
            "What to try": st.column_config.TextColumn(width="large"),
        },
    )
    if len(visible) > 1000:
        st.caption(f"Showing the first 1,000 of {len(visible):,} matching sessions.")

    choices = []
    choice_map = {}
    for s in visible[:500]:
        when = getattr(s, "request_ts", None) or getattr(s, "setup_ts", None)
        if pro_mode:
            label = (
                f"{when.isoformat() if when else 'unknown time'} · "
                f"{getattr(s, 'app_name', '') or '(unknown app)'} · "
                f"{session_category(s)} · tag {getattr(s, 'tag_id', '')}"
            )
        else:
            label = (
                f"{len(choices) + 1} · {getattr(s, 'app_name', '') or 'Unknown app'} · "
                f"{_novice_row(s)['Problem']}"
            )
        choices.append(label)
        choice_map[label] = s
    selected_session = st.selectbox(
        "Inspect one session" if pro_mode else "Choose a connection to review",
        choices,
    )
    session = choice_map[selected_session]
    status, resolution, _severity = session_resolution(session)
    if status:
        st.markdown(f"**{'Meaning' if pro_mode else 'What happened'}:** {status}")
    if resolution:
        st.markdown(f"**{'Documented next action' if pro_mode else 'What to try'}:** {resolution}")
    if pro_mode:
        st.caption(
            f"M-Tunnel ID: {getattr(session, 'mtunnel_id', '') or 'not observed'} · "
            f"Close initiator: {getattr(session, 'close_initiator', '') or 'unknown'} · "
            f"Setup latency: {getattr(session, 'setup_latency_s', None) if getattr(session, 'setup_latency_s', None) is not None else 'not observed'}"
        )
        with st.expander("Show the exact records for this session", expanded=True):
            for line in list(getattr(session, "lines", []) or [])[:80]:
                ts = getattr(line, "ts", None)
                source = getattr(line, "source_file", "")
                line_no = getattr(line, "line_no", 0)
                body = getattr(line, "body", "")
                st.code(f"{ts}  {source}:{line_no}\n{body}", language=None)
            if len(getattr(session, "lines", []) or []) > 80:
                st.caption("Only the first 80 correlated records are shown here. Use Deep evidence for the full record set.")
    else:
        st.caption("Use Error code help for the documented meaning. Switch to Pro for identifiers, timing, and exact log records.")
