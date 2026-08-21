"""
Triage Wizard — the Streamlit component that collects intake context
from the operator before analysis fires.

Phase 60a-Task-2 (2026-07-10). Renders a single scrolling page with
three titled sections:

  * **Step 1 — What is the customer reporting?**
      Tile grid (2 rows × 3 columns) selecting one ComplaintCategory.
      Optional free-text box for the customer's own words.
  * **Step 2 — Which user and when?**
      User identifier (prefilled from bundle metadata via the
      loginName → hostname fallback rule) and a time-scope radio.
      The "Specific date-time ± window" option reveals inline
      date/time/window inputs.
  * **Skip intake — run everything**
      Footer button that resets the intake to skipped state and
      falls back to legacy severity-only ranking. Always visible.

State lives in ``st.session_state["intake"]`` as an ``IntakeContext``
instance. The wizard writes to it as a side effect; callers can
retrieve the current value via ``get_intake(st.session_state)`` or
use the ``IntakeContext`` returned by ``render_intake_wizard()``.

Streamlit gotchas / decisions:
  * All widget keys are namespaced ``intake_wiz_*`` so they never
    collide with the other UI modules' widgets.
  * The tile grid uses ``st.button(type="primary")`` on the selected
    tile — Streamlit-native visual differentiation, no custom CSS
    required. Clicking a tile does NOT trigger st.rerun() explicitly;
    Streamlit reruns on every widget interaction, so the next render
    already reflects the new selection.
  * ``st.date_input`` / ``st.time_input`` produce naive ``date`` and
    ``time`` objects; we combine them into a UTC-aware datetime on
    read (users are expected to enter UTC — the label makes this
    explicit).
  * The bundle uploader is NOT in this component. It stays with the
    landing page (see ui/overview.py rewrite in Task 5). This module
    is JUST the intake collector.
"""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from typing import Any, Optional

import streamlit as st

from ..intake import (
    ComplaintCategory,
    IntakeContext,
    TimeScope,
    TimeScopeKind,
    clear_intake,
    get_intake,
    mark_skipped,
    resolve_user_from_summary,
    set_intake,
)


# --------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------


def render_intake_wizard(
    session_state: Any,
    summary: Any = None,
) -> IntakeContext:
    """Render the Triage Wizard in the current Streamlit page.

    Args:
        session_state: ``st.session_state``.
        summary: Optional BundleSummary. When provided, the user field
            is prefilled via ``resolve_user_from_summary``.

    Returns:
        The current ``IntakeContext``. Reflects any changes the user
        made during this render pass (Streamlit reruns after every
        widget interaction, so this is always current).
    """
    intake = get_intake(session_state)

    st.markdown("### Triage Wizard")
    st.caption(
        "Tell us what the customer is reporting so we can pin the "
        "relevant findings to the top. Skipping is fine — the wizard "
        "just shapes the ranking; every finding is still available."
    )

    # ---- Step 1: Complaint ----
    intake = _render_step1_complaint(session_state, intake)

    # ---- Step 2: Scope ----
    intake = _render_step2_scope(session_state, intake, summary)

    # ---- Footer: Skip / Reset ----
    _render_footer(session_state, intake)

    # Persist any tweaks made during this render pass and return.
    set_intake(session_state, intake)
    return intake


def render_intake_header(session_state: Any) -> None:
    """Compact one-line header for the results view.

    Renders the ``IntakeContext.summary_line()`` as an ``st.info`` /
    ``st.caption`` and a small ``[Change intake]`` button that
    resets to the wizard. Called from analyse-result pages.
    """
    intake = get_intake(session_state)
    line = intake.summary_line()

    col_msg, col_btn = st.columns([5, 1])
    with col_msg:
        if intake.skipped or intake.is_empty():
            st.caption(f":gray[{line}]")
        else:
            st.info(f"🎯 {line}", icon=None)
    with col_btn:
        if st.button(
            "Change intake",
            key="intake_header_change",
            use_container_width=True,
            help="Reset the wizard and re-scope the analysis",
        ):
            clear_intake(session_state)
            # A rerun forces the landing page to show the fresh wizard
            # on the next paint. Streamlit-safe from any button context.
            st.rerun()


# --------------------------------------------------------------------
# Section 1: Complaint tile grid + free text
# --------------------------------------------------------------------


def _render_step1_complaint(
    session_state: Any,
    intake: IntakeContext,
) -> IntakeContext:
    with st.container(border=True):
        st.markdown("#### Step 1 · What is the customer reporting?")
        st.caption(
            "Pick the tile that best matches the customer's own words. "
            "Not sure? Pick **General** — findings will rank by severity only."
        )

        # 2×3 tile grid — order matches ComplaintCategory enum order.
        tiles_order = [
            ComplaintCategory.INTERNAL_ACCESS,
            ComplaintCategory.WEB_SLOW_OR_BLOCKED,
            ComplaintCategory.REAUTH_OR_DISCONNECT,
            ComplaintCategory.FIRST_RUN_BROKEN,
            ComplaintCategory.REALTIME_PERF,
            ComplaintCategory.GENERAL,
        ]

        for row_start in (0, 3):
            row_tiles = tiles_order[row_start : row_start + 3]
            cols = st.columns(3)
            for col, cat in zip(cols, row_tiles):
                with col:
                    _render_tile(session_state, intake, cat)

        st.divider()

        # Free-text amplification. Optional.
        free = st.text_area(
            "Optional: paste the customer's message or a short note",
            value=intake.complaint_free_text,
            key="intake_wiz_freetext",
            height=68,
            placeholder=(
                "e.g. \"user can't open \\\\stdc01\\netlogon — tried "
                "reboot, still fails\""
            ),
            help=(
                "Shown verbatim in the 'Analyzed under' header at the "
                "top of the results page. Useful for future you when "
                "you re-open the same bundle in a week."
            ),
        )
        intake.complaint_free_text = free

    return intake


def _render_tile(
    session_state: Any,
    intake: IntakeContext,
    cat: ComplaintCategory,
) -> None:
    selected = intake.complaint_category == cat and not intake.skipped
    with st.container(border=True):
        # Header: bolded label, with a check icon when selected
        prefix = "✅ " if selected else ""
        st.markdown(f"**{prefix}{cat.display_label}**")
        st.caption(cat.helper_text)
        # Button — primary style when selected so it's obvious which
        # tile is active. Full container width so tiles look uniform.
        clicked = st.button(
            "Selected" if selected else "Select",
            key=f"intake_wiz_tile_{cat.value}",
            type="primary" if selected else "secondary",
            use_container_width=True,
            disabled=selected,  # can't re-select the current tile
        )
        if clicked:
            intake.complaint_category = cat
            intake.skipped = False
            if intake.created_utc is None:
                intake.created_utc = datetime.now(timezone.utc)
            set_intake(session_state, intake)
            st.rerun()


# --------------------------------------------------------------------
# Section 2: User + Time scope
# --------------------------------------------------------------------


def _render_step2_scope(
    session_state: Any,
    intake: IntakeContext,
    summary: Any,
) -> IntakeContext:
    with st.container(border=True):
        st.markdown("#### Step 2 · Which user and when?")
        st.caption(
            "Narrowing to a specific user or time window sharpens the "
            "correlator output. Leave blank if you're not sure — "
            "defaults look at the whole bundle."
        )

        # ---- User field ----
        placeholder_user = resolve_user_from_summary(summary)
        user_help = (
            "Prefilled from the bundle's loginName (or hostname if "
            "loginName is empty). Override with any email, username, "
            "or free text if you know the affected user."
        )
        # If intake.user is empty and we have a placeholder, seed the
        # field with the placeholder so the operator sees a suggested
        # value they can either accept or edit.
        current_user = intake.user or placeholder_user
        user_new = st.text_input(
            "Which user reported the issue?",
            value=current_user,
            key="intake_wiz_user",
            placeholder=placeholder_user or "user@example.invalid or HOSTNAME",
            help=user_help,
        )
        if user_new != intake.user:
            intake.user = user_new
            if user_new.strip():
                intake.skipped = False

        # ---- Time scope selector ----
        st.markdown("**When did the customer experience the issue?**")
        # radio with 4 kinds; use format_func to render display labels.
        kinds = [
            TimeScopeKind.WHOLE_BUNDLE,
            TimeScopeKind.LAST_30_MIN,
            TimeScopeKind.SPECIFIC_TIMESTAMP,
            TimeScopeKind.SINCE_LAST_BOOT,
        ]
        selected_kind = st.radio(
            label="time_scope_kind",
            options=kinds,
            index=kinds.index(intake.time_scope.kind),
            format_func=lambda k: k.display_label,
            key="intake_wiz_time_kind",
            label_visibility="collapsed",
        )
        if selected_kind != intake.time_scope.kind:
            intake.time_scope.kind = selected_kind
            if selected_kind != TimeScopeKind.WHOLE_BUNDLE:
                intake.skipped = False

        # ---- Conditional: specific date-time + window ----
        if selected_kind == TimeScopeKind.SPECIFIC_TIMESTAMP:
            col_date, col_time, col_win = st.columns([2, 2, 2])
            with col_date:
                anchor_seed = (
                    intake.time_scope.anchor_utc.date()
                    if intake.time_scope.anchor_utc
                    else datetime.now(timezone.utc).date()
                )
                d: Optional[date] = st.date_input(
                    "Date (UTC)",
                    value=anchor_seed,
                    key="intake_wiz_anchor_date",
                )
            with col_time:
                anchor_time_seed = (
                    intake.time_scope.anchor_utc.time()
                    if intake.time_scope.anchor_utc
                    else time(0, 0)
                )
                t: Optional[time] = st.time_input(
                    "Time (UTC)",
                    value=anchor_time_seed,
                    key="intake_wiz_anchor_time",
                    step=60,  # minute-granularity is plenty
                )
            with col_win:
                w: int = st.number_input(
                    "± window (minutes)",
                    min_value=1,
                    max_value=1440,  # 24h ceiling
                    value=int(intake.time_scope.window_min),
                    step=5,
                    key="intake_wiz_anchor_window",
                    help=(
                        "Half-width of the correlator window. e.g. 10 "
                        "means the analysis looks at anchor±10 min."
                    ),
                )

            if d is not None and t is not None:
                new_anchor = datetime(
                    d.year, d.month, d.day,
                    t.hour, t.minute, 0,
                    tzinfo=timezone.utc,
                )
                if new_anchor != intake.time_scope.anchor_utc:
                    intake.time_scope.anchor_utc = new_anchor
                    intake.skipped = False
            if int(w) != intake.time_scope.window_min:
                intake.time_scope.window_min = int(w)

    return intake


# --------------------------------------------------------------------
# Footer: skip / reset
# --------------------------------------------------------------------


def _render_footer(session_state: Any, intake: IntakeContext) -> None:
    st.divider()
    col_left, col_right = st.columns([4, 2])
    with col_left:
        st.caption(intake.summary_line())
    with col_right:
        skip_clicked = st.button(
            "Skip intake — run everything",
            key="intake_wiz_skip",
            type="secondary",
            use_container_width=True,
            help=(
                "Resets the wizard and analyzes the bundle with "
                "severity-only ranking — same as pre-wizard BundleScope."
            ),
        )
        if skip_clicked:
            mark_skipped(session_state)
            st.rerun()
