"""Guided Streamlit view for documented Zscaler codes."""

from __future__ import annotations

from typing import Any, Sequence

import streamlit as st

from zcc_diag.error_code_help import CodeExplanation, detect_documented_codes, explain_code


def _matches_scope(item: CodeExplanation, service_scope: str) -> bool:
    if service_scope == "All" or item.source.startswith("ZCC"):
        return True
    return item.product == service_scope or item.source.startswith(service_scope)


def _render_explanation(
    item: CodeExplanation, *, detected: bool, pro_mode: bool, sample: Any = None,
) -> None:
    count = f" · found {item.occurrences:,} time(s)" if detected else ""
    with st.expander(f"{item.code} · {item.label}{count}", expanded=detected):
        st.caption(f"{item.product or item.source} · {item.severity.title()} severity")
        if item.description and item.description != item.label:
            st.markdown(f"**What it means:** {item.description}")
        if item.resolution:
            st.markdown(f"**What to try:** {item.resolution}")
        if detected and sample is not None:
            when = sample.ts.isoformat() if getattr(sample, "ts", None) else "time unavailable"
            st.caption(
                f"Sample matching record · {sample.source_file}:{sample.line_no} · {when}"
            )
            st.code(sample.body, language=None, wrap_lines=True)
        if pro_mode:
            st.caption(f"Reference family: {item.source}")
        if item.source_url:
            st.markdown(f"[Open the Zscaler reference]({item.source_url})")


def render_error_code_help(
    log_index: Any = None,
    sessions: Sequence[Any] = (),
    signals: Any = None,
    *,
    pro_mode: bool = False,
    standalone: bool = False,
    service_scope: str = "All",
) -> None:
    st.markdown("## Error code help" if not standalone else "### Already have an error code?")
    st.caption(
        "Enter the code shown by Zscaler Client Connector or found in the logs. "
        "The result explains what it means and the documented next step."
    )

    if not standalone:
        detected = detect_documented_codes(
            log_index,
            sessions=sessions,
            signal_counts=getattr(signals, "code_counts", None),
        )
        detected = [item for item in detected if _matches_scope(item, service_scope)]
        if detected:
            st.markdown("### Codes found in these logs")
            limit = 30 if pro_mode else 8
            samples = getattr(signals, "code_examples", {}) or {}
            for item in detected[:limit]:
                _render_explanation(
                    item, detected=True, pro_mode=pro_mode,
                    sample=samples.get(item.code),
                )
            if len(detected) > limit:
                st.caption(f"Switch to Pro to review {len(detected) - limit} additional documented code matches.")
        else:
            st.info(
                "No documented Zscaler error or session code was identified in the selected logs. "
                "You can still look up a code reported by the user below."
            )

    query = st.text_input(
        "Zscaler error or status code",
        placeholder="Examples: -13, 2, 42016, BRK_MT_SETUP_FAIL",
        key=f"code_help_{'standalone' if standalone else 'bundle'}_{'pro' if pro_mode else 'novice'}",
    ).strip()
    if not query:
        return

    results = [
        item for item in explain_code(query, limit=50)
        if _matches_scope(item, service_scope)
    ][:20 if pro_mode else 8]
    if not results:
        st.warning(
            "That code is not in the bundled Zscaler reference. Check the spelling and sign, "
            "then use Pro evidence search to find the exact surrounding log record."
        )
        return

    st.markdown("### Documented result")
    for item in results:
        _render_explanation(item, detected=False, pro_mode=pro_mode)
