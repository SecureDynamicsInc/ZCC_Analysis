"""The at-a-glance panel: whose bundle this is, and what came with it.

Placed high on the guided summary, directly under the leading conclusion,
because both halves of it change how the conclusion should be read. A verdict
about a device means little until you know whose device, what window the
evidence covers, and whether a packet capture was included; and a reader who
does not yet know which log carries which evidence cannot tell a real absence
from a collection gap.

The evidence checklist therefore states what each log is expected to contain
whether or not it is present. That is deliberate: the missing rows are the ones
worth reading, and a bundle collected without the tunnel log should teach the
engineer what they are missing and why to ask for it.
"""

from __future__ import annotations

import html
from typing import Any

import streamlit as st

from zcc_diag.evidence_catalog import BundleRecap


def _cell(label: str, value: str, *, missing_note: str = "") -> str:
    shown = value.strip() or missing_note or BundleRecap.UNKNOWN
    muted = " la-recap-muted" if not value.strip() else ""
    return (
        f'<div class="la-recap-cell{muted}">'
        f'<span>{html.escape(label)}</span>'
        f'<strong>{html.escape(shown)}</strong>'
        f'</div>'
    )


def _render_identity(recap: BundleRecap, *, pro_mode: bool) -> None:
    cells = [
        _cell("User", recap.user),
        _cell("Device", recap.device),
        _cell("Operating system", recap.os_label),
        _cell("Client Connector", recap.zcc_version),
    ]
    span = [
        _cell("Evidence covers", recap.span_label),
        _cell("Span", recap.duration_label),
        _cell("Device time zone", recap.timezone_label),
        _cell(
            "Packet capture",
            (f"{recap.pcap_count} included" if recap.pcap_count else ""),
            missing_note="None included",
        ),
    ]
    st.markdown(
        '<div class="la-recap-grid">' + "".join(cells + span) + "</div>",
        unsafe_allow_html=True,
    )

    notes = []
    if recap.pcap_count and recap.pcap_window:
        notes.append(f"Capture window {recap.pcap_window}.")
    if pro_mode:
        notes.append(f"{recap.record_count:,} parsed records from {recap.log_file_count:,} log file(s).")
        if recap.rotations_found:
            notes.append(
                f"{recap.rotations_read} of {recap.rotations_found} compressed rotations read."
            )
        if recap.log_levels and not recap.has_debug_logging:
            notes.append(
                "No DEBUG records: the client was not in Debug log mode, so quiet "
                "subsystems may simply not have been logged."
            )
    if notes:
        st.caption(" ".join(notes))

    if not recap.user or not recap.device:
        st.caption(
            "A blank identity field means the value was not evidenced in the material "
            "read — not that it is empty on the device."
        )


def _render_checklist(recap: BundleRecap, *, pro_mode: bool) -> None:
    label = (
        f"What is in this bundle — {recap.present_count} of {len(recap.evidence)} evidence types present"
    )
    with st.expander(label, expanded=False):
        st.caption(
            "Every log ZCC can include, whether or not this bundle has it, with what "
            "each one is expected to tell you. Reading the missing rows is the point: "
            "an absence here is a collection gap, not a finding."
            if pro_mode else
            "The files Zscaler Client Connector can include, and what each one shows. "
            "A missing file means it was not collected — not that nothing happened."
        )
        for row in recap.evidence:
            mark = "✓" if row.present else "○"
            state = "la-check-on" if row.present else "la-check-off"
            detail = f" · {row.detail}" if row.detail else ""
            names = ", ".join(row.kind.filenames)
            st.markdown(
                f"""
                <div class="la-check-row {state}">
                  <span class="la-check-mark">{mark}</span>
                  <div>
                    <strong>{html.escape(row.kind.label_for(pro_mode=pro_mode))}</strong>
                    <em>{html.escape(names)}{html.escape(detail)}</em>
                    <span>{html.escape(row.kind.tells_you_for(pro_mode=pro_mode))}</span>
                    {'<span class="la-check-reach">' + html.escape(row.kind.reach_for_it) + '</span>' if pro_mode else ''}
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        st.caption(
            "Log definitions follow Zscaler's own: "
            "[Client Connector logs](https://help.zscaler.com/logs-fair-use/zscaler-client-connector-logs) "
            "and [packet capture](https://help.zscaler.com/zscaler-client-connector/enabling-packet-capture-zscaler-client-connector)."
        )


def render_bundle_recap(recap: Any, *, pro_mode: bool = True) -> None:
    """Identity, coverage, and the evidence checklist."""
    st.markdown("### This bundle at a glance" if pro_mode else "### What we are looking at")
    _render_identity(recap, pro_mode=pro_mode)

    missing = recap.missing_important
    if missing:
        names = ", ".join(row.kind.label_for(pro_mode=pro_mode) for row in missing)
        st.warning(
            f"**Not included: {names}.** Conclusions below are limited to the evidence "
            "that was collected. Expand the checklist to see what each missing item "
            "would have shown."
        )
    _render_checklist(recap, pro_mode=pro_mode)
