"""Summary-first guided triage view."""

from __future__ import annotations

import html
from typing import Any

import streamlit as st

from zcc_diag.evidence_catalog import build_recap
from zcc_diag.ui.bundle_recap import render_bundle_recap
from zcc_diag.ui.geoip_status import render_landing_card


_FOCUS = [
    "Show me the biggest problem",
    "Private app won't connect",
    "Internet tunnel won't connect",
    "DNS / name resolution",
    "Slow or intermittent",
    "Packet capture",
]

_NOVICE_FOCUS = [
    "Find the main problem",
    "A private app is not working",
    "Internet access is not working",
    "A website name will not resolve",
    "Connections are slow or unreliable",
]

_NOVICE_TO_ENGINE = {
    "Find the main problem": "Show me the biggest problem",
    "A private app is not working": "Private app won't connect",
    "Internet access is not working": "Internet tunnel won't connect",
    "A website name will not resolve": "DNS / name resolution",
    "Connections are slow or unreliable": "Slow or intermittent",
}


def _plain_text(value: str) -> str:
    """Translate internal product shorthand without changing evidence."""
    replacements = (
        ("M-Tunnel", "private app connection"),
        ("m-tunnel", "private app connection"),
        ("ZIA tunnel", "internet connection"),
        ("ZPA tunnel", "private app connection"),
        ("ZIA", "internet protection"),
        ("ZPA", "private access"),
        ("SERVER_DOWN_ERROR", "server connection error"),
        ("FIREWALL_BLOCK_ERROR", "firewall block"),
        ("TUNNEL_FORWARDING", "connected"),
        ("NXDOMAIN", "name not found"),
        ("TCP RST", "connection reset"),
        ("TCP", "network connection"),
        ("TLS", "secure connection"),
    )
    result = str(value or "")
    for old, new in replacements:
        result = result.replace(old, new)
    return result


def _finding_card(finding: Any, *, primary: bool = False, pro_mode: bool = True) -> None:
    severity = finding.severity if finding.severity in {
        "critical", "warning", "info", "success"
    } else "info"
    labels = {
        "hard": ("Hard failure", "Needs attention"),
        "soft": ("Intermittent / degraded", "Recovered or intermittent"),
        "policy": ("Policy decision", "Blocked by a rule"),
        "coverage": ("Evidence gap", "More logs needed"),
        "healthy": ("No explicit failure", "No clear failure found"),
    }
    label = {
        key: values[0] if pro_mode else values[1]
        for key, values in labels.items()
    }.get(finding.kind, finding.kind.title())
    primary_class = " la-finding-primary" if primary else ""
    code = finding.code if pro_mode else ""
    area = f" · {html.escape(finding.area)}" if pro_mode else ""
    title = finding.title if pro_mode else _plain_text(finding.title)
    conclusion = finding.conclusion if pro_mode else _plain_text(finding.conclusion)
    evidence = finding.evidence if pro_mode else _plain_text(finding.evidence)
    next_action = finding.next_action if pro_mode else _plain_text(finding.next_action)
    doc = (
        f'<a href="{html.escape(finding.doc_url)}" target="_blank">'
        f'{"Zscaler guidance" if pro_mode else "Learn more from Zscaler"} ↗</a>'
        if finding.doc_url else ""
    )
    st.markdown(
        f"""
        <div class="la-finding la-finding-{severity}{primary_class}">
          <div class="la-finding-top">
            <span class="la-finding-label">{html.escape(label)}{area}</span>
            <span class="la-finding-code">{html.escape(code)}</span>
          </div>
          <h3>{html.escape(title)}</h3>
          <p>{html.escape(conclusion)}</p>
          <div class="la-evidence"><b>{"Evidence" if pro_mode else "Why"}</b><span>{html.escape(evidence)}</span></div>
          <div class="la-action"><b>{"Do this next" if pro_mode else "Try this"}</b><span>{html.escape(next_action)}</span></div>
          {doc}
        </div>
        """,
        unsafe_allow_html=True,
    )
    sample = getattr(finding, "sample", None)
    if sample is not None:
        when = sample.ts.isoformat() if getattr(sample, "ts", None) else "time unavailable"
        st.caption(
            f"Sample matching record · {sample.source_file}:{sample.line_no} · {when}"
        )
        st.code(sample.body, language=None, wrap_lines=True)
    display_filter = getattr(finding, "wireshark_filter", "") or ""
    if display_filter:
        st.markdown("**Verify this in Wireshark**")
        st.caption(
            "Open the named `.pcapng` capture in Wireshark and paste this into the "
            "Display Filter bar. Use the copy button on the filter block."
        )
        st.code(display_filter, language=None, wrap_lines=True)


def render_quick_triage(
    triage: Any, facts: Any, *, rotations_read: int,
    rotations_found: int, pro_mode: bool = True, service_scope: str = "All",
    pac_documents: int = 0,
) -> None:
    st.markdown("## Guided summary" if pro_mode else "## What seems to be wrong?")
    if pro_mode:
        st.caption(
            "Choose the user's symptom. Results are reordered from direct tunnel and packet evidence."
        )
    focus = st.radio(
        "What are you trying to fix?",
        _FOCUS if pro_mode else _NOVICE_FOCUS,
        horizontal=True,
        key=f"rapid_triage_focus_{'pro' if pro_mode else 'novice'}",
    )
    findings = triage.for_focus(_NOVICE_TO_ENGINE.get(focus, focus))
    scoped = triage.for_scope(service_scope)
    scoped_ids = {id(finding) for finding in scoped}
    findings = [finding for finding in findings if id(finding) in scoped_ids] or scoped

    hard_count = sum(1 for f in findings if f.kind in {"hard", "policy"})
    top = findings[0]
    status = (
        "Action required" if top.severity == "critical"
        else "Review needed" if top.severity == "warning"
        else "No hard failure"
    )
    if pro_mode:
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Rapid verdict", status)
        k2.metric("Hard / policy signals", hard_count)
        k3.metric("Failed M-Tunnels", triage.failed_sessions)
        k4.metric("Packet captures", len(triage.pcap_summaries))

    _finding_card(top, primary=True, pro_mode=pro_mode)

    # Directly under the leading conclusion: a verdict about a device is hard to
    # act on until you know whose device, what window the evidence covers, and
    # what was collected. Kept above the supporting signals so it is visible
    # without scrolling past the fold.
    render_bundle_recap(
        build_recap(
            facts,
            pcaps=triage.pcap_summaries,
            pac_documents=pac_documents,
            rotations_read=rotations_read,
            rotations_found=rotations_found,
        ),
        pro_mode=pro_mode,
    )

    visible_supporting = findings[1:5] if pro_mode else findings[1:3]
    if visible_supporting:
        with st.expander(
            "Technical signals" if pro_mode else "Other things worth checking",
            expanded=pro_mode,
        ):
            for finding in visible_supporting:
                _finding_card(finding, pro_mode=pro_mode)
            if not pro_mode and len(findings) > 3:
                st.caption("Switch to Pro for every technical signal and the underlying records.")

    if pro_mode:
        st.markdown("### Investigation path")
        c1, c2, c3 = st.columns(3)
        c1.info(
            "**1 · Confirm the window**\n\n"
            f"Parsed span: {getattr(facts, 'first_ts', None) or 'unknown'} → "
            f"{getattr(facts, 'last_ts', None) or 'unknown'}"
        )
        c2.info(
            "**2 · Inspect the connection**\n\n"
            "Filter to a setup failure, policy block, reset, hostname, or application."
        )
        c3.info(
            "**3 · Check packet evidence**\n\n"
            + ("Follow a suggested problem stream." if triage.pcap_summaries
               else "No packet capture was included in this bundle.")
        )

    if rotations_found and rotations_read < rotations_found:
        if pro_mode:
            st.warning(
                f"This conclusion covers {rotations_read} of {rotations_found} compressed rotations. "
                "Increase history only if the incident falls outside the parsed time span."
            )
        else:
            st.caption("If this happened earlier than the analyzed time window, switch to Pro and expand the history.")


def render_collection_guidance(*, pro_mode: bool = True) -> None:
    """Upload guidance, paired with the endpoint-ownership readiness light.

    The MaxMind state sits beside the uploader rather than inside the Problem
    endpoints tab because it has to be actionable *before* a capture is
    analyzed — discovering afterwards that every endpoint is an unattributed
    address means re-reading the whole capture.
    """
    col_upload, col_geoip = st.columns(2, gap="small")
    with col_upload:
        st.markdown(
            f"""
            <div class="la-start-card">
              <b>UPLOAD</b><strong>Upload your ZCC log files</strong>
              <span>If you are not sure what is wrong, upload the entire support ZIP.
              For the fastest connection check, upload ZSATunnel.log by itself; it is the single best log in most cases.
              {'A full ZIP is also the right choice when you need policy, system, or packet-capture context.' if pro_mode else ''}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_geoip:
        render_landing_card()
