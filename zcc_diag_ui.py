# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""ZCC Log Explorer — guided local diagnosis over the measured engine.

The default experience is conclusion-first. Novice exposes What we found and
Fix a connection; Pro adds packet analysis and deep evidence.
Every finding is tied to an explicit tunnel state, reconstructed M-Tunnel
session, documented Zscaler status code, or observed packet field.
"""

from __future__ import annotations

import hashlib
import html
import sys
import uuid
from pathlib import Path
from typing import Any, Tuple

import streamlit as st

# Ensure relative imports work when launched via "streamlit run".
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from zcc_diag.bundle import open_bundle, ExtractedBundle  # noqa: E402
from zcc_diag.log_index import build_index, LogIndex  # noqa: E402
from zcc_diag.log_store import (  # noqa: E402
    InsufficientDiskSpace,
    build_store,
    estimate_source_bytes,
)
from zcc_diag.facts_extract import derive_facts, FactsSnapshot  # noqa: E402
from zcc_diag.id_inventory import build_inventory, IdInventory  # noqa: E402
from zcc_diag.local_intake import (  # noqa: E402
    IntakeError,
    SUPPORTED_INPUT_EXTENSIONS,
    prepare_inputs,
)
from zcc_diag.pcap_review import scan_bundle as scan_bundle_pcaps  # noqa: E402
from zcc_diag.pac_extract import scan_bundle as scan_bundle_pacs  # noqa: E402
from zcc_diag.zpa_session_correlator import extract_zpa_sessions  # noqa: E402
from zcc_diag.rapid_triage import (  # noqa: E402
    build_rapid_triage,
    pcap_summaries_to_ui,
    scan_tunnel_signals,
)
from zcc_diag.ui._components import inject_css  # noqa: E402
from zcc_diag.ui.quick_triage import (  # noqa: E402
    render_collection_guidance,
    render_quick_triage,
)
from zcc_diag.ui.tunnel_apps import render_tunnel_apps  # noqa: E402
from zcc_diag.ui.error_code_help import render_error_code_help  # noqa: E402
from zcc_diag.ui.error_reference import render_error_reference  # noqa: E402
from zcc_diag.ui.update_notice import render_update_notice  # noqa: E402
from zcc_diag.ui.endpoint_intelligence import render_endpoint_intelligence  # noqa: E402
from zcc_diag.ui.pac_files import render_pac_files  # noqa: E402
from zcc_diag.ui.tunnel_log import (  # noqa: E402
    inject_tunnel_css,
    render_tunnel_log_view,
)
from zcc_diag.ui.packet_capture import render_packet_capture_workbench  # noqa: E402
from zcc_diag.ui.facts import render_facts  # noqa: E402
from zcc_diag.ui.buckets import render_buckets  # noqa: E402
from zcc_diag.ui.entities import render_entities  # noqa: E402
from zcc_diag.ui.search import render_search  # noqa: E402
from zcc_diag.ui.session import render_session  # noqa: E402
from zcc_diag.ui.timeline import render_timeline  # noqa: E402
from zcc_diag.ui.deep_dive import render_deep_dive  # noqa: E402
from zcc_diag.ui.inventories import render_inventories  # noqa: E402
from zcc_diag.ui.raw import render_raw  # noqa: E402
from zcc_diag.transient_runtime import (  # noqa: E402
    RUN_MANAGER,
    TransientRun,
    clear_customer_session_state,
)

# --------------------------------------------------------------------------
# Pipeline version — bumped every rebuild slice. Slice 9 adds the
# service×subsystem line classifier (Buckets), rebuilds Facts around a
# single merged Identity section, and splits ZIA/ZPA cloud. v7 adds PAC
# document recovery and the endpoint-ownership readiness light.
# --------------------------------------------------------------------------
_PIPELINE_VERSION = "guided-triage-v7-2026-08-19"


st.set_page_config(
    page_title="ZCC Log Explorer",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# A page refresh creates a new Streamlit session token. Activating it destroys
# any workspace owned by the prior page. The manager is process-global on
# purpose: this localhost tool permits one customer run at a time, even across
# multiple tabs.
if "_privacy_session_token" not in st.session_state:
    st.session_state["_privacy_session_token"] = uuid.uuid4().hex
_privacy_session_token = st.session_state["_privacy_session_token"]
RUN_MANAGER.activate_session(_privacy_session_token)

# The two audience levels are deliberately different products on the same
# evidence engine. Novice hides parsing mechanics and raw evidence; Pro keeps
# the full investigation workbench.
control_mode, control_service, control_theme = st.columns([3, 3, 1])
with control_mode:
    experience = st.segmented_control(
        "Experience level",
        ["Novice", "Pro"],
        default="Novice",
        key="experience_level",
        help="Novice gives a short guided answer. Pro exposes log-depth, packet-stream, and raw-evidence controls.",
    ) or "Novice"
with control_service:
    service_scope = st.segmented_control(
        "Service view",
        ["All", "ZIA", "ZPA"],
        default="All",
        key="service_scope",
        help="ZIA focuses on internet and SaaS access. ZPA focuses on private applications.",
    ) or "All"
with control_theme:
    light_mode = st.toggle("Light mode", value=False, key="light_mode")

pro_mode = experience == "Pro"
inject_css("light" if light_mode else "dark")


def _active_port(default: int = 8501) -> int:
    """The port this instance is actually serving on.

    ``run_local.py`` moves to the next free port when 8501 is taken and records
    the choice in ``.run/active_port``. Reading it keeps the on-page "open this
    app at ..." instruction from naming a port the user is not on — which was
    exactly the case when a second copy started alongside the installed one.
    """
    try:
        recorded = (_HERE / ".run" / "active_port").read_text(encoding="utf-8").strip()
    except OSError:
        return default
    return int(recorded) if recorded.isdigit() else default


def _bundle_digest(uploaded_bytes: bytes) -> str:
    return hashlib.sha256(uploaded_bytes).hexdigest()[:16]


def _load_bundle_state(
    run: TransientRun, zip_bytes: bytes, cache_key: str,
    original_name: str = "bundle.zip",
    rotation_depth: int = 0,
) -> Tuple[ExtractedBundle, object, FactsSnapshot]:
    """Extract and index inside the current session's disposable workspace."""
    memo_key = f"bundle:{cache_key}"
    if memo_key in run.memo:
        return run.memo[memo_key]

    # Never write the customer-provided filename to disk.  The display name is
    # retained in RAM and assigned to Facts after parsing.
    zip_path = run.upload_path
    zip_path.write_bytes(zip_bytes)
    extracted = open_bundle(zip_path, temp_parent=run.root)
    run.add_cleanup(extracted.cleanup)

    # `rotation_depth` is how many compressed rotations to read per
    # component. 0 = plain .log only (the pre-Slice-12 behaviour);
    # -1 = every rotation. The store is SQLite-backed, so "every" is
    # actually feasible — a bundle with ~1,100 rotations holds ~40x more
    # lines than its plain logs and reaches weeks further back.
    idx = build_store(
        str(extracted.root),
        max_rotations_per_component=(
            None if rotation_depth < 0 else (rotation_depth or None)
        ),
        read_rotations=(rotation_depth != 0),
        db_dir=str(run.root),
    )
    run.add_cleanup(idx.cleanup)

    facts = derive_facts(extracted, idx)
    facts.bundle_name = original_name
    result = (extracted, idx, facts)
    run.memo[memo_key] = result
    return result


def _load_inventory(run: TransientRun, cache_key: str, _idx: LogIndex) -> IdInventory:
    """Build the bundle-wide ID inventory once and share it across the
    Facts, Session and Buckets tabs. Cached on the same `cache_key` as
    the LogIndex so a new bundle rebuilds it.

    `_idx` is underscore-prefixed deliberately: that's Streamlit's
    opt-out from hashing an argument. Without it the cache decorator
    walks the entire LogIndex — millions of IndexedLine objects — to
    compute a hash on EVERY rerun of EVERY tab, which costs far more
    than the work being cached. `cache_key` already identifies the
    bundle uniquely, so the index needs no hashing of its own.
    """
    memo_key = f"inventory:{cache_key}"
    if memo_key not in run.memo:
        run.memo[memo_key] = build_inventory(_idx)
    return run.memo[memo_key]


def _load_guided_state(
    run: TransientRun, cache_key: str, _idx: Any, _extracted: ExtractedBundle,
):
    """Build the high-signal investigation model once per bundle/depth."""
    memo_key = f"guided:{cache_key}"
    if memo_key not in run.memo:
        sessions = extract_zpa_sessions(_idx)
        signals = scan_tunnel_signals(_idx)
        pcaps = scan_bundle_pcaps(_extracted.root)
        triage = build_rapid_triage(sessions, signals, pcaps)
        run.memo[memo_key] = (
            sessions, pcaps, pcap_summaries_to_ui(pcaps), triage,
        )
    return run.memo[memo_key]


def _load_pac_scan(run: TransientRun, cache_key: str, _extracted: ExtractedBundle):
    """Recover PAC documents once per bundle.

    Kept out of `_load_guided_state` because it walks the extracted tree
    rather than the line index, and because a PAC is a standalone artefact
    that no triage finding depends on.
    """
    memo_key = f"pac:{cache_key}"
    if memo_key not in run.memo:
        run.memo[memo_key] = scan_bundle_pacs(_extracted.root)
    return run.memo[memo_key]


# --------------------------------------------------------------------------
# Landing page
# --------------------------------------------------------------------------
st.markdown(
    f"""
    <div class="la-hero">
      <div class="la-brand-row">
        <span class="la-brand-mark">Z</span>
        <span class="la-eyebrow">SECUREDYNAMICS · LOCAL WORKSPACE</span>
        <span class="la-local-pill">HTTP · 127.0.0.1 only</span>
      </div>
      <h1>ZCC Log Explorer</h1>
      <p>Find the connection failure, see the exact evidence, and get the next
      troubleshooting action — without sending customer logs off the workstation.</p>
      <div class="la-pipeline">Analysis engine · {_PIPELINE_VERSION}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

render_collection_guidance(pro_mode=pro_mode)
st.caption(
    f"Open this local app with **http://127.0.0.1:{_active_port()}** — HTTP, not HTTPS."
)
st.info(
    "**Private one-run workspace:** diagnostic files and findings stay on this "
    "workstation for this page session only. Refreshing, resetting, or selecting "
    "a different upload destroys the prior run. Nothing is retained as a case, "
    "policy, issue, learned fact, report, or recent-upload cache."
)

if st.button("Reset and destroy this run", type="secondary"):
    RUN_MANAGER.purge(_privacy_session_token)
    st.session_state["_upload_widget_generation"] = (
        int(st.session_state.get("_upload_widget_generation", 0)) + 1
    )
    clear_customer_session_state(st.session_state, preserve_current_upload=False)
    st.rerun()

with st.expander("About, license, and official distribution"):
    st.markdown(
        """
        **ZCC Log Explorer** is an independent SecureDynamics community project
        that processes selected diagnostic files locally on this workstation.

        Copyright 2026 SecureDynamics, Inc. Licensed under the
        [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
        The license permits forks and redistribution but does not grant rights
        to SecureDynamics names, logos, or official-release branding.

        **Official source:**
        [SecureDynamicsInc/ZCC_Analysis](https://github.com/SecureDynamicsInc/ZCC_Analysis)

        **Official project page:**
        [securedynamics.net/zcc-log-explorer](https://securedynamics.net/zcc-log-explorer)

        Community forks must use their own name and branding and may not imply
        endorsement, certification, or support by SecureDynamics. Zscaler and
        its product names are trademarks of Zscaler, Inc. This project is not
        affiliated with, endorsed by, or supported by Zscaler.
        """
    )

# Check the installed code before diagnostic bytes enter the session. This
# read-only Git check receives no upload name, content, or derived value.
render_update_notice(_HERE, pro_mode=pro_mode)

_upload_generation = int(st.session_state.get("_upload_widget_generation", 0))
uploaded_files = st.file_uploader(
    "Upload your ZCC log files",
    type=sorted(ext.lstrip(".") for ext in SUPPORTED_INPUT_EXTENSIONS),
    accept_multiple_files=True,
    key=f"diagnostic_upload_{_upload_generation}",
    help="Use one ZIP bundle, one standalone log, or several individual logs. "
         "Do not mix a ZIP with standalone files.",
)

if not uploaded_files:
    RUN_MANAGER.purge(_privacy_session_token)
    if pro_mode:
        st.markdown(
            """
            <div class="la-start-grid">
              <div class="la-start-card"><b>1</b><strong>Upload</strong>
              <span>Use the full ZIP by default, or a tunnel log for a focused check.</span></div>
              <div class="la-start-card"><b>2</b><strong>Analyze</strong>
              <span>Review connection, M-Tunnel, DNS, TCP, and TLS evidence.</span></div>
              <div class="la-start-card"><b>3</b><strong>Confirm</strong>
              <span>Drill into session records or follow the matching packet stream.</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div class="la-start-grid">
              <div class="la-start-card"><b>1</b><strong>Upload</strong>
              <span>Use the full ZIP when the cause is unknown, or ZSATunnel.log for the fastest connection check.</span></div>
              <div class="la-start-card"><b>2</b><strong>See the likely problem</strong>
              <span>The analyzer leads with the clearest connection issue it found.</span></div>
              <div class="la-start-card"><b>3</b><strong>Try the next step</strong>
              <span>Follow the recommended action, then check whether the connection works.</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.divider()
    render_error_code_help(pro_mode=pro_mode, standalone=True)
    with st.expander("Browse all known Zscaler errors and fixes"):
        render_error_reference()
    st.stop()

try:
    prepared = prepare_inputs([
        (item.name, item.getvalue()) for item in uploaded_files
    ])
except IntakeError as exc:
    st.error(str(exc))
    st.stop()

zip_bytes = prepared.bundle_bytes
digest = _bundle_digest(zip_bytes)

prior_run = RUN_MANAGER.active_run
if prior_run is None or prior_run.upload_digest != digest:
    clear_customer_session_state(st.session_state)
run = RUN_MANAGER.begin(_privacy_session_token, digest)
run.own_upload_handles(list(uploaded_files))

st.caption(
    f"Selected: **{html.escape(prepared.display_name)}** · "
    f"{prepared.source_kind} · {prepared.file_count:,} file(s) · processed locally"
)

# ---- How deep to read ------------------------------------------------
# ZCC compresses its older log rotations into .log.zip. Measured across
# the corpus, the plain .log files hold ~9% of the lines actually present
# — one bundle went from 322,701 lines (46 days) to 13,491,198 lines
# (79 days) once rotations were read. Depth is a control rather than a
# default because reading everything costs real disk and minutes.
_DEPTH_CHOICES = {
    "Plain logs only — fastest": 0,
    "+ newest 10 rotations per component": 10,
    "+ newest 50 rotations per component": 50,
    "+ newest 200 rotations per component": 200,
    "Everything (all rotations)": -1,
}
if pro_mode:
    with st.expander("Pro analysis settings", expanded=False):
        depth_label = st.selectbox(
            "History to analyze", list(_DEPTH_CHOICES), index=1, key="_depth",
            help="Read more compressed history only when the incident is older than the current analysis window.",
        )
        st.caption(
            "More history can take several minutes and several gigabytes on a large bundle."
        )
    rotation_depth = _DEPTH_CHOICES[depth_label]
else:
    # A useful recent window without exposing rotation mechanics to a new user.
    rotation_depth = 10

cache_key = f"{digest}|{_PIPELINE_VERSION}|depth{rotation_depth}"

try:
    with st.spinner(
        "Extracting, indexing"
        + (" (reading compressed rotations — this can take a few minutes "
           "on a large bundle)" if rotation_depth != 0 else "")
        + "..."
    ):
        extracted, idx, facts = _load_bundle_state(
            run, zip_bytes, cache_key, original_name=prepared.display_name,
            rotation_depth=rotation_depth,
        )
except InsufficientDiskSpace as e:
    st.error(f"**Not enough disk space to index this bundle at this depth.**"
             f"\n\n{e}")
    st.info("Pick a shallower **Log depth** above, or free up disk space.")
    st.stop()

# Facts reads the bundle name off the temp file we wrote; make sure it
# reports what the user actually uploaded even if a cached entry was
# created under a different name.
facts.bundle_name = prepared.display_name

_rot_found = getattr(idx, "rotations_found", 0)
_rot_read = getattr(idx, "rotations_read", 0)

with st.spinner("Reconstructing tunnel attempts and checking packet evidence…"):
    zpa_sessions, pcap_summaries, pcap_data, triage = _load_guided_state(
        run, cache_key, idx, extracted
    )

with st.spinner("Looking for a PAC file…"):
    pac_scan = _load_pac_scan(run, cache_key, extracted)

if not pro_mode:
    # Novice only gets the PAC tab when there is a PAC to read; an empty tab
    # is a question a new user cannot answer.
    novice_labels = [
        "What we found", "Fix a connection", "Raw ZSATunnel log",
        "Error code help", "Known errors",
    ]
    if pac_scan.found:
        novice_labels.append("Proxy settings (PAC)")
    novice_tabs = st.tabs(novice_labels)
    tab_start, tab_tunnel, tab_rawlog, tab_codes, tab_reference = novice_tabs[:5]
    with tab_start:
        render_quick_triage(
            triage, facts, rotations_read=_rot_read,
            rotations_found=_rot_found, pro_mode=False,
            service_scope=service_scope, pac_documents=pac_scan.found,
        )
    with tab_tunnel:
        render_tunnel_apps(
            zpa_sessions, triage.signals,
            pro_mode=False, service_scope=service_scope,
        )
    with tab_codes:
        render_error_code_help(
            idx, zpa_sessions, triage.signals,
            pro_mode=False, service_scope=service_scope,
        )
    with tab_reference:
        render_error_reference(triage.signals)
    with tab_rawlog:
        inject_tunnel_css()
        render_tunnel_log_view(idx, pro_mode=False, cache_key=cache_key)
    if pac_scan.found:
        with novice_tabs[5]:
            render_pac_files(pac_scan, pro_mode=False)
else:
    (tab_start, tab_tunnel, tab_rawlog, tab_codes, tab_reference, tab_endpoints,
     tab_pcap, tab_pac, tab_advanced) = st.tabs([
        "Guided summary",
        f"Tunnels & apps ({triage.failed_sessions})",
        "Raw ZSATunnel log",
        "Error code help",
        "Known error reference",
        "Problem endpoints",
        f"Packet analysis ({len(pcap_summaries)})",
        f"PAC files ({pac_scan.found})",
        "Deep evidence",
    ])

    with tab_start:
        render_quick_triage(
            triage, facts, rotations_read=_rot_read,
            rotations_found=_rot_found, pro_mode=True,
            service_scope=service_scope, pac_documents=pac_scan.found,
        )

    with tab_tunnel:
        render_tunnel_apps(
            zpa_sessions, triage.signals,
            pro_mode=True, service_scope=service_scope,
        )

    with tab_codes:
        render_error_code_help(
            idx, zpa_sessions, triage.signals,
            pro_mode=True, service_scope=service_scope,
        )

    with tab_reference:
        render_error_reference(triage.signals)

    with tab_pcap:
        render_packet_capture_workbench(pcap_data)

    with tab_endpoints:
        render_endpoint_intelligence(pcap_data)

    with tab_rawlog:
        inject_tunnel_css()
        render_tunnel_log_view(idx, pro_mode=True, cache_key=cache_key)

    with tab_pac:
        render_pac_files(pac_scan, pro_mode=True)

    with tab_advanced:
        st.markdown("## Deep evidence")
        st.caption(
            "Load detailed metadata, arbitrary search, traffic grouping, inventories, and raw records."
        )
        if not st.toggle("Load deep workspace", value=False):
            st.info("Turn this on when the guided views do not settle the case.")
        else:
            with st.spinner("Building the detailed evidence inventory…"):
                inv = _load_inventory(run, cache_key, idx)
            (adv_search, adv_session, adv_timeline, adv_flow, adv_facts,
             adv_map, adv_inv, adv_raw) = st.tabs([
                "Search", "Session", "Timeline", "Traffic", "Facts",
                "Evidence map", "Inventories", "Raw",
            ])
            with adv_search:
                render_search(idx, cache_key=cache_key)
            with adv_session:
                render_session(idx, cache_key=cache_key, inv=inv)
            with adv_timeline:
                render_timeline(idx, cache_key=cache_key)
            with adv_flow:
                render_deep_dive(extracted, idx, cache_key=cache_key)
            with adv_facts:
                render_facts(facts, inv=inv)
            with adv_map:
                map_entities, map_buckets = st.tabs(["Entities", "Coverage buckets"])
                with map_entities:
                    render_entities(idx, cache_key=cache_key, inv=inv)
                with map_buckets:
                    render_buckets(idx, cache_key=cache_key)
            with adv_inv:
                render_inventories(
                    extracted, idx, cache_key=cache_key,
                    os_family=facts.os_family or "",
                )
            with adv_raw:
                render_raw(idx)

            if _rot_found:
                st.caption(
                    f"Coverage: {_rot_read} of {_rot_found} compressed rotations read; "
                    f"{getattr(idx, 'plain_logs_read', 0)} plain logs; "
                    f"{getattr(idx, 'total_lines', 0):,} indexed records."
                )
            for _msg in getattr(idx, "archives_unreadable", [])[:3]:
                st.caption(f"Not readable: {_msg}")
