"""Inventories view — Slice 5 of the Log-Analyzer rebuild (2026-08-07).

Config snapshots + non-log artifact inventories + reference-code
lookup. One tab, expanders for each section so the operator can
scan quickly then drill in.

Sections:
    * App Profile (JSON)
    * Forwarding Profile details (On-Trusted / Off-Trusted / VPN)
    * Posture profiles + Trust conditions
    * Configured VPN bypass inventory
    * Session info (extracted identity)
    * PCAP inventory (files + capture windows + top DNS/SNI/IPs)
    * UPM SQLite inventory (files + table row counts)
    * XML event files + other bundle artifacts
    * Reference-code lookup (search across all `data/` modules)
    * Extractor diagnostics
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

import streamlit as st

from ..log_index import LogIndex
from ..snapshots import BundleSnapshots, build_snapshots
from ..code_lookup import lookup_code, known_sources
from ..bundle import ExtractedBundle


# --------------------------------------------------------------------------
# Cached snapshot build
# --------------------------------------------------------------------------

def _cached_snapshots(cache_key: str,
                      _bundle: ExtractedBundle,
                      _idx: LogIndex,
                      os_family: str) -> BundleSnapshots:
    """Snapshot build is expensive (PCAP scan, SQLite enumeration). Cache
    it per bundle so switching tabs is instant."""
    return build_snapshots(_bundle, _idx, os_family=os_family or None)


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------

def render_inventories(bundle: ExtractedBundle,
                       idx: LogIndex,
                       cache_key: str,
                       os_family: str = "") -> None:
    st.subheader("Inventories & Snapshots")
    with st.spinner("Building snapshots (one-time per bundle)..."):
        snaps = _cached_snapshots(cache_key, bundle, idx, os_family)

    _render_config_snapshots(snaps, idx)
    _render_artifact_inventories(snaps)
    _render_code_lookup()
    _render_diagnostics(snaps)


# --------------------------------------------------------------------------
# Config snapshots
# --------------------------------------------------------------------------

_TRUSTED_NET_STATE_RE = re.compile(
    r"Tunnel Network status \+\+([A-Za-z][A-Za-z \-]{0,40})"
)
_NETWORK_TYPE_RE = re.compile(r'"networkType"\s*:\s*(\d+)')
_OFF_TRUSTED_RE = re.compile(
    r"\b(off-?trusted|on-?trusted|non-?trusted)[ _]?network\b", re.IGNORECASE
)


def _render_trusted_network(idx: LogIndex) -> None:
    """Trusted-network evidence, from the log lines that actually carry it.

    Important scoping note, verified against real bundles (Scenario Windows C
    2026-07-07 and Scenario Windows D 2026-06-12): a ZCC support bundle does **not
    contain the trusted-network criteria**. There is no
    `trustedNetworks`, `networkCriteria`, `dnsSearchDomain` or
    equivalent config anywhere in the export — those live only in the
    Mobile Admin portal. Zero hits across every spelling.

    What the bundle does carry is the *evaluated result*: the network
    state the client decided it was on, and the numeric `networkType`
    in each Tunnel Status Response. So that's what's shown, labelled as
    observed state rather than configuration. Rendering an empty
    "Trusted networks" table would imply the extractor failed, when in
    fact the data was never in the file.
    """
    states: Dict[str, int] = {}
    nettypes: Dict[str, int] = {}
    phrases: Dict[str, int] = {}
    for ln in idx.lines:
        body = ln.body or ""
        if "Tunnel Network status" in body:
            m = _TRUSTED_NET_STATE_RE.search(body)
            if m:
                k = m.group(1).strip()
                states[k] = states.get(k, 0) + 1
        if "networkType" in body:
            m = _NETWORK_TYPE_RE.search(body)
            if m:
                nettypes[m.group(1)] = nettypes.get(m.group(1), 0) + 1
        m = _OFF_TRUSTED_RE.search(body)
        if m:
            k = m.group(0).lower()
            phrases[k] = phrases.get(k, 0) + 1

    total = len(states) + len(nettypes) + len(phrases)
    with st.expander(
        f"Trusted-network state — observed ({total} distinct signal(s))",
        expanded=False,
    ):
        st.caption(
            "**The trusted-network criteria are not in a ZCC bundle.** "
            "DNS-search-domain / DNS-server / hostname criteria are "
            "configured in Mobile Admin and never exported here — "
            "verified across bundles, zero hits for any config spelling. "
            "What the client logs is the *decision* it reached, below."
        )
        if not total:
            st.caption(
                "No network-state lines found either "
                "(`Tunnel Network status ++…`, `\"networkType\": N`, "
                "or an off/on-trusted phrase)."
            )
            return

        if states:
            st.markdown("**Reported tunnel network status**")
            st.dataframe(
                [{"status": k, "lines": v}
                 for k, v in sorted(states.items(), key=lambda kv: -kv[1])],
                hide_index=True, use_container_width=True,
            )
        if phrases:
            st.markdown("**Trust-state phrases in log text**")
            st.dataframe(
                [{"phrase": k, "lines": v}
                 for k, v in sorted(phrases.items(), key=lambda kv: -kv[1])],
                hide_index=True, use_container_width=True,
            )
        if nettypes:
            st.markdown("**`networkType` in Tunnel Status Response**")
            st.dataframe(
                [{"networkType": k, "lines": v}
                 for k, v in sorted(nettypes.items(),
                                    key=lambda kv: -kv[1])],
                hide_index=True, use_container_width=True,
            )
            st.caption(
                "Raw value shown deliberately un-translated. The "
                "0=Off-Trusted / 1=Trusted / 2=VPN mapping documented "
                "for *forwarding-profile* `networkType` has not been "
                "confirmed to apply to this Tunnel-Status field, so "
                "labelling it here would be a guess."
            )


def _render_config_snapshots(snaps: BundleSnapshots, idx: LogIndex) -> None:
    st.markdown("### Config snapshots")

    with st.expander(
        f"App Profile ({len(snaps.app_profile)} keys)",
        expanded=False,
    ):
        if snaps.app_profile:
            st.json(snaps.app_profile)
        else:
            st.caption("Not extracted from tray logs.")

    with st.expander(
        f"Forwarding Profile details ({len(snaps.profile_details)} keys)",
        expanded=False,
    ):
        if snaps.profile_details:
            st.json(snaps.profile_details)
        else:
            st.caption("Not extracted.")

    with st.expander(
        f"Device posture profiles ({len(snaps.posture_profiles)})",
        expanded=bool(snaps.posture_profiles),
    ):
        if snaps.posture_profiles:
            rows = []
            for p in snaps.posture_profiles:
                res = p.get("latest_result")
                rows.append({
                    "name": p.get("name") or "—",
                    "type": p.get("ptype") or "—",
                    "posture ID": p.get("posture_id") or "—",
                    "latest result": (
                        "pass" if res == 1 else
                        "fail" if res == 0 else
                        "not evaluated"
                    ),
                    "last evaluated (UTC)": (
                        str(p.get("latest_result_ts"))
                        if p.get("latest_result_ts") else "—"
                    ),
                    "evaluations": len(p.get("result_history") or []),
                    "check interval (s)": p.get("frequency_s") or "—",
                    "udid": p.get("udid") or "—",
                })
            rows.sort(key=lambda r: str(r["name"]).lower())
            st.dataframe(rows, hide_index=True, use_container_width=True)
            st.caption(
                "“not evaluated” means the check is referenced by the "
                "trust policy but produced no result line in this "
                "bundle — the policy depends on something the client "
                "isn't reporting. Interval shows “—” when the current "
                "ZCC build omits it from the definition line."
            )
        else:
            st.caption(
                "No posture data. Sources checked: "
                "`updatePostureProfileDetails` definition lines, "
                "`Device posture result str:` result JSON, and the "
                "`getTrustTypeResult: trustLevel condition:` policy "
                "blob — all in tray/tunnel logs."
            )

    with st.expander(
        f"Trust condition — posture checks required ({len(snaps.trust_conditions)})",
        expanded=bool(snaps.trust_conditions),
    ):
        if snaps.trust_conditions:
            st.dataframe(
                [
                    {
                        "OR group": c.get("or_group"),
                        "posture ID": c.get("id"),
                        "name (as the policy spells it)": c.get("name"),
                        "udid": c.get("udid"),
                    }
                    for c in snaps.trust_conditions
                ],
                hide_index=True, use_container_width=True,
            )
            st.caption(
                "Conditions sharing an OR group are ANDed — all of them "
                "must pass for that group to grant trust. Any single "
                "group passing is sufficient. Names here come from the "
                "trust policy, so they can differ from the posture "
                "profile name above if one side carries a typo."
            )
        else:
            st.caption(
                "No `getTrustTypeResult: trustLevel condition:` line in "
                "the tray/tunnel logs."
            )

    _render_trusted_network(idx)

    with st.expander(
        f"Configured VPN bypass ({sum(len(v) for v in snaps.configured_bypass.values() if isinstance(v, (list, dict)))} entries)",
        expanded=False,
    ):
        if snaps.configured_bypass:
            st.json(snaps.configured_bypass)
        else:
            st.caption("No `Network hostname csv:` line in tunnel logs.")

    with st.expander(
        f"Session info ({len(snaps.session_info)} keys)",
        expanded=False,
    ):
        if snaps.session_info:
            st.json(snaps.session_info)
        else:
            st.caption("No `raiseSessionInformationEvent` line found.")


# --------------------------------------------------------------------------
# Artifact inventories
# --------------------------------------------------------------------------

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} PB"


def _render_artifact_inventories(snaps: BundleSnapshots) -> None:
    st.markdown("### Non-log artifact inventories")

    # ---- PCAPs ----
    with st.expander(f"PCAPs ({len(snaps.pcaps)})", expanded=False):
        if not snaps.pcaps:
            st.caption("No `.pcapng` files in bundle.")
        else:
            rows = []
            for p in snaps.pcaps:
                first = p.ts_first.strftime("%Y-%m-%d %H:%M:%S") if p.ts_first else "-"
                last = p.ts_last.strftime("%Y-%m-%d %H:%M:%S") if p.ts_last else "-"
                dur = f"{p.duration_seconds:.1f}s" if p.duration_seconds else "-"
                rows.append({
                    "filename": p.filename,
                    "size": _fmt_bytes(p.size_bytes),
                    "packets": f"{p.packet_count:,}",
                    "first (UTC)": first,
                    "last (UTC)": last,
                    "duration": dur,
                })
            st.dataframe(rows, hide_index=True, use_container_width=True)

            # Per-PCAP detail. Streamlit forbids nesting an expander
            # inside an expander (raises StreamlitAPIException), and
            # this whole block already lives inside the "PCAPs"
            # expander — so any bundle containing a .pcapng used to
            # hard-crash this tab. A selectbox gives the same
            # drill-down without the nesting.
            names = [p.filename for p in snaps.pcaps]
            chosen = st.selectbox(
                "Top DNS / SNI / destination IPs for capture",
                options=names, index=0, key="_slice5_pcap_pick",
            )
            p = snaps.pcaps[names.index(chosen)]
            c1, c2, c3 = st.columns(3)
            with c1:
                st.caption("Top DNS queries")
                st.write(p.top_dns or "-")
            with c2:
                st.caption("Top SNI hosts")
                st.write(p.top_sni or "-")
            with c3:
                st.caption("Top destination IPs")
                st.write(p.top_dest_ips or "-")

    # ---- UPM DBs ----
    with st.expander(f"UPM SQLite databases ({len(snaps.upm_dbs)})",
                     expanded=False):
        if not snaps.upm_dbs:
            st.caption("No `.db` files in bundle.")
        else:
            for db in snaps.upm_dbs:
                st.markdown(f"**{db.filename}** — {_fmt_bytes(db.size_bytes)}")
                if not db.tables:
                    st.caption("(no tables enumerated)")
                    continue
                tab_rows = [
                    {"table": t, "row_count": v}
                    for t, v in sorted(
                        db.tables.items(), key=lambda kv: -kv[1],
                    )
                ]
                st.dataframe(tab_rows, hide_index=True, use_container_width=True)

    # ---- XML events ----
    with st.expander(f"XML event files ({len(snaps.xml_events)})",
                     expanded=False):
        if not snaps.xml_events:
            st.caption("No `.xml` files in bundle.")
        else:
            rows = [
                {"filename": a.filename, "size": _fmt_bytes(a.size_bytes)}
                for a in snaps.xml_events
            ]
            st.dataframe(rows, hide_index=True, use_container_width=True)

    # ---- Other files ----
    with st.expander(f"Other files ({len(snaps.other_files)})", expanded=False):
        if not snaps.other_files:
            st.caption("No other artifacts.")
        else:
            rows = [
                {"filename": a.filename, "size": _fmt_bytes(a.size_bytes)}
                for a in snaps.other_files
            ]
            st.dataframe(rows, hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------
# Reference-code lookup
# --------------------------------------------------------------------------

def _render_code_lookup() -> None:
    st.markdown("### Reference-code lookup")
    with st.expander(
        "Search across every documented Zscaler code / status "
        f"({len(known_sources())} sources)",
        expanded=False,
    ):
        query = st.text_input(
            "Code query",
            key="_slice5_code_query",
            placeholder="e.g. BRK_MT_SETUP_FAIL_SAML_EXPIRED, 5008, kerberos",
        )
        limit = st.slider(
            "Max hits", 5, 200, 30,
            key="_slice5_code_limit",
        )
        if not query.strip():
            st.caption("Enter a symbolic code, a numeric error, or a keyword.")
            return
        hits = lookup_code(query, limit=limit)
        if not hits:
            st.info("No matches in the reference data.")
            return
        st.caption(f"Matches: **{len(hits)}**")
        rows = []
        for h in hits:
            rows.append({
                "source": h.source,
                "match": h.match_reason,
                "code": h.code,
                "description": h.fields.get("description")
                             or h.fields.get("session_status")
                             or h.fields.get("meaning")
                             or "",
                "resolution": h.fields.get("resolution", ""),
            })
        st.dataframe(rows, hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------
# Diagnostics
# --------------------------------------------------------------------------

def _render_diagnostics(snaps: BundleSnapshots) -> None:
    if not snaps.extract_errors:
        return
    with st.expander(
        f"Extractor diagnostics ({len(snaps.extract_errors)} error(s))",
        expanded=False,
    ):
        for err in snaps.extract_errors:
            st.text(f"  {err}")
