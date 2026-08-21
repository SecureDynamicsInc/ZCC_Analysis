"""
Device Trust + Posture + ZDX Telemetry — own Streamlit module
(Phase 43i, 2026-06-24; Phase 43i.1 finishing move 2026-06-24).

Phase 43i was the IA split (sidebar entry); Phase 43i.1 physically
moves the render function bodies out of ui/policy.py into here, so
policy.py shrinks from 1280 lines back toward a single concern
(cross-suite Tenant Config).

The render functions are kept private (``_render_*``) so the public
contract of this module is just ``module_device(data)``.

Source provenance: the bodies of ``_render_device_trust`` and
``_render_zdx_telemetry`` came from ui/policy.py via the
Phase 41 (Device Trust extractor) and Phase 42c (ZDX telemetry UI)
work. They read from ``data["policy"]["device_trust"]`` and
``data["policy"]["zdx_telemetry"]`` respectively — both populated by
ui/analyse.py via the corresponding extractors.
"""

from __future__ import annotations

from typing import Any, Dict

import streamlit as st


# ----------------------------------------------------------------------
# Phase 41 (2026-06-19) — Device Trust & Posture renderer.
# Reads ``policy["device_trust"]`` (PostureExtraction from
# posture_extract.extract_posture) and renders posture-profile table,
# trust-condition tree, config-quality findings, ZPA reauth-timing
# strip, trusted-network revision strip.
# ----------------------------------------------------------------------


def _render_device_trust(data: Dict[str, Any]) -> bool:
    """Render the Device Trust & Posture section. Returns True if
    any content was rendered, False if the bundle had no posture
    data (in which case the caller can omit the heading)."""
    policy = data.get("policy") or {}
    posture = policy.get("device_trust")
    if posture is None:
        return False
    profiles = getattr(posture, "profiles", {}) or {}
    trust_cond = getattr(posture, "trust_condition", None)
    quality = getattr(posture, "quality_findings", []) or []
    auto_reauth = getattr(posture, "zpa_auto_reauth_timeout_s", None)
    notif_time = getattr(posture, "zpa_reauth_notif_time_s", None)
    notif_switch = getattr(posture, "zpa_reauth_notif_switch", None)
    tn_revs = getattr(posture, "distinct_trusted_net_revisions", []) or []
    posture_acks = getattr(posture, "posture_ack_count", 0)

    if not (
        profiles or trust_cond or quality or tn_revs
        or auto_reauth is not None or notif_time is not None
        or notif_switch is not None
    ):
        return False

    st.markdown(
        '<div class="zd-section">Device Trust &amp; Posture</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "The ZPA-side device-compliance checks and access-policy "
        "conditions that this client must satisfy to reach internal "
        "apps. Sourced from broker pushes captured in tray-manager "
        "and tunnel logs — every row below traces to a specific "
        "log line."
    )

    # ---- Quality findings (lead with what's wrong) ---------------
    if quality:
        st.warning(
            "**Config-quality findings:**\n\n"
            + "\n\n".join(f"- {f}" for f in quality),
            icon="⚠️",
        )

    # ---- Posture profile table -----------------------------------
    if profiles:
        st.markdown("**Posture profiles configured for this tenant:**")
        rows = []
        for p in profiles.values():
            if p.latest_result == 1:
                result_str = "✅ PASS"
            elif p.latest_result == 0:
                result_str = "❌ FAIL"
            else:
                result_str = "—"
            rows.append({
                "Name": p.name,
                "Type": p.ptype,
                "Posture ID": str(p.posture_id),
                "UDID": p.udid,
                "Check interval": (
                    f"{p.frequency_s}s ({p.frequency_s // 60} min)"
                    if p.frequency_s else "—"
                ),
                "Latest result": result_str,
                "Samples": str(len(p.result_history)),
            })
        st.dataframe(
            rows, hide_index=True, use_container_width=True,
            height=min(300, 38 + 35 * len(rows)),
        )

    # ---- Trust condition tree ------------------------------------
    if trust_cond is not None:
        st.markdown("**Trust-level access policy:**")
        st.caption(
            "The customer's ZPA access policy expressed as a "
            "disjunction of conjunctions: trust is granted when "
            "ANY OR-group's checks ALL pass."
        )
        for i, cn_group in enumerate(trust_cond.or_groups, 1):
            names = [c.get("name", "?") for c in cn_group]
            ids = [str(c.get("id", "?")) for c in cn_group]
            ands = " **AND** ".join(f"`{n}`" for n in names)
            st.markdown(
                f"  • **OR-group {i}:** {ands}  "
                f"_(posture IDs: {', '.join(ids)})_"
            )
        if len(trust_cond.or_groups) == 1:
            st.caption(
                "_One OR-group: user gets trust when ALL of the "
                "checks above pass. No fallback condition set._"
            )

    # ---- ZPA reauth timing strip ---------------------------------
    if (
        auto_reauth is not None
        or notif_time is not None
        or notif_switch is not None
    ):
        st.markdown("**ZPA re-auth timing (from TrayPolicy):**")
        cols = st.columns(3)
        cols[0].metric(
            "Auto re-auth timeout",
            f"{auto_reauth} s" if auto_reauth is not None else "—",
            help=(
                "`zpaAutoReauthTimeoutSec`. ZCC will silently try "
                "to re-authenticate for this many seconds before "
                "showing the user a prompt. Short values give the "
                "user less chance to recover transparently."
            ),
        )
        cols[1].metric(
            "Notification window",
            f"{notif_time} s" if notif_time is not None else "—",
            help=(
                "`zpaReauthNotificationTime`. How long ZCC shows a "
                "heads-up notification (when notifications are on)."
            ),
        )
        notif_str = (
            "Enabled"
            if notif_switch is True
            else ("Disabled" if notif_switch is False else "—")
        )
        cols[2].metric(
            "User notifications",
            notif_str,
            help=(
                "`zpaReauthNotifSwitch`. When disabled, the user "
                "gets no heads-up before the re-auth prompt — they "
                "see only the prompt itself. Often correlates with "
                "users 'missing' re-auth prompts and sessions "
                "stalling in AUTHENTICATION_REQUIRED state."
            ),
            delta=(
                "user gets no heads-up"
                if notif_switch is False else None
            ),
            delta_color="inverse" if notif_switch is False else "off",
        )

    # ---- Broker-pushed config tally ------------------------------
    bottom_cols = st.columns(2)
    bottom_cols[0].metric(
        "Trusted-network policy revisions",
        len(tn_revs),
        delta=(
            f"IDs: {', '.join(str(x) for x in tn_revs)}"
            if tn_revs else "none observed"
        ),
        delta_color="off",
        help=(
            "Distinct `zpn_trusted_networks_ack` revision IDs the "
            "broker has pushed to this client. These are policy-"
            "version numbers, not named entries — the actual "
            "named definitions live server-side."
        ),
    )
    bottom_cols[1].metric(
        "Posture profile acks",
        posture_acks,
        delta_color="off",
        help=(
            "Count of `zpn_posture_profile_ack` confirmations from "
            "the broker. Each one means the broker re-confirmed a "
            "posture-profile association for this client."
        ),
    )
    st.caption(
        "Source: `updatePostureProfileDetails`, "
        "`getTrustTypeResult: trustLevel condition:`, "
        "`Device posture result str:`, `zpn_trusted_networks_ack`, "
        "`zpn_posture_profile_ack`, and TrayPolicy "
        "`zpa*Reauth*` fields."
    )
    return True


# ----------------------------------------------------------------------
# Phase 42c (2026-06-19) — ZDX Telemetry renderer.
# Reads ``policy["zdx_telemetry"]`` (ZdxTelemetry from
# zdx_db_extract.extract_from_bundle) and renders device resource
# time-series, ZDX-monitored URL health, top CPU processes, device
# events by category, and recent install/uninstall events.
# ----------------------------------------------------------------------


def _render_zdx_telemetry(data: Dict[str, Any]) -> bool:
    """Render the ZDX Telemetry section. Returns True if any content
    was rendered, False when no upm_*.db data was extracted."""
    policy = data.get("policy") or {}
    telemetry = policy.get("zdx_telemetry")
    if telemetry is None or not getattr(telemetry, "has_data", False):
        return False

    monitored = getattr(telemetry, "monitored_urls", None) or []
    ts_map = getattr(telemetry, "time_series", None) or {}
    event_counts = (
        getattr(telemetry, "device_event_counts", None) or {}
    )
    proc_top = getattr(telemetry, "process_top_cpu", None) or []
    uninstalls = (
        getattr(telemetry, "inventory_recent_uninstalls", None) or []
    )
    installs = (
        getattr(telemetry, "inventory_recent_installs", None) or []
    )
    upload_n = getattr(telemetry, "upload_count", 0) or 0
    upload_fails = getattr(telemetry, "upload_failure_count", 0) or 0

    st.markdown(
        '<div class="zd-section">ZDX Telemetry</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Continuous device-experience telemetry that ZDX collects "
        "and caches on disk before uploading to the cloud. Sourced "
        "from the `upm_*.db` SQLite files in `log-<hash>/`. Every "
        "row below is a real measurement, not a heuristic."
    )

    # ---- Resource time-series strip ----
    if ts_map:
        st.markdown("**Device resources during the bundle window**")
        cols = st.columns(4)
        for idx, key in enumerate((
            "memory_pct_used", "cpu_pct_total",
            "disk_pct_used", "battery_level_pct",
        )):
            ts = ts_map.get(key)
            if ts is None:
                cols[idx].metric(key.replace("_", " ").title(), "—")
                continue
            label = {
                "memory_pct_used": "Memory",
                "cpu_pct_total": "CPU",
                "disk_pct_used": "Disk used",
                "battery_level_pct": "Battery",
            }.get(key, key)
            mean = ts.mean if ts.mean is not None else 0
            primary = f"{mean:.0f}% mean"
            delta = (
                f"p95 {ts.p95:.0f}% · max {ts.max:.0f}%"
                if ts.p95 is not None and ts.max is not None else "—"
            )
            delta_color = "off"
            if (
                ts.threshold_pct is not None
                and ts.threshold_pct >= 50.0
            ):
                delta_color = "inverse"
            cols[idx].metric(
                label, primary, delta=delta, delta_color=delta_color,
            )
            if (
                ts.threshold_value is not None
                and ts.threshold_count > 0
            ):
                cols[idx].caption(
                    f"_{ts.threshold_count:,} of {ts.samples:,} "
                    f"samples >= {ts.threshold_value:.0f}%_"
                )
        st.caption(
            "Source: `upm_device_stats.tbl_memory_usage`, "
            "`tbl_cpu_usage`, `tbl_disk_io`, `tbl_battery_status`."
        )
        st.divider()

    # ---- Monitored URL health table ----
    if monitored:
        st.markdown("**ZDX-monitored URLs (per-host probe health)**")
        rows = []
        for u in monitored:
            avail = u.availability_pct
            if avail is None:
                avail_str = "—"
                status_emoji = "—"
            elif avail >= 99:
                avail_str = f"{avail:.0f}%"
                status_emoji = "✅"
            elif avail >= 50:
                avail_str = f"{avail:.0f}%"
                status_emoji = "⚠️"
            else:
                avail_str = f"{avail:.0f}%"
                status_emoji = "❌"
            dns_ms = (
                f"{u.mean_dns_ns / 1_000_000:.1f} ms"
                if u.mean_dns_ns else "—"
            )
            pfl_ms = (
                f"{u.mean_pageload_ns / 1_000_000:.1f} ms"
                if u.mean_pageload_ns else "—"
            )
            rows.append({
                "": status_emoji,
                "URL": u.url,
                "Avail": avail_str,
                "Samples": str(u.sample_count),
                "Mean DNS": dns_ms,
                "Mean PageFetch": pfl_ms,
                "Traceroute": (
                    "unresolved" if u.has_unresolved_ip
                    else "resolved"
                ),
            })
        st.dataframe(
            rows, hide_index=True, use_container_width=True,
            height=min(350, 38 + 35 * len(rows)),
        )
        st.caption(
            "Source: `upm_webload.WebData` (per-URL probe rows) + "
            "`upm_traceroute.trmain` (resolved IPs)."
        )
        st.divider()

    # ---- Top CPU processes ----
    if proc_top:
        st.markdown("**Top CPU-consuming processes**")
        rows = [
            {
                "Process": name,
                "Avg CPU %": f"{avg:.2f}",
                "Max CPU %": f"{mx:.2f}",
            }
            for name, avg, mx in proc_top[:10]
        ]
        st.dataframe(
            rows, hide_index=True, use_container_width=True,
            height=min(300, 38 + 35 * len(rows)),
        )
        st.caption(
            "Source: `upm_device_stats.tbl_mon_processes` (per-PID "
            "CPU/memory samples)."
        )
        st.divider()

    # ---- Device event categories ----
    if event_counts:
        st.markdown("**Device events seen in the bundle window**")
        top = sorted(
            event_counts.items(), key=lambda kv: -kv[1],
        )[:15]
        rows = [
            {"Event": name, "Count": str(n)}
            for name, n in top
        ]
        st.dataframe(
            rows, hide_index=True, use_container_width=True,
            height=min(550, 38 + 35 * len(rows)),
        )
        if len(event_counts) > 15:
            st.caption(
                f"_+{len(event_counts) - 15} more event types not "
                "shown_"
            )
        st.caption(
            "Source: `upm_device_events.EVENTS` (categorized "
            "structured event log queued for ZDX cloud upload)."
        )
        st.divider()

    # ---- Recent install / uninstall events ----
    if installs or uninstalls:
        st.markdown("**Recent install / uninstall events**")
        st.caption(
            "Each row is a software install or uninstall captured "
            "by `upm_device_inventory`. **Watch for Microsoft Edge "
            "WebView2 Runtime, Edge, or Chrome uninstalls/reinstalls "
            "right before a user's auth-flow problem** — ZCC's "
            "embedded SAML UI uses WebView2, and a WebView2 churn "
            "event during the user's login window can break auth."
        )
        rows = []
        for ev in uninstalls[:10]:
            rows.append({
                "When": ev.ts.strftime("%Y-%m-%d %H:%M"),
                "Action": "uninstall",
                "Name": ev.name,
                "Version": ev.version,
                "Publisher": ev.publisher[:30],
            })
        for ev in installs[:10]:
            rows.append({
                "When": ev.ts.strftime("%Y-%m-%d %H:%M"),
                "Action": "install",
                "Name": ev.name,
                "Version": ev.version,
                "Publisher": ev.publisher[:30],
            })
        rows.sort(key=lambda r: r["When"], reverse=True)
        st.dataframe(
            rows, hide_index=True, use_container_width=True,
            height=min(500, 38 + 35 * len(rows)),
        )
        st.divider()

    # ---- ZDX cloud upload stats ----
    cols_btm = st.columns(2)
    cols_btm[0].metric(
        "ZDX cloud uploads",
        f"{upload_n:,}",
        delta=(
            f"{upload_fails} failure(s)"
            if upload_fails else "all successful"
        ),
        delta_color="inverse" if upload_fails else "off",
        help=(
            "Count of telemetry batches uploaded to the ZDX cloud. "
            "Source: `upm_upload_stats.upload_data` row count."
        ),
    )
    apps_total = len(getattr(telemetry, "inventory_apps", []) or [])
    cols_btm[1].metric(
        "Installed apps (inventory)",
        f"{apps_total:,}",
        help=(
            "Distinct installed-software entries in "
            "`upm_device_inventory.tbl_last_snapshot`."
        ),
    )

    return True


def module_device(data: Dict[str, Any]) -> None:
    """Streamlit entry point for the Device Trust + ZDX Telemetry module."""
    st.markdown(
        '<div class="zd-section">Device Posture &amp; ZDX Telemetry</div>',
        unsafe_allow_html=True,
    )

    has_device_trust = _render_device_trust(data)
    has_zdx_telemetry = _render_zdx_telemetry(data)

    if not (has_device_trust or has_zdx_telemetry):
        st.info(
            "This bundle has no Device Trust / Posture data and no "
            "ZDX telemetry. Posture data is populated when the customer's "
            "ZPA access policy uses device-trust conditions; ZDX telemetry "
            "requires the ZDX agent to be running and the upm_*.db "
            "SQLite files to be present in the bundle export. Neither "
            "is required for ZCC to function — they enrich the "
            "diagnostic surface when present."
        )
