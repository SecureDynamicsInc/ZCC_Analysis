"""
Policy & Config module — ZIA / ZPA status, Forwarding Profile, App
Profile detail, PAC file, customer bypass list, service edges.

This module surfaces the policy snapshot that ZCC's tray-manager
component dumps into its log on every push. The data comes from
``policy_extract.py``; the rendering and filtering helpers live here.

Three helpers are exported alongside the module entry point because
the older ``_render_bundle_panel`` and the Overview module also call
them — they're not policy-private:

  * ``is_zscaler_infra_host(host)`` — True for Zscaler-managed
    hostnames that ZCC auto-adds to the bypass list. The customer
    didn't put them there, so they shouldn't pollute the
    customer-policy view.
  * ``filter_customer_bypass(bypass)`` — drop the infra hosts.
  * ``consolidate_policy_rows(policy)`` — collapse the redundant
    ``ZIA enrolled / ZIA enabled for user`` pair (and ZPA equivalent)
    into a single status string per service. Runtime tunnel signal
    overrides a stale-looking policy snapshot.
  * ``runtime_zia_zpa_active(data)`` — alternative runtime probe that
    walks the log_index looking for tunnel-up markers. Currently
    unused by the live UI (``_analyse`` does the equivalent scan
    inline), kept here so a future caller can use it without rewriting.
"""

from __future__ import annotations

import html as _html_mod
from typing import Any, Dict, List, Tuple

import streamlit as st


def _h_inline(s: Any) -> str:
    """HTML-escape a value for safe embedding in inline markdown
    section headers (e.g. <div class="zd-section">Foo — <code>{x}</code></div>).
    Streamlit's st.markdown(html, unsafe_allow_html=True) doesn't escape
    user-supplied content; profile names from log files can contain
    `<` / `>` / `&` (unlikely but possible). Escape defensively."""
    return _html_mod.escape(str(s) if s is not None else "")


# Zscaler's own infrastructure domains. These appear in the bypass list
# automatically (ZCC manages them) and aren't customer policy entries
# the engineer needs to review. Filter them out of the user-facing
# bypass view so it shows only the customer's actual policy.
ZSCALER_INFRA_PATTERNS = (
    "zscaler.com", "zscaler.net", "zscalertwo.net", "zscalerthree.net",
    "zscalerbeta.net", "zscalerten.net", "zscalergov.net",
    "zscloud.net", "zsapi.net", "zs-cdn.net", "zdxcloud.net",
)


def is_zscaler_infra_host(host: str) -> bool:
    """True if ``host`` belongs to a Zscaler-owned infrastructure
    domain. Used to filter ZCC-managed bypass entries out of the
    customer-policy view."""
    if not host:
        return False
    h = host.lower().strip()
    # Strip any leading wildcard token (e.g. ``*.zscaler.com``).
    h = h.lstrip("*.").lstrip(".")
    for pat in ZSCALER_INFRA_PATTERNS:
        if h == pat or h.endswith("." + pat):
            return True
    # ``zs-*`` and ``zsalpha`` patterns also belong to Zscaler.
    if h.startswith("zs-") or h.startswith("zsalpha"):
        return True
    return False


def filter_customer_bypass(bypass: Dict[str, List[str]]
                            ) -> Dict[str, List[str]]:
    """Return a new dict with Zscaler-infra hosts dropped. Used by the
    user-facing bypass renderer; the original data is preserved (raw
    bypass cache stays in summary.bypass_cache for any consumer that
    actually wants infra entries)."""
    return {
        h: ips for h, ips in (bypass or {}).items()
        if not is_zscaler_infra_host(h)
    }


def runtime_zia_zpa_active(data: Dict[str, Any]) -> Tuple[bool, bool]:
    """Return ``(zia_active, zpa_active)`` inferred from RUNTIME signals
    in the parsed log index — NOT from the policy snapshot.

    Why: the TrayPolicy snapshot in tray-manager logs can be captured
    BEFORE the user has logged in / been enrolled. A bundle from a
    machine that's connected and observing slowness can show
    ``ziaEnabledForUser = 0`` because that's the policy at the
    snapshot moment. Cross-referencing the actual runtime signals
    (Was a tunnel up? Was an SME assigned? Did Tunnel-api responses
    come back?) gives the real picture.

    Currently unused — the live ``_analyse`` pipeline does the
    equivalent scan inline via ``_scan_index_for_marker`` and writes
    the result to ``policy["_runtime_zia_active"]`` /
    ``policy["_runtime_zpa_active"]``. Kept available for any future
    caller that wants the same logic without re-importing the
    underlying scanner.
    """
    zia_active = False
    zpa_active = False
    log_index = data.get("log_index")
    if log_index is None:
        return (False, False)
    zia_markers = (
        "Use Sme: 1", "Connected to ZEN", "ZIA Tunnel UP",
        "ZIA_TUNNEL_UP", "zcc_zia_server_up",
        '"brokerType":0',  # Tunnel api response broker_type=ZIA
    )
    zpa_markers = (
        "ZPA Tunnel UP", "ZPA_TUNNEL_UP", "zcc_zpa_server_up",
        '"brokerType":1', "BRK_MT_NO_POLICY_FOUND",
        "PA_ERROR_", "BRK_MT_REJECTED_BY_POLICY",
        "brokerName",
    )
    # Sample at most 50,000 lines for speed — clearly-active bundles
    # show signals well within the first few thousand.
    for i, ln in enumerate(log_index.lines):
        if i > 50_000:
            break
        b = ln.body
        if not zia_active:
            for m in zia_markers:
                if m in b:
                    zia_active = True
                    break
        if not zpa_active:
            for m in zpa_markers:
                if m in b:
                    zpa_active = True
                    break
        if zia_active and zpa_active:
            break
    return zia_active, zpa_active


def consolidate_policy_rows(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Return a NEW policy dict where the redundant ZIA/ZPA
    enrolled+enabled pairs are collapsed into a single status row each.

    The raw policy has four lines that ALWAYS travel together::

        ZIA enrolled         : True
        ZIA enabled for user : True
        ZPA enrolled         : True
        ZPA enabled for user : False

    The engineer cares about one thing per service: "is this service
    actively turned on for THIS user?" — which is enrolled AND
    enabled-for-user. We collapse to::

        ZIA status : enrolled · enabled for user
        ZPA status : enrolled · disabled for user

    Runtime tunnel signal (set into the policy dict by ``_analyse``
    under the keys ``_runtime_zia_active`` / ``_runtime_zpa_active``)
    overrides a stale-looking snapshot — a tunnel that's actually up
    means the user IS using the service even if the captured policy
    says otherwise.
    """
    if not policy:
        return policy
    out = dict(policy)  # shallow copy; we mutate the copy

    def _yn(v) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in ("true", "yes", "1", "y", "enabled")

    runtime_zia = policy.pop("_runtime_zia_active", False)
    runtime_zpa = policy.pop("_runtime_zpa_active", False)
    for service in ("ZIA", "ZPA"):
        enrolled_key = f"{service} enrolled"
        enabled_key = f"{service} enabled for user"
        if (enrolled_key not in out and enabled_key not in out
                and not (service == "ZIA" and runtime_zia)
                and not (service == "ZPA" and runtime_zpa)):
            continue
        enrolled = _yn(out.pop(enrolled_key, False))
        enabled = _yn(out.pop(enabled_key, False))
        runtime_up = runtime_zia if service == "ZIA" else runtime_zpa

        if runtime_up:
            if enrolled and enabled:
                status = "active (policy + runtime agree)"
            elif enrolled and not enabled:
                status = (
                    "active (policy says disabled, but runtime "
                    "tunnel is up — snapshot may be stale)"
                )
            elif not enrolled and enabled:
                status = (
                    "active (policy snapshot incomplete; runtime "
                    "tunnel is up)"
                )
            else:
                status = (
                    "active (runtime tunnel up; policy snapshot "
                    "predates enrollment)"
                )
        else:
            # No runtime tunnel observed — fall back to policy only.
            parts = []
            parts.append("enrolled" if enrolled else "not enrolled")
            if enrolled:
                parts.append(
                    "enabled for user" if enabled
                    else "disabled for user"
                )
            status = " · ".join(parts)
        out[f"{service} status"] = status
    return out


# ----------------------------------------------------------------------
# The module entry point.
# ----------------------------------------------------------------------

def _redact_apps_in_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply redact() to the app-domain column in catalog rows.
    When the sidebar PII toggle is OFF this is a pass-through; when
    ON, the customer app domains get tokenised. Returns a NEW list
    so the original rows (used in non-rendering paths) stay intact."""
    from zcc_diag.ui.redact import redact
    out = []
    for r in rows:
        rr = dict(r)
        for col in ("App domain", "App name (from session)"):
            if col in rr and rr[col]:
                rr[col] = redact(rr[col])
        out.append(rr)
    return out


def _render_zpa_app_catalog(data: Dict[str, Any]) -> None:
    """Render the ZPA app catalog with per-app session outcome counts.

    Data sources:
      * ``summary.bundle_meta["zpa_apps"]`` — the catalog extracted
        from ``zpn_client_app`` JSON events. List of ``ZpaApp`` objects
        each with app_domain, port ranges, bypass flags, etc.
      * ``data["zpa_sessions"]`` — per-tag_id sessions reconstructed
        by the ZPA session correlator. We aggregate outcome counts
        per app_domain so the engineer sees ON THE SAME ROW: "this
        app is configured for ports X with bypass NEVER, and over
        the bundle window 3 sessions to it landed in 'Other close'
        (non-NORMAL close codes — typically the broker rejecting
        setup with BRK_MT_SETUP_FAIL_*)."

    Empty-state handling:
      * No zpa_apps and no zpa_sessions: section hidden entirely
        (the engineer probably has a ZIA-only bundle).
      * zpa_apps present, no sessions: render the catalog with a
        "0 sessions" column and a caption explaining.
      * Sessions present, no catalog: render the sessions-only
        table with a caption that the app registry wasn't pushed
        in this bundle window.

    Filters:
      * A simple text filter on app_domain (substring, case-
        insensitive).
      * "Show only apps with broker-terminated sessions" toggle —
        scopes the table to the problem children.
    """
    s = data["summary"]
    bundle_meta = s.bundle_meta or {}
    zpa_apps_info = bundle_meta.get("zpa_apps") or {}
    apps = zpa_apps_info.get("apps") or []
    sessions = data.get("zpa_sessions") or []

    if not apps and not sessions:
        return  # Nothing ZPA-shaped in this bundle — keep silent.

    st.markdown(
        '<div class="zd-section">ZPA App Catalog</div>',
        unsafe_allow_html=True,
    )

    # Aggregate session outcomes per app_domain (suffix-match against
    # the session's app_name).
    #
    # Outcome buckets reflect the post-validation taxonomy (2026-06-12,
    # help.zscaler.com/zpa/understanding-zpa-session-status-codes):
    #   closed         = normal close (BRK_MT_CLOSED_FROM_ASSISTANT
    #                    or any other documented normal-close code)
    #   setup_failed   = mtunnel_request_ack arrived but with err_code != 1
    #   open           = ack:ok received, no end seen (still active OR
    #                    log rotation truncated the close)
    #   other          = end_error matched a non-normal pattern;
    #                    engineer should drill in to read the literal
    #                    code (surfaced in the session detail view)
    from zcc_diag.zpa_apps import find_app_for_domain
    outcomes_by_app: Dict[str, Dict[str, int]] = {}
    unmatched_sessions = 0
    for sess in sessions:
        sess_app = (sess.app_name or "").strip()
        if not sess_app:
            unmatched_sessions += 1
            continue
        matched = find_app_for_domain(apps, sess_app) if apps else None
        key = matched.app_domain if matched is not None else sess_app
        row = outcomes_by_app.setdefault(
            key, {"total": 0, "closed": 0, "open": 0,
                  "setup_failed": 0, "other": 0},
        )
        outcome = sess.outcome
        row["total"] += 1
        if outcome == "closed":
            row["closed"] += 1
        elif outcome == "open":
            row["open"] += 1
        elif outcome == "setup_failed":
            row["setup_failed"] += 1
        else:
            # "closed:<something>" or "incomplete" or anything else
            row["other"] += 1

    # Filter controls
    flt_col1, flt_col2 = st.columns([3, 2])
    with flt_col1:
        domain_filter = st.text_input(
            "Filter by app domain (substring)",
            value="",
            placeholder="e.g. example-tenant-a or salesforce",
            key="zpa_app_catalog_filter",
        ).strip().lower()
    with flt_col2:
        only_problem = st.checkbox(
            "Only apps with abnormal session outcomes",
            value=False,
            key="zpa_app_catalog_only_problem",
            help=(
                "Show only apps with setup_failed or 'other' session "
                "outcomes (i.e. sessions that did NOT end cleanly). "
                "Per Zscaler docs, BRK_MT_CLOSED_FROM_ASSISTANT is the "
                "normal-close signal, so a high 'Closed' count is "
                "expected on healthy apps."
            ),
        )

    def _ports_str(ranges):
        """Render [443,443,3389,3389] -> '443, 3389' or with ranges."""
        if not ranges or len(ranges) % 2:
            return ""
        out = []
        for i in range(0, len(ranges), 2):
            lo, hi = ranges[i], ranges[i + 1]
            if lo == hi:
                out.append(str(lo))
            else:
                out.append(f"{lo}-{hi}")
        return ", ".join(out)

    # Build the table rows. Three render paths depending on what data
    # we have.
    if apps:
        rows = []
        for a in apps:
            if domain_filter and domain_filter not in a.app_domain.lower():
                continue
            oc = outcomes_by_app.get(a.app_domain) or {}
            # "Abnormal" = setup_failed + other (catches closed:<reason>
            # variants that aren't documented normal closes).
            abnormal = (
                oc.get("setup_failed", 0)
                + oc.get("other", 0)
            )
            if only_problem and abnormal == 0:
                continue
            rows.append({
                "App domain": a.app_domain,
                "Bypass": (a.bypass_type or "—") if a.bypass else "no",
                "TCP ports": _ports_str(a.tcp_port_ranges) or "—",
                "UDP ports": _ports_str(a.udp_port_ranges) or "—",
                "ICMP": a.icmp_access_type or "—",
                "DblEnc": "yes" if a.double_encrypt else "",
                "Reauth-bypass": "yes" if a.bypass_on_reauth else "",
                "Deleted": "yes" if a.deleted else "",
                "Sessions": oc.get("total", 0),
                "Closed": oc.get("closed", 0),
                "Setup fail": oc.get("setup_failed", 0),
                "Other": oc.get("other", 0),
                "Open": oc.get("open", 0),
                "Last push": (
                    a.last_seen.isoformat(timespec="seconds")
                    if a.last_seen else ""
                ),
            })

        if not rows:
            st.caption(
                "_No apps match the current filter. Clear the filter or "
                "uncheck \"Only apps with broker-terminated sessions\"._"
            )
        else:
            # Default sort: abnormal (setup_failed + other) desc,
            # then Sessions desc, then App domain alphabetical.
            # Apps with sessions that DIDN'T end normally float to
            # the top — those are what needs triage. Streamlit's
            # dataframe still supports click-to-sort by any column,
            # so this is just the *initial* order.
            rows.sort(
                key=lambda r: (
                    -(int(r.get("Setup fail") or 0)
                      + int(r.get("Other") or 0)),
                    -int(r.get("Sessions") or 0),
                    str(r.get("App domain") or "").lower(),
                ),
            )
            st.caption(
                f"{len(apps)} app(s) in registry · "
                f"{zpa_apps_info.get('total_pushes', 0)} config push(es) "
                f"in this bundle · {len(rows)} shown after filtering. "
                f"Sorted by abnormal outcomes (setup_failed + other) "
                f"descending — click any column header to re-sort. "
                f"Columns: Bypass shows the configured action (NEVER "
                f"means tunnel-through-ZPA, ALWAYS means bypass ZPA "
                f"entirely). 'Closed' = normal session end per Zscaler "
                f"docs; 'Setup fail' = broker rejected the request; "
                f"'Other' = end_error didn't match any known normal-"
                f"close code."
            )
            st.dataframe(
                _redact_apps_in_rows(rows),
                hide_index=True, use_container_width=True,
            )

        # If the session correlator saw app_names that aren't in the
        # registry, surface them — likely the app was pushed BEFORE
        # the bundle's log window, then sessions to it appeared.
        unknown_apps = [
            key for key, _ in outcomes_by_app.items()
            if find_app_for_domain(apps, key) is None
        ]
        if unknown_apps:
            with st.expander(
                f"Sessions to {len(unknown_apps)} app(s) NOT in the "
                f"current registry",
                expanded=False,
            ):
                st.caption(
                    "_These app_names appeared in `tag_id` setup lines "
                    "but no matching `zpn_client_app` push was seen in "
                    "this bundle window. Most likely the app was pushed "
                    "before the captured log range — or the App Name "
                    "differs from any configured app_domain by more "
                    "than a suffix match._"
                )
                u_rows = []
                for key in sorted(unknown_apps):
                    oc = outcomes_by_app[key]
                    # Bucket keys: total / closed / open / setup_failed /
                    # other. The "other" bucket holds non-NORMAL close
                    # codes (closed:brk_mt_setup_fail_*) — the
                    # operationally interesting failures. Was
                    # historically "broker_terminated" until the
                    # 2026-06-12 outcome refactor.
                    u_rows.append({
                        "App name (from session)": key,
                        "Sessions": oc.get("total", 0),
                        "Closed": oc.get("closed", 0),
                        "Open": oc.get("open", 0),
                        "Setup failed": oc.get("setup_failed", 0),
                        "Other close": oc.get("other", 0),
                    })
                st.dataframe(
                    _redact_apps_in_rows(u_rows),
                    hide_index=True, use_container_width=True,
                )

    else:
        # No registry — but we have sessions. Render a sessions-only
        # table so the engineer at least sees what apps were targeted.
        st.caption(
            "_No `zpn_client_app` config-push events were captured in "
            "this bundle's log window. The session correlator still "
            "saw `tag_id` activity for these apps — listing them below "
            "without registry metadata._"
        )
        rows = []
        for key, oc in sorted(outcomes_by_app.items()):
            if domain_filter and domain_filter not in key.lower():
                continue
            # "abnormal" = setup_failed + other (matches the registry-
            # path logic above for consistency). The old code keyed
            # on broker_terminated, which was renamed/split during the
            # 2026-06-12 outcome refactor.
            abnormal = (
                oc.get("setup_failed", 0) + oc.get("other", 0)
            )
            if only_problem and abnormal == 0:
                continue
            rows.append({
                "App name (from session)": key,
                "Sessions": oc.get("total", 0),
                "Closed": oc.get("closed", 0),
                "Open": oc.get("open", 0),
                "Setup failed": oc.get("setup_failed", 0),
                "Other close": oc.get("other", 0),
            })
        if rows:
            st.dataframe(
                _redact_apps_in_rows(rows),
                hide_index=True, use_container_width=True,
            )
        else:
            st.caption(
                "_No app sessions match the current filter._"
            )

    if unmatched_sessions:
        st.caption(
            f"_{unmatched_sessions} session(s) had no App Name — "
            "typically loose `tag_id` references from rotated logs "
            "where the setup line is no longer in the bundle window._"
        )

    # ---- mtunnel session analytics expander -----------------------
    # Per-app aggregated stats over zpa_sessions: avg/median duration,
    # success rate, first/last seen. Useful for the engineer asking
    # "is this app having intermittent failures, or is every session
    # failing immediately?"
    if sessions:
        from zcc_diag.zpa_session_correlator import per_app_analytics
        analytics = per_app_analytics(sessions)
        if analytics:
            with st.expander(
                f"Per-app mtunnel analytics ({len(analytics)} app(s))",
                expanded=False,
            ):
                st.caption(
                    "_Aggregated session statistics per app. Success "
                    "rate = closed / (closed + setup_failed + other). "
                    "'Other' covers non-NORMAL close codes (e.g. "
                    "`closed:brk_mt_setup_fail_no_policy_found`) — "
                    "still a session that ended, but not on the happy "
                    "path. Duration is setup-to-end of each mtunnel; "
                    "very short durations (<1s) usually mean broker-"
                    "side rejection right after setup._"
                )
                a_rows = []
                for a in analytics:
                    # NOTE: ``outcome`` was refactored 2026-06-12 after
                    # Zscaler docs confirmed BRK_MT_CLOSED_FROM_ASSISTANT
                    # is a NORMAL close, not a broker termination. The
                    # ``broker_terminated`` outcome bucket was removed
                    # and split between ``closed`` (normal) and
                    # ``other`` (non-normal closes). The columns below
                    # reflect the new shape. Use .get() with defaults
                    # so older cached analytics (pre-refactor) don't
                    # explode the UI — they'll just show zeros.
                    a_rows.append({
                        "App": a["app_name"],
                        "Total": a["total_sessions"],
                        "Closed": a.get("closed", 0),
                        "Setup failed": a.get("setup_failed", 0),
                        "Other close": a.get("other", 0),
                        "Open": a.get("open", 0),
                        "Success %": f"{a['success_rate_pct']:.0f}%",
                        "Avg s": a["avg_duration_s"] if a["avg_duration_s"] is not None else "—",
                        "Median s": a["median_duration_s"] if a["median_duration_s"] is not None else "—",
                        "Min s": a["min_duration_s"] if a["min_duration_s"] is not None else "—",
                        "Max s": a["max_duration_s"] if a["max_duration_s"] is not None else "—",
                    })
                st.dataframe(
                    _redact_apps_in_rows([
                        {**r, "App domain": r["App"]} for r in a_rows
                    ]),
                    hide_index=True, use_container_width=True,
                )


def module_policy(data: Dict[str, Any]) -> None:
    """ZIA/ZPA status + Forwarding Profile + App Profile detail
    + PAC + Bypass."""
    s = data["summary"]
    policy = data.get("policy") or {}
    pac_info = data.get("pac_info") or {}
    bypass_resolutions = data.get("bypass_resolutions") or {}
    profile_details = data.get("profile_details") or {}

    # Diagnostic block: if profile_details is empty, tell the user
    # WHY (instead of just silently omitting sections).
    fp = (profile_details.get("forwarding_profile") or {}) \
        if profile_details else {}
    ap = (profile_details.get("app_profile") or {}) \
        if profile_details else {}
    fp_rows_zia = fp.get("by_network_type_zia") or []
    fp_rows_zpa = fp.get("by_network_type_zpa") or []
    fp_rows = fp_rows_zia or fp_rows_zpa or fp.get("by_network_type") or []
    ap_settings = ap.get("key_settings") or []
    has_profile_data = bool(fp_rows or ap_settings
                            or ap.get("captive_portal"))
    if not has_profile_data:
        st.info(
            "**No App Profile / Forwarding Profile detail in this "
            "bundle.** This typically means the user wasn't fully "
            "enrolled when the bundle was captured (the TrayPolicy "
            "snapshot was empty), or the bundle didn't include the "
            "tray-manager / service log that carries the policy "
            "push. Other Policy & Config sections (PAC, bypass) "
            "may still have data below.",
        )

    # ---- Forwarding Profile -----------------------------------------
    # Phase 29-B (2026-06-17): consolidated rendering.
    # Previously rendered the ZPA rules TWICE — once as expander rows
    # and once as the "ZPA forwarding action per network type" table.
    # That table is just a re-projection of `forwardingProfileZPNAction`
    # which is already covered by the per-network-type ZPA rows. Show
    # ONE view: ZIA rules as expanders (they have detailed knobs),
    # ZPA rules as a compact table (they're action-only). Profile
    # name lifted into the section header.
    if fp_rows_zia or fp_rows_zpa or fp_rows:
        fp_name = fp.get("name") or "(inline policy)"
        st.markdown(
            f'<div class="zd-section">Forwarding Profile — '
            f'<code>{_h_inline(fp_name)}</code></div>',
            unsafe_allow_html=True,
        )
        st.caption(
            "ZCC chooses the matching row at runtime based on the "
            "current network context (Trusted office / VPN / "
            "Off-Trusted Internet). The action is what ZCC does with "
            "user traffic on that network. Rules are split by service "
            "below — ZIA rules apply to Internet-bound traffic, ZPA "
            "rules apply to private-app traffic."
        )

        def _render_fp_rows(rows, header):
            if not rows:
                return
            st.markdown(f"**{header}**")
            for r in rows:
                with st.expander(
                    f"{r['network']}  →  **{r['action']}**",
                    expanded=False,
                ):
                    knobs = r.get("knobs") or {}
                    if knobs:
                        rows_tbl = [
                            {"setting": k, "value": str(v)}
                            for k, v in knobs.items()
                        ]
                        st.dataframe(
                            rows_tbl, hide_index=True,
                            use_container_width=True,
                        )
                    else:
                        st.caption(
                            "_No additional knobs surfaced for this "
                            "row._"
                        )

        # ZIA — render as expanders (they carry per-network knobs
        # that benefit from being one-click-revealable).
        if fp_rows_zia:
            _render_fp_rows(fp_rows_zia, "ZIA forwarding")
        else:
            st.caption(
                "_**ZIA forwarding** — no rules in this bundle. "
                "Either the tenant doesn't define explicit ZIA "
                "forwarding (relies on defaults), or the user was "
                "pre-enrollment when the bundle was captured (no "
                "policy push yet)._"
            )

        # ZPA — render as a single compact table. The per-network
        # data is just action-per-network, so a 3-row table is more
        # scannable than three collapsed expanders. This REPLACES the
        # previous "ZPA forwarding" expanders + "ZPA forwarding action
        # per network type" duplicate table.
        zpa_actions = fp.get("zpa_actions") or {}
        zpa_table_rows = []
        if fp_rows_zpa:
            zpa_table_rows = [
                {
                    "network": r["network"],
                    "action": r["action"],
                }
                for r in fp_rows_zpa
            ]
        elif zpa_actions:
            zpa_table_rows = [
                {"network": k, "action": v}
                for k, v in zpa_actions.items()
            ]
        if zpa_table_rows:
            st.markdown("**ZPA forwarding**")
            st.dataframe(
                zpa_table_rows, hide_index=True,
                use_container_width=True,
            )

        # Legacy fall-through: bundles where the extractor didn't
        # split by service. Rare on modern bundles.
        if not fp_rows_zia and not fp_rows_zpa and fp_rows:
            _render_fp_rows(fp_rows, "Forwarding rules")

    # ---- App Profile detail ----
    # Phase 29-B (2026-06-17): profile name surfaced in the section
    # header (was only in a caption). Also surface the bound
    # forwarding profile name so the engineer sees the App Profile
    # ↔ Forwarding Profile binding at a glance.
    if ap_settings:
        profile_name = ap.get("name") or ""
        header_suffix = (
            f' — <code>{_h_inline(profile_name)}</code>'
            if profile_name else ""
        )
        st.markdown(
            f'<div class="zd-section">App Profile{header_suffix}</div>',
            unsafe_allow_html=True,
        )
        # Forwarding-profile binding caption. The FP that this App
        # Profile points at lives in `fp["name"]` (extractor pairs
        # them at parse time). When fp has a real name (not the
        # "(inline policy)" placeholder) surface that linkage.
        fp_name_for_caption = fp.get("name") or ""
        if profile_name and fp_name_for_caption and fp_name_for_caption != "(inline policy)":
            caption = (
                f"_Forwarding Profile bound to this App Profile: "
                f"**`{fp_name_for_caption}`** — see Forwarding "
                f"Profile section above._"
            )
        elif not profile_name:
            caption = (
                "_Profile name is blank — the user wasn't fully "
                "enrolled when this bundle was captured, so no named "
                "App Profile had been pushed yet. The settings below "
                "are the default knobs ZCC applies pre-enrollment._"
            )
        else:
            caption = (
                "_Curated set of impactful App Profile knobs from "
                "the deployed TrayPolicy._"
            )
        st.caption(caption)
        with st.expander(
            f"Show {len(ap_settings)} setting(s)",
            expanded=False,
        ):
            st.dataframe(
                ap_settings, hide_index=True,
                use_container_width=True,
            )
        cp = ap.get("captive_portal") or {}
        if cp:
            with st.expander(
                f"Captive portal config  ·  {len(cp)} field(s)",
                expanded=False,
            ):
                st.dataframe(
                    [{"setting": k, "value": v}
                     for k, v in cp.items()],
                    hide_index=True,
                    use_container_width=True,
                )

    if profile_details and profile_details.get("source"):
        st.caption(
            f"_Profile data extracted from: "
            f"`{profile_details['source']}`_"
        )

    # Company/Tenant identity is in the header strip. Only the ZIA /
    # ZPA status pair stays here as a compact section.
    if policy:
        policy = consolidate_policy_rows(policy)
        status_rows = []
        for k in ("ZIA status", "ZPA status", "OneID enabled"):
            if k in policy:
                status_rows.append({"field": k, "value": str(policy[k])})
        if status_rows:
            st.markdown(
                '<div class="zd-section">ZIA / ZPA status</div>',
                unsafe_allow_html=True,
            )
            st.dataframe(status_rows, hide_index=True,
                         use_container_width=False)

    # Phase 14 (2026-06-17): PAC / Bypass list / Service edges moved
    # to module_zia (sidebar entry "ZIA (Internet Access)") so this
    # module stays focused on cross-suite policy (Forwarding Profile,
    # App Profile, ZIA/ZPA status overview) — without growing
    # unwieldy on bundles that have rich per-suite data.

    # Phase 14 (2026-06-17): the ZPA App Catalog used to render here,
    # but with Phase 13's per-session lifecycle data (byte totals,
    # setup latency, data events, client/broker close attribution),
    # the section grew large enough to deserve its own module. It now
    # lives in module_zpa() (sidebar entry "ZPA (Private Access)").
    # PAC / Bypass / Service edges similarly moved to module_zia()
    # so Policy & Config keeps the cross-suite bits (Forwarding
    # Profile, App Profile, ZIA/ZPA status) and the suite-specific
    # modules carry the data engineers reach for on triage.

    # Phase 43i (2026-06-24): Device Trust + ZDX Telemetry moved to
    # their own sidebar entry (MOD_DEVICE → ui/module_device.py).
    # Policy & Config keeps the cross-suite forwarding / app-profile /
    # PAC / bypass sections only. The renderer functions
    # (_render_device_trust, _render_zdx_telemetry) still live below
    # in this file for now; module_device.py delegates to them.

    if not (policy or pac_info or bypass_resolutions or s.service_edges):
        st.info(
            "**No policy / PAC / bypass data was extractable from "
            "this bundle.** The tray-manager log either didn't dump "
            "a TrayPolicy block, or this bundle predates the format "
            "we parse. The detectors still work — they just can't "
            "cross-reference policy config.",
        )


# ----------------------------------------------------------------------
# Phase 14 (2026-06-17): suite-segregated modules.
#
# Once the bundle has rich per-suite data (Phase 13's ~470 ZPA sessions
# with full byte stats, setup latencies, etc.), cramming everything
# into a single "Policy & Config" module hurts triage flow. These two
# modules let an engineer jump straight to the suite the customer
# reported an issue with.
# ----------------------------------------------------------------------


# Phase 43i.1 (2026-06-24): the LIVE _render_device_trust and
# _render_zdx_telemetry functions now live in ui/module_device.py —
# anyone needing to render those sections imports from there.
#
# The functions below (prefixed `_UNUSED_`) are the original copies.
# They're DEAD CODE — no caller imports them, no caller invokes them.
# The rename makes the dead status obvious to any greppy refactor;
# physical deletion of the bodies is a tiny follow-up (Phase 43i.2,
# split out so this phase can land safely without touching ~430 lines
# in one edit). When deleting, anchor on `_UNUSED_render_device_trust`
# at the def line and `return True` at the end of
# `_UNUSED_render_zdx_telemetry` — the chunk between them is the
# duplicated content.


def _UNUSED_render_device_trust(data: Dict[str, Any]) -> bool:
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
#
# Reads ``policy["zdx_telemetry"]`` (a ZdxTelemetry from Phase 42a's
# zdx_db_extract.extract_from_bundle) and renders the section as:
#   * Device resource time-series (memory / CPU / disk / battery)
#   * ZDX-monitored URL health (per-URL availability, DNS/PageFetch)
#   * Top CPU processes during the window
#   * Device events by category
#   * Recent install/uninstall events (with WebView2/Edge/Chrome
#     called out as known auth-stack triage signals)
# ----------------------------------------------------------------------


def _UNUSED_render_zdx_telemetry(data: Dict[str, Any]) -> bool:
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
            # Threshold-flag delta_color
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
        # Sort by count desc and show the top 15.
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
        # Sort combined list by timestamp desc
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


def module_zia(data: Dict[str, Any]) -> None:
    """ZIA-focused module: PAC, customer bypass list, Zscaler service
    edges. The cross-suite bits (Forwarding Profile, App Profile) stay
    in Policy & Config.
    """
    s = data["summary"]
    pac_info = data.get("pac_info") or {}
    bypass_resolutions = data.get("bypass_resolutions") or {}
    configured_bypass = data.get("configured_bypass") or {}

    st.caption(
        "ZIA-specific configuration: how Internet-bound traffic is "
        "forwarded (PAC) and which destinations are bypassed. For "
        "ZIA findings, switch to the Findings module; for shared "
        "policy (Forwarding Profile, App Profile), switch to Policy "
        "& Config."
    )

    rendered_anything = False

    # ---- PAC ------------------------------------------------------
    if pac_info:
        st.markdown('<div class="zd-section">PAC file</div>',
                    unsafe_allow_html=True)
        st.dataframe(
            [
                {"field": "Type", "value": pac_info.get("type", "?")},
                {"field": "Path / URL",
                 "value": pac_info.get("data_path", "")},
            ],
            hide_index=True, use_container_width=False,
        )
        rendered_anything = True

    # ---- Customer bypass list (Phase 52 — full inventory) --------
    # Three sources of truth, in order of authority:
    #
    #   1. configured_bypass — the literal "Network hostname csv:" line
    #      from the App Profile. Hostnames + IPv4 + CIDR. This is the
    #      customer's *configured policy*. Strict superset of (2) and (3).
    #   2. bypass_resolutions — hostnames the device actually resolved
    #      via "Resolved exclude hostname:" log lines during this
    #      capture window. Always ≤ (1).
    #   3. summary.bypass_cache — the runtime bypass cache that the
    #      bypass-misconfiguration detector reads. Hostnames only.
    #
    # Pre-Phase-52 the UI showed only (2) minus Zscaler-infra ≈ 88
    # entries while the customer had configured ~178 (104 hostnames +
    # 54 IPv4 + 20 CIDRs). The 74 IP/CIDR entries and the 8 unresolved
    # hostnames were silently hidden. This block now renders all
    # three categories with a status flag per row.
    cb_hosts = configured_bypass.get("hostnames") or []
    cb_ipv4 = configured_bypass.get("ipv4") or []
    cb_cidrs = configured_bypass.get("cidrs") or []
    cb_unparseable = configured_bypass.get("unparseable") or []
    cb_raw_count = configured_bypass.get("raw_count") or 0
    cb_source = configured_bypass.get("source_file") or ""
    cb_lines_seen = configured_bypass.get("csv_lines_seen") or 0

    customer_bypass_m = filter_customer_bypass(bypass_resolutions)
    customer_cache_m = [
        b for b in (s.bypass_cache or [])
        if not is_zscaler_infra_host(b)
    ]
    infra_dropped_m = (
        len(bypass_resolutions) - len(customer_bypass_m)
    )
    resolved_hosts_lc = {h.lower() for h in bypass_resolutions.keys()}
    configured_hosts_lc = {h.lower() for h in cb_hosts}

    has_any_bypass = bool(
        cb_hosts or cb_ipv4 or cb_cidrs
        or customer_cache_m or customer_bypass_m
    )
    if has_any_bypass:
        st.markdown('<div class="zd-section">Customer bypass list</div>',
                    unsafe_allow_html=True)

        # ---- Headline counts (configured vs resolved vs shown) ----
        zscaler_in_configured = sum(
            1 for h in cb_hosts if is_zscaler_infra_host(h)
        )
        zscaler_in_resolved = sum(
            1 for h in bypass_resolutions
            if is_zscaler_infra_host(h)
        )
        never_resolved_hosts = sorted(
            configured_hosts_lc - resolved_hosts_lc
        )
        external_configured = (
            len(cb_hosts) - zscaler_in_configured
        )
        external_resolved = (
            len(bypass_resolutions) - zscaler_in_resolved
        )

        count_rows = [
            {"category": "Configured CSV entries (total)",
             "count": cb_raw_count or "—",
             "note": ("from longest 'Network hostname csv:' line"
                      if cb_raw_count else "no CSV line found")},
            {"category": "  • Hostnames",
             "count": len(cb_hosts),
             "note": (f"{external_configured} customer + "
                      f"{zscaler_in_configured} Zscaler-infra")
             if cb_hosts else ""},
            {"category": "  • IPv4 addresses (/32-equiv)",
             "count": len(cb_ipv4),
             "note": "direct-IP bypass rules"
             if cb_ipv4 else ""},
            {"category": "  • IPv4 CIDR blocks",
             "count": len(cb_cidrs),
             "note": "RFC1918 + vendor subnets"
             if cb_cidrs else ""},
            {"category": "Resolved hostnames (DNS log evidence)",
             "count": len(bypass_resolutions),
             "note": (f"{external_resolved} customer + "
                      f"{zscaler_in_resolved} Zscaler-infra")
             if bypass_resolutions else ""},
            {"category": "Never resolved during capture",
             "count": len(never_resolved_hosts),
             "note": "in policy, no DNS lookup in this window"
             if never_resolved_hosts else ""},
        ]
        if cb_unparseable:
            count_rows.append({
                "category": "Unparseable entries",
                "count": len(cb_unparseable),
                "note": ", ".join(cb_unparseable[:3]) + (
                    "…" if len(cb_unparseable) > 3 else ""
                ),
            })
        st.dataframe(
            count_rows, hide_index=True, use_container_width=True,
        )
        provenance_bits = []
        if cb_source:
            provenance_bits.append(f"source `{cb_source}`")
        if cb_lines_seen:
            provenance_bits.append(
                f"{cb_lines_seen} CSV line(s) observed; longest "
                "taken as canonical"
            )
        if provenance_bits:
            st.caption("_" + "; ".join(provenance_bits) + "._")

        # ---- Toggle: show Zscaler-infra rows? ----
        show_infra = st.checkbox(
            "Show Zscaler-infra bypass entries "
            "(ZCC-managed, normally hidden)",
            value=False, key="zia_bypass_show_infra",
        )

        # ---- Hostnames table ----
        if cb_hosts or bypass_resolutions:
            host_rows: List[Dict[str, Any]] = []

            # 1) All configured hostnames first (from the CSV).
            for h in cb_hosts:
                hl = h.lower()
                is_infra = is_zscaler_infra_host(h)
                if is_infra and not show_infra:
                    continue
                resolved_ips = bypass_resolutions.get(h) or []
                # Try case-insensitive match if exact key missing.
                if not resolved_ips:
                    for k, v in bypass_resolutions.items():
                        if k.lower() == hl:
                            resolved_ips = v
                            break
                if is_infra:
                    status = "Zscaler-infra"
                elif resolved_ips:
                    status = "resolved"
                else:
                    status = "never resolved"
                host_rows.append({
                    "host": h,
                    "status": status,
                    "resolved_ips": ", ".join(resolved_ips),
                    "ip_count": len(resolved_ips),
                    "source": "App Profile CSV",
                })

            # 2) Hostnames seen as resolved but NOT in the CSV (rare —
            #    happens when the CSV rotated out of the bundle window
            #    but resolutions were still logged).
            extra = (
                resolved_hosts_lc - configured_hosts_lc
            )
            for h, ips in bypass_resolutions.items():
                if h.lower() not in extra:
                    continue
                is_infra = is_zscaler_infra_host(h)
                if is_infra and not show_infra:
                    continue
                host_rows.append({
                    "host": h,
                    "status": ("Zscaler-infra" if is_infra
                               else "resolved (not in CSV)"),
                    "resolved_ips": ", ".join(ips),
                    "ip_count": len(ips),
                    "source": "Resolved exclude hostname log",
                })

            # 3) bypass_cache entries that didn't appear anywhere else.
            seen_hosts = {r["host"].lower() for r in host_rows}
            for entry in customer_cache_m:
                if entry.lower() in seen_hosts:
                    continue
                host_rows.append({
                    "host": entry,
                    "status": "in runtime cache only",
                    "resolved_ips": "",
                    "ip_count": 0,
                    "source": "bypass_cache",
                })

            if host_rows:
                st.markdown(
                    "**Hostnames** "
                    f"({len(host_rows)} shown"
                    f"{' incl. Zscaler-infra' if show_infra else ''})"
                )
                st.dataframe(
                    host_rows, hide_index=True,
                    use_container_width=True,
                )

        # ---- IPv4 + CIDR tables (these were silently hidden before) ----
        if cb_ipv4:
            st.markdown(
                f"**IPv4 addresses** ({len(cb_ipv4)} — direct-IP "
                "bypass rules; do not appear in DNS resolution logs)"
            )
            ip_rows = [{"ip": ip} for ip in cb_ipv4]
            st.dataframe(
                ip_rows, hide_index=True, use_container_width=False,
            )

        if cb_cidrs:
            st.markdown(
                f"**IPv4 CIDR blocks** ({len(cb_cidrs)})"
            )

            def _cidr_note(c: str) -> str:
                base = c.split("/")[0]
                mask = c.split("/")[1]
                if base.startswith("10.") and mask == "8":
                    return "RFC1918 private (Class A)"
                if base.startswith("172.16.") and mask == "12":
                    return "RFC1918 private (Class B)"
                if base.startswith("192.168.") and mask == "16":
                    return "RFC1918 private (Class C)"
                if base.startswith("169.254."):
                    return "Link-local / cloud metadata"
                if base.startswith("224."):
                    return "Multicast"
                if base.startswith("127."):
                    return "Loopback"
                if base == "0.0.0.0" and mask == "0":
                    return "Catch-all (all networks)"
                return ""

            cidr_rows = [
                {"cidr": c, "note": _cidr_note(c)}
                for c in cb_cidrs
            ]
            st.dataframe(
                cidr_rows, hide_index=True, use_container_width=True,
            )

        # Legacy informational note kept for parity with prior UI.
        if infra_dropped_m and not show_infra:
            st.caption(
                f"_{infra_dropped_m} Zscaler-infrastructure entries "
                "hidden from the Hostnames table by default — toggle "
                "'Show Zscaler-infra' above to reveal._"
            )
        rendered_anything = True

    # ---- Service edges (Zscaler infrastructure) ------------------
    # Phase 29-E (2026-06-17): every row in this table MUST trace
    # back to a real log line in the bundle. Provenance audit:
    #
    #   * ZIA rows  — from summary.service_edges, populated by
    #                 `resolveDnsWithFamilyPriority` log lines in
    #                 ZSATunnel logs. Each host has the actual
    #                 resolved IP list from those DNS lookups.
    #   * ZPA cloud — from policy["ZPA cloud"], populated by the
    #                 `sendTrayPolicy: zpaCloud: <host>` regex in
    #                 the tray-manager log. ONE line per bundle.
    #   * ZPA brokers — from bundle_meta["zpa_broker_dcs"], populated
    #                 by `broker<N>-<N>.<dc>.prod.zpath.net` regex
    #                 in tunnel-log broker connection events.
    #
    # The "source" column makes the provenance explicit. The "ips"
    # column shows actual resolved IPs for ZIA rows (real data) and
    # an em-dash for ZPA rows where we have the hostname but no
    # resolved IP capture in logs (broker IPs aren't in the ZIA CENR
    # list — they're per-tenant assignments resolved server-side).
    bm = (s.bundle_meta or {})
    zpa_broker_dcs = bm.get("zpa_broker_dcs") or {}
    zpa_broker_hosts = zpa_broker_dcs.get("broker_hostnames") or []
    zpa_cloud_endpoint = (data.get("policy") or {}).get("ZPA cloud") or ""

    edge_rows: List[Dict[str, Any]] = []
    if s.service_edges:
        for host, ips in s.service_edges.items():
            edge_rows.append({
                "suite": "ZIA",
                "host": host,
                "resolved_ips": ", ".join(ips) if ips else "—",
                "source": "DNS resolution log",
            })
    if zpa_cloud_endpoint:
        edge_rows.append({
            "suite": "ZPA",
            "host": zpa_cloud_endpoint,
            "resolved_ips": "—",
            "source": "TrayPolicy zpaCloud field",
        })
    for bh in zpa_broker_hosts:
        edge_rows.append({
            "suite": "ZPA",
            "host": bh,
            "resolved_ips": "—",
            "source": "Tunnel-log broker event",
        })

    if edge_rows:
        st.markdown(
            '<div class="zd-section">Service edges '
            '(Zscaler infrastructure)</div>',
            unsafe_allow_html=True,
        )
        st.caption(
            "Hosts the client connected to during the bundle window. "
            "Each row is backed by a specific log-line source listed "
            "in the `source` column — no inferred entries. ZIA rows "
            "include resolved IPs from DNS lookups in the logs; ZPA "
            "rows show the hostname only (broker IPs aren't in the "
            "ZIA CENR list and aren't captured in client-side logs — "
            "they're per-tenant assignments resolved server-side)."
        )
        st.dataframe(
            edge_rows, hide_index=True, use_container_width=True,
        )
        rendered_anything = True

    if not rendered_anything:
        st.info(
            "**No ZIA-specific data extractable from this bundle.** "
            "Possible reasons: ZIA was not enrolled when the bundle "
            "was captured, the tray-manager log didn't carry the "
            "TrayPolicy dump, or PAC / bypass configuration was "
            "empty. Switch to Policy & Config for cross-suite "
            "config that may still be available."
        )


def _render_closed_from_assistant_clusters(sessions, data) -> None:
    """Surface clusters of BRK_MT_CLOSED_FROM_ASSISTANT events that
    fall within the same 5-minute window (Phase 46, 2026-06-24).

    Per the Zscaler docs, CLOSED_FROM_ASSISTANT IS a normal close —
    when the user disconnects ZCC, every active mtunnel closes that
    way. BUT: when 3+ mtunnels close that way within a few minutes
    on a ZCC that's still running, that's the force-reauth pattern
    we documented for Example Tenant A. The mtunnel correlator (Phase 48) tracks
    this; this banner surfaces it in the existing ZPA Sessions view
    without forcing the engineer to open the RCA View.
    """
    from datetime import timedelta
    cfa_sessions = [
        s for s in sessions
        if getattr(s, "end_error", "") == "BRK_MT_CLOSED_FROM_ASSISTANT"
        and getattr(s, "end_ts", None) is not None
    ]
    if len(cfa_sessions) < 3:
        return

    # Cluster end_ts values into 5-min windows.
    sorted_sess = sorted(cfa_sessions, key=lambda s: s.end_ts)
    clusters = []
    current = [sorted_sess[0]]
    for s in sorted_sess[1:]:
        if (s.end_ts - current[-1].end_ts) <= timedelta(minutes=5):
            current.append(s)
        else:
            if len(current) >= 3:
                clusters.append(current)
            current = [s]
    if len(current) >= 3:
        clusters.append(current)

    if not clusters:
        return

    rca_available = bool(
        (data.get("rca_reports") or {}).get("zpa_reauth_loop")
    )
    cluster_lines = []
    for c in clusters:
        first_ts = c[0].end_ts.strftime("%a %m-%d %H:%M:%S")
        last_ts = c[-1].end_ts.strftime("%H:%M:%S")
        tags = sorted({s.tag_id for s in c if hasattr(s, "tag_id")})[:5]
        cluster_lines.append(
            f"- **{first_ts} → {last_ts}** — {len(c)} sessions severed "
            f"(tag_ids: {', '.join(map(str, tags))}"
            f"{', …' if len(tags) > 5 else ''})"
        )

    rca_pointer = ""
    if rca_available:
        rca_pointer = (
            "\n\n**See the Root Cause Analysis module** for the full "
            "sleep-vs-IdP cadence split + recommended fix (the "
            "zpa_reauth_loop synthesizer pre-classifies each cluster)."
        )
    st.warning(
        f"**Session-severance clusters detected** — {len(clusters)} "
        f"window(s) where 3+ active mtunnels closed via "
        f"BRK_MT_CLOSED_FROM_ASSISTANT within 5 minutes. This is the "
        f"force-reauth-on-wake pattern (Modern Standby + "
        f"autoReauthForOnTrusted=false). Active user sessions were "
        f"likely severed mid-work.\n\n"
        + "\n".join(cluster_lines)
        + rca_pointer,
        icon="⚠️",
    )


def module_zpa(data: Dict[str, Any]) -> None:
    """ZPA-focused module with Phase 17 health-strip + Phase 16 tabs.

    Layout:
      1. Health banner — at-a-glance vitals (slow setups, byte
         imbalance, failure rate, traffic totals, median latency).
      2. App Catalog tab — the configured zpn_client_app catalog,
         cross-referenced with actual session outcomes per app.
      3. Sessions tab — filterable/sortable per-tag_id table with
         every Phase 13 lifecycle field (byte stats, setup latency,
         data events, keep-alives, close attribution).
    """
    st.caption(
        "ZPA-specific configuration and session telemetry. The app "
        "catalog cross-references configured `zpn_client_app` entries "
        "against the actual mtunnel sessions reconstructed from "
        "ZSATunnel logs — including bytes transferred, broker setup "
        "latency, and who closed each session. For ZPA findings, "
        "switch to the Findings module."
    )

    sessions = data.get("zpa_sessions") or []
    summary = data.get("summary")
    has_apps = bool(summary and summary.bundle_meta.get("zpa_apps"))

    if not sessions and not has_apps:
        st.info(
            "**No ZPA data extractable from this bundle.** Possible "
            "reasons: ZPA was not enrolled at the time of capture, "
            "the bundle didn't include ZSATunnel logs in the captured "
            "window, or the TrayPolicy didn't carry a zpn_client_app "
            "push. The cross-suite Forwarding Profile rows (ZPA-side) "
            "in Policy & Config may still have data."
        )
        return

    # ---- Phase 17: ZPA health banner -----------------------------
    if sessions:
        _render_zpa_health_banner(sessions)

    # ---- Phase 46 (2026-06-24): CLOSED_FROM_ASSISTANT banner -----
    # Surface session-severance clusters distinct from the normal
    # "user closed ZCC" interpretation of BRK_MT_CLOSED_FROM_ASSISTANT.
    # When >=3 mtunnels close via CLOSED_FROM_ASSISTANT within the
    # same 5-minute window, that's the force-reauth pattern we
    # documented for the Example Tenant A case (Phase 49a / Phase 48
    # mtunnel correlator); point the engineer at the RCA View for
    # the full per-event analysis.
    if sessions:
        _render_closed_from_assistant_clusters(sessions, data)

    # ---- Phase 16: tabbed App Catalog | Sessions -----------------
    tab_catalog, tab_sessions = st.tabs(
        ["App Catalog", f"Sessions ({len(sessions)})"]
    )
    with tab_catalog:
        _render_zpa_app_catalog(data)
    with tab_sessions:
        _render_zpa_sessions_drilldown(sessions)


# ----------------------------------------------------------------------
# Phase 17 helper — top-of-module health banner.
# ----------------------------------------------------------------------

def _render_zpa_health_banner(sessions: List[Any]) -> None:
    """Render a compact health-vitals strip from the per-session
    lifecycle data. Traffic-light coloring telegraphs scope without
    requiring the engineer to scroll the catalog or sessions tab.

    Computed metrics:
      * failure_rate  — sessions with outcome "setup_failed" or
                        "closed:<reason>" / "incomplete"
      * slow_setups   — sessions with setup_latency_s > 0.1
      * byte_drops    — sessions with has_byte_imbalance True
      * total bytes   — uploaded / downloaded across all sessions
      * median setup  — median setup latency for sessions that have it
    """
    import statistics

    total = len(sessions)
    if total == 0:
        return

    # Phase 28 (2026-06-17): single-pass stats. Previously this
    # block walked `sessions` four times — once for failures, once
    # for slow setups, once for drops, twice for byte totals (Cl.Rx
    # + Cl.Tx). Combining into one pass is 4x fewer iterations and
    # cleaner code.
    failed = 0
    slow_setups = 0
    drops = 0
    total_up = 0
    total_down = 0
    setup_lats = []
    for s in sessions:
        if s.outcome not in ("closed", "open"):
            failed += 1
        if s.setup_latency_s is not None:
            setup_lats.append(s.setup_latency_s)
            if s.setup_latency_s > 0.1:
                slow_setups += 1
        if s.has_byte_imbalance:
            drops += 1
        # `or 0` guards None — happens on sessions that never had a
        # disconnect-stats line AND never had runtime byte events.
        total_up += (s.bytes_client_rx or 0)
        total_down += (s.bytes_client_tx or 0)

    failure_pct = (100 * failed / total) if total else 0
    median_setup_ms = (
        f"{statistics.median(setup_lats) * 1000:.0f} ms"
        if setup_lats else "—"
    )
    p95_setup_ms = "—"
    if len(setup_lats) >= 20:
        # Cheap p95: sort + index. statistics.quantiles needs n>=2.
        try:
            sorted_lats = sorted(setup_lats)
            idx = int(0.95 * len(sorted_lats))
            p95_setup_ms = f"{sorted_lats[idx] * 1000:.0f} ms"
        except (ValueError, IndexError):
            pass

    def _fmt(n: int) -> str:
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        if n < 1024 * 1024 * 1024:
            return f"{n / (1024 * 1024):.1f} MB"
        return f"{n / (1024 * 1024 * 1024):.2f} GB"

    # Traffic-light color per metric — Streamlit's st.metric delta
    # arrows are limited so we use captions with markdown color hints.
    st.markdown(
        '<div class="zd-section">ZPA health vitals</div>',
        unsafe_allow_html=True,
    )
    cols = st.columns(5)
    cols[0].metric(
        "Sessions",
        f"{total}",
        delta=None,
    )
    cols[1].metric(
        "Failure rate",
        f"{failure_pct:.0f}%",
        delta=f"{failed} of {total}",
        delta_color=(
            "inverse" if failure_pct >= 25 else
            "off" if failure_pct == 0 else "normal"
        ),
        help=(
            "Sessions that did NOT close cleanly. Includes setup-"
            "failed (broker rejected) and non-NORMAL close codes "
            "(closed:brk_mt_setup_fail_*, incomplete, etc.). 0% = "
            "every session ended gracefully."
        ),
    )
    cols[2].metric(
        "Slow setups (>100ms)",
        f"{slow_setups}",
        delta=f"median {median_setup_ms} · p95 {p95_setup_ms}",
        delta_color=(
            "inverse" if slow_setups >= total // 4 else "off"
        ),
        help=(
            "Sessions whose broker setup latency exceeded 100ms. "
            "High counts suggest broker-side stress or a network "
            "path with elevated RTT between client and broker."
        ),
    )
    cols[3].metric(
        "Data drops",
        f"{drops}",
        delta=(
            "byte-counter mismatch" if drops else "no drops detected"
        ),
        delta_color=(
            "inverse" if drops > 0 else "off"
        ),
        help=(
            "Sessions where client-side and server-side byte "
            "counters didn't mirror. Indicates data lost at one of "
            "the two pipes during the session."
        ),
    )
    cols[4].metric(
        "Total transfer",
        _fmt(total_up + total_down),
        delta=f"↓ {_fmt(total_down)}  /  ↑ {_fmt(total_up)}",
        delta_color="off",
        help=(
            "Aggregate bytes across every captured session. ↓ = "
            "server → client (download), ↑ = client → server "
            "(upload). Sessions without disconnect lines are excluded."
        ),
    )


# ----------------------------------------------------------------------
# Phase 16 helper — sessions drill-down tab.
# ----------------------------------------------------------------------

def _render_zpa_sessions_drilldown(sessions: List[Any]) -> None:
    """Filterable + sortable per-session table. Surfaces every Phase 13
    lifecycle field. Replaces the buried "Per-app mtunnel analytics"
    expander as the primary drill-in surface for ZPA session triage.
    """
    if not sessions:
        st.caption("_No ZPA sessions reconstructed from this bundle._")
        return

    from zcc_diag.zpa_session_correlator import sessions_summary_table

    # ---- Filter / sort controls ----------------------------------
    f_app_col, f_outcome_col, f_close_col, sort_col, dir_col = st.columns(
        [3, 2, 2, 2, 1]
    )
    with f_app_col:
        app_query = st.text_input(
            "Filter by app name (substring)",
            value="",
            placeholder="e.g. dc01 or salesforce",
            key="zpa_sess_filter_app",
        ).strip().lower()
    with f_outcome_col:
        outcomes_present = sorted(
            {s.outcome for s in sessions}
        )
        outcome_filter = st.multiselect(
            "Outcome",
            options=outcomes_present,
            default=outcomes_present,
            key="zpa_sess_filter_outcome",
        )
    with f_close_col:
        close_options = ["client", "broker", "broker_switch", ""]
        close_present = [
            o for o in close_options
            if any(s.close_initiator == o for s in sessions)
        ]
        # Default: everything visible.
        close_filter = st.multiselect(
            "Closed by",
            options=close_present,
            default=close_present,
            format_func=lambda x: x if x else "(unknown)",
            key="zpa_sess_filter_close",
        )
    with sort_col:
        sort_key = st.selectbox(
            "Sort by",
            options=[
                "Setup time",
                "Duration",
                "Setup latency",
                "Bytes (total)",
                "Data events",
                "App",
                "Outcome",
            ],
            index=0,
            key="zpa_sess_sort_key",
        )
    with dir_col:
        sort_desc = st.checkbox(
            "↓ desc",
            value=False,
            key="zpa_sess_sort_desc",
            help="Toggle ascending/descending sort.",
        )

    # ---- Apply filters --------------------------------------------
    filtered = []
    for s in sessions:
        if app_query and app_query not in (s.app_name or "").lower():
            continue
        if outcome_filter and s.outcome not in outcome_filter:
            continue
        if close_filter and s.close_initiator not in close_filter:
            continue
        filtered.append(s)

    # ---- Apply sort -----------------------------------------------
    from datetime import datetime as _dt
    def _sort_anchor(s):
        if sort_key == "Setup time":
            return s.setup_ts or s.request_ts or s.ack_ts or _dt.max
        if sort_key == "Duration":
            return s.duration_s if s.duration_s is not None else (
                -1 if sort_desc else 1e18
            )
        if sort_key == "Setup latency":
            return s.setup_latency_s if s.setup_latency_s is not None else (
                -1 if sort_desc else 1e18
            )
        if sort_key == "Bytes (total)":
            tb = s.total_bytes
            return tb if tb is not None else (
                -1 if sort_desc else 1e18
            )
        if sort_key == "Data events":
            return s.data_event_count
        if sort_key == "App":
            return (s.app_name or "").lower()
        if sort_key == "Outcome":
            return s.outcome
        return ""
    filtered.sort(key=_sort_anchor, reverse=sort_desc)

    # ---- Render the table ------------------------------------------
    rows = sessions_summary_table(filtered)
    n_shown = len(rows)
    n_total = len(sessions)
    if n_shown < n_total:
        st.caption(
            f"_{n_shown:,} of {n_total:,} sessions shown after filtering._"
        )
    else:
        st.caption(f"_{n_total:,} session(s)._")

    if not rows:
        st.info(
            "No sessions match the current filters. Try widening the "
            "outcome selection or clearing the app-name filter."
        )
        return

    # Use _redact_apps_in_rows so the app-domain column gets scrubbed
    # when --redact / PII toggle is on. The helper expects a list of
    # dicts with an "App" key — sessions_summary_table emits that
    # field directly.
    st.dataframe(
        _redact_apps_in_rows(rows),
        hide_index=True, use_container_width=True,
    )


# ----------------------------------------------------------------------
# Backwards-compat aliases.
# ----------------------------------------------------------------------
_ZSCALER_INFRA_PATTERNS = ZSCALER_INFRA_PATTERNS
_is_zscaler_infra_host = is_zscaler_infra_host
_filter_customer_bypass = filter_customer_bypass
_runtime_zia_zpa_active = runtime_zia_zpa_active
# Exposed so test_ui_imports + future modules can reference it without
# importing the bare function name.
render_zpa_app_catalog = _render_zpa_app_catalog
_consolidate_policy_rows = consolidate_policy_rows
_module_policy = module_policy
_module_zia = module_zia
_module_zpa = module_zpa
