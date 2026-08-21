"""
App Path Analysis (ZDX) module — per-application MTR data sourced
from ZDX traceroute probes.

The module renders three sections in priority order:

  1. **Application reachability** — one row per app the customer
     actually uses. For ZIA-tunnelled apps the row shows all three
     legs (underlay / client→Zscaler / Zscaler→app). For BYPASS apps
     it shows two (underlay / direct→app).
  2. **(removed)** Standalone ICMP edge probes used to render here;
     dropped because ICMP loss to the SME is dominated by transit
     rate-limiting and routinely misled engineers into thinking the
     Zscaler edge was degraded when encrypted app traffic flowing
     through the same SME was perfectly healthy. Data still lives in
     ``bundle_meta["edge_probes"]`` for any detector that wants it.
  3. **Per-app drill-down** — pick an app, see its full leg-by-leg
     hop trace.

The module is intentionally narrow: it doesn't try to derive a
verdict for ZIA / ZPA tunnel state. That lives in the detector
layer. This view is *just* the MTR picture.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import streamlit as st

from zcc_diag.ui.narrators import _narrate_app_health


def ztr_status(loss: Optional[float], p90: Optional[float]) -> str:
    """Combined health classification — ``ok`` / ``warn`` / ``bad``.

    The thresholds match the Path Health caption shown below the
    reachability table:

      * ``bad``   — loss ≥ 5%  OR  p90 ≥ 250 ms (Critical)
      * ``warn``  — loss ≥ 1%  OR  p90 ≥ 100 ms (Degraded)
      * ``ok``    — otherwise (Healthy)
    """
    loss = loss or 0
    p90 = p90 or 0
    if loss >= 5 or p90 >= 250:
        return "bad"
    if loss >= 1 or p90 >= 100:
        return "warn"
    return "ok"


def aggregate_hops(hop_groups: List[List[Dict[str, Any]]],
                    renumber: bool = False) -> List[Dict[str, Any]]:
    """Pool hops from N traces by hop index, return one row per
    hop index with median RTT, median loss%, distinct IPs seen.

    ``renumber=True`` shifts indices to start at 1 (used for the
    internet-path leg, which in JSON traces starts at hop 9-ish).
    """
    import collections
    if not hop_groups:
        return []

    # If renumbering, find the minimum hop index across ALL traces
    # in the group; subtract it so the first hop in the leg = 1.
    min_index = None
    if renumber:
        for hops in hop_groups:
            for h in hops:
                idx = h.get("index")
                if idx is None:
                    continue
                if min_index is None or idx < min_index:
                    min_index = idx
        if min_index is None:
            min_index = 1

    agg: Dict[int, Dict[str, Any]] = {}
    for hops in hop_groups:
        for h in hops:
            idx = h.get("index")
            if idx is None:
                continue
            display_idx = (idx - min_index + 1) if renumber else idx
            rec = agg.setdefault(display_idx, {
                "index": display_idx,
                "ip_counter": collections.Counter(),
                "rtt_samples": [],
                "loss_samples": [],
                "probes_total": 0,
                "responses_total": 0,
            })
            ip = h.get("ip") or ""
            if ip:
                rec["ip_counter"][ip] += 1
            rec["probes_total"] += 1
            if h.get("rtt_ms") is not None:
                rec["rtt_samples"].append(float(h["rtt_ms"]))
                rec["responses_total"] += 1
            if h.get("loss_pct") is not None:
                rec["loss_samples"].append(float(h["loss_pct"]))

    def _med(vs):
        if not vs:
            return None
        ss = sorted(vs)
        return ss[len(ss) // 2]

    rows = []
    for idx in sorted(agg.keys()):
        rec = agg[idx]
        med_rtt = _med(rec["rtt_samples"])
        med_loss = _med(rec["loss_samples"])
        if med_loss is None and rec["probes_total"] > 0:
            med_loss = 100.0 * (
                1 - rec["responses_total"] / rec["probes_total"]
            )
        ip_counter = rec["ip_counter"]
        if not ip_counter:
            ip_cell = "(unresponsive)"
        else:
            top_ip, _ = ip_counter.most_common(1)[0]
            n_distinct = len(ip_counter)
            if n_distinct == 1:
                ip_cell = top_ip
            else:
                ip_cell = f"{top_ip} (+{n_distinct - 1} alt IPs)"
        status = "ok"
        if (med_loss or 0) >= 50:
            status = "bad"
        elif (med_loss or 0) >= 10 or (med_rtt or 0) >= 200:
            status = "warn"
        rows.append({
            "status": {"ok": "Healthy", "warn": "Degraded",
                       "bad": "Critical"}[status],
            "hop": idx,
            "hop IP": ip_cell,
            "probes": rec["probes_total"],
            "median ms": float(med_rtt) if med_rtt is not None else None,
            "loss %": float(med_loss) if med_loss is not None else None,
            "_ip_counter": ip_counter,
            "_probes_total": rec["probes_total"],
        })
    return rows


def render_one_leg_table(rows, title, caption):
    """Render one leg of an app's hop trace as a dataframe + caption.

    Strips the underscore-prefixed internal-only keys from each row
    before display, and adds an ECMP / route-flap disclosure when the
    same hop saw multiple IPs.
    """
    if not rows:
        # Quiet caption — this is a sub-section of a drill-in view;
        # an info banner here would be visual noise.
        st.caption(
            f"_No {title.lower()} data captured in this destination's "
            f"traces._"
        )
        return
    display_rows = [
        {k: v for k, v in r.items() if not k.startswith("_")}
        for r in rows
    ]
    st.markdown(f"**{title}** — {len(rows)} hop(s)")
    st.dataframe(
        display_rows, hide_index=True, use_container_width=True,
        column_config={
            "median ms": st.column_config.NumberColumn(format="%.0f"),
            "loss %": st.column_config.NumberColumn(format="%.1f%%"),
        },
    )
    # Compact multi-IP breakdown for hops where ECMP / route flap was seen.
    multi = [
        r for r in rows
        if r["_ip_counter"] and len(r["_ip_counter"]) > 1
    ]
    if multi:
        with st.expander(
            f"Hops with multiple IPs observed in this leg "
            f"({len(multi)} hop(s) — ECMP / route flap)",
            expanded=False,
        ):
            mi_rows = []
            for r in multi:
                for ip, count in r["_ip_counter"].most_common():
                    mi_rows.append({
                        "hop": r["hop"],
                        "IP": ip,
                        "times seen": count,
                        "% of traces at this hop": (
                            f"{100*count/r['_probes_total']:.0f}%"
                            if r["_probes_total"] else "?"
                        ),
                    })
            st.dataframe(mi_rows, hide_index=True,
                         use_container_width=True)
    st.caption(caption)


def render_app_drilldown(app_row: Dict[str, Any],
                          all_traces: List[Dict[str, Any]]):
    """Show 2 or 3 leg tables for ONE app, based on whether it's
    ZIA-tunneled.

    For ZIA-tunneled apps:
      Leg 1 — Underlay        (machine → first transit)
      Leg 2 — Client→Zscaler  (transit → DFW2 SME etc)
      Leg 3 — Zscaler→App     (SME → actual app server)

    For BYPASS / direct apps:
      Leg 1 — Underlay        (machine → first transit)
      Leg 2 — Direct→App      (transit → app server, NO Zscaler hop)
    """
    app_name = app_row["app_name"]
    target = app_row["app_target_ip"]
    sme_dc = app_row.get("sme_dc")
    via_zs = app_row["via_zscaler"]

    # Find all legs that belong to this app's MTR runs.
    app_traces = [t for t in all_traces if t.get("app_name") == app_name]
    if not app_traces:
        # Fallback: match by destination IP
        app_traces = [t for t in all_traces
                      if t.get("destination_ip") == target]

    underlay_legs = [t for t in app_traces
                     if t.get("destination_kind") == "EGRESS"]
    zen_legs = [t for t in app_traces
                if t.get("destination_kind") == "ZEN"
                and t.get("format") == "json"]
    server_legs = [t for t in app_traces
                   if t.get("destination_kind") == "SERVER"]

    # Show the route summary at top.
    if via_zs:
        st.markdown(
            f"**{app_name}** — `{target}` "
            f"(via Zscaler **{sme_dc or '?'}**)"
        )
        st.caption(
            f"Route: machine → first transit → "
            f"Zscaler {sme_dc or 'edge'} → {target}"
        )
    else:
        st.markdown(
            f"**{app_name}** — `{target}` (direct / tunnel-bypassed)"
        )
        st.caption(
            f"Route: machine → first transit → {target} (NO Zscaler hop)"
        )

    # ---- Leg 1: Underlay ----
    if underlay_legs:
        render_one_leg_table(
            aggregate_hops(
                [l.get("hops") or [] for l in underlay_legs],
                renumber=False,
            ),
            "Leg 1 — Underlay  (machine → first transit router)",
            "Path from the customer's machine through their LAN gateway, "
            "corporate FW, ISP modem, and ISP backbone. Loss / latency "
            "here = local or ISP — NOT Zscaler.",
        )
        st.write("")

    # ---- Leg 2: Client → Zscaler (only for ZIA-tunneled apps) ----
    if via_zs and zen_legs:
        render_one_leg_table(
            aggregate_hops(
                [l.get("hops") or [] for l in zen_legs],
                renumber=True,
            ),
            f"Leg 2 — Client to Zscaler  "
            f"(first transit → {sme_dc or 'Zscaler edge'})",
            "Path from the first responsive transit router to the "
            "Zscaler edge that handles this app. Loss / latency here "
            "= transit-network problem between the customer's ISP and "
            "Zscaler. This is the leg that often gets blamed on Zscaler "
            "but is actually transit-network.",
        )
        st.write("")

    # ---- Last leg: Server (Zscaler → App) or Direct → App ----
    if server_legs:
        if via_zs:
            title = (
                f"Leg 3 — Zscaler to App  "
                f"({sme_dc or 'Zscaler edge'} → {target})"
            )
            caption = (
                "Path from the Zscaler edge through Zscaler's backbone "
                "and out to the actual app server. Loss / latency here "
                "= Zscaler-side or destination-network. ICMP loss in "
                "this leg is often rate-limiting by the destination "
                "(many app providers cap ICMP), NOT real packet loss."
            )
        else:
            title = (
                f"Leg 2 — Direct to App  (first transit → {target})"
            )
            caption = (
                "Path from the first transit router straight to the app "
                "server, bypassing Zscaler. Loss / latency here = "
                "internet-transit or destination-network — NOT Zscaler."
            )
        render_one_leg_table(
            aggregate_hops(
                [l.get("hops") or [] for l in server_legs],
                renumber=True,
            ),
            title, caption,
        )
    st.caption(
        "Healthy = hop normal · Degraded = ≥10% loss or ≥200ms · "
        "Unreachable = ≥50% loss. "
        "Hop numbers are normalized to start at 1 per leg for "
        "readability."
    )


def module_path_health(data: Dict[str, Any]) -> None:
    """App Path Analysis (ZDX) module entry point.

    Per-application MTR data sourced from ZDX traceroute probes:
    loss + latency per leg (underlay, client→Zscaler, Zscaler→app for
    tunnelled apps; underlay + direct→app for bypassed apps).
    """
    meta = data["summary"].bundle_meta or {}
    app_rows = meta.get("app_health") or []
    edge_rows = meta.get("edge_probes") or []
    raw_traces = meta.get("ztraceroute_traces") or []

    # ---- CENR data-source banner ----
    # Tells the user whether DC names come from Zscaler's CENR (best)
    # or from in-bundle heuristics (when CENR doesn't know an IP).
    try:
        from zcc_diag import zscaler_dc_lookup
        cenr_status = zscaler_dc_lookup.load_status()
    except Exception as _exc:  # pragma: no cover -- module not installed
        cenr_status = f"CENR lookup unavailable ({_exc})"
    st.caption(f"DC labelling: {cenr_status}")

    if not app_rows and not edge_rows:
        st.info(
            "**App Path Analysis needs ZTraceroute data**, and this "
            "bundle doesn't have any. Enable **Diagnostic Route "
            "Collection** in the customer's app profile, then "
            "re-export during a problem window.",
        )
        return

    # ---- Section 1: Application reachability ----
    if app_rows:
        st.markdown(
            '<div class="zd-section">Application reachability</div>',
            unsafe_allow_html=True,
        )
        # Narrative headline FIRST — one sentence telling the engineer
        # the takeaway before they look at the table.
        st.markdown(
            _narrate_app_health(app_rows),
            unsafe_allow_html=True,
        )
        rows = []
        for r in app_rows:
            mark = {"ok": "Healthy", "warn": "Degraded",
                    "bad": "Critical"}.get(r["verdict"], "?")
            tunneling = (
                f"via {r['sme_dc']}" if r["sme_dc"]
                else ("via Zscaler" if r["via_zscaler"] else "direct")
            )
            rows.append({
                "status": mark,
                "app": r["app_name"],
                "tunneling": tunneling,
                "end-to-end ms": (
                    float(r["latency_median_ms"])
                    if r.get("latency_median_ms") is not None else None
                ),
                "end-to-end loss %": (
                    float(r["loss_median_pct"])
                    if (r.get("loss_median_pct") or -1) >= 0 else None
                ),
                "underlay ms": (
                    float(r["underlay_latency_median_ms"])
                    if r.get("underlay_latency_median_ms") is not None
                    else None
                ),
                "Zscaler ms": (
                    float(r["zen_latency_median_ms"])
                    if r.get("zen_latency_median_ms") is not None
                    else None
                ),
                "server ms": (
                    float(r["server_latency_median_ms"])
                    if r.get("server_latency_median_ms") is not None
                    else None
                ),
                "probes": r["run_count"],
                "verdict": r["verdict_reason"],
            })
        # Table behind a disclosure so the narrative leads the page.
        with st.expander(
            f"Show full table  ·  {len(rows)} app(s) measured",
            expanded=False,
        ):
            st.dataframe(
                rows, hide_index=True, use_container_width=True,
                column_config={
                    "end-to-end ms":
                        st.column_config.NumberColumn(format="%.0f"),
                    "end-to-end loss %":
                        st.column_config.NumberColumn(format="%.1f%%"),
                    "underlay ms":
                        st.column_config.NumberColumn(format="%.0f"),
                    "Zscaler ms":
                        st.column_config.NumberColumn(format="%.0f"),
                    "server ms":
                        st.column_config.NumberColumn(format="%.0f"),
                },
            )
            st.caption(
                "End-to-end is the median MTR latency across runs to "
                "each app. Per-leg latency columns show where in the "
                "path the time is being spent. **A leg with high "
                "latency or loss is where the actual problem lives.** "
                "The `verdict` column names the offending leg(s)."
            )

    # ---- Section 3: Per-app drill-down ----
    if app_rows:
        st.markdown(
            '<div class="zd-section">Per-app drill-down — full '
            'hop trace</div>',
            unsafe_allow_html=True,
        )
        labels = [
            f"{r['app_name']}  ·  {r['app_target_ip']}  "
            f"({'via ' + (r['sme_dc'] or 'Zscaler') if r['via_zscaler'] else 'direct'})"
            for r in app_rows
        ]
        pick = st.selectbox(
            "Pick an app to see its leg-by-leg trace",
            labels, index=0, key="app_drilldown",
        )
        idx = labels.index(pick)
        render_app_drilldown(app_rows[idx], raw_traces)


# ----------------------------------------------------------------------
# Backwards-compat aliases.
# ----------------------------------------------------------------------
_ztr_status = ztr_status
_aggregate_hops = aggregate_hops
_render_one_leg_table = render_one_leg_table
_render_app_drilldown = render_app_drilldown
_module_path_health = module_path_health
