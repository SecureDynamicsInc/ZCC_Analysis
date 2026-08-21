"""
Symptom Triage module — pick a customer-reported symptom, see the
findings the relevant detectors fired.

The page flow:

  1. Choose suite (ZIA / ZPA) — picks one of two symptom catalogues
     defined in ``wizard.py``.
  2. Pick a symptom from the catalogue (selectbox).
  3. The relevant detector IDs for that symptom are looked up; their
     findings are filtered with a suite-aware code-prefix rule so
     ZIA codes never leak into a ZPA symptom and vice versa.
  4. For the *Slowness* symptom path, two extra helpers are applied:
       * ``scope_slowness_findings`` — drop tunnel/adapter findings
         that don't temporally overlap an actual slowness signal.
       * ``build_slowness_narrative`` — compose a plain-English
         verdict from app_health MTR data naming the offending leg.
  5. Findings render through the standard clustered list pipeline so
     the Symptoms view stays visually consistent with Findings.

The two slowness helpers are exported because the Overview module's
"It's slow" focus uses the same logic. Keeping them here (rather than
in a separate ``slowness.py``) puts the symptom-related code together
and lets ``ui.overview`` import from ``ui.symptoms`` cleanly without
the reverse dependency.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import streamlit as st

from zcc_diag.issues import Severity
from zcc_diag.wizard import (
    ZIA_SYMPTOMS, ZPA_SYMPTOMS,
    _filter_catalogue_by_os,
)
from zcc_diag.ui.findings import _real_findings, _render_finding_list


# ----------------------------------------------------------------------
# Slowness scope + narrative — shared with the Overview module's
# "It's slow" focus chip.
# ----------------------------------------------------------------------

def scope_slowness_findings(findings: List[Dict[str, Any]]
                             ) -> List[Dict[str, Any]]:
    """For the Slowness symptom: include slowness detector findings
    unconditionally; include tunnel / adapter findings ONLY when their
    ``time_range`` overlaps a slowness signal's window (±5 min).

    Rationale: a tunnel flap from hours before the customer reported
    slowness isn't the cause of slowness. Keeping those in the slowness
    view dilutes the signal. They still appear in the main Findings
    module untouched.
    """
    slowness_codes = {"SLOWNESS_SIGNALS", "CPT_EVENT_DETECTED",
                      "ZTRACEROUTE_NOT_COLLECTED"}
    slowness = [f for f in findings if f["code"] in slowness_codes]
    if not slowness:
        # No slowness signals in this bundle → nothing to scope against;
        # return only the slowness-detector items (which may be empty).
        return slowness

    # Build the union of slowness windows. Each finding's ``time_range``
    # is (start, end) — historically documented as ISO strings, but
    # since Phase 47 (RCA framework) they are actual ``datetime``
    # objects. Phase 58e-H13 (2026-07-08): tolerate both forms.
    #
    # Prior code called ``datetime.fromisoformat(tr[0])`` on a
    # datetime, which raises TypeError. The TypeError was caught
    # silently by the try/except → every finding's window failed to
    # parse → scoping did nothing → slowness-adjacent findings were
    # never filtered. Defeated the whole point of this function.
    from datetime import datetime, timedelta
    def _coerce_dt(v):
        if v is None:
            return None
        if isinstance(v, datetime):
            return v
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except ValueError:
                return None
        return None

    windows: List[Tuple[datetime, datetime]] = []
    for f in slowness:
        tr = f.get("time_range") or (None, None)
        start = _coerce_dt(tr[0])
        end = _coerce_dt(tr[1]) or start
        if start is None:
            continue
        # Pad ±5 min for correlation
        windows.append((start - timedelta(minutes=5),
                        end + timedelta(minutes=5)))

    def _overlaps_any_window(f) -> bool:
        tr = f.get("time_range") or (None, None)
        s = _coerce_dt(tr[0])
        e = _coerce_dt(tr[1]) or s
        if s is None:
            return False
        for wlo, whi in windows:
            if not (e < wlo or s > whi):
                return True
        return False

    # Slowness-detector findings always in. Others gated by window
    # overlap. Findings that have NO time_range (older bundles) get
    # included as a courtesy — being conservative about hiding signals.
    out = list(slowness)
    for f in findings:
        if f in slowness:
            continue
        if windows and _overlaps_any_window(f):
            out.append(f)
        elif not windows:
            out.append(f)  # no windows to gate against — keep all
    return out


def build_slowness_narrative(scoped: List[Dict[str, Any]],
                              app_rows: List[Dict[str, Any]],
                              ) -> Optional[Dict[str, str]]:
    """Compose a one-paragraph narrative explaining the slowness
    picture. Returns ``{"headline": str, "body": str, "verdict_class":
    "ok"|"warn"|"bad"|"info"}`` or None if there's nothing to narrate.
    """
    slowness_codes = {"SLOWNESS_SIGNALS", "CPT_EVENT_DETECTED"}
    slowness = [f for f in scoped if f["code"] in slowness_codes]

    # Identify the offending leg(s) from app_health.
    bad_legs: Dict[str, int] = {}
    leg_apps: Dict[str, List[str]] = {}
    for r in app_rows:
        if r.get("verdict") not in ("warn", "bad"):
            continue
        # The verdict_reason names the offending leg e.g.
        # "client→Zscaler 220ms/3% loss" or "underlay 1.8s/2% loss"
        reason = (r.get("verdict_reason") or "").lower()
        for leg_token in ("underlay", "client→zscaler", "client->zscaler",
                          "zscaler→app", "zscaler->app", "zen"):
            if leg_token in reason:
                norm = leg_token.replace("->", "→")
                bad_legs[norm] = bad_legs.get(norm, 0) + 1
                leg_apps.setdefault(norm, []).append(r.get("app_name", "?"))
                break

    # Verdict classification
    if not slowness and not bad_legs:
        return {
            "headline": (
                "No sustained slowness signals detected in this"
                "bundle's analyzed window"
            ),
            "body": (
                "The slowness detector found no degraded sessions. "
                "If your customer reports slowness, it likely happened "
                "outside the window covered by this bundle (re-export "
                "during a live slow event) or affects an app type the "
                "detector doesn't yet recognise (e.g. UDP voice / "
                "video that ZCC doesn't traceroute)."
            ),
            "verdict_class": "ok",
        }

    if bad_legs and not slowness:
        # MTR flagged a leg but the slowness detector didn't.
        # Likely transit ICMP rate-limiting, not real slowness.
        leg = max(bad_legs, key=bad_legs.get)
        return {
            "headline": (
                f"Per-leg traces show {leg} degradation but no"
                f"end-to-end slowness was detected"
            ),
            "body": (
                f"The MTR data shows {bad_legs[leg]} app(s) with "
                f"elevated latency or loss on the {leg} leg "
                f"({', '.join(leg_apps[leg][:5])}). However, the "
                f"slowness detector — which correlates ZDX webload "
                f"timings and tunnel state — did NOT flag any "
                f"sustained slow sessions. <br><br>"
                f"This is usually <b>transit-network ICMP rate-"
                f"limiting</b>, not real Zscaler slowness. Encrypted "
                f"app traffic flows through the SME tunnel (the same "
                f"path ICMP can't follow), so the actual user "
                f"experience may be fine. Confirm with a real "
                f"page-load test before treating this as a slowness "
                f"incident."
            ),
            "verdict_class": "info",
        }

    # We have actual slowness signals.
    if bad_legs:
        leg = max(bad_legs, key=bad_legs.get)
        apps_str = ", ".join(leg_apps[leg][:5])
        verdict_class = "bad"
        headline = (
            f"Slowness detected — bottleneck localized to "
            f"the <b>{leg}</b> leg"
        )
        body = (
            f"The slowness detector flagged {len(slowness)} signal(s) "
            f"in this bundle. The MTR data points at the <b>{leg}</b> "
            f"leg as the dominant cause "
            f"({bad_legs[leg]} app(s) affected: {apps_str}). "
            f"<br><br>"
            f"<b>What this means:</b><br>"
            f"• <i>underlay</i> = machine→LAN gateway. Local network "
            f"or ISP first-hop is degraded.<br>"
            f"• <i>client→Zscaler</i> = transit between your ISP and "
            f"the Zscaler SME. Usually transit-provider congestion "
            f"or ICMP rate-limiting (check via webload timings).<br>"
            f"• <i>Zscaler→app</i> = Zscaler SME to the application's "
            f"origin server. App-side or origin-side issue, not a "
            f"Zscaler problem."
        )
    else:
        verdict_class = "warn"
        headline = (
            f"Slowness signals detected — leg-level cause "
            f"not localized from MTR"
        )
        body = (
            f"The slowness detector flagged {len(slowness)} signal(s) "
            f"but the MTR per-leg data didn't show a clearly "
            f"degraded leg. Likely causes: (1) the degradation is "
            f"sporadic and missed by median-based per-leg stats; "
            f"(2) the slow app wasn't being MTR-probed during the "
            f"slow window; (3) the bottleneck is at the application "
            f"or origin server, not in the transport path. "
            f"Check the slowness-detector evidence below for the "
            f"specific signals."
        )
    return {
        "headline": headline,
        "body": body,
        "verdict_class": verdict_class,
    }


# ----------------------------------------------------------------------
# The module entry point.
# ----------------------------------------------------------------------

def module_symptoms(data: Dict[str, Any]) -> None:
    """Combined ZIA/ZPA symptom selector → scoped findings."""
    findings = _real_findings(data["findings"])
    s = data["summary"]
    os_family = (s.os or {}).get("family")
    use_os_filter = os_family in ("windows", "macos")

    suite = st.radio(
        "Triage suite",
        ["ZIA (Internet access)", "ZPA (Private access)"],
        horizontal=True, key="symptom_suite",
    )
    catalogue = ZIA_SYMPTOMS if suite.startswith("ZIA") else ZPA_SYMPTOMS
    if use_os_filter:
        catalogue = _filter_catalogue_by_os(catalogue, os_family)

    labels = [row["label"] for row in catalogue]
    pick = st.selectbox(
        "Pick a symptom that matches what the user reported",
        labels, index=0, key="symptom_pick",
    )
    row = next(r for r in catalogue if r["label"] == pick)
    st.caption(f"Detectors checked: `{', '.join(row['detectors'])}`")

    # Suite-aware finding scope. Several detectors — notably
    # ``tunnel_not_established`` and ``adapter_instability`` — observe
    # the state machine for BOTH ZIA and ZPA tunnels and emit codes
    # prefixed with the corresponding suite (``ZIA_TUNNEL_DOWN_*``,
    # ``ZPA_TUNNEL_DOWN_*``, ``ZCC_ZIA_*``, ``ZCC_ZPA_*``). Filtering
    # by ``detector_id`` alone leaks ZIA codes into a ZPA triage and
    # vice versa.
    #
    # Rule:
    #   * ZIA suite: drop codes that explicitly start with a ZPA prefix.
    #   * ZPA suite: drop codes that explicitly start with a ZIA prefix.
    #   * Suite-neutral codes (LWF_*, LOCAL_NETWORK_DOWN, NETERR_*,
    #     CAPTIVE_*, T2_*, ADAPTER_*, etc.) pass through both — those
    #     genuinely affect either side and shouldn't be filtered out.
    if suite.startswith("ZIA"):
        wrong_prefixes = ("ZPA_", "ZCC_ZPA_")
    else:
        wrong_prefixes = ("ZIA_", "ZCC_ZIA_")

    def _matches_suite(f):
        code = f.get("code", "")
        return not any(code.startswith(p) for p in wrong_prefixes)

    raw_scoped = [
        f for f in findings
        if f["detector_id"] in row["detectors"] and _matches_suite(f)
    ]
    is_slowness_pick = (
        "slowness" in row.get("detectors", []) or "slow" in pick.lower()
    )

    # Scope BEFORE computing metrics. For the slowness symptom, drop
    # tunnel-not-established / adapter-instability findings that don't
    # temporally overlap a real slowness signal — those are noise for
    # this triage path. Other symptoms use the raw scoped list.
    if is_slowness_pick:
        scoped = scope_slowness_findings(raw_scoped)
    else:
        scoped = raw_scoped

    crit = [f for f in scoped if f["severity"] == Severity.CRITICAL]
    warn = [f for f in scoped if f["severity"] == Severity.WARNING]
    c1, c2, c3 = st.columns(3)
    c1.metric("Matching findings", len(scoped))
    c2.metric("Critical", len(crit))
    c3.metric("Warning", len(warn))

    # For slowness: tell the engineer what was filtered out (and why)
    # so the count metrics aren't surprising.
    if is_slowness_pick and len(raw_scoped) > len(scoped):
        n_drop = len(raw_scoped) - len(scoped)
        st.caption(
            f"_Note: {n_drop} tunnel / adapter finding(s) excluded "
            f"because they don't temporally overlap any slowness "
            f"signal in this bundle (±5 min). They remain visible in "
            f"the **Findings** module._"
        )

    if not scoped and not is_slowness_pick:
        # Empty state framed as a positive confirmation, not a warning.
        # "No findings matched" is actually good news — the symptom
        # path is clean.
        st.success(
            "**Clean on this symptom.** The relevant detectors didn't "
            "find anything in this bundle. If your customer is still "
            "reporting the issue, try re-exporting during a live event "
            "or check **Search** for specific hostnames / URLs.",
        )
        return

    # ---- Slowness-specific narrative + per-leg detail ----
    if is_slowness_pick:
        narrative = build_slowness_narrative(
            scoped, data["summary"].bundle_meta.get("app_health") or [],
        )
        if narrative:
            verdict_class = narrative.get("verdict_class", "info")
            st.markdown(
                f'<div class="zd-finding-card zd-sev-{verdict_class}">'
                f'<div class="zd-finding-title">'
                f'{narrative["headline"]}</div>'
                f'<div class="zd-finding-meta">'
                f'{narrative["body"]}</div></div>',
                unsafe_allow_html=True,
            )

        # Per-leg detail table behind an expander so the narrative
        # carries the message and the engineer can drill in if they
        # need the underlying numbers.
        app_rows = data["summary"].bundle_meta.get("app_health") or []
        if app_rows:
            with st.expander(
                "Per-leg latency details (from MTR)  ·  "
                f"{len(app_rows)} app(s) measured",
                expanded=False,
            ):
                rows = []
                for r in app_rows:
                    mark = {"ok": "Healthy", "warn": "Degraded",
                            "bad": "Critical"}.get(r["verdict"], "?")
                    rows.append({
                        "status": mark,
                        "app": r["app_name"],
                        "tunneling": (
                            f"via {r['sme_dc']}" if r.get("sme_dc")
                            else ("via Zscaler" if r.get("via_zscaler")
                                  else "direct")
                        ),
                        "underlay ms":
                            r.get("underlay_latency_median_ms"),
                        "client→Zscaler ms":
                            r.get("zen_latency_median_ms"),
                        "Zscaler→app ms":
                            r.get("server_latency_median_ms"),
                        "verdict": r["verdict_reason"],
                    })
                st.dataframe(
                    rows, hide_index=True, use_container_width=True,
                    column_config={
                        "underlay ms":
                            st.column_config.NumberColumn(format="%.0f"),
                        "client→Zscaler ms":
                            st.column_config.NumberColumn(format="%.0f"),
                        "Zscaler→app ms":
                            st.column_config.NumberColumn(format="%.0f"),
                    },
                )
                st.caption(
                    "Each row's `verdict` names the leg responsible "
                    "for any degradation. Open the **App Path "
                    "Analysis (ZDX)** module for the full hop-by-hop "
                    "drill-down."
                )

    # Render findings via the same clustering / grouping pipeline used
    # by the Findings module — so root-cause families (e.g. all the
    # ZIA tunnel-down sub-codes) collapse to ONE consolidated card here
    # too.
    _render_finding_list(
        scoped,
        empty=(
            "Nothing matched this symptom's detectors. The signature "
            "isn't present in the bundle's analyzed window."
        ),
    )


# ----------------------------------------------------------------------
# Backwards-compat aliases.
# ----------------------------------------------------------------------
_scope_slowness_findings = scope_slowness_findings
_build_slowness_narrative = build_slowness_narrative
_module_symptoms = module_symptoms
