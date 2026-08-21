"""
Narrative-first table summaries.

Every data table in the UI leads with a one-sentence headline that
names the TAKEAWAY. The raw table goes behind a "Show full table"
disclosure. Rationale: an engineer scanning the Overview should see
what matters in one read, not have to parse a 6-column table.

Each helper returns Markdown-ready text (caller passes it through
``st.markdown(text, unsafe_allow_html=True)``).
"""

from __future__ import annotations

from typing import Any, Dict, List


def narrate_app_health(app_rows: List[Dict[str, Any]]) -> str:
    """One-line summary of the per-app MTR reachability matrix."""
    if not app_rows:
        return ""
    n = len(app_rows)
    ok = sum(1 for r in app_rows if r.get("verdict") == "ok")
    warn = sum(1 for r in app_rows if r.get("verdict") == "warn")
    bad = sum(1 for r in app_rows if r.get("verdict") == "bad")
    via_z = sum(1 for r in app_rows if r.get("via_zscaler"))

    if bad == 0 and warn == 0:
        verdict = f"**All {n} app(s) measured are healthy.**"
        detail = f"{via_z} flow via Zscaler; the rest go direct."
    elif bad > 0:
        worst = next(
            (r for r in app_rows if r.get("verdict") == "bad"), None
        )
        leg_hint = ""
        if worst:
            reason = (worst.get("verdict_reason") or "").lower()
            if "underlay" in reason:
                leg_hint = " (underlay / local network)"
            elif "client→zscaler" in reason or "zen" in reason:
                leg_hint = " (client→Zscaler transit)"
            elif "zscaler→app" in reason or "server" in reason:
                leg_hint = " (Zscaler→app / origin side)"
        verdict = f"**{bad} of {n} app(s) degraded**{leg_hint}."
        detail = (
            f"{ok} healthy, {warn} marginal, {bad} bad. "
            f"Open the table for per-leg latency breakdown."
        )
    else:  # warn only
        verdict = f"**{warn} of {n} app(s) marginal**."
        detail = (
            f"No criticals, but some apps show elevated latency or "
            f"loss on at least one leg. Open the table for which."
        )
    return f"{verdict}<br>_{detail}_"


def narrate_bypass_resolutions(
    bypass: Dict[str, List[str]],
) -> str:
    """One-line summary of the bypass / forwarding-profile cache."""
    if not bypass:
        return ""
    n_hosts = len(bypass)
    n_ips = sum(len(v) for v in bypass.values())
    if n_hosts > 200:
        verdict = (
            f"**{n_hosts} bypassed hostnames** resolving to "
            f"{n_ips} IPs (large cache)."
        )
        detail = (
            "That's an unusually large bypass cache. Wildcards may "
            "be over-broad — review the forwarding profile."
        )
    else:
        verdict = (
            f"**{n_hosts} bypassed hostnames** resolving to "
            f"{n_ips} IPs."
        )
        detail = (
            "Standard bypass cache size. Open the table to see which "
            "hosts/IPs are skipping the tunnel."
        )
    return f"{verdict}<br>_{detail}_"


def narrate_service_edges(service_edges: Dict[str, List[str]]) -> str:
    """One-line summary of the SME service-edge inventory."""
    if not service_edges:
        return ""
    n_hosts = len(service_edges)
    n_ips = sum(len(ips) for ips in service_edges.values() if ips)
    return (
        f"**{n_hosts} Zscaler service edge(s)** resolved "
        f"({n_ips} unique IPs).<br>"
        f"_These are the SMEs ZCC discovered for this tenant; the "
        f"primary in use is on the header strip._"
    )


def narrate_log_kinds(kinds: Dict[str, int]) -> str:
    """One-line summary of log-file counts by component kind."""
    if not kinds:
        return ""
    have_tunnel = kinds.get("tunnel", 0)
    have_tray = kinds.get("tray_manager", 0) + kinds.get("tray", 0)
    have_service = kinds.get("service", 0)
    have_ztr = (
        kinds.get("zdx_traceroute", 0) + kinds.get("ztraceroute", 0)
    )
    if not have_tunnel and not have_service:
        verdict = (
            "**No tunnel or service logs in this bundle.** "
            "Detector coverage will be very limited."
        )
        detail = "Verify the export was complete."
    else:
        bits = []
        if have_tunnel: bits.append(f"{have_tunnel} tunnel")
        if have_service: bits.append(f"{have_service} service")
        if have_tray: bits.append(f"{have_tray} tray")
        if have_ztr: bits.append(f"{have_ztr} ZTraceroute")
        verdict = f"**Log inventory:** {', '.join(bits)}."
        if not have_ztr:
            detail = (
                "_Note: no ZTraceroute logs → the App Path Analysis "
                "(ZDX) module won't have data. Enable Diagnostic "
                "Route Collection for that view._"
            )
        else:
            detail = "_Full triage coverage available._"
    return f"{verdict}<br>{detail}"


def narrate_security_products(products: List[str]) -> str:
    """One-line summary of detected endpoint security products."""
    if not products:
        return ""
    n = len(products)
    sample = ", ".join(products[:3])
    more = f" + {n-3} more" if n > 3 else ""
    return (
        f"**{n} endpoint security product(s) detected:** "
        f"{sample}{more}.<br>"
        f"_Informational only — these aren't necessarily blocking "
        f"ZCC, but they shape the triage path. Check the Findings "
        f"module for any active interference._"
    )


def narrate_apps_installed(apps: List[Dict[str, Any]]) -> str:
    """One-line summary of the apps-installed inventory."""
    if not apps:
        return ""
    n = len(apps)
    return (
        f"**{n} running application(s) detected** at bundle "
        f"export time.<br>"
        f"_Open the table to scan for VPN clients, virtual switches, "
        f"or third-party agents that often coexist poorly with ZCC._"
    )


# Backwards-compat aliases (the underscore-prefixed names existed
# before the v45 module split; keeping them lets existing call sites
# keep working without churn).
_narrate_app_health = narrate_app_health
_narrate_bypass_resolutions = narrate_bypass_resolutions
_narrate_service_edges = narrate_service_edges
_narrate_log_kinds = narrate_log_kinds
_narrate_security_products = narrate_security_products
_narrate_apps_installed = narrate_apps_installed
