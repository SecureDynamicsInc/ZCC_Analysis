"""
Status Code Reference module — searchable browser of every documented
Zscaler code BundleScope knows about.

Pulls from ten authoritative data modules (Phases 2 / 4 / 6 / 7 / 8):

  * ZPA Session Status Codes      (200+ AC/CA/CLT/SE/ZPA BA codes)
  * ZPA Authentication Errors     (2008 + 42000..42048 enrollment codes)
  * ZCC Connection Status         (17 tray status messages)
  * ZCC Numeric Error Codes       (~90 cloud/admin/report-issue codes)
  * ZIA Policy Reasons            (~100 Insights/NSS policy action reasons)
  * ZIA Authentication Errors     (~103 codes: Generic / AD-LDAP / Kerberos /
                                   Identity Proxy hex 0x1388..0x13D2)
  * ZDX Web Probe Errors          (24 probe-phase errors)
  * ZDX Cloud Path Errors         (31 rows incl. 11 ZPA-via-ZDX cross-suite)
  * ZDX Remediation Errors        (41 rows, ZUPM_WORKFLOW_E_CODE_* prefix)
  * ZDX Managed Probe Errors      (60 rows across Web + Cloud Path probes)

This makes BundleScope useful BEYOND active triage — engineers can keep
the app open as a daily Zscaler reference. When a customer mentions an
error code, look it up here.

Cross-references the current bundle's log_index when available: each
row shows whether the code fires in the bundle, and how many times.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import streamlit as st

from zcc_diag.data.zpa_session_codes import CODES as ZPA_SESSION_CODES
from zcc_diag.data.zpa_auth_errors import ERRORS as ZPA_AUTH_ERRORS
from zcc_diag.data.zcc_connection_status import STATUSES as ZCC_TRAY
from zcc_diag.data.zcc_errors import ERRORS as ZCC_ERRORS
from zcc_diag.data.zia_policy_reasons import REASONS as ZIA_POLICY_REASONS
from zcc_diag.data.zia_auth_errors import ERRORS as ZIA_AUTH_ERRORS
from zcc_diag.data.zdx_web_probe_errors import ERRORS as ZDX_WEB_PROBE_ERRORS
from zcc_diag.data.zdx_cloud_path_errors import ERRORS as ZDX_CLOUD_PATH_ERRORS
from zcc_diag.data.zdx_remediation_errors import ERRORS as ZDX_REMEDIATION_ERRORS
from zcc_diag.data.zdx_managed_probe_errors import ERRORS as ZDX_MANAGED_PROBE_ERRORS


# ---------------------------------------------------------------------
# Unified row shape for the table view. Each documented entry from any
# of the 4 sources gets normalised into a common dict so the rendering
# code doesn't branch per source.

def _normalize_zpa_session(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": "ZPA Session Status",
        "code": row.get("code", ""),
        "category": row.get("category", ""),
        "component": row.get("component", ""),
        "label": row.get("session_status", ""),
        "description": row.get("description", ""),
        "resolution": row.get("resolution", ""),
        "severity_hint": row.get("severity_hint", ""),
        "source_url": "help.zscaler.com/zpa/understanding-zpa-session-status-codes",
    }


def _normalize_zpa_auth(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": "ZPA Authentication Errors",
        "code": row.get("code", ""),
        "category": "error",  # all 42xxx are documented errors
        "component": "—",
        "label": row.get("error_message", ""),
        "description": row.get("error_description", ""),
        "resolution": row.get("resolution", ""),
        "severity_hint": row.get("severity_hint", "critical"),
        "group": row.get("group", ""),
        "source_url": "help.zscaler.com/zscaler-client-connector/zscaler-client-connector-zpa-authentication-errors",
    }


def _normalize_zcc_tray(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": "ZCC Connection Status (tray)",
        "code": row.get("name", ""),  # tray uses name as identifier
        "category": row.get("category", ""),
        "component": row.get("scope", ""),
        "label": row.get("name", ""),
        "description": row.get("explanation", ""),
        "resolution": row.get("required_action", ""),
        "severity_hint": row.get("severity_hint", ""),
        "source_url": "help.zscaler.com/zscaler-client-connector/zscaler-client-connector-connection-status-errors",
    }


def _normalize_zcc_error(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": "ZCC Numeric Errors",
        "code": row.get("code", ""),
        "category": "error",
        "component": row.get("series", ""),
        "label": row.get("error_message", ""),
        "description": row.get("error_description", ""),
        "resolution": row.get("resolution", ""),
        "severity_hint": row.get("severity_hint", ""),
        "source_url": "help.zscaler.com/zscaler-client-connector/zscaler-client-connector-errors",
    }


def _normalize_zia_policy_reason(row: Dict[str, Any]) -> Dict[str, Any]:
    """Phase 6: ZIA Policy Reasons (Insights/NSS-side documentation)."""
    return {
        "source": "ZIA Policy Reasons (Insights/NSS)",
        "code": row.get("name", ""),  # the literal reason string is the identifier
        "category": row.get("category", "policy_block"),
        "component": row.get("feature", ""),
        "label": row.get("name", ""),
        "description": row.get("description", ""),
        "resolution": "",  # Policy Reasons documentation has no separate resolution column
        "severity_hint": row.get("severity_hint", ""),
        "source_url": "help.zscaler.com/zia/policy-reasons",
    }


def _normalize_zia_auth(row: Dict[str, Any]) -> Dict[str, Any]:
    """Phase 7: ZIA Authentication Error Codes.

    Multi-occurrence Kerberos rows (471000 ×5, 491000 ×2, 501000 ×2)
    are emitted as distinct rows here so the operator sees every
    documented When-It-Occurs / What-to-Do path. The `label` field
    incorporates the occurrence tag to disambiguate visually.

    Category mapping into the unified-row vocabulary:
      generic         -> warning      (recoverable misconfig)
      ldap_sync       -> error        (blocks login)
      kerberos        -> error        (blocks Kerberos auth)
      identity_proxy  -> policy_block (mostly transient; severity_hint
                                       still drives the chip colour)
    Most identity_proxy rows are flagged as transient; the explicit
    "user not found" / "wrong password" / "cloud app disabled" /
    "IdP disabled" rows have severity_hint=critical and will get the
    error-coloured chip via the existing severity-driven CSS path.
    """
    raw_cat = row.get("category", "")
    cat_map = {
        "generic": "warning",
        "ldap_sync": "error",
        "kerberos": "error",
        "identity_proxy": "policy_block",
    }
    occurrence = row.get("occurrence", "")
    base_desc = row.get("error_description", "")
    when = row.get("error_when", "")
    # Combine When-It-Occurs into description so the table cell shows
    # the full context. documentation separates them as two columns; we collapse
    # for the single-pane table view.
    parts = [base_desc]
    if when:
        parts.append(f"When it occurs: {when}")
    description = "  ".join(p for p in parts if p)
    label = base_desc if not occurrence else f"{base_desc} ({occurrence})"
    return {
        "source": "ZIA Authentication Errors",
        "code": row.get("code", ""),
        "category": cat_map.get(raw_cat, ""),
        "component": raw_cat.replace("_", " ").title(),
        "label": label,
        "description": description,
        "resolution": row.get("recommended_action", ""),
        "severity_hint": row.get("severity_hint", ""),
        "source_url": "help.zscaler.com/zia/internet-saas-authentication-error-codes",
    }


# ---------------------------------------------------------------------
# Phase 8 (2026-06-17): four ZDX sources

def _zdx_severity_to_category(severity: str) -> str:
    """ZDX rows expose severity_hint directly; map into the unified
    category vocabulary so the existing chip/filter UI works."""
    if severity == "info":
        return "info"
    if severity == "critical":
        return "error"
    return "warning"


def _normalize_zdx_web_probe(row: Dict[str, Any]) -> Dict[str, Any]:
    """ZDX Web Probe errors — phase-tagged HTTP/TCP/HTTPS probe failures."""
    sev = row.get("severity_hint", "")
    msg = row.get("error_message", "")
    return {
        "source": "ZDX Web Probe Errors",
        "code": msg,  # documented message is the operator-facing identifier
        "category": _zdx_severity_to_category(sev),
        "component": (row.get("probe_phase", "") or "").replace("_", " ").title(),
        "label": msg,
        "description": row.get("error_description", ""),
        "resolution": row.get("recommended_action", ""),
        "severity_hint": sev,
        "source_url": "help.zscaler.com/zdx/web-probe-errors",
    }


def _normalize_zdx_cloud_path(row: Dict[str, Any]) -> Dict[str, Any]:
    """ZDX Cloud Path errors — includes the 11 ZPA-via-ZDX cross-suite
    rows (flagged via the zpa_via_zdx component label)."""
    sev = row.get("severity_hint", "")
    msg = row.get("error_message", "")
    phase = row.get("probe_phase", "") or ""
    component = phase.replace("_", " ").title()
    if row.get("zpa_via_zdx"):
        component = "ZPA-via-ZDX"
    return {
        "source": "ZDX Cloud Path Errors",
        "code": msg,
        "category": _zdx_severity_to_category(sev),
        "component": component,
        "label": msg,
        "description": row.get("error_description", ""),
        "resolution": row.get("recommended_action", ""),
        "severity_hint": sev,
        "source_url": "help.zscaler.com/zdx/cloud-path-errors",
    }


def _normalize_zdx_remediation(row: Dict[str, Any]) -> Dict[str, Any]:
    """ZDX Remediation errors — ZUPM_WORKFLOW_E_CODE_* prefix. Two rows
    share the SCRIPT_CERT_VALIDATION_FAILED code; both emit here."""
    sev = row.get("severity_hint", "")
    code = row.get("code", "")
    fam = row.get("family", "") or ""
    msg = row.get("error_message", "")
    return {
        "source": "ZDX Remediation Errors",
        "code": code,
        "category": _zdx_severity_to_category(sev),
        "component": fam.replace("_", " ").title(),
        "label": msg,
        "description": row.get("error_description", ""),
        "resolution": row.get("recommended_action", ""),
        "severity_hint": sev,
        "source_url": "help.zscaler.com/zdx/remediation-errors",
    }


def _normalize_zdx_managed_probe(row: Dict[str, Any]) -> Dict[str, Any]:
    """ZDX Managed Probe errors — 9 Web + 51 Cloud Path. "Internal
    error" appears in both sub-tables; component disambiguates."""
    sev = row.get("severity_hint", "")
    msg = row.get("error_message", "")
    ptype = row.get("probe_type", "") or ""
    cat = row.get("category", "") or ""
    return {
        "source": "ZDX Managed Probe Errors",
        # Code combines message + probe_type so "Internal error" in
        # the Web vs Cloud Path tables produces distinct, addressable
        # rows in the unified table.
        "code": f"{msg} [{ptype}]" if msg == "Internal error" else msg,
        "category": _zdx_severity_to_category(sev),
        "component": f"{ptype.replace('_', ' ').title()} / {cat}",
        "label": msg,
        "description": row.get("error_description", ""),
        "resolution": row.get("recommended_action", ""),
        "severity_hint": sev,
        "source_url": "help.zscaler.com/zdx/zscaler-managed-probe-errors",
    }


@st.cache_data(show_spinner=False)
def _build_all_rows() -> List[Dict[str, Any]]:
    """Build the unified list once. Cache survives reruns."""
    rows: List[Dict[str, Any]] = []
    for r in ZPA_SESSION_CODES:
        rows.append(_normalize_zpa_session(r))
    for r in ZPA_AUTH_ERRORS:
        rows.append(_normalize_zpa_auth(r))
    for r in ZCC_TRAY:
        rows.append(_normalize_zcc_tray(r))
    for r in ZCC_ERRORS:
        rows.append(_normalize_zcc_error(r))
    for r in ZIA_POLICY_REASONS:
        rows.append(_normalize_zia_policy_reason(r))
    for r in ZIA_AUTH_ERRORS:
        rows.append(_normalize_zia_auth(r))
    for r in ZDX_WEB_PROBE_ERRORS:
        rows.append(_normalize_zdx_web_probe(r))
    for r in ZDX_CLOUD_PATH_ERRORS:
        rows.append(_normalize_zdx_cloud_path(r))
    for r in ZDX_REMEDIATION_ERRORS:
        rows.append(_normalize_zdx_remediation(r))
    for r in ZDX_MANAGED_PROBE_ERRORS:
        rows.append(_normalize_zdx_managed_probe(r))
    return rows


# ---------------------------------------------------------------------
# Bundle cross-reference: when a bundle is loaded, count how many times
# each known code appears in the parsed log_index. Cached per bundle.

def _count_code_in_bundle(
    log_index: Any, code: str,
) -> int:
    """Return how many times ``code`` appears as a literal substring in
    the bundle's parsed log records. Cheap substring count — not regex.
    Returns 0 when log_index is unavailable.
    """
    if log_index is None or not code:
        return 0
    n = 0
    try:
        # log_index is the in-memory list of parsed records. Each record
        # has a `.message` attr we can substring-check against.
        for rec in log_index:
            msg = getattr(rec, "message", "") or ""
            if code in msg:
                n += 1
    except Exception:
        return 0
    return n


@st.cache_data(show_spinner=False)
def _cached_code_counts(
    bundle_hash: Optional[str],
    log_index_id: int,
    codes: tuple,
) -> Dict[str, int]:
    """Cache wrapper. ``log_index_id`` is id(log_index) — used as a
    cache key surrogate so a fresh bundle invalidates the cache."""
    # The actual log_index isn't passed (Streamlit can't hash it). The
    # caller invokes this with bundle_hash as the cache key; the count
    # is recomputed when bundle_hash changes.
    return {}  # placeholder; the real implementation pulls from session


def _compute_counts(
    rows: List[Dict[str, Any]], log_index: Any,
) -> Dict[str, int]:
    """Compute per-code occurrence counts in the loaded bundle."""
    if log_index is None:
        return {}
    counts: Dict[str, int] = {}
    # Pre-collect all messages once.
    try:
        messages = [
            (getattr(r, "message", "") or "")
            for r in log_index
        ]
    except Exception:
        return {}

    for row in rows:
        code = row.get("code", "")
        if not code:
            continue
        # For numeric codes we want bare-token match to avoid matching
        # e.g. "1" inside "100". For symbolic codes (BRK_MT_*, etc.) a
        # substring match is fine and faster.
        if code.lstrip("-").isdigit() or code == "2008":
            # Bare-token regex. Compile lazily per code (number of
            # numeric codes is small).
            pat = re.compile(rf"\b{re.escape(code)}\b")
            counts[code] = sum(1 for m in messages if pat.search(m))
        else:
            counts[code] = sum(1 for m in messages if code in m)
    return counts


# ---------------------------------------------------------------------
# Rendering helpers

_CATEGORY_LABELS = {
    "info": "Info · No action required",
    "error": "Error · Action required",
    "policy_block": "Policy Block · Working as designed",
    "warning": "Warning",
}

_CATEGORY_CSS = {
    "info": "zd-cat-info",
    "error": "zd-cat-error",
    "policy_block": "zd-cat-policy",
    "warning": "zd-cat-policy",
}


def _category_chip(category: str) -> str:
    label = _CATEGORY_LABELS.get(category, category.title() or "")
    css = _CATEGORY_CSS.get(category, "zd-cat-info")
    if not label:
        return ""
    return (
        f'<span class="zd-cat-chip {css}">{label}</span>'
    )


# ---------------------------------------------------------------------
# Main module entry point

def render_status_code_reference(data: Dict[str, Any]) -> None:
    """Render the Status Code Reference page."""
    st.header("Status Code Reference")
    st.caption(
        "Every Zscaler status code ZCC Log Explorer knows about — searchable "
        "across the linked official Zscaler Help references. Use this as your "
        "daily reference when a customer mentions an error code."
    )

    rows = _build_all_rows()

    # Pull bundle's log_index from session state for cross-reference.
    # When unavailable (no bundle loaded) we skip the "fires in bundle"
    # column gracefully.
    log_index = (data or {}).get("log_index")
    bundle_hash = (data or {}).get("bundle_hash") or ""

    # Counts dict only computed when a bundle is loaded. Caching keyed
    # on bundle_hash means the same bundle reuses results across page
    # reruns. Different bundle -> recomputed.
    counts: Dict[str, int] = {}
    if log_index is not None:
        # Defer the heavier compute to a button click rather than
        # auto-running on every page render. ~200 substring sweeps
        # over 500k+ records is non-trivial on big bundles.
        do_count = st.checkbox(
            "Cross-reference with currently-loaded bundle",
            value=False,
            help=(
                "Shows how many times each documented code appears in "
                "the bundle's parsed logs. Adds a 'Fires in bundle' "
                "column. Computed on-demand because a substring sweep "
                "over a large bundle can take a few seconds."
            ),
        )
        if do_count:
            with st.spinner("Counting code occurrences in bundle…"):
                counts = _compute_counts(rows, log_index)
    else:
        st.info(
            "No bundle currently loaded. Showing the documented codes "
            "alone. Load a bundle (sidebar) to add per-bundle "
            "occurrence counts to each row."
        )

    # ----- Filters --------------------------------------------------

    st.markdown("#### Filters")
    col_src, col_cat, col_comp = st.columns([2, 2, 2])

    all_sources = sorted({r["source"] for r in rows})
    chosen_sources = col_src.multiselect(
        "Source",
        options=all_sources,
        default=all_sources,
        help=(
            "Pick which Zscaler reference family or families to show. By default "
            "all available families are included."
        ),
    )

    all_categories = sorted({r.get("category", "") for r in rows
                              if r.get("category")})
    chosen_categories = col_cat.multiselect(
        "Category",
        options=all_categories,
        default=all_categories,
        format_func=lambda c: _CATEGORY_LABELS.get(c, c),
        help=(
            "Filter by documented category. 'info' = no action required "
            "(normal closures). 'error' = real failure. 'policy_block' "
            "= intentional policy enforcement."
        ),
    )

    all_components = sorted({r.get("component", "") for r in rows
                              if r.get("component")})
    chosen_components = col_comp.multiselect(
        "Component / scope",
        options=all_components,
        default=all_components,
        help=(
            "Filter by component (AC/CA/CLT/SE for ZPA), platform "
            "(windows/macos/both for tray), or numeric series "
            "(cloud_auth/cloud/admin_console/report_issue)."
        ),
    )

    query = st.text_input(
        "Search (code or description)",
        value="",
        placeholder="e.g. SAML, 42016, captive portal, BRK_MT_AUTH",
        help=(
            "Substring search against the code identifier, the "
            "documented label, the description, and the resolution. "
            "Case-insensitive."
        ),
    ).strip().lower()

    only_in_bundle = False
    if counts:
        only_in_bundle = st.checkbox(
            "Only show codes that fire in this bundle",
            value=False,
            help="Hide documented codes that never appear in the loaded bundle's logs.",
        )

    # ----- Apply filters --------------------------------------------

    filtered: List[Dict[str, Any]] = []
    for row in rows:
        if row["source"] not in chosen_sources:
            continue
        if row.get("category", "") not in chosen_categories:
            continue
        if (
            row.get("component", "") not in chosen_components
            and row.get("component", "") != ""
        ):
            continue
        if query:
            hay = " ".join([
                str(row.get("code", "")),
                str(row.get("label", "")),
                str(row.get("description", "")),
                str(row.get("resolution", "")),
            ]).lower()
            if query not in hay:
                continue
        if only_in_bundle and counts.get(row["code"], 0) == 0:
            continue
        filtered.append(row)

    # ----- Summary line ---------------------------------------------

    total = len(rows)
    shown = len(filtered)
    if counts:
        bundle_n = sum(1 for r in filtered if counts.get(r["code"], 0))
        st.caption(
            f"{shown} of {total} documented codes shown · "
            f"{bundle_n} appear in this bundle"
        )
    else:
        st.caption(f"{shown} of {total} documented codes shown")

    if not filtered:
        st.info(
            "No documented codes match the current filters. Try widening "
            "the source / category / component selections or clearing the "
            "search text."
        )
        return

    # ----- Table view -----------------------------------------------

    # Sort: codes that fire in the bundle first (descending count),
    # then alphabetically by code. When no counts, just alphabetical.
    if counts:
        filtered.sort(
            key=lambda r: (
                -counts.get(r["code"], 0),
                str(r.get("code", "")).lower(),
            ),
        )
    else:
        filtered.sort(key=lambda r: str(r.get("code", "")).lower())

    # Render as expandable rows. Streamlit's dataframe doesn't easily
    # do multi-line cells with HTML chips, so we use a custom table.
    for row in filtered:
        code = row["code"]
        n = counts.get(code, 0) if counts else 0
        bundle_chip = ""
        if counts:
            if n > 0:
                bundle_chip = (
                    f' <span class="zd-finding-count">'
                    f'fires ×{n} in bundle</span>'
                )
            else:
                bundle_chip = (
                    ' <span class="zd-finding-when">'
                    'not in bundle</span>'
                )

        with st.expander(
            f"{code}  ·  {row.get('label', '')[:90]}",
            expanded=False,
        ):
            header_html = (
                f'<div class="zd-finding-head">'
                f'<span class="zd-finding-title">{row.get("label", "")}</span> '
                f'{_category_chip(row.get("category", ""))}'
                f'{bundle_chip}'
                f'<div class="zd-finding-meta-row">'
                f'<span class="zd-finding-code">'
                f'{row.get("source", "")} · component: '
                f'{row.get("component", "—")}</span>'
                f'</div>'
                f'</div>'
            )
            st.markdown(header_html, unsafe_allow_html=True)

            if row.get("description"):
                st.markdown(
                    f"**Description.** {row['description']}",
                )
            if row.get("resolution"):
                st.markdown(
                    f"**Documented resolution.** {row['resolution']}",
                )
            if row.get("group"):
                st.caption(f"Group: {row['group']}")
            url = row.get("source_url", "")
            if url:
                st.markdown(
                    f"**Source:** [{url}](https://{url})"
                )
