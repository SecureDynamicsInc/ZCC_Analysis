"""
Header strip — the three-row bundle context bar shown at the top of
every module.

It answers "who, what, where" at a glance so the engineer never has to
hunt through the Overview to see which customer / cloud / SME the
bundle is from:

    Row 1 (identity):   User · Bundle · OS / ZCC version
    Row 2 (tenant):     Customer domain · Org ID · ZPA cloud
    Row 3 (network):    ZIA cloud · Public IP · Primary SME

Visual styling lives in ``ui.styles`` under the ``.zd-header`` rules.
"""

from __future__ import annotations

from typing import Any, Dict

import streamlit as st

from zcc_diag.ui.redact import redact


# Phase 33 (2026-06-19): values ZCC writes when a field has been
# sanitized at export time or never populated. We treat these the
# same as empty so the header falls through to the next available
# source (policy-extracted email, AppInfo, etc) instead of
# rendering the literal tombstone string to the engineer.
_HEADER_SENTINELS = frozenset({
    "###", "null", "(null)", "none", "(none)",
    "(unset)", "(unknown)", "n/a", "na",
})


def render_header_strip(data: Dict[str, Any]) -> None:
    """Bundle-context strip at the top of every module.

    Three rows of three cells. Holds everything the engineer needs to
    answer "who, what, where" at a glance.

    Previously row 2 / row 3 were combined and the tenant identity
    lived in a separate "Company / Tenant Summary" section in the
    Overview. Moving it up here lets every module see it without
    burying it inside an expander — and removes the duplicate panel
    that was confusing in Policy & Config.
    """
    s = data["summary"]
    si = data.get("session_info") or {}
    policy = data.get("policy") or {}
    os_name = (s.os or {}).get("name", "?")
    zcc = "?"
    if s.versions and s.versions.components:
        zcc = " / ".join(sorted(set(s.versions.components.values())))
    cloud = "?"
    if s.cloud and s.cloud.main_cloud:
        cloud = s.cloud.main_cloud

    # PII-sensitive fields go through ``redact()`` — pass-through when
    # the sidebar toggle is OFF (default), tokenised when ON. Identity
    # fields (user, customer domain, org ID, public IP, primary SME)
    # are the canonical "share-externally" PII; cloud / ZCC version /
    # OS are platform metadata and stay visible.
    public_ip = redact(si.get("Public IP (egress)") or "?", data)
    primary_sme = redact(si.get("SME (Service Edge) IP") or "?", data)
    # Partner-Tenant detection. When the policy extractor recognised
    # this bundle as a ZPA Partner Tenant or pre-enrollment capture,
    # it sets enrollment_status with a friendly label. Surface that
    # explicitly so engineers don't see a row of "?" and think the
    # parser is broken — instead they see "(N/A — Partner Tenant)".
    enrollment_status = policy.get("enrollment_status") or ""
    # Phase 33 (2026-06-19) sentinel-username guard. ZCC's
    # bundle-export sanitization sometimes writes the loginName as
    # "###" (and a few other tombstone strings — see
    # _HEADER_SENTINELS). When that happens we must NOT show "###"
    # to the engineer — fall through to the next available source.
    # Example Tenant A bundle 2026-06-18 hit this: AppInfo.xml loginName was
    # "###" but the synthetic email (user@example.invalid) was in the
    # tray-manager log Partner Login marker. The policy extractor
    # (Phase 32) now writes the real value into policy["Login name"],
    # and this guard makes sure we don't get "###" preferred over
    # that real value if both happen to be present.
    def _drop_sentinel(v: str) -> str:
        if not v:
            return ""
        if v.strip().lower() in _HEADER_SENTINELS:
            return ""
        return v
    _user_raw = (
        _drop_sentinel(policy.get("Login name") or "")
        or _drop_sentinel(policy.get("loginName") or "")
        or ""
    )
    _domain_raw = _drop_sentinel(policy.get("Customer domain") or "")
    _org_raw = _drop_sentinel(policy.get("Org ID") or "")
    # When the raw value starts with "(" we treat it as a fallback
    # label string (e.g. "(not applicable — Partner Tenant)") and
    # skip redaction — it's not PII, it's an explanatory tag.
    def _maybe_redact(v: str) -> str:
        if not v:
            return "?"
        if v.startswith("("):
            return v  # explanatory label, not PII
        return redact(v, data)
    user = _maybe_redact(_user_raw)
    domain = _maybe_redact(_domain_raw)
    org_id = _maybe_redact(_org_raw)
    zpa_cloud = policy.get("ZPA cloud") or "?"

    # ZPA broker DC code — parsed from broker hostnames seen in the
    # tunnel logs. E.g. "broker6-2.den3.prod.zpath.net" -> "den3".
    # When multiple DCs are observed (broker pool failover), join
    # them with "/" so the user sees the failover pattern at a glance.
    zpa_dcs = (s.bundle_meta or {}).get("zpa_broker_dcs") or {}
    zpa_dcs_list = zpa_dcs.get("dcs") or []
    if zpa_dcs_list:
        zpa_dc_str = " / ".join(zpa_dcs_list[:3])
        if len(zpa_dcs_list) > 3:
            zpa_dc_str += f" (+{len(zpa_dcs_list) - 3})"
    else:
        zpa_dc_str = "?"

    # Bundle timezone. Captured from the first parsed log line by the
    # log_index builder. Critical for the engineer's mental match
    # against customer-reported times ("around 9:30 Mountain Time").
    # Falls back to "?" when no log_index is available (e.g. very
    # old cached bundle).
    try:
        from zcc_diag.ui.tz_display import (
            get_bundle_tz_label, get_bundle_tz_offset,
        )
        _tz_label = get_bundle_tz_label() or ""
        _tz_offset = get_bundle_tz_offset() or ""
        if _tz_label and _tz_offset:
            tz_str = f"{_tz_label} ({_tz_offset})"
        elif _tz_label:
            tz_str = _tz_label
        else:
            tz_str = "?"
    except Exception:
        tz_str = "?"

    def _h(x):
        return str(x).replace("<", "&lt;").replace(">", "&gt;")

    # Row 1 = identity, Row 2 = tenant (domain / org / ZPA cloud),
    # Row 3 = network (ZIA cloud / Public IP / Primary SME).
    # ZPA cloud replaced the MA host (mobile API endpoint) here — MA
    # host is the same for every user on a given ZIA cloud and isn't
    # actionable, while the ZPA cloud tells you the user's ZPA tenant
    # at a glance.
    rows = [
        [
            ("User",    _h(user)),
            ("Bundle",  _h(redact(data["bundle_name"], data))),
            ("OS / ZCC", f"{_h(os_name)} · {_h(zcc)}"),
        ],
        [
            ("Customer domain", _h(domain)),
            ("Org ID",          _h(org_id)),
            ("ZPA cloud / DC",  f"{_h(zpa_cloud)} · {_h(zpa_dc_str)}"),
        ],
        [
            ("ZIA cloud",   _h(cloud)),
            ("Public IP",   _h(public_ip)),
            ("Primary SME", _h(primary_sme)),
        ],
        [
            ("Bundle TZ",   _h(tz_str)),
            ("",            ""),
            ("",            ""),
        ],
    ]
    html = '<div class="zd-header">'
    for row in rows:
        html += '<div class="zd-header-row">'
        for lbl, val in row:
            html += (
                f'<div class="cell"><div class="lbl">{lbl}</div>'
                f'<div class="val" title="{val}">{val}</div></div>'
            )
        html += '</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

    # Enrollment-status caption. When the bundle is a Partner Tenant
    # or pre-enrollment capture, surface it here so the engineer
    # immediately understands WHY identity fields are labelled
    # "(N/A — Partner Tenant)" instead of carrying user / domain /
    # org-ID values. Silent on a normal enrolled bundle.
    if enrollment_status:
        st.caption(f"_Bundle enrollment state: **{enrollment_status}**._")


# Backwards-compat alias.
_render_header_strip = render_header_strip
