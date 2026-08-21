"""Facts view — rebuilt Slice 9 (2026-08-14).

Renders a `FactsSnapshot` (+ the bundle-wide `IdInventory`) as a dense,
single-scroll page. Every visible value is directly verifiable from log
evidence — no interpretation, no severity, no ranking, no findings.

What changed in Slice 9 and why:

  * **One Identity section, not two.** Slice 8 rendered identity twice —
    once from the single best-effort App Profile pluck and again from
    the log-wide inventory — which put `Login: —` directly above
    `Username: user@…` for the same bundle. They're now merged
    into one row set: each field takes the config value when present,
    otherwise the most-frequent log-derived value, and always states
    which source it came from. When the two sources disagree, the
    disagreement is shown rather than hidden.

  * **ZIA and ZPA clouds are separate fields.** A tenant is routinely on
    zscalertwo.net for ZIA and zpath.net for ZPA; one merged "cloud"
    field showed one and silently dropped the other.

  * **Compact layout.** `st.metric` was overflowing long values
    (emails, timestamps) and burning a screen of vertical space on a
    dozen fields. Replaced with `kv_grid` at body font, ellipsis +
    hover for long values.

  * **Regrouped sections.** Bundle · Identity & environment · Time ·
    Parse & coverage · Entities · Configuration. Each fact appears in
    exactly one group.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import streamlit as st

from ..facts_extract import FactsSnapshot
from ..id_inventory import IdInventory, IdStat
from ._components import (
    KV,
    bar,
    chips,
    fmt_bytes,
    fmt_count,
    fmt_duration,
    fmt_ts,
    inject_css,
    kv_grid,
    section,
)


# --------------------------------------------------------------------------
# Inventory helpers
# --------------------------------------------------------------------------

def _top(inv: Optional[IdInventory], tag_type: str) -> Optional[IdStat]:
    """Most-frequent value for a tag type, or None if the bundle had no
    match for it."""
    if inv is None:
        return None
    bucket = inv.groups.get(tag_type)
    if not bucket:
        return None
    return max(bucket.values(), key=lambda s: s.count)


def _distinct(inv: Optional[IdInventory], tag_type: str) -> int:
    if inv is None:
        return 0
    return len(inv.groups.get(tag_type) or {})


def _merged(label: str,
            config_value: Optional[str],
            config_source: str,
            inv: Optional[IdInventory],
            tag_type: Optional[str]) -> KV:
    """Build one identity cell from two possible sources.

    Precedence: an explicit config value (App Profile / TrayPolicy) wins
    over log-derived text, because it's the tenant's declared setting
    rather than an observation. But when config is absent — Partner-
    Tenant bundles, redacted exports, captures taken before the first
    policy push — the log-derived value is all there is, and showing a
    dash there was the bug this fixes.

    When both exist and disagree, the config value is shown and the
    source line reports the conflict. Silently preferring one would hide
    a real signal: a stale install-day policy blob contradicting what
    the client is actually doing right now.
    """
    cfg = (config_value or "").strip() or None
    stat = _top(inv, tag_type) if tag_type else None

    if cfg and stat:
        n = _distinct(inv, tag_type)
        if cfg.lower() == stat.value.lower():
            src = f"{config_source} + logs ×{stat.count:,}"
        else:
            src = f"{config_source}; logs say “{stat.value}” ×{stat.count:,}"
        if n > 1:
            src += f" ({n} distinct in logs)"
        return KV(label, cfg, src)

    if cfg:
        return KV(label, cfg, config_source)

    if stat:
        n = _distinct(inv, tag_type)
        src = f"logs ×{stat.count:,}"
        if n > 1:
            src += f" ({n} distinct)"
        mods = ", ".join(sorted(stat.components))
        if mods:
            src += f" · {mods}"
        return KV(label, stat.value, src)

    return KV(label, None, "")


def _ap(facts: FactsSnapshot, *keys: str) -> Optional[str]:
    """First non-empty App Profile value among `keys`. policy_extract
    stores these under human labels ("ZIA cloud", "Org ID"), and which
    labels are populated varies by bundle shape."""
    for k in keys:
        v = facts.app_profile.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s and s.lower() not in {"none", "null", "###", "(unset)"}:
            return s
    return None


def _qualify_cloud(v: Optional[str]) -> Optional[str]:
    """Normalise a cloud name to its fully-qualified form.

    TrayPolicy stores `ziaCloudName` bare (`zscalertwo`) on most Windows
    bundles, while the log-derived value is always qualified
    (`zscalertwo.net`) because it's harvested from real hostnames.
    Comparing the two raw made `_merged` report a config-vs-logs
    disagreement on nearly every Windows bundle — a manufactured
    conflict that would send someone hunting a tenant misconfiguration
    that doesn't exist.
    """
    if not v:
        return None
    s = str(v).strip().strip(".").lower()
    if not s:
        return None
    return s if "." in s else f"{s}.net"


# --------------------------------------------------------------------------
# Renderer
# --------------------------------------------------------------------------

def render_facts(facts: FactsSnapshot,
                 inv: Optional[IdInventory] = None) -> None:
    """Render the Facts page.

    `inv` — the bundle-wide IdInventory, shared with the Session and
    Buckets tabs. When present, identity fields are backfilled from
    log evidence wherever the config pluck came up empty.
    """
    inject_css()

    _render_bundle(facts)
    _render_identity(facts, inv)
    _render_time(facts)
    _render_parse(facts)
    _render_entities(facts, inv)
    _render_config(facts)
    _render_diagnostics(facts)


# ---- Bundle ---------------------------------------------------------------

def _render_bundle(facts: FactsSnapshot) -> None:
    section("Bundle")
    kv_grid([
        KV("Bundle", facts.bundle_name),
        KV("Size on disk", fmt_bytes(facts.bundle_bytes)),
        KV("Files in bundle", fmt_count(facts.bundle_file_count)),
        KV(".log files", fmt_count(facts.bundle_log_file_count)),
    ], columns=4)


# ---- Identity & environment (merged) -------------------------------------

def _render_identity(facts: FactsSnapshot,
                     inv: Optional[IdInventory]) -> None:
    section("Identity & environment")

    rows = [
        _merged("User / login", facts.user_login or _ap(facts, "Login name"),
                "App Profile", inv, "username"),
        _merged("Device hostname", facts.user_hostname,
                "App Profile", inv, "device_hostname"),
        _merged("ZCC version", facts.zcc_version,
                "App Profile", inv, "zcc_version"),
        KV("OS family", facts.os_family,
           "inferred from bundle filenames" if facts.os_family else ""),

        _merged("ZIA cloud", _qualify_cloud(_ap(facts, "ZIA cloud")),
                "App Profile", inv, "zia_cloud"),
        _merged("ZPA cloud", _qualify_cloud(_ap(facts, "ZPA cloud")),
                "App Profile", inv, "zpa_cloud"),
        _merged("Data center", None, "", inv, "dc"),
        _merged("Org / tenant ID", _ap(facts, "Org ID"),
                "App Profile", inv, "org_id"),

        KV("Customer domain", _ap(facts, "Customer domain"), "App Profile"),
        KV("App Profile", _ap(facts, "App Profile"), "App Profile"),
        KV("MA host", _ap(facts, "MA host"), "App Profile"),
        KV("Enrollment", _ap(facts, "enrollment_status"), "App Profile"),
    ]
    kv_grid(rows, columns=4)

    # Suite status — separate from identity because these are runtime
    # state flags, not who/where the device is.
    zia_enr = facts.app_profile.get("ZIA enrolled")
    zpa_enr = facts.app_profile.get("ZPA enrolled")
    if zia_enr is not None or zpa_enr is not None:
        def _flag(v, override_key):
            if v is None:
                return None, ""
            txt = "yes" if v else "no"
            note = ("overridden by runtime evidence"
                    if facts.app_profile.get(override_key) else "App Profile")
            return txt, note

        zia_txt, zia_note = _flag(zia_enr, "ZIA enrolled override")
        zpa_txt, zpa_note = _flag(zpa_enr, "ZPA enrolled override")
        kv_grid([
            KV("ZIA enrolled", zia_txt, zia_note),
            KV("ZPA enrolled", zpa_txt, zpa_note),
            KV("ZIA runtime traffic",
               "observed" if facts.app_profile.get("zia_runtime_active") else None,
               str(facts.app_profile.get("zia_runtime_source") or "")),
            KV("ZPA runtime traffic",
               "observed" if facts.app_profile.get("zpa_runtime_active") else None,
               str(facts.app_profile.get("zpa_runtime_source") or "")),
        ], columns=4)

    if inv is not None:
        _render_env_drilldown(inv)


_ENV_TAG_TYPES: List[Tuple[str, str]] = [
    ("zia_cloud", "ZIA cloud"),
    ("zpa_cloud", "ZPA cloud"),
    ("dc", "Data center"),
    ("username", "User / login"),
    ("device_hostname", "Device hostname"),
    ("org_id", "Org / tenant ID"),
    ("zcc_version", "ZCC version"),
]


def _render_env_drilldown(inv: IdInventory) -> None:
    """Every distinct value behind the merged cells above, with counts,
    time span, and which log module produced it.

    The merged row shows only the most-frequent value; a bundle spanning
    a DC migration or a client upgrade legitimately has several, and
    this is where that shows up.
    """
    present = [(t, lbl) for t, lbl in _ENV_TAG_TYPES if inv.groups.get(t)]
    if not present:
        return
    total = sum(len(inv.groups[t]) for t, _ in present)
    with st.expander(
        f"All distinct identity/environment values ({total}) — with provenance",
        expanded=False,
    ):
        rows = []
        for tag_type, label in present:
            for s in sorted(inv.groups[tag_type].values(),
                            key=lambda x: -x.count):
                rows.append({
                    "field": label,
                    "value": s.value,
                    "lines": s.count,
                    "first (UTC)": fmt_ts(s.first_ts) or "—",
                    "last (UTC)": fmt_ts(s.last_ts) or "—",
                    "modules": ", ".join(sorted(s.components)) or "—",
                    "files": len(s.files),
                })
        st.dataframe(rows, hide_index=True, use_container_width=True)


# ---- Time ----------------------------------------------------------------

def _render_time(facts: FactsSnapshot) -> None:
    section("Time")
    tz = None
    if facts.bundle_tz_offset:
        tz = facts.bundle_tz_offset
        if facts.bundle_tz_label:
            tz = f"{facts.bundle_tz_offset} ({facts.bundle_tz_label})"
    kv_grid([
        KV("First line", fmt_ts(facts.first_ts)),
        KV("Last line", fmt_ts(facts.last_ts)),
        KV("Span", fmt_duration(facts.duration_seconds)),
        KV("Device UTC offset", tz,
           "log-line metadata; timestamps above are UTC"),
    ], columns=4)


# ---- Parse & coverage ----------------------------------------------------

def _render_parse(facts: FactsSnapshot) -> None:
    section("Parse & coverage")

    total_seen = facts.total_lines + facts.lines_skipped_unparseable
    pct = (100.0 * facts.total_lines / total_seen) if total_seen else 0.0

    kv_grid([
        KV("Lines parsed", fmt_count(facts.total_lines)),
        KV("Lines unparseable", fmt_count(facts.lines_skipped_unparseable),
           "no timestamp/level prefix — continuation lines, blanks, banners"),
        KV("Parse rate", f"{pct:.1f}%"),
        KV("Bytes scanned", fmt_bytes(facts.bytes_scanned)),
        KV("Log files scanned", fmt_count(facts.files_scanned),
           "tunnel / service / tray / upm only"),
        KV(".log files in bundle", fmt_count(facts.bundle_log_file_count)),
        KV("Files not indexed",
           fmt_count(max(0, facts.bundle_log_file_count - facts.files_scanned)),
           "ZSAHelper / ZSAUpdater / <200 B are skipped by design"),
        KV("Distinct source files", fmt_count(len(facts.distinct_source_files))),
    ], columns=4)
    bar(pct)


# ---- Entities ------------------------------------------------------------

def _render_entities(facts: FactsSnapshot,
                     inv: Optional[IdInventory]) -> None:
    section("Entities observed")

    kv_grid([
        KV("Processes (PIDs)", fmt_count(len(facts.distinct_pids))),
        KV("Log components", fmt_count(len(facts.distinct_components))),
        KV("Session IDs", fmt_count(len(facts.distinct_session_ids))),
        KV("Hosts contacted", fmt_count(len(facts.distinct_hosts))),
        KV("ZPA tag IDs", fmt_count(_distinct(inv, "tag_id"))),
        KV("mtunnel IDs", fmt_count(_distinct(inv, "mtunnel_id"))),
        KV("Brokers", fmt_count(_distinct(inv, "broker"))),
        KV("SME hosts", fmt_count(_distinct(inv, "sme_host"))),
        KV("Apps", fmt_count(_distinct(inv, "app"))),
        KV("Error codes", fmt_count(_distinct(inv, "err_code"))),
        KV("Symbolic codes", fmt_count(_distinct(inv, "symbolic_code"))),
        KV("IPv4 addresses", fmt_count(_distinct(inv, "ipv4"))),
    ], columns=4)

    st.caption("Lines by component")
    chips(sorted(facts.lines_by_component.items(), key=lambda kv: -kv[1]))
    st.caption("Lines by level")
    chips(sorted(facts.lines_by_level.items(), key=lambda kv: -kv[1]))

    with st.expander(
        f"Lines by source file ({len(facts.lines_by_source_file)})",
        expanded=False,
    ):
        rows = sorted(facts.lines_by_source_file.items(),
                      key=lambda kv: -kv[1])
        st.dataframe(
            [{"source_file": k, "lines": v} for k, v in rows],
            hide_index=True, use_container_width=True,
        )

    # The actual VALUES behind these counts live in the Entities tab.
    # They used to be dumped here via `st.write(list)`, which Streamlit
    # renders as a collapsible JSON tree chunked into [0-99] [100-199]
    # … buckets — a screen-high stack of range accordions that overlapped
    # the next column and hid every value behind two clicks. Counts
    # belong on this page; browsable values belong in a table.
    st.caption(
        "→ Open the **Entities** tab to browse the values behind these "
        "counts as sortable, filterable, exportable tables."
    )


# ---- Configuration -------------------------------------------------------

def _render_config(facts: FactsSnapshot) -> None:
    section("Configuration snapshots")
    st.caption(
        "Full config extraction — Forwarding Profile, bypass inventory, "
        "PCAPs, UPM databases — lives in the **Inventories** tab. "
        "Shown here: what the Facts pass itself pulled."
    )

    with st.expander(f"App Profile ({len(facts.app_profile)} keys)",
                     expanded=False):
        if facts.app_profile:
            st.json(facts.app_profile)
        else:
            st.caption(
                "No TrayPolicy blob found in tray logs. Identity fields "
                "above fall back to log-derived evidence."
            )

    # Rendered as tables, not `st.write(list)` — the same reason the
    # entity dumps were moved out. Posture names are short lists so they
    # stay here; the full per-check detail (type, pass/fail, last
    # evaluated, check interval) is in the Inventories tab.
    c1, c2 = st.columns(2)
    with c1:
        with st.expander(
            f"Posture profiles ({len(facts.posture_profile_names)})",
            expanded=False,
        ):
            if facts.posture_profile_names:
                st.dataframe(
                    [{"posture check": n}
                     for n in facts.posture_profile_names],
                    hide_index=True, use_container_width=True,
                )
                st.caption(
                    "Per-check type / pass-fail / last-evaluated is in "
                    "**Inventories → Device posture profiles**."
                )
            else:
                st.caption("No posture data in this bundle's logs.")
    with c2:
        with st.expander(
            f"Trust condition checks ({len(facts.trust_condition_names)})",
            expanded=False,
        ):
            if facts.trust_condition_names:
                st.dataframe(
                    [{"required check": n}
                     for n in facts.trust_condition_names],
                    hide_index=True, use_container_width=True,
                )
                st.caption(
                    "Names as the trust policy spells them — these can "
                    "differ from the posture-profile names beside them "
                    "if either side carries a typo. See **Inventories → "
                    "Trust condition** for the AND/OR structure."
                )
            else:
                st.caption("No trust condition found in this bundle's logs.")


# ---- Diagnostics ---------------------------------------------------------

def _render_diagnostics(facts: FactsSnapshot) -> None:
    if not facts.extract_errors:
        return
    with st.expander(
        f"Extractor diagnostics ({len(facts.extract_errors)})",
        expanded=False,
    ):
        st.caption(
            "Best-effort extractors that raised. The affected fields "
            "read “—” above rather than showing a guess."
        )
        for err in facts.extract_errors:
            st.text(f"  {err}")
