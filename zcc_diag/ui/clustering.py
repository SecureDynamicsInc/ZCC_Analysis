"""
Root-cause clustering — data + logic, no rendering.

Findings often come in *families*: a tunnel-state flap can also produce
an SME-failure count, a zEvents-bus error, and a fail-open transition,
all describing the same underlying event. Showing each one separately
in the UI doubles the noise without adding signal.

This module groups findings into root-cause clusters. Each cluster has
one "primary" finding (the headline) and zero or more "supporting"
findings (the corroborating signals). The render side lives in
``ui.findings._render_root_cause_cluster`` — kept there so the rendering
layer (which imports ``_render_finding_card``) doesn't pull data
structures into a circular import with this module.

Public API:
  * ``ROOT_CAUSE_FAMILIES``    — the static catalogue of families.
  * ``root_cause_family_for(code)`` — code → (family_label, primary_pref)
  * ``DETECTOR_GROUPS``        — detector_id → human group label
  * ``cluster_by_root_cause(findings)`` — bucket findings into clusters

Legacy underscore aliases at the bottom keep existing call sites working.
"""

from __future__ import annotations

from typing import Any, Dict, List

from zcc_diag.issues import Severity


# Each entry: (label, (exact_codes_set, dynamic_prefixes_tuple), primary_pref_list)
#   exact_codes_set  – codes that match this family on string equality
#   dynamic_prefixes – codes whose *prefix* matches the family (e.g. PA_ERROR_42022)
#   primary_pref     – codes preferred as the cluster's headline finding,
#                      in order. First match wins; if no match, the most
#                      severe finding in the cluster becomes the primary.
ROOT_CAUSE_FAMILIES = [
    (
        "ZIA tunnel — Service Edge unreachable",
        (
            {
                "ZCC_ZIA_SERVER_DOWN_ERROR",
                "ZCC_ZIA_NETWORK_ERROR",
                "ZCC_ZIA_STATE_FLAP_DOWN",
                "ZCC_ZIA_CONNECTION_FAILED",
                "SME_FAILURE_COUNT_HIGH",
                "SME_PROXY_BAD_STATE",
                "ZPN_CLIENT_AUTHENTICATE_FAIL",
                "ZTUI_BUS_FAIL",
            },
            ("ZIA_TUNNEL_DOWN_",),  # ZIA_TUNNEL_DOWN_SERVER_DOWN_ERROR etc.
        ),
        ["ZIA_TUNNEL_DOWN_SERVER_DOWN_ERROR",
         "ZCC_ZIA_SERVER_DOWN_ERROR"],
    ),
    (
        "ZIA tunnel — state recovered",
        ({"ZCC_ZIA_STATE_FLAP_UP"}, ()),
        ["ZCC_ZIA_STATE_FLAP_UP"],
    ),
    (
        "ZPA tunnel — broker unreachable",
        (
            {
                "ZCC_ZPA_SERVER_DOWN_ERROR",
                "ZCC_ZPA_NETWORK_ERROR",
                "ZCC_ZPA_STATE_FLAP_DOWN",
                "ZCC_ZPA_CONNECTION_FAILED",
            },
            ("ZPA_TUNNEL_DOWN_",),
        ),
        ["ZPA_TUNNEL_DOWN_SERVER_DOWN_ERROR",
         "ZCC_ZPA_SERVER_DOWN_ERROR"],
    ),
    (
        "ZPA tunnel — state recovered",
        ({"ZCC_ZPA_STATE_FLAP_UP"}, ()),
        ["ZCC_ZPA_STATE_FLAP_UP"],
    ),
    (
        "Tunnel-2 (DTLS) → TLS fallback",
        ({"ZCC_T2_DTLS_TO_TLS_FALLBACK", "T2_FALLBACK_TO_T1"}, ()),
        ["ZCC_T2_DTLS_TO_TLS_FALLBACK", "T2_FALLBACK_TO_T1"],
    ),
    (
        "Local network / adapter / driver down",
        (
            {"LOCAL_NETWORK_DOWN"},
            ("ZIA_TUNNEL_DOWN_ADAPTER_", "ZPA_TUNNEL_DOWN_ADAPTER_",
             "ZIA_TUNNEL_DOWN_DRIVER_", "ZPA_TUNNEL_DOWN_DRIVER_"),
        ),
        ["LOCAL_NETWORK_DOWN"],
    ),
    (
        "Internet unreachable",
        (
            set(),
            ("ZIA_TUNNEL_DOWN_INTERNET_", "ZPA_TUNNEL_DOWN_INTERNET_"),
        ),
        ["ZIA_TUNNEL_DOWN_INTERNET_UNREACHABLE_ERROR"],
    ),
    (
        "SSL inspection / cert chain broken",
        (
            {"SSL_INTERCEPTION_DETECTED", "STALE_CERT_IN_TRUSTSTORE",
             "DEVICE_CERT_EXPIRED"},
            ("ZIA_TUNNEL_DOWN_ZPA_UNTRUSTED_",
             "ZPA_TUNNEL_DOWN_ZPA_UNTRUSTED_",
             "NETERR_CERT_"),
        ),
        ["SSL_INTERCEPTION_DETECTED"],
    ),
    (
        "ZPA broker policy / config failure",
        (
            {
                "BRK_MT_NO_POLICY_FOUND",
                "BRK_MT_REJECTED_BY_POLICY",
                "SAML_EXPIRED_BROKER",
                "SAML_FORCE_EXPIRED",
                "WEBPROBE_HTTPS_DISABLED",
                "PA_POLICY_BLOCKED",
                "AUTH_STATE_FLAPPED",
                # ZPA broker SAML fingerprint mismatch — was previously
                # mis-clustered under the ZIA auth family because the
                # detector emitted ``SAML_FINGERPRINT_MISMATCH`` (no
                # suite prefix). Renamed to ``ZPA_SAML_FINGERPRINT_MISMATCH``
                # and moved here where it belongs.
                "ZPA_SAML_FINGERPRINT_MISMATCH",
            },
            ("BRK_MT_SETUP_FAIL_", "PA_ERROR_"),
        ),
        ["BRK_MT_NO_POLICY_FOUND",
         "SAML_EXPIRED_BROKER", "PA_POLICY_BLOCKED"],
    ),
    # Endpoint security blocking ZCC — Windows + Mac codes unified.
    (
        "Endpoint security interfering with ZCC",
        (
            {
                # Windows (endpoint_fw_av) — real codes audited
                "LWF_DRIVER_NOT_RUNNING",
                "FILTER_DRIVER_FAIL",
                "HEALTHCHECK_TO_100_64_FAILED",
                "PORT_9000_BIND_FAIL",
                "FIREWALL_RETRIES_EXPIRED",
                "FIREWALL_BLOCK_ERROR_STATE",
                "WFP_BAD_HEALTH",
                "FIREWALL_RULE_INSTALL_FAIL",
                "FIREWALL_API_FAIL",
                "ACCESS_DENIED_ZSA",
                "CONTROLSERVICE_PERMISSION_DENIED",
                "ANTI_TAMPER_VIOLATION",
                # macOS (endpoint_fw_av_mac) — real codes audited
                "WANDERA_EDNS_INTERCEPT",
                "UMBRELLA_DNS_INTERCEPT",
                "JAMF_PROTECT_ACTIVITY",
                "PFCTL_BLOCK",
                "SOCKETFILTERFW_DENY",
                "SYSEXT_LOAD_DENIED",
                "NEFILTER_PROVIDER_FAILURE",
                "DNS_SINKHOLE_GENERIC",
                "MAC_FIREWALL_DISABLED",
            },
            (),
        ),
        ["FIREWALL_RETRIES_EXPIRED", "SYSEXT_LOAD_DENIED",
         "WFP_BAD_HEALTH", "PFCTL_BLOCK", "SOCKETFILTERFW_DENY",
         "LWF_DRIVER_NOT_RUNNING"],
    ),
    (
        "Endpoint security products present (informational)",
        ({"SECURITY_PRODUCTS_PRESENT"}, ()),
        ["SECURITY_PRODUCTS_PRESENT"],
    ),
    (
        "ZPA app unreachable",
        (
            {"ZPA_DNS_CHECK_NOT_FOUND",
             "ZPA_MACHINE_TUNNEL_CONFIG_MISSING"},
            (),
        ),
        ["ZPA_DNS_CHECK_NOT_FOUND",
         "ZPA_MACHINE_TUNNEL_CONFIG_MISSING"],
    ),
    (
        "ZPA reconnect instability",
        ({"ZPA_MTUNNEL_RECONNECT_LOOP",
          "ZPA_DATA_PLANE_RESETS"}, ()),
        ["ZPA_MTUNNEL_RECONNECT_LOOP",
         "ZPA_DATA_PLANE_RESETS"],
    ),
    # Policy / bypass / hostfile — codes audited against actual
    # detector emissions (bypass_misconfiguration, wildcard_app_
    # segment_purge, hostfile_interference).
    (
        "Policy / bypass / hostfile misconfiguration",
        (
            {
                "BYPASS_CACHE_EMPTY",
                "BYPASS_CACHE_LARGE",
                "BYPASS_CACHE_VERY_LARGE",
                "CERT_ERROR_HOST_NOT_BYPASSED",
                "CERT_ERROR_UNATTRIBUTED",
                "GATEWAY_NOT_IN_BYPASS",
                "HOSTFILE_PRIVATE_OVERRIDE",
                "HOSTFILE_PUBLIC_OVERRIDE",
            },
            (),
        ),
        ["GATEWAY_NOT_IN_BYPASS",
         "CERT_ERROR_HOST_NOT_BYPASSED",
         "BYPASS_CACHE_VERY_LARGE",
         "HOSTFILE_PUBLIC_OVERRIDE"],
    ),
    # 3rd-party agent process pinning — dynamic codes use prefix match.
    (
        "3rd-party process pinned outside ZCC",
        (set(), ("AI_CLI_PIN__", "RMM_AGENT_PIN__")),
        ["AI_CLI_PIN__", "RMM_AGENT_PIN__"],
    ),
    # NCSI / OS connectivity-status probes failing through ZCC.
    (
        "OS connectivity-status probe failing through ZCC",
        ({"NCSI_PROBE_SSL_FAIL", "MIMECAST_SSL_FAIL",
          "MAC_CONNECTIVITY_PROBE_SSL_FAIL"}, ()),
        ["NCSI_PROBE_SSL_FAIL", "MAC_CONNECTIVITY_PROBE_SSL_FAIL"],
    ),
    # Windows driver / adapter family.
    (
        "Windows networking layer failure",
        (
            {"ADAPTER_INSTABILITY",
             "LIGHTWEIGHT_FILTER_NOT_LOADED",
             "LWF_INITIAL_CHECK_FAILED",
             "LWF_UNABLE_TO_LOAD",
             "TRAY_DRIVER_ERROR"},
            (),
        ),
        ["ADAPTER_INSTABILITY",
         "LIGHTWEIGHT_FILTER_NOT_LOADED"],
    ),
    # IdP redirect — all three dynamic-code patterns.
    (
        "IdP / SSO authentication redirect failure",
        (
            set(),
            ("IDP_REDIRECT_FAIL__", "IDP_REDIRECT_FAIL_VPN__",
             "AADSTS_ERROR_"),
        ),
        ["IDP_REDIRECT_FAIL__"],
    ),
    # ZIA auth — broad family covering HTTP failures + OneID errors.
    # ``SAML_FINGERPRINT_MISMATCH`` removed: that signal was actually
    # the ZPA broker microtunnel SAML failure and is now emitted as
    # ``ZPA_SAML_FINGERPRINT_MISMATCH`` under the ZPA broker family.
    # ``MAC_MOBILE_API_HTTP_`` prefix dropped — the Mac-path detector
    # was unified to the OS-agnostic ``MOBILE_API_HTTP_`` prefix; the
    # old name is never emitted by modern code.
    (
        "ZIA authentication failure",
        (
            {"AUTH_INTERNAL_ERROR", "FORCED_UNREGISTER",
             "HTTP_407_FROM_SME", "ONEID_KEEPALIVE_401"},
            ("MOBILE_API_HTTP_",
             "MOBILE_API_ERROR_", "ONEID_DEVICE_REG_FAIL_"),
        ),
        ["HTTP_407_FROM_SME", "ONEID_KEEPALIVE_401"],
    ),
    # Captive portal — all variants.
    (
        "Captive portal detected",
        ({"CAPTIVE_PORTAL_ERROR_STATE",
          "CAPTIVE_PORTAL_FAILOPEN_STATE",
          "TRAY_CAPTIVE_PORTAL_DETECTED",
          "ZCPM_PORTAL_DETECTED"}, ()),
        ["CAPTIVE_PORTAL_ERROR_STATE",
         "ZCPM_PORTAL_DETECTED"],
    ),
    # Generic network errors — the runbook's -8 family.
    (
        "Connection failures (errorMessage family)",
        ({"NETERR_CONNECTION_RESET",
          "NETERR_HOST_NOT_FOUND",
          "NETERR_NET_UNREACHABLE",
          "NETERR_NO_ROUTE",
          "NETERR_SSL_EXCEPTION"}, ()),
        ["NETERR_CONNECTION_RESET",
         "NETERR_HOST_NOT_FOUND"],
    ),
]


def root_cause_family_for(code: str):
    """Return (family_label, primary_pref_list) for a code, or None if
    the code doesn't belong to any known family.

    Matches in two ways:
      1. Exact membership in the family's static-code set.
      2. Prefix match against any of the family's dynamic-code prefixes
         (e.g. ``PA_ERROR_42022`` matches the prefix ``PA_ERROR_``).
    """
    for label, (exact_codes, prefixes), primary in ROOT_CAUSE_FAMILIES:
        if code in exact_codes:
            return label, primary
        for prefix in prefixes:
            if code.startswith(prefix):
                return label, primary
    return None


# detector_id → human group label. Used in Findings module so related
# detectors cluster under one heading instead of being scattered
# alphabetically.
DETECTOR_GROUPS = {
    "tunnel_not_established":    "Tunnel state",
    "adapter_instability":       "Tunnel state",
    "captive_portal":            "Tunnel state",
    "network_error":             "Tunnel state",
    "driver_error":              "Tunnel state",
    "ncsi_false_negative":       "Tunnel state",
    "ncsi_false_negative_mac":   "Tunnel state",
    "zia_auth_failures":         "ZIA authentication",
    "idp_redirect_fail":         "ZIA authentication",
    "cert_pinned_saas_inspection": "ZIA authentication",
    "zpa_auth_failures":         "ZPA authentication",
    "zpa_dns_check_not_found":   "ZPA reachability",
    "zpa_app_not_reachable":     "ZPA reachability",
    "zpa_mtunnel_reconnect_loop":"ZPA reachability",
    "zpa_machine_tunnel_config_missing": "ZPA reachability",
    "zpa_data_plane_resets":     "ZPA data plane",
    "bypass_misconfiguration":   "Policy / Bypass",
    "wildcard_app_segment_purge":"Policy / Bypass",
    "hostfile_interference":     "Policy / Bypass",
    "endpoint_fw_av":            "Endpoint security",
    "endpoint_fw_av_mac":        "Endpoint security",
    "ai_cli_pin":                "Endpoint security",
    "rmm_agent_pin":             "Endpoint security",
    "zphm_force_stop_loop":      "Endpoint security",
    "p2p_app_blocked":           "Endpoint security",
    "zcc_client_version_drift":  "Client version",
    "slowness":                  "Performance / latency",
}


def cluster_by_root_cause(findings):
    """Cluster findings that share a root-cause family. Returns a list
    of cluster dicts:

      ``{"label": str, "primary": finding, "supporting": [findings],
         "worst_rank": int, "member_count": int}``

    Findings NOT in any known family come back as singleton clusters
    with the finding itself as ``primary`` and ``supporting`` empty.
    """
    sev_rank = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    by_family: Dict[str, List[Dict[str, Any]]] = {}
    standalone: List[Dict[str, Any]] = []
    family_primary_pref: Dict[str, List[str]] = {}

    for f in findings:
        fam = root_cause_family_for(f["code"])
        if fam is None:
            standalone.append(f)
        else:
            label, primary_pref = fam
            by_family.setdefault(label, []).append(f)
            family_primary_pref[label] = primary_pref

    clusters = []
    for label, items in by_family.items():
        # Pick the primary: first item whose code is in the
        # primary_pref list (in order); if none, pick most-severe.
        primary = None
        pref = family_primary_pref.get(label) or []
        for code in pref:
            for f in items:
                if f["code"] == code:
                    primary = f
                    break
            if primary:
                break
        if primary is None:
            primary = min(items, key=lambda x: sev_rank.get(x["severity"], 9))
        supporting = [f for f in items if f is not primary]
        # Cluster severity = worst across all members
        worst_sev_value = min(
            sev_rank.get(f["severity"], 9) for f in items
        )
        clusters.append({
            "label": label,
            "primary": primary,
            "supporting": supporting,
            "worst_rank": worst_sev_value,
            "member_count": len(items),
        })
    for f in standalone:
        clusters.append({
            "label": None,
            "primary": f,
            "supporting": [],
            "worst_rank": sev_rank.get(f["severity"], 9),
            "member_count": 1,
        })
    return clusters


# ----------------------------------------------------------------------
# Backwards-compat aliases — the underscore-prefixed names lived inside
# zcc_diag_ui.py before the v45 module split. Keeping them lets the
# remaining call sites import either name.
# ----------------------------------------------------------------------
_ROOT_CAUSE_FAMILIES = ROOT_CAUSE_FAMILIES
_root_cause_family_for = root_cause_family_for
_DETECTOR_GROUPS = DETECTOR_GROUPS
_cluster_by_root_cause = cluster_by_root_cause
