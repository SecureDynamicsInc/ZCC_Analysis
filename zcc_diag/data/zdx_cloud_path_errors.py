"""
ZDX Cloud Path Errors — authoritative reference data.

Normalized from the Zscaler documentation "Digital Experience Monitoring
(ZDX): Cloud Path Errors".

31 entries across TWO sub-tables in the documentation:

  1. Cloud Path Errors (20 rows) — errors emitted by ZDX's Cloud
     Path probe (hop-by-hop traceroute view in the ZDX UI).

  2. Private Access and ZDX Error Codes (11 rows) — ZPA session
     statuses that can ALSO surface via ZDX probes when the target
     application is fronted by Private Access. These overlap
     semantically with the ZPA Session Status Codes documentation but the
     Zscaler docs document them separately under ZDX.

ICON KEY (from the documentation):
  info     (blue ⓘ)       — informational only, no action required
  warning  (yellow ⚠)     — action might be necessary
  critical (red ⊘)        — issue could affect user experience

PROBE PHASES (our derivation):

  internal          — ZCC internal errors
  network           — interface down / ISP issues
  domain_dns        — domain invalid / not resolvable
  proxy             — proxy connection / HTTP URL config
  network_change    — Cloud Path discarded due to device network change
  egress_trace      — egress IP can't be traced (GRE/IPSec / unfetched)
  protocol          — protocol-type blocked (ICMP/UDP/TCP)
  zpa_via_zdx       — ZPA-fronted application path (cross-suite)
  external_proxy    — third-party-proxy interaction paths

CATEGORIES (per documentation severity icon):

  category = "info" / "warning" / "error" — drives chip CSS class

CROSS-SUITE NOTE:

The 11 ZPA-via-ZDX rows duplicate session_status names from the ZPA
Session Status Codes documentation (already encoded in zpa_session_codes.py).
They are kept here too because the ZDX docs document them as part of
the Cloud Path error vocabulary. The chip cascade should prefer the
ZPA Session Status Codes entry when both modules match the same
string — that module has the canonical code (BRK_MT_*) and
component (SE / AC) fields. This module's contribution is the
ZDX-perspective resolution wording.

Source URL: https://help.zscaler.com/zdx/cloud-path-errors
"""

from __future__ import annotations

from typing import Dict, List, Optional

try:
    from typing import TypedDict
except ImportError:
    TypedDict = dict  # type: ignore


class ZdxCloudPathError(TypedDict, total=False):
    """One row from the ZDX Cloud Path Errors documentation.

    Fields:
      identifier         — our snake_case slug
      error_message      — documented from the documentation
      error_description  — documented from the documentation
      recommended_action — documented from the documentation
                           (documentation column titled "Solution" for Cloud Path
                           and "Resolution" for ZPA-via-ZDX section)
      probe_phase        — our derived category (see module docstring)
      category           — info | warning | error  (matches documentation icon)
      severity_hint      — critical | warning | info
      zpa_via_zdx        — bool; True when this is one of the 11
                           ZPA-fronted rows (cross-suite, dedupe with
                           zpa_session_codes.py when matching)
    """
    identifier: str
    error_message: str
    error_description: str
    recommended_action: str
    probe_phase: str
    category: str
    severity_hint: str
    zpa_via_zdx: bool


# =====================================================================
# Cloud Path Errors (20 rows) — direct ZDX probe errors
# =====================================================================

_CLOUD_PATH: List[ZdxCloudPathError] = [
    {
        "identifier": "zcc_internal_error",
        "error_message": "Zscaler Client Connector error. Contact Zscaler Support.",
        "error_description": "There is an internal error incurred by the Zscaler Client Connector.",
        "recommended_action": "Contact Zscaler Support.",
        "probe_phase": "internal",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "network_communication_failure",
        "error_message": "Network communication failure. Either network interface is down or traffic is blocked.",
        "error_description": "There is a network error. One of the interfaces is down, the probes are not receiving a response, or the ISP upstream connectivity might be down.",
        "recommended_action": "Verify your ISP connectivity and that the ICMP/UDP protocol configured for the probe is not blocked on the network.",
        "probe_phase": "network",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "domain_invalid_or_not_resolvable",
        "error_message": "The domain is invalid or not resolvable. Verify your domain.",
        "error_description": "The domain is invalid or not resolvable.",
        "recommended_action": "Verify the name of the domain or your DNS configuration.",
        "probe_phase": "domain_dns",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "proxy_connection_failed",
        "error_message": "Proxy connection failed.",
        "error_description": "There were issues when connecting to your web proxy.",
        "recommended_action": "Verify your proxy policy and authentication mechanism and that access is allowed for this application URL.",
        "probe_phase": "proxy",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "invalid_http_url",
        "error_message": "Invalid HTTP URL. Check the Web probe configuration.",
        "error_description": "Connection to the host is successful, but there are issues with connecting to your URL.",
        "recommended_action": "Verify that your URL for the Web probe is correct.",
        "probe_phase": "proxy",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "probe_discarded_network_change",
        "error_message": "The probe result was discarded due to a device network change.",
        "error_description": "The network changed during the Cloud Path probe run. Cloud Path probes for that sample were aborted.",
        "recommended_action": "Zscaler Client Connector detected the network change. No action is required.",
        "probe_phase": "network_change",
        "category": "info",
        "severity_hint": "info",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "egress_not_traceable_gre_ipsec_recommended",
        "error_message": "The network path to the client egress cannot be traced. Configuring a GRE/IPSec tunnel bypass rule for the client egress router is recommended.",
        "error_description": "The network path to the client egress IP address cannot be traced correctly because the egress IP is tunneled. This also means that the end-to-end latency value does not include the latency from the client to the Internet egress point.",
        "recommended_action": "Configure an access list for your router or SD-WAN device to bypass ICMP/UDP from the tunnel (GRE/IPSec) for your client egress IP address.",
        "probe_phase": "egress_trace",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "egress_not_traceable_zdx_data_unfetched",
        "error_message": "The network path to the client egress cannot be traced. Zscaler Client Connector was unable to fetch ZDX service data from Zscaler cloud.",
        "error_description": "The network path from the client to the Internet egress point (client egress) cannot be traced. Zscaler Client Connector was unable to fetch ZDX service data from the Zscaler cloud. This also means that the end-to-end latency value does not include the latency from the client to the internet egress point.",
        "recommended_action": "Contact Zscaler Support.",
        "probe_phase": "egress_trace",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "client_egress_detection_protocol_blocked",
        "error_message": "Client egress detection was not possible with the configured protocol type in the Cloud Path. Try a different protocol type.",
        "error_description": "The Zscaler Client Connector could not discover the user's Internet egress IP address.",
        "recommended_action": "Verify the configuration and try a different protocol (ICMP/UDP). The current Cloud Path protocol is blocked.",
        "probe_phase": "protocol",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "hop_info_zpa_pse_to_app_not_collected",
        "error_message": "Hop information from ZPA Public Service Edge to the application is not collected by ZDX.",
        "error_description": "We are not able to display the actual Cloud Path for applications accessed through Private Access.",
        "recommended_action": "No action required.",
        "probe_phase": "zpa_via_zdx",
        "category": "info",
        "severity_hint": "info",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "zia_pse_not_reachable_from_zcc",
        "error_message": "The Zscaler Public Service Edge is not reachable from Zscaler Client Connector.",
        "error_description": "The TCP traceroute to the Zscaler Service Edge was dropped.",
        "recommended_action": "Check your network connection.",
        "probe_phase": "network",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "probe_not_allowed_in_ndr",
        "error_message": "Probe not allowed in NDR.",
        "error_description": "ICMP and UDP probes are not supported in a No Default Route (NDR) environment.",
        "recommended_action": "Ensure you're running probes via TCP.",
        "probe_phase": "protocol",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "traceroute_not_reaching_zia_pse",
        "error_message": "Traceroute packets are not reaching the Zscaler Service Edge.",
        "error_description": "ICMP, TCP, or UDP protocol traceroute might not be supported on the network.",
        "recommended_action": "Ensure the underlying network permits the configured protocol.",
        "probe_phase": "protocol",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "external_proxy_to_destination_not_discoverable",
        "error_message": "Data from external proxy to destination is not discoverable.",
        "error_description": "Path is not available.",
        "recommended_action": "No action required.",
        "probe_phase": "external_proxy",
        "category": "info",
        "severity_hint": "info",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "external_proxy_to_egress_not_discoverable",
        "error_message": "Data from external proxy to egress is not discoverable.",
        "error_description": "Path is not available.",
        "recommended_action": "No action required.",
        "probe_phase": "external_proxy",
        "category": "info",
        "severity_hint": "info",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "cloud_path_packets_not_reaching_external_proxy",
        "error_message": "Cloud Path packets are not reaching the external proxy.",
        "error_description": "ICMP protocol might not be supported on the network.",
        "recommended_action": "Ensure the underlying network allows ICMP packets.",
        "probe_phase": "external_proxy",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "external_proxy_to_dc_egress_not_discoverable",
        "error_message": "Data from external proxy to data center egress is not discoverable.",
        "error_description": "Path is not available.",
        "recommended_action": "No action required.",
        "probe_phase": "external_proxy",
        "category": "info",
        "severity_hint": "info",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "dc_egress_to_destination_with_external_proxy_not_discoverable",
        "error_message": "Data from data center egress to destination is not discoverable when external proxy is present.",
        "error_description": "Path is not available.",
        "recommended_action": "No action required.",
        "probe_phase": "external_proxy",
        "category": "info",
        "severity_hint": "info",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "egress_to_destination_with_external_proxy_not_discoverable",
        "error_message": "Data from egress to destination is not discoverable when external proxy is present.",
        "error_description": "Path is not available.",
        "recommended_action": "No action required.",
        "probe_phase": "external_proxy",
        "category": "info",
        "severity_hint": "info",
        "zpa_via_zdx": False,
    },
    {
        "identifier": "client_egress_router_no_icmp_ttl_response",
        "error_message": "The client egress router did not respond to Cloud Path probes coming from the ZIA Public Service Edge.",
        "error_description": "The egress could not be probed. It did not respond with an ICMP TTL expired message for the ZDX Cloud Path probe.",
        "recommended_action": "Configure the router to return ICMP TTL expired messages for packets with IP TTL-1.",
        "probe_phase": "egress_trace",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": False,
    },
]


# =====================================================================
# Private Access and ZDX Error Codes (11 rows) — ZPA-via-ZDX
# These mirror session_status strings from zpa_session_codes.py;
# kept here for ZDX-perspective lookups. Chip cascade should prefer
# the ZPA module when both match.
# =====================================================================

_POLICY_OR_ATTR_RESOLUTION = (
    "Update the policy to allow the user. "
    "Ensure all SAML attributes are present in the SAML assertion and "
    "restart the Zscaler Client Connector. "
    "Ensure all SCIM attributes or SCIM groups are present. "
    "Modify policies to match the user's client type. "
    "Enable the App Segment or Segment Group."
)

_APP_NOT_CONFIG_RESOLUTION = (
    "Ensure that the Application and Application Segment are configured "
    "in the Zscaler Admin Console. Ask the user to access the "
    "application again. If the error persists, contact Zscaler Admin "
    "Console."
)

_ZPA_VIA_ZDX: List[ZdxCloudPathError] = [
    {
        "identifier": "zpa_internal_error",
        "error_message": "ZPA internal error.",
        "error_description": "The probe might have encountered a Private Access internal error.",
        "recommended_action": "Contact Zscaler Support.",
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_application_not_reachable",
        "error_message": "ZPA application is not reachable.",
        "error_description": "The probe might have failed to reach the Private Access destination.",
        "recommended_action": "Contact Zscaler Support.",
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_error_finding_customer",
        "error_message": "Error in finding customer.",
        "error_description": "The Public Service Edge for Private Access or Private Service Edge for Private Access cannot retrieve customer information due to a configuration error when processing the data connection request.",
        "recommended_action": "Ask the user to reauthenticate. If the error persists, contact Zscaler Support.",
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_user_session_expired",
        "error_message": "User session expired.",
        "error_description": "The Public Service Edge for Private Access or Private Service Edge for Private Access cannot set up a data connection because reauthentication is required.",
        "recommended_action": "Ask the user to reauthenticate. If the error persists, contact Zscaler Support.",
        "probe_phase": "zpa_via_zdx",
        "category": "warning",
        "severity_hint": "warning",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_error_filling_assistant_groups",
        "error_message": "Error in filling assistant groups.",
        "error_description": "The Public Service Edge for Private Access or Private Service Edge for Private Access cannot fill assistant groups due to a configuration error when processing the data request.",
        "recommended_action": "Ask the user to validate configuration. If the error persists, contact Zscaler Support.",
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_policy_or_attributes_misconfigured",
        "error_message": "Policy or attributes misconfigured for access.",
        "error_description": "A valid policy cannot be matched to an application access request. There is a missing or mismatched configuration in policy settings, SAML/SCIM attributes, Posture Profiles, Trusted Networks, Client Types, Cloud Connector Groups, or Machine Groups. The application request is also blocked when an App Segment or App Group Segment is disabled.",
        "recommended_action": _POLICY_OR_ATTR_RESOLUTION,
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_app_connector_group_not_configured",
        "error_message": "App Connector group not configured.",
        "error_description": "The Public Service Edge for Private Access was unable to process the application request since an App Connector group was not specified in the Server group configuration.",
        "recommended_action": "Edit the Server group to add the App Connector groups. To learn more, see Editing Server Groups.",
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_application_policy_blocked",
        "error_message": "Application policy blocked access.",
        "error_description": "The Private Access service blocked the application request because the user isn't allowed to access the requested application.",
        "recommended_action": "Update the policy to allow the user access.",
        "probe_phase": "zpa_via_zdx",
        "category": "warning",  # policy block — working as designed
        "severity_hint": "warning",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_timeout_policy_blocked",
        "error_message": "Timeout policy blocked access.",
        "error_description": "The Private Access service blocked the application request because the timeout policy requires the user to authenticate.",
        "recommended_action": "The user must reauthenticate in Zscaler Client Connector.",
        "probe_phase": "zpa_via_zdx",
        "category": "warning",  # policy block — working as designed
        "severity_hint": "warning",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_application_not_configured",
        "error_message": "Application not configured.",
        "error_description": "The Public Service Edge for Private Access or the Private Service Edge for Private Access cannot set up a connection since the application is not configured.",
        "recommended_action": _APP_NOT_CONFIG_RESOLUTION,
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
    {
        "identifier": "zpa_connection_request_timed_out",
        "error_message": "Connection request timed out.",
        "error_description": "The Public Service Edge for Private Access or Private Service Edge for Private Access was waiting for a data connection request from an App Connector that could provide access to the application, but the request timed out while waiting. The request from an App Connector is triggered in response to the initial application request from Zscaler Client Connector.",
        "recommended_action": "Ensure that the App Connectors can reach the Public Service Edge for Private Access or Private Service Edge for Private Access and the requested application.",
        "probe_phase": "zpa_via_zdx",
        "category": "error",
        "severity_hint": "critical",
        "zpa_via_zdx": True,
    },
]


# =====================================================================
# Aggregated exports
# =====================================================================

ERRORS: List[ZdxCloudPathError] = _CLOUD_PATH + _ZPA_VIA_ZDX

ERRORS_BY_ID: Dict[str, ZdxCloudPathError] = {r["identifier"]: r for r in ERRORS}
ERRORS_BY_MESSAGE: Dict[str, ZdxCloudPathError] = {
    r["error_message"]: r for r in ERRORS
}


def get_zdx_cloud_path_error(key: str) -> Optional[ZdxCloudPathError]:
    """Return the ZDX Cloud Path error row for ``key``, or None.

    Tries identifier match first, then exact documented message match.
    """
    if key is None:
        return None
    k = str(key).strip()
    if k in ERRORS_BY_ID:
        return ERRORS_BY_ID[k]
    if k in ERRORS_BY_MESSAGE:
        return ERRORS_BY_MESSAGE[k]
    return None


def zdx_cloud_path_error_severity(key: str, default: str = "warning") -> str:
    """Return the derived severity hint for a ZDX Cloud Path error."""
    row = get_zdx_cloud_path_error(key)
    if row is None:
        return default
    return row.get("severity_hint", default)


# =====================================================================
# Self-check at import time
# =====================================================================

assert len(_CLOUD_PATH) == 20, f"Cloud Path count drifted: {len(_CLOUD_PATH)}"
assert len(_ZPA_VIA_ZDX) == 11, f"ZPA-via-ZDX count drifted: {len(_ZPA_VIA_ZDX)}"
assert len(ERRORS) == 31, f"Total row count drifted: {len(ERRORS)}"
