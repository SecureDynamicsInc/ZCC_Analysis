"""
ZDX Zscaler Managed Probe Errors — authoritative reference data.

Normalized from the Zscaler documentation "Digital Experience Monitoring
(ZDX): Zscaler Managed Probe Errors".

60 error rows across TWO sub-tables for Zscaler Managed probes
(probes managed and operated by Zscaler — distinct from
customer-configured Web probes covered in zdx_web_probe_errors.py).

  1. Web probe         (9 rows)  — probe_type="web"
  2. Cloud Path probe  (51 rows) — probe_type="cloud_path"

NOTE: "Internal error" appears in BOTH tables as a distinct row —
the Web table version blames the Web probe; the Cloud Path version
covers the Cloud Path probe internal path. Identifiers are
disambiguated by probe_type.

CATEGORIES (our derivation):

  memory     — exhaustion / allocation failure
  config     — invalid input / IP / config mismatch
  timeout    — probe / DNS / socket timeout
  socket     — low-level socket operations (read/write/option/handle/close)
  network    — interface / packet-level network failures
  dns        — DNS resolution / response errors
  protocol   — unsupported protocol (TCP/ICMP)
  icmp       — unexpected ICMP messages received
  destination — unreachable / unresponsive destination
  internal   — generic internal errors / unhandled events

SEVERITY DERIVATION:

  critical — outright probe failure (memory exhaustion, socket
             handle creation failed, can't connect to host, DNS
             timeout on socket)
  warning  — recoverable / config-investigation paths (most rows —
             "Report the error to Zscaler Support" is informational
             but not customer-facing critical)
  info     — benign "No action required" rows

WHERE THESE APPEAR:

Zscaler Managed Probe errors fire from probe infrastructure operated
by Zscaler (not customer-configured probes). They surface in ZDX
admin UI and may appear in ZCC tray / service logs when the local
probe agent encounters them. They're typically infrastructure-side
issues — operators should usually contact Zscaler Support.

Source URL: https://help.zscaler.com/zdx/zscaler-managed-probe-errors
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

try:
    from typing import TypedDict
except ImportError:
    TypedDict = dict  # type: ignore


class ZdxManagedProbeError(TypedDict, total=False):
    """One row from the ZDX Managed Probe Errors documentation.

    Fields:
      identifier         — our snake_case slug (prefixed with web_ or cp_
                           to disambiguate the duplicate "Internal error")
      error_message      — documented from the documentation
      error_description  — documented from the documentation
      recommended_action — documented from the documentation
      probe_type         — web | cloud_path
      category           — memory | config | timeout | socket | network |
                           dns | protocol | icmp | destination | internal
      severity_hint      — critical | warning | info
    """
    identifier: str
    error_message: str
    error_description: str
    recommended_action: str
    probe_type: str
    category: str
    severity_hint: str


_REPORT_TO_SUPPORT = "Report the error to Zscaler Support."


def _mk(
    ident: str, msg: str, desc: str, action: str,
    probe_type: str, category: str, severity: str,
) -> ZdxManagedProbeError:
    """Helper to keep row literals readable."""
    return {
        "identifier": ident,
        "error_message": msg,
        "error_description": desc,
        "recommended_action": action,
        "probe_type": probe_type,
        "category": category,
        "severity_hint": severity,
    }


# =====================================================================
# Web probe (9 rows) — probe_type="web"
# =====================================================================

_WEB: List[ZdxManagedProbeError] = [
    _mk("web_insufficient_memory",
        "Web probe has insufficient memory",
        "The Web probe ran out of memory.",
        _REPORT_TO_SUPPORT,
        "web", "memory", "critical"),
    _mk("web_incorrect_configuration",
        "Web probe has incorrect configuration",
        "The Web probe contains an incorrect configuration.",
        "Review and validate the Web probe's configuration.",
        "web", "config", "warning"),
    _mk("web_invalid_location",
        "Invalid location",
        "The Web probe has an invalid location.",
        _REPORT_TO_SUPPORT,
        "web", "config", "warning"),
    _mk("web_invalid_destination_url",
        "Invalid Web probe Destination URL",
        "The Web probe contains an invalid destination URL.",
        "Check that your destination URL for the Web probe is correct.",
        "web", "config", "warning"),
    _mk("web_met_maximum_redirects",
        "Web probe has met the maximum redirects",
        "The Web probe reached the maximum amount of redirects.",
        "Increase the maximum amount of redirects.",
        "web", "config", "warning"),
    _mk("web_not_within_http_code_range",
        "Not within the HTTP response code range",
        "The Web probe has reached an error code that does not exist within the HTTP response code range.",
        "No action required.",
        "web", "config", "info"),
    _mk("web_request_timed_out",
        "Web probe request timed out",
        "The Web probe has timed out.",
        "Increase the maximum allowed timeout.",
        "web", "timeout", "warning"),
    _mk("web_system_error_processing_analytics",
        "System error while processing analytics",
        "There is a system error where data could not be gathered for analytics.",
        _REPORT_TO_SUPPORT,
        "web", "internal", "critical"),
    _mk("web_internal_error",
        "Internal error",
        "There is an unknown internal error with the Web probe.",
        _REPORT_TO_SUPPORT,
        "web", "internal", "critical"),
]


# =====================================================================
# Cloud Path probe (51 rows) — probe_type="cloud_path"
# =====================================================================

_CLOUD_PATH: List[ZdxManagedProbeError] = [
    _mk("cp_error_processing_timeout_event",
        "Error processing a timeout event",
        "The Cloud Path probe timed out while waiting for a response.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "timeout", "warning"),
    _mk("cp_error_processing_socket_event",
        "Error processing socket event",
        "The Cloud Path probe experienced an error while processing.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_failed_dns_response",
        "Failed DNS response",
        "The Cloud Path probe aborted due to an internal error and cannot read/write DNS packets to/from the probe.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "dns", "critical"),
    _mk("cp_insufficient_memory",
        "Cloud Path probe has insufficient memory",
        "The Cloud Path probe has exceeded the memory limit for the connection.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "memory", "critical"),
    _mk("cp_currently_in_progress",
        "Cloud Path probe is currently in progress.",
        "A Cloud Path probe is already in progress for the device.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_user_logging_callback_already_set",
        "User logging callback already set",
        "Tried to set an existing user logging callback.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_user_logging_expanded_callback_already_set",
        "User logging expanded callback already set",
        "Tried to set an existing user logging callback.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_unable_to_generate_random_numbers",
        "Unable to generate random numbers",
        "Internal error with random number generator.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "critical"),
    _mk("cp_unable_to_create_hash_table",
        "Unable to create hash table",
        "Internal error creating hash table.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "critical"),
    _mk("cp_duplicate_entry_in_hash_table",
        "Duplicate entry in hash table",
        "Duplicate Cloud Path probe",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_reached_max_capacity_hash_table",
        "Reached maximum capacity for hash table",
        "Cannot create more as limitation has been reached.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_unable_to_create_timeout_list",
        "Unable to create timeout list",
        "Internal error when trying to create a timeout list.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "critical"),
    _mk("cp_duplicate_entry_in_timeout_list",
        "Duplicate entry in timeout list",
        "There is a duplicate entry in the timeout list.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_unable_to_read_write_network_socket",
        "Unable to read/write network socket",
        "Aborted Cloud Path probe due to network or system error.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "network", "critical"),
    _mk("cp_unable_to_create_socket_handle",
        "Unable to create socket handle",
        "Aborted Cloud Path probe due to a system error possibly related to limited system resources.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "critical"),
    _mk("cp_cannot_retrieve_socket_address",
        "Cannot retrieve socket address",
        "Aborted probe due to system error related to no availability of network interfaces.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "network", "critical"),
    _mk("cp_cannot_rw_sockopt_reuse_address",
        "Cannot read/write socket option's reuse address",
        "Aborted probe due to system error.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_cannot_rw_sockopt_reuse_port",
        "Cannot read/write socket option's reuse port",
        "Aborted probe due to system error.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_cannot_write_sockopt_ip_header_include",
        "Cannot write socket option's IP header include",
        "Aborted probe due to system error.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_cannot_rw_socket_recv_buffer",
        "Cannot read/write the socket recv buffer",
        "Aborted probe due to system error with Zscaler Managed probe.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_cannot_rw_sockopt_error",
        "Cannot read/write socket option's error",
        "Aborted probe due to system error related to an unsupported socket option.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_cannot_connect_to_host",
        "Cannot connect to the host",
        "The probe is unable to connect to the host.",
        "Review probe configuration for a valid DNS name or IP address. If the error persists, report the error to Zscaler Support.",
        "cloud_path", "network", "critical"),
    _mk("cp_socket_address_not_binded",
        "Socket address not binded",
        "Aborted probe due to system error related to host.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "critical"),
    _mk("cp_unable_to_read_packets",
        "Unable to read packets",
        "There is an internal error with reading packets.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "network", "critical"),
    _mk("cp_cannot_write_to_socket",
        "Cannot write to the socket",
        "There is an internal error with writing packets to the network.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "network", "critical"),
    _mk("cp_socket_cannot_close_for_reading",
        "Socket cannot close for reading",
        "There was an internal error while trying to close the connection to the network.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_socket_cannot_close_for_writing",
        "Socket cannot close for writing",
        "There was an internal error while trying to close the connection to the network.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "socket", "warning"),
    _mk("cp_network_protocol_not_supported",
        "Network protocol not supported",
        "Network protocol is not supported.",
        "Provide a supported network protocol.",
        "cloud_path", "protocol", "warning"),
    _mk("cp_protocol_not_supported",
        "Protocol not supported",
        "A protocol other than TCP or ICMP was provided and is not supported.",
        "Provide a TCP or ICMP as the protocol.",
        "cloud_path", "protocol", "warning"),
    _mk("cp_invalid_ip_address",
        "Invalid IP address",
        "Invalid IP address was provided.",
        "Check your IP address for validity.",
        "cloud_path", "config", "warning"),
    _mk("cp_resolved_ip_type_mismatch",
        "Resolved IP address type does not match the requested type",
        "The provided IP address does not match the requested type (IP or IPv6).",
        _REPORT_TO_SUPPORT,
        "cloud_path", "config", "warning"),
    _mk("cp_did_not_reach_destination",
        "Cloud Path probe did not reach destination.",
        "The Cloud Path probe is unable to reach the destination.",
        "Check if the destination IP or domain is valid.",
        "cloud_path", "destination", "warning"),
    _mk("cp_timeout_list_hint_not_provided",
        "Timeout list hint was not provided",
        "Aborted probe due to an internal error.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_invalid_socket_event",
        "Invalid socket event",
        "Aborted probe due to an unexpected error.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_invalid_timeout_event",
        "Invalid timeout event",
        "Aborted probe due to an internal error with an invalid timeout event.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_triggered_unhandled_event",
        "Triggered unhandled event",
        "Probe was aborted due to an internal error with an unhandled event.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "warning"),
    _mk("cp_error_resolving_domain",
        "Error resolving domain",
        "There was an issue resolving the domain name.",
        "Verify the DNS name for probe destination.",
        "cloud_path", "dns", "warning"),
    _mk("cp_dns_request_timed_out",
        "DNS request timed out while waiting for a reply.",
        "There was an issue with the DNS server response to the DNS request.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "dns", "warning"),
    _mk("cp_non_existent_domain",
        "Non-existent domain",
        "The DNS name is not resolvable.",
        "Verify the DNS name for probe destination.",
        "cloud_path", "dns", "warning"),
    _mk("cp_empty_dns_response",
        "Empty DNS response",
        "There was no response from the DNS server with the provided IPs.",
        "Verify if the domain name is valid.",
        "cloud_path", "dns", "warning"),
    _mk("cp_cannot_write_socket_due_to_timeout",
        "Cannot write socket due to timeout",
        "There is an internal error.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "timeout", "warning"),
    _mk("cp_cannot_read_socket_due_to_timeout",
        "Cannot read socket due to timeout",
        "Aborted probe due to no destination response in the allotted timeout.",
        "Review timeout field in probe configuration.",
        "cloud_path", "timeout", "warning"),
    _mk("cp_invalid_probe_state",
        "Invalid Cloud Path probe state",
        "There is an internal error with the Cloud Path probe.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "internal", "critical"),
    _mk("cp_dest_server_binary_search_unresponsive",
        "Destination server for the Binary Search of the Cloud Path probe is unresponsive.",
        "The destination server of the probe is unresponsive.",
        "Review the number of maximum hops for the probe destination.",
        "cloud_path", "destination", "warning"),
    _mk("cp_dest_server_unresponsive",
        "Destination server of the Cloud Path probe is unresponsive.",
        "The destination server of the probe is unresponsive causing a timeout.",
        "Review the timeout for the destination server.",
        "cloud_path", "destination", "warning"),
    _mk("cp_unexpected_icmp_time_exceeded",
        "Received unexpected ICMP TIME EXCEEDED message.",
        "Aborted probe due to an unexpected packet.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "icmp", "warning"),
    _mk("cp_unexpected_icmp_dst_or_port_unreachable",
        "Received unexpected ICMP DST UNREACHABLE/PORT UNREACHABLE message.",
        "Aborted probe due to an unexpected packet.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "icmp", "warning"),
    _mk("cp_unexpected_icmp_dst_unreachable",
        "Received unexpected ICMP DST UNREACHABLE message.",
        "Aborted probe due to an unexpected packet.",
        _REPORT_TO_SUPPORT,
        "cloud_path", "icmp", "warning"),
    _mk("cp_tcp_reached_maximum_retries",
        "TCP Cloud Path probe reached maximum retries.",
        "Reached maximum number of packet retries within the received timeout.",
        "Review probe timeout configuration.",
        "cloud_path", "destination", "warning"),
    _mk("cp_tcp_syn_received_unexpectedly",
        "TCP SYN packet received unexpectedly",
        "Unexpected SYN packet sent.",
        "No action required.",
        "cloud_path", "internal", "info"),
    _mk("cp_internal_error",
        "Internal error",
        "Aborted probe due to an unexpected internal error.",
        "No action required.",
        "cloud_path", "internal", "warning"),
]


# =====================================================================
# Aggregated exports
# =====================================================================

ERRORS: List[ZdxManagedProbeError] = _WEB + _CLOUD_PATH

ERRORS_BY_ID: Dict[str, ZdxManagedProbeError] = {r["identifier"]: r for r in ERRORS}

# Message -> list of rows. "Internal error" appears in BOTH tables so
# it gets 2 entries; everything else gets a singleton.
ERRORS_BY_MESSAGE: Dict[str, List[ZdxManagedProbeError]] = {}
for _row in ERRORS:
    ERRORS_BY_MESSAGE.setdefault(_row["error_message"], []).append(_row)


def get_zdx_managed_probe_error(
    key: str,
    probe_type: Optional[str] = None,
) -> Optional[ZdxManagedProbeError]:
    """Return the ZDX Managed Probe error row for ``key``, or None.

    Tries identifier match first, then documented error_message match.
    When ``probe_type`` is provided ("web" or "cloud_path") and the
    message has multiple matches (i.e. "Internal error"), narrows to
    the matching probe_type. Otherwise returns the first match.
    """
    if key is None:
        return None
    k = str(key).strip()
    if k in ERRORS_BY_ID:
        return ERRORS_BY_ID[k]
    hits = ERRORS_BY_MESSAGE.get(k, [])
    if not hits:
        return None
    if probe_type:
        for h in hits:
            if h.get("probe_type") == probe_type:
                return h
    return hits[0]


def get_zdx_managed_probe_error_all(message: str) -> List[ZdxManagedProbeError]:
    """Return every row matching the documented error_message — only
    "Internal error" returns 2 rows; everything else returns ≤ 1."""
    if message is None:
        return []
    return list(ERRORS_BY_MESSAGE.get(str(message).strip(), ()))


def zdx_managed_probe_error_severity(
    key: str,
    probe_type: Optional[str] = None,
    default: str = "warning",
) -> str:
    """Return the derived severity hint for a ZDX Managed Probe error."""
    row = get_zdx_managed_probe_error(key, probe_type)
    if row is None:
        return default
    return row.get("severity_hint", default)


# =====================================================================
# Self-check at import time
# =====================================================================

assert len(_WEB) == 9, f"Web probe count drifted: {len(_WEB)}"
assert len(_CLOUD_PATH) == 51, f"Cloud Path probe count drifted: {len(_CLOUD_PATH)}"
assert len(ERRORS) == 60, f"Total row count drifted: {len(ERRORS)}"
# "Internal error" must appear twice (once per probe table)
assert len(ERRORS_BY_MESSAGE.get("Internal error", [])) == 2, \
    "'Internal error' should appear in both Web and Cloud Path tables"
# Identifiers must be unique (probe_type prefix disambiguates)
assert len(ERRORS_BY_ID) == 60, "Identifier collisions detected"
