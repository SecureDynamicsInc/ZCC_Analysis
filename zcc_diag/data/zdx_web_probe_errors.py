"""
ZDX Web Probe Errors — authoritative reference data.

Normalized from the Zscaler documentation "Digital Experience Monitoring
(ZDX): Web Probe Errors".

24 error messages that ZDX Web probes emit when probing application
URLs. These appear as icons in the Web probe Metrics section of the
User details panel in the ZDX admin console.

ICON / SEVERITY KEY (from the documentation):

  warning  (yellow triangle) — action might be necessary to resolve
                                an issue and achieve accurate results
  critical (red circle)      — issue that could affect user experience
  rate-limit (blue dot)      — Private Access Web probe is rate-limited
                                (distinct icon; informational/warning)

PROBE PHASES (our derivation, used for chip routing):

  domain_dns      — DNS resolution failure
  tcp_connect     — Raw TCP connect to the application (no proxy)
  http_method     — HTTP method not supported by the probe config
  http_connect    — Public Service Edge HTTP CONNECT proxy phase
  http_status     — HTTP status code mismatch with configured success codes
  http_request    — TCP-level issue while sending HTTP request to app
  https           — HTTPS / TLS handshake issues (cert, SSL)
  timeout         — Overall Web probe timeout
  rate_limit      — Private Access rate limiting

WHERE THESE APPEAR:

ZDX Web probe errors are displayed in the ZDX cloud admin UI, not
typically in ZCC tunnel logs. Their value in BundleScope is as
reference material when a customer reports a specific Web probe error
icon and asks what it means — engineers can look it up here without
leaving the tool.

Source URL: https://help.zscaler.com/zdx/web-probe-errors
"""

from __future__ import annotations

from typing import Dict, List, Optional

try:
    from typing import TypedDict
except ImportError:
    TypedDict = dict  # type: ignore


class ZdxWebProbeError(TypedDict, total=False):
    """One row from the ZDX Web Probe Errors documentation.

    Fields:
      identifier         — our snake_case slug (since the documentation doesn't
                           give numeric codes — the error_message
                           string IS the identifier from the docs)
      error_message      — documented from the documentation "Error Message" column
      error_description  — documented from the documentation "Error Description"
                           column
      recommended_action — documented from the documentation "Recommended Action"
                           column
      probe_phase        — our category (domain_dns / tcp_connect /
                           http_method / http_connect / http_status /
                           http_request / https / timeout / rate_limit)
      severity_hint      — critical | warning | info  (matches documentation icon)
    """
    identifier: str
    error_message: str
    error_description: str
    recommended_action: str
    probe_phase: str
    severity_hint: str


# =====================================================================
# Domain / DNS phase
# =====================================================================

_DOMAIN_DNS: List[ZdxWebProbeError] = [
    {
        "identifier": "domain_invalid_or_not_resolvable",
        "error_message": "The domain is invalid or not resolvable. Verify your domain.",
        "error_description": "After redirection, DNS resolution failed. This could be an issue with the application or its domain.",
        "recommended_action": "Verify the domain configured in the application is still valid or that it exists. Also check the application redirection.",
        "probe_phase": "domain_dns",
        "severity_hint": "critical",
    },
]


# =====================================================================
# Raw TCP connect phase (direct to application, no proxy CONNECT)
# =====================================================================

_TCP_CONNECT: List[ZdxWebProbeError] = [
    {
        "identifier": "tcp_connection_was_reset",
        "error_message": "TCP connection was reset",
        "error_description": "The TCP connection was reset. This could be due to a firewall or security policies, lack of server resources, server error, or congestion.",
        "recommended_action": "Verify that the security policies allow traffic to this application, or that the server is listening on the config port, or that server resources are adequate.",
        "probe_phase": "tcp_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_connection_timed_out",
        "error_message": "TCP connection timed out",
        "error_description": "The TCP connection timed out while waiting for a response from the application.",
        "recommended_action": "Check that the application configured for the Web probe is correct. Also check for any network devices that might be dropping SYN packets silently.",
        "probe_phase": "tcp_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_connection_aborted",
        "error_message": "TCP connection aborted",
        "error_description": "The TCP connection was aborted, as a TCP connection reset message was received after the connection was established.",
        "recommended_action": "High numbers of aborted connections can point to network or server problems.",
        "probe_phase": "tcp_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_connection_refused",
        "error_message": "TCP connection refused",
        "error_description": "The TCP connection was refused. This means that no port is listening or that a firewall is blocking the port.",
        "recommended_action": "Check the configuration to verify that the correct port was used and your server is listening on that port. Also verify that your security policies allow traffic to this port.",
        "probe_phase": "tcp_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_connection_error",
        "error_message": "TCP connection error",
        "error_description": "There was a generic TCP connection error.",
        "recommended_action": "Contact Zscaler Support.",
        "probe_phase": "tcp_connect",
        "severity_hint": "critical",
    },
]


# =====================================================================
# HTTP method phase
# =====================================================================

_HTTP_METHOD: List[ZdxWebProbeError] = [
    {
        "identifier": "http_method_not_supported",
        "error_message": "The Web probe HTTP method is not supported by the application",
        "error_description": "Zscaler does not currently support this HTTP request method. Currently, you can configure only the GET method from the UI.",
        "recommended_action": "Check the Web probe configuration. Consider adding a 40X/50X code to build a valid success code in the Web probe configuration.",
        "probe_phase": "http_method",
        "severity_hint": "warning",
    },
]


# =====================================================================
# HTTP CONNECT phase (Public Service Edge proxy)
# =====================================================================

_HTTP_CONNECT: List[ZdxWebProbeError] = [
    {
        "identifier": "tcp_reset_during_http_connect",
        "error_message": "TCP connection was reset during HTTP CONNECT request",
        "error_description": "The Public Service Edge for Internet & SaaS timed out the HTTP connection as no response was received from the destination server.",
        "recommended_action": "Check that you are authenticated to use the Zscaler service and there is a valid policy.",
        "probe_phase": "http_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_timeout_during_http_connect",
        "error_message": "TCP connection timed out during HTTP CONNECT request",
        "error_description": "The Public Service Edge for Internet & SaaS timed out the HTTP connection as no response was received from the destination server.",
        "recommended_action": "Check that the URL in the Web probe configuration is correct.",
        "probe_phase": "http_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_aborted_during_http_connect",
        "error_message": "TCP connection aborted during HTTP CONNECT request",
        "error_description": "The Public Service Edge for Internet & SaaS aborted the HTTP connection after receiving a TCP reset from the destination server.",
        "recommended_action": "Check the configuration to verify that the URL is correct.",
        "probe_phase": "http_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_refused_during_http_connect",
        "error_message": "TCP connection refused during HTTP CONNECT request",
        "error_description": "The Public Service Edge for Internet & SaaS refused the HTTP connection after receiving a TCP reset from the destination server.",
        "recommended_action": "Check the configuration to verify that the correct port was used and the destination server is listening on that port. Also check the security policy.",
        "probe_phase": "http_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "invalid_http_response_during_http_connect",
        "error_message": "Invalid HTTP response received during HTTP CONNECT request",
        "error_description": "The Public Service Edge for Internet & SaaS HTTP response code had an error.",
        "recommended_action": "Contact Zscaler Support.",
        "probe_phase": "http_connect",
        "severity_hint": "critical",
    },
    {
        "identifier": "http_connect_request_failed",
        "error_message": "HTTP CONNECT request failed",
        "error_description": "There was a generic exception in sending the connection to the Public Service Edge for Internet & SaaS.",
        "recommended_action": "Verify that the Public Service Edge for Internet & SaaS is not blocked by the firewall.",
        "probe_phase": "http_connect",
        "severity_hint": "critical",
    },
]


# =====================================================================
# HTTP status code phase
# =====================================================================

_HTTP_STATUS: List[ZdxWebProbeError] = [
    {
        "identifier": "http_response_code_not_success",
        "error_message": "HTTP response code xxx not a success code",
        "error_description": "The HTTP response code was a mismatch and is not in the configured list of successful HTTP codes.",
        "recommended_action": "The Web probe is configured to consider successful HTTP connections in the range (100-199), (200-299), and (300-399). The response code received was not in this range. Consider reconfiguring the HTTP success code to include (400-499) client errors. If (500-599) server errors are also transiently received, you might consider adding them as an HTTP success code. To learn more, see Configuring a Probe.",
        "probe_phase": "http_status",
        "severity_hint": "warning",
    },
]


# =====================================================================
# HTTP request to application phase (post-CONNECT, app-side TCP issues)
# =====================================================================

_HTTP_REQUEST: List[ZdxWebProbeError] = [
    {
        "identifier": "tcp_reset_during_http_request",
        "error_message": "TCP connection was reset during HTTP request to application.",
        "error_description": "The TCP connection was reset by the application server while the HTTP request was in progress.",
        "recommended_action": "The application server closed the TCP connection. This is probably due to a high load on the application.",
        "probe_phase": "http_request",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_timeout_during_http_request",
        "error_message": "TCP connection timed out during HTTP request to application",
        "error_description": "The TCP connection timed out while sending the HTTP request to the application server.",
        "recommended_action": "A response was not received from the server in the configured timeout (60 seconds by default).",
        "probe_phase": "http_request",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_aborted_during_http_request",
        "error_message": "TCP connection aborted during HTTP request to application",
        "error_description": "The TCP connection was aborted by the application server during the HTTP request.",
        "recommended_action": "The application server sent a TCP connection reset. This is probably due to a high load on the application.",
        "probe_phase": "http_request",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_refused_during_http_request",
        "error_message": "TCP connection refused during HTTP request to application",
        "error_description": "The TCP connection was refused by the server during the HTTP request.",
        "recommended_action": "Verify that the configured port is open on the server. Also check if there is a firewall in the path that is blocking the connection.",
        "probe_phase": "http_request",
        "severity_hint": "critical",
    },
    {
        "identifier": "tcp_error_during_http_request",
        "error_message": "TCP connection error during HTTP request to application",
        "error_description": "A generic application server error was received.",
        "recommended_action": "The TCP connection with the application could not be established. This is probably due to a high load on the application.",
        "probe_phase": "http_request",
        "severity_hint": "critical",
    },
]


# =====================================================================
# HTTPS / TLS handshake phase
# =====================================================================

_SSL_CAUSES = (
    "The application server SSL handshake has a generic exception. "
    "Possible causes could be: Improperly formatted SSL certificate; "
    "Improperly installed certificate; Wrong cipher; Problem in the "
    "certificate's chain of trust."
)

_HTTPS: List[ZdxWebProbeError] = [
    {
        "identifier": "https_invalid_certificate",
        "error_message": "HTTPS connection failed due to invalid certificate",
        "error_description": "The certificate received from the application server is invalid.",
        "recommended_action": "Verify the validity of the certificate and that the certificate has not expired.",
        "probe_phase": "https",
        "severity_hint": "critical",
    },
    {
        "identifier": "https_ssl_context_exception",
        "error_message": "HTTPS connection failed due to SSL context exception",
        "error_description": "An SSL context exception error occurred.",
        "recommended_action": _SSL_CAUSES,
        "probe_phase": "https",
        "severity_hint": "critical",
    },
    {
        "identifier": "https_ssl_error",
        "error_message": "HTTPS connection failed due to SSL error",
        "error_description": "A generic SSL exception occurred. This could be due to multiple possible causes.",
        "recommended_action": _SSL_CAUSES,
        "probe_phase": "https",
        "severity_hint": "critical",
    },
]


# =====================================================================
# Overall probe timeout + rate limit
# =====================================================================

_TIMEOUT_AND_RATE: List[ZdxWebProbeError] = [
    {
        "identifier": "web_probe_request_timed_out",
        "error_message": "Web probe request timed out",
        "error_description": "The probe timed out as there was no response. The Web probe HTTP request exceeded the configured timeout value (60, by default) in the probe configuration.",
        "recommended_action": "Verify that the URL is correctly configured or change the default timeout value.",
        "probe_phase": "timeout",
        "severity_hint": "critical",
    },
    {
        "identifier": "web_probe_is_rate_limited",
        "error_message": "Web probe is rate limited",
        "error_description": "The Web probe failed due to Private Access rate limiting to control the probe threshold.",
        "recommended_action": "When configuring Web probes for internal applications through Private Access, configure probes only for users, user groups, and departments that use the application.",
        "probe_phase": "rate_limit",
        "severity_hint": "warning",
    },
]


# =====================================================================
# Aggregated exports
# =====================================================================

ERRORS: List[ZdxWebProbeError] = (
    _DOMAIN_DNS + _TCP_CONNECT + _HTTP_METHOD + _HTTP_CONNECT
    + _HTTP_STATUS + _HTTP_REQUEST + _HTTPS + _TIMEOUT_AND_RATE
)

# Identifier-keyed lookup (snake_case slug -> row)
ERRORS_BY_ID: Dict[str, ZdxWebProbeError] = {r["identifier"]: r for r in ERRORS}

# Documented-message-keyed lookup (documentation Error Message string -> row).
# Use this when the operator pastes the literal error string they saw
# in the ZDX UI.
ERRORS_BY_MESSAGE: Dict[str, ZdxWebProbeError] = {
    r["error_message"]: r for r in ERRORS
}


def get_zdx_web_probe_error(key: str) -> Optional[ZdxWebProbeError]:
    """Return the ZDX Web Probe error row for ``key``, or None.

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


def zdx_web_probe_error_severity(key: str, default: str = "warning") -> str:
    """Return the derived severity hint for a ZDX Web Probe error."""
    row = get_zdx_web_probe_error(key)
    if row is None:
        return default
    return row.get("severity_hint", default)


# =====================================================================
# Self-check at import time
# =====================================================================

assert len(_DOMAIN_DNS) == 1, f"Domain/DNS count drifted: {len(_DOMAIN_DNS)}"
assert len(_TCP_CONNECT) == 5, f"TCP connect count drifted: {len(_TCP_CONNECT)}"
assert len(_HTTP_METHOD) == 1, f"HTTP method count drifted: {len(_HTTP_METHOD)}"
assert len(_HTTP_CONNECT) == 6, f"HTTP CONNECT count drifted: {len(_HTTP_CONNECT)}"
assert len(_HTTP_STATUS) == 1, f"HTTP status count drifted: {len(_HTTP_STATUS)}"
assert len(_HTTP_REQUEST) == 5, f"HTTP request count drifted: {len(_HTTP_REQUEST)}"
assert len(_HTTPS) == 3, f"HTTPS count drifted: {len(_HTTPS)}"
assert len(_TIMEOUT_AND_RATE) == 2, f"Timeout/rate count drifted: {len(_TIMEOUT_AND_RATE)}"
assert len(ERRORS) == 24, f"Total row count drifted: {len(ERRORS)}"
