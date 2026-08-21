"""
Detector: IdP redirect chain breaks during third-party SSO.

Third-party VPN clients (AWS VPN, Cisco AnyConnect, Citrix, Pulse
Secure, GlobalProtect) often delegate authentication to a corporate
IdP (Entra ID, Okta, Auth0, Ping). The auth flow is a chain of
302 redirects through ``login.microsoftonline.com`` / ``okta.com`` /
``auth0.com`` / etc. When ZIA inspects an intermediate hop of that
chain, the resigned cert breaks the IdP's expected handshake and the
redirect dies silently.

The symptom is "VPN can't authenticate" -- but the customer's
network is healthy, ZCC tunnels are up, and the cert error doesn't
fire against the VPN gateway itself. It fires against an IdP hop.

Grounded by:
- an anonymized internal case (Example Tenant N AWS VPN). Ticket content
  observed: *"Our VPN typically requires a redirect to our IdP,
  Entra ID, but that redirect is not occurring when connected to
  Zscaler. Another VPN of ours, OpenVPN, does allow the redirect
  and successfully connects."*
- Same pattern likely applies to an anonymized internal case
  ("Can't AnyConnect").

Signature: an SSL handshake / cert error against a known IdP host
that immediately preceded (or followed) traffic to a known VPN
gateway endpoint on the same thread. This is a chain-correlation
detector rather than a single-line one.

Distinct from other detectors:
- ``bypass_misconfiguration`` would catch a cert error against any
  bypass-list-missing host; this one is more specific and attributes
  it to the VPN+IdP combination.
- ``ai_cli_pin`` / ``rmm_agent_pin`` cover vendor-specific cert pin
  failures; IdP redirect failures aren't the same shape (the IdP
  itself trusts Zscaler intermediate; it's the redirect chain that
  breaks, not the cert per se).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# IdP host catalogue. We match by suffix so subdomain variants
# (tenant-specific Okta orgs etc.) are covered.
_IDP_HOST_SUFFIXES = (
    # Microsoft Entra ID
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.live.com",
    "device.login.microsoftonline.com",
    # Okta (tenant subdomain.okta.com)
    ".okta.com",
    "okta.com",
    # Auth0
    ".auth0.com",
    "auth0.com",
    # Ping Identity
    ".pingidentity.com",
    "pingidentity.com",
    ".ping-eng.com",
    # OneLogin
    ".onelogin.com",
    "onelogin.com",
    # Google Workspace
    "accounts.google.com",
    # Duo (often layered on Entra/Okta)
    ".duosecurity.com",
    "duosecurity.com",
    # JumpCloud SSO
    "console.jumpcloud.com",
    "sso.jumpcloud.com",
)

# Third-party VPN gateway host catalogue. The detector fires when a
# cert error on an IdP host above happens on the same thread / in
# the same correlation window as traffic to one of these.
_VPN_GATEWAY_HINTS = (
    # AWS VPN client (Verified Access)
    "vpn-endpoint",  # appears in URL of AWS Verified Access endpoints
    "amazonaws.com",
    # Cisco AnyConnect / Secure Client
    "anyconnect",
    "vpn.cisco.com",
    # Citrix
    "citrix.com",
    "netscaler",
    # Pulse Secure / Ivanti
    "pulsesecure.net",
    "ivanti.com",
    # GlobalProtect / Palo Alto
    "globalprotect",
    "paloaltonetworks.com",
    # Generic ones some customers use
    "openvpn",
)


# Entra ID (Azure AD) AADSTS error codes. Most-cited from Zscaler
# community discussions, with the meanings per Microsoft's published
# AADSTS docs. When ZCC captures the IdP's redirect response in
# tunnel-log or tray-log records, the AADSTS<N> token appears
# observed.
#
#   AADSTS53003 - Access blocked by Conditional Access policy.
#   AADSTS50105 - The signed-in user is not assigned to a role for
#                 the application.
#   AADSTS50020 - User account from external identity provider
#                 does not exist in the tenant.
#   AADSTS50158 - External security challenge not satisfied (MFA).
#   AADSTS500011 - The resource principal named X was not found in
#                  the tenant.
#   AADSTS900971 - No reply address provided.
_AADSTS_CATALOG = {
    "AADSTS53003":  "Access blocked by Conditional Access policy",
    "AADSTS50105":  "User not assigned to a role for this app",
    "AADSTS50020":  "User from external IdP not in tenant",
    "AADSTS50158":  "External security challenge (MFA) not satisfied",
    "AADSTS500011": "Resource principal not found in tenant",
    "AADSTS900971": "No reply address provided",
    "AADSTS70008":  "The provided authorization code has expired",
    "AADSTS65001":  "The user has not consented to the application",
    "AADSTS50012":  "Invalid client secret",
    "AADSTS50034":  "User account does not exist in directory",
}
_RE_AADSTS_TOKEN = re.compile(
    r"\b(AADSTS\d{4,7})\b"
)

_RE_HOST_LINE = re.compile(
    r"\bHost=(?P<host>[A-Za-z0-9.\-]+)(?::\d+)?",
)
_RE_SSL_FAIL = re.compile(
    r"Auth::Lib::certificateErroCallback:\s*Invalid certificate"
    r"|Certificate validation error"
    r"|SSL handshake (?:failure|failed|fail)"
    r"|TLS handshake (?:failure|failed|fail)"
    r"|ssl3_get_server_certificate.*?verify failed",
    re.IGNORECASE,
)
# 302 redirect signatures. Some ZCC versions log this directly.
_RE_HTTP_REDIRECT = re.compile(
    r"\bHTTP/[\d.]+ 30[2378]\b"
    r"|Location:\s*https?://"
    r"|HttpRedirect:",
    re.IGNORECASE,
)


def _is_idp_host(host: str) -> Optional[str]:
    h = host.lower().rstrip(".")
    for suffix in _IDP_HOST_SUFFIXES:
        s = suffix.lower()
        if s.startswith("."):
            if h.endswith(s):
                return s.lstrip(".")
        else:
            if h == s or h.endswith("." + s):
                return s
    return None


def _is_vpn_hint(host: str) -> bool:
    h = host.lower()
    return any(hint in h for hint in _VPN_GATEWAY_HINTS)


EVIDENCE_CAP = 10


@register
class IdpRedirectFailDetector(IssueDetector):
    id = "idp_redirect_fail"
    title = "IdP redirect chain broken by SSL inspection"
    sop_file = "idp_redirect_fail.md"
    # ZIA-only: SSL inspection of IdP redirect chains is a ZIA-side
    # behaviour. ZPA enrollment uses its own SAML path that's not
    # routed through ZIA's inspection pipeline.
    applies_to_suite = ("zia",)

    def __init__(self) -> None:
        super().__init__()
        # Per-thread state:
        #   - last_idp_host: most recent IdP host seen on the thread
        #   - vpn_context_seen: whether a VPN-gateway host appeared
        #     on the same thread within the recent window
        self._thread_last_idp: Dict[tuple, Tuple[str, str]] = {}  # (host, matched_idp_suffix)
        self._thread_vpn_context: Dict[tuple, bool] = {}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        key = (record.pid, record.tid)

        m_host = _RE_HOST_LINE.search(msg)
        if m_host:
            host = m_host.group("host")
            idp = _is_idp_host(host)
            if idp is not None:
                self._thread_last_idp[key] = (host, idp)
            elif _is_vpn_hint(host):
                self._thread_vpn_context[key] = True

        # Entra ID AADSTS error code surfacing. ZCC captures the IdP's
        # redirect response when it has the body inline; the AADSTS<N>
        # token appears as a literal substring. Fires regardless of
        # SSL-fail context because the AADSTS code IS the diagnostic
        # signal -- the user got blocked at the IdP layer, not by SSL
        # inspection.
        m_aadsts = _RE_AADSTS_TOKEN.search(msg)
        if m_aadsts:
            code = m_aadsts.group(1)
            meaning = _AADSTS_CATALOG.get(code, "uncatalogued AADSTS code")
            f = self._bucket(
                f"AADSTS_ERROR_{code}",
                Severity.CRITICAL,
                f"Entra ID returned {code}: {meaning}",
                (
                    f"The IdP (Microsoft Entra ID) returned error "
                    f"``{code}`` -- ``{meaning}``. This is an IdP-side "
                    f"rejection, not a Zscaler SSL-inspection failure. "
                    f"Fixing it requires action in the customer's "
                    f"Entra admin portal, not on the Zscaler side.\n\n"
                    f"Common fixes by code:\n"
                    f"  * AADSTS53003 -> Conditional Access blocked "
                    f"the sign-in. Check the user's CA policy "
                    f"assignment; the device may need to be marked "
                    f"compliant in Intune or join the right "
                    f"location filter.\n"
                    f"  * AADSTS50105 -> User isn't assigned to the "
                    f"Zscaler enterprise app. Entra admin -> "
                    f"Enterprise Applications -> Zscaler -> Users "
                    f"and groups -> Add user.\n"
                    f"  * AADSTS50020 -> User exists in an external "
                    f"tenant (B2B guest) but isn't invited to this "
                    f"tenant. Invite as guest first.\n"
                    f"  * AADSTS50158 -> MFA challenge wasn't "
                    f"completed. Verify the user has an MFA method "
                    f"registered.\n"
                    f"  * AADSTS50012 -> Invalid client secret on "
                    f"the Zscaler app registration. Rotate the "
                    f"secret in Entra and update Zscaler config.\n"
                    f"  * AADSTS70008 -> Authorization code expired "
                    f"between IdP and Zscaler. Usually a clock-skew "
                    f"issue or the user took too long on the IdP page."
                ),
                sop_anchor="#aadsts-error",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        if _RE_SSL_FAIL.search(msg):
            idp_state = self._thread_last_idp.get(key)
            if idp_state is None:
                return
            host, idp = idp_state
            had_vpn_ctx = self._thread_vpn_context.get(key, False)

            if had_vpn_ctx:
                # Strong: IdP failure with a VPN gateway in the same
                # thread context. This is the Example Tenant N case shape.
                f = self._bucket(
                    f"IDP_REDIRECT_FAIL_VPN__{idp}",
                    Severity.CRITICAL,
                    (
                        f"VPN SSO chain breaks at IdP ``{host}`` "
                        f"(SSL inspection)"
                    ),
                    (
                        f"ZCC's SSL inspection broke a handshake "
                        f"against IdP host ``{host}`` (catalogue: "
                        f"``{idp}``). Earlier on the same thread, "
                        f"traffic was flowing to a third-party VPN "
                        f"gateway -- the failed IdP hop is part of "
                        f"that VPN's SSO redirect chain.\n\n"
                        f"This is the Example Tenant N AWS VPN case shape: "
                        f"VPN delegates auth to Entra ID, Zscaler "
                        f"inspects the redirect, IdP rejects the "
                        f"resigned cert mid-chain, VPN can't "
                        f"complete authentication. The customer's "
                        f"network is healthy; only this specific "
                        f"flow is broken.\n\n"
                        f"Fix: add the IdP host AND the VPN gateway "
                        f"host to BLSSL bypass. Both must be exempt "
                        f"from SSL inspection -- bypassing only one "
                        f"side leaves the redirect chain still "
                        f"broken."
                    ),
                    sop_anchor="#idp-redirect-fail-vpn",
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)
            else:
                # Weaker: IdP failure without obvious VPN context.
                # Surface at WARN -- could be a web-SSO flow that
                # happens to involve the IdP.
                f = self._bucket(
                    f"IDP_REDIRECT_FAIL__{idp}",
                    Severity.WARNING,
                    f"IdP cert error against ``{host}``",
                    (
                        f"ZCC's SSL inspection broke a handshake "
                        f"against IdP host ``{host}`` (catalogue: "
                        f"``{idp}``). No third-party VPN gateway "
                        f"appeared on the same thread, so the SSO "
                        f"chain in play is uncertain.\n\n"
                        f"Add ``{host}`` to BLSSL bypass if the "
                        f"customer is hitting SSO failures. The "
                        f"correlation window may reveal which "
                        f"app was initiating the auth (Slack, "
                        f"Salesforce, custom SaaS, etc.)."
                    ),
                    sop_anchor="#idp-redirect-fail",
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
