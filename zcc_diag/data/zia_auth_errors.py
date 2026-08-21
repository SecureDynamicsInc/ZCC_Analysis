"""
ZIA Authentication Error Codes — authoritative reference data.

Normalized from two external Zscaler Help references:

  1. "Internet & SaaS Authentication Error Codes" — the reference covering
     Generic, AD/LDAP, Kerberos, and Identity Proxy.
  2. "Internet & SaaS Error Codes for Kerberos Authentication" — the focused
     Kerberos reference. It is encoded here once with the Kerberos category
     tag rather than duplicated as a separate data module.

~103 rows total across four ZIA authentication categories:

  - generic         (2 codes — 211000, 421000)
  - ldap_sync       (16 codes — 100..116, skipping 107)
  - kerberos        (15 rows — 9 codes including 5 occurrences of 471000
                     and 2 occurrences each of 491000/501000)
  - identity_proxy  (70 hex codes — 0x1388..0x13D2 with gaps at
                     0x1397/0x13A2/0x13A7/0x13A8/0x13BB)

WHERE THESE APPEAR:

These error codes are user-facing — they're the codes the Zscaler
service displays on an error page when authentication fails. ZCC
tunnel logs occasionally surface them in mobile-API response bodies
or in tray-log `Auth::Lib::executeMobileAdminPostAPI` paths when the
ZIA enrollment API returns an auth failure. Even when they don't
appear in the bundle, this module is the authoritative reference for
a user-reported code.

CROSS-SUITE NOTES:

  * Kerberos 491000/501000 (Occurrence 1) — "computer time is
    incorrect" / clock skew. This overlaps with ZPA 42016 (also
    120-second clock-skew threshold). When both surface in the same
    bundle, time sync at the endpoint is the common cause.
  * Identity Proxy hex range 0x1388..0x13D2 — these are ZIA's
    SAML-broker errors when ZIA itself is acting as the IdP proxy for
    a cloud app. Distinct from ZPA SAML auth (42000-series) and from
    ZCC SAML embedded-browser flows.

CATEGORY MAPPING (our derivation — not in the documentation):

  category        | severity_hint | rationale
  ----------------|---------------|------------------------------------
  generic         | warning       | misrouted traffic / cookie mismatch
  ldap_sync       | critical      | blocks user login until resolved
  kerberos        | critical      | blocks Kerberos auth until resolved
  identity_proxy  | warning       | mostly "retry" / transient flagged
                  | critical      | for "user not found" / "cloud app
                  |               | disabled" / "wrong password" /
                  |               | "IdP disabled" — actionable

Source URLs (Zscaler Help):
  https://help.zscaler.com/zia/internet-saas-authentication-error-codes
  https://help.zscaler.com/zia/internet-saas-error-codes-kerberos-authentication
"""

from __future__ import annotations

from typing import Dict, List, Optional

try:
    from typing import TypedDict
except ImportError:
    TypedDict = dict  # type: ignore


class ZiaAuthError(TypedDict, total=False):
    """One row from the ZIA Authentication Error Codes documentation.

    Fields:
      code                — string code as it appears in the documentation
                            ("211000", "100", "471000", "0x1388")
      category            — generic | ldap_sync | kerberos | identity_proxy
      occurrence          — sub-discriminator for codes with multiple
                            documented occurrences (e.g. 471000 has 5).
                            Empty string for codes with a single row.
      error_description   — documented from the documentation's "Description" column
      error_when          — documented from the documentation's "When It Occurs"
                            column. Empty string when the documentation does not
                            provide a When-It-Occurs column (Identity
                            Proxy table has only Description/What-to-Do).
      recommended_action  — documented from the documentation's "What to Do" column
      severity_hint       — critical | warning | info  (our derivation)
    """
    code: str
    category: str
    occurrence: str
    error_description: str
    error_when: str
    recommended_action: str
    severity_hint: str


# =====================================================================
# Generic Authentication Error Codes
# Generic authentication entries
# Category derivation: misrouted traffic / cookie mismatch — these are
# user-visible but recoverable. Warning, not critical.
# =====================================================================

_GENERIC: List[ZiaAuthError] = [
    {
        "code": "211000",
        "category": "generic",
        "occurrence": "",
        "error_description": "This error occurs when gateway redirected traffic is forwarded from a location where authentication is disabled.",
        "error_when": "",
        "recommended_action": "Check if your tenant configuration has the gateway redirected setting matching the actual traffic forwarding configuration.",
        "severity_hint": "warning",
    },
    {
        "code": "421000",
        "category": "generic",
        "occurrence": "",
        "error_description": "This error occurs when the organization's information extracted from the user cookie does not match the organization's DPPC port used for forwarding traffic.",
        "error_when": "",
        "recommended_action": "Clear the cookie and retry. If the error persists, contact Zscaler Support.",
        "severity_hint": "warning",
    },
]


# =====================================================================
# Active Directory & LDAP Synchronization Error Codes
# Active Directory and LDAP entries
# Category derivation: these block user login. Critical.
# Code 107 is absent from the documentation (likely deprecated).
# =====================================================================

_LDAP_SYNC: List[ZiaAuthError] = [
    {
        "code": "100",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The ldapsearch couldn't be done against the directory.",
        "error_when": "Invalid LDAP filter.",
        "recommended_action": "Check the LDAP search filter in the Zscaler Admin Console and ensure the syntax is correct. Verify if the same filter works with the ldapsearch.",
        "severity_hint": "critical",
    },
    {
        "code": "101",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "Incorrect password.",
        "error_when": "Incorrect login password.",
        "recommended_action": "Correct the password.",
        "severity_hint": "critical",
    },
    {
        "code": "102",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The LDAP connection closed.",
        "error_when": "The server closed the connection unexpectedly.",
        "recommended_action": "Retry. This should only be a transient error.",
        "severity_hint": "warning",
    },
    {
        "code": "103",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The user wasn't found on the LDAP servers (search failed).",
        "error_when": "The ldapsearch for the user failed. The search can be done using \"email\" or \"username\" based on advanced search status.",
        "recommended_action": "Check if a manual ldapsearch returns the user with the same query as the one configured in the Zscaler Admin Console.",
        "severity_hint": "critical",
    },
    {
        "code": "104",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The user's DN couldn't be found.",
        "error_when": "The user's DN couldn't be read due to LDAP library issues.",
        "recommended_action": "Consult your LDAP admin.",
        "severity_hint": "critical",
    },
    {
        "code": "105",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "Error performing a BIND with the user's credentials.",
        "error_when": "The DN might be invalid.",
        "recommended_action": "Check if a manual BIND works with the same user credentials.",
        "severity_hint": "critical",
    },
    {
        "code": "106",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "Internal error.",
        "error_when": "A deleted user tried to log in.",
        "recommended_action": "Check if the user is in the list of synchronized users. Synchronize the users.",
        "severity_hint": "critical",
    },
    {
        "code": "108",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The LDAP context wasn't found.",
        "error_when": "A user in a second directory tried to log in when there was no secondary LDAP configuration.",
        "recommended_action": "Zscaler must \"unset\" flags in the DB for secondary users or do a sync-preview sync once for your organization.",
        "severity_hint": "critical",
    },
    {
        "code": "109",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The synchronization is in progress. Users are not allowed to log in.",
        "error_when": "A user tried to log in during the synchronization.",
        "recommended_action": "Wait until the synchronization is completed.",
        "severity_hint": "warning",
    },
    {
        "code": "110",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The LDAP bind failed.",
        "error_when": "The admin's LDAP bind password might be wrong.",
        "recommended_action": "Check the password.",
        "severity_hint": "critical",
    },
    {
        "code": "111",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "Internal error.",
        "error_when": "Internal error.",
        "recommended_action": "Retry or contact Zscaler Support.",
        "severity_hint": "critical",
    },
    {
        "code": "112",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The advanced search query couldn't be sent.",
        "error_when": "Your organization is using an advanced search query for logins, and there's a problem with the advanced search filter used.",
        "recommended_action": "Check the advanced search filter. Ensure that ldapsearch returns users with the same filter.",
        "severity_hint": "critical",
    },
    {
        "code": "113",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "The user wasn't found in the list of synchronized users.",
        "error_when": "The user is not in the list of synchronized users.",
        "recommended_action": "Synchronize the user data and retry.",
        "severity_hint": "critical",
    },
    {
        "code": "114",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "Login failed. The connection to the directory server was reset.",
        "error_when": "The connection to the directory server was reset.",
        "recommended_action": "Retry.",
        "severity_hint": "warning",
    },
    {
        "code": "115",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "Login failed. The configuration changed.",
        "error_when": "An admin activated new configuration settings in the Zscaler Admin Console.",
        "recommended_action": "Retry.",
        "severity_hint": "warning",
    },
    {
        "code": "116",
        "category": "ldap_sync",
        "occurrence": "",
        "error_description": "Login failed. The user was deleted.",
        "error_when": "A deleted user tried to log in.",
        "recommended_action": "Check if the user is in the list of synchronized users. Synchronize the user data and retry.",
        "severity_hint": "critical",
    },
]


# =====================================================================
# Kerberos Authentication Error Codes
# External references: ZIA authentication plus the focused Kerberos reference (consistency-
# checked, identical content)
# Category derivation: blocks Kerberos auth. Critical.
#
# Notes on multi-row codes:
#   - 441000 and 461000 share one documentation row ("The user cannot be found")
#     -> emitted as two rows with identical description / when / action
#   - 471000 has FIVE occurrences (PAC file / GPO / AES / realm trust /
#     DC connectivity) -> five rows
#   - 491000 / 501000 each have TWO occurrences (clock skew / other) and
#     share rows in the documentation -> two rows per code (4 rows total)
#
# Cross-suite: 491000/501000 Occurrence 1 = clock skew; mirrors ZPA
# 42016 (120s threshold). [[zcc_zpa_event_taxonomy]]
# =====================================================================

_KERBEROS: List[ZiaAuthError] = [
    {
        "code": "391000",
        "category": "kerberos",
        "occurrence": "",
        "error_description": "The page cannot load.",
        "error_when": "Generic error code.",
        "recommended_action": "Contact Zscaler Support.",
        "severity_hint": "critical",
    },
    {
        "code": "441000",
        "category": "kerberos",
        "occurrence": "",
        "error_description": "The user cannot be found.",
        "error_when": "The user was deleted or cannot be found in the registered domain.",
        "recommended_action": "Add the user.",
        "severity_hint": "critical",
    },
    {
        "code": "461000",
        "category": "kerberos",
        "occurrence": "",
        "error_description": "The user cannot be found.",
        "error_when": "The user was deleted or cannot be found in the registered domain.",
        "recommended_action": "Add the user.",
        "severity_hint": "critical",
    },
    {
        "code": "451000",
        "category": "kerberos",
        "occurrence": "",
        "error_description": "The domain does not exist.",
        "error_when": "The realm is not a registered domain on the Zscaler service.",
        "recommended_action": "Contact Zscaler Support to add the realm as a registered domain.",
        "severity_hint": "critical",
    },
    {
        "code": "471000",
        "category": "kerberos",
        "occurrence": "Occurrence 1",
        "error_description": "The proxy authorization header does not contain the encoded Kerberos ticket. In almost all cases, this means that NTLM was used.",
        "error_when": "The traffic was sent to the Public Service Edge for Internet & SaaS (ZIA) IP address. The default Zscaler PAC file was used instead of the Kerberos PAC file. Symptoms: klist does not show either the Public Service Edge or KDC tickets.",
        "recommended_action": "Change the PAC file. Ensure that you use the Kerberos PAC file.",
        "severity_hint": "critical",
    },
    {
        "code": "471000",
        "category": "kerberos",
        "occurrence": "Occurrence 2",
        "error_description": "The proxy authorization header does not contain the encoded Kerberos ticket.",
        "error_when": "The user's computer does not have the GPO updates, the GPO updates are not on the domain controller, or the user is not logged in to the domain. Symptoms: A traffic capture from the user's computer does not show any query to the domain controller for the Zscaler ticket.",
        "recommended_action": "Verify the registry settings to ensure the user's computer has the Zscaler Kerberos settings. If they are not on the computer, verify that the domain controller has the GPO configurations. Verify that the user is logged in to the domain.",
        "severity_hint": "critical",
    },
    {
        "code": "471000",
        "category": "kerberos",
        "occurrence": "Occurrence 3",
        "error_description": "The proxy authorization header does not contain the encoded Kerberos ticket.",
        "error_when": "AES encryption is not enabled in the realm trust on the domain controller. Symptoms: klist does not show either the Public Service Edge or KDC tickets. A traffic capture shows the domain controller returning ETYPE_NOSUPP errors.",
        "recommended_action": "Modify the realm trust relationship and ensure that the AES encryption option is selected.",
        "severity_hint": "critical",
    },
    {
        "code": "471000",
        "category": "kerberos",
        "occurrence": "Occurrence 4",
        "error_description": "The proxy authorization header does not contain the encoded Kerberos ticket.",
        "error_when": "The realm trust relationship is not configured on the domain controller or the realm trust was configured with an incorrect password. Symptoms: klist does not show the Zscaler KDC or Public Service Edge tickets. A traffic capture shows the domain controller returning PRINCIPAL_UNKNOWN error.",
        "recommended_action": "Verify the realm trust configuration. Ensure that the realm name is in upper case and that the Zscaler cloud name is correct. If they are both correct, then the passwords in the organization's realm and the Zscaler realm might not match. Log in to the Zscaler Admin Console, regenerate the trust password, and copy it. On the domain controller, delete the trust configuration and create a new one as described in Kerberos Trust Relationship Configuration Guide for Windows Server and GPO Push. Ensure that you use the newly generated password that you copied from the Zscaler Admin Console.",
        "severity_hint": "critical",
    },
    {
        "code": "471000",
        "category": "kerberos",
        "occurrence": "Occurrence 5",
        "error_description": "The proxy authorization header does not contain the encoded Kerberos ticket.",
        "error_when": "The user's computer cannot connect to the domain controller. Symptoms: When you run klist purge to clear the tickets, refresh the browser, and then run klist again, Kerberos tickets are not displayed, including those of the domain controller.",
        "recommended_action": "Verify that the computer can contact the domain controller. If the user is using DirectAccess, run netsh name show effectivepolicy to determine if the DirectAccess client considers the workstation as being in the intranet or outside.",
        "severity_hint": "critical",
    },
    {
        "code": "48100",
        "category": "kerberos",
        "occurrence": "",
        "error_description": "Invalid encoding of Kerberos credentials.",
        "error_when": "Possible header corruption. Ensure that there is no intermediate proxy or L7 device that might be corrupting the header.",
        "recommended_action": "Contact Zscaler Support.",
        "severity_hint": "critical",
    },
    {
        "code": "491000",
        "category": "kerberos",
        "occurrence": "Occurrence 1",
        "error_description": "Invalid Kerberos token or username.",
        "error_when": "The computer time is incorrect.",
        "recommended_action": "Kerberos is very sensitive to clocks being in sync. Ensure that computer time is correct and it synchronizes with an NTP server.",
        "severity_hint": "critical",
    },
    {
        "code": "491000",
        "category": "kerberos",
        "occurrence": "Occurrence 2",
        "error_description": "Invalid Kerberos token or username.",
        "error_when": "Other issues.",
        "recommended_action": "Contact Zscaler Support.",
        "severity_hint": "critical",
    },
    {
        "code": "501000",
        "category": "kerberos",
        "occurrence": "Occurrence 1",
        "error_description": "Invalid Kerberos token or username.",
        "error_when": "The computer time is incorrect.",
        "recommended_action": "Kerberos is very sensitive to clocks being in sync. Ensure that computer time is correct and it synchronizes with an NTP server.",
        "severity_hint": "critical",
    },
    {
        "code": "501000",
        "category": "kerberos",
        "occurrence": "Occurrence 2",
        "error_description": "Invalid Kerberos token or username.",
        "error_when": "Other issues.",
        "recommended_action": "Contact Zscaler Support.",
        "severity_hint": "critical",
    },
    {
        "code": "510000",
        "category": "kerberos",
        "occurrence": "",
        "error_description": "The user name is too long.",
        "error_when": "The user's login name exceeds the maximum allowed characters.",
        "recommended_action": "Contact Zscaler Support.",
        "severity_hint": "critical",
    },
]


# =====================================================================
# Identity Proxy Error Codes (when ZIA acts as IdP for cloud apps)
# Identity Proxy entries
# 70 hex codes in the range 0x1388..0x13D2 with documented gaps at
# 0x1397, 0x13A2, 0x13A7, 0x13A8, 0x13BB.
#
# Severity derivation:
#   * "user wasn't found" / "cloud app disabled" / "IdP disabled" /
#     "wrong password" / "user must log out" -> critical (actionable)
#   * "transient cloud issue" / "retry" / "SAML decode" -> warning
#     (Zscaler-side or recoverable)
# =====================================================================

_RETRY_ACTION = (
    "Retry after a few seconds. If the error persists, contact Zscaler Support."
)


def _ip(code: str, desc: str, action: str = _RETRY_ACTION, severity: str = "warning") -> ZiaAuthError:
    """Build an Identity Proxy row. Reduces 70-row boilerplate; the
    Identity Proxy documentation has no When-It-Occurs column."""
    return {
        "code": code,
        "category": "identity_proxy",
        "occurrence": "",
        "error_description": desc,
        "error_when": "",
        "recommended_action": action,
        "severity_hint": severity,
    }


_IDENTITY_PROXY: List[ZiaAuthError] = [
    _ip("0x1388", "The organization wasn't found.",
        "The organization is invalid or might have been deleted.", "critical"),
    _ip("0x1389", "Identity Proxy is disabled for the cloud app.",
        "Enable Zscaler as the IdP proxy for the cloud app.", "critical"),
    _ip("0x138A", "A transient cloud issue."),
    _ip("0x138B", "An invalid SAML request was received."),
    _ip("0x138C", "A transient cloud issue."),
    _ip("0x138D", "A transient cloud issue."),
    _ip("0x138E", "A transient cloud issue."),
    _ip("0x138F", "A transient cloud issue."),
    _ip("0x1390", "A transient cloud issue."),
    _ip("0x1391", "A transient cloud issue."),
    _ip("0x1392", "A transient cloud issue."),
    _ip("0x1393", "A transient cloud issue."),
    _ip("0x1394", "A transient cloud issue."),
    _ip("0x1395", "A transient cloud issue."),
    _ip("0x1396", "No ID was found in the SAML request."),
    # 0x1397 — absent from documentation
    _ip("0x1398", "An invalid user, cookie, or session."),
    _ip("0x1399", "An invalid user, cookie, or session."),
    _ip("0x139A", "An invalid user, cookie, or session."),
    _ip("0x139B", "The timestamp in the SAML request is invalid."),
    _ip("0x139C", "The version in the SAML request is invalid."),
    _ip("0x139D", "The SAML request is outdated."),
    _ip("0x139E", "A transient cloud issue."),
    _ip("0x139F", "A transient cloud issue."),
    _ip("0x13A0", "A transient cloud issue."),
    _ip("0x13A1", "A transient cloud issue."),
    # 0x13A2 — absent from documentation
    _ip("0x13A3", "A transient cloud issue."),
    _ip("0x13A4", "The cloud app in the SAML request isn't supported."),
    _ip("0x13A5", "The SAML request came from an unknown Public Service Edge for Internet & SaaS."),
    _ip("0x13A6", "The SAML endpoint is invalid."),
    # 0x13A7, 0x13A8 — absent from documentation
    _ip("0x13A9", "No SAML request was found in the payload."),
    _ip("0x13AA", "No SAML request was found in the payload."),
    _ip("0x13AB", "The SAML request failed to decode."),
    _ip("0x13AC", "The SAML request failed to decode."),
    _ip("0x13AD", "The SAML request path is too long."),
    _ip("0x13AE", "The SAML request was sent to the wrong cloud."),
    _ip("0x13AF", "The user wasn't found.",
        "The user might have been deleted. Re-add the user.", "critical"),
    _ip("0x13B0", "The user wasn't found.",
        "The user might have been deleted. Re-add the user.", "critical"),
    _ip("0x13B1", "The user wasn't found.",
        "The user might have been deleted. Re-add the user.", "critical"),
    _ip("0x13B2", "The user wasn't found.",
        "The user might have been deleted. Re-add the user.", "critical"),
    _ip("0x13B3", "The user wasn't found.",
        "The user might have been deleted. Re-add the user.", "critical"),
    _ip("0x13B4", "The domain in the SAML request is invalid. The Zscaler service was unable to perform user transformation."),
    _ip("0x13B5", "The domain in the SAML request is invalid. The Zscaler service was unable to perform user transformation."),
    _ip("0x13B6", "An internal error occurred."),
    _ip("0x13B7", "The cloud app is disabled.",
        "Enable the cloud app for your organization.", "critical"),
    _ip("0x13B8", "The cloud app configuration was modified during the authentication process."),
    _ip("0x13B9", "An internal error occurred."),
    _ip("0x13BA", "An internal error occurred."),
    # 0x13BB — absent from documentation
    _ip("0x13BC", "The user wasn't found.",
        "The user might have been deleted. Re-add the user.", "critical"),
    _ip("0x13BD", "The SAML request took too long to complete."),
    _ip("0x13BE", "A transient cloud issue."),
    _ip("0x13BF", "A transient cloud issue."),
    _ip("0x13C0", "A transient cloud issue."),
    _ip("0x13C1", "The user is stored in the Zscaler Hosted User Database and entered the wrong password.",
        "Check if the user is entering the correct password.", "critical"),
    _ip("0x13C2", "The user is synchronized with Zscaler Authentication Bridge (ZAB). The Zscaler service was unable to connect to the ZAB."),
    _ip("0x13C3", "The user is synchronized with ZAB. The Zscaler service was unable to connect to the ZAB."),
    _ip("0x13C4", "The user is synchronized with ZAB and entered the wrong password."),
    _ip("0x13C5", "An internal error occurred."),
    _ip("0x13C6", "The user might be authenticated with another organization that doesn't have an identity proxy configured.",
        "The user must log out from their existing Zscaler account and log in using the account with the identity proxy configured.", "critical"),
    _ip("0x13C7", "There is no key to sign the SAML response."),
    _ip("0x13C8", "Wrong binding method. The Zscaler service didn't receive a POST request."),
    _ip("0x13C9", "The organization was deleted during the authentication process."),
    _ip("0x13CA", "The IdP is disabled during the authentication process.",
        "Enable the IdP for your organization.", "critical"),
    _ip("0x13CB", "An invalid cookie."),
    _ip("0x13CC", "The cloud app configuration was disabled or deleted during the authentication process."),
    _ip("0x13CD", "The cloud app configuration was disabled or deleted during the authentication process."),
    _ip("0x13CE", "The SAML request is outdated."),
    _ip("0x13CF", "The SAML request is outdated."),
    _ip("0x13D0", "The user wasn't found.",
        "The user might have been deleted. Re-add the user.", "critical"),
    _ip("0x13D1", "The SAML request is outdated."),
    _ip("0x13D2", "An internal error occurred."),
]


# =====================================================================
# Aggregated exports
# =====================================================================

ERRORS: List[ZiaAuthError] = _GENERIC + _LDAP_SYNC + _KERBEROS + _IDENTITY_PROXY

# Code -> first row (chip-display path).
# Identity Proxy codes are stored in their canonical lower-case-x form
# ("0x1388") AND additionally indexed under their upper-case-X variant
# ("0X1388") and bare-hex variant ("1388") for tolerant lookups —
# Zscaler logs and customer reports vary in casing.
ERRORS_BY_CODE: Dict[str, ZiaAuthError] = {}
ERRORS_BY_CODE_ALL: Dict[str, List[ZiaAuthError]] = {}

for _row in ERRORS:
    _c = _row["code"]
    ERRORS_BY_CODE_ALL.setdefault(_c, []).append(_row)
    if _c not in ERRORS_BY_CODE:
        ERRORS_BY_CODE[_c] = _row

# Tolerant-lookup aliases for the hex codes.
for _row in _IDENTITY_PROXY:
    _c = _row["code"]
    if _c.startswith("0x"):
        _upper = "0X" + _c[2:].upper()
        _bare = _c[2:].upper()
        ERRORS_BY_CODE.setdefault(_upper, _row)
        ERRORS_BY_CODE.setdefault(_bare, _row)
        ERRORS_BY_CODE_ALL.setdefault(_upper, [_row])
        ERRORS_BY_CODE_ALL.setdefault(_bare, [_row])
        # Also lowercase-hex bare variant ("13a4" as well as "13A4")
        ERRORS_BY_CODE.setdefault(_c[2:].lower(), _row)
        ERRORS_BY_CODE_ALL.setdefault(_c[2:].lower(), [_row])


def get_zia_auth_error(code: str) -> Optional[ZiaAuthError]:
    """Return the first ZIA auth error row for ``code``, or None.

    For Kerberos codes with multiple documented occurrences (471000,
    491000, 501000), returns the first occurrence. Use
    ``get_zia_auth_error_all()`` to retrieve every occurrence.

    Tolerant of common code variants:
      - "471000" / 471000 -> same row
      - "0x1388" / "0X1388" / "1388" / "13A4" -> same row
    """
    if code is None:
        return None
    key = str(code).strip()
    if key in ERRORS_BY_CODE:
        return ERRORS_BY_CODE[key]
    # Try a few canonicalizations.
    if key.lower().startswith("0x"):
        norm = "0x" + key[2:].upper().replace("X", "")
        if norm in ERRORS_BY_CODE:
            return ERRORS_BY_CODE[norm]
    return None


def get_zia_auth_error_all(code: str) -> List[ZiaAuthError]:
    """Return every row for ``code`` (multi-occurrence codes get a list
    of length > 1). Empty list if unknown."""
    if code is None:
        return []
    key = str(code).strip()
    return list(ERRORS_BY_CODE_ALL.get(key, ()))


def zia_auth_error_severity(code: str, default: str = "warning") -> str:
    """Return the derived severity hint for a ZIA auth error code."""
    row = get_zia_auth_error(code)
    if row is None:
        return default
    return row.get("severity_hint", default)


def zia_auth_error_category(code: str) -> Optional[str]:
    """Return the category (generic | ldap_sync | kerberos |
    identity_proxy) for ``code``, or None if unknown."""
    row = get_zia_auth_error(code)
    if row is None:
        return None
    return row.get("category")


# =====================================================================
# Self-check: assert documentation expected counts at import time. Fast (~1ms),
# catches accidental row drops during edits.
# =====================================================================

assert len(_GENERIC) == 2, f"Generic count drifted: {len(_GENERIC)}"
assert len(_LDAP_SYNC) == 16, f"LDAP sync count drifted: {len(_LDAP_SYNC)}"
assert len(_KERBEROS) == 15, f"Kerberos row count drifted: {len(_KERBEROS)}"
assert len(_IDENTITY_PROXY) == 70, f"Identity Proxy count drifted: {len(_IDENTITY_PROXY)}"
assert len(ERRORS) == 103, f"Total row count drifted: {len(ERRORS)}"
