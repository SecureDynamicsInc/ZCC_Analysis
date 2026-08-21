"""
ZPA Authentication Errors — authoritative reference data.

Normalized from the Zscaler documentation "Zscaler Client Connector: Private
Access Authentication Errors".

The documentation lists ~50 enrollment error codes a user might see in ZCC during
Private Access registration:

  * Code 2008  — the lone 4-digit oddball
  * Codes 42000..42010 (gaps) — initial errors, user input, internal
  * Codes 42013..42022 — SAML validation
  * Codes 42023..42026 — certificate issues
  * Codes 42027..42031 — subscription / org info
  * Codes 42032..42045 — IdP / SP configuration
  * Codes 42046..42048 — IdP / SAML signing certificate expiry

We bucket each into one of five SOP groups so the existing detector's
group-based SOP rendering keeps working:

  user_input       — username typed wrong / missing domain / domain mismatch
  tenant_config    — IdP or SP misconfigured at the tenant level
  saml_validation  — SAML response validation failed (signature, time, format)
  certificate      — CA cert / signing cert / private key problem
  internal         — capacity / object store / catch-all internal

Source URL: https://help.zscaler.com/zscaler-client-connector/zscaler-client-connector-zpa-authentication-errors
"""

from __future__ import annotations

from typing import Dict, List

from . import AuthError


# =====================================================================
# Auth error rows (50 codes — 2008 + 42000..42048)
# =====================================================================

ERRORS: List[AuthError] = [

    # -------- The oddball 4-digit code --------
    {
        "code": "2008",
        "error_message": "Authentication failed due to an invalid redirection URL. Please try again.",
        "error_description": "This error occurs when a user delays Private Access authentication.",
        "resolution": "Authenticate again. If the error persists, contact Zscaler Support.",
        "group": "user_input",
        "severity_hint": "critical",
    },

    # -------- 42000-42010 — user input & early init --------
    {
        "code": "42000",
        "error_message": "Inconsistency in user credentials is detected. Log out of the client and retry.",
        "error_description": "When the user attempts to reauthenticate to Private Access, this error occurs if they enter a different username, or the IdP SAML response has a different NameID than was sent during initial enrollment.",
        "resolution": "Verify the user has entered the username used during initial enrollment. Verify the IdP SAML response NameID matches what was received during initial enrollment. Have the user log out and re-enroll if needed.",
        "group": "user_input",
        "severity_hint": "critical",
    },
    {
        "code": "42001",
        "error_message": "Internal Error: Contact Administrator",
        "error_description": "This error occurs when a user attempts to log in to Zscaler Client Connector without a domain name. Private Access cannot identify the user's organization.",
        "resolution": "Verify the user has entered a valid domain as part of the username (e.g. user@example.invalid).",
        "group": "user_input",
        "severity_hint": "critical",
    },
    {
        "code": "42002",
        "error_message": "Zscaler Private Access is not configured for your company.",
        "error_description": "Private Access is not configured correctly and is unable to identify the IdP that must be used for enrolling the user.",
        "resolution": "Verify that an IdP is configured for Private Access and that the IdP can communicate with Private Access.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42004",
        "error_message": "Internal Error: Contact Administrator",
        "error_description": "Zscaler Client Connector is not sending the expected information to Private Access during the user's enrollment process.",
        "resolution": "Verify that SSO for Private Access has been configured correctly.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42005",
        "error_message": "Internal Error: Contact Administrator",
        "error_description": "Private Access cannot correctly interpret the information sent by Zscaler Client Connector during the user's enrollment process.",
        "resolution": "Verify that SSO for Private Access has been configured correctly.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42006",
        "error_message": "Internal Error: Contact Administrator",
        "error_description": "SAML response validation fails. The failure could be due to system clock out of sync, an expired IdP certificate, SAML response signature validation failure, or IdP lookup by IdP entity ID issues.",
        "resolution": "Verify SSO for Private Access has been configured correctly.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },
    {
        "code": "42007",
        "error_message": "Internal Error: Contact Administrator",
        "error_description": "The certificate signing request in Private Access fails during the user enrollment process.",
        "resolution": "Verify that the signing certificate chosen for enrolling the user device to Private Access is valid.",
        "group": "certificate",
        "severity_hint": "critical",
    },
    {
        "code": "42010",
        "error_message": "Internal Error: Contact Administrator",
        "error_description": "Private Access does not receive the expected information during the user enrollment process.",
        "resolution": "This is an internal error. Contact Zscaler Support.",
        "group": "internal",
        "severity_hint": "critical",
    },

    # -------- 42013-42022 — SAML validation --------
    {
        "code": "42013",
        "error_message": "The message is not of the SAML response object type.",
        "error_description": "The IdP SAML response doesn't match the expected SAML response object type.",
        "resolution": "Update the IdP configuration to send the expected object type in the SAML response.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },
    {
        "code": "42014",
        "error_message": "The SAML response status is unsuccessful.",
        "error_description": "The status in the SAML response is unsuccessful.",
        "resolution": "Review the user's information in the IdP and have the user retry logging in.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },
    {
        "code": "42015",
        "error_message": "Failed to validate the SAML response signature.",
        "error_description": "The IdP certificates aren't configured correctly OR the public certificate used by Private Access to validate the SAML response from the IdP has expired.",
        "resolution": "Verify IdP certificates are configured correctly in Private Access. Check the expiration date and upload a valid certificate if expired.",
        "group": "certificate",
        "severity_hint": "critical",
    },
    {
        "code": "42016",
        "error_message": "The response issue time is either too old or with date in the future. IdP Issue Time: [Timestamp]s Accepted Range: [Timestamp]s to [Timestamp]s",
        "error_description": "The IdP and the Private Access authentication service clocks have a large skew. The maximum accepted skew time is 120 seconds.",
        "resolution": "Ensure the value for the response issue time is in the accepted range.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },
    {
        "code": "42017",
        "error_message": "The IdP originated SSO is not supported.",
        "error_description": "The IdP sends Private Access a SAML response without the Private Access authentication service initiating it.",
        "resolution": "Only the service provider (SP) initiated SSO is supported with Private Access.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42018",
        "error_message": "Failed to look up the SAML request corresponding to the SAML response received.",
        "error_description": "The Private Access authentication service failed to look up the SAML request corresponding to the SAML response from its database.",
        "resolution": "Contact Zscaler Support.",
        "group": "internal",
        "severity_hint": "critical",
    },
    {
        "code": "42019",
        "error_message": "The intended destination doesn't match any of the configured endpoints.",
        "error_description": "The assertion consumer endpoint of the Private Access authentication service isn't properly configured in the IdP.",
        "resolution": "Review the SP configuration in your IdP.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42020",
        "error_message": "Failed to validate the issuer in the SAML response.",
        "error_description": "The IdP entity ID isn't properly configured in the Zscaler Admin Console. The entity ID is case sensitive.",
        "resolution": "In the Zscaler Admin Console, review the entity ID of the IdP configuration.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42021",
        "error_message": "The assertion is too old / failed because of notBefore / failed because of notOnOrAfter condition.",
        "error_description": "The Private Access authentication service failed to validate the assertions in the SAML response. May fail due to timing issues, unsupported assertion conditions (e.g. OneTimeUse).",
        "resolution": "Ensure the value for the response issue time is in the valid range.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },
    {
        "code": "42022",
        "error_message": "Missing NameID in the SAML response.",
        "error_description": "The SAML response doesn't have NameID in it.",
        "resolution": "In the IdP configuration, ensure NameID is part of the subject in the SAML response message.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },

    # -------- 42023-42026 — certificate / signing key --------
    {
        "code": "42023",
        "error_message": "The CA certificate (signing certificate) for Zscaler Client Connector has expired.",
        "error_description": "The Central Authority (CA) certificate for Zscaler Client Connector has expired.",
        "resolution": "Provision a valid CA certificate for Zscaler Client Connector.",
        "group": "certificate",
        "severity_hint": "critical",
    },
    {
        "code": "42024",
        "error_message": "The CA certificate (signing certificate) for Zscaler Client Connector is missing.",
        "error_description": "The CA certificate for Zscaler Client Connector is missing.",
        "resolution": "Provision a valid CA certificate for Zscaler Client Connector.",
        "group": "certificate",
        "severity_hint": "critical",
    },
    {
        "code": "42025",
        "error_message": "The private key for the Zscaler Client Connector CA certificate (signing certificate) is missing.",
        "error_description": "The private key for the Zscaler Client Connector CA certificate is missing.",
        "resolution": "Provision a valid CA certificate for Zscaler Client Connector.",
        "group": "certificate",
        "severity_hint": "critical",
    },
    {
        "code": "42026",
        "error_message": "Unable to secure a valid certificate for this user.",
        "error_description": "Zscaler Client Connector fails to get a valid certificate.",
        "resolution": "Contact Zscaler Support.",
        "group": "certificate",
        "severity_hint": "critical",
    },

    # -------- 42027-42031 — subscription / org info --------
    {
        "code": "42027",
        "error_message": "Your organization has reached the limit for the maximum number of allowed users.",
        "error_description": "Your organization has provisioned more users than the number allowed by its subscription.",
        "resolution": "Verify that the existing Private Access subscription meets the needs of your organization.",
        "group": "internal",
        "severity_hint": "critical",
    },
    {
        "code": "42028",
        "error_message": "Unexpected or missing information when enrolling or unenrolling Zscaler Client Connector.",
        "error_description": "The Private Access authentication service receives a request from Zscaler Client Connector with missing or unexpected information.",
        "resolution": "Contact Zscaler Support.",
        "group": "internal",
        "severity_hint": "critical",
    },
    {
        "code": "42029",
        "error_message": "Unable to identify the user by domain from the provided username.",
        "error_description": "The user's username doesn't have a domain that is associated with the organization.",
        "resolution": "Contact Zscaler Support.",
        "group": "user_input",
        "severity_hint": "critical",
    },
    {
        "code": "42030",
        "error_message": "Unable to look up the user's organization information.",
        "error_description": "This error occurs due to missing information in the account associated with the Private Access service.",
        "resolution": "Contact Zscaler Support.",
        "group": "internal",
        "severity_hint": "critical",
    },
    {
        "code": "42031",
        "error_message": "Unable to authorize Zscaler Client Connector enrollment request.",
        "error_description": "Due to missing information in the account associated with the Private Access service.",
        "resolution": "Contact Zscaler Support.",
        "group": "internal",
        "severity_hint": "critical",
    },

    # -------- 42032-42040 — IdP & SP config --------
    {
        "code": "42032",
        "error_message": "The Private Access authentication service doesn't support the OneTimeUse condition in the SAML assertion.",
        "error_description": "The IdP issues a SAML assertion with the OneTimeUse condition.",
        "resolution": "Update the IdP configuration to not issue OneTimeUse SAML assertion.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },
    {
        "code": "42033",
        "error_message": "Private Access SP was not able to validate the SAML response.",
        "error_description": "The Private Access service cannot validate the SAML response for the Private Access admin.",
        "resolution": "Verify an IdP is configured for Private Access administrator SSO and that the IdP can communicate with Private Access.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42034",
        "error_message": "Private Access SP was not able to validate the SAML response.",
        "error_description": "The Private Access service cannot validate the SAML response for the Private Access user.",
        "resolution": "Verify an IdP is configured for Private Access user SSO and that the IdP can communicate with Private Access.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42035",
        "error_message": "User not authorized because of domain mismatch.",
        "error_description": "The user's username domain doesn't match any domains associated with the organization.",
        "resolution": "Contact Zscaler Support.",
        "group": "user_input",
        "severity_hint": "critical",
    },
    {
        "code": "42036",
        "error_message": "Unable to verify the IdP configuration for the IdP entity ID.",
        "error_description": "The Private Access service cannot verify the entity ID for the IdP configuration.",
        "resolution": "In the Zscaler Admin Console, review the entity ID of the IdP configuration.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42037",
        "error_message": "IdP is not enabled for admin SSO.",
        "error_description": "The IdP isn't enabled for the admin SSO.",
        "resolution": "Verify that SSO for Private Access is configured correctly for admin SSO.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42038",
        "error_message": "Failed to insert into Object Store.",
        "error_description": "This is an internal error.",
        "resolution": "Contact Zscaler Support.",
        "group": "internal",
        "severity_hint": "critical",
    },
    {
        "code": "42039",
        "error_message": "Unable to verify the SP configuration for this domain.",
        "error_description": "The Private Access service cannot verify the service provider (SP) configuration for the domain.",
        "resolution": "Verify that the SP for IdP has been configured correctly.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42040",
        "error_message": "Failed to encrypt.",
        "error_description": "This is an internal error.",
        "resolution": "Contact Zscaler Support.",
        "group": "internal",
        "severity_hint": "critical",
    },

    # -------- 42042-42044 — IdP enable / config --------
    {
        "code": "42042",
        "error_message": "Configured IdP is disabled for SSO.",
        "error_description": "IdP is disabled on Private Access.",
        "resolution": "Enable the IdP on Private Access UI.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42043",
        "error_message": "IdP configuration is incomplete.",
        "error_description": "The IdP is misconfigured.",
        "resolution": "Verify configuration.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },
    {
        "code": "42044",
        "error_message": "IdP configuration has mismatched SSO type/usage.",
        "error_description": "The SSO type and usage for the IdP configuration do not match.",
        "resolution": "Verify that SSO for Private Access is configured correctly.",
        "group": "tenant_config",
        "severity_hint": "critical",
    },

    # -------- 42045-42048 — SAML assertion / signing certs --------
    {
        "code": "42045",
        "error_message": "Zscaler Private Access: SAML Assertion input too large.",
        "error_description": "The IdP issues a SAML assertion that is larger than expected.",
        "resolution": "Contact Zscaler Support.",
        "group": "saml_validation",
        "severity_hint": "critical",
    },
    {
        "code": "42046",
        "error_message": "All the signing certificates associated with the IdP are expired.",
        "error_description": "When a user tries to log in to ZCC and the IdP's signing certificates in Private Access have expired.",
        "resolution": "Update the IdP configuration to upload a valid signing certificate from the IdP.",
        "group": "certificate",
        "severity_hint": "critical",
    },
    {
        "code": "42047",
        "error_message": "The SAML request signing certificate has expired.",
        "error_description": "The SAML request signing certificate configured in Zscaler Admin Console has expired.",
        "resolution": "Edit the IdP configuration to change the certificate.",
        "group": "certificate",
        "severity_hint": "critical",
    },
    {
        "code": "42048",
        "error_message": "The SAML request signing certificate is invalid.",
        "error_description": "The SAML request signing certificate configured in Zscaler Admin Console is not valid.",
        "resolution": "Edit the IdP configuration to change the certificate.",
        "group": "certificate",
        "severity_hint": "critical",
    },
]


# =====================================================================
# Lookup dictionaries
# =====================================================================

ERRORS_BY_CODE: Dict[str, AuthError] = {
    row["code"]: row for row in ERRORS
}


def errors_by_group(group: str) -> List[AuthError]:
    """Return all error rows in the given group ("user_input",
    "tenant_config", "saml_validation", "certificate", "internal")."""
    return [row for row in ERRORS if row.get("group") == group]
