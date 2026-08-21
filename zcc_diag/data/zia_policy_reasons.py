"""
ZIA Policy Reasons — authoritative reference data.

Normalized from the Zscaler documentation "Internet & SaaS (ZIA): Policy
Reasons".

These are the strings that ZIA emits in Insights and NSS reports to
explain *why* a transaction was blocked / allowed / cautioned. ~100
documented reasons across these ZIA features:

  - SSL/TLS                    (cert + handshake + version + record)
  - Core Proxy                 (domain fronting, HTTP tunneling)
  - Firewall Filtering         (DPI, NAT Control, internal-error paths)
  - Sandbox                    (file analysis, quarantine, isolate)
  - DLP                        (compliance, archive-to-mailbox)
  - URL Filtering              (denylist, time-of-day, category, browse)
  - Cloud App Control          (social, file share, webmail, streaming,
                                business / consumer / enterprise / IT)
  - File Type Control          (upload / download cautions + blocks)
  - Mobile Malware Protection  (per-app block reasons)
  - Tenancy Restriction        (Blocked - Tenant Restricted)
  - Web Insights Logs          (Blocked due to invalid server IP)
  - Advanced Threat Protection (IPS inbound/outbound, reputation, page risk)
  - Locations                  (Acceptable Use Policy)
  - Bandwidth Control          (size-quota blocks)
  - Browser Control            (browser-version, secure-browsing)
  - FTP Control                (FTP over HTTP toggles)
  - Malware Protection         (file malware + unscannable / encrypted)

IMPORTANT — WHERE THESE APPEAR:

These strings come from ZIA's cloud-side logs (Admin Console Insights
view, NSS feeds). They do NOT typically appear in ZCC tunnel logs we
capture in support bundles. So:

  - The detector layer can't match against them in a bundle
  - Bundle cross-reference in the Status Code Reference UI will
    typically show "not in bundle" for these
  - The VALUE is as a reference: when a customer mentions a policy
    reason in their report, the engineer can look it up directly

Three categories (our derivation, not in the documentation):

  policy_block — the rule blocked / denied the request (most rows).
                 "Working as designed" — the tenant's configured policy
                 is enforcing.
  info         — successful allow path; documented for completeness.
                 Includes "Allowed and archived to mailbox", etc.
  warning      — caution / quarantine / isolate / sandbox-held paths.
                 The user was warned, allowed, or held briefly.
  error        — ZIA-side system errors (Bypassed due to missing
                 config, Dropped due to internal error, Timed out
                 while waiting for a config). These signal that the
                 Service Edge had trouble talking to the CA.

Source URL: https://help.zscaler.com/zia/policy-reasons
"""

from __future__ import annotations

from typing import Dict, List

try:
    from typing import TypedDict
except ImportError:
    TypedDict = dict


class PolicyReason(TypedDict, total=False):
    name: str           # exact string from Insights/NSS report
    feature: str        # which ZIA subsystem (Firewall, SSL/TLS, etc.)
    description: str    # documented from documentation Description column
    category: str       # policy_block | info | warning | error
    severity_hint: str  # critical | warning | info


# =====================================================================
# Block / Deny / Restrict actions
# Category: policy_block (intentional service decision)
# Severity: critical when blocking access; warning when restrictive
# =====================================================================

_BLOCKS: List[PolicyReason] = [
    {"name": "Access denied due to bad server certificate", "feature": "SSL/TLS",
     "description": "Transaction to an SSL/TLS site was blocked due to server certificate validation failure or OCSP revocation check failure.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Access denied due to low TLS version", "feature": "SSL/TLS",
     "description": "Inspected or uninspected SSL/TLS traffic was blocked due to a minimum TLS version enforcement in Policy > SSL/TLS Inspection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Access denied due to Domain Fronting", "feature": "Core Proxy",
     "description": "Transaction indicating domain fronting due to FQDN mismatch between the request URL and host header, or between SNI and the inner host header.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Block Internet access", "feature": "Locations",
     "description": "Access to the internet (including non-HTTP traffic) was blocked because the user has not accepted the Acceptable Use Policy.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Blocked due to Rate-based HTTP/HTTP2 Command and Control traffic detection",
     "feature": "Advanced Threat Protection",
     "description": "Transaction blocked by IPS as rate-based botnet C2 traffic was detected in the response.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked Mobile App communicating with remote unknown servers",
     "feature": "Mobile Malware Protection",
     "description": "App communicates with unknown 3rd-party servers and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked Mobile App communicating to Ad websites",
     "feature": "Mobile Malware Protection",
     "description": "App communicates with ad sites and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Blocked Mobile App leaking Device Identifier information",
     "feature": "Mobile Malware Protection",
     "description": "App shares device information and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked Mobile App leaking Location information",
     "feature": "Mobile Malware Protection",
     "description": "App shares location information and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked Mobile App leaking user credentials insecurely",
     "feature": "Mobile Malware Protection",
     "description": "App transmits user credentials in clear text and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked Mobile App exhibiting malicious behavior",
     "feature": "Mobile Malware Protection",
     "description": "App is known malware and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked Mobile App leaking Personally Identifiable Information (PII)",
     "feature": "Mobile Malware Protection",
     "description": "App shares PII and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked Mobile App with known security vulnerabilities",
     "feature": "Mobile Malware Protection",
     "description": "App has known security vulnerabilities and was blocked by Mobile Malware Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked - Tenant Restricted", "feature": "Tenancy Restriction",
     "description": "Transaction blocked by a Tenant Restriction policy.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked by Default URL Filtering", "feature": "URL Filtering",
     "description": "Transaction blocked by the default URL Filtering policy.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Blocked due to Bad SSL/TLS record", "feature": "SSL/TLS",
     "description": "SSL/TLS connection blocked due to forwarding of non-SSL/TLS traffic to an HTTPS port.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Blocked due to invalid server IP", "feature": "Web Insights Logs",
     "description": "DNS server resolved an origin server as an invalid IP address.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Blocked due to Server Probe Failure", "feature": "SSL/TLS",
     "description": "Block Undecryptable Traffic enabled and Zscaler was unable to make a server-side TCP/TLS connection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Country block outbound request: not allowed to access sites in this country",
     "feature": "Advanced Threat Protection",
     "description": "Access request to a country was blocked due to an ATP Suspicious Countries policy.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Custom reputation block outbound request malicious URL",
     "feature": "Advanced Threat Protection",
     "description": "Destination is part of your Blocked Malicious URLs list.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "DNAT with redirect to FQDN failed", "feature": "Firewall Filtering",
     "description": "Transaction blocked due to an unreachable FQDN in a NAT Control rule.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Dropped due to failed client SSL/TLS handshake", "feature": "SSL/TLS",
     "description": "Transaction dropped due to a failure in client SSL/TLS handshake. See Client SSL/TLS Handshake Failure Reason for details.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "File Attachment not allowed", "feature": "Cloud App Control",
     "description": "An attempt to attach a file to an email on a webmail app was blocked by a Cloud App Control policy.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "FTP access is blocked by a firewall policy", "feature": "Firewall Filtering",
     "description": "Access to an FTP Network Service/Application was blocked by a Firewall Filtering rule.",
     "category": "policy_block", "severity_hint": "warning"},

    # IPS inbound responses (Advanced Threat Protection)
    {"name": "IPS block inbound response: adware/spyware traffic",
     "feature": "Advanced Threat Protection",
     "description": "Adware or spyware traffic detected in the response.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block inbound response: anonymization site",
     "feature": "Advanced Threat Protection",
     "description": "Access to anonymization sites was blocked in the response by IPS.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "IPS block inbound response: botnet command and control traffic",
     "feature": "Advanced Threat Protection",
     "description": "Botnet C2 traffic detected in the response.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block inbound response: malicious content",
     "feature": "Advanced Threat Protection",
     "description": "Malicious content detected in the response.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block inbound response: page contains known browser exploits",
     "feature": "Advanced Threat Protection",
     "description": "Known browser exploits detected; access blocked.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block inbound response: page contains known dangerous ActiveX controls",
     "feature": "Advanced Threat Protection",
     "description": "Known dangerous ActiveX controls detected.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block inbound response: phishing content",
     "feature": "Advanced Threat Protection",
     "description": "Potential phishing content detected.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block inbound response: webspam traffic",
     "feature": "Advanced Threat Protection",
     "description": "Web spam traffic detected.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "IPS block inbound response. IRC use/tunneling",
     "feature": "Advanced Threat Protection",
     "description": "IRC use or tunneling detected.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "IPS block inbound: file contains known vulnerabilities.",
     "feature": "Advanced Threat Protection",
     "description": "Download attempt blocked because the file has known vulnerabilities.",
     "category": "policy_block", "severity_hint": "critical"},

    # IPS outbound responses
    {"name": "IPS block outbound request: adware/spyware traffic",
     "feature": "Advanced Threat Protection",
     "description": "Adware or spyware traffic detected in the request.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block outbound request: botnet command and control traffic",
     "feature": "Advanced Threat Protection",
     "description": "Botnet C2 traffic detected in the request.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block outbound request: browser cookie theft",
     "feature": "Advanced Threat Protection",
     "description": "Request blocked because the site was detected to potentially steal browser cookies.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block outbound request: cross-site scripting (XSS) attack",
     "feature": "Advanced Threat Protection",
     "description": "Site detected to be vulnerable to XSS attacks; request blocked.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block outbound request: IRC use/tunneling",
     "feature": "Advanced Threat Protection",
     "description": "IRC use or tunneling detected in the request.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "IPS block outbound request: page contains known browser exploits",
     "feature": "Advanced Threat Protection",
     "description": "Known browser exploits detected.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block: Cryptomining traffic",
     "feature": "Advanced Threat Protection",
     "description": "Cryptomining traffic detected.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "IPS block: SSH use/tunneling",
     "feature": "Advanced Threat Protection",
     "description": "SSH use or tunneling detected.",
     "category": "policy_block", "severity_hint": "warning"},

    # Malware Protection blocks
    {"name": "Malware block: malicious file", "feature": "Malware Protection",
     "description": "Download attempt of malicious content/files was blocked by inline antivirus signature match.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Not allowed to upload/download encrypted or password-protected archive files",
     "feature": "Malware Protection",
     "description": "File blocked because it was encrypted or password-protected and the Password-Protected Archive Files block was enabled.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to upload/download unscannable file formats",
     "feature": "Malware Protection",
     "description": "File format is not supported by Zscaler and the policy to block Unscannable Files was enabled.",
     "category": "policy_block", "severity_hint": "warning"},

    # URL Filtering / Categories
    {"name": "Not allowed because URL is placed on the denylist", "feature": "URL Filtering",
     "description": "URL was placed on the denylist by a URL Filtering policy.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to browse this category", "feature": "URL Filtering",
     "description": "URL Filtering policy with a Block action triggered.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed during this time of day",
     "feature": "Cloud App Control / File Type Control / URL Filtering",
     "description": "Transaction blocked by a policy restricting access based on time of day.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Request method not allowed for this category", "feature": "URL Filtering",
     "description": "URL Filtering policy blocks the POST method.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Time quota exceeded daily limit",
     "feature": "Cloud App Control / URL Filtering",
     "description": "Transaction blocked due to a time quota.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Volume quota exceeded daily limit",
     "feature": "Cloud App Control / URL Filtering",
     "description": "Transaction blocked due to a volume quota.",
     "category": "policy_block", "severity_hint": "warning"},

    # Cloud App Control blocks
    {"name": "Not allowed the use of this business site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts access to business cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this Consumer site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts Consumer cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this enterprise site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts enterprise cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this Hosting Providers site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts hosting cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this IT Services site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts IT services cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this Mobile App Store", "feature": "Mobile App Store Control",
     "description": "Access to the mobile app store was denied by Mobile App Store Control policy.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this sales and marketing site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts Marketing cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this site with personal credentials", "feature": "Cloud App Control",
     "description": "Blocked due to Google Apps / Microsoft Login Services tenant restrictions.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Not allowed the use of this Social Network/Blogging site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts Social Networking cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed the use of this system and development site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts System and Development cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to access this file type", "feature": "File Type Control",
     "description": "File blocked due to a File Type Control policy.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to access to FTP sites", "feature": "FTP Control",
     "description": "Blocked because the user does not have Allow FTP over HTTP enabled.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to browse this P2P site", "feature": "Advanced Threat Protection",
     "description": "Access to a known peer-to-peer site was blocked.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to browse with unknown user agent", "feature": "Advanced Threat Protection",
     "description": "Unknown user agent detected; transaction blocked.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to establish SSL/TLS connection due to policy", "feature": "SSL/TLS",
     "description": "Traffic blocked due to an SSL/TLS inspection policy with a Block action.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to post message to this site", "feature": "Cloud App Control",
     "description": "An attempt to post content to a Social Networking app was blocked.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to send webmail", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts sending emails from webmail cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to upload files to this site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricts uploading to File Sharing cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to upload/download files of size greater than configured limit",
     "feature": "Bandwidth Control",
     "description": "User attempted to upload/download a file larger than the configured limit.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to upload/download files of this type", "feature": "File Type Control",
     "description": "Attempt to upload/download a file blocked by File Type Control.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to upload/download media files of this type", "feature": "Cloud App Control",
     "description": "Cloud App Control restricts Streaming Media / File Sharing cloud apps for this transaction.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use Adware/Spyware sites", "feature": "Advanced Threat Protection",
     "description": "Access to a known adware/spyware site was denied based on reputation.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Not allowed to use FTP over HTTP for upload", "feature": "FTP Control",
     "description": "Upload blocked because user does not have Allow FTP over HTTP enabled.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use HTTP tunnel", "feature": "Core Proxy",
     "description": "HTTP tunneling on a non-HTTP port detected; org has Block tunneling to non-HTTP/HTTPS ports enabled.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Not allowed to use mobile app", "feature": "Mobile Malware Protection",
     "description": "Mobile app blocked due to Mobile Malware Protection settings.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use this browser", "feature": "Browser Control",
     "description": "Transaction generated by a browser not allowed by Browser Blocking.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use this File Share site", "feature": "Cloud App Control",
     "description": "Cloud App Control restricts File Sharing cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use this IM site", "feature": "Cloud App Control",
     "description": "Cloud App Control restricts instant messaging cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use this Streaming/Media site", "feature": "Cloud App Control",
     "description": "Cloud App Control restricts streaming media cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use this Webmail site", "feature": "Cloud App Control",
     "description": "Cloud App Control restricts webmail cloud apps.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Not allowed to use tunnels", "feature": "Advanced Threat Protection",
     "description": "ATP policy restricts SSH tunneling.",
     "category": "policy_block", "severity_hint": "warning"},

    # PageRisk + Reputation + Sandbox + Misc blocks
    {"name": "PageRisk block inbound response: page is unsafe",
     "feature": "Advanced Threat Protection",
     "description": "Page content score exceeded the Page Risk threshold set by ATP Suspicious Content Protection.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Reputation block outbound request malicious URL",
     "feature": "Advanced Threat Protection",
     "description": "Destination is known to serve malware.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Reputation block outbound request: anonymization site",
     "feature": "Advanced Threat Protection",
     "description": "Destination reputation is anonymizer.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Reputation block outbound request: botnet site",
     "feature": "Advanced Threat Protection",
     "description": "Request to a known C2 server.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Reputation block outbound request: phishing site",
     "feature": "Advanced Threat Protection",
     "description": "Request to a known phishing site.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Reputation block outbound request: webspam",
     "feature": "Advanced Threat Protection",
     "description": "Web spam traffic detected in the response.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Sandbox block inbound response: malicious file", "feature": "Sandbox",
     "description": "File was found to be malicious.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Secure Browsing blocked an outdated/disallowed component",
     "feature": "Browser Control",
     "description": "Outdated component blocked by Browser Vulnerability Protection.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Undecryptable Traffic Block", "feature": "Cloud App Control",
     "description": "Traffic from apps using non-standard encryption blocked (Block Undecryptable Traffic enabled).",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Unenrolled user is not allowed to establish SSL/TLS connection", "feature": "SSL/TLS",
     "description": "SSL/TLS connection of an unenrolled user blocked. Use a non-SSL/TLS URL to enroll.",
     "category": "policy_block", "severity_hint": "warning"},
    {"name": "Violates Compliance Category", "feature": "DLP",
     "description": "DLP policy violation; transaction blocked.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Violates Compliance Category, archive to mailbox", "feature": "DLP",
     "description": "DLP policy violation; transaction blocked + email sent to auditor's mailbox.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Violates Compliance Category, archive to mailbox failed", "feature": "DLP",
     "description": "DLP policy violation; transaction blocked but auditor email failed to send.",
     "category": "policy_block", "severity_hint": "critical"},
    {"name": "Web application is blocked by Firewall rule", "feature": "Firewall Filtering",
     "description": "Network Application blocked because it is part of a Firewall Filtering rule.",
     "category": "policy_block", "severity_hint": "warning"},
]


# =====================================================================
# Allow actions — successful processing path
# Category: info (no action required)
# =====================================================================

_ALLOWS: List[PolicyReason] = [
    {"name": "Allowed", "feature": "N/A",
     "description": "The transaction was allowed.",
     "category": "info", "severity_hint": "info"},
    {"name": "Allowed - No Active Content", "feature": "Sandbox",
     "description": "File allowed for download; benign with no active content per inline Sandbox static analysis.",
     "category": "info", "severity_hint": "info"},
    {"name": "Allowed and archived to mailbox", "feature": "DLP",
     "description": "DLP policy rule violated but allowed; email sent to auditor's mailbox.",
     "category": "info", "severity_hint": "warning"},
    {"name": "Allowed and archived to mailbox failed", "feature": "DLP",
     "description": "DLP policy rule violated but allowed; auditor email failed to send.",
     "category": "info", "severity_hint": "warning"},
    {"name": "Allowed and No Scan", "feature": "Sandbox",
     "description": "File allowed because Sandbox policy First Time Action was Allow and Do Not Scan.",
     "category": "info", "severity_hint": "info"},
    {"name": "Allow due to insufficient app data", "feature": "Firewall Filtering",
     "description": "DPI was trying to determine the network application but the session terminated unexpectedly before any policy could match.",
     "category": "info", "severity_hint": "warning"},
    {"name": "Allowed due to override", "feature": "URL Filtering",
     "description": "Transaction was blocked initially but allowed after the override password was entered.",
     "category": "info", "severity_hint": "info"},
]


# =====================================================================
# Caution + Isolate/Quarantine actions
# Category: warning
# =====================================================================

_CAUTIONS: List[PolicyReason] = [
    {"name": "Cautioned the use of this Social Network site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricting Social Networking cloud apps cautioned the transaction.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Cautioned to post message to this site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricting posting to Social Networking cloud apps.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Cautioned to upload media files to this site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricting upload to Streaming Media / File Sharing cloud apps.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Cautioned to use this File Share site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricting File Sharing cloud apps.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Cautioned to use this Streaming/Media site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricting media streaming cloud apps.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Cautioned to use this Webmail site", "feature": "Cloud App Control",
     "description": "Cloud App Control policy restricting Webmail cloud apps.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Filetype download cautioned", "feature": "File Type Control",
     "description": "File download was cautioned by File Type Control.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Filetype upload cautioned", "feature": "File Type Control",
     "description": "File upload attempt was cautioned by File Type Control.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Filetype upload/download cautioned", "feature": "File Type Control",
     "description": "Upload/download was cautioned by File Type Control.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Internet access cautioned", "feature": "URL Filtering",
     "description": "Transaction was cautioned by a URL Filtering policy.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Request method cautioned", "feature": "URL Filtering",
     "description": "An attempt to post content to a webpage was cautioned.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Secure Browsing warned about an outdated/disallowed component",
     "feature": "Browser Control",
     "description": "Outdated component detected; user warned by Browser Vulnerability Protection.",
     "category": "warning", "severity_hint": "warning"},
    {"name": "Isolate and Scan", "feature": "Sandbox",
     "description": "File isolated on a remote browser and analyzed in the Advanced Sandbox.",
     "category": "warning", "severity_hint": "info"},
    {"name": "Quarantined", "feature": "Sandbox",
     "description": "Download temporarily held due to Sandbox First Time Action set to Quarantine.",
     "category": "warning", "severity_hint": "warning"},
]


# =====================================================================
# ZIA system errors — these signal Service Edge ↔ CA trouble
# Category: error (real diagnostic signal)
# =====================================================================

_ERRORS: List[PolicyReason] = [
    {"name": "Bypassed due to missing config", "feature": "Firewall Filtering",
     "description": "Service Edge for Internet & SaaS (ZIA) failed to establish a connection with the Zscaler Central Authority (CA), resulting in traffic passing through ZIA Firewall/DNS without policy application. Often happens when traffic from a specific user/location arrives at the Service Edge for the first time.",
     "category": "error", "severity_hint": "critical"},
    {"name": "Dropped due to internal error", "feature": "Firewall Filtering",
     "description": "Firewall received user-side traffic but failed to establish the internet-side connection, dropping the flow. Often occurs when Service Edge infrastructure is momentarily overused.",
     "category": "error", "severity_hint": "warning"},
    {"name": "Timed out while waiting for a config", "feature": "Firewall Filtering",
     "description": "Service Edge for ZIA established a connection with the CA but the requested configuration did not arrive within the expected time period (typically 5 seconds). Often happens on first-time arrival from a specific user/location.",
     "category": "error", "severity_hint": "critical"},
    {"name": "Fake Proxy Authentication", "feature": "N/A",
     "description": "Used if the server sends a 407 response code (Proxy-Authenticate) for remote users. Server is asking the service to disclose authentication information.",
     "category": "error", "severity_hint": "info"},
]


# =====================================================================
# Combined exports
# =====================================================================

REASONS: List[PolicyReason] = _BLOCKS + _ALLOWS + _CAUTIONS + _ERRORS

REASONS_BY_NAME: Dict[str, PolicyReason] = {
    row["name"]: row for row in REASONS
}

REASONS_BY_NAME_CI: Dict[str, PolicyReason] = {
    row["name"].lower(): row for row in REASONS
}


def get_policy_reason(name: str):
    """Look up a Policy Reason row by name (case-insensitive)."""
    if not name:
        return None
    row = REASONS_BY_NAME.get(name)
    if row is None:
        row = REASONS_BY_NAME_CI.get(name.lower())
    return row


def reasons_by_feature(feature: str) -> List[PolicyReason]:
    """Return all policy reasons attributed to a given ZIA feature
    (substring match — feature column sometimes lists multiple)."""
    f = feature.lower()
    return [
        row for row in REASONS
        if f in row.get("feature", "").lower()
    ]


def reasons_by_category(category: str) -> List[PolicyReason]:
    return [row for row in REASONS if row.get("category") == category]
