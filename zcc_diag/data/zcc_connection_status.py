"""
ZCC Connection Status errors — authoritative tray-message reference.

Normalized from the Zscaler documentation "Zscaler Client Connector:
Connection Status Errors".

These are the error messages that appear in the Service Status field
of the ZCC tray UI. Each entry documents:
  - the literal tray label users see
  - what condition triggers it
  - the documented required action
  - whether it's effectively an error, warning, or info per the docs
  - which platform(s) it applies to

Source URL: help.zscaler.com/zscaler-client-connector/zscaler-client-connector-connection-status-errors
"""

from __future__ import annotations

from typing import Dict, List

try:
    from typing import TypedDict
except ImportError:  # pragma: no cover
    TypedDict = dict  # type: ignore


class TrayStatus(TypedDict, total=False):
    """One tray-status row from the Connection Status Errors documentation.

    Fields:
      name             — literal tray label (e.g. "Driver Error")
      category         — "error" | "warning" | "info"
      explanation      — documented from the documentation's "Explanation" column
      required_action  — documented from the documentation's "Required Action" column
      scope            — "windows" | "macos" | "both"
      severity_hint    — our derived severity for the chip
    """
    name: str
    category: str
    explanation: str
    required_action: str
    scope: str
    severity_hint: str


# =====================================================================
# Tray status messages (17 documented entries)
# =====================================================================

STATUSES: List[TrayStatus] = [
    {
        "name": "Intermediate Authentication Error",
        "category": "warning",
        "explanation": "A tunnel authentication error has occurred because an intermediate proxy service has intercepted the app authentication request.",
        "required_action": "No action required.",
        "scope": "both",
        "severity_hint": "warning",
    },
    {
        "name": "Authenticating...",
        "category": "info",
        "explanation": "A tunnel authentication error has occurred because the Public Service Edge for Internet & SaaS is waiting for user configuration.",
        "required_action": "No action required.",
        "scope": "both",
        "severity_hint": "info",
    },
    {
        "name": "Authentication Error",
        "category": "error",
        "explanation": "A tunnel authentication error has occurred.",
        "required_action": "For Internet Security: Click Retry. For Private Access: Click Authenticate. If persistent, Restart Service or log out / back in.",
        "scope": "both",
        "severity_hint": "critical",
    },
    {
        "name": "Captive Portal Detected",
        "category": "warning",
        "explanation": "Zscaler Client Connector is in a fail-open state because Zscaler Client Connector detected a captive portal.",
        "required_action": "Click Open Browser to access the internet. If you don't resolve the captive portal in time, click Retry.",
        "scope": "both",
        "severity_hint": "warning",
    },
    {
        "name": "Captive Portal Error",
        "category": "error",
        "explanation": "The user has not resolved the captive portal within the time configured in the Zscaler Admin Console.",
        "required_action": "Click Retry and then resolve the captive portal.",
        "scope": "both",
        "severity_hint": "warning",
    },
    {
        "name": "Chaining Authentication Error",
        "category": "error",
        "explanation": "A tunnel authentication error has occurred due to proxy chaining.",
        "required_action": "For Internet Security: Click Retry. For Private Access: Click Authenticate. If persistent, Restart Service.",
        "scope": "both",
        "severity_hint": "critical",
    },
    {
        "name": "Connection Error",
        "category": "error",
        "explanation": "The Public Service Edge for Internet & SaaS cannot be reached.",
        "required_action": "Click Retry. If persistent, Restart Service.",
        "scope": "both",
        "severity_hint": "critical",
    },
    {
        "name": "Driver Error",
        "category": "error",
        "explanation": "A Windows driver installation issue has been detected, and the tunnel interface cannot be started. ZCC is in a fail-open state unless fail-close app profile option is enabled.",
        "required_action": "In the More window, click Repair App (Troubleshoot section). If persistent, contact Zscaler Support.",
        "scope": "windows",
        "severity_hint": "critical",
    },
    {
        "name": "Endpoint FW/AV Error",
        "category": "error",
        "explanation": "The device has a firewall or antivirus program blocking Zscaler Client Connector traffic. ZCC is in a fail-open state unless fail-close app profile option is enabled.",
        "required_action": "Contact your administrator for any required configuration changes on the device.",
        "scope": "both",
        "severity_hint": "critical",
    },
    {
        "name": "Fail Open",
        "category": "warning",
        "explanation": "Zscaler Client Connector is in a fail-open state because Zscaler Client Connector detected Windows safe mode activation.",
        "required_action": "Restart Windows without safe mode.",
        "scope": "windows",
        "severity_hint": "warning",
    },
    {
        "name": "Fail Close",
        "category": "error",
        "explanation": "Zscaler Client Connector is in a fail-close state because the tunnel interface cannot be started (e.g. a driver error or an endpoint FW/AV error).",
        "required_action": "Click Retry. If persistent, Restart Service.",
        "scope": "both",
        "severity_hint": "critical",
    },
    {
        "name": "Internal Error",
        "category": "error",
        "explanation": "Internal socket problem has been detected.",
        "required_action": "Click Retry. If persistent, Restart Service.",
        "scope": "both",
        "severity_hint": "critical",
    },
    {
        "name": "Installation Error",
        "category": "error",
        "explanation": "Zscaler Client Connector experienced a network error while trying to connect to the Zscaler Digital Experience (ZDX) server.",
        "required_action": "Click Retry. If persistent, Restart Service.",
        "scope": "both",
        "severity_hint": "warning",
    },
    {
        "name": "Network Error",
        "category": "error",
        "explanation": "No network interface is detected.",
        "required_action": "Click Retry. If persistent, Restart Service.",
        "scope": "both",
        "severity_hint": "critical",
    },
    {
        "name": "Safe Mode",
        "category": "warning",
        "explanation": "The Zscaler service is down. You'll only have access to critical resources determined by your organization.",
        "required_action": "No action required.",
        "scope": "both",
        "severity_hint": "warning",
    },
    {
        "name": "Server Error",
        "category": "error",
        "explanation": "Zscaler Client Connector is unable to connect to the ZDX cloud.",
        "required_action": "Check network connectivity. Click Retry. If persistent, Restart Service.",
        "scope": "both",
        "severity_hint": "warning",
    },
    {
        "name": "Untrusted Root Cert",
        "category": "error",
        "explanation": "Zscaler Client Connector is unable to validate the Private Service Edge for Private Access root certificate.",
        "required_action": "Contact Zscaler Support.",
        "scope": "both",
        "severity_hint": "critical",
    },
]


# =====================================================================
# Lookup dictionaries (keyed by lowercase canonical name for tolerant
# matching — detector finding codes don't always preserve case)
# =====================================================================

STATUSES_BY_NAME: Dict[str, TrayStatus] = {
    row["name"]: row for row in STATUSES
}

STATUSES_BY_NAME_CI: Dict[str, TrayStatus] = {
    row["name"].lower(): row for row in STATUSES
}


def get_tray_status(name: str) -> "TrayStatus | None":
    """Look up a tray-status row by name (case-insensitive)."""
    if not name:
        return None
    # Try exact first (preserves case-sensitive matches), then lower-case
    row = STATUSES_BY_NAME.get(name)
    if row is None:
        row = STATUSES_BY_NAME_CI.get(name.lower())
    return row


def tray_statuses_by_category(category: str) -> List[TrayStatus]:
    """Return all tray statuses in the given category."""
    return [row for row in STATUSES if row.get("category") == category]
