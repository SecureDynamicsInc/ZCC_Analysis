"""
Detector: Endpoint Firewall / Antivirus errors.

Issue #3 in the user spec. Per the official Zscaler "Client Connector
Errors" documentation (Connection Status Errors table), the user-facing tray
status is "Endpoint FW/AV Error" with explanation "The device has a
firewall or antivirus program blocking Zscaler Client Connector
traffic." The canonical state machine value (Windows Registry Keys
section) is ``FIREWALL_BLOCK_ERROR`` -- "ZCC's attempt to create an
outbound and/or inbound connection to itself failed."

CALIBRATION NOTE: None of the bundles available during development
(bundles 1, 2, 3 in the test corpus) contain an actual FW/AV failure.
This detector is therefore designed from:

  1. The Zscaler Errors documentation (authoritative state names, error meanings).
  2. Curated regex patterns developed against earlier-session bundles
     (no longer available) and re-validated against current bundles.
  3. Validation that the patterns DON'T false-fire on the three
     healthy bundles I do have.

It has NOT been validated against a real failure-mode bundle. When such
a bundle becomes available, the regex selectivity and severity
thresholds should be re-evaluated.

Watches for:

  * ``FIREWALL_BLOCK_ERROR`` proxy-state transitions (canonical signal)
  * ``Firewall detected retries expired`` -- documentation-documented signature
  * ``[WFP]: Bad health`` -- documentation-documented signature
  * Health-check failures to 100.64.0.0/24 (ZCC's internal probe targets:
    100.64.0.6 / 100.64.0.8 on ports 80 (ZIA), 9090 (ZPA), with 443 /
    8080 fallback). Healthy bundles emit thousands of INFO-level
    connection lines to these IPs, so detection is gated on log level
    (ERROR/WARN) and explicit error phrasing.
  * Local port 9000 bind / listen failures -- ZCC's default local
    listener for the DNS proxy and TUN-Proxy
  * LWF / TAP / FilterDriver load failures
  * Firewall rule install failures
  * Process-launch denials (Access denied for ZSA*)
  * ControlService Windows error 0x426 (service permission denied)
  * Anti-tamper violations (ZCC's own self-protection trip)
  * Listing detected AV/EDR products from summary.security_products as
    INFO context (the most likely culprit when other findings fire).

Distinct from other detectors:

  * Tunnel-not-established detector watches ``SERVER_DOWN_ERROR``,
    ``ADAPTER_DOWN_ERROR`` etc. but explicitly excludes
    ``FIREWALL_BLOCK_ERROR`` (delegated here).
  * The ZIA/ZPA auth detectors don't overlap.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# Canonical state-machine signal. Same shape as in the tunnel detector,
# but only matching FIREWALL_BLOCK_ERROR.
_RE_STATE_CHANGE_FW = re.compile(
    r"Changing\s+(?P<svc>ZIA|ZPA)\s+state\s+from:\s*"
    r"(?P<from>\w+)\s+to\s+(?P<to>FIREWALL_BLOCK_ERROR)"
)

# Driver load failures.
_RE_LWF_NOT_RUNNING = re.compile(
    r"\"?lwfDriverRunning\"?\s*[:=]\s*\"?false\b",
    re.IGNORECASE,
)
_RE_FILTER_DRIVER_FAIL = re.compile(
    r"FilterDriver.*?(?:failed|error|load.*fail)",
    re.IGNORECASE,
)

# Health-check connection failures.
#
# What ZCC actually does (NOT 127.0.0.1!):
#   * Sends a health-check probe to 100.64.0.6 / 100.64.0.8 on ports
#     80 (ZIA), 9090 (ZPA in real bundles), 443 / 8080 fallback.
#   * Listens locally on port 9000 (default; user-configurable).
# Per the Zscaler ZCCTF runbook, when a host firewall blocks this, the
# tray flips to "Endpoint FW/AV Error" / FIREWALL_BLOCK_ERROR.
#
# Healthy bundles show LOTS of 100.64.0.6 traffic in INF / DBG records
# (1285 mentions in bundle 1, 210 in bundle 3) -- so we MUST gate on
# both an explicit error phrase AND a non-INFO log level.
_RE_HEALTHCHECK_FAIL = re.compile(
    # 100.64.0.0/24 IP appearing alongside an error phrase, in either
    # order. The error-phrase list is deliberately narrow to avoid
    # the "Refused_conn: 0" healthy-stats false positive we hit in v1.
    r"100\.64\.0\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"
    r"[^\n]{0,120}?"
    r"(?:connection\s+refused"
    r"|connection\s+reset"
    r"|connection\s+timed?\s*out"
    r"|connect(?:ion)?\s+failed"
    r"|cannot\s+connect"
    r"|unable\s+to\s+connect"
    r"|no\s+route\s+to\s+host"
    r"|host\s+unreachable)"
    r"|"
    r"(?:connection\s+refused"
    r"|connection\s+reset"
    r"|connection\s+timed?\s*out"
    r"|connect(?:ion)?\s+failed"
    r"|cannot\s+connect"
    r"|unable\s+to\s+connect"
    r"|no\s+route\s+to\s+host"
    r"|host\s+unreachable)"
    r"[^\n]{0,120}?"
    r"100\.64\.0\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b",
    re.IGNORECASE,
)

# Local listener on port 9000 failed to bind / listen / accept.
# Healthy mode: ``initializeDnsServerSocket: Trying port :9000`` ->
# ``Dns Proxy Listener: [::]:9000 Sock fd: ...``.
# Failure mode: bind / listen / socket failure on 9000.
_RE_PORT_9000_BIND_FAIL = re.compile(
    r"(?:initializeDnsServerSocket|Listener\s+addr|listener_port|"
    r"bind|listen|accept)[^\n]{0,80}?"
    r"\b9000\b[^\n]{0,80}?"
    r"(?:fail(?:ed|ure)?|error|refused|denied)"
    r"|"
    r"\b9000\b[^\n]{0,40}?"
    r"(?:fail(?:ed|ure)?|error|refused|denied)[^\n]{0,40}?"
    r"(?:bind|listen|socket|listener|inbound)",
    re.IGNORECASE,
)

# documentation-documented explicit signatures. These are inherently failure-only
# and don't appear in healthy bundles, so we match bare (any level).
_RE_FW_RETRIES_EXPIRED = re.compile(
    r"Firewall detected retries expired",
    re.IGNORECASE,
)
_RE_WFP_BAD_HEALTH = re.compile(
    r"\[WFP\][^\n]*?Bad health",
    re.IGNORECASE,
)

# Firewall rule install failures. The healthy form is
# ``INF Adding firewall rule for Name: [...]``; the failure form
# adds "failed" / "error" downstream.
_RE_FIREWALL_RULE_FAIL = re.compile(
    r"Adding firewall rule[^\n]*?(?:failed|error)",
    re.IGNORECASE,
)
_RE_FIREWALL_API_FAIL = re.compile(
    r"FirewallAPI[^\n]*?(?:failed|error)",
    re.IGNORECASE,
)

# Process-launch denials.
_RE_ACCESS_DENIED_ZSA = re.compile(
    r"Access (?:is )?denied[^\n]*?ZSA",
    re.IGNORECASE,
)

# Service start permission failure (Windows error 0x426 = service is
# not active / start denied).
_RE_CONTROLSERVICE_426 = re.compile(
    r"ControlService failed[^\n]*?Error[^\n]*?0x0*426\b",
    re.IGNORECASE,
)

# Anti-tampering violation -- ZCC's OWN self-protection logic detected
# something modifying its files / processes.
_RE_ANTI_TAMPER = re.compile(
    r"Anti.?Tamper[^\n]*?violation",
    re.IGNORECASE,
)


EVIDENCE_CAP = 10


# --- Detector ---------------------------------------------------------

@register
class FwAvErrorsDetector(IssueDetector):
    id = "endpoint_fw_av"
    title = "Endpoint Firewall / Antivirus errors"
    sop_file = "endpoint_fw_av.md"
    # Cross-suite: FW/AV blocking ZCC traffic breaks both ZIA and
    # ZPA tunnels. Gate is OS-only (Windows).
    applies_to_suite = None
    # All current signatures are Windows-only (LWF JSON status,
    # FirewallAPI, ControlService 0x426, WFP). Mac uses pfctl /
    # socketfilterfw / system extensions and is handled in a separate
    # ``endpoint_fw_av_mac.py``.
    applies_to_os = ("windows",)

    def __init__(self) -> None:
        super().__init__()
        # Track FIREWALL_BLOCK_ERROR transitions per service (ZIA / ZPA).
        # Per documentation, FIREWALL_BLOCK_ERROR is "applicable only for Private
        # Access" but we still log if it appears for either, since the
        # state-machine implementation may share code.
        self._fw_state_records: List[LogLine] = []

    # --- IssueDetector overrides ----------------------------------

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # 1. Canonical state transition.
        if _RE_STATE_CHANGE_FW.search(msg):
            self._fw_state_records.append(record)
            return  # state-change line is unique enough

        # 2. Driver load failures.
        if _RE_LWF_NOT_RUNNING.search(msg):
            f = self._bucket(
                "LWF_DRIVER_NOT_RUNNING",
                Severity.CRITICAL,
                "LWF driver is not running",
                "ZCC reported lwfDriverRunning=false. The Zscaler "
                "Lightweight Filter (LWF) driver is the kernel-mode "
                "component that intercepts traffic in modern ZCC "
                "(replacing the legacy TAP driver). Without it, ZCC "
                "cannot intercept anything and traffic flows around "
                "the client. Common cause: an EDR/AV product is "
                "blocking driver load, or the driver's signature got "
                "rejected after a Windows update.",
                sop_anchor="#lwf-driver-not-running",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        if _RE_FILTER_DRIVER_FAIL.search(msg):
            f = self._bucket(
                "FILTER_DRIVER_FAIL",
                Severity.CRITICAL,
                "Filter driver load failure",
                "ZCC's filter driver failed to load. Often caused by an "
                "EDR/AV product blocking kernel-driver loads, or by a "
                "Windows code-integrity policy that rejected the "
                "driver's signature.",
                sop_anchor="#filter-driver-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 3. Health-check failures to 100.64.0.0/24 range.
        # Gate on log level: real health-check errors should be ERROR
        # (or at worst WARN). Healthy bundles emit thousands of
        # ``checkTunTcpEchoServerUpImpl: Connecting to 100.64.0.6:80
        # for ZIA health check`` lines at INFO level -- the level gate
        # (ERROR/WARN only) is what keeps this from drowning in noise
        # even when the regex would otherwise match a healthy line.
        # (Levels are normalised by the parser: ERR -> ERROR, WRN ->
        # WARN, see log_parser._LEVEL_NORMALISE.)
        if record.level in ("ERROR", "WARN") and _RE_HEALTHCHECK_FAIL.search(msg):
            f = self._bucket(
                "HEALTHCHECK_TO_100_64_FAILED",
                Severity.CRITICAL,
                "Health-check connection to 100.64.0.0/24 failed",
                "ZCC's attempt to reach its internal health-check "
                "endpoints (100.64.0.6 / 100.64.0.8 on ports 80, "
                "9090, 443, or 8080) failed at the network layer. "
                "This is the canonical signature of a host firewall "
                "or AV/EDR blocking ZCC's health-check traffic, OR "
                "the 100.64.0.0/24 range being mis-routed onto a "
                "third-party VPN adapter instead of the physical "
                "interface. Triage: run "
                "`Find-NetRoute -RemoteIPAddress 100.64.0.6` in "
                "PowerShell to confirm the route uses Wi-Fi or "
                "Ethernet, not the VPN adapter.",
                sop_anchor="#healthcheck-to-100-64-failed",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 3b. Local port 9000 bind / listen failure.
        if _RE_PORT_9000_BIND_FAIL.search(msg):
            f = self._bucket(
                "PORT_9000_BIND_FAIL",
                Severity.CRITICAL,
                "ZCC failed to bind / listen on port 9000",
                "Port 9000 is ZCC's local listening port (configurable "
                "in the forwarding profile, but 9000 is default). The "
                "port is used for the DNS proxy listener and the "
                "TUN-Proxy local listener. If ZCC can't bind / listen "
                "on it, traffic interception is broken. Common cause: "
                "an inbound firewall rule blocking local port 9000, "
                "or another application already bound to that port.",
                sop_anchor="#port-9000-bind-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 3c. documentation-documented "Firewall detected retries expired".
        if _RE_FW_RETRIES_EXPIRED.search(msg):
            f = self._bucket(
                "FIREWALL_RETRIES_EXPIRED",
                Severity.CRITICAL,
                "Firewall detected retries expired",
                "Per the Zscaler ZCCTF runbook, this log signature "
                "means ZCC's internal Windows Filtering Platform (WFP) "
                "callout retried the blocked traffic up to its retry "
                "limit and gave up. Almost always paired with "
                "FIREWALL_BLOCK_ERROR. Root cause is the same as the "
                "health-check failure: a host firewall or EDR product "
                "is blocking ZCC's health-check / loopback traffic.",
                sop_anchor="#firewall-retries-expired",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 3d. documentation-documented "[WFP]: Bad health".
        if _RE_WFP_BAD_HEALTH.search(msg):
            f = self._bucket(
                "WFP_BAD_HEALTH",
                Severity.CRITICAL,
                "Windows Filtering Platform reported bad health",
                "Per the Zscaler ZCCTF runbook, ``[WFP] Bad health`` "
                "indicates ZCC's Windows Filtering Platform driver "
                "is reporting itself unhealthy -- usually because its "
                "callout traffic is being blocked. Often paired with "
                "FIREWALL_BLOCK_ERROR transitions and "
                "``Firewall detected retries expired``.",
                sop_anchor="#wfp-bad-health",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 4. Firewall rule install failures.
        if _RE_FIREWALL_RULE_FAIL.search(msg):
            f = self._bucket(
                "FIREWALL_RULE_INSTALL_FAIL",
                Severity.CRITICAL,
                "Firewall rule install failed",
                "ZCC tried to add a Windows Firewall allow-rule for "
                "itself and failed. Typically a permissions issue "
                "(ZCC service account couldn't write firewall config) "
                "or a Group Policy / EDR product preventing rule "
                "modifications.",
                sop_anchor="#firewall-rule-install-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        if _RE_FIREWALL_API_FAIL.search(msg):
            f = self._bucket(
                "FIREWALL_API_FAIL",
                Severity.CRITICAL,
                "FirewallAPI call failed",
                "ZCC's call to the Windows FirewallAPI returned an "
                "error. Same root causes as firewall rule install "
                "failure.",
                sop_anchor="#firewall-api-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 5. Process-launch denials.
        if _RE_ACCESS_DENIED_ZSA.search(msg):
            f = self._bucket(
                "ACCESS_DENIED_ZSA",
                Severity.CRITICAL,
                "Access denied launching a ZCC component",
                "An EDR / AV product or Windows ACL denied the launch "
                "of a Zscaler component. ZCC component file paths "
                "(ZSAService.exe, ZSATunnel.exe, ZSATray.exe, "
                "ZSAUpm.exe) and the ProgramData\\Zscaler directory "
                "must be on the EDR allow-list.",
                sop_anchor="#access-denied-zsa",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 6. Service-start permission failure.
        if _RE_CONTROLSERVICE_426.search(msg):
            f = self._bucket(
                "CONTROLSERVICE_PERMISSION_DENIED",
                Severity.CRITICAL,
                "ZSAService start denied (Windows 0x426)",
                "ControlService returned Windows error 0x00000426 -- "
                "service is not active / start was denied. Usually a "
                "Group Policy hardening or an EDR product preventing "
                "service start.",
                sop_anchor="#controlservice-426",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 7. Anti-tamper violation.
        if _RE_ANTI_TAMPER.search(msg):
            f = self._bucket(
                "ANTI_TAMPER_VIOLATION",
                Severity.CRITICAL,
                "ZCC self-protection (anti-tamper) trip",
                "ZCC's own anti-tamper logic detected something "
                "modifying its files, registry keys, or processes. "
                "Often an aggressive EDR product (or another AV "
                "trying to 'clean' ZCC) is the culprit.",
                sop_anchor="#anti-tamper-violation",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        findings: List[Finding] = list(self._buckets.values())

        # FIREWALL_BLOCK_ERROR transitions: emit one finding summarising
        # all of them.
        if self._fw_state_records:
            f = Finding(
                code="FIREWALL_BLOCK_ERROR_STATE",
                severity=Severity.CRITICAL,
                title=(
                    f"FIREWALL_BLOCK_ERROR state entered "
                    f"({len(self._fw_state_records)} time(s))"
                ),
                description=(
                    "ZCC's proxy state transitioned into "
                    "FIREWALL_BLOCK_ERROR. Per the Zscaler 'Client "
                    "Connector Errors' documentation, this means "
                    "ZCC's attempt to create an outbound and/or "
                    "inbound connection to itself failed -- the "
                    "canonical 'Endpoint FW/AV Error' that surfaces "
                    "in the tray. A host firewall or endpoint "
                    "protection product is blocking ZCC's loopback "
                    "/ IPC traffic. The documentation documents this state as "
                    "'applicable only for Private Access', but check "
                    "your forwarding profile to confirm."
                ),
                sop_anchor="#firewall-block-error-state",
            )
            for rec in self._fw_state_records[:EVIDENCE_CAP]:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        # Surface detected AV/EDR products as INFO context. This isn't
        # a finding in the "something is wrong" sense -- it's
        # diagnostic context that's most useful when other findings
        # have fired. We always emit it (when products are detected)
        # so the report shows the human "here's what's installed."
        if summary.security_products:
            products = ", ".join(summary.security_products)
            findings.append(Finding(
                code="SECURITY_PRODUCTS_PRESENT",
                severity=Severity.INFO,
                title=(
                    f"{len(summary.security_products)} security "
                    f"product(s) detected"
                ),
                description=(
                    f"The following AV/EDR product(s) were detected "
                    f"on the system from AppInfo.xml: {products}. "
                    f"This is informational context. If FW/AV "
                    f"findings have fired above, one of these is the "
                    f"most likely culprit -- verify ZCC components "
                    f"and the ProgramData\\Zscaler directory are on "
                    f"that product's allow-list."
                ),
                sop_anchor="#security-products-present",
            ))

        return findings
