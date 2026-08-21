"""
Synthetic-line test for the Endpoint FW/AV detector (Windows).

Real bundles available during development (1, 2, 3) are all healthy
w.r.t. FW/AV, so we manufacture log lines to verify:

    1. Each documented failure mode fires a finding:
       - Health-check failures to 100.64.0.0/24
       - Local port 9000 bind/listen failures
       - documentation-documented signatures (`Firewall detected retries expired`,
         `[WFP] Bad health`)
       - LWF-not-running, FilterDriver-load-fail, firewall-rule-fail,
         access-denied-ZSA, ControlService 0x426, Anti-tamper

    2. The healthy-bundle false positives we hit during development
       do NOT fire:
       - JSON config dumps containing 'loopback' / 'blocked'
       - Stats lines containing 'Refused_conn: 0'
       - Healthy 100.64.0.6 INFO-level health-check probes
       - 'lwfDriverRunning:true' (success counter)
       - Benign zapprd registry path mentions

    3. The level-gate on health-check failures works: ERROR-level
       failures fire, INFO-level lookalikes don't.

Mac counterpart: ``test_endpoint_fw_av_mac.py``.

Run:  python test_endpoint_fw_av.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.endpoint_fw_av import FwAvErrorsDetector


def make_record(level: str, message: str) -> LogLine:
    """Build a synthetic LogLine for testing.

    Note: log_parser normalises level names (ERR -> ERROR, WRN -> WARN).
    Tests should use the normalised names since that's what feed() sees.
    Only the level + message fields matter; other fields are dummies.
    """
    return LogLine(
        timestamp=datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc),
        level=level,
        pid=1,
        tid=1,
        message=message,
        source_path=Path("synthetic.log"),
        raw=f"2026-05-05 12:00:00.000(+0000)[1:1] {level} {message}",
        line_no=1,
    )


# (label, level, message, expected_finding_codes_set)
# Levels are NORMALISED names: INFO, DEBUG, ERROR, WARN, TRACE, ...
CASES = [
    # ---- positive cases: real failure modes ----
    (
        "LWF driver not running",
        "INFO",
        '... statusJson stringify: {"lwfDriverRunning":false,"tapDriverRunning":false,...}',
        {"LWF_DRIVER_NOT_RUNNING"},
    ),
    (
        "Health-check to 100.64.0.6 connection refused (ERROR)",
        "ERROR",
        "Failed to connect to 100.64.0.6:80 for ZIA health check: connection refused",
        {"HEALTHCHECK_TO_100_64_FAILED"},
    ),
    (
        "Health-check to 100.64.0.8 timed out (ERROR)",
        "ERROR",
        "100.64.0.8:9090 connection timed out after 5000ms",
        {"HEALTHCHECK_TO_100_64_FAILED"},
    ),
    (
        "Health-check no route to host (ERROR)",
        "ERROR",
        "no route to host for 100.64.0.6 on adapter Ethernet",
        {"HEALTHCHECK_TO_100_64_FAILED"},
    ),
    (
        "Port 9000 bind failure",
        "ERROR",
        "initializeDnsServerSocket: bind on port 9000 failed: address in use",
        {"PORT_9000_BIND_FAIL"},
    ),
    (
        "Port 9000 listener refused",
        "ERROR",
        "Listener addr [::]:9000 listen failed: access denied",
        {"PORT_9000_BIND_FAIL"},
    ),
    (
        "documentation signature: Firewall detected retries expired",
        "ERROR",
        "Firewall detected retries expired - giving up on health probe",
        {"FIREWALL_RETRIES_EXPIRED"},
    ),
    (
        "documentation signature: [WFP] Bad health",
        "ERROR",
        "[WFP]: Bad health detected on callout 12345",
        {"WFP_BAD_HEALTH"},
    ),
    (
        "Firewall rule install failure",
        "ERROR",
        "Adding firewall rule for ZSATunnel failed: access denied",
        {"FIREWALL_RULE_INSTALL_FAIL"},
    ),
    (
        "Access denied launching ZSA component",
        "ERROR",
        "createProcess: Access denied for ZSAUpdater.exe",
        {"ACCESS_DENIED_ZSA"},
    ),
    (
        "ControlService 0x426 permission denied",
        "ERROR",
        "ControlService failed for ZSAService, Error: 0x00000426",
        {"CONTROLSERVICE_PERMISSION_DENIED"},
    ),
    (
        "Anti-tamper violation",
        "ERROR",
        "Anti-Tamper module detected violation: registry write blocked",
        {"ANTI_TAMPER_VIOLATION"},
    ),
    (
        "FilterDriver load failure",
        "ERROR",
        "FilterDriver loadDriver failed with error 0xC0000022",
        {"FILTER_DRIVER_FAIL"},
    ),
    # ---- negative cases: must NOT fire ----
    (
        "JSON config dump with 'loopback':false (still must not fire)",
        "DEBUG",
        'windows config: {"flowLoggingConfig":{"loopback":false,"vpn":false},"zcc_blocked_traffic":false}',
        set(),
    ),
    (
        "Healthy stats with 'Refused_conn: 0' (B1/B2/B3 false-positive)",
        "INFO",
        "Loopback Connection check response code: 200 data: Success;Loopback:Curr_conn:1,Refused_conn: 0,Total_conn: 8",
        set(),
    ),
    (
        "Healthy 100.64.0.6 ZIA health probe (INFO-level)",
        "INFO",
        "checkTunTcpEchoServerUpImpl: Connecting to 100.64.0.6:80 for ZIA health check (address family = IPv4)",
        set(),
    ),
    (
        "Healthy 100.64.0.6 ZPA health probe (INFO-level)",
        "INFO",
        "checkTunTcpEchoServerUpImpl: Connecting to 100.64.0.6:9090 for ZPA health check (address family = IPv4)",
        set(),
    ),
    (
        "Healthy TUN-Proxy disconnect on 100.64.0.6 (DEBUG-level)",
        "DEBUG",
        "ID=930170855, Disconnecting Tag id: 0 from [::ffff:100.64.0.6]:53801 for app_name: , stats=[Cl:(Rx:0,Tx:0)]",
        set(),
    ),
    (
        "INFO-level 100.64 line that would otherwise match (level-gate test)",
        "INFO",
        "100.64.0.6 connection refused -- but this is just a transient retry log",
        set(),
    ),
    (
        "Healthy port 9000 listener startup",
        "INFO",
        "Listener addr: [::]:9000, listener_port: 9000",
        set(),
    ),
    (
        "Healthy DNS server socket initialization on port 9000",
        "INFO",
        "initializeDnsServerSocket: Trying port :9000",
        set(),
    ),
    (
        "Routine 'Adding firewall rule' success line",
        "INFO",
        "Adding firewall rule for Name: [Zscaler App Rule]",
        set(),
    ),
    (
        "Healthy lwfDriverRunning:true",
        "INFO",
        '{"lwfDriverRunning":true,"tapDriverRunning":false,...}',
        set(),
    ),
    (
        "Benign zapprd registry path mention (B3 saw this)",
        "ERROR",
        "ZSARegistryInterfaceImpl::getValue: failed for Registry: SYSTEM\\CurrentControlSet\\Services\\zapprd\\Parameters\\hwOffloadingMode",
        set(),  # zapprd as a registry path != filter driver failure
    ),
]


def run_one(label: str, level: str, msg: str, expected: set) -> bool:
    det = FwAvErrorsDetector()
    rec = make_record(level, msg)
    summary = BundleSummary()  # empty summary; we only test feed()
    det.feed(rec, summary)
    findings = det.finalize(summary)
    # Filter out informational-context findings that always fire when
    # security_products is non-empty (it's empty in our synthetic summary).
    actual = {f.code for f in findings if f.code != "SECURITY_PRODUCTS_PRESENT"}

    ok = actual == expected
    mark = "OK   " if ok else "FAIL "
    print(f"  {mark} {label}")
    if not ok:
        print(f"        expected: {expected}")
        print(f"        actual:   {actual}")
    return ok


def main() -> int:
    failed = 0
    for label, level, msg, expected in CASES:
        if not run_one(label, level, msg, expected):
            failed += 1
    print()
    if failed:
        print(f"{failed} FAILED out of {len(CASES)}")
        return 1
    print(f"all {len(CASES)} FW/AV cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
