"""
Synthetic-data test for the endpoint_fw_av_mac detector.

Note: real Mac failure-mode bundles weren't available during
authoring, so all 8 patterns are exercised via planted synthetic
lines. When a real failure bundle becomes available, run it through
this detector and tighten the regexes if needed.

Run:  python test_endpoint_fw_av_mac.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary
from zcc_diag.issues.endpoint_fw_av_mac import FwAvMacErrorsDetector


def make_rec(msg: str, level: str = "WARN", pid: int = 1000,
             tid: int = 2000) -> LogLine:
    return LogLine(
        timestamp=datetime(2026, 5, 15, 12, 0, 0, tzinfo=timezone.utc),
        level=level,
        pid=pid,
        tid=tid,
        message=msg,
        source_path=Path("com.zscaler.UPMServiceController.log"),
        raw=msg,
        line_no=1,
    )


def assert_eq(label, got, want):
    ok = got == want
    print(f"  {'OK   ' if ok else 'FAIL '} {label}")
    if not ok:
        print(f"        got:  {got!r}")
        print(f"        want: {want!r}")
    return ok


def main() -> int:
    failed = 0
    summary = BundleSummary()

    # ---- Case 1: Wandera EDNS interception (Example Tenant J observed) ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "DNS query to edns.wandera.com returned NXDOMAIN"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "edns.wandera.com fires WANDERA_EDNS_INTERCEPT",
        {f.code for f in findings},
        {"WANDERA_EDNS_INTERCEPT"},
    ):
        failed += 1

    # ---- Case 2: Cisco Umbrella DNS ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "Resolved hostname: dns.umbrella.com --> 208.67.222.222"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "dns.umbrella.com fires UMBRELLA_DNS_INTERCEPT",
        {f.code for f in findings},
        {"UMBRELLA_DNS_INTERCEPT"},
    ):
        failed += 1

    # ---- Case 3: Jamf Protect process activity (INFO) ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "Detected jamfprotectd running with pid 12345"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "jamfprotectd fires JAMF_PROTECT_ACTIVITY (INFO)",
        {f.code for f in findings},
        {"JAMF_PROTECT_ACTIVITY"},
    ):
        failed += 1

    # ---- Case 4: pfctl block ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "pfctl: block in quick on en0 proto udp from any to any"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "pfctl block line fires PFCTL_BLOCK",
        {f.code for f in findings},
        {"PFCTL_BLOCK"},
    ):
        failed += 1

    # ---- Case 5: socketfilterfw deny ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "socketfilterfw: deny TCP outbound for ZSATunnel"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "socketfilterfw deny fires SOCKETFILTERFW_DENY",
        {f.code for f in findings},
        {"SOCKETFILTERFW_DENY"},
    ):
        failed += 1

    # ---- Case 6: System Extension load denied ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "SystemExtensionRequest for com.zscaler.tunnel was denied "
        "by user policy"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "SystemExtensionRequest denied fires SYSEXT_LOAD_DENIED",
        {f.code for f in findings},
        {"SYSEXT_LOAD_DENIED"},
    ):
        failed += 1

    # ---- Case 7: NEFilterDataProvider termination ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "NEFilterDataProvider terminated unexpectedly after 100ms"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "NEFilter terminated fires NEFILTER_PROVIDER_FAILURE",
        {f.code for f in findings},
        {"NEFILTER_PROVIDER_FAILURE"},
    ):
        failed += 1

    # ---- Case 8: generic DNS sinkhole (NextDNS) ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec(
        "DNS query routed through nextdns.io"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "nextdns.io fires DNS_SINKHOLE_GENERIC",
        {f.code for f in findings},
        {"DNS_SINKHOLE_GENERIC"},
    ):
        failed += 1

    # ---- Case 9: healthy Mac log -> no findings ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec("Connection established to gateway.zscalerthree.net"), summary)
    d.feed(make_rec("PAC fetch successful"), summary)
    d.feed(make_rec("Resolved hostname: mobile.zscalerthree.net --> 165.225.0.0"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "healthy Mac log -> no findings",
        {f.code for f in findings},
        set(),
    ):
        failed += 1

    # ---- Case 10: multiple findings co-occur ----
    d = FwAvMacErrorsDetector()
    d.feed(make_rec("jamfprotectd active"), summary)
    d.feed(make_rec("DNS query to edns.wandera.com NXDOMAIN"), summary)
    d.feed(make_rec(
        "SystemExtensionRequest for com.zscaler.networkextension denied"
    ), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "co-occurring signals fire distinct buckets",
        {f.code for f in findings},
        {
            "JAMF_PROTECT_ACTIVITY",
            "WANDERA_EDNS_INTERCEPT",
            "SYSEXT_LOAD_DENIED",
        },
    ):
        failed += 1

    # ---- Case 11: same signal repeated -> single bucket with multiple evidence ----
    d = FwAvMacErrorsDetector()
    for _ in range(5):
        d.feed(make_rec("edns.wandera.com responded with NXDOMAIN"), summary)
    findings = d.finalize(summary)
    if not assert_eq(
        "5 hits of same signal -> 1 finding with count=5",
        (
            {f.code for f in findings},
            findings[0].count if findings else None,
        ),
        ({"WANDERA_EDNS_INTERCEPT"}, 5),
    ):
        failed += 1

    print()
    if failed:
        print(f"FAILED ({failed} test case(s))")
        return 1
    print("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
