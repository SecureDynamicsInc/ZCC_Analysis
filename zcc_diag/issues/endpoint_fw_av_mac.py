"""
Detector: macOS firewall / EDR / DNS-filter interference.

Mac analogue of ``endpoint_fw_av`` (which is Windows-only). The
detection surface is fundamentally different on macOS:
- No LWF kernel filter driver -- ZCC uses Apple System Extensions.
- No Windows Firewall API -- Mac uses ``pfctl`` (packet filter) and
  ``socketfilterfw`` (the application firewall).
- DNS filtering products (Jamf Protect with Wandera, Cisco Umbrella
  for Mac) install per-host DNS sinkholes that intercept queries
  even when ZIA is disabled.
- System Extension load can be denied by MDM policy ("user approved
  kernel extensions" left unchecked).

Grounded by:
- an anonymized internal case (Example Tenant J JumpCloud Remote Assist
  on macOS, closed `ISSUE_FIXED`). observed from 2026-02-06 Zoom AI
  Summary: *"new DNS filtering problems caused by Jamf Protect's
  block lists for open DNS... the edns.wandera.com domain was
  causing connectivity issues, and Patrick was instructed to exempt
  his computer from Jamf Protect's configuration."*
- Same case: *"Wandera, which was intercepting them, potentially
  explaining why certain configurations did not work as expected.
  Patrick noted that the settings were applied on a device basis
  rather than a browser basis."*

CALIBRATION CAVEAT: this detector was authored without a real Mac
failure-mode bundle. The Wandera-EDNS / Jamf Protect signatures
come from observed Zoom AI Summary quotes; the pfctl / sysext
signatures are inferred from Apple's API surfaces. When a real Mac
failure bundle becomes available, run it through this detector and
calibrate the regex selectivity. False positives should be rare
(the signatures are specific endpoint names / process names), but
false negatives are likely until the detector sees real failures.

Distinct from other detectors:
- ``endpoint_fw_av`` is Windows-only (gated via applies_to_os).
- ``ai_cli_pin`` / ``rmm_agent_pin`` overlap on the Mac side if the
  Mac is the SSL-inspection endpoint, but those detectors emit
  policy-edit recommendations; this detector emits EDR-coexistence
  recommendations.
"""

from __future__ import annotations

import re
from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# Wandera EDNS DNS sinkhole. Installed by Jamf Protect's "Open DNS
# threat" feature; intercepts DNS queries on the Mac and substitutes
# its own responses for blocked categories. The Example Tenant J case
# confirmed this as a recurring source of "ZIA disabled but DNS
# still broken" Mac reports.
_RE_WANDERA_EDNS = re.compile(
    r"\bedns\.wandera\.com\b", re.IGNORECASE,
)

# Cisco Umbrella's Mac DNS endpoint. Same shape as Wandera --
# intercepts DNS for security categories.
_RE_UMBRELLA_DNS = re.compile(
    r"\b(?:dns|gateway)\.umbrella\.com\b"
    r"|\b208\.67\.22[02]\.22[02]\b",  # 208.67.222.222 / 220.220
    re.IGNORECASE,
)

# Jamf Protect process / service identifier. Mac log lines that
# mention this process by name + an error are diagnostic of MDM
# interference.
_RE_JAMF_PROTECT = re.compile(
    r"\b(?:com\.jamf\.protect|jamfprotectd|JamfProtect)\b",
    re.IGNORECASE,
)

# Generic pf / packet-filter rule-engine line. Look for it co-located
# with ZCC process names or ports.
_RE_PFCTL_BLOCK = re.compile(
    r"\b(?:pfctl|pf)\b.*?\b(?:block|drop)\b",
    re.IGNORECASE,
)

# Application Firewall ``socketfilterfw`` activity. The block form
# appears in ``com.apple.alf`` log records and in ZCC's own log if
# ZCC notices it's been firewalled.
_RE_SOCKETFILTERFW_DENY = re.compile(
    r"socketfilterfw[^\n]{0,80}?(?:deny|block|reject)",
    re.IGNORECASE,
)

# System Extension load denial. macOS Catalina+ requires user (or
# MDM) approval for ZCC's system extensions; without it ZCC can't
# intercept traffic and the operator gets a misleading "ZCC isn't
# working" symptom.
_RE_SYSEXT_LOAD_DENIED = re.compile(
    r"SystemExtensionRequest.*?(?:denied|failed|rejected)"
    r"|com\.zscaler\.[a-z]+ext[^\n]{0,40}?(?:not (?:loaded|approved)"
    r"|denied|rejected|failed to (?:load|activate))",
    re.IGNORECASE,
)

# Network Extension framework's per-flow callback failures. ZCC on
# Mac uses NEFilterDataProvider; if it gets killed by the kernel
# (typically because it took too long in a callback) ZCC fails open.
_RE_NEFILTER_FAIL = re.compile(
    r"NEFilterDataProvider[^\n]{0,80}?"
    r"(?:terminated|killed|exited|failed|timeout)"
    r"|nesessionmanager[^\n]{0,80}?(?:error|fail|denied)",
    re.IGNORECASE,
)

# Cross-product DNS-blocker generics. Customers run all sorts of Mac
# MDM agents; these tend to share a "DNS hijacker" pattern.
_RE_DNS_SINKHOLE_GENERIC = re.compile(
    r"\b(?:nextdns\.io|dns\.cloudflare-?gateway|controld\.com|"
    r"adguard-dns\.com|nordvpn-dns)\b",
    re.IGNORECASE,
)


EVIDENCE_CAP = 10


# --- Detector ---------------------------------------------------------

@register
class FwAvMacErrorsDetector(IssueDetector):
    id = "endpoint_fw_av_mac"
    title = "macOS firewall / EDR / DNS-filter interference"
    sop_file = "endpoint_fw_av_mac.md"
    # Cross-suite: Mac firewall/EDR/DNS-filter interference affects
    # both ZIA and ZPA tunnels equally.
    applies_to_suite = None
    applies_to_os = ("macos",)
    wants_tray_logs = True  # Mac auth-side signals live in tray logs

    # --- IssueDetector overrides ----------------------------------

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        self._maybe_emit(record, summary)

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        # Mac auth / tray-side signatures share signature shapes with
        # tunnel-log records, so route both through the same emitter.
        self._maybe_emit(record, summary)

    def _maybe_emit(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # 1. Wandera EDNS interception (Jamf Protect's DNS sinkhole).
        if _RE_WANDERA_EDNS.search(msg):
            f = self._bucket(
                "WANDERA_EDNS_INTERCEPT",
                Severity.CRITICAL,
                "Wandera EDNS is intercepting DNS on this Mac",
                (
                    "ZCC's log mentions ``edns.wandera.com``, which "
                    "is the DNS sinkhole installed by Jamf Protect's "
                    "'Open DNS threat' feature. It intercepts DNS "
                    "queries on the Mac and substitutes its own "
                    "responses for blocked categories -- and crucially, "
                    "it operates **independently of ZIA**: even when "
                    "the user disables Zscaler, DNS filtering can "
                    "still break with this in place.\n\n"
                    "From the Example Tenant J JumpCloud case: *'new DNS "
                    "filtering problems caused by Jamf Protect's "
                    "block lists for open DNS... Patrick was "
                    "instructed to exempt his computer from Jamf "
                    "Protect's configuration.'*\n\n"
                    "Fix path: exempt the Mac from Jamf Protect's "
                    "Open DNS configuration, OR reconfigure Jamf "
                    "Protect to NOT sinkhole the affected category. "
                    "Coordinate with the customer's Jamf admin."
                ),
                sop_anchor="#wandera-edns-intercept",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 2. Cisco Umbrella DNS on Mac. Same class of problem as
        # Wandera but a different vendor.
        if _RE_UMBRELLA_DNS.search(msg):
            f = self._bucket(
                "UMBRELLA_DNS_INTERCEPT",
                Severity.WARNING,
                "Cisco Umbrella DNS interception on this Mac",
                (
                    "ZCC's log mentions Cisco Umbrella's DNS endpoint "
                    "(`dns.umbrella.com` / `208.67.222.222`). Umbrella "
                    "intercepts DNS on the device and applies its own "
                    "category rules. When deployed alongside ZIA, "
                    "the two products can fight over DNS resolution "
                    "with confusing results.\n\n"
                    "Fix path: scope Umbrella to bypass corporate "
                    "domains (or disable on managed-Mac fleet if ZIA "
                    "is the primary security tool). Per the runbook, "
                    "Umbrella + ZIA on the same machine is a "
                    "supported-but-not-recommended posture."
                ),
                sop_anchor="#umbrella-dns-intercept",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 3. Jamf Protect process activity (broader than just EDNS).
        if _RE_JAMF_PROTECT.search(msg):
            f = self._bucket(
                "JAMF_PROTECT_ACTIVITY",
                Severity.INFO,
                "Jamf Protect is active on this Mac",
                (
                    "Jamf Protect (com.jamf.protect / jamfprotectd) "
                    "is running on the device. This is INFO-level "
                    "context unless paired with another finding -- "
                    "if you see ``WANDERA_EDNS_INTERCEPT`` above, "
                    "this is the cause. If you don't, Jamf Protect "
                    "is still worth noting because it manages "
                    "Mac System Extension approval and can silently "
                    "deny ZCC's sysext load."
                ),
                sop_anchor="#jamf-protect-activity",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 4. pfctl / pf block rule activity.
        if _RE_PFCTL_BLOCK.search(msg):
            f = self._bucket(
                "PFCTL_BLOCK",
                Severity.WARNING,
                "pfctl block / drop activity mentioned in ZCC logs",
                (
                    "macOS's packet filter (`pfctl`) is recording "
                    "block or drop actions. On a managed Mac the "
                    "ruleset usually comes from MDM (Jamf, Kandji, "
                    "Mosyle) or a security product (CrowdStrike, "
                    "SentinelOne Mac agent). When ZCC's outbound "
                    "traffic is matched by a block rule, traffic "
                    "interception breaks silently.\n\n"
                    "Triage: `sudo pfctl -sa` on the affected Mac to "
                    "list active rules. If the customer's MDM is "
                    "managing pf, coordinate with the MDM admin to "
                    "exempt ZCC component paths "
                    "(`/Library/Application Support/Zscaler/`, "
                    "`/Applications/Zscaler.app/`)."
                ),
                sop_anchor="#pfctl-block",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 5. socketfilterfw (app firewall) deny.
        if _RE_SOCKETFILTERFW_DENY.search(msg):
            f = self._bucket(
                "SOCKETFILTERFW_DENY",
                Severity.WARNING,
                "macOS application firewall denied a ZCC connection",
                (
                    "macOS's application firewall (`socketfilterfw`) "
                    "denied a connection involving a ZCC component. "
                    "Triage: check whether ZCC's components are on "
                    "the firewall's allow-list:\n\n"
                    "```\n"
                    "sudo socketfilterfw --getappblocked\n"
                    "  /Applications/Zscaler.app/Contents/MacOS/Zscaler\n"
                    "```\n\n"
                    "If blocked, add via:\n\n"
                    "```\n"
                    "sudo socketfilterfw --add\n"
                    "  /Applications/Zscaler.app/Contents/MacOS/Zscaler\n"
                    "sudo socketfilterfw --unblockapp\n"
                    "  /Applications/Zscaler.app/Contents/MacOS/Zscaler\n"
                    "```"
                ),
                sop_anchor="#socketfilterfw-deny",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 6. System Extension load denied.
        if _RE_SYSEXT_LOAD_DENIED.search(msg):
            f = self._bucket(
                "SYSEXT_LOAD_DENIED",
                Severity.CRITICAL,
                "ZCC System Extension was denied by macOS / MDM",
                (
                    "ZCC requires a macOS System Extension to "
                    "intercept traffic. The system extension load "
                    "was denied -- either by the user (didn't click "
                    "'Allow' in System Preferences → Security & "
                    "Privacy) or, more commonly on managed fleets, "
                    "by the MDM not pre-approving Zscaler's team ID.\n\n"
                    "Without an active System Extension, ZCC cannot "
                    "intercept traffic at all -- the user sees ZCC "
                    "running but every connection bypasses it.\n\n"
                    "Fix path (MDM-managed fleet): push a System "
                    "Extension Allow-list payload that pre-approves "
                    "Zscaler's team ID `7HQV7WHV9D` and the "
                    "extension bundle IDs:\n"
                    "  - `com.zscaler.tunnel`\n"
                    "  - `com.zscaler.security`\n"
                    "  - `com.zscaler.networkextension`\n"
                    "Then `systemextensionsctl list` should show "
                    "`[activated enabled]` for each."
                ),
                sop_anchor="#sysext-load-denied",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 7. NEFilterDataProvider failure -- kernel killed the
        # network-extension callback because it was too slow.
        if _RE_NEFILTER_FAIL.search(msg):
            f = self._bucket(
                "NEFILTER_PROVIDER_FAILURE",
                Severity.CRITICAL,
                "ZCC's NEFilterDataProvider exited / was terminated",
                (
                    "macOS's NEFilterDataProvider (the kernel-side "
                    "Network Extension that ZCC uses to intercept "
                    "traffic) was terminated or exited. After that "
                    "ZCC fails open and traffic bypasses inspection.\n\n"
                    "Common causes:\n"
                    "  - Kernel killed the callback for taking too "
                    "    long (typically pegged at ~100ms);\n"
                    "  - Another security product's NetworkExtension "
                    "    raced ZCC and got priority;\n"
                    "  - macOS version upgrade rejected the signed "
                    "    extension and it never re-activated.\n\n"
                    "Triage: `systemextensionsctl list` should show "
                    "the Zscaler extensions as `[activated enabled]`. "
                    "If they're `[terminated]` or absent, re-approve "
                    "via MDM and restart."
                ),
                sop_anchor="#nefilter-provider-failure",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 8. Generic non-ZCC DNS sinkhole (NextDNS / ControlD / etc.)
        if _RE_DNS_SINKHOLE_GENERIC.search(msg):
            f = self._bucket(
                "DNS_SINKHOLE_GENERIC",
                Severity.WARNING,
                "Third-party DNS sinkhole present on this Mac",
                (
                    "ZCC's log mentions a third-party DNS sinkhole "
                    "(NextDNS / ControlD / AdGuard DNS / Cloudflare "
                    "Gateway). Same risk profile as Wandera or "
                    "Umbrella -- this product can intercept DNS "
                    "queries even with ZIA disabled, leading to "
                    "confusing 'sometimes works' connectivity reports.\n\n"
                    "Fix path: coordinate with the customer's IT "
                    "team about whether the third-party DNS "
                    "intercept is intended; if not, configure the "
                    "Mac to use ZIA's DNS resolver and remove the "
                    "competing config profile."
                ),
                sop_anchor="#dns-sinkhole-generic",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        # In addition to whatever the log-scan emitted, consume the
        # structured ``AppInfo.log`` plist data that ``summary.py``
        # populates on Mac bundles. This is the authoritative source
        # for SYSEXT_LOAD_DENIED and JAMF_PROTECT_ACTIVITY -- the log-
        # line regexes earlier in this file are a backstop for log-
        # emitted variants of the same signals.
        #
        # Grounded by the 2026-05-19 multi-bundle calibration: both
        # Example Tenant J Macs (User D M4 + User E M3 Max) showed
        # ``pktfilter [activated waiting for user]`` in the plist
        # ``SystemExtensions`` text but no equivalent log line. The
        # detector previously missed both real findings.
        self._finalize_from_plist(summary)
        return list(self._buckets.values())

    def _finalize_from_plist(self, summary: BundleSummary) -> None:
        """Drain ``summary.sysext_states`` / ``summary.mac_firewall``
        / ``summary.running_security_products`` / ``summary.mac_primary_dns``
        into findings buckets.
        """
        # 1. SYSEXT_LOAD_DENIED from sysext_states.
        # ZCC's two extensions: com.zscaler.zscaler.TRPTunnel and
        # com.zscaler.zscaler.pktfilter. Either one not in a healthy
        # "activated enabled" state is a real misconfiguration.
        for ext in summary.sysext_states:
            bid = ext.get("bundle_id", "")
            state = ext.get("state", "")
            if "zscaler" not in bid.lower():
                continue
            if state == "activated enabled":
                continue  # healthy
            if "terminated waiting to uninstall" in state:
                # Pre-existing old version being cleaned up after an
                # upgrade -- benign, expected on update.
                continue
            # Anything else (waiting for user, terminated, denied,
            # failed) is the misconfiguration we want to surface.
            severity = (
                Severity.CRITICAL
                if "waiting for user" in state
                or "denied" in state
                or "rejected" in state
                or state.startswith("activated waiting")
                else Severity.WARNING
            )
            f = self._bucket(
                "SYSEXT_LOAD_DENIED",
                severity,
                (
                    f"Zscaler System Extension ``{ext.get('name', '?')}``"
                    f" not enabled (state: ``{state}``)"
                ),
                (
                    f"The macOS System Extension ``{bid}`` "
                    f"(version ``{ext.get('version', '?')}``) is in "
                    f"state ``{state}`` rather than ``activated "
                    f"enabled``. ZCC needs BOTH ``TRPTunnel`` AND "
                    f"``pktfilter`` extensions activated for "
                    f"interception to work properly; if either is "
                    f"stuck, traffic interception is degraded "
                    f"silently and the user-visible tray status can "
                    f"still appear connected.\n\n"
                    f"Fix path (MDM-managed fleet): push a System "
                    f"Extension Allow-list payload that pre-approves "
                    f"Zscaler's team ID ``PCBCQZJ7S7`` and the "
                    f"bundle IDs ``com.zscaler.zscaler.TRPTunnel`` "
                    f"and ``com.zscaler.zscaler.pktfilter``. Then "
                    f"``systemextensionsctl list`` should show both "
                    f"as ``[activated enabled]``.\n\n"
                    f"Grounded by the 2026-05-19 multi-bundle "
                    f"calibration: this pattern was observed on "
                    f"2-of-2 Example Tenant J Macs (User D M4 + User E "
                    f"M3 Max) -- a fleet-wide MDM misconfiguration."
                ),
                sop_anchor="#sysext-load-denied",
            )
            # Synthetic evidence -- no LogLine, but the finding text
            # carries all the diagnostic info the operator needs.

        # 2. JAMF_PROTECT_ACTIVITY from sysext_states + running procs.
        # Use sysext_states first (more reliable) and fall back to
        # process-list filter only if no Jamf-Protect sysext line
        # appeared.
        jamf_active = any(
            "jamf.protect" in ext.get("bundle_id", "").lower()
            and ext.get("state", "") == "activated enabled"
            for ext in summary.sysext_states
        )
        if not jamf_active:
            jamf_active = any(
                "jamf.protect" in p.lower() or "jamfprotectd" in p.lower()
                for p in summary.running_security_products
            )
        if jamf_active:
            self._bucket(
                "JAMF_PROTECT_ACTIVITY",
                Severity.INFO,
                "Jamf Protect is active on this Mac",
                (
                    "Jamf Protect's endpoint-security extension is "
                    "active on this device. INFO-level context: pair "
                    "this with any DNS / sysext / firewall findings "
                    "above. Jamf Protect manages MDM-side System "
                    "Extension approval; if ZCC's ``pktfilter`` is "
                    "stuck waiting for user, the Jamf MDM payload is "
                    "the right place to fix it."
                ),
                sop_anchor="#jamf-protect-activity",
            )

        # 3. macOS application firewall state -- when disabled, surface
        # as INFO; when ZCC components appear in the blocked-apps list,
        # surface as WARN (the SOCKETFILTERFW_DENY case but read from
        # plist rather than log).
        if summary.mac_firewall:
            state_text = (summary.mac_firewall.get("firewallState")
                          or "").lower()
            if "firewall is disabled" in state_text:
                self._bucket(
                    "MAC_FIREWALL_DISABLED",
                    Severity.INFO,
                    "macOS application firewall is disabled",
                    (
                        "The macOS built-in application firewall "
                        "(``socketfilterfw``) is disabled. INFO-level "
                        "context: ZCC traffic is not being filtered "
                        "by the OS-level firewall. This is benign on "
                        "its own; relevant only if other findings "
                        "implicate the firewall."
                    ),
                    sop_anchor="#socketfilterfw-deny",
                )
            apps_text = (summary.mac_firewall.get("firewallAppsList")
                         or "")
            if "Zscaler" in apps_text and (
                "block" in apps_text.lower() or "deny" in apps_text.lower()
            ):
                self._bucket(
                    "SOCKETFILTERFW_DENY",
                    Severity.WARNING,
                    "ZCC component is on macOS firewall block-list",
                    (
                        "The macOS application firewall has a Zscaler "
                        "component on its block / deny list. This "
                        "blocks ZCC's outbound connections at the "
                        "OS layer.\n\n"
                        "Fix: ``sudo socketfilterfw --add "
                        "/Applications/Zscaler.app/Contents/MacOS/"
                        "Zscaler && sudo socketfilterfw --unblockapp "
                        "/Applications/Zscaler.app/Contents/MacOS/"
                        "Zscaler``."
                    ),
                    sop_anchor="#socketfilterfw-deny",
                )

        # 4. DNS sinkhole detection from plist nameserver.
        # If the primary nameserver is a known sinkhole IP, surface
        # WARN. Catalogue is conservative.
        if summary.mac_primary_dns:
            ns = summary.mac_primary_dns
            # Wandera EDNS (Jamf Protect): documented IPs vary by
            # region. Public-DNS-sinkhole catalogue:
            sinkhole_map = {
                "208.67.222.222": "Cisco Umbrella",
                "208.67.220.220": "Cisco Umbrella",
                "94.140.14.14": "AdGuard DNS",
                "94.140.15.15": "AdGuard DNS",
                "76.76.19.19": "ControlD",
                "76.76.2.0": "ControlD",
            }
            vendor = sinkhole_map.get(ns)
            if vendor:
                self._bucket(
                    "DNS_SINKHOLE_GENERIC",
                    Severity.WARNING,
                    (
                        f"Mac primary DNS is a third-party sinkhole "
                        f"({vendor} at ``{ns}``)"
                    ),
                    (
                        f"The device's primary DNS resolver "
                        f"(``nameserver[0] = {ns}``) is a known "
                        f"third-party sinkhole ({vendor}). This "
                        f"product can intercept DNS queries even "
                        f"with ZIA disabled, leading to confusing "
                        f"'sometimes works' connectivity reports."
                    ),
                    sop_anchor="#dns-sinkhole-generic",
                )
