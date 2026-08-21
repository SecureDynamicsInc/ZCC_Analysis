"""
endpoint_fw_av RCA synthesizer (Phase 49g, 2026-06-24).

Single synthesizer that handles BOTH the Windows (endpoint_fw_av) and
macOS (endpoint_fw_av_mac) detectors. The buckets differ by platform
but the customer-facing fix recommendations have the same shape: identify
the conflicting endpoint product, exempt ZCC, restart ZCC.

Finding code → bucket:

Windows:
  LWF_DRIVER_NOT_RUNNING, FILTER_DRIVER_FAIL  → driver_load (CRITICAL)
  HEALTHCHECK_TO_100_64_FAILED                → healthcheck_fw_block (CRITICAL)
  FIREWALL_RETRIES_EXPIRED, FIREWALL_BLOCK_ERROR_STATE → fw_block (CRITICAL)
  PORT_9000_BIND_FAIL                         → port_bind (CRITICAL)
  WFP_BAD_HEALTH                              → wfp_health (CRITICAL)
  SECURITY_PRODUCTS_PRESENT                   → info_only (INFO)

macOS:
  SYSEXT_LOAD_DENIED, NEFILTER_PROVIDER_FAILURE → sysext_load (CRITICAL)
  PFCTL_BLOCK, SOCKETFILTERFW_DENY            → mac_fw_block (WARNING)
  WANDERA_EDNS_INTERCEPT, UMBRELLA_DNS_INTERCEPT,
  DNS_SINKHOLE_GENERIC                        → dns_sinkhole (varies)
  JAMF_PROTECT_ACTIVITY                       → mdm_activity (INFO)
  MAC_FIREWALL_DISABLED                       → info_only (INFO)
"""

from __future__ import annotations

from datetime import timezone
from typing import Any, Dict, List, Optional

from ..model import (
    ContributingFactor, Evidence, EvidenceStrength, EventClassification,
    FixHorizon, FixRecommendation, ImpactMetric, OpenQuestion,
    RootCause, TimelineEvent,
)
from ..synthesizer_base import RCASynthesizer


_BUCKETS = {
    # Windows
    "LWF_DRIVER_NOT_RUNNING": "driver_load",
    "FILTER_DRIVER_FAIL": "driver_load",
    "HEALTHCHECK_TO_100_64_FAILED": "healthcheck_fw_block",
    "FIREWALL_RETRIES_EXPIRED": "fw_block",
    "FIREWALL_BLOCK_ERROR_STATE": "fw_block",
    "PORT_9000_BIND_FAIL": "port_bind",
    "WFP_BAD_HEALTH": "wfp_health",
    "SECURITY_PRODUCTS_PRESENT": "info_only",
    # macOS
    "SYSEXT_LOAD_DENIED": "sysext_load",
    "NEFILTER_PROVIDER_FAILURE": "sysext_load",
    "PFCTL_BLOCK": "mac_fw_block",
    "SOCKETFILTERFW_DENY": "mac_fw_block",
    "WANDERA_EDNS_INTERCEPT": "dns_sinkhole",
    "UMBRELLA_DNS_INTERCEPT": "dns_sinkhole",
    "DNS_SINKHOLE_GENERIC": "dns_sinkhole",
    "JAMF_PROTECT_ACTIVITY": "mdm_activity",
    "MAC_FIREWALL_DISABLED": "info_only",
}


def _bucket_for_code(code: str) -> str:
    return _BUCKETS.get((code or "").upper(), "other")


class EndpointFwAvSynthesizer(RCASynthesizer):
    """Single synthesizer for endpoint_fw_av (Windows) and
    endpoint_fw_av_mac (macOS). Same registered class, different
    detector IDs route to it via the registry."""

    synthesizer_id = "endpoint_fw_av"
    synthesizer_version = "1.0"
    issue_title = "Endpoint Firewall / AV / EDR Interference"

    def __init__(self, summary, findings, correlators):
        super().__init__(summary, findings, correlators)
        self._buckets: Dict[str, List] = {}
        for f in self.findings:
            b = _bucket_for_code(getattr(f, "code", "") or "")
            self._buckets.setdefault(b, []).append(f)
        # Platform fingerprint — used to tailor fix language. Pull from
        # the OS summary; default to "unknown" so fix language stays
        # generic.
        self._platform = self._infer_platform()

    def _infer_platform(self) -> str:
        os_info = self.summary.os or {}
        family = (os_info.get("family") or "").lower()
        if "windows" in family or "win" in family:
            return "windows"
        if "darwin" in family or "mac" in family:
            return "macos"
        return "unknown"

    def _build_timeline(self) -> List[TimelineEvent]:
        result = []
        for f in self.findings:
            tr = getattr(f, "time_range", None)
            if not tr or tr[0] is None:
                continue
            ts_local = tr[0]
            try:
                ts_utc = ts_local.astimezone(timezone.utc)
            except (TypeError, ValueError):
                ts_utc = ts_local
            duration = None
            if tr[1] is not None:
                duration = (tr[1] - tr[0]).total_seconds()
            code = (getattr(f, "code", "") or "").upper()
            # Phase 58e-H6 (2026-07-08): endpoint-fw/AV events don't
            # inherently tell us whether the user was actively working.
            # Info-only / MDM-activity are true background noise; keep
            # everything else as UNKNOWN so power-change correlation can
            # promote to MID_WORK when it fires in-session. Prior code
            # unconditionally classified as MID_WORK, over-escalating
            # boot-time driver bringup events.
            classification = EventClassification.UNKNOWN
            if _BUCKETS.get(code) in ("info_only", "mdm_activity"):
                classification = EventClassification.POST_STANDBY_BACKGROUND_BLIP
            result.append(TimelineEvent(
                ts_local=ts_local, ts_utc=ts_utc,
                classification=classification,
                recovery_seconds=duration,
                tunnel_impact=getattr(f, "title", "") or code,
            ))
        result.sort(key=lambda e: e.ts_local)
        return result

    def _build_summary(self) -> List[str]:
        if not self.findings:
            return ["No endpoint-firewall/AV findings emitted for this bundle."]
        n = len(self.findings)
        paras = [
            f"The endpoint_fw_av detector emitted **{n} finding(s)** "
            f"on this {self._platform} bundle, spanning these buckets: "
            f"`{', '.join(self._buckets.keys())}`."
        ]
        if "driver_load" in self._buckets or "sysext_load" in self._buckets:
            paras.append(
                "**Kernel-level component load failed** — the Zscaler "
                f"{'LWF driver' if self._platform == 'windows' else 'system extension'} "
                "could not load. Without it, ZCC cannot intercept any "
                "network traffic. Almost always caused by an "
                "EDR/MDM product blocking kernel loads or rejecting "
                "the driver/extension signature."
            )
        if "healthcheck_fw_block" in self._buckets:
            paras.append(
                "**ZCC's health-check traffic blocked** — ZCC tried to "
                "reach its internal health-check endpoints "
                "(100.64.0.0/24) and was denied at the network layer. "
                "Diagnostic: `Find-NetRoute -RemoteIPAddress 100.64.0.6` "
                "in PowerShell will confirm whether the route goes via "
                "the physical NIC or a stale VPN adapter. The latter is "
                "the canonical signature of a third-party VPN client "
                "stealing the 100.64.0.0/24 range."
            )
        if "port_bind" in self._buckets:
            paras.append(
                "**Port 9000 bind failure** — ZCC's local listener "
                "couldn't bind. Another process is already on the port, "
                "or an inbound firewall rule denies the bind."
            )
        if "dns_sinkhole" in self._buckets:
            paras.append(
                "**DNS sinkhole detected** (macOS) — Wandera, Umbrella, "
                "or another endpoint security product is intercepting "
                "DNS queries. This conflicts with ZCC's tunnel-time DNS "
                "resolution. Customer must coordinate the two products."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes = []
        n = 0

        if "driver_load" in self._buckets or "sysext_load" in self._buckets:
            n += 1
            comp_name = ("LWF kernel driver" if self._platform == "windows"
                         else "system extension")
            causes.append(RootCause(
                id=f"RC-{n}",
                title=f"Zscaler {comp_name} not loaded",
                mechanism=(
                    f"The {comp_name} is the component that intercepts "
                    "network traffic for ZCC. Without it, traffic flows "
                    "AROUND ZCC and policy is not enforced. Failure "
                    "to load is almost always caused by an EDR product "
                    "(CrowdStrike, SentinelOne, Defender ATP, Carbon "
                    "Black, etc.) blocking the load, or by a code-"
                    "integrity policy rejecting the signature."
                ),
            ))

        if "healthcheck_fw_block" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="Health-check traffic blocked at network layer",
                mechanism=(
                    "ZCC's checkTunTcpEchoServerUpImpl probe to "
                    "100.64.0.6/8 on ports 80/9090/443/8080 fails. The "
                    "100.64.0.0/24 (CGNAT) range is ZCC's internal "
                    "loopback for tunnel-health validation. Two common "
                    "causes: (1) third-party VPN adapter is the "
                    "best-match route for 100.64.0.0/24 (run "
                    "`Find-NetRoute` to confirm), or (2) host firewall "
                    "/ EDR product is blocking ZCC's outbound to those "
                    "addresses."
                ),
            ))

        if "fw_block" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="Windows Filtering Platform / firewall blocking ZCC",
                mechanism=(
                    "WFP callout retried blocked traffic until it gave "
                    "up. ZCC's own filter is healthy; something outside "
                    "ZCC's filter is rejecting its outbound traffic. "
                    "Almost certainly a host firewall rule or an EDR "
                    "with anti-tampering policy."
                ),
            ))

        if "port_bind" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="ZCC couldn't bind local listener (port 9000)",
                mechanism=(
                    "ZCC's DNS proxy + TUN-Proxy listener requires "
                    "port 9000 (configurable). Bind failure means "
                    "either another process is on port 9000 (run "
                    "`netstat -ano | findstr :9000`) or an inbound "
                    "firewall rule denies the bind."
                ),
            ))

        if "wfp_health" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="WFP filter health check failed",
                mechanism=(
                    "Zscaler's [WFP]: Bad health log signature means "
                    "ZCC's filter passed installation but its runtime "
                    "health check (filter still attached, callout still "
                    "responding) failed. This typically follows an "
                    "EDR product de-registering ZCC's WFP filter — "
                    "investigate the AV/EDR's anti-tampering events."
                ),
            ))

        if "dns_sinkhole" in self._buckets:
            n += 1
            distinct = sorted({
                getattr(f, "code", "") for f in self._buckets["dns_sinkhole"]
            })
            causes.append(RootCause(
                id=f"RC-{n}",
                title=f"DNS being intercepted by endpoint product ({len(distinct)} type(s))",
                mechanism=(
                    f"DNS sinkhole signatures observed: "
                    f"{', '.join(distinct)}. An endpoint security "
                    "product is intercepting DNS queries before ZCC "
                    "sees them. ZCC's per-tunnel DNS policy and Domain "
                    "Bypass logic don't apply because the queries are "
                    "answered upstream. Customer must coordinate the "
                    "two products — usually by configuring the endpoint "
                    "product to exempt Zscaler DNS resolution."
                ),
            ))

        if "mac_fw_block" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="macOS pfctl / socketfilterfw blocking ZCC",
                mechanism=(
                    "macOS Packet Filter (pfctl) or the Application "
                    "Firewall (socketfilterfw) is denying ZCC's "
                    "traffic. Customer admin needs to add an explicit "
                    "allow rule for Zscaler processes."
                ),
            ))

        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        factors = []
        if "info_only" in self._buckets:
            # SECURITY_PRODUCTS_PRESENT — context for the engineer
            sec = self._buckets["info_only"]
            factors.append(ContributingFactor(
                id="CF-1",
                title=(
                    f"Endpoint security products detected on this device "
                    f"({len(sec)} finding(s))"
                ),
                body=(
                    "When ZCC findings indicate driver/firewall issues, "
                    "the SECURITY_PRODUCTS_PRESENT finding identifies "
                    "which AV/EDR products are installed — the prime "
                    "suspects for the conflict. Review the finding "
                    "evidence for the specific product names."
                ),
                is_hypothesis=False,
            ))
        return factors

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        if not self.findings:
            return []
        return [
            ImpactMetric("Total findings", str(len(self.findings))),
            ImpactMetric("Platform", self._platform),
            ImpactMetric(
                "Driver / SystemExtension load failures",
                str(len(self._buckets.get("driver_load", []))
                    + len(self._buckets.get("sysext_load", []))),
                highlight=(
                    len(self._buckets.get("driver_load", [])) > 0
                    or len(self._buckets.get("sysext_load", [])) > 0
                ),
            ),
            ImpactMetric(
                "Health-check / firewall blocks",
                str(len(self._buckets.get("healthcheck_fw_block", []))
                    + len(self._buckets.get("fw_block", []))
                    + len(self._buckets.get("mac_fw_block", []))),
            ),
            ImpactMetric(
                "DNS sinkhole events (macOS)",
                str(len(self._buckets.get("dns_sinkhole", []))),
            ),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes = []
        if "driver_load" in self._buckets or "sysext_load" in self._buckets:
            comp = "LWF driver" if self._platform == "windows" else "system extension"
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="Endpoint security admin",
                title=f"Add Zscaler {comp} to EDR/AV exception list",
                body="The conflicting endpoint product needs to allow ZCC's kernel components:",
                bullets=[
                    "Identify the EDR/AV product from SECURITY_PRODUCTS_PRESENT (CF-1)",
                    "Whitelist Zscaler binaries: ZSAService.exe, ZSATray.exe, ZSATrayManager.exe (Windows) or com.zscaler.* bundles (macOS)",
                    "On macOS: ensure system extension is approved in Settings → Privacy & Security",
                    "Restart ZCC service after exception is applied",
                ],
                effect="ZCC's kernel component loads on next start.",
            ))
        if "healthcheck_fw_block" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="IT support / Network admin",
                title="Free 100.64.0.0/24 routing for ZCC",
                body="Two sub-causes — diagnose first:",
                bullets=[
                    "Run `Find-NetRoute -RemoteIPAddress 100.64.0.6` (PowerShell)",
                    "If route shows a non-physical adapter (VPN client): disable/uninstall the VPN client",
                    "If route shows Wi-Fi/Ethernet but still fails: host firewall is blocking outbound — add ZCC rules",
                ],
                effect="Health-check probes succeed, tunnel reaches healthy state.",
            ))
        if "port_bind" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="IT support",
                title="Free port 9000 for ZCC's local listener",
                body=(
                    "Identify the process holding port 9000 "
                    "(`netstat -ano | findstr :9000` on Windows) and "
                    "either move that process or reconfigure ZCC's "
                    "listener port in the Forwarding Profile."
                ),
            ))
        if "dns_sinkhole" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.SHORT,
                owner="Endpoint security admin",
                title="Coordinate Zscaler DNS with endpoint product",
                body=(
                    "The endpoint product needs to be configured to "
                    "exempt Zscaler tunnel DNS. Each vendor has a "
                    "different mechanism — Wandera, Umbrella, etc."
                ),
            ))
        return fixes

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if "driver_load" in self._buckets or "sysext_load" in self._buckets:
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    "Which EDR / AV product(s) are deployed on the "
                    "affected device? See SECURITY_PRODUCTS_PRESENT "
                    "finding for the list."
                ),
                why_it_matters=(
                    "Each vendor has a different exemption workflow."
                ),
            ))
        if "healthcheck_fw_block" in self._buckets:
            questions.append(OpenQuestion(
                id="Q2",
                question=(
                    "Is a third-party VPN client (Cisco AnyConnect, "
                    "GlobalProtect, etc.) installed on the affected "
                    "device? Often the cause of 100.64.0.0/24 route "
                    "hijack."
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no endpoint-fw/AV findings"
        if "driver_load" in self._buckets or "sysext_load" in self._buckets:
            return "High — Zscaler kernel component not loading; no traffic interception"
        if "healthcheck_fw_block" in self._buckets or "fw_block" in self._buckets:
            return "High — host firewall blocking ZCC; tunnel can't reach healthy state"
        if "dns_sinkhole" in self._buckets:
            return f"Medium — DNS sinkhole conflicts ({len(self._buckets['dns_sinkhole'])} event(s))"
        return f"Medium — {len(self.findings)} endpoint-fw/AV finding(s)"
