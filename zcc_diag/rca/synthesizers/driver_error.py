"""
driver_error RCA synthesizer (Phase 49i, 2026-06-24).

Single synthesizer for BOTH driver_error (Windows LWF kernel driver)
and driver_error_mac (macOS system extensions + kexts). Same shape as
endpoint_fw_av — class handles both detectors via platform inference.

Finding code → bucket:

Windows:
  LWF_UNABLE_TO_LOAD            → load_failure
  LWF_INITIAL_CHECK_FAILED      → load_failure
  LIGHTWEIGHT_FILTER_NOT_LOADED → load_failure
  TRAY_DRIVER_ERROR             → tray_state (user-visible Driver Error state)

macOS:
  MAC_SYSEXT_LOAD_FAIL          → load_failure
  MAC_SYSEXT_NOT_APPROVED       → approval (user/admin must approve in System Settings)
  MAC_NETWORK_EXTENSION_FAIL    → load_failure
  MAC_KEXT_LOAD_FAIL            → load_failure  (legacy kext)
  MAC_TRAY_SYSEXT_ERROR_STATE   → tray_state
  MAC_SYSEXT_STATE::<bundle_id> → sysext_state (one per failing extension)
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
    "LWF_UNABLE_TO_LOAD": "load_failure",
    "LWF_INITIAL_CHECK_FAILED": "load_failure",
    "LIGHTWEIGHT_FILTER_NOT_LOADED": "load_failure",
    "TRAY_DRIVER_ERROR": "tray_state",
    # macOS
    "MAC_SYSEXT_LOAD_FAIL": "load_failure",
    "MAC_SYSEXT_NOT_APPROVED": "approval",
    "MAC_NETWORK_EXTENSION_FAIL": "load_failure",
    "MAC_KEXT_LOAD_FAIL": "load_failure",
    "MAC_TRAY_SYSEXT_ERROR_STATE": "tray_state",
}


def _bucket_for_code(code: str) -> str:
    code = (code or "").upper()
    if code in _BUCKETS:
        return _BUCKETS[code]
    # Per-bundle-ID sysext state findings
    if code.startswith("MAC_SYSEXT_STATE::"):
        return "sysext_state"
    return "other"


class DriverErrorSynthesizer(RCASynthesizer):
    synthesizer_id = "driver_error"
    synthesizer_version = "1.0"
    issue_title = "Driver / System Extension Load Failure"

    def __init__(self, summary, findings, correlators):
        super().__init__(summary, findings, correlators)
        self._buckets: Dict[str, List] = {}
        for f in self.findings:
            b = _bucket_for_code(getattr(f, "code", "") or "")
            self._buckets.setdefault(b, []).append(f)
        self._platform = self._infer_platform()

    def _infer_platform(self) -> str:
        os_info = self.summary.os or {}
        family = (os_info.get("family") or "").lower()
        if "windows" in family or "win" in family:
            return "windows"
        if "darwin" in family or "mac" in family:
            return "macos"
        # Fallback: infer from finding codes themselves
        for f in self.findings:
            code = (getattr(f, "code", "") or "").upper()
            if code.startswith("MAC_"):
                return "macos"
            if code.startswith("LWF_") or code == "LIGHTWEIGHT_FILTER_NOT_LOADED":
                return "windows"
        return "unknown"

    def _component_name(self) -> str:
        return ("LWF kernel driver" if self._platform == "windows"
                else "system extension")

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
            # Phase 58e-H6 (2026-07-08): a driver/kext failure disrupts
            # the tunnel but we don't know whether the user was actively
            # working. Use UNKNOWN; the caller can enrich with
            # power_change data if available. Prior blanket MID_WORK
            # inflated severity on background driver hiccups.
            classification = EventClassification.UNKNOWN
            result.append(TimelineEvent(
                ts_local=ts_local, ts_utc=ts_utc,
                classification=classification,
                recovery_seconds=duration,
                tunnel_impact=getattr(f, "title", "")
                              or getattr(f, "code", ""),
            ))
        result.sort(key=lambda e: e.ts_local)
        return result

    def _build_summary(self) -> List[str]:
        if not self.findings:
            return [f"No driver/{self._component_name()} errors emitted."]
        n = len(self.findings)
        bucket_names = list(self._buckets.keys())
        comp = self._component_name()
        paras = [
            f"The driver_error detector emitted **{n} finding(s)** on "
            f"this {self._platform} bundle, spanning these buckets: "
            f"`{', '.join(bucket_names)}`."
        ]
        if "load_failure" in self._buckets:
            paras.append(
                f"**{comp.capitalize()} failed to load.** Without it, "
                f"ZCC cannot intercept network traffic and the tunnel "
                f"is dead. This is a hard failure — the user sees no "
                f"ZCC functionality at all (or fail-open traffic that "
                f"bypasses ZIA / ZPA policy)."
            )
        if "approval" in self._buckets:
            paras.append(
                "**System extension waiting for user approval** "
                "(macOS only). The user/admin must approve the Zscaler "
                "system extension in System Settings → Privacy & "
                "Security before it can load. Until then, ZCC can't "
                "intercept traffic."
            )
        if "tray_state" in self._buckets:
            paras.append(
                "**Tray shows 'Driver Error' state** — the user-visible "
                "indication that something is wrong. Cross-reference "
                "with the load_failure findings to identify the "
                "underlying cause."
            )
        return paras

    def _build_root_causes(self) -> List[RootCause]:
        causes = []
        n = 0
        comp = self._component_name()

        if "load_failure" in self._buckets:
            n += 1
            ev = []
            for f in self._buckets["load_failure"][:1]:
                for rec in (getattr(f, "evidence", []) or [])[:2]:
                    ev.append(Evidence(
                        text=(getattr(rec, "raw", None)
                              or rec.message or "").strip()[:200],
                        strength=EvidenceStrength.DIRECT_QUOTE,
                        source_file=(rec.source_path.name
                                     if hasattr(rec.source_path, "name")
                                     else None),
                        ts=getattr(rec, "timestamp", None),
                    ))
            if self._platform == "windows":
                mech = (
                    "The LWF kernel driver did not load. Per the ZCC "
                    "Traffic Forwarding runbook, the common causes "
                    "(in decreasing frequency):\n\n"
                    "1. **EDR / AV product blocking driver load.** "
                    "Modern endpoint protection often quarantines or "
                    "denies kernel-mode drivers from third-party "
                    "vendors. Look at the SECURITY_PRODUCTS_PRESENT "
                    "finding from endpoint_fw_av for the suspect list.\n"
                    "2. **DriverStore corruption.** "
                    "C:\\Windows\\System32\\DriverStore has a corrupted "
                    "or missing copy of the LWF driver.\n"
                    "3. **Missing registry entries** for the ZCC "
                    "driver service (HKLM\\SYSTEM\\CurrentControlSet\\"
                    "Services\\ZSALWFDriver).\n"
                    "4. **Windows code-integrity policy** rejecting "
                    "the driver signature after a Windows update."
                )
            else:
                mech = (
                    "The Zscaler system extension did not load. Per "
                    "the macOS-side runbook:\n\n"
                    "1. **Not approved by user/admin** — system "
                    "extensions require explicit approval at "
                    "System Settings → Privacy & Security. MDM can "
                    "pre-approve via configuration profile.\n"
                    "2. **Conflicting endpoint security product** "
                    "(Jamf Protect, CrowdStrike) blocking the load.\n"
                    "3. **Legacy kext fallback failing** — older ZCC "
                    "versions used kexts; if a kext is still "
                    "registered, macOS may refuse to load both.\n"
                    "4. **System Integrity Protection** edge cases "
                    "on Apple Silicon."
                )
            causes.append(RootCause(
                id=f"RC-{n}",
                title=f"{comp.capitalize()} failed to load",
                mechanism=mech,
                evidence=ev,
            ))

        if "approval" in self._buckets:
            n += 1
            causes.append(RootCause(
                id=f"RC-{n}",
                title="macOS system extension waiting for approval",
                mechanism=(
                    "macOS requires the user (or an MDM-pushed config "
                    "profile) to explicitly approve a system extension "
                    "before it activates. The Zscaler system extension "
                    "is in the 'waiting for user' state. Until "
                    "approval, ZCC has no traffic-intercept component."
                ),
            ))

        if "sysext_state" in self._buckets:
            n += 1
            bundle_ids = sorted({
                getattr(f, "code", "").replace("MAC_SYSEXT_STATE::", "")
                .replace("_", ".")
                for f in self._buckets["sysext_state"]
            })
            causes.append(RootCause(
                id=f"RC-{n}",
                title=(
                    f"Specific system extension(s) in bad state — "
                    f"{', '.join(bundle_ids)}"
                ),
                mechanism=(
                    "The SystemExtensions plist reports one or more "
                    "Zscaler-owned bundles in a non-activated state "
                    "('activated waiting for user', 'terminated', etc.). "
                    "Each bundle ID has a specific role (pktfilter, "
                    "netextension, etc.) — see the per-finding "
                    "description for the role and the precise state."
                ),
            ))

        return causes

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        factors = []
        # Cross-reference: if endpoint_fw_av has driver_load findings too,
        # the cause is the same; mention it.
        all_findings = self.bm.get("_all_findings_for_correlation") or []
        # Simpler heuristic: if SECURITY_PRODUCTS_PRESENT shows up in
        # this synthesizer's correlator-shared context, mention it.
        # For v1 we just add a generic CF.
        if "load_failure" in self._buckets:
            factors.append(ContributingFactor(
                id="CF-1",
                title="Likely shared cause with endpoint_fw_av driver_load findings",
                body=(
                    "If the endpoint_fw_av detector ALSO emitted "
                    "driver_load findings on this bundle, the same EDR "
                    "/ AV product is the cause. Investigate the "
                    "SECURITY_PRODUCTS_PRESENT finding for the suspect "
                    "list — exempting Zscaler binaries from the "
                    "endpoint product typically clears both."
                ),
                is_hypothesis=False,
            ))
        return factors

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        if not self.findings:
            return []
        return [
            ImpactMetric("Total driver_error findings", str(len(self.findings))),
            ImpactMetric("Platform", self._platform),
            ImpactMetric(
                f"{self._component_name().capitalize()} load failures",
                str(len(self._buckets.get("load_failure", []))),
                highlight=(len(self._buckets.get("load_failure", [])) > 0),
            ),
            ImpactMetric(
                "Tray 'Driver Error' state events",
                str(len(self._buckets.get("tray_state", []))),
            ),
            ImpactMetric(
                "Per-extension state findings (macOS)",
                str(len(self._buckets.get("sysext_state", []))),
            ),
        ]

    def _build_fixes(self) -> List[FixRecommendation]:
        fixes = []
        comp = self._component_name()
        if "approval" in self._buckets:
            fixes.append(FixRecommendation(
                horizon=FixHorizon.IMMEDIATE,
                owner="User / IT support",
                title="Approve the Zscaler system extension",
                body="On the affected macOS device:",
                bullets=[
                    "Open System Settings → Privacy & Security",
                    "Scroll to 'Allow applications from these developers' / 'System Extensions'",
                    "Approve the Zscaler entry",
                    "If MDM-managed: push a configuration profile that pre-approves the extension",
                ],
                effect="System extension activates and ZCC can intercept traffic.",
            ))
        if "load_failure" in self._buckets:
            if self._platform == "windows":
                fixes.append(FixRecommendation(
                    horizon=FixHorizon.IMMEDIATE,
                    owner="IT support / Endpoint security admin",
                    title="Resolve LWF driver load failure",
                    body="Triage in order:",
                    bullets=[
                        "Check EDR / AV exception list — add Zscaler binaries (ZSAService.exe, ZSALWFDriver.sys)",
                        "If recently updated Windows: reinstall ZCC to push the driver back into the current DriverStore",
                        "Confirm HKLM\\SYSTEM\\CurrentControlSet\\Services\\ZSALWFDriver exists",
                        "Check Windows Event Viewer → System log for driver-load failures (filter on source 'Service Control Manager' or 'CodeIntegrity')",
                    ],
                    effect="LWF driver loads on next ZCC service start.",
                ))
            else:
                fixes.append(FixRecommendation(
                    horizon=FixHorizon.IMMEDIATE,
                    owner="IT support / Endpoint security admin",
                    title="Resolve macOS system extension load failure",
                    body="Triage in order:",
                    bullets=[
                        "Check approval state (see 'approval' fix if applicable)",
                        "Remove any leftover Zscaler kext: `sudo kextstat | grep zscaler` then `sudo kextunload`",
                        "Check Jamf Protect / CrowdStrike exclusion list",
                        "On Apple Silicon, verify reduced-security mode if a kext is needed",
                    ],
                ))
        return fixes

    def _build_open_questions(self) -> List[OpenQuestion]:
        questions = []
        if "load_failure" in self._buckets:
            questions.append(OpenQuestion(
                id="Q1",
                question=(
                    "Which EDR / AV product(s) are deployed on the "
                    "affected device? (See endpoint_fw_av's "
                    "SECURITY_PRODUCTS_PRESENT finding if available.)"
                ),
            ))
            if self._platform == "windows":
                questions.append(OpenQuestion(
                    id="Q2",
                    question=(
                        "Was a Windows feature update or major .NET / "
                        "VC++ runtime update installed recently? Driver "
                        "code-integrity policy changes ride with these."
                    ),
                ))
        if "approval" in self._buckets:
            questions.append(OpenQuestion(
                id="Q3",
                question=(
                    "Is this device under MDM management? If yes, can "
                    "the MDM admin push a configuration profile that "
                    "pre-approves the Zscaler system extension?"
                ),
            ))
        return questions

    def _severity_label(self) -> str:
        if not self.findings:
            return "Low — no driver_error findings"
        if "load_failure" in self._buckets:
            return f"High — {self._component_name()} not loaded; ZCC has no traffic interception"
        if "approval" in self._buckets:
            return "High — system extension awaiting approval; no traffic interception"
        return f"Medium — {len(self.findings)} driver_error finding(s)"
