"""
Base class for RCA synthesizers.

A synthesizer takes:
  - the BundleSummary (re-derived facts, never carried forward)
  - the Findings emitted by ONE detector (the issue being diagnosed)
  - the correlator outputs (Phase 48 — Modern Standby, mtunnel lifecycle,
    polling cadence, service starts)

and produces an RCAReport.

Each synthesizer subclass overrides `_build_*` hooks to fill in the
sections it has data for. Common scaffolding (header, bundle facts,
provenance) is provided here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..summary import BundleSummary
from ..issues import Finding
from .model import (
    BundleFact,
    ContributingFactor,
    Evidence,
    EvidenceStrength,
    FixRecommendation,
    ImpactMetric,
    OpenQuestion,
    RCAReport,
    RootCause,
    TimelineEvent,
    VerificationStep,
)

log = logging.getLogger(__name__)


class RCASynthesizer:
    """Subclass per issue. Override the `_build_*` methods you have data for."""

    # Override in subclass.
    synthesizer_id: str = "base"
    synthesizer_version: str = "0"
    issue_title: str = "Issue"

    def __init__(
        self,
        summary: BundleSummary,
        findings: List[Finding],
        correlators: Optional[Dict[str, Any]] = None,
    ):
        self.summary = summary
        self.findings = findings
        self.correlators = correlators or {}
        self.bm = getattr(summary, "bundle_meta", {}) or {}

    # ─────────────────────────────────────────────────── public entry
    def build(self) -> RCAReport:
        """Build the full RCAReport. Most subclasses do not override this
        — instead, override the `_build_*` hooks."""
        report = RCAReport(
            customer=self._customer(),
            user=self._user(),
            device=self._device(),
            bundle_filename=self._bundle_filename(),
            bundle_exported=self._bundle_exported(),
            zcc_version=self._zcc_version(),
            report_date=self._report_date(),
            severity_label=self._severity_label(),
            # Pull the issue_title from the synthesizer's class
            # attribute. Each subclass sets this (e.g. ZpaReauthSynthesizer.
            # issue_title = "ZPA Re-Authentication Disruptions").
            issue_title=getattr(
                type(self), "issue_title", ""
            ) or self.synthesizer_id,
            synthesizer_id=self.synthesizer_id,
            synthesizer_version=self.synthesizer_version,
        )

        # Each hook may add to the report — kept separate for testability.
        report.summary_paragraphs = self._build_summary()
        report.timeline = self._build_timeline()
        report.root_causes = self._build_root_causes()
        report.contributing_factors = self._build_contributing_factors()
        report.evidence_quotes = self._build_evidence_quotes()
        report.impact_metrics = self._build_impact_metrics()
        report.fixes = self._build_fixes()
        report.verifications = self._build_verifications()
        report.open_questions = self._build_open_questions()
        report.bundle_facts = self._build_bundle_facts()
        return report

    # ─────────────────────────────────────────────────── header derivation
    # These read from BundleSummary, which is re-derived per bundle. NO
    # carry-forward between bundles. If a value isn't in the bundle,
    # return a string that makes that obvious.

    def _customer(self) -> str:
        return self.bm.get("customer_name") or "(customer)"

    def _user(self) -> str:
        # Prefer UPN from partner-login extractor; fall back to device user.
        upn = self.bm.get("partner_login_upn") or self.bm.get("user_upn")
        if upn:
            return str(upn)
        return self.bm.get("user_name") or "(user)"

    def _device(self) -> str:
        host = getattr(self.summary, "hostname", None) or self.bm.get("hostname")
        os_name = self.bm.get("os_name") or getattr(self.summary, "os", None) or ""
        ram = self.bm.get("ram_total_mb")
        ram_str = ""
        if ram:
            try:
                ram_gb = round(float(ram) / 1024)
                ram_str = f", {ram_gb} GB"
            except (TypeError, ValueError):
                pass
        if host and os_name:
            return f"{host} ({os_name}{ram_str})"
        return host or "(device)"

    def _bundle_filename(self) -> str:
        return self.bm.get("bundle_filename") or "(bundle)"

    def _bundle_exported(self) -> str:
        return self.bm.get("bundle_export_time_str") or "(unknown)"

    def _zcc_version(self) -> str:
        versions = getattr(self.summary, "versions", None) or self.bm.get("zcc_versions")
        if isinstance(versions, dict):
            return versions.get("tunnel") or versions.get("tray") or next(iter(versions.values()), "(unknown)")
        return str(versions or self.bm.get("zcc_version") or "(unknown)")

    def _report_date(self) -> str:
        return datetime.now().strftime("%Y-%m-%d")

    def _severity_label(self) -> str:
        # Synthesizers can override based on classification mix
        return ""

    # ─────────────────────────────────────────────────── section hooks
    # Override in subclass. Default returns empty list/dict so the
    # renderer simply skips the section.

    def _build_summary(self) -> List[str]:
        return []

    def _build_timeline(self) -> List[TimelineEvent]:
        return []

    def _build_root_causes(self) -> List[RootCause]:
        return []

    def _build_contributing_factors(self) -> List[ContributingFactor]:
        return []

    def _build_evidence_quotes(self):  # -> List[Tuple[str, List[str]]]
        return []

    def _build_impact_metrics(self) -> List[ImpactMetric]:
        return []

    def _build_fixes(self) -> List[FixRecommendation]:
        return []

    def _build_verifications(self) -> List[VerificationStep]:
        return []

    def _build_open_questions(self) -> List[OpenQuestion]:
        return []

    def _build_bundle_facts(self) -> List[BundleFact]:
        """Default: emit the re-derived universal facts every RCA needs."""
        facts: List[BundleFact] = []
        bm = self.bm
        sm = self.summary

        def add(label: str, value, source: Optional[str] = None) -> None:
            if value:
                facts.append(BundleFact(label=label, value=str(value), source=source))

        add("ZIA cloud", bm.get("zia_cloud") or getattr(sm, "cloud", None), "AppInfo.xml / log banner")
        add("ZPA broker (data path)", bm.get("zpa_broker_active"), "ZSATunnel zpnBrokerRedirectCb")
        add("SAML SP (auth path)", bm.get("zpa_saml_sp"), "ZSATunnel SAML redirect")
        add("Entra tenant ID", bm.get("idp_tenant_id"), "ZSATray SAML URL")
        add("User identity", bm.get("os_user_identity") or self._user(), "gpresult / AppInfo")
        add("Device join", bm.get("domain_join_status"), "gpresult")
        add("Boot time", bm.get("boot_time_str"), "AppInfo.xml")
        add("Log timezone (observed)", bm.get("log_tz_label"), "log line offset")
        return facts

    # ─────────────────────────────────────────────────── evidence helpers
    @staticmethod
    def quote(text: str, source_file: Optional[str] = None,
              line_no: Optional[int] = None,
              ts: Optional[datetime] = None) -> Evidence:
        return Evidence(
            text=text,
            strength=EvidenceStrength.DIRECT_QUOTE,
            source_file=source_file, line_no=line_no, ts=ts,
        )

    @staticmethod
    def inference(text: str, refs: Optional[List[Evidence]] = None) -> Evidence:
        return Evidence(
            text=text, strength=EvidenceStrength.LOG_INFERENCE,
            source_refs=refs or [],
        )

    @staticmethod
    def hypothesis(text: str) -> Evidence:
        return Evidence(text=text, strength=EvidenceStrength.HYPOTHESIS)

    @staticmethod
    def customer_stated(text: str) -> Evidence:
        return Evidence(text=text, strength=EvidenceStrength.CUSTOMER_STATED)
