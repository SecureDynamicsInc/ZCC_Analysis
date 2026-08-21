"""
RCA data model — the typed objects that synthesizers produce and the
renderers consume.

The model encodes the senior-engineer-grade RCA principles learned from
the Example Tenant A User A investigation:

  1. Every claim is tagged with EvidenceStrength.
  2. Root causes are separated from contributing factors.
  3. Each TimelineEvent has an EventClassification (pre-work fresh-start,
     mid-work active session severed, post-standby background blip, etc.)
     so the reader can see at a glance which events were user-visible.
  4. Fix recommendations are bucketed by horizon (Immediate / Short /
     Medium / Long) and each carries its own VerificationStep.
  5. BundleFacts are typed and intended to be RE-DERIVED per bundle —
     never carried forward.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────── evidence

class EvidenceStrength(str, Enum):
    """How confident we are in a claim — used to format and to gate
    whether the claim appears in customer-facing output as assertion
    vs hypothesis.

    DIRECT_QUOTE     — the claim IS the literal text of a log line. Strongest.
    LOG_INFERENCE    — claim derived from log evidence via reasoning
                       (e.g., "PID changed therefore service restarted").
    HYPOTHESIS       — symptoms FIT this explanation but the cause is
                       not directly visible. MUST be framed as hypothesis
                       in output. (e.g., "autoReauthForOnTrusted=false")
    CUSTOMER_STATED  — claim came from customer email/Slack and is
                       unverified. MUST be flagged as such.
    """
    DIRECT_QUOTE = "DIRECT_QUOTE"
    LOG_INFERENCE = "LOG_INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"
    CUSTOMER_STATED = "CUSTOMER_STATED"


@dataclass
class Evidence:
    """A single piece of evidence supporting a claim.

    For DIRECT_QUOTE evidence, `text` is the literal log line and
    `source_file` + `line_no` + `ts` are populated. For LOG_INFERENCE,
    `text` is the reasoning and `source_refs` lists the lines it derives
    from. For HYPOTHESIS / CUSTOMER_STATED, source_file may be None.
    """
    text: str
    strength: EvidenceStrength
    source_file: Optional[str] = None
    line_no: Optional[int] = None
    ts: Optional[datetime] = None
    # For LOG_INFERENCE, the upstream lines this conclusion was drawn from.
    source_refs: List["Evidence"] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────── timeline

class EventClassification(str, Enum):
    """How an auth/tunnel event affected the user — the key signal Example Tenant A
    was missing in v1 of the RCA."""

    PRE_WORK_FRESH_START = "PRE_WORK_FRESH_START"
    """Re-auth that happens just after a fresh service start. User can't
    have been mid-work because ZCC was just initialized."""

    MID_WORK_ACTIVE_SESSION_SEVERED = "MID_WORK_ACTIVE_SESSION_SEVERED"
    """Re-auth that tore down N>0 in-flight mtunnels. Direct user pain."""

    POST_STANDBY_BACKGROUND_BLIP = "POST_STANDBY_BACKGROUND_BLIP"
    """Re-auth that fired after Modern Standby exit, surfaced only when
    the next background poll (e.g., Citrix Workspace 15-min) tried to
    use ZPA. User may not have perceived it."""

    POST_STANDBY_FOREGROUND_BLIP = "POST_STANDBY_FOREGROUND_BLIP"
    """Re-auth after Modern Standby exit where the user was actively
    using ZPA at the time of disruption."""

    IDP_FORCED_REAUTH = "IDP_FORCED_REAUTH"
    """Re-auth driven by IdP Sign-in Frequency rather than sleep."""

    UNKNOWN = "UNKNOWN"


@dataclass
class TimelineEvent:
    """One row in the RCA timeline table."""
    ts_local: datetime              # log wall-clock (carries tz)
    ts_utc: datetime                # always tz-aware UTC
    classification: EventClassification
    recovery_seconds: Optional[float] = None
    tunnel_impact: str = ""         # human-readable: "5 mtunnels CLOSED_FROM_ASSISTANT"
    mtunnels_severed: int = 0       # active sessions ZCC tore down
    mtunnels_rejected: int = 0      # broker setup rejections during recovery
    sleep_duration_seconds: Optional[float] = None  # for post-standby events
    evidence: List[Evidence] = field(default_factory=list)

    @property
    def recovery_text(self) -> str:
        if self.recovery_seconds is None:
            return "—"
        s = self.recovery_seconds
        if s < 60:
            return f"{s:.1f} s"
        mins, secs = divmod(s, 60)
        return f"{int(mins)} m {secs:.0f} s"

    @property
    def severity_emoji(self) -> str:
        """Visual marker for the timeline table."""
        return {
            EventClassification.PRE_WORK_FRESH_START: "🟢",
            EventClassification.MID_WORK_ACTIVE_SESSION_SEVERED: "🔴",
            EventClassification.POST_STANDBY_FOREGROUND_BLIP: "🟠",
            EventClassification.POST_STANDBY_BACKGROUND_BLIP: "🟡",
            EventClassification.IDP_FORCED_REAUTH: "🟡",
            EventClassification.UNKNOWN: "⚪",
        }.get(self.classification, "⚪")


# ──────────────────────────────────────────────────────────────── causes

@dataclass
class RootCause:
    """A primary mechanism that drives the issue.

    Distinguished from ContributingFactor: a RC, if removed, would
    eliminate the issue. A CF amplifies or shapes it but is not the
    primary driver.
    """
    id: str                     # e.g. "RC-1"
    title: str
    mechanism: str              # how the symptom arises
    observed_sequence: List[str] = field(default_factory=list)  # bulletable
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class ContributingFactor:
    """Secondary condition that amplifies or shapes the root cause(s).

    is_hypothesis=True means the claim is symptom-consistent but not
    directly proven from the bundle — MUST be rendered with "symptoms
    suggest..." framing.
    """
    id: str                     # e.g. "CF-1"
    title: str
    body: str
    is_hypothesis: bool = False
    evidence: List[Evidence] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────── impact

@dataclass
class ImpactMetric:
    label: str
    value: str                  # already-formatted (e.g., "5 m 37 s")
    highlight: bool = False     # for "worst case" emphasis


# ──────────────────────────────────────────────────────────────── fix

class FixHorizon(str, Enum):
    IMMEDIATE = "IMMEDIATE"     # today, in the Zscaler console
    SHORT = "SHORT_TERM"        # this week (e.g., Entra admin)
    MEDIUM = "MEDIUM_TERM"      # this sprint (e.g., Intune)
    LONG = "LONG_TERM"          # next change window


@dataclass
class FixRecommendation:
    horizon: FixHorizon
    owner: str                  # who does this (e.g., "ZCC admin", "Entra admin")
    title: str
    body: str                   # multi-line description
    bullets: List[str] = field(default_factory=list)
    effect: str = ""            # what changes after this fix


@dataclass
class VerificationStep:
    """How to confirm a fix worked."""
    after_fix: str              # e.g., "After applying RC-1 fix"
    action: str                 # e.g., "Capture a fresh 48-h ZCC bundle"
    expected: str               # what "good" looks like


# ──────────────────────────────────────────────────────────────── open Q

@dataclass
class OpenQuestion:
    """A question the bundle cannot answer — for the customer to confirm."""
    id: str                     # e.g., "Q1"
    question: str
    why_it_matters: str = ""    # optional context


# ──────────────────────────────────────────────────────────────── facts

@dataclass
class BundleFact:
    """A single re-derived-per-bundle fact (never carried between bundles)."""
    label: str
    value: str
    source: Optional[str] = None   # e.g., "AppInfo.xml", "ZSATray log line 1"


# ──────────────────────────────────────────────────────────────── report

@dataclass
class RCAReport:
    """The full structured RCA. Serializers consume this."""
    # Header
    customer: str
    user: str
    device: str
    bundle_filename: str
    bundle_exported: str        # human string
    zcc_version: str
    report_date: str            # human string
    prepared_by: str = "SecureDynamics MSSP Engineering"
    severity_label: str = ""    # e.g., "High — active user impact, fix identified"
    # Human title for the issue being analysed (e.g., "ZPA Re-Authentication
    # Disruptions"). Populated by the synthesizer's class attribute in
    # RCASynthesizer.build(). Used by the UI sidebar to label each report
    # in the picker. Defaults to the synthesizer_id when empty.
    issue_title: str = ""

    # Body sections (all optional — synthesizer fills what it has)
    summary_paragraphs: List[str] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    root_causes: List[RootCause] = field(default_factory=list)
    contributing_factors: List[ContributingFactor] = field(default_factory=list)
    evidence_quotes: List[Tuple[str, List[str]]] = field(default_factory=list)
    """Free-form 'Evidence' section — list of (heading, bullet_lines)."""
    impact_metrics: List[ImpactMetric] = field(default_factory=list)
    fixes: List[FixRecommendation] = field(default_factory=list)
    verifications: List[VerificationStep] = field(default_factory=list)
    open_questions: List[OpenQuestion] = field(default_factory=list)
    bundle_facts: List[BundleFact] = field(default_factory=list)

    # Provenance — what synthesizer / version produced this
    synthesizer_id: str = ""
    synthesizer_version: str = ""

    def to_markdown(self, view: str = "brief") -> str:
        """Delegate to the markdown renderer at the requested verbosity.

        ``view`` accepts "brief" (default — chat/Slack), "standard"
        (ticket reply / escalation), or "full" (formal docx).
        """
        from .markdown import render_markdown, RCAView
        return render_markdown(self, RCAView(view))
