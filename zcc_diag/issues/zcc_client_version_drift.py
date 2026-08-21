"""
Detector: ZCC client version drift.

Compares each component's reported version against a "known recent
GA" baseline. Older versions get an INFO-level finding so the
operator can rule out client-version-specific bugs before deeper
triage.

Grounded by WestStar 2-04 Zoom AI Summary (verbatim): *"TimG was on
version 141 while Dan was on 202... determined the problem might be
machine-specific rather than a general issue."* Two coworkers on
dramatically different ZCC versions produced different ZCC behaviour
on the same network -- recognising this immediately would have saved
the engineer hours.

Components watched: ZSATunnel, ZSAService, ZSATray, ZSAUpm, UPMService
Controller (Mac), and the synthetic "ZCC" key populated by the
macOS plist backstop.

This detector reads from ``summary.versions.components`` (already
populated by ``summary.py`` from the App Version banners). No tunnel-
log feed needed.

Baseline policy: this file ships a baseline string keyed on the
build's release date. When new GA versions appear, update the
``_BASELINE_GA`` map. Default tolerance: 10 builds; anything older
fires a WARN, anything 50+ builds older fires a CRIT.
"""

from __future__ import annotations

from typing import List, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Known-GA baseline as of 2026-05-19. Update when Zscaler ships a new
# GA. Keys must match ``summary.versions.components`` keys (case-
# sensitive). The synthetic "ZCC" key is populated by the macOS plist
# backstop in summary.py:651.
#
# Tuples are (major, minor, patch, build).
#
# History:
#   2026-05-19: bumped from 4.7.0.202 -> 4.8.0.156 after multi-bundle
#               calibration confirmed 4.8.0.156 is in production at
#               Example Tenant C. See
#               zcc_diag_zia_multi_bundle_calibration_v3_2026-05-19.md.
_BASELINE_GA = {
    "ZSATunnel": (4, 8, 0, 156),
    "ZSAService": (4, 8, 0, 156),
    "ZSATray": (4, 8, 0, 156),
    "ZSAUpm": (4, 8, 0, 156),
    "UPMServiceController": (4, 8, 0, 156),  # macOS-only
    "ZCC": (4, 8, 0, 156),                   # macOS plist key
}

# How many builds behind triggers each severity.
_WARN_BUILDS_BEHIND = 10
_CRIT_BUILDS_BEHIND = 50


def _parse_version(s: str) -> Tuple[int, ...]:
    """Parse ``4.6.0.168`` -> (4, 6, 0, 168). Returns empty tuple on
    failure -- caller treats missing parses as "skip"."""
    parts: List[int] = []
    for piece in s.strip().split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            return tuple()
    return tuple(parts)


def _builds_behind(have: Tuple[int, ...], want: Tuple[int, ...]) -> int:
    """Return how many builds ``have`` is behind ``want``.
    - 0 if ``have`` >= ``want`` (newer-or-equal is fine -- forward-
      compatible so we don't false-positive on bumped clients).
    - direct build-number subtraction if major/minor/patch agree.
    - 999 (>> CRIT threshold) if major/minor/patch differ AND ``have``
      is older, so the operator examines manually.

    Was previously broken: returned 999 unconditionally when major/
    minor differed, which fired CRIT on every healthy newer client.
    Confirmed by 5-of-5 false-positive CRITs in the 2026-05-19 multi-
    bundle calibration.
    """
    if not have or not want:
        return 0  # can't compare
    # Forward-compat: newer-or-equal is silent.
    if tuple(have) >= tuple(want):
        return 0
    # Same major/minor/patch -- compare the build number.
    if have[:3] == want[:3]:
        if len(have) < 4 or len(want) < 4:
            return 0
        return max(0, want[3] - have[3])
    # Older major/minor/patch -- definitely behind, treat as severe.
    return 999


@register
class ZccClientVersionDriftDetector(IssueDetector):
    id = "zcc_client_version_drift"
    title = "ZCC client version drift"
    sop_file = "zcc_client_version_drift.md"
    # Cross-suite: ZCC version applies to every component regardless
    # of which Zscaler service is enrolled.
    applies_to_suite = None

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        findings: List[Finding] = []
        components = summary.versions.components or {}

        # Aggregate the worst offender across all components -- one
        # finding total, not one per component (since they should
        # usually be in lockstep).
        worst_component = None
        worst_behind = 0
        worst_have = None
        worst_want = None
        for comp, ver_str in components.items():
            baseline = _BASELINE_GA.get(comp)
            if baseline is None:
                continue
            have = _parse_version(ver_str)
            behind = _builds_behind(have, baseline)
            if behind > worst_behind:
                worst_behind = behind
                worst_component = comp
                worst_have = ver_str
                worst_want = ".".join(str(x) for x in baseline)

        if worst_behind >= _CRIT_BUILDS_BEHIND:
            findings.append(Finding(
                code="ZCC_VERSION_FAR_BEHIND",
                severity=Severity.CRITICAL,
                title=(
                    f"{worst_component} is {worst_behind} builds behind "
                    f"current GA ({worst_have} vs {worst_want})"
                ),
                description=(
                    f"The ZCC component ``{worst_component}`` reported "
                    f"version ``{worst_have}`` but the detector's "
                    f"known-GA baseline is ``{worst_want}``. That's "
                    f"a {worst_behind}-build gap.\n\n"
                    f"Update the client BEFORE doing deeper triage. "
                    f"Old ZCC versions accumulate fixed bugs (auth "
                    f"flakiness, certificate-store mismatches, "
                    f"driver-version drift) that look like "
                    f"infrastructure issues but disappear on update.\n\n"
                    f"From the WestStar 2-04 case: an engineer spent "
                    f"hours diagnosing what turned out to be a "
                    f"v141-vs-v202 client-version mismatch."
                ),
                sop_anchor="#zcc-version-far-behind",
            ))
        elif worst_behind >= _WARN_BUILDS_BEHIND:
            findings.append(Finding(
                code="ZCC_VERSION_BEHIND",
                severity=Severity.WARNING,
                title=(
                    f"{worst_component} is {worst_behind} builds behind "
                    f"current GA ({worst_have} vs {worst_want})"
                ),
                description=(
                    f"The ZCC component ``{worst_component}`` reported "
                    f"version ``{worst_have}`` but the detector's "
                    f"known-GA baseline is ``{worst_want}``. Consider "
                    f"updating the client before declaring an "
                    f"infrastructure or policy fault."
                ),
                sop_anchor="#zcc-version-behind",
            ))

        return findings

    # No tunnel-log feeding needed.
    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        return
