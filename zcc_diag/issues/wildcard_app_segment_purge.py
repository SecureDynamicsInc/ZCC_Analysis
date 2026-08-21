"""
Detector: Overly-permissive bypass policy (originally wildcard-literal
detection, now indirect via runtime bypass cache size).

DATA-SOURCE NOTE (rewritten 2026-05-19): the original detector walked
``summary.forwarding_profile`` looking for wildcard literals (``*``,
``0.0.0.0/0``). Real bundles confirmed that JSON contains only
TUNNEL transport config -- no bypass list at all -- so wildcard
literals in the customer's policy aren't visible from the bundle.

The detector now uses an indirect signal: the **size** of
``summary.bypass_cache``. A healthy enterprise bypass policy yields
~50-200 hosts in the runtime cache (Example Tenant C bundles A+B: 85
and 97 unique hosts). When the cache grows much larger, it suggests
the customer has overly-permissive bypass rules -- typically
wildcards on large platforms (S3, Azure storage) that match
thousands of hostnames at runtime.

Original grounding still applies:
- Classic Home (2026-05): operator kept a wildcard in a ZPA app
  segment as a stopgap.
- Example Tenant H (maintainer guidance): warned against wildcarding large
  platforms.
- Example Tenant D (2026-05): bypass list had 221k wildcard entries.

Without policy-config parsing we can't catch wildcards that match 0
hosts (the dot-vs-star case the Classic Home stopgap created -- the
``bypass_misconfiguration`` detector covers that via cert-error
attribution). What we CAN catch is the inflated-cache symptom.
"""

from __future__ import annotations

from typing import List

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Thresholds for bypass-cache size signal. Calibrated from
# real-bundle data:
#   - Example Tenant C bundles: 85 / 97 unique hosts (healthy)
#   - The Example Tenant D 221k wildcard case would produce a runtime
#     cache far above WARN_THRESHOLD, possibly into thousands.
# Both numbers are conservative. Tighten when more grounding data is
# available.
_INFO_THRESHOLD = 300   # "starting to look broad"
_WARN_THRESHOLD = 1000  # "almost certainly over-permissive"


@register
class WildcardAppSegmentPurgeDetector(IssueDetector):
    id = "wildcard_app_segment_purge"
    title = "Bypass policy looks overly permissive"
    sop_file = "wildcard_app_segment_purge.md"
    # ZPA-only: bypass-list governance is meaningful only for ZPA
    # app-segment policy hygiene.
    applies_to_suite = ("zpa",)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        cache = summary.bypass_cache or []
        n = len(cache)

        if n >= _WARN_THRESHOLD:
            sample = ", ".join(cache[:8])
            return [Finding(
                code="BYPASS_CACHE_VERY_LARGE",
                severity=Severity.WARNING,
                title=(
                    f"Runtime bypass cache holds {n} hosts — "
                    f"policy likely over-permissive"
                ),
                description=(
                    f"ZCC's runtime bypass cache contains {n} unique "
                    f"hosts -- well above the typical 50-200 range "
                    f"seen on healthy enterprise bundles. This "
                    f"suggests the customer has wildcard rules that "
                    f"match very large platforms (Amazon S3, Azure "
                    f"storage, CloudFront), broad cloud-app "
                    f"categories on permissive policy, or "
                    f"accumulated stopgap exceptions that were never "
                    f"reverted.\n\n"
                    f"Audit candidates (first 8 of {n}): {sample}\n\n"
                    f"Action: review the customer's bypass / cloud-"
                    f"app-control policy for star-prefixed entries "
                    f"on large CDN / storage platforms. Per US "
                    f"Cloud observed guidance: avoid wildcarding "
                    f"large platforms like Amazon S3 or Azure "
                    f"storage."
                ),
                sop_anchor="#bypass-cache-very-large",
            )]
        elif n >= _INFO_THRESHOLD:
            sample = ", ".join(cache[:8])
            return [Finding(
                code="BYPASS_CACHE_LARGE",
                severity=Severity.INFO,
                title=(
                    f"Runtime bypass cache holds {n} hosts "
                    f"(reference range: 50-200)"
                ),
                description=(
                    f"ZCC's runtime bypass cache contains {n} unique "
                    f"hosts. This is larger than the typical "
                    f"enterprise range but not yet alarming. Worth "
                    f"a periodic audit if growth continues.\n\n"
                    f"Sample (first 8 of {n}): {sample}"
                ),
                sop_anchor="#bypass-cache-large",
            )]
        return []

    # No tunnel-log feeding needed -- summary already has the data.
    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        return
