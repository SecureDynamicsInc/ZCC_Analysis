"""
Detector: ZPA machine-tunnel config absent.

When ZCC is configured to use Machine Tunnel (for pre-logon AD /
Kerberos coverage) but the machine-tunnel config file is missing or
unreadable, three related error strings appear in tunnel logs:

  * ``ERR machine tunnel, tunnel config file doesn't exist``
  * ``Failed to read the machine tunnel config data``
  * ``Failed to disable credential provider``

The third string is the user-facing consequence: with no machine-
tunnel config, ZCC cannot disable the third-party credential provider
it would otherwise replace on the lock screen, breaking pre-logon
Active Directory authentication on domain-joined Windows endpoints.

Bundle mining (example-tenant-c, today-2026-05-19, plus a second
windows-17mb bundle) confirms this as a recurring real-world pattern
on Windows endpoints that *should* have machine-tunnel enabled but
don't.

Mac and Linux endpoints route this differently (network extensions on
Mac, no machine-tunnel concept on Linux), so this detector is gated to
``applies_to_os = ("windows",)``.

Common root causes:

  1. **Machine Tunnel feature isn't enabled in the customer's ZIA/ZPA
     tenant** -- but the ZCC client expects it (forwarding profile
     mismatch).
  2. **The machine-tunnel config push failed** -- the device is online
     but never received the latest forwarding profile.
  3. **A previous uninstall left orphaned config paths** -- the file
     was renamed or deleted on the endpoint.

The detector fires WARNING (not CRITICAL) because the user-facing
impact depends on whether the customer intends to use machine-tunnel:
some sites deliberately leave it off. The SOP walks through how to
distinguish the two cases.
"""

from __future__ import annotations

import re
from typing import List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


_RE_CONFIG_MISSING = re.compile(
    r"machine tunnel,?\s*tunnel config file doesn't exist",
    re.IGNORECASE,
)
_RE_CONFIG_UNREADABLE = re.compile(
    r"Failed to read the machine tunnel config data",
    re.IGNORECASE,
)
_RE_CREDPROVIDER_FAIL = re.compile(
    r"Failed to disable credential provider",
    re.IGNORECASE,
)

EVIDENCE_CAP = 8


@register
class ZpaMachineTunnelConfigMissingDetector(IssueDetector):
    id = "zpa_machine_tunnel_config_missing"
    title = "ZPA Machine Tunnel config missing"
    sop_file = "zpa_machine_tunnel_config_missing.md"
    # ZPA-only + Windows-only: machine-tunnel is a Windows-credential-
    # provider feature wired to ZPA enrollment.
    applies_to_suite = ("zpa",)
    applies_to_os = ("windows",)
    # Each of the three regexes requires "machine tunnel" or
    # "credential provider" as a literal substring (case-insensitive).
    # Lowercase the prematch tokens; we'd need the multiplexer to
    # lowercase the message too -- not worth it. Use case-sensitive
    # tokens that appear in the actual ZCC log emissions.
    prematch_substrings = (
        "machine tunnel",
        "credential provider",
    )

    def __init__(self) -> None:
        super().__init__()
        self._missing_count = 0
        self._unreadable_count = 0
        self._credprov_count = 0
        self._sample_records: List[LogLine] = []

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        matched = False
        msg = record.message
        if _RE_CONFIG_MISSING.search(msg):
            self._missing_count += 1
            matched = True
        if _RE_CONFIG_UNREADABLE.search(msg):
            self._unreadable_count += 1
            matched = True
        if _RE_CREDPROVIDER_FAIL.search(msg):
            self._credprov_count += 1
            matched = True
        if matched and len(self._sample_records) < EVIDENCE_CAP:
            self._sample_records.append(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        total = (
            self._missing_count
            + self._unreadable_count
            + self._credprov_count
        )
        if total == 0:
            return []

        # Severity: if credential-provider disable specifically failed,
        # the user-facing impact (broken lock-screen / pre-logon AD)
        # is real -> WARNING. If only the bare "config file doesn't
        # exist" line fires (and credprov is silent), the customer is
        # almost certainly not using machine-tunnel at all -> INFO.
        if self._credprov_count > 0:
            severity = Severity.WARNING
            severity_tag = "credential-provider disable failed"
        else:
            severity = Severity.INFO
            severity_tag = "config absent, no credential-provider impact"

        f = Finding(
            code="ZPA_MACHINE_TUNNEL_CONFIG_MISSING",
            severity=severity,
            title=(
                f"ZPA Machine Tunnel config missing "
                f"({severity_tag})"
            ),
            description=(
                f"ZCC tried to load the Machine Tunnel forwarding "
                f"profile and could not, across "
                f"{self._missing_count} 'file doesn't exist', "
                f"{self._unreadable_count} 'failed to read', and "
                f"{self._credprov_count} 'failed to disable "
                f"credential provider' log lines.\n\n"
                f"Machine Tunnel provides pre-logon AD/Kerberos "
                f"coverage on Windows domain-joined endpoints. If the "
                f"customer intends to use it (pre-logon SSO, AD GPO "
                f"on first boot, lock-screen sign-in over ZPA), this "
                f"is breaking that use case.\n\n"
                f"If the customer doesn't use machine-tunnel, the "
                f"config-absent lines are expected noise -- but the "
                f"forwarding profile should still be cleaned up to "
                f"stop ZCC from logging these errors every cycle. "
                f"See SOP for the diagnostic flow."
            ),
            sop_anchor="#zpa-machine-tunnel-config-missing",
        )
        for rec in self._sample_records:
            f.add_evidence(rec, cap=EVIDENCE_CAP)
        return [f]
