"""
AAD Primary Refresh Token (PRT) availability detector.

Reverse-engineering audit finding H-1 (the highest-impact gap in the
Example Tenant A RCA): I recommended `autoReauthForOnTrusted=true` without
verifying the device can actually do silent SAML refresh. Silent
refresh requires an Azure AD Primary Refresh Token (PRT). The PRT is
present when the device is:

  - Entra-joined (was: Azure AD-joined), OR
  - Hybrid Entra-joined, OR
  - Workplace-joined (a user added a Work Account via Windows
    "Access work or school" settings)

A pure Workgroup-only / Standalone Workstation with no Work Account
attached has NO PRT. autoReauthForOnTrusted=true on such a device is a
no-op or worse — it'll fail back to the interactive path silently.

This detector scans ZSATray + ZSATrayManager logs for signals that ZCC
successfully obtained tokens from WAM (Web Account Manager — the
Windows component that brokers PRT-backed token acquisition):

  Positive signals (PRT present):
    - "WAM" or "wamCloudConnect" calls succeeding
    - "AcquireTokenSilent" succeeded with no interactive fallback
    - "primaryRefreshToken" or "PRT" appearing in tokens responses

  Negative signals (PRT likely absent):
    - "AcquireTokenInteractive" always invoked instead of Silent
    - "WAM_E_NO_ACCOUNT" or similar account-not-found errors
    - dsregcmd /status shown but WorkplaceJoined=NO + AzureAdJoined=NO
      + DomainJoined=NO

The detector returns a `PRTAvailability` with a confidence label so
the synthesizer can:

  - HIGH-confidence PRT present  →  recommend autoReauthForOnTrusted=true
  - LIKELY-absent PRT            →  recommend Entra device join FIRST,
                                    then autoReauthForOnTrusted=true
  - UNCERTAIN                    →  add as Open Question for customer
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, List, Optional

from ..log_parser import LogLine


class PRTConfidence(str, Enum):
    LIKELY_PRESENT = "LIKELY_PRESENT"
    LIKELY_ABSENT = "LIKELY_ABSENT"
    UNCERTAIN = "UNCERTAIN"


_RE_WAM_OK = re.compile(
    r"(wamCloudConnect|WAM\s+token|AcquireTokenSilent.*success|"
    r"primaryRefreshToken|\"PRT\"|prt_token)",
    re.IGNORECASE,
)
_RE_WAM_BAD = re.compile(
    r"(WAM_E_NO_ACCOUNT|no_account_found|AADSTS50059|"
    r"AcquireTokenSilent.*fail|interactive.*fallback)",
    re.IGNORECASE,
)
_RE_DSREG_JOIN_NONE = re.compile(
    r"(AzureAdJoined\s*:\s*NO|"
    r"DomainJoined\s*:\s*NO|"
    r"WorkplaceJoined\s*:\s*NO)",
    re.IGNORECASE,
)
_RE_DSREG_JOIN_YES = re.compile(
    r"(AzureAdJoined\s*:\s*YES|"
    r"WorkplaceJoined\s*:\s*YES)",
    re.IGNORECASE,
)


@dataclass
class PRTAvailability:
    """Best-effort verdict on whether this device has a usable AAD PRT."""
    confidence: PRTConfidence
    positive_signal_count: int = 0
    negative_signal_count: int = 0
    dsregcmd_yes_count: int = 0
    dsregcmd_no_count: int = 0
    notes: List[str] = field(default_factory=list)
    example_records: List[LogLine] = field(default_factory=list)


def detect_prt_availability(
    records: Iterable[LogLine],
) -> PRTAvailability:
    """Scan tray logs + any dsregcmd output for PRT-presence signals."""
    pos = neg = 0
    dsy = dsn = 0
    examples: List[LogLine] = []

    for r in records:
        msg = r.message or ""
        if _RE_WAM_OK.search(msg):
            pos += 1
            if len(examples) < 6:
                examples.append(r)
        if _RE_WAM_BAD.search(msg):
            neg += 1
            if len(examples) < 6:
                examples.append(r)
        if _RE_DSREG_JOIN_YES.search(msg):
            dsy += 1
        if _RE_DSREG_JOIN_NONE.search(msg):
            dsn += 1

    notes: List[str] = []
    confidence = PRTConfidence.UNCERTAIN

    # dsregcmd is the strongest signal — if we see explicit join state,
    # trust it over WAM call frequency.
    if dsy >= 2 and dsn == 0:
        confidence = PRTConfidence.LIKELY_PRESENT
        notes.append("dsregcmd reports an active join (Entra / Hybrid / Workplace)")
    elif dsn >= 2 and dsy == 0:
        confidence = PRTConfidence.LIKELY_ABSENT
        notes.append("dsregcmd reports no Entra/Hybrid/Workplace join state")
    elif pos >= 3 and neg == 0:
        confidence = PRTConfidence.LIKELY_PRESENT
        notes.append("WAM silent token acquisition observed without failures")
    elif neg >= 2 and pos == 0:
        confidence = PRTConfidence.LIKELY_ABSENT
        notes.append("WAM token acquisition consistently falls back to interactive")
    else:
        notes.append(
            "Insufficient signal in this bundle to determine PRT availability; "
            "ask the customer to run `dsregcmd /status` on the affected device."
        )

    return PRTAvailability(
        confidence=confidence,
        positive_signal_count=pos,
        negative_signal_count=neg,
        dsregcmd_yes_count=dsy,
        dsregcmd_no_count=dsn,
        notes=notes,
        example_records=examples,
    )
