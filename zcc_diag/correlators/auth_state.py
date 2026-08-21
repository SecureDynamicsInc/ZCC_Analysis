"""
ZPA auth state pairer.

Consumes ZSATray records and pairs:

    AUTHENTICATED → AUTHENTICATION_REQUIRED → AUTHENTICATED

into `AuthStateEvent` objects with exact recovery_seconds.

Reverse-engineering audit finding L-14: bundles can end with the state
still AUTHENTICATION_REQUIRED (re-auth never completed before export).
Those events get `outcome=UNRESOLVED` instead of crashing or silently
omitting them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable, List, Optional

from ..log_parser import LogLine


_RE_AUTH_STATE = re.compile(
    r"ZPA Auth state changed,\s*From:\s*(\w+)\s*To:\s*(\w+)",
    re.IGNORECASE,
)


class AuthEventOutcome(str, Enum):
    RECOVERED = "RECOVERED"   # AUTHENTICATED→AUTH_REQUIRED→AUTHENTICATED, normal recovery
    UNRESOLVED = "UNRESOLVED"  # AUTHENTICATED→AUTH_REQUIRED, no recovery before bundle end
    DEGENERATE = "DEGENERATE"  # transitions don't form the expected loss/recovery pair


@dataclass
class AuthStateEvent:
    """One complete (or unresolved) auth disruption."""
    lost_ts: datetime
    recovered_ts: Optional[datetime]
    outcome: AuthEventOutcome
    lost_record: Optional[LogLine] = None
    recovered_record: Optional[LogLine] = None

    @property
    def recovery_seconds(self) -> Optional[float]:
        if self.recovered_ts is None:
            return None
        return (self.recovered_ts - self.lost_ts).total_seconds()


def find_auth_state_events(
    records: Iterable[LogLine],
) -> List[AuthStateEvent]:
    """Pair AUTHENTICATED→AUTHENTICATION_REQUIRED→AUTHENTICATED transitions.

    The function tolerates noise: anything that isn't an auth-state line
    is ignored. Sequential AUTHENTICATED→AUTHENTICATED or duplicate
    AUTH_REQUIRED entries are detected and marked DEGENERATE rather than
    silently merged.
    """
    transitions: List = []
    for r in records:
        msg = r.message or ""
        m = _RE_AUTH_STATE.search(msg)
        if not m:
            continue
        transitions.append((r.timestamp, m.group(1).upper(),
                            m.group(2).upper(), r))
    transitions.sort(key=lambda t: t[0])

    events: List[AuthStateEvent] = []
    pending_loss: Optional[AuthStateEvent] = None

    for ts, frm, to, rec in transitions:
        # Auth-loss transition
        if frm == "AUTHENTICATED" and to == "AUTHENTICATION_REQUIRED":
            if pending_loss is not None:
                # Second loss without intervening recovery — finalize
                # the prior as UNRESOLVED, start a new pending.
                pending_loss.outcome = AuthEventOutcome.UNRESOLVED
                events.append(pending_loss)
            pending_loss = AuthStateEvent(
                lost_ts=ts, recovered_ts=None,
                outcome=AuthEventOutcome.UNRESOLVED,
                lost_record=rec,
            )
            continue

        # Recovery transition
        if frm == "AUTHENTICATION_REQUIRED" and to == "AUTHENTICATED":
            if pending_loss is None:
                # Recovery without a preceding loss — degenerate (loss
                # was in a rotated-off log).
                events.append(AuthStateEvent(
                    lost_ts=ts, recovered_ts=ts,
                    outcome=AuthEventOutcome.DEGENERATE,
                    recovered_record=rec,
                ))
                continue
            pending_loss.recovered_ts = ts
            pending_loss.recovered_record = rec
            pending_loss.outcome = AuthEventOutcome.RECOVERED
            events.append(pending_loss)
            pending_loss = None
            continue

        # Other transitions (CONNECTING→AUTHENTICATED, etc.) are ignored.

    # If a loss is still pending at end of stream, it's unresolved.
    if pending_loss is not None:
        events.append(pending_loss)

    return events
