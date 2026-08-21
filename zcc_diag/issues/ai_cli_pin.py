"""
Detector: AI tool / CLI cert pinning.

A growing class of customer issues are SSL handshake failures against
AI tooling endpoints (Claude.ai, Cursor, OpenAI, Copilot, Gemini,
Perplexity) caused by Zscaler SSL inspection. These endpoints
typically pin their certificates and refuse to trust the Zscaler
intermediate -- the handshake fails, the user sees the tool break.

Grounded by:
- an anonymized internal case (Example Tenant H Cursor IDE)
- an anonymized internal case (Example Tenant I Claude.ai -- observed: "zscaler
  intermediate certificate was not showing up for claude.ai")
- Example Tenant M 4-08 Zoom session: created an ``A_AI_testing`` AD group
  to give specific users access without the cloud-app caution.

Signature is a 2-line correlation: (1) ``Host=<ai-domain>`` and
(2) an SSL handshake / cert error -- but specific to a catalogue of
known cert-pinning AI endpoints, NOT the generic
``bypass_misconfiguration`` shape. This lets the SOP recommend the
right policy surface (BLSSL bypass + a Cloud-App-Control rule for an
AI testing AD group) rather than a generic bypass entry.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# Domain catalogue. Case-insensitive substring match against the
# host. Anything new the customer asks for (or that a future
# grounding pass surfaces) goes here.
_AI_DOMAINS = (
    "claude.ai",
    "anthropic.com",
    "openai.com",
    "chatgpt.com",
    "cursor.sh",
    "cursor.com",
    "copilot.microsoft.com",
    "gemini.google.com",
    "perplexity.ai",
    "grok.x.ai",
    "x.ai",
    "huggingface.co",
    "anthropic.cloud",
    "claude.com",
)

# Compile once. We tolerate slight host variations (api., www.,
# regional prefixes) by using endswith semantics.
_RE_HOST_LINE = re.compile(
    r"\bHost=(?P<host>[A-Za-z0-9.\-]+)(?::\d+)?",
)

# SSL handshake / cert error signatures. Anything in this set, when
# paired with an AI domain on the same thread, fires the detector.
_RE_SSL_FAIL = re.compile(
    r"Auth::Lib::certificateErroCallback:\s*Invalid certificate"
    r"|Certificate validation error"
    r"|SSL handshake (?:failure|failed|fail)"
    r"|TLS handshake (?:failure|failed|fail)"
    r"|ssl3_get_server_certificate.*?verify failed",
    re.IGNORECASE,
)


def _is_ai_host(host: str) -> Optional[str]:
    """Return the matching catalogue entry if ``host`` ends in one,
    else None. Used to attribute the finding to the right vendor."""
    h = host.lower().rstrip(".")
    for d in _AI_DOMAINS:
        if h == d or h.endswith("." + d):
            return d
    return None


EVIDENCE_CAP = 10


@register
class AiCliPinDetector(IssueDetector):
    id = "ai_cli_pin"
    title = "AI tool / CLI cert pinning failures"
    sop_file = "ai_cli_pin.md"
    # Cross-suite: cert pinning breaks at the SSL-inspection layer,
    # which can be triggered by either ZIA (web) or ZPA (private app)
    # forwarding. Customer-grounded patterns target both paths.
    applies_to_suite = None

    def __init__(self) -> None:
        super().__init__()
        # Per-thread state: last AI-host seen, awaiting an SSL fail.
        self._thread_last_ai_host: Dict[tuple, str] = {}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        key = (record.pid, record.tid)

        m_host = _RE_HOST_LINE.search(msg)
        if m_host:
            ai = _is_ai_host(m_host.group("host"))
            if ai is not None:
                self._thread_last_ai_host[key] = m_host.group("host")

        if _RE_SSL_FAIL.search(msg):
            target = self._thread_last_ai_host.get(key)
            if target is None:
                return  # not an AI-host failure
            ai = _is_ai_host(target)
            if ai is None:
                return
            f = self._bucket(
                f"AI_CLI_PIN__{ai}",
                Severity.WARNING,
                f"SSL inspection breaking ``{target}`` (AI tool)",
                (
                    f"ZCC's SSL inspection caused a handshake / cert "
                    f"failure against ``{target}``, which is in the "
                    f"detector's known cert-pinning AI catalogue "
                    f"(matched ``{ai}``). The endpoint refuses to "
                    f"trust the Zscaler intermediate cert.\n\n"
                    f"Two policy surfaces fix this:\n"
                    f"  1. **BLSSL bypass** -- add ``*.{ai}`` to the "
                    f"BLSSL list so ZCC stops inspecting the "
                    f"endpoint. Fast, broad.\n"
                    f"  2. **AI testing AD group** (Example Tenant M pattern) "
                    f"-- create an ``A_AI_testing`` AD group and "
                    f"scope a Cloud App Control rule to allow AI tools "
                    f"for that group only, while keeping the default "
                    f"caution / block for everyone else.\n\n"
                    f"If the customer is rolling out AI tooling "
                    f"organisation-wide, prefer (1). If only specific "
                    f"users / departments are sanctioned, prefer (2)."
                ),
                sop_anchor="#ai-cli-pin",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return list(self._buckets.values())
