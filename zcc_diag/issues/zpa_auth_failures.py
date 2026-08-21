"""
Detector: ZPA authentication failures.

ZPA = Zscaler Private Access. ZPA-side log signals are everything under
``Zpn*`` / ``broker`` / ``BRK_MT_*`` / ``zpn_*``, plus the documented
Private Access enrollment error codes ``42000``..``42048`` and ``2008``.
This is distinct from the ZIA detector (which lives in
``zia_auth_failures.py`` and watches ``Sme*`` / mobile API responses).

REFERENCE COVERAGE (linked in docs/REFERENCE_SOURCES.md):

  1. "Understanding Private Access Session Status Codes" — exhaustive
     enumeration of every AC:/CA:/CLT:/SE: code with documented meaning,
     description, and resolution. Status codes are grouped as:
       - Error Codes (real failures — most BRK_MT_SETUP_FAIL_*, all
         AST_MT_SETUP_ERR_*, all BRK_MT_AUTH_*, most ZPN_ERR_*)
       - Info Codes (NORMAL closures — BRK_MT_TERMINATED,
         BRK_MT_RESET_FROM_SERVER, BRK_MT_TERMINATED_IDLE_TIMEOUT,
         BRK_MT_CLOSED_FROM_CLIENT, BRK_MT_CLOSED_FROM_ASSISTANT,
         MT_CLOSED_TLS_CONN_GONE, most FOHH_CLOSE_REASON_*)
       - Policy Block Codes (intentional service decisions —
         BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY,
         BRK_MT_SETUP_FAIL_NO_POLICY_FOUND,
         BRK_MT_SETUP_FAIL_SAML_EXPIRED)
  2. "Zscaler Client Connector: Private Access Authentication Errors"
     — the complete 2008 + 42000..42048 enrollment-error code table.

KEY CLASSIFICATION NOTES:

  * ``BRK_MT_SETUP_FAIL_SAML_EXPIRED`` is a documented POLICY BLOCK
    code ("Timeout policy blocked access"), NOT a SAML cert / clock-
    skew failure. Severity dropped CRITICAL -> WARNING. This is the
    tenant's Timeout Policy doing what it's configured to do.
  * ``BRK_MT_CLOSED_FROM_ASSISTANT`` is a documented INFO code
    ("Connection closed by App Connector" — app server sent TCP FIN).
    The legacy detector that classified it as CRITICAL was renamed to
    ``ZpaAppSessionsDetector`` (INFO severity, per-app tally only).
  * ``42016`` clock-skew threshold of 120 seconds is DOCUMENTED, not
    heuristic ("The maximum accepted skew time is 120 seconds").
  * Added detection for the BRK_MT_AUTH_* family
    (SAML_FAILURE / DECODE_FAIL / FINGER_PRINT_FAIL / NO_USER_ID /
    NO_SAML_ASSERTION_IN_MSG / TWO_SAML_ASSERTION_IN_MSG /
    ALREADY_FAILED / SAML_CANNOT_ADD_ATTR_TO_HEAP|HASH) — previously
    not surfaced.
  * Added detection for the ZPN_ERR_* family
    (AUTH_SAML_EXPIRED / CERT_EXPIRED / AUTH_CUSTOMER_FAIL /
    AUTH_NOT_COMPLETE / AUTH_EXPIRED / AUTH_TIMEOUT / AUTH_APP_FAIL /
    AUTH_CUSTOMER_MISSING / AUTH_SERVICE_DISABLED / CUSTOMER_DISABLED /
    SCIM_INACTIVE) — previously not surfaced.

Watches the tunnel log for evidence of:

  * SAML expiry / forced re-auth (``BRK_MT_SETUP_FAIL_SAML_EXPIRED`` —
    timeout policy, ``saml force expired has been set``)
  * Generic broker microtunnel setup failures (``BRK_MT_SETUP_FAIL_*``)
  * Broker SAML/auth validation failures (``BRK_MT_AUTH_*``)
  * Service-Edge auth/cert lifecycle errors (``ZPN_ERR_*``)
  * ``getZpnAuthState`` flipping away from ``AUTHENTICATED``
  * Device-cert expiry signals from ``Auth::Crypto::isCertificateExpired``
    (the ``day: N`` field; non-positive == expired)
  * Application access blocked by Private Access policy (often confused
    with auth failures by users)
  * Documented Private-Access enrollment error codes (see
    ``_PA_ERROR_CODES`` table below).

Caveat on 42xxx detection: the source documentation gives error codes and their
human-facing messages but doesn't specify the literal log-line shape
ZSATunnel writes when these errors occur. The match strategy below is
deliberately conservative: we require either bracketed code context
(``[42016]`` / ``(42016)`` / ``error code 42016``) OR a phrase
fragment from the documentation's "Error Message" column. Bare integer matches
(e.g. byte counts, thread IDs that happen to be 42xxx) are rejected.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary
from ..data import get_session_code, get_auth_error
from ..data.zpa_auth_errors import errors_by_group


# ---------------------------------------------------------------------
# Severity-hint -> Severity enum mapping. The data module records a
# string hint ("critical" / "warning" / "info") per code. This helper
# translates it to the enum the detector framework expects.
def _hint_to_severity(hint: str) -> Severity:
    h = (hint or "warning").lower()
    if h == "critical":
        return Severity.CRITICAL
    if h == "info":
        return Severity.INFO
    return Severity.WARNING


# --- Patterns ---------------------------------------------------------

# BRK_MT_SETUP_FAIL_<reason>; capture the trailing reason for grouping.
_RE_BRK_FAIL = re.compile(r"BRK_MT_SETUP_FAIL_(?P<reason>[A-Z_]+)")

# BRK_MT_AUTH_* family — SAML / authentication failures at the broker.
# Aligned with the official Zscaler "Understanding
# Private Access Session Status Codes" documentation. These are SE-side codes
# (Service Edge) emitted when SAML processing fails.
_RE_BRK_AUTH = re.compile(r"BRK_MT_AUTH_(?P<auth_reason>[A-Z_]+)")

# ZPN_ERR_* family — Service-Edge-emitted auth/cert/scope errors. Per
# the same source documentation. Distinct from BRK_MT_AUTH_* in that these are
# higher-level lifecycle errors (cert expiry, user disabled, scope
# misconfig) rather than per-assertion validation failures.
_RE_ZPN_ERR = re.compile(r"ZPN_ERR_(?P<zpn_reason>[A-Z_]+)")

# saml force expired
_RE_SAML_FORCE_EXPIRED = re.compile(
    r"saml force expired has been set", re.IGNORECASE
)

# getZpnAuthState transitions. Also captures the modern ZPN_STATUS_*
# token family which surfaces in newer ZCC builds as an alternate
# representation of the same state machine -- normalized below so the
# transition counter sees them as equivalent to the legacy state names.
_RE_AUTH_STATE = re.compile(
    r"(?:"
    r"getZpnAuthState:\s*(?P<state1>[A-Z_]+)"
    r"|"
    r"\b(?P<state2>ZPN_STATUS_(?:AUTHENTICATED|DISCONNECTED|CONNECTING"
    r"|UNAUTHENTICATED))\b"
    r")"
)

# Normalize ZPN_STATUS_X -> X so transitions across the two phrasings
# are detected as continuous state. Healthy clients sit on AUTHENTICATED
# regardless of which phrasing the log used at that moment.
def _normalize_auth_state(s: str) -> str:
    if s.startswith("ZPN_STATUS_"):
        return s[len("ZPN_STATUS_"):]
    return s

# Device-cert expiry. The log emits two consecutive lines; the parser
# stitches them, so we match either form.
_RE_CERT_EXPIRED = re.compile(
    r"Auth::Crypto::isCertificateExpired:.*?day:\s*(?P<days>-?\d+)",
    re.IGNORECASE | re.DOTALL,
)

# Application access blocked
_RE_PA_BLOCKED = re.compile(
    r"Application access is blocked by Private Access policy",
    re.IGNORECASE,
)

# ZPA-suite ZEvent codes — discovered in the Scenario Windows D bundle (2026-06-12)
# and recorded in zcc_zpa_event_taxonomy. These ZEvents are emitted by
# the tunnel logs as "INF ZEvents: Raised event: <code>" lines OR
# embedded as named keys in metrics JSON payloads.
#
# Each row: (regex, finding_code, severity, title, description, sop_anchor)
# Order matters — first match wins so SSL-exception captures the rich
# broker context BEFORE the generic state-flap catch-all.
_ZEVENT_PATTERNS = [
    (
        # Broker SSL-connection drops with rich diagnostic JSON. The
        # following keys travel with this event: broker_hostname,
        # broker_ip, ssl_errString, clientCert_cname / _expiry,
        # serverCert_cname / _expiry / _issuer. We don't parse them
        # field-by-field here (the evidence line shows the full JSON
        # already); the operator gets the broker hostname + IP + cert
        # CN by reading the captured evidence row.
        re.compile(r"zcc_zpa_failed_ssl_exception\b"),
        "ZPA_SSL_EXCEPTION",
        Severity.CRITICAL,
        "ZPA broker SSL connection dropped",
        "ZPA reported SSL_EXCEPTION on a broker connection. The "
        "evidence line carries broker_hostname, broker_ip, "
        "ssl_errString, and certificate CN/issuer/expiry. Common "
        "causes: SSL inspection of *.zpath.net traffic by an "
        "upstream proxy / firewall (a Zscaler SSL bypass MUST be "
        "applied for the broker pool); broker certificate rotation "
        "with stale client trust; intermittent transport-layer drops.",
        "#zpa-ssl-exception",
    ),
    (
        re.compile(r"zcc_zpa_failed_auth_timeout\b"),
        "ZPA_AUTH_TIMEOUT",
        Severity.CRITICAL,
        "ZPA broker auth handshake timed out",
        "The SAML / broker authentication handshake exceeded its "
        "timeout. Distinct from a SAML rejection — the IdP never "
        "responded fast enough OR the broker session-establishment "
        "RPC never completed. Check IdP availability (Okta / Azure "
        "AD admin console) and whether IdP traffic is being SSL-"
        "inspected when it shouldn't be.",
        "#zpa-auth-timeout",
    ),
    (
        re.compile(r"zcc_zpa_server_down_error\b"),
        "ZPA_SERVER_DOWN",
        Severity.CRITICAL,
        "ZPA broker reported server-down",
        "Broker was reachable but reported itself as down — usually "
        "a connector-side failure. Open ZPA Admin Console -> Connector "
        "Groups, verify connectors are up and healthy for the "
        "affected app segments.",
        "#zpa-server-down",
    ),
    (
        re.compile(r"zcc_zpa_failed_read_error\b"),
        "ZPA_READ_ERROR",
        Severity.WARNING,
        "ZPA broker channel read error",
        "Read error on the broker control channel — the broker "
        "dropped the connection mid-read. Often a transport-layer "
        "drop or a load-balancer-side close. Multiple read errors "
        "in a short window suggests a broker pool issue; isolated "
        "read errors are usually expected lifecycle behaviour.",
        "#zpa-read-error",
    ),
    (
        re.compile(r"zcc_zpa_network_error\b"),
        "ZPA_NETWORK_ERROR",
        Severity.WARNING,
        "ZPA network-layer error to broker",
        "Network-layer error reaching the ZPA broker. Distinct from "
        "SSL_EXCEPTION (which is post-TCP) — this fires when the TCP "
        "connection itself can't be established. Check route to "
        "*.prod.zpath.net broker IPs and whether a firewall is "
        "dropping outbound to TCP/443 for the broker pool.",
        "#zpa-network-error",
    ),
    (
        # Force-reauth triggered by sleep wake. INFO severity because
        # it's expected behaviour after a system sleep — the ZIA
        # lifecycle downgrader will suppress correlated tunnel flaps,
        # but this re-auth event is the WHY for those re-auths.
        re.compile(r"zcc_zpa_force_reauth_sleep_trigger\b"),
        "ZPA_FORCE_REAUTH_SLEEP",
        Severity.INFO,
        "ZPA forced re-auth after system sleep",
        "After the OS came back from sleep, the ZPA policy engine "
        "forced a re-authentication. This is normal — many tenants "
        "set re-auth-on-resume for security. NOT an incident on its "
        "own. If correlated with user complaints about \"having to "
        "log in again\", that's the customer policy doing what it's "
        "configured to do; review tenant Force-Reauth policy in ZPA "
        "Admin Console if the cadence is too aggressive.",
        "#zpa-force-reauth-sleep",
    ),
    (
        re.compile(r"zcc_zpa_force_reauth_network_change_trigger\b"),
        "ZPA_FORCE_REAUTH_NETWORK",
        Severity.INFO,
        "ZPA forced re-auth after network change",
        "After a network-level change (DNS server change, gateway "
        "change, dock-undock, wifi-eth swap), the ZPA policy engine "
        "forced a re-authentication. Expected behaviour. Cross-"
        "correlate with sys_dns_changed events; back-to-back network "
        "changes + force-reauths suggest the user is on a flaky "
        "network rather than ZPA misbehaving.",
        "#zpa-force-reauth-network",
    ),
]


# --- Private Access enrollment error codes (42xxx + 2008) -------------
#
# Source: Zscaler Help Portal, "Zscaler Client Connector: Private Access
# Authentication Errors" (documentation dated 05/06/2026).
#
# Codes are grouped into 5 logical buckets so the SOP can have one
# anchored section per bucket rather than 30+. Each entry carries:
#
#   group       -- one of "user_input", "tenant_config", "saml_validation",
#                  "certificate", "internal"
#   sop_anchor  -- markdown anchor in zpa_auth_failures.md
#   phrase      -- a distinctive substring from the documentation's "Error Message"
#                  column. Used as a SECOND match-condition to reject
#                  false positives like byte counts that happen to be
#                  42500 / 42999 / etc.
#
# The phrase need not be the whole message -- just enough to be unique.

# Group -> SOP anchor mapping (used when emitting findings for 42xxx
# enrollment errors). Each error code's `group` field in the data
# module determines which SOP anchor the finding routes to.
_PA_GROUP_SOP = {
    "user_input":      "#pa-error-user-input",
    "tenant_config":   "#pa-error-tenant-config",
    "saml_validation": "#pa-error-saml-validation",
    "certificate":     "#pa-error-certificate",
    "internal":        "#pa-error-internal",
}

# Phrase-trigger regex built from the documented "Error Message" column
# of every code in the data module. Used as a SECOND match-condition
# to reject false positives like byte counts that happen to be
# 42500 / 42999 / etc. (Built lazily at import time.)
def _build_phrase_trigger_regex() -> "re.Pattern[str]":
    from ..data.zpa_auth_errors import ERRORS
    # Use a distinctive substring from each row's error_message — first
    # 25-30 chars usually suffices and stays unique across codes.
    phrases = []
    for row in ERRORS:
        msg = row.get("error_message", "")
        # Pick a phrase: prefer first sentence (up to first period),
        # otherwise first 30 chars.
        first_dot = msg.find(".")
        phrase = msg[:first_dot] if first_dot > 8 else msg[:30]
        if phrase:
            phrases.append(re.escape(phrase))
    return re.compile("|".join(phrases), re.IGNORECASE)


# Set of all known codes for quick lookup. Populated from the data
# module's ERRORS_BY_CODE dict.
def _build_known_codes() -> "frozenset[str]":
    from ..data.zpa_auth_errors import ERRORS_BY_CODE
    return frozenset(ERRORS_BY_CODE.keys())


_PA_KNOWN_CODES = _build_known_codes()

# Anchored-context match. Catches codes appearing as ``[42016]``, ``(42016)``,
# ``code 42016``, ``code: 42016``, or ``error 42016``. Excludes bare-number
# matches that turned out to false-positive on byte counts and thread IDs.
_RE_PA_CODE_ANCHORED = re.compile(
    r"(?:"
    r"[\[(]\s*(?P<code1>(?:2008|42\d{3}))\s*[\])]"   # [42016] or (42016)
    r"|"
    r"\b(?:error|code)\s*[:=#]?\s*(?P<code2>(?:2008|42\d{3}))\b"
    r")"
)

# Phrase-context match. Compiled at import time from the data module's
# error_message column. Used as a high-confidence secondary trigger
# alongside the anchored code regex.
_RE_PA_PHRASE_TRIGGER = _build_phrase_trigger_regex()

# Bare-code finder used ONLY when the phrase trigger fires (so we already
# have high confidence this is a real PA-auth log line).
_RE_PA_CODE_ANY = re.compile(r"\b(?P<code>(?:2008|42\d{3}))\b")

# 42016 special: extract the IdP timestamp and accepted range from the
# message body so the finding can quote them. The documentation specifies the
# message format includes ``IdP Issue Time: <ts>`` and ``Accepted Range:
# <ts> to <ts>``. Stop at any of CR/LF/comma/semicolon to survive minor
# format drift.
_RE_42016_DETAIL = re.compile(
    r"IdP Issue Time:\s*(?P<idp_ts>[^\r\n,;]+).*?"
    r"Accepted Range:\s*(?P<accept_from>[^\r\n,;]+?)\s+to\s+"
    r"(?P<accept_to>[^\r\n,;]+)",
    re.IGNORECASE | re.DOTALL,
)


def _detect_pa_error_codes(msg: str):
    """Yield ``(code, group, sop_anchor)`` triples for any PA error codes
    we can confidently identify in ``msg``.

    Two-condition strategy:
      A. anchored-context match (``[42016]``, ``error 42016``) -- always
         trusted, regardless of phrase presence.
      B. phrase-trigger match: if a phrase from the documented Error
         Message column appears in ``msg``, scan for any bare
         42xxx/2008 code in the same record.

    A code can match via either path; we yield it at most once per
    record (set-dedupe). Group is now sourced from the data module
    rather than a hardcoded table in this file."""
    seen: set = set()

    def _row_group(c: str) -> str:
        info = get_auth_error(c)
        return (info or {}).get("group", "internal")  # type: ignore

    for m in _RE_PA_CODE_ANCHORED.finditer(msg):
        code = m.group("code1") or m.group("code2")
        if code and code in _PA_KNOWN_CODES and code not in seen:
            seen.add(code)
            group = _row_group(code)
            yield code, group, _PA_GROUP_SOP.get(group, "")

    if _RE_PA_PHRASE_TRIGGER.search(msg):
        for m in _RE_PA_CODE_ANY.finditer(msg):
            code = m.group("code")
            if code in _PA_KNOWN_CODES and code not in seen:
                seen.add(code)
                group = _row_group(code)
                yield code, group, _PA_GROUP_SOP.get(group, "")


_GROUP_DESCRIPTIONS = {
    "user_input": (
        "Private Access enrollment failed because of a user-input or "
        "username-domain mismatch. Triage: verify the username matches "
        "initial enrollment and re-issue enrollment if needed."
    ),
    "tenant_config": (
        "Private Access enrollment failed because of a tenant-side or "
        "IdP-side configuration problem. Triage: Zscaler Admin Console "
        "-> Identity / SSO."
    ),
    "saml_validation": (
        "Private Access rejected the SAML response from the IdP. Causes "
        "include clock skew (>120s per Zscaler docs), expired signing "
        "certificate, malformed assertion conditions, destination/issuer "
        "mismatch. Triage: IdP side."
    ),
    "certificate": (
        "Private Access enrollment failed because of a certificate or "
        "signing-key problem. Triage: Admin Console cert management."
    ),
    "internal": (
        "Private Access returned an internal / capacity / catch-all "
        "error. Most cases require contacting Zscaler Support."
    ),
}


def _pa_error_description(code: str, group: str) -> str:
    """Compose a finding description for a specific 42xxx code.

    Combines:
      1. The per-code documented Error Description from the documentation
         (looked up in the data module)
      2. The per-code documented Resolution from the documentation
      3. The per-group narrative summary (for context)

    Falls back gracefully if the code isn't found in the data module.
    """
    row = get_auth_error(code)
    parts: List[str] = []
    if row is not None:
        msg = row.get("error_message", "")
        desc = row.get("error_description", "")
        res = row.get("resolution", "")
        if msg:
            parts.append(f'Documented message: "{msg.strip()}"')
        if desc:
            parts.append(f"Cause: {desc.strip()}")
        if res:
            parts.append(f"Resolution: {res.strip()}")
    else:
        # Unknown code — emit a placeholder so the finding still
        # carries context even when the data lookup fails.
        parts.append(
            f"Documented Private Access enrollment error {code} -- per "
            f"the Zscaler 'Private Access Authentication Errors' "
            f"reference."
        )

    base = _GROUP_DESCRIPTIONS.get(group, "")
    if base:
        parts.append(base)
    parts.append(
        "Reference: help.zscaler.com/zscaler-client-connector/"
        "zscaler-client-connector-zpa-authentication-errors"
    )
    return "\n\n".join(parts)


# --- Thresholds (kept conservative to avoid false alarms) -------------

REPEATED_THRESHOLD = 3   # >= this many same-code events triggers REPEATED
EVIDENCE_CAP = 10        # per-finding evidence cap


# --- Detector ---------------------------------------------------------

@register
class ZPAAuthFailuresDetector(IssueDetector):
    id = "zpa_auth_failures"
    title = "ZPA authentication failures (SAML/broker/cert)"
    sop_file = "zpa_auth_failures.md"
    # ZPA-only: BRK_MT_* / AST_MT_* / ZPN_ERR_* / 42xxx codes are
    # all ZPA-side. Skipped on ZIA-only bundles by the multiplexer.
    applies_to_suite = ("zpa",)

    def __init__(self) -> None:
        super().__init__()
        # auth-state transition tracking
        self._last_auth_state: Optional[str] = None
        self._auth_transitions: List[LogLine] = []
        # device cert: track the most-negative day reading we see
        self._worst_cert_days: Optional[int] = None
        self._worst_cert_record: Optional[LogLine] = None

    # --- Data-driven dispatch helper ------------------------------

    def _emit_from_data(
        self,
        record: LogLine,
        full_code: str,
        default_sop_anchor: Optional[str] = None,
    ) -> None:
        """Look up ``full_code`` in zcc_diag.data.zpa_session_codes and
        emit a Finding using the documented severity/title/description.

        Unknown codes are silently skipped — the surrounding detector
        logic uses regex patterns that may match codes outside the
        documented set, and we don't want to emit speculative findings
        for codes we have no reference data for.
        """
        info = get_session_code(full_code)
        if info is None:
            return  # unknown code — caller decides what to do
        sev = _hint_to_severity(info.get("severity_hint", "warning"))
        title_prefix = "ZPA: "
        # Component prefix in the title for engineer clarity.
        title = title_prefix + info.get(
            "session_status", full_code,
        )
        # Compose description from documented description + resolution.
        desc_parts = []
        if info.get("description"):
            desc_parts.append(info["description"])
        if info.get("resolution"):
            desc_parts.append("Resolution: " + info["resolution"])
        desc_parts.append(
            "Reference: help.zscaler.com/zpa/"
            "understanding-zpa-session-status-codes."
        )
        desc = " ".join(desc_parts)
        f = self._bucket(
            full_code,
            sev,
            title,
            desc,
            sop_anchor=default_sop_anchor,
        )
        f.add_evidence(record, cap=EVIDENCE_CAP)

    # --- IssueDetector overrides ---------------------------------

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # BRK_MT_SETUP_FAIL_<reason> -- check this FIRST. If the broker
        # rejection is the cause, the "saml force expired" flag on the
        # same line is downstream and would double-count.
        m = _RE_BRK_FAIL.search(msg)
        brk_fired = False
        if m:
            reason = m.group("reason")
            brk_fired = True
            if reason == "SAML_EXPIRED":
                # CORRECTION (2026-06-12 — validated against authentic
                # Zscaler documentation "Understanding Private Access Session
                # Status Codes", Policy Block table):
                #
                # BRK_MT_SETUP_FAIL_SAML_EXPIRED is documented as
                # "SE: Timeout policy blocked access" — a POLICY BLOCK
                # not a SAML cert/clock-skew failure. The Private
                # Access service blocked the request because the
                # tenant's TIMEOUT POLICY requires the user to
                # reauthenticate (configured behaviour).
                #
                # Documented resolution: "The user must reauthenticate
                # in Zscaler Client Connector. If needed, update the
                # timeout policy to increase the interval before a
                # timeout."
                #
                # Severity dropped CRITICAL -> WARNING. Re-auth is
                # expected; only escalate if it's happening so often
                # it's disruptive (cf. tenant's Timeout Policy config).
                f = self._bucket(
                    "SAML_EXPIRED_BROKER",
                    Severity.WARNING,
                    "Timeout policy required re-authentication",
                    "ZPA's configured timeout policy required the "
                    "user to reauthenticate. NOT a SAML cert / clock-"
                    "skew failure — this is the tenant's documented "
                    "Timeout Policy doing what it's configured to do. "
                    "If the cadence is too aggressive for users, "
                    "review the timeout policy in the ZPA Admin "
                    "Console (Policies -> Timeout). Reference: "
                    "help.zscaler.com/zpa/understanding-zpa-session-"
                    "status-codes, Policy Block Codes table.",
                    sop_anchor="#brk-mt-setup-fail-saml-expired",
                )
            elif reason == "WEBPROBE_HTTPS_DISABLED":
                f = self._bucket(
                    "WEBPROBE_HTTPS_DISABLED",
                    Severity.WARNING,
                    "Web-probe HTTPS disabled at broker",
                    "Broker microtunnel setup failed because HTTPS web "
                    "probing is disabled. Verify ZPA app-segment config.",
                    sop_anchor="#webprobe-https-disabled",
                )
            elif reason == "NO_POLICY_FOUND":
                # VALIDATED (2026-06-12, authentic Zscaler documentation
                # "Understanding Private Access Session Status Codes",
                # Policy Block Codes table):
                #
                # "SE: Policy is not configured for access" —
                # "The Private Access service blocked the application
                # request because a policy isn't configured for the
                # requested application. The application request is
                # also blocked when an application segment or a segment
                # group is disabled."
                #
                # Resolution per docs: "Update the policy to allow the
                # user. Enable the application segment and segment
                # group."
                #
                # Real-bundle evidence: example-tenant-c-windows-17mb fires
                # this 420 times in a captured window. Operator's
                # first step is ZPA Admin Console -> Policies +
                # Application Segments, not network triage.
                f = self._bucket(
                    "BRK_MT_NO_POLICY_FOUND",
                    Severity.CRITICAL,
                    "ZPA: no policy configured for access",
                    "Private Access blocked the application request "
                    "because no access policy is configured for it. "
                    "This also fires when the application segment OR "
                    "segment group is disabled. Update the policy to "
                    "allow the user and verify the segment + segment "
                    "group are enabled. Distinct from the client-side "
                    "DNS check (zpa_dns_check_not_found) which fires "
                    "BEFORE reaching the broker; if both fire, "
                    "DNS-check is upstream symptom and segment/policy "
                    "gap is root cause. Reference: help.zscaler.com/"
                    "zpa/understanding-zpa-session-status-codes.",
                    sop_anchor="#brk-mt-no-policy-found",
                )
            elif reason == "REJECTED_BY_POLICY":
                # VALIDATED (2026-06-12, authentic Zscaler documentation
                # "Understanding Private Access Session Status Codes",
                # Policy Block Codes table):
                #
                # "SE: Application policy blocked access" —
                # "The Private Access service blocked the application
                # request because the user isn't allowed to access the
                # requested application."
                #
                # Resolution per docs: "Update the policy to allow the
                # user."
                #
                # Distinct from NO_POLICY_FOUND (where no rule
                # matched at all) — here a rule explicitly said no.
                f = self._bucket(
                    "BRK_MT_REJECTED_BY_POLICY",
                    Severity.CRITICAL,
                    "ZPA: access policy denied the request",
                    "An access-policy rule matched the request and "
                    "explicitly denied it. Identify the destination "
                    "(tag_id in the same JSON), then in ZPA Admin "
                    "Console -> Policies -> Access Policy walk the "
                    "rule set to find the deny rule. Common cause: a "
                    "broad deny rule placed above the user's grant "
                    "rule; rule ordering matters. Reference: "
                    "help.zscaler.com/zpa/understanding-zpa-session-"
                    "status-codes.",
                    sop_anchor="#brk-mt-rejected-by-policy",
                )
            else:
                f = self._bucket(
                    f"BRK_MT_SETUP_FAIL_{reason}",
                    Severity.WARNING,
                    f"Broker microtunnel setup failed: {reason}",
                    f"Generic ZPA broker setup failure: {reason}.",
                    sop_anchor="#brk-mt-setup-fail-generic",
                )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # BRK_MT_AUTH_* family (SAML / authentication validation
        # failures at the broker). REFACTORED 2026-06-12 (phase 2d):
        # the per-code metadata is now sourced from the data module
        # ``zcc_diag.data.zpa_session_codes`` — one place to maintain.
        # See docs/REFERENCE_SOURCES.md for the external reference index.
        m_auth = _RE_BRK_AUTH.search(msg)
        if m_auth:
            full_code = "BRK_MT_AUTH_" + m_auth.group("auth_reason")
            self._emit_from_data(record, full_code,
                                 default_sop_anchor="#brk-mt-auth-saml-fail")

        # ZPN_ERR_* family — Service-Edge auth/cert/scope errors.
        # Same data-driven dispatch as BRK_MT_AUTH_*.
        m_zpn = _RE_ZPN_ERR.search(msg)
        if m_zpn:
            full_code = "ZPN_ERR_" + m_zpn.group("zpn_reason")
            self._emit_from_data(record, full_code,
                                 default_sop_anchor="#zpn-err-auth")

        # (BRK_MT_AUTH_* and ZPN_ERR_* handlers moved above and refactored
        # to use the data module's _emit_from_data helper, which looks
        # up the documented severity / title / description from
        # zcc_diag.data.zpa_session_codes.CODES_BY_NAME. The legacy
        # hardcoded _AUTH_MEANINGS / _ZPN_MEANINGS dicts were ~120
        # lines that we have deleted — the data lives in the data
        # module now.)

        # SAML force expired -- only count when NOT a downstream signal
        # of a broker rejection on the same line.
        if not brk_fired and _RE_SAML_FORCE_EXPIRED.search(msg):
            f = self._bucket(
                "SAML_FORCE_EXPIRED",
                Severity.WARNING,
                "SAML token force-expired",
                "ZCC explicitly invalidated the SAML assertion. Frequent "
                "occurrence usually means the IdP cookie isn't sticking, "
                "the IdP URL is going through SSL inspection, or the IdP "
                "is being routed back through Zscaler.",
                sop_anchor="#saml-force-expired",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # 407 Proxy Auth and the generic "internal error" string are
        # ZIA-side signals -- handled by ZIAAuthFailuresDetector. The
        # 42xxx codes (including 42000) are handled by this detector
        # below via the _PA_ERROR_CODES table.

        # Application access blocked (policy, not auth)
        if _RE_PA_BLOCKED.search(msg):
            f = self._bucket(
                "PA_POLICY_BLOCKED",
                Severity.INFO,
                "Application access blocked by Private Access policy",
                "Not strictly an auth failure -- the user authenticated "
                "but a ZPA policy denied access. Listed here because users "
                "often report this as 'login is broken'.",
                sop_anchor="#pa-policy-blocked",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # Private Access enrollment error codes (42xxx + 2008).
        for code, group, anchor in _detect_pa_error_codes(msg):
            f = self._bucket(
                f"PA_ERROR_{code}",
                Severity.CRITICAL,
                f"Private Access enrollment error {code}",
                _pa_error_description(code, group),
                sop_anchor=anchor,
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

            # 42016 is uniquely informative -- the message itself carries
            # the IdP-issued timestamp and the server's accepted range.
            # If we can extract them, attach to the finding description.
            if code == "42016":
                m = _RE_42016_DETAIL.search(msg)
                if m and "IdP Issue Time" not in f.description:
                    f.description += (
                        f"\n\nObserved values: IdP Issue Time = "
                        f"{m.group('idp_ts').strip()}; "
                        f"Accepted Range = {m.group('accept_from').strip()} "
                        f"to {m.group('accept_to').strip()}. "
                        f"Skew of >120s is the documented threshold."
                    )

        # Auth-state transitions. The regex has two alternative capture
        # groups (legacy ``getZpnAuthState: X`` vs. modern ``ZPN_STATUS_X``);
        # take whichever fired and normalize so transitions across
        # phrasings count as continuous state.
        m = _RE_AUTH_STATE.search(msg)
        if m:
            raw_state = m.group("state1") or m.group("state2")
            if raw_state is not None:
                state = _normalize_auth_state(raw_state)
                if (
                    self._last_auth_state is not None
                    and state != self._last_auth_state
                ):
                    self._auth_transitions.append(record)
                self._last_auth_state = state

        # ZPA-suite ZEvent codes (zcc_zpa_*). Each pattern in
        # _ZEVENT_PATTERNS is a (regex, code, severity, title,
        # description, sop_anchor) tuple. First-match-wins so the
        # more-specific patterns (e.g. SSL_EXCEPTION with its rich
        # broker JSON) get priority over generic state-flap matches.
        for zre, zcode, zsev, ztitle, zdesc, zsop in _ZEVENT_PATTERNS:
            if zre.search(msg):
                zf = self._bucket(
                    zcode, zsev, ztitle, zdesc,
                    sop_anchor=zsop,
                )
                zf.add_evidence(record, cap=EVIDENCE_CAP)
                # Don't break — multiple zcc_zpa_* events can appear on
                # the same line in theory; in practice each line carries
                # one event but the patterns are disjoint so the loop
                # cost is negligible.

        # Device-cert expiry tracking
        m = _RE_CERT_EXPIRED.search(msg)
        if m:
            try:
                days = int(m.group("days"))
            except ValueError:
                days = None
            if days is not None:
                if (
                    self._worst_cert_days is None
                    or days < self._worst_cert_days
                ):
                    self._worst_cert_days = days
                    self._worst_cert_record = record

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        findings: List[Finding] = []

        # Re-title SAML_EXPIRED_BROKER with the repeat count if it
        # crossed the threshold. (This is a documented Timeout Policy
        # block code, not a SAML failure — see feed() above.)
        for code, f in self._buckets.items():
            if (
                code == "SAML_EXPIRED_BROKER"
                and f.count >= REPEATED_THRESHOLD
            ):
                f.title = (
                    f"Timeout policy re-auth (×{f.count} — "
                    f"aggressive cadence?)"
                )
            findings.append(f)

        # Auth-state oscillation finding (only if we saw transitions).
        if self._auth_transitions:
            f = Finding(
                code="AUTH_STATE_FLAPPED",
                severity=Severity.WARNING,
                title=(
                    f"Auth state changed {len(self._auth_transitions)} "
                    "time(s)"
                ),
                description=(
                    "getZpnAuthState transitioned during the captured "
                    "window. Healthy clients sit on AUTHENTICATED. "
                    "Transitions correlate with SAML refreshes, network "
                    "changes, or trusted-network detection flips."
                ),
                sop_anchor="#auth-state-flapped",
            )
            for rec in self._auth_transitions:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        # Device-cert expiry: report only if we saw a non-positive day
        # reading AND the cert wasn't ancient. The auth-crypto layer
        # iterates the system trust store on init, so legacy CAs that
        # expired years ago show up here; they're not actionable.
        # Threshold: -90 < days <= 0 means recently-expired and worth
        # surfacing.
        if (
            self._worst_cert_days is not None
            and -90 < self._worst_cert_days <= 0
        ):
            f = Finding(
                code="DEVICE_CERT_EXPIRED",
                severity=Severity.CRITICAL,
                title=(
                    f"Recently-expired cert in auth chain "
                    f"(days remaining: {self._worst_cert_days})"
                ),
                description=(
                    "Auth::Crypto::isCertificateExpired reported zero or "
                    "fewer days remaining for a certificate observed in "
                    "the recent past. Likely the device-posture cert or "
                    "an active CA. Until renewed, ZIA/ZPA auth may fail."
                ),
                sop_anchor="#device-cert-expired",
            )
            if self._worst_cert_record is not None:
                f.add_evidence(self._worst_cert_record, cap=EVIDENCE_CAP)
            findings.append(f)
        elif (
            self._worst_cert_days is not None
            and self._worst_cert_days <= -90
        ):
            # Long-expired cert -- almost always a stale trust-store CA.
            # Surface as INFO so the human can verify, but don't alarm.
            f = Finding(
                code="STALE_CERT_IN_TRUSTSTORE",
                severity=Severity.INFO,
                title=(
                    f"Long-expired cert observed in trust enumeration "
                    f"(days remaining: {self._worst_cert_days})"
                ),
                description=(
                    "An expired cert was iterated by Auth::Crypto. Almost "
                    "always a legacy CA in the system trust store, not "
                    "the active device cert. Verify only if other auth "
                    "findings co-occur."
                ),
                sop_anchor="#device-cert-expired",
            )
            if self._worst_cert_record is not None:
                f.add_evidence(self._worst_cert_record, cap=EVIDENCE_CAP)
            findings.append(f)

        return findings
