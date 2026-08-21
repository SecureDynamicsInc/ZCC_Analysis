"""
Detector: ZIA authentication failures.

ZIA = Zscaler Internet Access. ZIA-side auth in ZCC manifests through:

  * The mobile API endpoints under ``mobile.<cloud>.net/api/mobile/...``
    (``policy/v2/keepAlive``, ``policy/v2/download``, ``device/...``).
    These return JSON with an ``error`` field on failure.
  * ``getSmeProxyState`` (Service-Edge-Mobile = ZIA Public Service Edge)
    transitioning out of ``TUNNEL_FORWARDING`` into states like
    ``SERVER_DOWN_ERROR``, ``ADAPTER_DOWN_ERROR``, ``CONNECTING``.
    ``TURNED_OFF`` is NOT an error -- it just means ZIA is disabled in
    the active forwarding profile.
  * Forced ``unregisterDevice`` calls (re-enrollment cycle).
  * ``ZTUI failed to send ZTunnel Status`` errors -- UI/service bus break,
    often co-occurs with auth/policy push failures.
  * ``Status: 407`` from the Public Service Edge (Proxy-Authentication-
    Required), per Zscaler's published ZIA troubleshooting guide.
  * Generic "An internal error occurred" message in auth context -- per
    Zscaler's doc, this is the canonical ZIA "Authentication Internal
    Error" symptom (auth-domain provisioning mismatch).
  * **OneID / OIDC device-registration failures** -- ZCC's OneID
    library handles the OAuth/OpenID-Connect device-registration flow
    against the customer's IdP. When this fails, both ZIA and ZPA can
    be left in ``REGISTRATION_REQUIRED`` state. The OneID failure is
    upstream of the SAML / mobile API symptoms -- catching it here
    points the operator at the actual auth-handshake breakage rather
    than the downstream cascade.

Note on 42xxx codes: per the Zscaler "Private Access Authentication
Errors" reference, the entire ``42000``..``42048`` range and the
standalone ``2008`` code belong to Private Access enrollment and are
handled by :class:`zpa_auth_failures.ZPAAuthFailuresDetector`.

Distinct from :class:`zpa_auth_failures.ZPAAuthFailuresDetector` which
watches ``Zpn*`` / ``BRK_MT_*`` / ``broker*`` constructs and the 42xxx
codes. OneID failures fire HERE because they're the upstream of both
products' auth chains -- the OneID error message text already mentions
which product (ZIA vs ZPA) it was attempting to register.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, List, Optional

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# Mobile API error responses. The log shape is:
#     Tunnel api request: {...,"url":"https://mobile.<cloud>.net/api/mobile/..."} response: { "error": N }
# We capture the URL and the error code together so we can group by
# endpoint AND error.
_RE_MOBILE_API_ERROR = re.compile(
    r"\"url\":\"https?://(?P<host>[^/\"]+)(?P<path>/api/mobile/[^\"]+)\""
    r".*?response:\s*\{\s*\"error\":\s*(?P<code>\d+)",
    re.DOTALL,
)

# SmeProxyState transitions. Capture the state token only.
_RE_SME_STATE = re.compile(
    r"getSmeProxyState:?\s*(?P<state>[A-Z_]+)"
)

# 407 Proxy Authentication Required. ZIA-side because the SME (Service
# Edge Mobile) returns it -- e.g. ``ID=N, SME response: ... Status: 407``.
_RE_407 = re.compile(r"SME response:.*?Status:\s*407", re.IGNORECASE)

# Forced device unregister (re-enrollment cycle).
_RE_UNREGISTER = re.compile(
    r"/api/mobile/device/unregisterDevice", re.IGNORECASE
)

# ZTUI service-bus failure
_RE_ZTUI_FAIL = re.compile(
    r"ZTUI failed to send ZTunnel Status"
)

# Generic "An internal error occurred" message. Per Zscaler's docs the
# canonical ZIA "Authentication Internal Error" symptom is an unspecified
# internal error in an auth context. Note: 42xxx codes are Private-Access
# enrollment errors and live in the ZPA detector.
_RE_INTERNAL_ERROR = re.compile(
    r"(?:an\s+)?internal error\s+occurred", re.IGNORECASE,
)

# OneID / OIDC device-registration failure. ZCC's OneID library drives
# the OAuth/OpenID-Connect device-registration flow. When it fails the
# log line shape is:
#   ERR One::ID::Device ZIA registration fail with error: -9
#   ERR One::ID::Device ZPA registration fail with error: -9
# The errCode captures which OneID error code surfaced -- -9 is the
# generic "App Internal Error, Please Contact Administrator" code
# observed in the synthetic reference bundle.
#
# Documented co-occurring lines that triangulate the same event (kept
# for SOP guidance, not matched separately to avoid double-firing):
#   ERR One::ID::ZS_Device_Registration_<ZIA|ZPA>_Req failed type 3, errCode: -9, reason: App Internal Error, Please Contact Administrator.
#   INF One::ID::error on service: ZS_Device_Registration_<ZIA|ZPA>_Req type: 3, err code: -9, error = App Internal Error, Please Contact Administrator.
_RE_ONEID_DEVICE_REG_FAIL = re.compile(
    r"One::ID::Device\s+(?P<product>ZIA|ZPA)\s+registration fail "
    r"with error:\s*(?P<code>-?\d+)",
    re.IGNORECASE,
)

# OneID keep-alive HTTP 401 (INVALID TOKEN). Indicates the OneID
# session token is no longer valid -- typically when the upstream
# IdP rotated or revoked the user's session. Distinct from a ZIA
# mobile-API 401 because OneID is the auth-handshake layer; mobile
# API 401 would be a downstream symptom of this same failure.
_RE_ONEID_KEEPALIVE_401 = re.compile(
    r"One::ID::ZS_Keep_Alive_Req\s+http status code\s+401",
    re.IGNORECASE,
)

# Zscaler-documented Kerberos / SAML auth-failure tokens. Sourced
# from help.zscaler.com/zia (Kerberos authentication error codes
# page, 2026-05-19 research pass).
#
#   ERR_zpn_client_authenticate:
#     Generic ZPN-side auth failure marker; emitted in ZIA contexts
#     when the client-side auth handshake against the Public Service
#     Edge fails for an unspecified reason. Often co-occurs with
#     SERVER_AUTH_ERROR state transitions.
#
#   BRK_MT_AUTH_SAML_FINGER_PRINT_FAIL:
#     ZPA broker microtunnel setup failure where the SAML assertion's
#     signing certificate fingerprint didn't match what the broker
#     expected. Despite being detected from this ZIA-auth-failures
#     file (historical placement), the underlying event is a ZPA-side
#     concern; the emitted code is ``ZPA_SAML_FINGERPRINT_MISMATCH``
#     so the Symptoms-module suite filter routes it to ZPA triage.
#     Usually caused by an IdP certificate rotation that wasn't
#     propagated to the Zscaler tenant config.
_RE_ZPN_CLIENT_AUTH_FAIL = re.compile(
    r"\bERR_zpn_client_authenticate\b",
)
_RE_SAML_FINGERPRINT_FAIL = re.compile(
    r"\bBRK_MT_AUTH_SAML_FINGER_PRINT_FAIL\b",
)


# Healthy SME states. Anything else is potentially interesting.
# TURNED_OFF means ZIA is disabled in the forwarding profile -- not an
# error, just an absence.
_HEALTHY_SME = frozenset({
    "TUNNEL_FORWARDING", "TURNED_OFF", "CONNECTING",
})

# Bad SME states owned by the AUTH detector. Authoritative names per
# the Zscaler "Client Connector Errors" documentation (Windows Registry Keys
# section, ZWS_State table).
#
# This detector ONLY tracks auth-state failures here. Network-layer
# states (SERVER_DOWN_ERROR, ADAPTER_DOWN_ERROR,
# INTERNET_UNREACHABLE_ERROR, SERVICE_DOWN_ERROR,
# SYSTEM_SOCKETS_EXHAUSTED_ERROR) live in the tunnel-not-established
# detector. Captive (CAPTIVE_PORTAL_ERROR) lives in issue #4. Driver
# (DRIVER_ERROR) lives in issue #6. FW (FIREWALL_BLOCK_ERROR) lives in
# issue #3. ZPA cert (ZPA_UNTRUSTED_SERVER_CERT_ERROR) lives in the ZPA
# detector.
_BAD_SME_STATES = frozenset({
    "SERVER_AUTH_ERROR",                # Edge rejected auth credentials
    "SERVER_AUTH_TERMINATED_AT_UNKNOWN",# Chaining auth: realm mismatch
})

# --- macOS-specific patterns (tray-log) ------------------------------
#
# On macOS the same Mobile API calls are logged in ZSATray as a
# multi-line trace by ``Auth::Lib::executeMobileAdminPostAPI``. The
# request URL and the response status code appear on separate log
# lines (usually adjacent on the same (pid, tid)). The healthy
# response is HTTP 200; anything else is a finding.

# URL-line shape:
#   INF Auth::Lib::executeMobileAdminPostAPI: https://mobile.<cloud>.net/<path>
_RE_MAC_API_URL = re.compile(
    r"Auth::Lib::executeMobileAdminPostAPI:\s+"
    r"(?P<url>https?://\S+)"
)

# Response-code-line shape:
#   INF Auth::Lib::executeMobileAdminPostAPI: Response: 200, Length: 772
_RE_MAC_API_RESPONSE = re.compile(
    r"Auth::Lib::executeMobileAdminPostAPI:\s+"
    r"Response:\s+(?P<code>\d{3})\b"
)

# Pull the path off a URL for grouping by endpoint, not by host.
_RE_MAC_API_URL_PATH = re.compile(
    r"https?://[^/]+(?P<path>/\S+)"
)

EVIDENCE_CAP = 10


@register
class ZIAAuthFailuresDetector(IssueDetector):
    id = "zia_auth_failures"
    title = "ZIA authentication failures"
    sop_file = "zia_auth_failures.md"
    # ZIA-only: HTTP 407 from Service Edge, SME state transitions,
    # ZTUI bus, and mobile API endpoints are all ZIA-suite.
    applies_to_suite = ("zia",)

    # ZIA auth on Windows is logged in ZSATunnel (one-line ``Tunnel api
    # request: {...} response: {...}`` format). On macOS the same Mobile
    # API calls go through ZSATray as ``Auth::Lib::executeMobileAdminPostAPI``
    # multi-line traces -- so we opt in to tray-log feeding to catch
    # them.
    wants_tray_logs = True

    def __init__(self) -> None:
        super().__init__()
        # Track SME-state hits per state token for the summary finding.
        self._sme_state_counts: Dict[str, int] = {}
        self._sme_bad_records: List[LogLine] = []
        # Phase 58e-C5 (2026-07-08): uncapped 407 timestamp list for
        # the Phase-53b burst guard. Prior implementation scanned
        # f.evidence which is capped at EVIDENCE_CAP=10 — real bursts
        # after the first 10 records were silently dropped. This list
        # holds every timestamp we observe; finalize() computes the
        # burst check against this, not the capped evidence.
        self._sme_407_timestamps: List[datetime] = []
        # Mac auth: track the URL currently in flight per thread so the
        # Response: <code> line can be attributed to the correct
        # endpoint. Keyed by (pid, tid) tuple. Only filled when running
        # over tray logs.
        self._mac_inflight_url: Dict[tuple, str] = {}

    # --- IssueDetector overrides --------------------------------------

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # Mobile API errors -- highest-value ZIA-specific signal.
        m = _RE_MOBILE_API_ERROR.search(msg)
        if m:
            host = m.group("host")
            path = m.group("path")
            code = m.group("code")
            # Only act on Zscaler mobile API hosts (defensive: don't fire
            # on a customer-internal endpoint that happens to look similar).
            if "zscaler" in host.lower() or host.endswith(".zscloud.net"):
                # Pick a stable subkind based on the endpoint suffix.
                if "policy/v2/keepAlive" in path:
                    sub, anchor = "KEEPALIVE", "#mobile-api-keepalive-error"
                elif "policy/v2/download" in path:
                    sub, anchor = "POLICY_DOWNLOAD", "#mobile-api-policy-download-error"
                elif "device/unregisterDevice" in path:
                    sub, anchor = "UNREGISTER", "#mobile-api-unregister-error"
                elif "device/" in path:
                    sub, anchor = "DEVICE", "#mobile-api-device-error"
                else:
                    sub, anchor = "OTHER", "#mobile-api-generic-error"
                f = self._bucket(
                    f"MOBILE_API_ERROR_{sub}_{code}",
                    Severity.CRITICAL,
                    f"ZIA mobile API {sub.lower()} returned error {code}",
                    f"The ZIA mobile API endpoint at {path} returned "
                    f"``error={code}``. This is the authoritative ZIA-"
                    f"side failure indicator -- the client failed to "
                    f"download policy, keep its session alive, or manage "
                    f"enrollment.",
                    sop_anchor=anchor,
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)

        # 407 Proxy-Authentication-Required from Service Edge.
        if _RE_407.search(msg):
            f = self._bucket(
                "HTTP_407_FROM_SME",
                Severity.WARNING,
                "HTTP 407 from ZIA Service Edge",
                "The Public Service Edge returned 407 Proxy "
                "Authentication Required. Transient during re-auth is "
                "fine; sustained 407s suggest the auth cookie was lost "
                "or a captive-portal exemption broke.",
                sop_anchor="#http-407",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            # Phase 58e-C5 (2026-07-08): record every 407 timestamp
            # UNCAPPED for the finalize-time burst guard. add_evidence()
            # caps the visible list at 10; the burst guard needs to
            # see them all.
            if record.timestamp is not None:
                self._sme_407_timestamps.append(record.timestamp)

        # Forced unregister (re-enrollment cycle).
        if _RE_UNREGISTER.search(msg):
            f = self._bucket(
                "FORCED_UNREGISTER",
                Severity.WARNING,
                "Device unregister called",
                "The client invoked ``/api/mobile/device/unregisterDevice``. "
                "ZCC self-triggers this when a policy push fails repeatedly "
                "or the user manually signs out. A small number is normal "
                "around manual sign-out; a stream of them indicates an "
                "unstable enrollment.",
                sop_anchor="#forced-unregister",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # ZTUI failure
        if _RE_ZTUI_FAIL.search(msg):
            f = self._bucket(
                "ZTUI_BUS_FAIL",
                Severity.WARNING,
                "Tray UI couldn't reach the ZCC service",
                "ZTUI -> ZSAService communication failed. Often co-occurs "
                "with auth/policy push failures because the service is "
                "blocked from talking to the cloud OR has crashed.",
                sop_anchor="#ztui-bus-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # SmeProxyState tracking
        m = _RE_SME_STATE.search(msg)
        if m:
            state = m.group("state")
            self._sme_state_counts[state] = (
                self._sme_state_counts.get(state, 0) + 1
            )
            if state in _BAD_SME_STATES and len(self._sme_bad_records) < EVIDENCE_CAP:
                self._sme_bad_records.append(record)

        # Generic "An internal error occurred" -- per Zscaler docs this is
        # the canonical ZIA "Authentication Internal Error" symptom (root
        # cause is auth-domain provisioning).
        if _RE_INTERNAL_ERROR.search(msg):
            ml = msg.lower()
            if any(k in ml for k in ("auth", "saml", "credential", "login",
                                      "enroll", "policy")):
                f = self._bucket(
                    "AUTH_INTERNAL_ERROR",
                    Severity.WARNING,
                    "ZIA Authentication Internal Error",
                    "ZCC surfaced 'An internal error occurred' in an "
                    "auth-related code path. Per Zscaler's troubleshooting "
                    "guide, root cause is usually incorrect user auth "
                    "domain provisioning -- the tenant doesn't have the "
                    "user's email domain set up to route to the right IdP.",
                    sop_anchor="#auth-internal-error",
                )
                f.add_evidence(record, cap=EVIDENCE_CAP)

        # OneID / OIDC signals -- can appear in either tunnel logs
        # (Windows ZSATunnel) or tray logs (Windows ZSATrayManager +
        # macOS ZSATray). Routed through a shared check so both
        # feed() and feed_tray() catch them.
        self._check_oneid(record)

    # --- Tray-log feeding (macOS) ------------------------------------
    #
    # On macOS the Mobile API call sequence is logged in ZSATray as a
    # multi-line trace:
    #
    #   INF Auth::Lib::executeMobileAdminPostAPI: Begin
    #   INF Auth::Lib::executeMobileAdminPostAPI: Trial: 0
    #   INF Auth::Lib::executeMobileAdminPostAPI: <URL>
    #   INF Auth::Lib::executeMobileAdminPostAPI: Response: 200, Length: 772
    #   ... (more headers/length) ...
    #   INF Auth::Lib::executeMobileAdminPostAPI: Finish
    #
    # The URL appears one line before the Response. We track the in-
    # flight URL per (pid, tid) so the Response line can be attributed
    # to the right endpoint. Failures are any non-2xx response. The
    # Windows path (Tunnel api request: ... response: {...} on a single
    # line, with the JSON body containing ``"error":N``) remains in
    # ``feed()`` above.

    def feed_tray(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # OneID / OIDC signals can appear in tray-log records too
        # (Windows ZSATrayManager + macOS ZSATray). Same check as in
        # feed() so both routes catch them. Grounded by the 2026-05-19
        # synthetic reference bundle, where the ZIA / ZPA registration
        # failures appear in ZSATrayManager_*.log.
        self._check_oneid(record)

        # Capture the URL when we see it. The lines that aren't a URL
        # also have the prefix (``Begin``, ``Trial``, ``Response``,
        # ``Finish``) -- only the URL line starts with ``http``.
        m = _RE_MAC_API_URL.search(msg)
        if m:
            url = m.group("url")
            self._mac_inflight_url[(record.pid, record.tid)] = url
            return

        # Response line: if non-2xx, fire a finding tied to whatever
        # URL was last seen on this thread.
        m = _RE_MAC_API_RESPONSE.search(msg)
        if m:
            try:
                code = int(m.group("code"))
            except ValueError:
                return
            if 200 <= code < 300:
                # Healthy -- clear the in-flight slot.
                self._mac_inflight_url.pop((record.pid, record.tid), None)
                return
            url = self._mac_inflight_url.pop(
                (record.pid, record.tid), "<unknown URL>"
            )
            # Pull the endpoint path for the code key so we group by
            # endpoint, not by full URL (host is the same for all).
            mp = _RE_MAC_API_URL_PATH.search(url)
            path = mp.group("path") if mp else url
            # NOTE: this signal is NOT macOS-only -- it appears in
            # BOTH Windows ZSATrayManager AND macOS ZSATray. We
            # previously labelled the code "MAC_MOBILE_API_HTTP_..."
            # which mis-attributed the finding on Windows bundles
            # (e.g. the user could see "macOS Mobile API endpoint
            # returned HTTP 503" surfaced as the root issue on a
            # Windows 11 bundle, which is confusing and wrong). The
            # code prefix is now OS-agnostic; the per-detector OS gate
            # remains in feed_tray's caller (the multiplexer feeds
            # tray logs from both Windows and Mac bundles). Severity
            # is downgraded to WARNING for transient 5xx because
            # sporadic 503s from the Mobile API endpoint are common
            # transient cloud-side failures, NOT necessarily an
            # authentication root cause. 4xx (401/403/407) stays at
            # CRITICAL because those indicate auth state breakage.
            sev = (
                Severity.CRITICAL if 400 <= code < 500
                else Severity.WARNING
            )
            f = self._bucket(
                f"MOBILE_API_HTTP_{code}",
                sev,
                f"Mobile API endpoint returned HTTP {code}",
                f"ZCC's tray (``ZSATray`` on macOS, "
                f"``ZSATrayManager`` on Windows) logs the Mobile API "
                f"call sequence as multi-line traces under "
                f"``Auth::Lib::executeMobileAdminPostAPI``. A non-2xx "
                f"response code from any of these calls is the "
                f"ZIA-side authentication / policy-management signal. "
                f"Endpoint affected: ``{path}``. HTTP {code} typically "
                f"means: 401/403 = session invalid; 407 = proxy auth "
                f"required upstream; 5xx = ZIA service edge-side "
                f"failure (often transient -- worth correlating with "
                f"a sustained pattern before treating as a root "
                f"cause).",
                sop_anchor="#mobile-api-failure",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

    # --- Shared OneID / OIDC checks ---------------------------------
    #
    # OneID is the OAuth/OpenID-Connect handshake layer that drives
    # both ZIA and ZPA device enrollment. On Windows the OneID lines
    # appear in ``ZSATrayManager_*.log`` (which classifies as
    # ``tray_manager``); on macOS they appear in ``ZSATray_*.log``.
    # On rare occasions tunnel logs also carry the same lines, so we
    # call this from both ``feed()`` and ``feed_tray()``.

    def _check_oneid(self, record: LogLine) -> None:
        msg = record.message

        # Device registration failure (the canonical OneID failure
        # line). Bucket per (product, errCode) so the same bundle can
        # show distinct findings for ZIA vs ZPA + different codes.
        m = _RE_ONEID_DEVICE_REG_FAIL.search(msg)
        if m:
            product = m.group("product").upper()
            code = m.group("code")
            f = self._bucket(
                f"ONEID_DEVICE_REG_FAIL_{product}_{code}",
                Severity.CRITICAL,
                (
                    f"OneID device registration failed for {product} "
                    f"(errCode {code})"
                ),
                (
                    f"ZCC's OneID library (the OAuth/OpenID-Connect "
                    f"handshake against the customer's IdP) failed to "
                    f"register the device for {product} with error "
                    f"code ``{code}``. The OneID failure is **upstream** "
                    f"of any SAML / mobile-API / state-machine "
                    f"symptoms -- when this fires, downstream detectors "
                    f"like ``zpa_auth_failures`` (SAML empty), "
                    f"``tunnel_not_established`` (SERVER_DOWN_ERROR), "
                    f"and ``zphm_force_stop_loop`` are likely also "
                    f"firing as cascading consequences. Fix THIS one "
                    f"first.\n\n"
                    f"Triage:\n"
                    f"  1. Check the OIDC tenant config: does "
                    f"``<tenant>.zslogin.net/.well-known/openid-"
                    f"configuration`` return 200 with a valid OIDC "
                    f"document? Look earlier on the same thread for "
                    f"the discovery URL.\n"
                    f"  2. Verify the user actually completed the "
                    f"browser-based authorize step. ZCC logs "
                    f"``launch browser for user authentication`` "
                    f"before the failure; if the user closed the "
                    f"browser, abandoned the flow, or the IdP "
                    f"redirect chain broke, the registration call "
                    f"comes back failed.\n"
                    f"  3. errCode ``-9`` = ``App Internal Error, "
                    f"Please Contact Administrator`` -- the OneID "
                    f"library couldn't reconcile the IdP's response "
                    f"with the user's expected tenant binding. Check "
                    f"ZIA admin -> Administration -> Authentication "
                    f"Settings for the email-domain -> auth-domain "
                    f"mapping.\n"
                    f"  4. errCode in 42xxx-50xxx range = documented "
                    f"Private Access enrollment error. See the ZPA "
                    f"auth detector's SOP for the specific code's "
                    f"meaning.\n"
                    f"  5. Co-occurring documented lines (look in the "
                    f"correlation window): "
                    f"``ZS_Device_Registration_{product}_Req failed "
                    f"type 3, errCode: {code}`` and "
                    f"``One::ID::error on service: "
                    f"ZS_Device_Registration_{product}_Req``."
                ),
                sop_anchor="#oneid-device-registration-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # Generic ZPN client-authenticate failure (Zscaler-documented
        # token). Almost always co-occurs with SERVER_AUTH_ERROR;
        # surfacing it as its own finding lets the operator know the
        # auth-handshake-layer error has a specific Zscaler-side
        # token name to search the docs / community for.
        if _RE_ZPN_CLIENT_AUTH_FAIL.search(msg):
            f = self._bucket(
                "ZPN_CLIENT_AUTHENTICATE_FAIL",
                Severity.WARNING,
                "ZPN client-authenticate handshake failed",
                (
                    "ZCC logged ``ERR_zpn_client_authenticate``, a "
                    "Zscaler-documented marker that the client-side "
                    "auth handshake against the Public Service Edge "
                    "failed. Typically downstream of a more specific "
                    "failure (OneID registration, SAML expiry, "
                    "mobile-API rejection). Check the correlation "
                    "window for the upstream cause and fix that "
                    "first."
                ),
                sop_anchor="#zpn-client-authenticate-fail",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # SAML signing-certificate fingerprint mismatch.
        #
        # NOTE: ``BRK_MT_AUTH_SAML_FINGER_PRINT_FAIL`` is a ZPA
        # broker-microtunnel signal (``BRK_MT_*`` prefix = broker
        # microtunnel), not a ZIA event. It only fires in this ZIA
        # detector because the regex was historically placed here;
        # the emitted code is therefore prefixed ``ZPA_`` so the
        # suite-aware Symptoms-module filter routes it to ZPA triage
        # views (and not into ZIA ones). The detection itself can stay
        # here for now — moving it to zpa_auth_failures.py is a
        # future cleanup, not a behavior change.
        if _RE_SAML_FINGERPRINT_FAIL.search(msg):
            f = self._bucket(
                "ZPA_SAML_FINGERPRINT_MISMATCH",
                Severity.CRITICAL,
                "ZPA broker SAML signing-certificate fingerprint mismatch",
                (
                    "ZCC logged ``BRK_MT_AUTH_SAML_FINGER_PRINT_FAIL``, "
                    "a Zscaler-documented ZPA broker microtunnel-setup "
                    "failure where the SAML assertion's signing-"
                    "certificate fingerprint did not match what the "
                    "broker expected. Almost always caused by an IdP "
                    "certificate rotation that wasn't propagated to the "
                    "Zscaler tenant configuration.\n\n"
                    "Fix path:\n"
                    "  1. In the customer's IdP (Entra/Okta/Ping/etc.), "
                    "     export the current SAML signing certificate.\n"
                    "  2. In ZPA admin -> Administration -> IdP "
                    "     Configuration -> [the IdP entry] -> SAML "
                    "     signing cert, upload the new certificate "
                    "     (or replace the existing fingerprint).\n"
                    "  3. Have the affected user re-authenticate. "
                    "     The SAML response will now match the "
                    "     expected fingerprint."
                ),
                sop_anchor="#saml-fingerprint-mismatch",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

        # Keep-alive 401 (INVALID TOKEN from the IdP).
        if _RE_ONEID_KEEPALIVE_401.search(msg):
            f = self._bucket(
                "ONEID_KEEPALIVE_401",
                Severity.WARNING,
                "OneID keep-alive returned 401 INVALID TOKEN",
                (
                    "ZCC's OneID library tried to keep its session "
                    "token alive against the IdP and received HTTP 401 "
                    "with content ``INVALID TOKEN``. The IdP no longer "
                    "considers the user's session valid -- typically "
                    "because:\n"
                    "  * The IdP-side session expired (refresh-token "
                    "lifetime elapsed).\n"
                    "  * An admin revoked the user's session.\n"
                    "  * A conditional-access policy change forced "
                    "re-auth.\n"
                    "  * Device clock skew > 5 minutes (JWT exp "
                    "claim past).\n\n"
                    "A single 401 here usually self-heals (the user "
                    "is prompted to re-auth in the next browser "
                    "popup). Sustained 401s suggest a stale token in "
                    "ZCC's local store -- ``unregisterDevice`` + "
                    "fresh sign-in is the standard recovery."
                ),
                sop_anchor="#oneid-keepalive-401",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        findings = list(self._buckets.values())

        # Phase 53b (2026-06-26): HTTP 407 burst guard.
        # The corpus audit of 9 real bundles showed every healthy bundle
        # emits dozens-to-thousands of `SME response: ... Status: 407`
        # lines — they are the normal proxy challenge/response handshake.
        # Calling each one an "auth failure" makes the finding fire on
        # every clean bundle. A real 407 incident shows a BURST: 5+
        # SME-407s within a 60-second window (the cookie was lost and
        # the client retries rapidly).
        #
        # Strategy: scan the UNCAPPED 407 timestamp list for any 60s
        # sliding window containing ≥5 events. Drop the finding if no
        # burst is found.
        #
        # Phase 58e-C5 (2026-07-08): now reads self._sme_407_timestamps
        # (uncapped) instead of f.evidence (capped at 10). Prior
        # implementation would silently mask real bursts that happened
        # after the first 10 scattered 407s were already logged.
        _BURST_MIN_EVENTS = 5
        _BURST_WINDOW_S = 60
        keep_findings: List[Finding] = []
        for f in findings:
            if f.code != "HTTP_407_FROM_SME":
                keep_findings.append(f)
                continue
            ts = sorted(self._sme_407_timestamps)
            if len(ts) < _BURST_MIN_EVENTS:
                continue  # not enough events at all — drop
            burst_found = False
            for i in range(len(ts) - _BURST_MIN_EVENTS + 1):
                window = ts[i + _BURST_MIN_EVENTS - 1] - ts[i]
                if window.total_seconds() <= _BURST_WINDOW_S:
                    burst_found = True
                    break
            if burst_found:
                keep_findings.append(f)
            # else: 407s observed but spread out — normal proxy noise.
        findings = keep_findings

        # Aggregate SME-state finding only if we saw bad states.
        bad_count = sum(
            self._sme_state_counts.get(s, 0) for s in _BAD_SME_STATES
        )
        if bad_count > 0 and self._sme_bad_records:
            seen_bad = {
                s: c for s, c in self._sme_state_counts.items()
                if s in _BAD_SME_STATES
            }
            f = Finding(
                code="SME_PROXY_BAD_STATE",
                severity=Severity.CRITICAL,
                title=(
                    f"ZIA Service-Edge proxy in error state "
                    f"({bad_count} record(s))"
                ),
                description=(
                    f"``getSmeProxyState`` reported non-healthy state(s) "
                    f"during the capture: {seen_bad}. "
                    f"SERVER_AUTH_ERROR means the Public Service Edge "
                    f"rejected the auth credentials. "
                    f"SERVER_AUTH_TERMINATED_AT_UNKNOWN is a chaining-auth "
                    f"error -- the realm of the edge and the logged-in "
                    f"user don't match (often an intermediate proxy "
                    f"intercepted the request). "
                    f"SERVER_DOWN_ERROR / INTERNET_UNREACHABLE_ERROR / "
                    f"SERVICE_DOWN_ERROR mean the edge couldn't be "
                    f"reached at the network level. "
                    f"ADAPTER_DOWN_ERROR means the local Z-tunnel "
                    f"adapter is gone."
                ),
                sop_anchor="#sme-proxy-bad-state",
            )
            for rec in self._sme_bad_records:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        return findings
