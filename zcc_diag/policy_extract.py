"""
Policy / App Profile / bypass-resolution extractors.

Three on-demand walks over the bundle's tray and tunnel logs:

  1. ``extract_app_profile(bundle)``  — pulls the customer-level policy
     fields out of the ``TrayPolicy::serialize()`` JSON blob that
     ZSATrayManager.log emits at session start. Returns the App Profile
     name, customer domain, tenant org id, login name, MA host, and
     ZIA / ZPA enrollment flags.

  2. ``extract_bypass_resolutions(bundle)`` — walks tunnel logs for
     ``Resolved exclude hostname: <host> --> <ip>`` lines and returns
     ``Dict[hostname, List[ip]]``. This is the actual end-state of the
     bypass list after DNS resolution -- much more useful for triage
     than the raw csv-style bypass cache because you see what the
     bypassed hosts ACTUALLY resolved to.

  3. ``extract_pac_info(summary)`` — pure summary-side helper. The PAC
     URL is already captured into ``summary.pac`` by summary.py; this
     wrapper just normalises the shape and adds a "where it came from"
     description so the UI can present it cleanly.

These are additive helpers — they don't modify BundleSummary or any
existing detector. Both extractors cap their walk (line / hit limits)
so they're safe on large bundles.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# Caps -- keep the walks bounded on big bundles.
_BYPASS_MAX_LINES_PER_FILE = 100_000
_BYPASS_MAX_HOSTS = 500
_TRAY_MAX_LINES = 200_000


# Fields we pull from the TrayPolicy JSON. Keyed by the JSON key;
# value is the friendlier label shown in the UI.
# Per-field name aliases. Windows TrayPolicy JSON uses camelCase keys
# (``maHostName``, ``ziaCloudName``); the Mac plist dump uses
# snake_case + lowercase (``ma_hostname``, ``zia_cloud_name``) or an
# alternate key with the same data (``ziaCloudNameWithTld``).
#
# Each entry: (tuple of alias keys, friendly label). The parser tries
# every alias in order and stops on first match per field. First win
# always preserved -- so the canonical key is listed first.
_POLICY_FIELDS = [
    (("policy_name",), "App Profile"),
    # ``domain`` is in Windows TrayPolicy JSON but NOT in the Mac
    # plist dump. For Mac we derive from loginName below in
    # ``_apply_field_derivations`` (split on "@" and take the
    # domain part).
    (("domain", "customerDomain", "seedDomain"), "Customer domain"),
    (("companyOrgId", "company_id", "companyId"), "Org ID"),
    (("loginName", "login_name"), "Login name"),
    (("maHostName", "ma_hostname"), "MA host"),
    (("ziaCloudName", "zia_cloud_name", "ziaCloudNameWithTld",
      "cloudName", "cloud_name"), "ZIA cloud"),
    (("zpn_cloud", "zpnCloud"), "ZPA cloud"),
    (("isZIAEnrolled", "is_zia_enrolled"), "ZIA enrolled"),
    (("isZPAEnrolled", "is_zpa_enrolled"), "ZPA enrolled"),
    (("ziaEnabledForUser", "zia_enabled"), "ZIA enabled for user"),
    (("zpaEnabledForUser", "zpa_enabled"), "ZPA enabled for user"),
    (("isOneIdEnabled", "is_oneid_enabled"), "OneID enabled"),
    (("zpnServerV2", "zpn_server"), "ZPA SAML endpoint"),
    (("zpaWBCAuthUrl", "zpa_wbc_auth_url"), "ZPA WBC auth URL"),
    (("pac_url", "pacUrl"), "PAC URL"),
]


def _find_tray_manager_logs(bundle) -> List:
    """Locate tray-log files that contain the TrayPolicy push.

    Naming varies by platform:
      * **Windows**: ``ZSATrayManager_<ts>.log`` -- a dedicated process
        handles the policy push, separate from the tray UI.
      * **macOS**: ``ZSATray_<ts>.log`` -- there's no separate
        ``TrayManager`` process; the tray itself logs the policy
        ``TrayPolicy::serialize()`` blob alongside its UI events.
      * **macOS (older)**: ``com.zscaler.ZSATrayManager_<ts>.log``.

    Match all three to ensure we find the policy push on every bundle
    shape we've seen.
    """
    files = []
    for p in bundle.files:
        if p.suffix != ".log":
            continue
        name = p.name
        if (
            "ZSATrayManager" in name
            or "TrayManager" in name
            or "ZSATray" in name  # Mac: policy push lives in ZSATray.log
        ):
            files.append(p)
    return files


def _find_tunnel_logs(bundle) -> List:
    files = []
    for p in bundle.files:
        if p.suffix != ".log":
            continue
        if "ZSATunnel" in p.name or "TRPTunnel" in p.name:
            files.append(p)
    return files


def _parse_tray_policy_blob(blob: str) -> Dict[str, Any]:
    """Pull each ``_POLICY_FIELDS`` value out of one TrayPolicy blob.

    Two on-the-wire formats exist for the same data:

      * **Windows JSON**: ``"key":"value"`` or ``"key":42`` (no quotes
        around the key sometimes either) emitted by ``ZSATrayManager``.
      * **macOS plist/dict**: ``"key" = "value";`` or ``key = 42;``
        emitted by ``ZSATray`` (Mac doesn't have a separate Manager
        process). Keys may or may not be quoted; values quoted for
        strings, bare for ints/booleans, semicolon-terminated.

    Returns ``{label: value}``. May be empty if no field matched.
    """
    out: Dict[str, Any] = {}
    for aliases, label in _POLICY_FIELDS:
        for key in aliases:
            ek = re.escape(key)
            # String: "key":"val"  OR  "key" = "val";  OR  key = "val";
            mm = re.search(
                rf'"?{ek}"?\s*[:=]\s*"([^"]*)"', blob,
            )
            if mm:
                out[label] = mm.group(1)
                break
            # Bare value (no quotes): zia_cloud_name = zscalertwo;
            mm = re.search(
                rf'"?{ek}"?\s*[:=]\s*(?!")(?P<v>[A-Za-z0-9.\-_]+)\s*[;,}}]',
                blob,
            )
            if mm:
                v = mm.group("v")
                if v == "true":
                    out[label] = True
                elif v == "false":
                    out[label] = False
                elif v.lstrip("-").isdigit():
                    out[label] = int(v)
                else:
                    out[label] = v
                break
            # Boolean / numeric quoted: "key":42 OR "key" = 42;
            mm = re.search(
                rf'"?{ek}"?\s*[:=]\s*(true|false|-?\d+)\s*[;,}}]', blob,
            )
            if mm:
                v = mm.group(1)
                if v == "true":
                    out[label] = True
                elif v == "false":
                    out[label] = False
                else:
                    out[label] = int(v)
                break

    # Derivations: when an explicit field is missing, infer it from
    # related fields. Critical on Mac where the plist dump doesn't
    # include a top-level ``domain`` key but loginName carries the
    # user's domain after the "@".
    if not out.get("Customer domain"):
        login = out.get("Login name") or ""
        if "@" in login:
            derived = login.rsplit("@", 1)[-1].strip().lower()
            if derived and "." in derived:
                out["Customer domain"] = derived
    return out


def _score_policy(parsed: Dict[str, Any]) -> int:
    """Score how 'populated' a parsed TrayPolicy blob is. The ZCC service
    emits an empty / boilerplate TrayPolicy push at session start before
    Mobile Admin returns the real policy; later pushes are the populated
    ones we actually want. Count non-empty strings + ``True`` booleans."""
    score = 0
    for v in parsed.values():
        if isinstance(v, str) and v:
            score += 1
        elif isinstance(v, bool) and v:
            score += 1
        elif isinstance(v, int):
            score += 1  # any int counts (org IDs etc are useful even if 0)
    return score


def extract_app_profile(bundle) -> Dict[str, Any]:
    """Pull the customer-level config from TrayPolicy.

    Two emitter shapes:

      * **Windows (ZSATrayManager)** writes blobs prefixed with
        ``TrayPolicy::serialize() - trayPolicy = {...}`` on a single
        line (the whole JSON-shaped dict). We brace-walk to find the
        matching ``}``.
      * **macOS (ZSATray)** dumps the policy plist as a bare
        ``{...}`` block with NO ``TrayPolicy::serialize()`` anchor —
        it's just an Apple ``-description`` plist style dump indented
        across many lines.

    Strategy: scan for the Windows marker first; if no marker is found
    in a file, fall back to parsing the entire file content as one
    pseudo-blob (the regex parser is field-specific enough that the
    fields it looks for don't appear elsewhere in tray logs). Scores
    every parsed blob and keeps the most-populated one.
    """
    best: Dict[str, Any] = {}
    best_score = -1
    best_source = ""
    for path in _find_tray_manager_logs(bundle):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                content = fp.read(_TRAY_MAX_LINES * 800)  # ~bounded read
        except OSError:
            continue
        any_marker = False
        # Iterate over every Windows-shaped TrayPolicy blob in this file.
        for m in re.finditer(
            r"TrayPolicy::serialize\(\)\s*-\s*trayPolicy\s*=\s*(\{)",
            content,
        ):
            any_marker = True
            blob_start = m.end() - 1
            depth = 0
            i = blob_start
            end = -1
            while i < len(content):
                c = content[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
                i += 1
            if end < 0:
                continue
            blob = content[blob_start:end]
            parsed = _parse_tray_policy_blob(blob)
            s = _score_policy(parsed)
            if s > best_score:
                best, best_score, best_source = parsed, s, path.name

        # Mac fallback: no Windows-shaped marker, but the file may still
        # contain a plist-format policy dump. Run the field parser on
        # the whole file content; the policy field NAMES (maHostName,
        # policy_name, companyOrgId, ...) are unique enough that a
        # false positive elsewhere in the tray log is extremely unlikely.
        if not any_marker:
            parsed = _parse_tray_policy_blob(content)
            s = _score_policy(parsed)
            if s > best_score:
                best, best_score, best_source = parsed, s, path.name
    if best:
        best["source"] = best_source

    # Partner-Login extraction. Phase 32 (2026-06-19): this used to
    # only run when the TrayPolicy extractor came up empty
    # (best_score <= 0). That gated the username extraction behind
    # "no TrayPolicy at all" — which broke any bundle where the
    # ONLY TrayPolicy::serialize() blob in the bundle is the
    # *install-day* one (every flag = bootstrap default = false,
    # but the JSON has enough fields to score > 0). Example Tenant A bundle
    # 2026-06-18 hit exactly this shape: TrayPolicy from Jun 12
    # install day scored high, the Partner-Login fallback never
    # ran, and a user's synthetic email (user@example.invalid) — clearly
    # present in the current Jun 18 tray-manager log — never
    # populated the header.
    #
    # Fix: ALWAYS run Partner-Login extraction. Merge its fields
    # INTO best, but only for keys best doesn't already populate
    # with a meaningful value (or where best holds a sentinel/
    # stale install-day value — see _is_stale_value below).
    # Username extraction in particular is moved to ALWAYS-merge
    # because the AppInfo.xml loginName is frequently sanitized
    # to "###" / "" by ZCC export, leaving the policy logs as
    # the only authoritative source.
    partner = _extract_partner_login_fallback(bundle)
    if partner:
        for k, v in partner.items():
            existing = best.get(k)
            # Sentinel-aware merge: replace install-day stale or
            # sanitized values with partner-login findings. The
            # _is_stale_value helper recognises Phase 33's
            # sentinel set ("###", "(unset)", empty, etc).
            if not existing or _is_stale_value(existing):
                best[k] = v
        if best_score <= 0:
            best.setdefault(
                "source",
                "Partner-Login fallback (ZSATrayManager)",
            )

    # Phase 32 runtime suite-evidence override. The install-day
    # TrayPolicy carries isZIAEnrolled/isZPAEnrolled = false because
    # ZCC hasn't enrolled with the cloud yet at install. If that's
    # the ONLY blob the bundle has but the current logs show ZCC
    # is actively running ZIA/ZPA traffic, we must NOT trust the
    # stale install-day flag. The sidebar gate later reads these
    # flags and hides the modules — burning the engineer.
    evidence = _detect_runtime_suite_evidence(bundle)
    if evidence.get("zia_runtime_active"):
        best["zia_runtime_active"] = True
        best["zia_runtime_source"] = evidence.get("zia_source", "")
        # Override stale install-day false with runtime truth.
        if best.get("ZIA enrolled") is False:
            best["ZIA enrolled"] = True
            best["ZIA enrolled override"] = "runtime"
    if evidence.get("zpa_runtime_active"):
        best["zpa_runtime_active"] = True
        best["zpa_runtime_source"] = evidence.get("zpa_source", "")
        if best.get("ZPA enrolled") is False:
            best["ZPA enrolled"] = True
            best["ZPA enrolled override"] = "runtime"
    return best


# Phase 33 (2026-06-19): values ZCC writes to indicate a field has
# been redacted, sanitized, or never populated. When `loginName`,
# `domain`, etc. carry one of these we treat the field as missing
# and let downstream extractors (partner login, login_hint, etc)
# take over. "###" is what ZCC export uses when bundles are
# uploaded through certain Support channels with redaction on.
_SENTINEL_VALUES = frozenset({
    "", "###", "null", "(null)", "none", "(none)",
    "(unset)", "(unknown)", "n/a", "na",
})


def _is_stale_value(v: Any) -> bool:
    """True if v is a known-junk placeholder that should be replaced
    by a real extracted value when one is available."""
    if isinstance(v, str):
        return v.strip().lower() in _SENTINEL_VALUES
    return False


def _detect_runtime_suite_evidence(bundle) -> Dict[str, Any]:
    """Scan tray + tray-manager + tunnel logs for *live runtime*
    evidence that ZIA and/or ZPA are actually in use, regardless
    of what the install-day TrayPolicy blob says.

    Phase 32 (2026-06-19): added after Example Tenant A bundle showed
    isZIAEnrolled=isZPAEnrolled=false from a Jun-12 install-day
    blob, while the same bundle's Jun-18 tray logs were full of
    "ZPA state changed To: TUNNEL_FORWARDING", "processZPAPart",
    and "Client policy ZPN enabled. Broker Cloud:" markers —
    unmistakable ZPA-active signals that the gate was ignoring.

    Returns a dict with keys:
      - zia_runtime_active (bool)
      - zia_source (str — which marker hit, for provenance)
      - zpa_runtime_active (bool)
      - zpa_source (str)

    Provenance principle: every flag here ties to a specific log
    line marker; the source string is shown in the UI so the
    engineer can verify.
    """
    out: Dict[str, Any] = {
        "zia_runtime_active": False,
        "zia_source": "",
        "zpa_runtime_active": False,
        "zpa_source": "",
    }
    # Iterate tray + tray-manager logs. Bounded read per file.
    for path in _find_tray_manager_logs(bundle):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                # 8 MB per file — plenty for any tray log we've seen.
                content = fp.read(8 * 1024 * 1024)
        except OSError:
            continue

        # ---- ZPA runtime markers ----
        if not out["zpa_runtime_active"]:
            for marker, label in (
                ("ZPA state changed",
                 "tray log: 'ZPA state changed' state-machine event"),
                ("Client policy ZPN enabled",
                 "tray log: 'Client policy ZPN enabled. Broker Cloud:'"),
                ("processZPAPart",
                 "tray log: 'processZPAPart: domain:' parsing"),
                ("createZPAPartnerTenantTrayPolicyList",
                 "tray-manager log: Partner Tenant ZPA policy push"),
                ("ZPN_AUTHENTICATION_REQUIRED",
                 "tray log: ZPA RPC re-auth notification"),
                ("TUNNEL_FORWARDING",
                 "tray log: ZPA tunnel-forwarding state"),
            ):
                if marker in content:
                    out["zpa_runtime_active"] = True
                    out["zpa_source"] = label
                    break

        # ---- ZIA runtime markers ----
        if not out["zia_runtime_active"]:
            for marker, label in (
                ("mobile.zscalertwo.net",
                 "tray log: ZIA cloud zscalertwo URL"),
                ("mobile.zscaler.net",
                 "tray log: ZIA cloud zscaler URL"),
                ("mobile.zscloud.net",
                 "tray log: ZIA cloud zscloud URL"),
                ("mobile.zscalergov.net",
                 "tray log: ZIA cloud zscalergov URL"),
                ("mobile.zscalerthree.net",
                 "tray log: ZIA cloud zscalerthree URL"),
                ("mobile.zscalerbeta.net",
                 "tray log: ZIA cloud zscalerbeta URL"),
                ("mobile.zscaler.us",
                 "tray log: ZIA cloud zscaler.us URL"),
            ):
                if marker in content:
                    out["zia_runtime_active"] = True
                    out["zia_source"] = label
                    break

        if out["zia_runtime_active"] and out["zpa_runtime_active"]:
            break  # both confirmed; no need to scan more files

    # Tunnel-log fallback. The tray logs miss-rate is low but the
    # tunnel log can confirm ZIA without any tray-log mobile.* URL
    # when traffic is flowing — "Tunnel api request:" lines hit
    # the mobile cloud endpoints.
    if not out["zia_runtime_active"]:
        for path in _find_tunnel_logs(bundle):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fp:
                    content = fp.read(8 * 1024 * 1024)
            except OSError:
                continue
            if "Tunnel api request:" in content and "mobile." in content:
                out["zia_runtime_active"] = True
                out["zia_source"] = (
                    "tunnel log: 'Tunnel api request:' to a "
                    "Zscaler mobile.* endpoint"
                )
                break

    return out


def _extract_partner_login_fallback(bundle) -> Dict[str, Any]:
    """Salvage what's possible from a Partner-Tenant (ZPA-only) bundle
    that doesn't emit a full TrayPolicy JSON push.

    What we can extract:
      * ``ZPA cloud`` from ``sendTrayPolicy: zpaCloud: <host>`` lines.
      * ``enrollment_status`` — a string that tells the engineer this
        bundle is intentionally Partner-Tenant-shaped, not broken.
      * ``Partner login`` flag — derived from the
        ``createZPAPartnerTenantTrayPolicyList`` marker.

    What's NOT in this kind of bundle (and shouldn't be shown as "?"):
      * loginName  → user isn't enrolled to a ZIA tenant
      * customerDomain → same
      * Org ID → same

    The Header strip handles the "Partner Tenant" state by labelling
    these N/A fields explicitly rather than showing "?".
    """
    out: Dict[str, Any] = {}
    is_partner = False
    is_unenrolled = False
    partner_user_email = ""
    partner_user_domain = ""
    for path in _find_tray_manager_logs(bundle):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                content = fp.read(_TRAY_MAX_LINES * 800)
        except OSError:
            continue

        # zpaCloud:<host>
        if "ZPA cloud" not in out:
            m = re.search(
                r"sendTrayPolicy:\s*zpaCloud:\s*([^,\s]+)",
                content,
            )
            if m:
                out["ZPA cloud"] = m.group(1).strip()

        # Partner-Login marker
        if "createZPAPartnerTenantTrayPolicyList" in content:
            is_partner = True

        # Phase 26 (2026-06-17): real user email extraction. Two
        # patterns to try — both appear in tray / tray-manager logs
        # for Partner-Tenant / pre-enrolled bundles:
        #
        # (a) "Partner Login  getPartnerConnection not found
        #      for user = user@example.invalid"
        # (b) "[processLoginHint] url: https://samlsp.private.zscaler
        #      .com/auth/v2/login?domain=example.invalid&...
        #      &login_hint=user%40example.invalid"
        #
        # Without these, Partner Tenant bundles showed
        # "(not applicable — Partner Tenant)" for the User field —
        # but the email IS in the logs, just under different paths
        # than the AppInfo.xml loginName field we used to rely on.
        if not partner_user_email:
            m = re.search(
                r"Partner Login.*?for user\s*=\s*([^\s,]+@[^\s,]+)",
                content,
                re.IGNORECASE,
            )
            if m:
                partner_user_email = m.group(1).strip()
                if "@" in partner_user_email:
                    partner_user_domain = (
                        partner_user_email.split("@", 1)[1]
                    )
        if not partner_user_email:
            m = re.search(
                r"login_hint=([^&\s\"']+)",
                content,
                re.IGNORECASE,
            )
            if m:
                # URL-decode the email (%40 → @)
                raw = m.group(1).replace("%40", "@").replace("+", " ")
                if "@" in raw:
                    partner_user_email = raw
                    partner_user_domain = raw.split("@", 1)[1]

        # Unenrolled marker
        if "Resetting domain and loginName as user isn't enrolled" in content:
            is_unenrolled = True

    if is_partner or is_unenrolled:
        out["Partner login"] = "yes" if is_partner else ""
        # Set enrollment_status so the Header can distinguish
        # "data missing" from "data N/A by design".
        if is_partner:
            out["enrollment_status"] = "ZPA Partner Tenant (no ZIA enrollment)"
        elif is_unenrolled:
            out["enrollment_status"] = "User not enrolled at bundle capture time"
        # Phase 26: prefer the real extracted email over the
        # "(not applicable...)" placeholder. The placeholder is only a
        # fallback when no email was found in tray/tray-manager logs.
        if partner_user_email:
            out["Login name"] = partner_user_email
        else:
            out["Login name"] = (
                "(not applicable — Partner Tenant)" if is_partner
                else "(unenrolled)"
            )
        if partner_user_domain:
            out["Customer domain"] = partner_user_domain
        else:
            out["Customer domain"] = (
                "(not applicable — Partner Tenant)" if is_partner
                else "(unenrolled)"
            )
        out["Org ID"] = (
            "(not applicable — Partner Tenant)" if is_partner
            else "(unenrolled)"
        )
    return out


# --------------------------------------------------------------------
# Forwarding Profile + App Profile detail extractor (added in v34)
# --------------------------------------------------------------------
#
# Engineers triaging a ZCC issue often want to inspect the actually-
# deployed policy: WHICH App Profile and Forwarding Profile is on this
# machine, and what mode are they configured for?
#
# ZSATrayManager (Windows) and ZSAService (macOS) both dump the policy
# in two shapes:
#
#   Windows JSON (single line):
#     trayPolicy = {"policy_name":"PROD App","forwardingProfileActions":[
#       {"networkType":0,"actionType":1,"redirectWebTraffic":1,...},
#       {"networkType":1,...},  ...
#     ],"forwardingProfileZPNAction":{"actionTypeTrusted":1,...}, ...}
#
#   macOS plist (multi-line, semicolon-terminated):
#     "policy_name" = "MacOS App Profile";
#     forwardingProfileActions = (
#       { networkType = 0; actionType = 1; ... },
#       ...
#     );
#
# The networkType integer maps to a network context the user is on:
#   0 = Off-Trusted (general Internet / café / home)
#   1 = Trusted (corporate office, trusted network test passed)
#   2 = VPN (legacy VPN client active)
#
# The actionType integer maps to:
#   0 = NONE (no Zscaler intercept)
#   1 = TUN (Z-Tunnel — encrypted to SME)
#   2 = PAC / system proxy
#   3 = DIRECT bypass
#   (values may vary slightly by ZCC version)
#
# We surface the FIRST 50 KB of the TrayPolicy blob (or the entire
# ZSAService policy section on Mac), then parse out:
#   - app_profile.name
#   - app_profile.key_settings (curated set of impactful toggles)
#   - forwarding_profile.by_network_type → ordered list of rows
#   - forwarding_profile.zpa_actions (TUN mode for Trusted/NonTrusted/VPN)
#   - captive_portal (sub-config from captivePortalConfig)


_NETWORK_TYPE_LABEL = {
    0: "Off-Trusted (Internet / café / home)",
    1: "Trusted (corporate office)",
    2: "VPN (legacy VPN active)",
}
_ACTION_TYPE_LABEL = {
    0: "NONE (no Zscaler intercept)",
    1: "TUN (Z-Tunnel to SME)",
    2: "PROXY / PAC",
    3: "DIRECT (bypass)",
}

# Curated list of App Profile settings worth surfacing. Each tuple:
#   (key-aliases-tuple, friendly-label, value-formatter-or-None)
# NOTE: ``policy_name`` is rendered as the section HEADER (Profile
# name caption), not as a row -- duplicating it as "Name" was just
# visual clutter.
_APP_PROFILE_KEY_SETTINGS = [
    (("enableAntiTampering", "enable_anti_tampering"),
     "Anti-tampering", None),
    (("strictEnforcement", "strict_enforcement"),
     "Strict enforcement", None),
    (("hideUIOnLaunch", "hide_ui_on_launch"),
     "Hide tray UI on launch", None),
    (("ssoUsingWindowsPrimaryAccount",),
     "SSO via Windows primary account", None),
    (("autofillIDPUsername", "autoFillUsingLoginHint"),
     "Autofill IdP username", None),
    (("autoReauthForOffTrusted",),
     "Auto-reauth off-trusted", None),
    (("autoReauthForOnTrusted",),
     "Auto-reauth on-trusted", None),
    (("autoReauthForVpnTrusted",),
     "Auto-reauth VPN", None),
    (("enableLocalPacketCapture",),
     "Local packet capture enabled", None),
    (("enforceSecurePacUrls",),
     "Enforce secure PAC URLs", None),
    (("enableZdpForPolicy",),
     "ZDP for policy enabled", None),
    (("upmEnabledForUser",),
     "UPM enabled for user", None),
    (("supportEnabled",),
     "Support / troubleshooting enabled", None),
    (("logLevel",), "Log level", None),
    (("logMode",), "Log mode", None),
    (("log_file_size", "logFileSize"),
     "Log file size (MB)", None),
]


def _coerce_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _try_parse_braced_json(content: str, start: int) -> Optional[str]:
    """Brace-walk to extract a balanced { ... } starting at content[start]."""
    if start < 0 or start >= len(content) or content[start] != "{":
        return None
    depth = 0
    for i in range(start, len(content)):
        c = content[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return content[start:i + 1]
    return None


def _extract_field_value(blob: str, key: str) -> Optional[str]:
    """Look up a single key in either JSON or plist style. Returns the
    string value (raw), or None if not found."""
    ek = re.escape(key)
    # JSON: "key":"val"  OR plist: "key" = "val";
    m = re.search(rf'"?{ek}"?\s*[:=]\s*"([^"]*)"', blob)
    if m:
        return m.group(1)
    # Bare numeric / boolean: "key":42  OR  key = 42;
    m = re.search(rf'"?{ek}"?\s*[:=]\s*([0-9A-Za-z._-]+)\s*[,;\}}]', blob)
    if m:
        return m.group(1)
    return None


def _parse_forwarding_action(action_blob: str) -> Dict[str, Any]:
    """Extract the key fields from one forwardingProfileActions entry."""
    fields = {}
    for k in (
        "networkType", "actionType", "redirectWebTraffic",
        "enablePacketTunnel", "useTunnel2ForProxiedWebTraffic",
        "latencyBasedZenEnablement", "tunnel2FallbackType",
        "allowTLSFallback", "dropIpv6Traffic", "customPac",
        "zenProbeInterval", "zenThresholdLimit", "primaryTransport",
    ):
        v = _extract_field_value(action_blob, k)
        if v is not None:
            fields[k] = v
    return fields


def extract_profile_details(
    bundle,
    os_family: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the deployed App Profile + Forwarding Profile detail.

    ``os_family`` (``"windows"`` / ``"macos"`` / ``None``) selects which
    parser path runs. Mac and Windows ZCC log policy in **completely
    different formats** and each parser has its own anchors:

      * **Windows**: ``ZSATrayManager`` logs the policy as a single
        JSON line: ``TrayPolicy::serialize() - trayPolicy = {...}``.
        Forwarding-profile rules and captive-portal config are NOT
        in this blob -- they appear as discrete one-line records
        elsewhere in the same file (``Partner Login
        forwardingProfileZpaActions - networkType = N - key = value``
        and ``processed captive portal config: {json}``).

      * **macOS**: ``ZSAService`` / ``ZSATray`` logs the policy as a
        multi-line plist dump with ``forwardingProfileActions = (...)``
        and ``failOpenPolicy = { ... }`` blocks. No flat one-line
        records.

    Running both parsers blindly on every bundle wastes time and
    risks cross-contamination on weird hybrid bundles. Branching on
    OS keeps each platform's parser focused on its native format.
    When ``os_family`` is unknown we run BOTH paths as a fallback.

    Output shape unchanged from prior versions.
    """
    out: Dict[str, Any] = {
        "app_profile": {"name": "", "key_settings": [],
                        "captive_portal": {}},
        "forwarding_profile": {
            "name": "(inline policy)",
            # Split by service. Each list holds rows of the same shape
            # as the legacy ``by_network_type``: dicts with
            # ``network`` / ``action`` / ``knobs``.
            "by_network_type_zia": [],
            "by_network_type_zpa": [],
            # ``by_network_type`` is preserved as a LEGACY alias for
            # any older code that still reads it. New UI code reads
            # the split lists above.
            "by_network_type": [],
            "zpa_actions": {},
        },
        "source": "",
    }

    os_family = (os_family or "").lower()
    is_win = (os_family == "windows")
    is_mac = (os_family in ("macos", "mac", "darwin"))
    is_unknown = not (is_win or is_mac)

    # Build candidate file list. Windows: tray-manager only. Mac:
    # tray + ZSAService (Mac sometimes dumps via ZSAService). Unknown:
    # try everything.
    candidates = list(_find_tray_manager_logs(bundle))
    if is_mac or is_unknown:
        for p in bundle.files:
            if p.suffix != ".log":
                continue
            if ("ZSAService" in p.name
                    or "com.zscaler.ZscalerService" in p.name):
                candidates.append(p)

    best_score = -1
    best: Dict[str, Any] = {}
    best_source = ""

    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                content = fp.read(_TRAY_MAX_LINES * 1200)
        except OSError:
            continue

        # Collect candidate blobs from this file. ZCC dumps the
        # TrayPolicy blob MULTIPLE TIMES over a session (one per
        # policy push -- enrollment, refresh, network change). The
        # first dump is typically pre-enrollment (all fields empty).
        # Later dumps carry the populated post-enrollment policy.
        # We iterate every occurrence and pick the most-populated.
        blobs: List[str] = []

        # ---- Windows path: every TrayPolicy::serialize() occurrence ----
        if is_win or is_unknown:
            anchor_marker = "TrayPolicy::serialize() - trayPolicy ="
            search_from = 0
            while True:
                idx = content.find(anchor_marker, search_from)
                if idx < 0:
                    break
                brace_at = content.find("{", idx)
                extracted = _try_parse_braced_json(content, brace_at)
                if extracted:
                    blobs.append(extracted)
                    search_from = idx + len(anchor_marker) + len(extracted)
                else:
                    search_from = idx + len(anchor_marker)

        # ---- Mac path: earliest-anchor plist slice (only one slice
        #     per file -- the Mac plist isn't periodically re-dumped) ----
        if not blobs and (is_mac or is_unknown):
            mac_anchors = [
                "forwardingProfileActions",
                "forwardingProfileZpaActions",
                "policy_name",
                "appProfileName",
                "failOpenPolicy",
            ]
            earliest = -1
            for anchor in mac_anchors:
                pos = content.find(anchor)
                if pos >= 0 and (earliest < 0 or pos < earliest):
                    earliest = pos
            if earliest >= 0:
                blob_start = max(0, earliest - 10_000)
                blobs.append(content[blob_start:blob_start + 200_000])

        if not blobs:
            continue

        # Score every blob from this file; track the best.
        for blob in blobs:
            parsed = _parse_profile_blob(blob)

            # ---- Windows flat-line augmentation ----
            # The Windows ZSATrayManager logs forwardingProfile actions
            # + captive-portal config as DISCRETE one-line records
            # elsewhere in the same file (not inside any single
            # TrayPolicy blob). Run the augmenter against the WHOLE
            # file content for each candidate blob -- the augmenter
            # is idempotent (first-write-wins).
            if is_win or is_unknown:
                _augment_from_windows_flat_lines(content, parsed)

            # Score: more populated fields = better.
            score = (
                (3 if parsed["app_profile"]["name"] else 0)
                + len(parsed["app_profile"]["key_settings"])
                + (len(parsed["forwarding_profile"]["by_network_type_zia"])
                   + len(parsed["forwarding_profile"]["by_network_type_zpa"])
                   + len(parsed["forwarding_profile"]["by_network_type"])
                   ) * 3
                + len(parsed["app_profile"]["captive_portal"])
            )
            if score > best_score:
                best = parsed
                best_score = score
                best_source = path.name

    if best:
        out.update(best)
        out["source"] = best_source
    return out


def _parse_profile_blob(blob: str) -> Dict[str, Any]:
    """Parse a TrayPolicy / ZSAService policy blob into structured form."""
    out: Dict[str, Any] = {
        "app_profile": {"name": "", "key_settings": [],
                        "captive_portal": {}},
        "forwarding_profile": {
            "name": "(inline policy)",
            "by_network_type_zia": [],
            "by_network_type_zpa": [],
            "by_network_type": [],  # legacy alias
            "zpa_actions": {},
        },
        "source": "",
    }

    # ---- App Profile name + key settings ----
    name = _extract_field_value(blob, "policy_name") \
        or _extract_field_value(blob, "appProfileName") or ""
    out["app_profile"]["name"] = name

    for aliases, label, fmt in _APP_PROFILE_KEY_SETTINGS:
        for k in aliases:
            v = _extract_field_value(blob, k)
            if v is None:
                continue
            # Drop visually-empty values -- if the key exists in the
            # policy snapshot but has no meaningful value (empty
            # string, "0" for non-boolean integer fields like log
            # level / log file size when the field was simply not
            # populated), there's nothing to show.
            stripped = str(v).strip()
            if stripped == "":
                break
            # Boolean-looking ints → friendly labels
            if v in ("0", "false", "False"):
                v_out = "off"
            elif v in ("1", "true", "True"):
                v_out = "on"
            else:
                v_out = v
            out["app_profile"]["key_settings"].append({
                "setting": label, "value": v_out,
            })
            break

    # ---- Captive portal config (sub-dict) ----
    # Two shapes:
    #   * Windows JSON: captivePortalConfig = { ... }
    #   * macOS plist:  failOpenPolicy = { captivePortalWebSecDisable
    #                   Minutes = N; tunnelFailureRetryCount = N; ... }
    # We try both anchors and merge what each contributes.
    for anchor, fields in (
        ("captivePortalConfig", [
            ("enableCaptivePortalDetection", "Detection enabled"),
            ("enableEmbeddedCaptivePortal", "Embedded captive portal"),
            ("automaticCapture", "Automatic capture"),
            ("automaticCaptureDuration", "Auto-capture duration (s)"),
            ("captivePortalWebSecDisableMinutes",
             "WebSec disable on captive (min)"),
            ("enableFailOpen", "Fail-open on captive portal"),
            ("captiveDetectionUrl", "Detection URL"),
        ]),
        ("failOpenPolicy", [
            ("captivePortalWebSecDisableMinutes",
             "WebSec disable on captive (min)"),
            ("enableStrictEnforcementPrompt",
             "Strict enforcement prompt"),
            ("enableWebSecOnProxyUnreachable",
             "WebSec on proxy unreachable"),
            ("enableWebSecOnTunnelFailure",
             "WebSec on tunnel failure"),
            ("tunnelFailureRetryCount",
             "Tunnel-failure retry count"),
            ("strictEnforcementPromptDelaySeconds",
             "Strict-enforcement prompt delay (s)"),
        ]),
    ):
        m = re.search(rf"{anchor}\s*[:=]\s*(\{{)", blob)
        if not m:
            continue
        sub_blob = _try_parse_braced_json(blob, m.end() - 1)
        if not sub_blob:
            continue
        for cp_key, cp_label in fields:
            v = _extract_field_value(sub_blob, cp_key)
            if v is None:
                continue
            if v in ("0", "false", "False"):
                v = "off"
            elif v in ("1", "true", "True"):
                v = "on"
            # First-write-wins so the more-canonical anchor's value
            # isn't overwritten by an alternate-anchor value.
            out["app_profile"]["captive_portal"].setdefault(cp_label, v)

    # ---- Forwarding Profile actions (per network type) ----
    # The actions array contains 3 entries, one per networkType.
    # Find each entry by brace-walking inside `forwardingProfileActions`.
    fp_match = re.search(
        r"forwardingProfileActions\s*[:=]\s*[\(\[]", blob,
    )
    if fp_match:
        # Find the matching closing paren/bracket and extract every
        # nested {...} from inside.
        start_idx = fp_match.end()
        opener = blob[start_idx - 1]
        closer = ")" if opener == "(" else "]"
        depth = 1
        i = start_idx
        end_idx = -1
        while i < len(blob):
            c = blob[i]
            if c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
            i += 1
        if end_idx > start_idx:
            actions_block = blob[start_idx:end_idx]
            # Pull every balanced { ... } out
            i = 0
            actions: List[Dict[str, Any]] = []
            while i < len(actions_block):
                if actions_block[i] == "{":
                    extracted = _try_parse_braced_json(actions_block, i)
                    if extracted:
                        actions.append(_parse_forwarding_action(extracted))
                        i += len(extracted)
                        continue
                i += 1
            for a in actions:
                nt = _coerce_int(a.get("networkType"))
                at = _coerce_int(a.get("actionType"))
                knobs = {}
                for k in (
                    "redirectWebTraffic", "enablePacketTunnel",
                    "useTunnel2ForProxiedWebTraffic",
                    "latencyBasedZenEnablement",
                    "tunnel2FallbackType", "allowTLSFallback",
                    "dropIpv6Traffic", "customPac",
                    "zenProbeInterval", "zenThresholdLimit",
                    "primaryTransport",
                ):
                    v = a.get(k)
                    if v is None:
                        continue
                    if v in ("0", "false", "False"):
                        v = "off"
                    elif v in ("1", "true", "True"):
                        v = "on"
                    knobs[k] = v
                row = {
                    "network": _NETWORK_TYPE_LABEL.get(
                        nt, f"Network type {nt}"),
                    "action": _ACTION_TYPE_LABEL.get(
                        at, f"Action type {at}"),
                    "knobs": knobs,
                }
                # ``forwardingProfileActions`` is the ZIA / general
                # service block on Mac. ZPA-specific rules live in
                # ``forwardingProfileZpaActions`` (parsed separately
                # below).
                out["forwarding_profile"]["by_network_type_zia"].append(row)
                out["forwarding_profile"]["by_network_type"].append(row)

    # ---- Mac ZPA actions (per-network-type, separate plist array) ----
    zpa_arr = re.search(
        r"forwardingProfileZpaActions\s*[:=]\s*[\(\[]", blob,
    )
    if zpa_arr:
        start_idx = zpa_arr.end()
        opener = blob[start_idx - 1]
        closer = ")" if opener == "(" else "]"
        depth = 1
        i = start_idx
        end_idx = -1
        while i < len(blob):
            c = blob[i]
            if c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
            i += 1
        if end_idx > start_idx:
            actions_block = blob[start_idx:end_idx]
            i = 0
            while i < len(actions_block):
                if actions_block[i] == "{":
                    extracted = _try_parse_braced_json(actions_block, i)
                    if extracted:
                        a = _parse_forwarding_action(extracted)
                        nt = _coerce_int(a.get("networkType"))
                        at = _coerce_int(a.get("actionType"))
                        knobs = {
                            k: v for k, v in a.items()
                            if k not in ("networkType", "actionType")
                        }
                        out["forwarding_profile"][
                            "by_network_type_zpa"
                        ].append({
                            "network": _NETWORK_TYPE_LABEL.get(
                                nt, f"Network type {nt}"),
                            "action": _ACTION_TYPE_LABEL.get(
                                at, "TUN (Z-Tunnel — ZPA)"),
                            "knobs": knobs,
                        })
                        i += len(extracted)
                        continue
                i += 1

    # ---- ZPA general actions (per network type, simple action ids) ----
    zpn_match = re.search(
        r"forwardingProfileZPNAction\s*[:=]\s*(\{)", blob,
    )
    if zpn_match:
        zpn_blob = _try_parse_braced_json(blob, zpn_match.end() - 1)
        if zpn_blob:
            for k, lbl in [
                ("actionTypeTrusted", "Trusted"),
                ("actionTypeNonTrusted", "Non-Trusted"),
                ("actionTypeVPN", "VPN"),
            ]:
                v = _extract_field_value(zpn_blob, k)
                if v is not None:
                    out["forwarding_profile"]["zpa_actions"][lbl] = \
                        _ACTION_TYPE_LABEL.get(
                            _coerce_int(v), f"Action type {v}")

    return out


# Pattern for Windows-format forwarding-profile rows. Each line is:
#   ``INF Partner Login forwardingProfileZpaActions
#      - networkType = N - <key> = <value>``
# (also ``forwardingProfileActions`` — same shape.)
_WIN_FP_RE = re.compile(
    r"forwardingProfile(?P<kind>Zpa)?Actions"
    r"\s*-\s*networkType\s*=\s*(?P<nt>\d+)"
    r"\s*-\s*(?P<key>\w+)\s*=\s*(?P<val>\S+)"
)

# Pattern for Windows-format captive-portal-config JSON dump.
_WIN_CP_RE = re.compile(
    r"processed captive portal config:\s*(\{[^}]+\})"
)


def _augment_from_windows_flat_lines(
    content: str,
    parsed: Dict[str, Any],
) -> None:
    """Mutate ``parsed`` in place by extracting forwarding-profile
    and captive-portal data from Windows-format flat log lines.

    Mac dumps these as nested plist blobs that fit inside the
    TrayPolicy::serialize() blob -- ``_parse_profile_blob`` handles
    that path. Windows logs the SAME data as discrete one-line
    records elsewhere in the file, so we scan the whole file content
    for them and merge whatever we find. First-write-wins so this
    augmenter never overwrites Mac-blob data.
    """
    # ---- Forwarding profile ----
    # Accumulate {networkType_int -> {key: value, "_zpa": bool}}
    per_nt: Dict[int, Dict[str, Any]] = {}
    for m in _WIN_FP_RE.finditer(content):
        try:
            nt = int(m.group("nt"))
        except ValueError:
            continue
        key = m.group("key")
        val = m.group("val")
        is_zpa = (m.group("kind") == "Zpa")
        bucket = per_nt.setdefault(nt, {"_zpa": is_zpa})
        # First-write-wins (multiple log iterations re-emit the same
        # lines; we keep the first observed value).
        bucket.setdefault(key, val)
        # If we see BOTH Zpa and non-Zpa kinds for the same nt,
        # de-flag (the row spans both action types).
        if is_zpa != bucket["_zpa"]:
            bucket["_zpa"] = False  # mixed -> treat as general

    # Don't double-render -- only fill in when Mac-blob parser left
    # the buckets empty. Windows augmenter routes rows to the right
    # bucket (ZIA vs ZPA) based on the line kind, rather than tagging
    # them in the same list (which previously made every Windows row
    # look like "ZPA only" even on ZIA+ZPA tenants).
    have_zia_rows = bool(parsed["forwarding_profile"]["by_network_type_zia"])
    have_zpa_rows = bool(parsed["forwarding_profile"]["by_network_type_zpa"])
    if per_nt and not (have_zia_rows and have_zpa_rows):
        for nt in sorted(per_nt.keys()):
            entry = per_nt[nt]
            is_zpa = entry.pop("_zpa", False)
            at_raw = entry.get("actionType")
            at_i = _coerce_int(at_raw)
            # When actionType is missing (Windows ZPA-only rows don't
            # log it), the presence of a row IS the action signal --
            # TUN is the only possible action when a forwarding rule
            # exists. Show a short label without the verbose
            # "(inferred from action row)" justification.
            action_label = (
                _ACTION_TYPE_LABEL.get(at_i, "TUN (Z-Tunnel to SME)")
                if at_raw is not None
                else "TUN (Z-Tunnel)"
            )
            knobs = {
                k: v for k, v in entry.items()
                if k not in ("networkType", "actionType")
            }
            row = {
                "network": _NETWORK_TYPE_LABEL.get(
                    nt, f"Network type {nt}"),
                "action": action_label,
                "knobs": knobs,
            }
            if is_zpa and not have_zpa_rows:
                parsed["forwarding_profile"][
                    "by_network_type_zpa"
                ].append(row)
                parsed["forwarding_profile"][
                    "by_network_type"
                ].append(row)  # legacy alias
            elif not is_zpa and not have_zia_rows:
                parsed["forwarding_profile"][
                    "by_network_type_zia"
                ].append(row)
                parsed["forwarding_profile"][
                    "by_network_type"
                ].append(row)  # legacy alias

    # ---- Captive portal config (single-line JSON) ----
    if not parsed["app_profile"]["captive_portal"]:
        cp_match = _WIN_CP_RE.search(content)
        if cp_match:
            json_blob = cp_match.group(1)
            field_map = [
                ("enableCaptivePortalDetection", "Detection enabled"),
                ("enableEmbeddedCaptivePortal", "Embedded captive portal"),
                ("automaticCapture", "Automatic capture"),
                ("automaticCaptureDuration", "Auto-capture duration (s)"),
                ("captivePortalWebSecDisableMinutes",
                 "WebSec disable on captive (min)"),
                ("enableFailOpen", "Fail-open on captive portal"),
                ("captiveDetectionUrl", "Detection URL"),
            ]
            for cp_key, cp_label in field_map:
                v = _extract_field_value(json_blob, cp_key)
                if v is None:
                    continue
                if v in ("0", "false", "False"):
                    v = "off"
                elif v in ("1", "true", "True"):
                    v = "on"
                parsed["app_profile"]["captive_portal"].setdefault(
                    cp_label, v
                )


_BYPASS_CSV_PATTERN = re.compile(r"Network hostname csv:\s*(.+?)\s*$")
_RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_RE_IPV4_CIDR = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_RE_HOSTNAME = re.compile(r"^[A-Za-z][A-Za-z0-9._\-]*\.[A-Za-z][A-Za-z0-9.\-]*$")


def extract_configured_bypass_csv_from_index(log_index) -> Dict[str, Any]:
    """Parse the ``Network hostname csv:`` line — the literal customer-
    configured VPN bypass list — and return a structured breakdown.

    This is the **configured-policy** view of the bypass list. It is
    separate from ``extract_bypass_resolutions_from_index`` (which only
    captures hostnames the device actually had to DNS-resolve during
    the capture window). The CSV always carries strictly more entries
    than the resolved set — every host the customer put into ZIA
    Forwarding Profile shows up here, even ones the device never
    touched during the bundle window.

    Multiple ``Network hostname csv:`` lines may appear over the bundle
    lifetime (the list mutates as the App Profile is reloaded). We
    take the **longest** line as the canonical snapshot — it is the
    most-complete observed list.

    Returns a dict with shape::

        {
            "hostnames": ["app1.example.com", ...],  # sorted, unique
            "ipv4":      ["1.2.3.4", ...],           # sorted, unique
            "cidrs":     ["10.0.0.0/8", ...],        # sorted, unique
            "unparseable": [...],                    # anything that didn't match
            "raw_count": <int>,                       # entries in CSV
            "source_file": "<filename>",
            "csv_lines_seen": <int>,                  # how many lines we found
        }

    Empty dict when no ``Network hostname csv:`` line is found.

    Re-derived per-bundle (no carry-forward between bundles).
    """
    if not log_index:
        return {}
    # Collect every "Network hostname csv" line, keep the longest.
    longest_payload = ""
    longest_source = ""
    lines_seen = 0
    for ln in log_index.lines:
        if "Network hostname csv" not in ln.body:
            continue
        m = _BYPASS_CSV_PATTERN.search(ln.body)
        if not m:
            continue
        lines_seen += 1
        payload = m.group(1).strip()
        if len(payload) > len(longest_payload):
            longest_payload = payload
            longest_source = ln.source_file or ""
    if not longest_payload:
        return {}

    # Split on commas, strip whitespace, drop empty cells.
    entries = [e.strip() for e in longest_payload.split(",") if e.strip()]
    hostnames: List[str] = []
    ipv4: List[str] = []
    cidrs: List[str] = []
    unparseable: List[str] = []
    for e in entries:
        if _RE_IPV4_CIDR.match(e):
            cidrs.append(e)
        elif _RE_IPV4.match(e):
            ipv4.append(e)
        elif _RE_HOSTNAME.match(e):
            hostnames.append(e)
        else:
            unparseable.append(e)

    # Sort IPs numerically by octets so the UI table is readable;
    # hostnames alphabetically.
    def _ip_key(s: str):
        base = s.split("/")[0]
        try:
            return tuple(int(o) for o in base.split("."))
        except ValueError:
            return (0, 0, 0, 0)

    return {
        "hostnames": sorted(set(hostnames), key=lambda h: h.lower()),
        "ipv4": sorted(set(ipv4), key=_ip_key),
        "cidrs": sorted(set(cidrs), key=_ip_key),
        "unparseable": sorted(set(unparseable)),
        "raw_count": len(entries),
        "source_file": longest_source,
        "csv_lines_seen": lines_seen,
    }


def extract_bypass_resolutions_from_index(log_index) -> Dict[str, List[str]]:
    """Fast path: extract ``Resolved exclude hostname:`` records from a
    pre-built ``log_index`` instead of re-reading every tunnel log.
    Behaviour identical to ``extract_bypass_resolutions`` but the I/O
    has already happened during bundle load."""
    out: Dict[str, List[str]] = {}
    pat = re.compile(
        r"Resolved exclude hostname:\s*"
        r"(?P<host>[A-Za-z0-9.\-_]+)\s*-->\s*"
        r"(?P<ip>[0-9a-fA-F:.]+)"
    )
    if not log_index:
        return out
    for ln in log_index.lines:
        if ln.component != "tunnel":
            continue
        if "Resolved exclude hostname" not in ln.body:
            continue
        m = pat.search(ln.body)
        if not m:
            continue
        host = m.group("host")
        ip = m.group("ip")
        if host not in out:
            if len(out) >= _BYPASS_MAX_HOSTS:
                break
            out[host] = []
        if ip not in out[host]:
            out[host].append(ip)
    return out


def extract_bypass_resolutions(bundle) -> Dict[str, List[str]]:
    """Walk tunnel logs for ``Resolved exclude hostname:`` records and
    return ``Dict[host, List[ip]]``. The IPs are de-duplicated and
    in insertion order. The walk is capped at ``_BYPASS_MAX_HOSTS``
    distinct hostnames so a massive bundle doesn't explode."""
    out: Dict[str, List[str]] = {}
    pat = re.compile(
        r"Resolved exclude hostname:\s*"
        r"(?P<host>[A-Za-z0-9.\-_]+)\s*-->\s*"
        r"(?P<ip>[0-9a-fA-F:.]+)"
    )
    for path in _find_tunnel_logs(bundle):
        if len(out) >= _BYPASS_MAX_HOSTS:
            break
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                for i, line in enumerate(fp):
                    if i >= _BYPASS_MAX_LINES_PER_FILE:
                        break
                    if "Resolved exclude hostname" not in line:
                        continue
                    m = pat.search(line)
                    if not m:
                        continue
                    host = m.group("host")
                    ip = m.group("ip")
                    if host not in out:
                        if len(out) >= _BYPASS_MAX_HOSTS:
                            break
                        out[host] = []
                    if ip not in out[host]:
                        out[host].append(ip)
        except OSError:
            continue
    return out


def extract_session_info_from_index(
    log_index,
    sme_dc_map: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Fast path: pull session-level identity from the shared in-memory
    log index instead of re-walking tunnel logs. Equivalent behaviour
    to ``extract_session_info``."""
    channels: Dict[str, Dict[str, Any]] = {}
    pat = re.compile(
        r"ZSCCM::(?P<ch>ZT2[AB])::raiseSessionInformationEvent:[^\[]*\["
        r"(?P<body>[^\]]+)\]"
    )
    field_pat = re.compile(r"(\w+):\s*([^\s]+)")
    src_file = ""
    if log_index:
        for ln in log_index.lines:
            if ln.component != "tunnel":
                continue
            if "raiseSessionInformationEvent" not in ln.body:
                continue
            m = pat.search(ln.body)
            if not m:
                continue
            body = m.group("body")
            ch = m.group("ch")
            fields = dict(field_pat.findall(body))
            if fields:
                channels[ch] = fields
                src_file = ln.source_file
    if not channels:
        return {}
    # Reuse the slow-path's field-mapping logic by constructing a small
    # adapter and delegating. The mapping code is short enough to
    # duplicate -- avoids tangling the slow path with adapter helpers.
    return _build_session_info_output(channels, src_file, sme_dc_map)


def _build_session_info_output(
    channels: Dict[str, Dict[str, Any]],
    src_file: str,
    sme_dc_map: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    """Shared mapping: raw {ZT2A/ZT2B → fields} into the labelled output
    dict that the UI expects. Refactored out of ``extract_session_info``
    so both the slow path and the fast (index-backed) path share the
    exact same output schema."""
    out: Dict[str, Any] = {}
    primary = channels.get("ZT2A") or channels.get("ZT2B") or {}
    out["channel"] = "ZT2A" if "ZT2A" in channels else "ZT2B"
    client_addr = primary.get("ClientAddress", "")
    if client_addr and ":" in client_addr:
        ip, _, port = client_addr.rpartition(":")
        out["Public IP (egress)"] = ip
        out["Public source port"] = port
    elif client_addr:
        out["Public IP (egress)"] = client_addr
    try:
        from .zdx_parser import label_sme_ip
    except Exception:
        def label_sme_ip(ip, m): return ip
    sme_keys = {"SMEAddress", "ServiceIP"}
    name_map = (
        ("TunIP", "Tunnel IP (synthetic)"),
        ("SMEAddress", "SME (Service Edge) IP"),
        ("ServiceIP", "Zscaler Service IP"),
        ("DNSIP", "Zscaler DNS resolver"),
        ("ProbeIP", "Connectivity probe IP"),
        ("TunMTU", "Tunnel MTU"),
        ("DataChannelCount", "Data channel count"),
        ("svpn_tun_port", "Tunnel port"),
        ("SessionID", "Session ID"),
    )
    for raw_key, label in name_map:
        if raw_key in primary:
            val = primary[raw_key]
            if raw_key in sme_keys:
                val = label_sme_ip(val, sme_dc_map)
            out[label] = val
    if len(channels) == 2:
        sec = channels.get("ZT2B") if out.get("channel") == "ZT2A" \
            else channels.get("ZT2A")
        if sec:
            sec_sme = sec.get("SMEAddress", "")
            if sec_sme:
                out["Secondary SME (other channel)"] = label_sme_ip(
                    sec_sme, sme_dc_map,
                )
        a_addr = channels.get("ZT2A", {}).get("ClientAddress", "")
        b_addr = channels.get("ZT2B", {}).get("ClientAddress", "")
        if a_addr and b_addr and a_addr != b_addr:
            out["Public IP (ZT2A)"] = a_addr.rpartition(":")[0]
            out["Public IP (ZT2B)"] = b_addr.rpartition(":")[0]
    out["source"] = src_file
    return out


def extract_session_info(bundle, sme_dc_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Pull session-level network identity from tunnel logs.

    The ``raiseSessionInformationEvent`` line ZSATunnel emits after
    device-auth-ack carries the customer's **public egress IP** (the
    source address as Zscaler sees it), the synthetic tunnel IP,
    SME / Service IPs, DNS / Probe IPs, the negotiated tunnel MTU,
    and the data-channel count. Returns the most-recent observed
    set of values, plus the source log filename.

    Example line:
        ``ZSCCM::ZT2B::raiseSessionInformationEvent: Sending: [ SessionID: ...
        TunMTU: 1400 SMEAddress: 165.225.38.78 DataChannelCount: 2
        TunIP: 165.225.220.23 ... DNSIP: 185.46.212.88 ProbeIP: 185.46.212.82
        ServiceIP: 165.225.221.212 ClientAddress: 198.51.100.98:50565 ... ]``
    """
    out: Dict[str, Any] = {}
    # We want the most-recent record per channel (ZT2A and ZT2B). Track
    # by channel; latest write wins.
    channels: Dict[str, Dict[str, Any]] = {}
    pat = re.compile(
        r"ZSCCM::(?P<ch>ZT2[AB])::raiseSessionInformationEvent:[^\[]*\["
        r"(?P<body>[^\]]+)\]"
    )
    field_pat = re.compile(r"(\w+):\s*([^\s]+)")
    src_file = ""
    for path in _find_tunnel_logs(bundle):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                for line in fp:
                    if "raiseSessionInformationEvent" not in line:
                        continue
                    m = pat.search(line)
                    if not m:
                        continue
                    body = m.group("body")
                    ch = m.group("ch")
                    fields = dict(field_pat.findall(body))
                    if fields:
                        channels[ch] = fields
                        src_file = path.name
        except OSError:
            continue
    if not channels:
        return out
    # Slow path delegates to the shared mapper so both paths produce
    # identical UI fields.
    return _build_session_info_output(channels, src_file, sme_dc_map)


def extract_pac_info(summary) -> Dict[str, Any]:
    """Return PAC info from the parsed summary. Empty dict if no PAC
    is configured."""
    pac = getattr(summary, "pac", None) or {}
    out: Dict[str, Any] = {}
    if not pac:
        return out
    # ``type`` is an integer encoding from policy: 0 = none, 1 = URL,
    # 2 = file path. Surface the raw value plus a friendly description.
    type_raw = pac.get("type")
    type_label = {
        0: "None",
        "0": "None",
        1: "PAC URL",
        "1": "PAC URL",
        2: "PAC file path",
        "2": "PAC file path",
    }.get(type_raw, f"Type {type_raw}")
    out["type"] = type_label
    out["type_raw"] = type_raw
    if pac.get("data_path"):
        out["data_path"] = pac["data_path"]
    return out
