"""ID inventory — Slice 3+ (2026-08-07).

Walk the LogIndex once, extract every recognisable identifier /
code / hostname from every line's body, and group into a typed
inventory: type -> value -> IdStat(count, first_ts, last_ts,
files_touched, components_touched).

This is what powers the "browse by tag" experience — instead of
making the engineer type in a specific tag_id or mtunnel_id, the
inventory lists every distinct value that appeared in the bundle
with occurrence counts. Click one and jump to `reconstruct_session`.

Also useful stand-alone: it's the ZPA session catalog, the observed
broker set, the observed app set, the observed error-code
distribution.

Pure library. No streamlit deps. CLI-shared.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple


# --------------------------------------------------------------------------
# Extractors — the regex library. One entry per tag type.
# --------------------------------------------------------------------------

# `tag_id=NNN` — ZPA mtunnel numeric identifier
_RE_TAG_ID = re.compile(r"tag_id[=:\s]+(\d+)", re.IGNORECASE)

# `mtunnel_id=XXX,YYY` — full mtunnel identifier (control,data pair)
_RE_MTUNNEL_FULL = re.compile(
    r"mtunnel_id[=:\s]+([a-zA-Z0-9+/=_-]+),([a-zA-Z0-9+/=_-]+)",
    re.IGNORECASE,
)

# `conn_id=XXX` — ZIA connection identifier
_RE_CONN_ID = re.compile(r"conn_id[=:\s]+([a-zA-Z0-9+/=_-]+)", re.IGNORECASE)

# `session_id=XXX` or `sessionId: XXX` — ZIA session identifier
_RE_SESSION_ID = re.compile(
    r"session[_ ]?id[=:\s]+([a-zA-Z0-9+/=_-]+)", re.IGNORECASE,
)

# `err_code=NNN` — numeric error code
_RE_ERR_CODE = re.compile(r"err[_ ]?code[=:\s]+(\d+)", re.IGNORECASE)

# Symbolic codes like `BRK_MT_SETUP_FAIL_SAML_EXPIRED`,
# `ZPN_ERR_DNS_CHECK_NO_ASSISTANT`. Recognisable by uppercase-underscore
# tokens 12+ chars long starting with a common ZS prefix.
_RE_SYMBOLIC_CODE = re.compile(
    r"\b(?:BRK_MT_[A-Z0-9_]{4,}|BRK_REDIRECT_[A-Z0-9_]+"
    r"|ZPN_[A-Z0-9_]{4,}|ZEVENT_[A-Z0-9_]{4,}|ZS_[A-Z0-9_]{4,})"
    r"\b"
)

# App names — `App Name: FooApp` or `app_name=FooApp`
_RE_APP_NAME = re.compile(
    r"(?:App[_ ]Name|app_name)[:\s=]+([a-zA-Z0-9._\-]+)",
    re.IGNORECASE,
)

# ZPA broker hostnames: `broker7-2.chi2.prod.zpath.net`, etc.
_RE_BROKER_HOST = re.compile(
    r"\b(broker[a-z0-9_-]*\.(?:[a-z0-9_-]+\.)*(?:zpath|zscaler|zpalb|zpaservice)\.net)\b",
    re.IGNORECASE,
)

# ZIA SME hostnames — `sme-chi01.zscalertwo.net`, `dublin-sme.zscalerthree.net`,
# or the bare `sme.zscalerX.net`. Two labels total (host + zscaler cloud).
_RE_SME_HOST = re.compile(
    r"\b(?:sme|(?:[a-z0-9_-]+[-_])?sme[-_][a-z0-9_-]+|[a-z0-9_-]+[-_]sme[0-9]*)"
    r"\.zscaler[a-z0-9]*\.net\b",
    re.IGNORECASE,
)

# NOTE: a generic "internal FQDN" extractor was defined here and never
# wired into `_extract_all`. Removed in Phase 61 rather than activated:
# measured against the corpus it matched essentially every dotted token
# in every line (versions, filenames, class names like
# `ZSAWinProxyUtil:`), which would have swamped the inventory with tens
# of thousands of non-hostnames. Real hostnames of interest are already
# covered by the targeted `broker` / `sme_host` patterns plus
# `log_index._extract_host()`, all of which are anchored on context.

# IPv4 addresses
_RE_IPV4 = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
                      r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3})\b")

# HTTP proxy tokens: `HTTP/1.1 407`, `HTTP 407` (auth challenges)
_RE_HTTP_STATUS = re.compile(r"HTTP(?:/\d\.\d)?\s+([1-5]\d{2})\b")


# --------------------------------------------------------------------------
# Environment / identity extractors — cloud, DC, username, device hostname,
# org id, ZCC version.
#
# Why these exist (2026-08-14 addition): the earlier tag set (tag_id,
# mtunnel_id, broker, sme_host, ...) is all *session-plumbing* — it says
# nothing about WHICH cloud, WHICH data center, or WHO. Those facts are
# genuinely in the logs (Shameel confirmed it), just not pulled out
# because `facts_extract.py` only plucks a single "best" App Profile
# blob from tray logs. That's a single point of failure: if the blob
# never got exported (Partner-Tenant bundles, redacted exports, a
# bundle captured before the first policy push), the fields silently
# read "-" even though the SAME data appears dozens of times elsewhere
# — in tunnel session-info lines, SME/broker hostnames, login_hint URLs,
# Partner-Login prose.
#
# These extractors run per LINE (same single pass as every other tag
# type), so every occurrence across every log file is captured with
# full provenance (count / first / last / files / components) instead
# of one plucked value with no way to see where it came from.
# --------------------------------------------------------------------------

# ---- Cloud, split by service ----------------------------------------
#
# ZIA and ZPA live on SEPARATE clouds and a tenant is routinely on
# different ones (ZIA on zscalertwo.net while ZPA is on zpath.net), so
# collapsing them into a single "cloud" field is actively misleading —
# it shows one value and hides the other. They're extracted into two
# independent tag types.
#
# The split is unambiguous by domain, with no overlap between the two
# pattern sets:
#   ZIA clouds end in  zscaler*.net / zscaler.us / zscloud.net
#   ZPA clouds end in  zpath.net / zpabeta.net / zpagov.net
#                      / private.zscaler.com   (note: .com, not .net)

_RE_ZIA_CLOUD = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"(zscalerthree|zscalertwo|zscalerbeta|zscalergov|zscalerten|zscloud|zscaler)"
    r"\.(net|us)\b",
    re.IGNORECASE,
)
# Explicitly labeled ZIA cloud field from the TrayPolicy blob — highest
# confidence, and present even in bundles with no live ZIA traffic.
_RE_ZIA_CLOUD_LABELED = re.compile(
    r'(?:ziaCloudName(?:WithTld)?|zia_cloud_name|cloudName|cloud_name)'
    r'"?\s*[:=]\s*"?([a-z0-9][a-z0-9.\-]{2,40})"?',
    re.IGNORECASE,
)

_RE_ZPA_CLOUD = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"(zpath\.net|zpabeta\.net|zpagov\.net|private\.zscaler\.com)\b",
    re.IGNORECASE,
)
_RE_ZPA_CLOUD_LABELED = re.compile(
    r'(?:zpaCloud|zpn_cloud|zpnCloud|Broker\s*Cloud)'
    r'"?\s*[:=]\s*"?([a-z0-9][a-z0-9.\-]{2,40})"?',
    re.IGNORECASE,
)

# ZPA gateway-shaped SME hostname: zs1-tlv2-gw1-sme.gateway.emea.net
# -> dc="tlv2". Same anchor zdx_parser.py's _SME_HOSTNAME_PAT uses for
# the ZTraceroute sme_dc_map, kept in sync here so Session/Facts and
# the ZDX network-health view agree on DC naming.
_RE_DC_GATEWAY = re.compile(
    r"zs\d+-(?P<dc>[a-z0-9]+)-[a-z0-9]+-sme\.gateway\.[a-z]+\.net",
    re.IGNORECASE,
)
# Airport-code-shaped LABEL (whole dot/hyphen-separated segment is
# exactly 3 letters + 1-2 digits) — catches the "chi2" in
# broker7-2.chi2.prod.zpath.net, the "chi01" in sme-chi01.zscalertwo.net.
# Matched against WHOLE labels (see _derive_dc_tokens), not as a
# substring search, so "broker7" doesn't false-match on its trailing
# "ker7". Applied only to hostnames THIS line already matched as a
# broker/sme_host (see _extract_all), so it's always grounded in a
# directly-observed hostname, never a bare guess.
_RE_DC_TOKEN = re.compile(r"^[a-z]{3}\d{1,2}$", re.IGNORECASE)
_RE_HOST_LABEL_SPLIT = re.compile(r"[.\-]")


def _derive_dc_tokens(host: str) -> List[str]:
    """Split a hostname into dot/hyphen-separated labels and return the
    ones that look like a DC airport code (exactly 3 letters + 1-2
    digits), uppercased. Whole-label match only — a substring search
    would false-match "broker7" (trailing "ker7") as a DC code."""
    out = []
    for label in _RE_HOST_LABEL_SPLIT.split(host):
        if _RE_DC_TOKEN.match(label):
            out.append(label.upper())
    return out

# Username / login identity. Labeled fields first (highest confidence —
# same keys policy_extract.py's TrayPolicy parser looks for, but here
# matched against EVERY line, not just a TrayPolicy blob). Then
# Partner-Login prose, then the login_hint URL param (needs %40 decode),
# then a generic email fallback with a small noise-domain blocklist so
# Zscaler's own system/support addresses don't drown out the real user.
_RE_USERNAME_LABELED = re.compile(
    r'(?:loginName|login_name|Login\s*name|UPN|userName|user_name)'
    r'"?\s*[:=]\s*"?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"?',
    re.IGNORECASE,
)
_RE_USERNAME_FOR_USER = re.compile(
    r"for user\s*=\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)
_RE_USERNAME_LOGIN_HINT = re.compile(r"login_hint=([^&\s\"']+)", re.IGNORECASE)
_RE_EMAIL_GENERIC = re.compile(
    r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)
_USERNAME_DOMAIN_NOISE: Set[str] = {
    "zscaler.com", "zscaler.net", "example.com", "test.com",
}

# Device hostname — label-anchored only. A bare "Host:" is already
# covered by log_index.py's `_extract_host()` (proxied-request URL
# host), which would massively over-match if reused here; this pattern
# only fires on the machine-identity keys ZCC actually uses.
_RE_DEVICE_HOSTNAME = re.compile(
    r'(?:hostName|computerName|host_name|Host\s*[Nn]ame)'
    r'"?\s*[:=]\s*"?([A-Za-z0-9._\-]{2,64})"?',
)

# Status words ZCC writes where a hostname is expected while a lookup is
# still in flight. Without this filter a line like
# `Host Name: Searching` lands "Searching" in the device_hostname
# bucket and — because it repeats on every poll — it outranks the real
# machine name and becomes the headline value in the Facts view.
_HOSTNAME_STATUS_NOISE: Set[str] = {
    "searching", "unknown", "pending", "none", "null", "n/a", "na",
    "localhost", "disabled", "enabled", "true", "false", "empty",
    "failed", "success", "connecting", "connected", "disconnected",
    "resolving", "waiting", "retrying", "initializing", "unavailable",
    "notfound", "not_found", "error", "default", "undefined", "nil",
}


def _looks_like_device_hostname(val: str) -> bool:
    """True if `val` looks like an actual machine name rather than a
    status word.

    Two gates, both cheap and evidence-based:
      1. Not in the known status-word blocklist.
      2. Structurally machine-shaped — real hostnames carry a separator
         (`-`, `_`, `.`) or a digit (`WKS01`, `DEWEY-LAPTOP`,
         `mac.local`), or are written all-caps as NetBIOS names. A bare
         mixed-case English word like "Searching" satisfies none of
         these and is rejected.
    """
    if not val:
        return False
    low = val.lower()
    if low in _HOSTNAME_STATUS_NOISE:
        return False
    if any(c in val for c in "-_."):
        return True
    if any(c.isdigit() for c in val):
        return True
    if val.isupper() and len(val) >= 3:
        return True
    return False

# Org / tenant id — numeric, label-anchored (same keys as
# policy_extract._POLICY_FIELDS, applied bundle-wide).
_RE_ORG_ID = re.compile(
    r'(?:companyOrgId|company_id|companyId|Org\s*ID)"?\s*[:=]\s*"?(\d+)"?',
    re.IGNORECASE,
)

# ZCC client version — label-anchored, dotted version number.
_RE_ZCC_VERSION = re.compile(
    r'(?:ZCCVersion|clientVersion|appVersion|zccVersion|Agent\s*Version)'
    r'"?\s*[:=]\s*"?(\d+(?:\.\d+){1,4})"?',
    re.IGNORECASE,
)


# --------------------------------------------------------------------------
# Filter noise — some patterns pull too much junk. Blocklists per type.
# --------------------------------------------------------------------------

# App names we always ignore — parser artefacts / noise words that
# accidentally match _RE_APP_NAME.
_APP_NAME_NOISE: Set[str] = {
    "unknown", "null", "none", "", "true", "false",
}

# IPs we always ignore.
_IPV4_NOISE: Set[str] = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
}


# --------------------------------------------------------------------------
# Datamodel
# --------------------------------------------------------------------------

@dataclass
class IdStat:
    """Per-value stats: how many times we saw it, first/last, where."""
    value: str
    count: int
    first_ts: Optional[datetime]
    last_ts: Optional[datetime]
    files: Set[str] = field(default_factory=set)
    components: Set[str] = field(default_factory=set)


@dataclass
class IdInventory:
    """The whole inventory. `groups` is tag_type -> value -> IdStat."""
    groups: Dict[str, Dict[str, IdStat]] = field(default_factory=dict)

    def tag_types(self) -> List[str]:
        return sorted(self.groups)

    def values_for(self, tag_type: str,
                   sort: str = "count") -> List[IdStat]:
        """Return every IdStat for a tag type.
        `sort` in {"count", "value", "first_ts", "last_ts"}."""
        stats = list(self.groups.get(tag_type, {}).values())
        if sort == "count":
            stats.sort(key=lambda s: (-s.count, s.value))
        elif sort == "value":
            stats.sort(key=lambda s: s.value)
        elif sort == "first_ts":
            stats.sort(key=lambda s: (s.first_ts or datetime.max, s.value))
        elif sort == "last_ts":
            stats.sort(key=lambda s: (s.last_ts or datetime.min, s.value), reverse=True)
        else:
            raise ValueError(f"unknown sort {sort!r}")
        return stats

    def total_ids(self) -> int:
        return sum(len(g) for g in self.groups.values())

    def total_by_type(self) -> Dict[str, int]:
        return {t: len(g) for t, g in self.groups.items()}


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def _extract_all(body: str) -> Dict[str, List[str]]:
    """Return every recognisable identifier in `body`, grouped by tag
    type. Duplicates within the same line are preserved (caller dedupes
    per line when accumulating IdStat.count)."""
    out: Dict[str, List[str]] = defaultdict(list)

    for m in _RE_TAG_ID.finditer(body):
        val = m.group(1)
        # `tag_id=0` is ZCC's not-yet-assigned placeholder, not a real
        # mtunnel. It was being harvested like any other ID, so it
        # appeared in the Session tab's browse list — usually near the
        # top, since it repeats — and reconstructing it returns zero
        # lines. A visible dead end that looks like a tool bug.
        if val.strip("0"):
            out["tag_id"].append(val)

    for m in _RE_MTUNNEL_FULL.finditer(body):
        control, data = m.group(1), m.group(2)
        out["mtunnel_id"].append(f"{control},{data}")
        out["broker_session"].append(control)
        out["data_channel"].append(data)

    for m in _RE_CONN_ID.finditer(body):
        out["conn_id"].append(m.group(1))

    for m in _RE_SESSION_ID.finditer(body):
        out["session_id"].append(m.group(1))

    for m in _RE_ERR_CODE.finditer(body):
        out["err_code"].append(m.group(1))

    for m in _RE_SYMBOLIC_CODE.finditer(body):
        out["symbolic_code"].append(m.group(0))

    for m in _RE_APP_NAME.finditer(body):
        val = m.group(1)
        if val.lower() not in _APP_NAME_NOISE:
            out["app"].append(val)

    for m in _RE_BROKER_HOST.finditer(body):
        out["broker"].append(m.group(1).lower())

    for m in _RE_SME_HOST.finditer(body):
        out["sme_host"].append(m.group(0).lower())

    for m in _RE_IPV4.finditer(body):
        val = m.group(1)
        if val not in _IPV4_NOISE:
            out["ipv4"].append(val)

    for m in _RE_HTTP_STATUS.finditer(body):
        out["http_status"].append(m.group(1))

    # ---- Cloud (split ZIA / ZPA — a tenant is routinely on both) ----
    for m in _RE_ZIA_CLOUD.finditer(body):
        out["zia_cloud"].append(f"{m.group(1).lower()}.{m.group(2).lower()}")
    for m in _RE_ZIA_CLOUD_LABELED.finditer(body):
        val = m.group(1).lower().strip(".")
        if val and val not in _APP_NAME_NOISE:
            # The labeled field is sometimes bare ("zscalertwo") and
            # sometimes fully qualified ("zscalertwo.net"). Normalise to
            # the qualified form so both spellings collapse to one value
            # instead of showing up as two distinct clouds.
            out["zia_cloud"].append(val if "." in val else f"{val}.net")

    for m in _RE_ZPA_CLOUD.finditer(body):
        out["zpa_cloud"].append(m.group(1).lower())
    for m in _RE_ZPA_CLOUD_LABELED.finditer(body):
        val = m.group(1).lower().strip(".")
        if val and val not in _APP_NAME_NOISE:
            out["zpa_cloud"].append(val)

    # ---- Data center ----
    for m in _RE_DC_GATEWAY.finditer(body):
        out["dc"].append(m.group("dc").upper())
    # Derive DC tokens from any broker/sme host THIS line already
    # matched — grounded in a directly-observed hostname, not a guess.
    for host_val in out.get("broker", []) + out.get("sme_host", []):
        out["dc"].extend(_derive_dc_tokens(host_val))

    # ---- Username ----
    for m in _RE_USERNAME_LABELED.finditer(body):
        out["username"].append(m.group(1))
    for m in _RE_USERNAME_FOR_USER.finditer(body):
        out["username"].append(m.group(1))
    for m in _RE_USERNAME_LOGIN_HINT.finditer(body):
        raw = m.group(1).replace("%40", "@").replace("+", " ")
        if "@" in raw:
            out["username"].append(raw)
    if not out.get("username"):
        for m in _RE_EMAIL_GENERIC.finditer(body):
            addr = m.group(1)
            domain = addr.split("@", 1)[-1].lower()
            if domain in _USERNAME_DOMAIN_NOISE:
                continue
            out["username"].append(addr)

    # ---- Device hostname ----
    for m in _RE_DEVICE_HOSTNAME.finditer(body):
        val = m.group(1)
        if _looks_like_device_hostname(val):
            out["device_hostname"].append(val)

    # ---- Org / tenant ID ----
    for m in _RE_ORG_ID.finditer(body):
        out["org_id"].append(m.group(1))

    # ---- ZCC client version ----
    for m in _RE_ZCC_VERSION.finditer(body):
        out["zcc_version"].append(m.group(1))

    return dict(out)


def build_inventory(idx) -> IdInventory:
    """Single pass over `idx.lines`. Populates an IdInventory."""
    groups: Dict[str, Dict[str, IdStat]] = defaultdict(dict)

    for line in idx.lines:
        body = line.body or ""
        ts = line.ts
        src = line.source_file or ""
        comp = line.component or ""

        by_type = _extract_all(body)
        for tag_type, values in by_type.items():
            # De-dupe within-line: counting the SAME value twice on one
            # line inflates the visible count without adding information.
            for val in set(values):
                bucket = groups[tag_type]
                stat = bucket.get(val)
                if stat is None:
                    stat = IdStat(
                        value=val, count=0,
                        first_ts=ts, last_ts=ts,
                    )
                    bucket[val] = stat
                stat.count += 1
                if ts is not None:
                    if stat.first_ts is None or ts < stat.first_ts:
                        stat.first_ts = ts
                    if stat.last_ts is None or ts > stat.last_ts:
                        stat.last_ts = ts
                if src:
                    stat.files.add(src)
                if comp:
                    stat.components.add(comp)

    return IdInventory(groups=dict(groups))


# --------------------------------------------------------------------------
# Module (component) grouping — answers "what did each log module tell
# me?" instead of "what values exist for this tag type, from anywhere?"
# --------------------------------------------------------------------------

def group_by_component(inv: IdInventory) -> Dict[str, Dict[str, List[IdStat]]]:
    """Pivot the inventory: component -> tag_type -> [IdStat, ...],
    each list sorted by count descending.

    Free — `IdStat.components` is already tracked per-value during the
    single `build_inventory()` pass, so this is a pure re-grouping with
    no second pass over the log.

    Why this matters: cloud name / username / org id / device hostname
    show up almost exclusively in **tray** logs (policy pushes, login
    prose); DC / broker / mtunnel IDs show up almost exclusively in
    **tunnel** logs. Browsing tag-type-first mixes both; browsing
    module-first lets an engineer ask "what did the tray log actually
    tell me" directly.
    """
    out: Dict[str, Dict[str, List[IdStat]]] = defaultdict(lambda: defaultdict(list))
    for tag_type, bucket in inv.groups.items():
        for stat in bucket.values():
            comps = stat.components or {"(unknown)"}
            for comp in comps:
                out[comp][tag_type].append(stat)

    result: Dict[str, Dict[str, List[IdStat]]] = {}
    for comp, by_type in out.items():
        result[comp] = {
            t: sorted(v, key=lambda s: (-s.count, s.value))
            for t, v in by_type.items()
        }
    return result
