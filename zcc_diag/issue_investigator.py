"""
Issue Investigator — prompt-driven re-investigation.

Phase 39 (2026-06-19). Lets the engineer paste a customer-ticket
description into BundleScope and get back a structured Markdown
report focused on that specific issue — re-walking the logs filtered
by the parsed time window, suite, symptoms, and affected hosts/apps.

Pipeline:

  1. parse_prompt(text, bundle_window) -> Investigation
     Extracts time window (relative phrases like "yesterday around
     2pm" anchored against the bundle's actual capture window),
     suite hints (ZIA/ZPA/ZDX), symptom keywords (auth, connect,
     dns, crash, etc.), and host/IP/app tokens.

  2. investigate(bundle, findings, sessions, log_index, inv)
                -> InvestigationReport
     Filters every input by the Investigation context:
       - findings whose time_range overlaps the window
       - ZPA sessions whose lifetime overlaps the window and whose
         app_name or dest_ip matches an extracted host
       - log lines in the window matching any extracted keyword
     Then groups related lines into correlated clusters keyed on
     tag_id / conn_id / session_id and surfaces the highest-signal
     events (broker errors, DNS failures, auth re-prompts, …).

  3. render_report(report) -> str
     Returns a Markdown string ready to paste into a ticket / Slack
     reply / customer email. Every claim cites a specific log line
     by timestamp + file + line number so the engineer can verify.

The parser is deterministic — no LLM dependency, pure stdlib.
That keeps the toolkit self-contained and the report reproducible
across runs of the same bundle + prompt.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# --------------------------------------------------------------------
# Symptom vocabulary
# --------------------------------------------------------------------
#
# Each entry maps a symptom category to a list of substrings the user
# might type. Match is case-insensitive substring against the raw
# prompt. Categories are then used downstream to:
#   - bias which detectors / findings are emphasized in the report
#   - bias which log-line patterns get pulled into the correlation
#     groups
#
# Vocabulary is intentionally lossy: "auth fail" matches "auth" → the
# auth category is selected, and the finer-grained "fail" word is
# noted in keywords but doesn't get its own category. The point is
# routing, not exhaustive classification.

_SYMPTOMS: Dict[str, Tuple[str, ...]] = {
    "auth": (
        "auth", "authenticat", "saml", "log in", "login", "logon",
        "logout", "log out", "credential", "password", "mfa",
        "two factor", "2fa", "oauth", "token expired", "idp",
        "single sign", "sso", "session expired",
    ),
    "connect": (
        "connect", "disconnect", "drop", "reset", "tunnel down",
        "tunnel up", "can't reach", "cannot reach", "unable to reach",
        "no connection", "timed out", "timeout", "broken", "interrupt",
    ),
    "slow": (
        "slow", "lag", "latenc", "perform", "delay", "sluggish",
        "freeze", "hang", "stuck",
    ),
    "block": (
        "block", "denied", "deny", "rejected", "forbidden", "403",
        "blocked by", "policy block", "policy denied",
    ),
    "dns": (
        "dns", "resolv", "lookup", "host not", "nxdomain", "name "
        "resolution", "name server",
    ),
    "crash": (
        "crash", "crashing", "restart", "respawn", "spinning",
        "tray gone", "tray crash", "tray respawn", "memory dump",
    ),
    "pac": (
        "pac", "wpad", "proxy auto", "autoconfig", "proxy config",
    ),
    "captive": (
        "captive", "captive portal", "hotel wifi", "guest wifi",
        "sign in to network",
    ),
    "av": (
        "antivirus", "av ", "av/", "edr", "endpoint protection",
        "defender", "crowdstrike", "sentinelone",
    ),
}

# Suite-hint vocabulary — matches the user's explicit mention of the
# product family. Used to scope the report to the relevant suite.
_SUITES: Dict[str, Tuple[str, ...]] = {
    "zia": (
        "zia", "internet traffic", "internet access", "web traffic",
        "private internet", "ssl inspection",
    ),
    "zpa": (
        "zpa", "private access", "internal app", "internal apps",
        "broker", "microtunnel", "mtunnel", "app segment",
    ),
    "zdx": (
        "zdx", "digital experience", "user experience",
    ),
}


# --------------------------------------------------------------------
# Time parsing
# --------------------------------------------------------------------
#
# The bundle's local timezone is captured in its log timestamps (e.g.
# "(-0600)" = Mountain). We anchor relative phrases against the bundle
# window so the engineer doesn't have to think about UTC offsets:
#
#   "around 2pm" + bundle covers Jun 12–18 → 2026-06-18 14:00 local
#     (defaults to the most recent day of the bundle window)
#   "yesterday around 2pm" + bundle exported Jun 18 → 2026-06-17 14:00
#   "Jun 17 at 2pm" → 2026-06-17 14:00 (explicit absolute)
#   "between 13:00 and 15:00" → window of that name on the most-
#     recent day
#   "in the morning" → 06:00-12:00 of most-recent day
#   "in the afternoon" → 12:00-18:00
#   "evening" → 17:00-22:00
#   "overnight" → 22:00 of prior day - 06:00 of current day
#
# All resulting windows are returned as a (start, end) tuple of
# *timezone-aware* datetimes matching the bundle's reference TZ.

_RE_TIME_HHMM = re.compile(
    r"\b([0-2]?\d):([0-5]\d)\b",
)
_RE_TIME_AMPM = re.compile(
    r"\b(\d{1,2})\s*(?::([0-5]\d))?\s*(a\.?m\.?|p\.?m\.?|am|pm)\b",
    re.IGNORECASE,
)
_RE_DATE_ISO = re.compile(
    r"\b(20\d{2})-(\d{2})-(\d{2})\b",
)
_RE_DATE_MONTH_DAY = re.compile(
    r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)"
    r"(?:[a-z]*)\s+(\d{1,2})(?:[a-z]{0,3})\b",
    re.IGNORECASE,
)
_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Window size when the prompt anchors a single point in time (e.g.
# "around 2pm" — no range). 60 min total = ±30 min around the point.
# Tuned for typical user-reported issues: they say "around X" and the
# event is usually within half an hour.
_POINT_WINDOW = timedelta(minutes=30)


# ────────────────────────────── Phase 57b: TZ hint recognition
#
# The prompt may name a timezone next to the clock ("5am MST",
# "07:51 UTC", "8:33am eastern"). We map the abbreviation to a UTC
# offset in hours (int). Positive = east of UTC, negative = west.
# The parser converts the user's clock to the bundle's log-local TZ
# before building the window — otherwise a user in PST who typed
# "5am PST" would query 05:00 in the bundle's local TZ, which is a
# different moment.
_TZ_ABBREVIATIONS = {
    "utc": 0, "gmt": 0, "z": 0,
    "est": -5, "edt": -4, "eastern": -5,
    "cst": -6, "cdt": -5, "central": -6,
    "mst": -7, "mdt": -6, "mountain": -7,
    "pst": -8, "pdt": -7, "pacific": -8,
    "akst": -9, "akdt": -8, "alaska": -9,
    "hst": -10, "hawaii": -10,
    "ist": 5,  # Indian Standard Time abbreviation
    "cet": 1, "cest": 2,
    "bst": 1, "wet": 0, "west": 1,
    "aest": 10, "aedt": 11,
}
_RE_TZ_HINT = re.compile(
    r"\b(" + "|".join(sorted(_TZ_ABBREVIATIONS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


def _parse_tz_hint(text: str) -> Optional[int]:
    """Return the UTC-offset (hours) implied by the FIRST timezone
    abbreviation in text, or None. e.g. "5am MST" → -7.

    Only the first hint is used — the assumption is one prompt = one
    reference TZ (even when the prompt has multiple clocks).
    """
    m = _RE_TZ_HINT.search(text)
    if not m:
        return None
    return _TZ_ABBREVIATIONS.get(m.group(1).lower())


@dataclass
class Investigation:
    """Parsed user prompt — the inputs to the investigator pipeline.

    Every field is OPTIONAL. The investigator handles "no time window
    parsed" by defaulting to the whole bundle, "no suite hint" by
    looking at all suites, etc. The point is graceful degradation
    when the prompt is sparse.
    """
    raw_prompt: str
    parsed_time: Optional[Tuple[datetime, datetime]] = None
    time_description: str = ""  # human-readable form of parsed_time
    hosts: List[str] = field(default_factory=list)
    apps: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    symptoms: List[str] = field(default_factory=list)
    suites: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True if the prompt parsed to nothing actionable."""
        return not any((
            self.parsed_time, self.hosts, self.apps,
            self.ip_addresses, self.symptoms, self.suites,
        ))


def _local_tz_from_window(
    bundle_window: Optional[Tuple[datetime, datetime]],
) -> Optional[timezone]:
    """Return the timezone of the bundle window's start, or None."""
    if not bundle_window:
        return None
    start = bundle_window[0]
    if start.tzinfo is None:
        return None
    return start.tzinfo  # type: ignore[return-value]


def _anchor_day(
    bundle_window: Optional[Tuple[datetime, datetime]],
    offset_days: int = 0,
) -> Optional[datetime]:
    """The most-recent day in the bundle window, optionally shifted
    backward by ``offset_days`` (1 = yesterday relative to bundle
    end). Returns a midnight datetime in the bundle's local TZ."""
    if not bundle_window:
        return None
    end = bundle_window[1]
    anchor = end - timedelta(days=offset_days)
    return anchor.replace(hour=0, minute=0, second=0, microsecond=0)


def _expand_point(
    point: datetime,
    half_window: timedelta = _POINT_WINDOW,
) -> Tuple[datetime, datetime]:
    """Turn a single instant into a (start, end) window."""
    return (point - half_window, point + half_window)


def _parse_clock(text: str) -> Optional[Tuple[int, int]]:
    """Extract (hour, minute) from text. Returns None if no clock
    expression found. Handles 24h ("14:30") and 12h with am/pm
    ("2pm", "2:30 pm", "2:30pm", "2 p.m.").

    Phase 57a (2026-07-02): kept for backward-compat. New callers
    should use :func:`_parse_clocks` which returns every clock in the
    text (needed for multi-timestamp prompts like "7:51am then reauth
    at 8:33am and 8:37am").
    """
    clocks = _parse_clocks(text)
    return clocks[0] if clocks else None


def _parse_clocks(text: str) -> List[Tuple[int, int]]:
    """Extract EVERY clock expression from text (Phase 57a).

    Handles the same formats as :func:`_parse_clock` (24-hour "14:30"
    and 12-hour "2pm" / "2:30 pm" / "2 p.m.") but returns all matches
    in appearance order. Deduplicated to avoid the same clock
    counted twice when it appears in overlapping regex classes.

    Returns an empty list when no clock is found.
    """
    seen: List[Tuple[int, int]] = []
    seen_set: set = set()

    def _add(hh: int, mm: int) -> None:
        if not (0 <= hh < 24 and 0 <= mm < 60):
            return
        key = (hh, mm)
        if key in seen_set:
            return
        seen_set.add(key)
        seen.append(key)

    # AM/PM matches first — more specific.
    for m in _RE_TIME_AMPM.finditer(text):
        hh = int(m.group(1))
        mm = int(m.group(2)) if m.group(2) else 0
        suffix = m.group(3).lower().replace(".", "")
        if suffix == "pm" and hh < 12:
            hh += 12
        elif suffix == "am" and hh == 12:
            hh = 0
        _add(hh, mm)

    # Bare HH:MM (24-hour) — take everything that DIDN'T already
    # match an AM/PM span. Overlapping matches are eliminated by the
    # seen_set dedupe.
    for m in _RE_TIME_HHMM.finditer(text):
        _add(int(m.group(1)), int(m.group(2)))

    return seen


def _parse_date(
    text: str,
    bundle_window: Optional[Tuple[datetime, datetime]],
) -> Optional[datetime]:
    """Extract an explicit date from text. Returns None if none found.
    The returned datetime is at midnight in the bundle's TZ."""
    tz = _local_tz_from_window(bundle_window)
    # Try ISO "YYYY-MM-DD" first.
    m = _RE_DATE_ISO.search(text)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            return datetime(y, mo, d, tzinfo=tz)
        except ValueError:
            return None
    # Try "Jun 17" / "June 17th" / etc.
    m = _RE_DATE_MONTH_DAY.search(text)
    if m:
        mo = _MONTHS[m.group(1)[:3].lower()]
        d = int(m.group(2))
        # Anchor year: use the bundle window's year, or the current
        # year if no bundle window.
        year = bundle_window[1].year if bundle_window else datetime.now().year
        try:
            return datetime(year, mo, d, tzinfo=tz)
        except ValueError:
            return None
    return None


def _parse_part_of_day(text: str) -> Optional[Tuple[int, int]]:
    """Match phrases like 'morning' / 'afternoon' / 'evening' /
    'overnight' / 'midday' / 'noon'. Returns (start_hour, end_hour)
    in 24h, or None."""
    t = text.lower()
    if "midnight" in t:
        return (0, 1)
    if "morning" in t:
        return (6, 12)
    if "midday" in t or "noon" in t:
        return (11, 13)
    if "afternoon" in t:
        return (12, 18)
    if "evening" in t:
        return (17, 22)
    if "night" in t or "overnight" in t:
        return (22, 24)  # window into "tomorrow" handled by caller
    return None


def _parse_time_window(
    text: str,
    bundle_window: Optional[Tuple[datetime, datetime]],
    bundle_local_offset: Optional[str] = None,
) -> Optional[Tuple[Tuple[datetime, datetime], str]]:
    """Extract a time window from prompt text. Returns
    ((start, end), description) or None if no time expression found.

    Priority (highest to lowest):
      1. Explicit date + explicit clock     → ±30 min window
      2. Explicit date alone                → that whole day
      3. "yesterday/today/this morning..." + clock → anchored day + clock
      4. Explicit clock alone               → most-recent bundle day + clock
      5. "yesterday/today" alone            → that whole day
      6. Part-of-day alone                  → that range on most-recent bundle day
    """
    tz = _local_tz_from_window(bundle_window)
    txt_low = text.lower()

    explicit_date = _parse_date(text, bundle_window)
    clocks = _parse_clocks(text)          # Phase 57a — ALL clocks
    clock = clocks[0] if clocks else None  # backward-compat single clock
    part = _parse_part_of_day(text)

    # Phase 58c (2026-07-02): timezone-hint conversion.
    #
    # Post-Phase-58a, log timestamps are UTC. When the user types
    # "5am MDT" they mean their local wall-clock time; we need to
    # convert that TO UTC before matching against the log.
    #
    # User's UTC hour = user's local hour - user_tz_offset_h.
    # (For MDT the user offset is -6, so 5am MDT = 11 UTC.)
    #
    # If the user didn't specify a TZ but the log has an offset, we
    # assume the user's clock IS in the bundle's local TZ (that's the
    # 99% case for customer tickets) and convert using the bundle
    # offset as the user_tz_offset_h.
    user_tz_offset_h = _parse_tz_hint(text)
    if user_tz_offset_h is None and bundle_local_offset:
        # Default: user's clock is in the bundle's local TZ. Parse
        # "-0600" into -6 hours. Post-58a bundle_window is UTC so
        # tz.utcoffset() is 0 and can't be used here.
        try:
            sign = -1 if bundle_local_offset[0] == "-" else 1
            hh = int(bundle_local_offset[1:3])
            user_tz_offset_h = sign * hh
        except (ValueError, IndexError):
            user_tz_offset_h = None
    if user_tz_offset_h is not None and clocks:
        # Convert user_local → UTC. Adding -offset (since offset is
        # negative for west-of-Greenwich zones).
        delta_h = -user_tz_offset_h
        if delta_h != 0:
            shifted: List[Tuple[int, int]] = []
            for hh, mm in clocks:
                nh = (hh + delta_h) % 24
                shifted.append((nh, mm))
            clocks = shifted
            clock = clocks[0]

    # Detect relative-day phrases.
    rel_offset = None
    if "yesterday" in txt_low:
        rel_offset = 1
    elif "today" in txt_low:
        rel_offset = 0
    elif "day before yesterday" in txt_low:
        rel_offset = 2

    # Case 1: explicit date + clock → ±30 min point window
    if explicit_date and clock:
        hh, mm = clock
        point = explicit_date.replace(hour=hh, minute=mm)
        win = _expand_point(point)
        return win, f"{point.strftime('%Y-%m-%d %H:%M')} ±30 min"

    # Case 2: explicit date alone → that whole day
    if explicit_date and not clock and not part:
        start = explicit_date
        end = start + timedelta(days=1)
        return (start, end), f"{start.strftime('%Y-%m-%d')} (whole day)"

    # Case 3: relative day + clock
    if rel_offset is not None and clock:
        day = _anchor_day(bundle_window, offset_days=rel_offset)
        if day is None:
            return None
        hh, mm = clock
        point = day.replace(hour=hh, minute=mm)
        win = _expand_point(point)
        label = "today" if rel_offset == 0 else (
            "yesterday" if rel_offset == 1 else f"{rel_offset} days ago"
        )
        return win, f"{label} around {hh:02d}:{mm:02d} (±30 min)"

    # Case 4: clock(s) alone → most-recent bundle day + clock(s).
    # Phase 57a (2026-07-02): when the prompt contains MULTIPLE clocks
    # (e.g., "7:51am first prompt, then reauth at 8:33am and 8:37am"),
    # build a UNION window from the earliest to latest clock plus a
    # ±30-min slack. Previously only the first clock was used, which
    # collapsed multi-timestamp prompts to a tiny window around the
    # first one — that's how an early investigation returned zero
    # results despite four clocks in the prompt.
    if clocks and bundle_window:
        day = _anchor_day(bundle_window, offset_days=0)
        if day is not None:
            if len(clocks) == 1:
                hh, mm = clocks[0]
                point = day.replace(hour=hh, minute=mm)
                win = _expand_point(point)
                return win, (
                    f"{point.strftime('%Y-%m-%d')} around "
                    f"{hh:02d}:{mm:02d} (±30 min, inferred from "
                    "bundle window)"
                )
            # Multiple clocks — build union window.
            points = sorted(
                day.replace(hour=hh, minute=mm) for hh, mm in clocks
            )
            first, last = points[0], points[-1]
            win = (first - _POINT_WINDOW, last + _POINT_WINDOW)
            clock_str = ", ".join(
                p.strftime("%H:%M") for p in points
            )
            return win, (
                f"{day.strftime('%Y-%m-%d')} spanning "
                f"{first.strftime('%H:%M')}–{last.strftime('%H:%M')} "
                f"(±30 min around {len(clocks)} timestamps: "
                f"{clock_str})"
            )

    # Case 5: relative-day alone → that whole day
    if rel_offset is not None:
        day = _anchor_day(bundle_window, offset_days=rel_offset)
        if day is None:
            return None
        end = day + timedelta(days=1)
        label = (
            "today" if rel_offset == 0 else
            "yesterday" if rel_offset == 1 else
            f"{rel_offset} days ago"
        )
        return (day, end), f"{label} ({day.strftime('%Y-%m-%d')}, whole day)"

    # Case 6: part-of-day alone → range on most-recent bundle day
    if part and bundle_window:
        day = _anchor_day(bundle_window, offset_days=0)
        if day is not None:
            sh, eh = part
            start = day.replace(hour=sh)
            end = day.replace(hour=min(eh, 23), minute=59) if eh < 24 \
                else day + timedelta(days=1)
            return (start, end), (
                f"{day.strftime('%Y-%m-%d')} {sh:02d}:00-{eh:02d}:00 "
                "(inferred from bundle window)"
            )

    return None


# --------------------------------------------------------------------
# Host / IP / app extraction
# --------------------------------------------------------------------

# Hostname: tokens with at least one dot + reasonable charset.
# Conservative — avoids matching version strings ("4.6.0.232") because
# the leading-dot heuristic excludes pure-numeric tokens.
_RE_HOSTNAME = re.compile(
    r"\b(?=[a-zA-Z])[a-zA-Z0-9][a-zA-Z0-9\-]*"
    r"(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+\b",
)
# IPv4 address.
_RE_IPV4 = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)


# Common SaaS / enterprise-app keywords that engineers reference by
# bare name (no TLD) in tickets. When found in the prompt, we add the
# keyword as an "app hint" — investigate() then matches it (substring,
# case-insensitive) against actual ZPA session app_names and tunnel-
# log content. The list is conservative — only words distinctive enough
# that a substring match against log content is reliable.
_KNOWN_APP_KEYWORDS = (
    # SaaS
    "salesforce", "office365", "outlook", "exchange", "sharepoint",
    "onedrive", "teams", "slack", "zoom", "webex", "github",
    "gitlab", "bitbucket", "jira", "confluence", "okta",
    "dropbox", "box.com", "servicenow", "workday", "tableau",
    "powerbi", "datadog", "splunk", "newrelic", "pagerduty",
    # Common internal app keywords
    "storefront", "intranet", "fileserver", "fileshare",
    "samba", "rdp", "vdi", "citrix", "sap", "oracle",
    "remotedesktop",
)


def _extract_hosts_and_ips(
    text: str,
) -> Tuple[List[str], List[str], List[str]]:
    """Pull hostnames, IPv4 addresses, and bare-name app keywords
    out of the prompt.

    Hostnames are deduped, lowercased, and stripped of trailing
    punctuation. IPs are validated as four 0-255 octets. App
    keywords are matched case-insensitive against
    ``_KNOWN_APP_KEYWORDS`` — used by investigate() to cross-
    reference against actual ZPA app_names and log content.
    """
    hosts: List[str] = []
    for m in _RE_HOSTNAME.finditer(text):
        h = m.group(0).strip(".,;:!?").lower()
        if h and h not in hosts:
            hosts.append(h)
    ips: List[str] = []
    for m in _RE_IPV4.finditer(text):
        ip = m.group(0)
        try:
            parts = [int(p) for p in ip.split(".")]
            if all(0 <= p <= 255 for p in parts):
                if ip not in ips:
                    ips.append(ip)
        except (ValueError, TypeError):
            continue
    txt_low = text.lower()
    apps: List[str] = []
    for kw in _KNOWN_APP_KEYWORDS:
        if kw in txt_low and kw not in apps:
            apps.append(kw)
    return hosts, ips, apps


# --------------------------------------------------------------------
# Top-level parser
# --------------------------------------------------------------------

def parse_prompt(
    text: str,
    bundle_window: Optional[Tuple[datetime, datetime]] = None,
    bundle_local_offset: Optional[str] = None,
) -> Investigation:
    """Parse a free-text customer-ticket prompt into a structured
    Investigation. Pure-stdlib, deterministic.

    ``bundle_window`` is the (start, end) of the bundle's capture
    window. Used to anchor relative time phrases ("yesterday",
    "around 2pm").

    ``bundle_local_offset`` (Phase 58c, 2026-07-02) is the log's
    embedded local-offset string (e.g. "-0600"). Post-Phase-58a all
    log timestamps are UTC, so the bundle_window's tzinfo is always
    UTC; we need this separate parameter to know the device's local
    TZ so we can convert user-typed local clocks ("5am") into UTC
    before matching against the log.
    """
    inv = Investigation(raw_prompt=text or "")
    if not text:
        return inv

    # ---- Time ----
    tw = _parse_time_window(text, bundle_window, bundle_local_offset)
    if tw:
        inv.parsed_time, inv.time_description = tw

    # ---- Hosts / IPs / bare-name apps ----
    hosts, ips, bare_apps = _extract_hosts_and_ips(text)
    inv.hosts = hosts
    inv.ip_addresses = ips
    # bare-name apps land in inv.apps directly; investigate() will
    # cross-reference each against actual ZPA session app_names.
    for app in bare_apps:
        if app not in inv.apps:
            inv.apps.append(app)

    # ---- Symptoms ----
    txt_low = text.lower()
    for category, phrases in _SYMPTOMS.items():
        for p in phrases:
            if p in txt_low:
                if category not in inv.symptoms:
                    inv.symptoms.append(category)
                if p not in inv.keywords:
                    inv.keywords.append(p)
                break  # one match per category is enough

    # ---- Suites ----
    for suite, phrases in _SUITES.items():
        for p in phrases:
            if p in txt_low:
                if suite not in inv.suites:
                    inv.suites.append(suite)
                break

    # ---- Apps (heuristic) ----
    # If the engineer says "salesforce" or names an app, we want it as
    # an "app" hint distinct from a hostname. Heuristic: any extracted
    # hostname under common SaaS / internal TLDs is also an app
    # candidate. Internal hosts (.local, .corp, .internal) are
    # treated as ZPA-relevant apps too.
    saas_tlds = (".com", ".net", ".io", ".cloud", ".app", ".co",
                 ".org")
    internal_tlds = (".local", ".internal", ".corp", ".intra",
                     ".lan", ".home")
    for h in hosts:
        if any(h.endswith(t) for t in saas_tlds + internal_tlds):
            if h not in inv.apps:
                inv.apps.append(h)

    return inv


# --------------------------------------------------------------------
# Investigation
# --------------------------------------------------------------------

@dataclass
class CorrelatedGroup:
    """A set of related log lines that share a session identifier or
    a strong topical link (broker error code, same app_name, etc).

    Rendered in the report as a coherent narrative block so the
    engineer can follow one sequence of events without reconstructing
    it mentally.
    """
    label: str                       # human-readable group title
    anchor_ts: Optional[datetime] = None
    tag_id: Optional[str] = None
    conn_id: Optional[str] = None
    session_id: Optional[str] = None
    app_name: Optional[str] = None
    lines: List[Any] = field(default_factory=list)   # IndexedLine
    severity: str = "INFO"
    summary: str = ""               # one-line synopsis for the heading


@dataclass
class InvestigationReport:
    """The deliverable. Rendered as Markdown for ticket / chat reply."""
    investigation: Investigation
    window: Optional[Tuple[datetime, datetime]] = None
    window_description: str = ""
    findings_in_window: List[Any] = field(default_factory=list)
    matched_sessions: List[Any] = field(default_factory=list)
    correlated_groups: List[CorrelatedGroup] = field(default_factory=list)
    log_kind_counts: Dict[str, int] = field(default_factory=dict)
    broker_error_counts: Dict[str, int] = field(default_factory=dict)
    reauth_event_count: int = 0
    dns_failures: Dict[str, int] = field(default_factory=dict)
    likely_root_cause: str = ""
    recommended_actions: List[str] = field(default_factory=list)
    # Diagnostic — what we observed (or didn't) in the window so the
    # engineer can see why the report says what it says.
    diagnostics: List[str] = field(default_factory=list)
    # Phase 57d (2026-07-02): RCA reports whose finding time_range
    # overlaps the query window. These are top-tier hits — they
    # represent the whole-pipeline diagnosis (detector + correlator +
    # synthesizer), not just raw log grep.
    rca_reports_in_window: List[Any] = field(default_factory=list)
    # Correlator events (Modern Standby cycles, mtunnel closes, etc.)
    # whose timestamp overlaps the window. Surfaces the same signal
    # the drill-down panel uses in Phase 55c.
    correlator_hits: Dict[str, List[Any]] = field(default_factory=dict)


def _ts_in_window(
    ts: Optional[datetime],
    window: Optional[Tuple[datetime, datetime]],
) -> bool:
    """True if ``ts`` is inside the window, or window is None
    (= no window filter, accept everything)."""
    if window is None:
        return True
    if ts is None:
        return False
    return window[0] <= ts <= window[1]


def _finding_in_window(
    finding: Any,
    window: Optional[Tuple[datetime, datetime]],
) -> bool:
    """True if any part of the finding's time_range overlaps the
    window. A finding with no time_range is included (we can't tell
    when it happened, so we surface it)."""
    if window is None:
        return True
    tr = getattr(finding, "time_range", None)
    if tr is None:
        return True
    start, end = tr
    return not (end < window[0] or start > window[1])


def _session_matches_hosts(
    session: Any,
    hosts: List[str],
    ips: List[str],
    apps: Optional[List[str]] = None,
) -> bool:
    """True if the session's app_name or dest_ip matches any of the
    extracted hosts/IPs/apps. If no hints were extracted, returns
    True (no filter)."""
    apps = apps or []
    if not hosts and not ips and not apps:
        return True
    app_name = (getattr(session, "app_name", "") or "").lower()
    dest = getattr(session, "dest_ip", "") or ""
    for h in hosts:
        if h in app_name:
            return True
    for ip in ips:
        if ip == dest or ip in app_name:
            return True
    # Bare-name apps (e.g. "salesforce") — substring match against
    # the session's app_name. "salesforce" matches
    # "myorg.my.salesforce.com" / "salesforce.com" / "lightning-
    # salesforce.foo.local" etc.
    for a in apps:
        if a in app_name:
            return True
    return False


def _classify_line_topic(body: str) -> Optional[str]:
    """Bucket a log line into a coarse topic for correlation. Returns
    None if the line doesn't fit any known topic (the line will still
    be available via the time-window scan, just not grouped)."""
    b = body
    if "BRK_MT_SETUP_FAIL_SAML_EXPIRED" in b:
        return "broker_saml_expired"
    if "BRK_MT_SETUP_FAIL_NO_POLICY_FOUND" in b:
        return "broker_no_policy"
    if "BRK_MT_SETUP_FAIL" in b:
        return "broker_setup_fail_other"
    if "BRK_MT_CLOSED" in b or "BRK_MT_TERMINATED" in b:
        return "broker_closed"
    if "ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED" in b:
        return "zpa_reauth_prompt"
    if "WinHttpGetProxyForUrl Failed" in b:
        return "wpad_fail"
    if "Error connecting to tcp echo server" in b:
        return "zpa_health_check_fail"
    if "resolveDnsWithFamilyPriority" in b and "Host not found" in b:
        return "dns_host_not_found"
    if "rateLimitTraySpawn" in b:
        return "tray_spawn_ratelimit"
    if "ZSATray" in b and "crash" in b.lower():
        return "tray_crash"
    if "Signer File other error" in b:
        return "zep_signer_fail"
    return None


def investigate(
    bundle_summary: Any,
    findings: List[Any],
    zpa_sessions: List[Any],
    log_index: Any,
    inv: Investigation,
    *,
    max_lines_in_window: int = 200_000,
    max_lines_per_group: int = 20,
    rca_reports: Optional[Dict[str, Any]] = None,
    correlators: Optional[Dict[str, Any]] = None,
) -> InvestigationReport:
    """Run the investigation. Returns a structured report.

    All inputs are read-only — nothing is mutated. The report holds
    references to log lines (IndexedLine objects) so the renderer can
    cite source_file:line_no for every claim.

    Phase 57d (2026-07-02): now optionally consults
    ``rca_reports`` (Dict[detector_id → RCAReport]) and
    ``correlators`` (Dict[stream → events]) so the investigation
    returns whole-pipeline diagnoses first, not just raw log grep.
    Both default to None so callers without a pipeline-wired data
    dict still work unchanged.
    """
    report = InvestigationReport(investigation=inv)
    report.window = inv.parsed_time
    report.window_description = inv.time_description

    # ---- Filter RCA reports by window (Phase 57d) ----
    # An RCA report is a top-tier hit when any of the timestamps its
    # timeline references overlap the query window. We approximate
    # this by checking whether the report's OWN metadata carries a
    # time_range OR whether any of its timeline events falls in the
    # window.
    if rca_reports:
        for det_id, rpt in (rca_reports or {}).items():
            timeline = getattr(rpt, "timeline", None) or []
            if inv.parsed_time is None:
                report.rca_reports_in_window.append(rpt)
                continue
            for tev in timeline:
                ts = (
                    getattr(tev, "ts_local", None)
                    or getattr(tev, "ts_utc", None)
                )
                if _ts_in_window(ts, inv.parsed_time):
                    report.rca_reports_in_window.append(rpt)
                    break

    # ---- Filter correlator events by window (Phase 57d) ----
    if correlators:
        for stream, events in (correlators or {}).items():
            if not events:
                continue
            hits = []
            if isinstance(events, list):
                for ev in events:
                    ts = (
                        (ev.get("ts") if isinstance(ev, dict) else None)
                        or getattr(ev, "ts", None)
                        or getattr(ev, "timestamp", None)
                    )
                    if _ts_in_window(ts, inv.parsed_time):
                        hits.append(ev)
            elif isinstance(events, dict):
                # e.g., force_reauth_summary is a dict; look at its
                # embedded 'events' list.
                inner = events.get("events") or []
                for ev in inner:
                    ts = (
                        (ev.get("ts") if isinstance(ev, dict) else None)
                        or getattr(ev, "ts", None)
                    )
                    if _ts_in_window(ts, inv.parsed_time):
                        hits.append(ev)
            if hits:
                report.correlator_hits[stream] = hits

    # ---- Filter findings ----
    if findings:
        report.findings_in_window = [
            f for f in findings
            if _finding_in_window(f, inv.parsed_time)
        ]

    # ---- Filter sessions ----
    if zpa_sessions:
        for s in zpa_sessions:
            # Time-window intersection: session is "in window" if any
            # of its key timestamps falls in window.
            s_ts = [
                getattr(s, "setup_ts", None),
                getattr(s, "request_ts", None),
                getattr(s, "ack_ts", None),
                getattr(s, "end_ts", None),
            ]
            in_window = (
                inv.parsed_time is None
                or any(_ts_in_window(t, inv.parsed_time) for t in s_ts if t)
            )
            host_match = _session_matches_hosts(
                s, inv.hosts, inv.ip_addresses, inv.apps,
            )
            if in_window and host_match:
                report.matched_sessions.append(s)

    # ---- Walk log_index for in-window topical events ----
    topic_lines: Dict[str, List[Any]] = {}
    log_kind_counts: Dict[str, int] = {}
    broker_codes: Dict[str, int] = {}
    dns_fails: Dict[str, int] = {}
    reauth_count = 0
    scanned = 0

    if log_index is not None and hasattr(log_index, "lines"):
        for ln in log_index.lines:
            if scanned >= max_lines_in_window:
                report.diagnostics.append(
                    f"Hit max_lines_in_window cap ({max_lines_in_window}); "
                    "some context may be incomplete."
                )
                break
            ts = getattr(ln, "ts", None)
            if not _ts_in_window(ts, inv.parsed_time):
                continue
            scanned += 1
            body = getattr(ln, "body", "") or ""
            # Per-log-kind tally.
            kind = getattr(ln, "kind", "") or "unknown"
            log_kind_counts[kind] = log_kind_counts.get(kind, 0) + 1

            # Broker code tally.
            m = re.search(r"\bBRK_MT_[A-Z_]+\b", body)
            if m:
                code = m.group(0)
                broker_codes[code] = broker_codes.get(code, 0) + 1

            # ZPA re-auth prompts.
            if "ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED" in body:
                reauth_count += 1

            # DNS failures by host.
            dm = re.search(
                r"Host not found:\s*([^\")\s]+)", body,
            )
            if dm:
                host = dm.group(1).strip(".,;:")
                dns_fails[host] = dns_fails.get(host, 0) + 1

            # Topic classification.
            topic = _classify_line_topic(body)
            if topic:
                topic_lines.setdefault(topic, []).append(ln)

            # Keyword / host filtering — pull additional lines that
            # match the user's extracted hosts/IPs/keywords so the
            # narrative has on-topic context.
            for h in inv.hosts:
                if h in body.lower():
                    topic_lines.setdefault(f"host:{h}", []).append(ln)
                    break
            for ip in inv.ip_addresses:
                if ip in body:
                    topic_lines.setdefault(f"ip:{ip}", []).append(ln)
                    break

    report.log_kind_counts = log_kind_counts
    report.broker_error_counts = dict(
        sorted(broker_codes.items(), key=lambda kv: -kv[1])
    )
    report.dns_failures = dict(
        sorted(dns_fails.items(), key=lambda kv: -kv[1])
    )
    report.reauth_event_count = reauth_count

    # ---- Build correlated groups ----
    #
    # Phase 58e-M2 (2026-07-08): every ``ts`` here comes from the log
    # index which returns aware UTC datetimes (Phase 58a). Using naive
    # ``datetime.min`` / ``datetime.max`` as the ``or`` fallback would
    # crash the sort the first time any line lacks a ``ts`` — pin the
    # sentinels to UTC.
    _AWARE_MIN = datetime.min.replace(tzinfo=timezone.utc)
    _AWARE_MAX = datetime.max.replace(tzinfo=timezone.utc)
    for topic, lines in topic_lines.items():
        if not lines:
            continue
        # Sort by timestamp, then cap.
        lines.sort(key=lambda x: getattr(x, "ts", _AWARE_MIN))
        kept = lines[:max_lines_per_group]
        label, sev, summary = _label_topic(topic, len(lines))
        report.correlated_groups.append(CorrelatedGroup(
            label=label,
            anchor_ts=getattr(kept[0], "ts", None),
            lines=kept,
            severity=sev,
            summary=summary,
        ))

    # Sort groups by severity then anchor_ts.
    sev_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    report.correlated_groups.sort(
        key=lambda g: (sev_order.get(g.severity, 9),
                       g.anchor_ts or _AWARE_MAX),
    )

    # ---- Derive root-cause hypothesis ----
    report.likely_root_cause, report.recommended_actions = (
        _hypothesize_root_cause(inv, report)
    )

    return report


def _label_topic(topic: str, count: int) -> Tuple[str, str, str]:
    """Human-readable label + severity + one-line summary for a
    correlated topic group."""
    if topic == "broker_saml_expired":
        return (
            "ZPA broker rejected setup: SAML expired",
            "CRITICAL",
            f"{count} `BRK_MT_SETUP_FAIL_SAML_EXPIRED` rejection(s) — "
            "the IdP session expired before ZPA's broker would accept "
            "the tunnel setup. Smoking gun for re-auth loops.",
        )
    if topic == "broker_no_policy":
        return (
            "ZPA broker rejected setup: no policy match",
            "CRITICAL",
            f"{count} `BRK_MT_SETUP_FAIL_NO_POLICY_FOUND` rejection(s) — "
            "the broker has no app segment that covers this destination. "
            "Likely missing from ZPA app catalog.",
        )
    if topic == "broker_setup_fail_other":
        return (
            "ZPA broker setup failure (other)",
            "WARNING",
            f"{count} `BRK_MT_SETUP_FAIL_*` rejection(s) outside the "
            "SAML / no-policy categories. Check the specific code.",
        )
    if topic == "broker_closed":
        return (
            "ZPA broker closed / terminated",
            "INFO",
            f"{count} broker-side close event(s).",
        )
    if topic == "zpa_reauth_prompt":
        return (
            "ZPA re-authentication required",
            "WARNING",
            f"{count} `ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED` "
            "RPC notification(s). Each one means ZCC told the user to "
            "re-authenticate.",
        )
    if topic == "wpad_fail":
        return (
            "Proxy auto-discovery (WPAD) failures",
            "WARNING",
            f"{count} `WinHttpGetProxyForUrl Failed with "
            "lastError=12180` event(s) — ERROR_WINHTTP_AUTODETECTION_"
            "FAILED. The client cannot find the proxy via DHCP/DNS.",
        )
    if topic == "zpa_health_check_fail":
        return (
            "ZPA tunnel health-check failures",
            "WARNING",
            f"{count} TCP echo server connection failure(s). ZPA "
            "tunnel's health probe at 100.64.0.6:9090 is unreachable.",
        )
    if topic == "dns_host_not_found":
        return (
            "DNS resolution failures (Host not found)",
            "WARNING",
            f"{count} DNS resolution failure(s). The host(s) "
            "involved may be missing from the ZPA app catalog.",
        )
    if topic == "tray_spawn_ratelimit":
        return (
            "Tray respawn rate limiter",
            "WARNING",
            f"{count} tray spawn-throttle event(s). The tray was "
            "crashing/respawning fast enough that Windows triggered "
            "the rate limiter.",
        )
    if topic == "tray_crash":
        return (
            "Tray crash",
            "CRITICAL",
            f"{count} tray crash event(s) in window.",
        )
    if topic == "zep_signer_fail":
        return (
            "ZEP (anti-tampering) signature verification failures",
            "WARNING",
            f"{count} `Signer File other error` event(s).",
        )
    if topic.startswith("host:"):
        host = topic[5:]
        return (
            f"Activity mentioning host `{host}`",
            "INFO",
            f"{count} log line(s) mentioning the host.",
        )
    if topic.startswith("ip:"):
        ip = topic[3:]
        return (
            f"Activity mentioning IP `{ip}`",
            "INFO",
            f"{count} log line(s) mentioning the address.",
        )
    return (topic, "INFO", f"{count} event(s)")


def _hypothesize_root_cause(
    inv: Investigation,
    report: InvestigationReport,
) -> Tuple[str, List[str]]:
    """Heuristic root-cause derivation. Looks at the strongest signals
    in the report and emits a one-paragraph hypothesis plus a list of
    next-step recommendations.

    Rules in priority order — first match wins. Each branch is grounded
    in a specific log-content signal so the engineer can verify.
    """
    bc = report.broker_error_counts
    reauth = report.reauth_event_count
    dns_fails = report.dns_failures
    sessions = report.matched_sessions

    # Rule 1: SAML expired storm + re-auth prompts → upstream IdP TTL
    if bc.get("BRK_MT_SETUP_FAIL_SAML_EXPIRED", 0) >= 5 or reauth >= 5:
        return (
            "The customer's IdP session lifetime is shorter than ZPA's "
            "configured Auth Timeout. ZPA's broker keeps rejecting "
            "tunnel setups with `BRK_MT_SETUP_FAIL_SAML_EXPIRED`, "
            "which ZCC translates into re-authentication prompts to "
            "the user. The fix is at the IdP, not in ZPA.",
            [
                "Confirm the IdP's session lifetime / token TTL for "
                "the Zscaler SAML or OIDC app (Okta: Authorization "
                "Server access policy; Azure AD: Conditional Access "
                "sign-in frequency; ADFS: TokenLifetime).",
                "Compare against ZPA's configured Auth Timeout and "
                "Idle Timeout in the policy.",
                "Align the IdP token TTL to match or exceed the ZPA "
                "Idle Timeout (typically 30 min).",
                "If the IdP TTL is correct, check whether MFA "
                "re-challenge is forcing the re-auth.",
            ],
        )

    # Rule 2: No-policy storm → ZPA app catalog gap
    if bc.get("BRK_MT_SETUP_FAIL_NO_POLICY_FOUND", 0) >= 5:
        affected = sorted({
            (getattr(s, "app_name", "") or "")
            for s in sessions
            if getattr(s, "ack_error", "") == "BRK_MT_SETUP_FAIL_NO_POLICY_FOUND"
        })
        affected = [a for a in affected if a]
        targeted = (
            f" The affected host(s) appear to be: "
            f"`{'`, `'.join(affected[:5])}`."
            if affected else ""
        )
        return (
            "ZPA's broker has no app segment policy matching the "
            "destination(s) the user tried to reach. Either the app "
            "segment is missing from the ZPA admin UI, or the user "
            "isn't in a group that's granted access to it." + targeted,
            [
                "In the ZPA admin UI, confirm an Application Segment "
                "exists that covers the affected host(s) (FQDN or "
                "wildcard).",
                "Confirm the user is a member of a group granted "
                "access via a Policy.",
                "If the app segment is correct, verify the App "
                "Connector serving that segment is healthy.",
            ],
        )

    # Rule 3: DNS host-not-found cluster → likely missing app segments
    if dns_fails and sum(dns_fails.values()) >= 5:
        top = sorted(dns_fails.items(), key=lambda kv: -kv[1])[:3]
        hosts = ", ".join(f"`{h}` ({n}×)" for h, n in top)
        return (
            f"DNS resolution is failing for one or more internal "
            f"hosts (top offenders: {hosts}). These hosts are not "
            "resolvable via public DNS, which is expected for "
            "internal apps — but they should be reachable via ZPA "
            "if they're in an app segment. They aren't.",
            [
                "Confirm each failing host has a matching ZPA "
                "Application Segment.",
                "If yes, confirm the segment is published to a "
                "healthy App Connector group with line-of-sight to "
                "internal DNS.",
                "Run `nslookup <host> <internal-dns>` from the "
                "connector to verify the connector can resolve.",
            ],
        )

    # Rule 4: WPAD failure cluster → proxy autodiscovery broken
    wpad_lines = [g for g in report.correlated_groups
                  if "WPAD" in g.label or "Proxy auto" in g.label]
    if wpad_lines and any(
            "wpad" in (g.label or "").lower()
            or "winhttp" in (g.summary or "").lower()
            for g in wpad_lines):
        return (
            "WPAD / proxy auto-discovery is failing repeatedly on "
            "the client. ZCC's WinHttpGetProxyForUrl call is "
            "returning ERROR_WINHTTP_AUTODETECTION_FAILED (12180), "
            "meaning the client cannot find a proxy via DHCP option "
            "252 or a DNS WPAD record. This often manifests as "
            "bypass-routing surprises and IdP-redirect failures.",
            [
                "Confirm DHCP option 252 is being served on the "
                "user's subnet, OR a `wpad.<domain>` DNS A record "
                "resolves.",
                "Confirm the WPAD-served PAC file is reachable "
                "from the client.",
                "If WPAD is intentionally not deployed, set the "
                "Forwarding Profile to not rely on autodetection.",
            ],
        )

    # Rule 5: Tray crash cluster
    crash_groups = [g for g in report.correlated_groups
                    if "crash" in (g.label or "").lower()
                    or "spawn" in (g.label or "").lower()]
    if crash_groups:
        return (
            "The ZSATray process crashed (or respawned past the "
            "Windows rate limiter) during the investigation window. "
            "Combined with any auth-required prompts in the same "
            "window, this is often a tray-side handling crash on "
            "repeated re-auth notifications.",
            [
                "Collect the `ZSATray.exe.<pid>.dmp.zip` files for "
                "Zscaler support analysis.",
                "Note whether the crashes correlate temporally with "
                "ZPA re-auth prompts or system sleep/wake events.",
                "If the crashes are concurrent with re-auth, treat "
                "the SAML / IdP fix as primary; the tray fix is a "
                "Zscaler-side bug to escalate via support.",
            ],
        )

    # Default — no strong signal
    return (
        "No single dominant failure pattern in the investigation "
        "window. The report below shows the available evidence by "
        "topic. Inspect the matched sessions and correlated groups "
        "to identify the issue manually.",
        [
            "Open the matched sessions in the ZPA tab and inspect "
            "their phase timelines.",
            "Cross-reference the broker error counts with the time "
            "of the customer's reported issue.",
            "Widen the investigation window if the prompt time was "
            "narrower than the actual incident.",
        ],
    )


# --------------------------------------------------------------------
# Markdown renderer
# --------------------------------------------------------------------

def render_report(report: InvestigationReport) -> str:
    """Return the investigation report as a Markdown string. Designed
    to paste into a ticket / Slack / email without reformatting.

    Every claim cites a specific source: timestamp + log file + line
    number where available, broker code counts otherwise. The
    engineer can verify any line by searching the bundle.
    """
    inv = report.investigation
    out: List[str] = []

    out.append("# Investigation report")
    out.append("")
    out.append(f"**Prompt:** {_md_quote(inv.raw_prompt)}")
    out.append("")
    if inv.is_empty:
        out.append(
            "_Prompt parsed to no actionable filters — running an "
            "unfiltered audit across the whole bundle._"
        )
        out.append("")

    out.append("## Parsed context")
    if report.window_description:
        out.append(f"- **Time window:** {report.window_description}")
    else:
        out.append("- **Time window:** whole bundle (no time hint in prompt)")
    if inv.suites:
        out.append(f"- **Suite(s):** {', '.join(s.upper() for s in inv.suites)}")
    if inv.symptoms:
        out.append(f"- **Symptom(s):** {', '.join(inv.symptoms)}")
    if inv.hosts:
        out.append(f"- **Host(s):** `{'`, `'.join(inv.hosts)}`")
    if inv.ip_addresses:
        out.append(f"- **IP(s):** `{'`, `'.join(inv.ip_addresses)}`")
    if inv.apps:
        out.append(f"- **App(s):** `{'`, `'.join(inv.apps)}`")
    if inv.keywords:
        out.append(
            f"- **Keyword(s) matched:** {', '.join(inv.keywords)}"
        )
    out.append("")

    # Phase 57d (2026-07-02): surface top-tier RCA hits FIRST, before
    # scope counts. An RCA report is the whole-pipeline conclusion
    # (detector + correlator + synthesizer); if one matches the query
    # window it's the answer to the engineer's question.
    if report.rca_reports_in_window:
        out.append("## Top-tier findings — RCA-grade")
        for r in report.rca_reports_in_window[:5]:
            title = getattr(r, "issue_title", "") or getattr(
                r, "synthesizer_id", "RCA report"
            )
            sev = getattr(r, "severity_label", "") or ""
            det = getattr(r, "synthesizer_id", "")
            out.append(f"- **{title}** — {sev}  ·  detector `{det}`")
        out.append("")
        out.append(
            "_Open the Root Cause Analysis workspace to see the full "
            "structured RCA for each of these._"
        )
        out.append("")
    if report.correlator_hits:
        out.append("## Correlator events in window")
        for stream, hits in report.correlator_hits.items():
            out.append(f"- **{stream}:** {len(hits)} event(s)")
        out.append("")

    out.append("## Scope of in-window evidence")
    if report.log_kind_counts:
        total = sum(report.log_kind_counts.values())
        kinds = ", ".join(
            f"{k} ({v:,})"
            for k, v in sorted(
                report.log_kind_counts.items(), key=lambda kv: -kv[1],
            )
        )
        out.append(f"- **Lines scanned:** {total:,} ({kinds})")
    if report.broker_error_counts:
        codes = ", ".join(
            f"`{c}` ({n})"
            for c, n in report.broker_error_counts.items()
        )
        out.append(f"- **Broker codes:** {codes}")
    if report.reauth_event_count:
        out.append(
            f"- **ZPA re-auth prompts:** {report.reauth_event_count} "
            "events (`ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED`)"
        )
    if report.dns_failures:
        top = list(report.dns_failures.items())[:5]
        hosts = ", ".join(f"`{h}` ({n}×)" for h, n in top)
        out.append(f"- **DNS host-not-found:** {hosts}")
    if report.matched_sessions:
        out.append(
            f"- **Matched ZPA sessions:** {len(report.matched_sessions)} "
            "(see the ZPA tab for full drill-downs)"
        )
    if report.findings_in_window:
        out.append(
            f"- **Detector findings in window:** "
            f"{len(report.findings_in_window)}"
        )
    out.append("")

    out.append("## Likely root cause")
    out.append(report.likely_root_cause)
    out.append("")

    if report.recommended_actions:
        out.append("### Recommended next steps")
        for i, step in enumerate(report.recommended_actions, 1):
            out.append(f"{i}. {step}")
        out.append("")

    if report.correlated_groups:
        out.append("## Correlated evidence")
        out.append(
            "_Each block below is a topical cluster of in-window log "
            "lines. Severity in brackets._"
        )
        out.append("")
        for g in report.correlated_groups:
            out.append(f"### [{g.severity}] {g.label}")
            if g.summary:
                out.append(g.summary)
            out.append("")
            # Sample lines — capped per group.
            if g.lines:
                out.append("```text")
                for ln in g.lines:
                    ts = getattr(ln, "ts", None)
                    src = getattr(ln, "source_file", "")
                    lno = getattr(ln, "line_no", "")
                    body = getattr(ln, "body", "") or ""
                    ts_str = (
                        ts.strftime("%Y-%m-%d %H:%M:%S")
                        if ts else "(no ts)"
                    )
                    src_label = (
                        f" {src}:{lno}" if src else ""
                    )
                    out.append(f"{ts_str}{src_label}  {body[:300]}")
                out.append("```")
                out.append("")

    if report.matched_sessions:
        out.append("## Matched ZPA sessions")
        out.append(
            "_The sessions below intersect both the prompt's time "
            "window and the prompt's host/app context. Open each in "
            "the ZPA tab for the full phase timeline._"
        )
        out.append("")
        out.append(
            "| Time | App | TAG ID | Conn ID | Outcome | Bytes |"
        )
        out.append(
            "|------|-----|--------|---------|---------|-------|"
        )
        for s in report.matched_sessions[:30]:
            ts = getattr(s, "setup_ts", None) or getattr(s, "ack_ts", None)
            ts_str = ts.strftime("%H:%M:%S") if ts else "—"
            app = (getattr(s, "app_name", "") or "—")[:40]
            tag = getattr(s, "tag_id", "") or "—"
            conn = getattr(s, "conn_id", "") or "—"
            outcome = (getattr(s, "outcome", "") or "—")[:30]
            br = getattr(s, "bytes_runtime_read", 0) or 0
            bw = getattr(s, "bytes_runtime_written", 0) or 0
            bytes_str = (
                f"{br + bw:,}" if (br or bw) else "—"
            )
            out.append(
                f"| {ts_str} | `{app}` | `{tag}` | `{conn}` | "
                f"{outcome} | {bytes_str} |"
            )
        out.append("")

    if report.diagnostics:
        out.append("## Investigation diagnostics")
        for d in report.diagnostics:
            out.append(f"- {d}")
        out.append("")

    out.append("---")
    out.append(
        "_Generated by BundleScope Investigate. Every entry above is "
        "derived from log lines in the bundle — no inferred data._"
    )

    return "\n".join(out)


def _md_quote(s: str) -> str:
    """Quote a string for safe Markdown rendering — escapes backticks
    and surrounding-quote pairs."""
    if not s:
        return "_(empty)_"
    cleaned = s.replace("`", "'").replace("\n", " ").strip()
    return f"> {cleaned}"
