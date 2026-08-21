"""
Device Trust & Posture extractor.

Phase 41 (2026-06-19). Pulls the ZPA *device-compliance* and *trust-
level access policy* configuration out of a ZCC bundle and turns it
into a structured report:

  * Posture profiles — UDID → name, type, frequency, latest pass/
    fail result, full result history.
  * Trust-level condition — the disjunction-of-conjunctions tree
    that says "user gets trust level X when posture checks Y/Z
    pass." This is the ZPA access policy.
  * Trusted-network policy revisions — counts + IDs of every
    ``zpn_trusted_networks_ack`` the broker has pushed.
  * Posture profile ack count — how many times the broker
    re-confirmed each profile.
  * ZPA reauth timing config — ``zpaAutoReauthTimeoutSec``,
    ``zpaReauthNotificationTime``, ``zpaReauthNotifSwitch``. These
    were already in TrayPolicy but never surfaced to the engineer;
    Phase 41 adds them to the report because they're directly
    relevant to the re-auth loop UX.
  * Posture-config quality findings — typo / name-mismatch
    detection. Caught the "Dectect Full Disk Encryption" misspelling
    in the Example Tenant A bundle's trust-condition. The customer's ZPA admin
    UI shows the typo to every operator; surfacing it lets the
    engineer flag it during triage.

The extractor is pure stdlib. Inputs are tray-manager + tunnel +
service log files (whichever carry the patterns); output is a
``PostureExtraction`` dataclass consumed by ``ui/policy.py`` for
the Device Trust & Posture section.

Grounded in Example Tenant A bundle 2026-06-18: 2 posture profiles (Defender +
FDE both PROCESS_CHECK / FULL_DISK_ENCRYPTION running every 900s,
both passing), 1 AND'd trust condition, 2 trusted-network revisions,
``zpaAutoReauthTimeoutSec=30 / NotifSwitch=false`` — the combination
that explains the "user gets no warning before re-auth prompt"
behaviour.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# --------------------------------------------------------------------
# Data shapes
# --------------------------------------------------------------------


@dataclass
class PostureProfile:
    """One device-compliance check configured in ZPA."""
    udid: str                      # UUID assigned by ZPA admin
    posture_id: int                # numeric admin-assigned ID
    name: str                      # human-readable label
    ptype: str                     # "PROCESS_CHECK", "FULL_DISK_ENCRYPTION", etc.
    type_num: Optional[int] = None # numeric type code (9, 6, ...)
    frequency_s: int = 0           # check-run interval in seconds
    latest_result: Optional[int] = None     # 1 = pass, 0 = fail
    latest_result_ts: Optional[datetime] = None
    # Full history: (timestamp, result) pairs. Capped at 200 to bound
    # memory on long bundles.
    result_history: List[Tuple[datetime, int]] = field(default_factory=list)


@dataclass
class TrustCondition:
    """Trust-level access policy parsed from
    ``getTrustTypeResult: trustLevel condition: {...}``.

    Wire shape: ``{"cs": [{"cn": [...]}, ...]}`` where ``cs`` is
    the OR set (any group's conditions, all met, grants trust) and
    each ``cn`` is the AND set (all conditions must pass).

    Real-world policies are usually one ``cs`` entry with multiple
    ``cn`` items — a single AND group.
    """
    raw: dict
    # Outer list = OR groups; inner list = AND'd conditions; each
    # condition has keys ``id``, ``name``, ``udid``.
    or_groups: List[List[Dict[str, Any]]] = field(default_factory=list)


@dataclass
class PostureExtraction:
    """Everything Phase 41 pulls from the bundle."""
    profiles: Dict[str, PostureProfile] = field(default_factory=dict)
    trust_condition: Optional[TrustCondition] = None
    # (timestamp, revision_id) tuples — every zpn_trusted_networks_ack.
    trusted_network_revisions: List[Tuple[Optional[datetime], int]] = field(
        default_factory=list,
    )
    posture_ack_count: int = 0
    # ZPA reauth timing from TrayPolicy.
    zpa_auto_reauth_timeout_s: Optional[int] = None
    zpa_reauth_notif_time_s: Optional[int] = None
    zpa_reauth_notif_switch: Optional[bool] = None
    # Config-quality findings — typos, name mismatches, etc.
    quality_findings: List[str] = field(default_factory=list)

    @property
    def distinct_trusted_net_revisions(self) -> List[int]:
        """Unique revision IDs in time order of first ack."""
        seen: set = set()
        out: List[int] = []
        for _, rev in self.trusted_network_revisions:
            if rev not in seen:
                seen.add(rev)
                out.append(rev)
        return out


# --------------------------------------------------------------------
# Regex patterns
# --------------------------------------------------------------------

# ``updatePostureProfileDetails Posture name: <name>, udid: <UUID>,
#   type: <PROCESS_CHECK|FULL_DISK_ENCRYPTION|...>, posture ID: <N>,
#   freq: <SEC>``
# Name can contain spaces; using a non-greedy match up to the first
# comma-then-key boundary.
_RE_POSTURE_DETAILS = re.compile(
    r"updatePostureProfileDetails\s+Posture name:\s*(?P<name>.+?),"
    r"\s*udid:\s*(?P<udid>[\w-]+),"
    r"\s*type:\s*(?P<ptype>\w+),"
    r"\s*posture ID:\s*(?P<pid>\d+),"
    r"\s*freq:\s*(?P<freq>\d+)"
)

# ``getTrustTypeResult: trustLevel condition: {"cs":[...]}``
_RE_TRUST_CONDITION = re.compile(
    r"getTrustTypeResult:\s*trustLevel condition:\s*(\{.+\})"
)

# ``Device posture result str: [[{...}, ...]]``
_RE_POSTURE_RESULT = re.compile(
    r"Device posture result str:\s*(\[.+\])"
)

# ``zpn_trusted_networks_ack":{"id":<N>}``
_RE_TRUSTED_NET_ACK = re.compile(
    r'zpn_trusted_networks_ack["}\s:]*\{"id"\s*:\s*(\d+)\}'
)

# ``zpn_posture_profile_ack":{"id_str":"<UUID>"}``
_RE_POSTURE_PROF_ACK = re.compile(
    r'zpn_posture_profile_ack["}\s:]*\{"id_str"\s*:\s*"([\w-]+)"\}'
)

# TrayPolicy timing fields.
_RE_AUTO_REAUTH = re.compile(r'"zpaAutoReauthTimeoutSec"\s*:\s*(\d+)')
_RE_REAUTH_NOTIF_TIME = re.compile(r'"zpaReauthNotificationTime"\s*:\s*(\d+)')
_RE_REAUTH_NOTIF_SWITCH = re.compile(
    r'"zpaReauthNotifSwitch"\s*:\s*(true|false)'
)

# Standard ZCC Format A timestamp prefix.
_RE_TS = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d+)\(([+-]\d{4})\)"
)

# Common typos we've seen in customer-defined ZPA names. Used by the
# quality-finding pass. Expand as more bundles surface new ones.
_KNOWN_TYPOS: Dict[str, str] = {
    "Dectect": "Detect",
    "Defendor": "Defender",
    "Encyption": "Encryption",
    "Compliace": "Compliance",
    "Comliance": "Compliance",
    "Bitlocer": "Bitlocker",
    "Crypotgraph": "Cryptograph",
    "Posure": "Posture",
}

# Cap on per-profile result history. Bounds memory on long bundles;
# 200 samples × 900s interval = ~50h of history per profile, which is
# more than the typical 4-7 day bundle window covers anyway.
_HISTORY_CAP = 200


# --------------------------------------------------------------------
# Timestamp parsing
# --------------------------------------------------------------------


def _parse_format_a_ts(line: str) -> Optional[datetime]:
    """Pull the leading ZCC Format A timestamp from a log line.

    Format A: ``YYYY-MM-DD HH:MM:SS.ffffff(±HHMM) ...``. Returns a
    timezone-aware UTC datetime or None if the prefix doesn't match.

    Phase 58e-H2 (2026-07-08): the numeric portion IS UTC. The (±HHMM)
    is metadata about the device's local offset, not the timestamp's
    own timezone. Prior code attached the offset as tzinfo (making
    later ``astimezone(UTC)`` calls shift by |offset| hours) which
    contradicted Phase 58a's log_parser fix and produced posture
    timestamps 6h off on MDT bundles. This helper now mirrors
    log_parser._parse_ts by attaching timezone.utc directly.
    """
    m = _RE_TS.match(line)
    if not m:
        return None
    try:
        base = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        return base.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------
# Bundle scan
# --------------------------------------------------------------------


def _find_relevant_logs(bundle) -> List:
    """Return every log file in the bundle that's likely to contain
    posture / trust / TrayPolicy data."""
    files = []
    for p in getattr(bundle, "files", []):
        if p.suffix != ".log":
            continue
        name = p.name
        # ZSATrayManager carries TrayPolicy + posture detail lines.
        # ZSATunnel carries the zpn_*_ack control messages. ZSATray
        # is the macOS sibling for TrayPolicy on Mac bundles.
        if (
            "ZSATrayManager" in name
            or "ZSATunnel" in name
            or "ZSATray" in name
            or "TrayManager" in name
            or "TRPTunnel" in name   # macOS tunnel naming
        ):
            files.append(p)
    return files


# How much of each log file we read. Posture details + trust
# conditions tend to live near the start of each tray-manager log
# (set during startup); ack messages are scattered across the tunnel
# log. The cap is generous because posture state is small relative
# to the typical tunnel-log volume.
_FILE_READ_CAP_BYTES = 200 * 1024 * 1024   # 200 MB / file


def extract_posture(bundle) -> PostureExtraction:
    """Scan the bundle's tray + tunnel logs and assemble the
    PostureExtraction. Pure-stdlib, deterministic."""
    out = PostureExtraction()

    for path in _find_relevant_logs(bundle):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                content = fp.read(_FILE_READ_CAP_BYTES)
        except OSError as e:
            log.debug("posture_extract: skipping %s: %s", path, e)
            continue
        _ingest_content(out, content)

    # A check named by the trust policy but never evaluated is itself a
    # finding, so make sure it appears in the profile list.
    _backfill_profiles_from_trust_condition(out)

    _derive_quality_findings(out)
    return out


# ``type`` in the posture-result JSON is numeric; the verbose
# definition line (when present) spells it out. This maps the numeric
# codes we've actually observed in bundles so a synthesised profile
# still shows a readable type. Unobserved codes render as "type N"
# rather than a guess.
_POSTURE_TYPE_NUM_TO_NAME = {
    6: "FULL_DISK_ENCRYPTION",
    9: "PROCESS_CHECK",
}


def _ensure_profile_from_result(out: PostureExtraction, udid: str,
                                entry: dict) -> PostureProfile:
    """Return the PostureProfile for `udid`, creating it from the
    posture-RESULT entry if the definition line never appeared.

    Why this exists: `_RE_POSTURE_DETAILS` expects
    ``updatePostureProfileDetails Posture name: X, udid: Y, type: Z,
    posture ID: N, freq: S``. Current ZCC builds (4.9.x, verified
    against the Scenario Windows C 2026-07-07 and Scenario Windows D 2026-06-12 bundles)
    emit only ``updatePostureProfileDetails Posture size: 2`` and
    ``... Posture in User Tunnel`` — the fields are simply not on that
    line any more. The old code then did
    ``if udid not in out.profiles: continue``, so every posture result
    was discarded and `profiles` stayed empty. That's why the UI showed
    "Posture profiles (0)" on bundles that plainly contain posture data.

    The result JSON carries everything needed — name, postureId, type,
    udid — so we build the profile from it. `frequency_s` stays 0
    because the result line genuinely doesn't carry it; a definition
    line, if one does appear, still wins and fills that in.
    """
    p = out.profiles.get(udid)
    if p is not None:
        return p
    type_num = entry.get("type")
    try:
        pid = int(entry.get("postureId") or 0)
    except (TypeError, ValueError):
        pid = 0
    p = PostureProfile(
        udid=udid,
        posture_id=pid,
        name=str(entry.get("name") or "(unnamed)"),
        ptype=_POSTURE_TYPE_NUM_TO_NAME.get(
            type_num, f"type {type_num}" if type_num is not None else "",
        ),
        type_num=type_num,
        frequency_s=0,
    )
    out.profiles[udid] = p
    return p


def _backfill_profiles_from_trust_condition(out: PostureExtraction) -> None:
    """Add any posture check that the trust condition references but
    that never produced a result line.

    A check configured in the trust policy but never evaluated is
    exactly the kind of gap worth seeing — it means the policy depends
    on something the client isn't reporting on. Marking it with
    `latest_result=None` keeps it visibly distinct from a pass or fail.
    """
    if out.trust_condition is None:
        return
    for group in out.trust_condition.or_groups:
        for cond in group:
            if not isinstance(cond, dict):
                continue
            udid = cond.get("udid") or ""
            if not udid or udid in out.profiles:
                continue
            try:
                pid = int(cond.get("id") or 0)
            except (TypeError, ValueError):
                pid = 0
            out.profiles[udid] = PostureProfile(
                udid=udid,
                posture_id=pid,
                name=str(cond.get("name") or "(unnamed)"),
                ptype="",
                type_num=None,
                frequency_s=0,
                latest_result=None,
            )


def _ingest_content(out: PostureExtraction, content: str) -> None:
    """Walk one log file's text and update the extraction."""
    for line in content.split("\n"):
        if not line:
            continue
        # Cheap rejection: skip lines that don't contain any of our
        # signal keywords. This keeps the regex pool from running on
        # every log line.
        # NOTE: this gate is case-SENSITIVE and that mattered. It used to
        # test only `"Posture" in line` (capital P), which silently
        # rejected every `Device posture result str: [[...]]` line —
        # lowercase 'p' — so the per-check pass/fail results never
        # reached `_RE_POSTURE_RESULT` at all and every profile showed
        # `latest_result=None`. Matching lowercase 'posture' too fixes
        # it; the keyword set stays cheap enough to run per line.
        if not (
            "osture" in line          # matches Posture AND posture
            or "trustLevel" in line
            or "trusted_networks_ack" in line
            or "zpaAutoReauthTimeoutSec" in line
            or "zpaReauthNotif" in line
        ):
            continue

        # --- Posture profile details (definition push) ---
        m = _RE_POSTURE_DETAILS.search(line)
        if m:
            udid = m.group("udid")
            if udid not in out.profiles:
                try:
                    out.profiles[udid] = PostureProfile(
                        udid=udid,
                        posture_id=int(m.group("pid")),
                        name=m.group("name").strip(),
                        ptype=m.group("ptype"),
                        frequency_s=int(m.group("freq")),
                    )
                except (ValueError, TypeError):
                    pass
            continue

        # --- Trust-level condition ---
        m = _RE_TRUST_CONDITION.search(line)
        if m and out.trust_condition is None:
            try:
                raw = json.loads(m.group(1))
                or_groups = []
                for cs_entry in raw.get("cs", []):
                    or_groups.append(cs_entry.get("cn", []))
                out.trust_condition = TrustCondition(
                    raw=raw, or_groups=or_groups,
                )
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass
            continue

        # --- Posture result (per-check pass/fail) ---
        m = _RE_POSTURE_RESULT.search(line)
        if m:
            ts = _parse_format_a_ts(line)
            try:
                results = json.loads(m.group(1))
                # The wire shape is a list-of-lists of dicts. Walk
                # both levels defensively.
                if isinstance(results, list):
                    for outer in results:
                        # Some ZCC builds emit a single flat list rather
                        # than a list-of-lists. Accept both.
                        entries = outer if isinstance(outer, list) else [outer]
                        for entry in entries:
                            if not isinstance(entry, dict):
                                continue
                            udid = entry.get("udid", "")
                            if not udid:
                                continue
                            p = _ensure_profile_from_result(out, udid, entry)
                            r = entry.get("result")
                            p.latest_result = r
                            p.latest_result_ts = ts
                            if p.type_num is None:
                                p.type_num = entry.get("type")
                            if ts is not None and r is not None:
                                if len(p.result_history) < _HISTORY_CAP:
                                    p.result_history.append((ts, r))
            except (json.JSONDecodeError, TypeError):
                pass
            continue

        # --- Trusted-network policy ack (revision IDs) ---
        m = _RE_TRUSTED_NET_ACK.search(line)
        if m:
            try:
                rev = int(m.group(1))
                out.trusted_network_revisions.append(
                    (_parse_format_a_ts(line), rev)
                )
            except (ValueError, TypeError):
                pass
            continue

        # --- Posture profile ack ---
        if _RE_POSTURE_PROF_ACK.search(line):
            out.posture_ack_count += 1
            continue

        # --- ZPA reauth timing from TrayPolicy ---
        m = _RE_AUTO_REAUTH.search(line)
        if m and out.zpa_auto_reauth_timeout_s is None:
            try:
                out.zpa_auto_reauth_timeout_s = int(m.group(1))
            except (ValueError, TypeError):
                pass
        m = _RE_REAUTH_NOTIF_TIME.search(line)
        if m and out.zpa_reauth_notif_time_s is None:
            try:
                out.zpa_reauth_notif_time_s = int(m.group(1))
            except (ValueError, TypeError):
                pass
        m = _RE_REAUTH_NOTIF_SWITCH.search(line)
        if m and out.zpa_reauth_notif_switch is None:
            out.zpa_reauth_notif_switch = (m.group(1) == "true")


# --------------------------------------------------------------------
# Quality findings
# --------------------------------------------------------------------


def _derive_quality_findings(out: PostureExtraction) -> None:
    """Run the typo / name-mismatch checks against the extracted
    posture profiles and trust condition. Adds messages to
    ``out.quality_findings``. Each finding is human-readable Markdown.
    """
    # 1. Name mismatch between posture-profile definition and
    #    trust-condition reference. If the customer's ZPA admin
    #    edited the access-policy name but not the underlying
    #    posture profile (or vice versa), the names diverge — this
    #    is real misconfiguration that the engineer should flag.
    if out.trust_condition is not None:
        for cn_group in out.trust_condition.or_groups:
            for cond in cn_group:
                tc_name = cond.get("name", "")
                tc_udid = cond.get("udid", "")
                if not (tc_udid and tc_name):
                    continue
                profile = out.profiles.get(tc_udid)
                if profile is None:
                    out.quality_findings.append(
                        f"Trust condition references posture UDID "
                        f"`{tc_udid[:8]}…` ({tc_name}) but no "
                        f"`updatePostureProfileDetails` line for "
                        f"that UDID was found. The posture profile "
                        f"may have been deleted or renamed and the "
                        f"trust condition not updated."
                    )
                    continue
                if profile.name != tc_name:
                    out.quality_findings.append(
                        f"Posture-name mismatch: profile UDID "
                        f"`{tc_udid[:8]}…` is named "
                        f"\"{profile.name}\" in the profile "
                        f"definition but the trust condition "
                        f"references it as \"{tc_name}\". One side "
                        f"has a typo or stale reference — visible "
                        f"to ZPA admins."
                    )

    # 2. Known-typo detection in any posture name AND trust-condition
    #    reference.
    def _check_typos(label: str, name: str) -> None:
        if not name:
            return
        for wrong, right in _KNOWN_TYPOS.items():
            if wrong in name:
                finding = (
                    f"{label} contains likely misspelling "
                    f"\"{wrong}\" (probably meant \"{right}\"). "
                    f"Visible in the ZPA admin UI — worth flagging "
                    f"to the customer for cleanup."
                )
                if finding not in out.quality_findings:
                    out.quality_findings.append(finding)

    for p in out.profiles.values():
        _check_typos(f"Posture profile \"{p.name}\"", p.name)
    if out.trust_condition is not None:
        for cn_group in out.trust_condition.or_groups:
            for cond in cn_group:
                _check_typos(
                    f"Trust condition reference \"{cond.get('name', '')}\"",
                    cond.get("name", ""),
                )

    # 3. Reauth-config UX warning: if NotifSwitch is False, the user
    #    gets no advance warning before being prompted to re-auth.
    #    Combined with a short auto-reauth timeout, this is a UX
    #    problem the engineer should call out.
    if out.zpa_reauth_notif_switch is False:
        msg = (
            "`zpaReauthNotifSwitch` is **disabled** — the user "
            "gets no in-tray notification before being prompted to "
            "re-authenticate. Combined with the configured "
        )
        if out.zpa_auto_reauth_timeout_s is not None:
            msg += (
                f"`zpaAutoReauthTimeoutSec` of "
                f"{out.zpa_auto_reauth_timeout_s} s, "
            )
        msg += (
            "this means SAML expiries arrive at the user as a "
            "sudden prompt with no heads-up. Often correlates with "
            "users \"missing\" the re-auth prompt and the session "
            "sitting in AUTHENTICATION_REQUIRED state."
        )
        out.quality_findings.append(msg)


# --------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------


def format_trust_condition_human(
    cond: TrustCondition,
) -> str:
    """Render a TrustCondition as a single human-readable string.

    Example output:
        ALL of [Detect Defender, Detect Full Disk Encryption]
        OR ALL of [Compliant Workstation]

    Most policies have one OR group with one AND list, which renders
    as a clean "ALL of [a, b, c]".
    """
    if not cond or not cond.or_groups:
        return "(empty trust condition)"
    parts: List[str] = []
    for cn_group in cond.or_groups:
        names = [c.get("name", "?") for c in cn_group]
        parts.append(f"ALL of [{', '.join(names)}]")
    return "  OR  ".join(parts)
