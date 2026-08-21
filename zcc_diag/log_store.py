"""SQLite-backed line store — Slice 12/13/14 (2026-08-19).

Replaces the all-in-RAM `LogIndex` so the analyzer can read **every**
log line in a bundle, including the compressed rotations.

Why this exists
---------------
Measured across the 26-bundle corpus: the plain `.log` files hold ~4.5 M
lines, but the bundles also contain **1,822 `.log.zip` rotations holding
an estimated ~44 M lines**. ZCC compresses older rotations; the old
loader globbed `*.log` only, so it was reading roughly **9%** of the
available history. That matters because the most common triage failure
is "the incident window isn't in the bundle" — often it is, just zipped.

44 M `IndexedLine` objects would need ~11 GB resident, so holding them
in a Python list is not an option. This module keeps the lines in a
SQLite file and streams them.

Design contract
---------------
* **Drop-in.** `LogStore` exposes the same surface the rest of the app
  already uses — `.lines`, `.search()`, `.time_window()`,
  `.surrounding_lines()`, `.bundle_tz_offset`, and the counters. `.lines`
  is a lazy `LineSequence` supporting `len()`, integer and slice
  indexing (including a step), and iteration, so consumers that do
  `idx.lines[0]`, `idx.lines[:500]`, `idx.lines[::17]` or
  `for ln in idx.lines` keep working untouched.
* **No in-memory sort.** Chronological order comes from
  `ORDER BY ts, source_file, line_no` at query time, which also removes
  the old whole-list sort.
* **Honest accounting.** `rotations_found` / `rotations_read` /
  `archives_unreadable` are reported so the UI can say what was *not*
  read rather than implying full coverage.
* Deterministic and interpretation-free, like everything else here.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import sqlite3
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .log_index import IndexedLine, _LINE_RE, _extract_host, _extract_session_id


class InsufficientDiskSpace(RuntimeError):
    """Raised by the preflight check before any bytes are written.

    Measured cost on a real bundle: Example Tenant A's 1,134 rotations expand to
    ~4.2 GB of log text and produce a ~3.6 GB SQLite file (~265 bytes per
    stored line). A silent `sqlite3.OperationalError: database or disk is
    full` two hundred seconds into a build — which is what the first cut
    did — tells the operator nothing about how much room was needed or
    where it tried to write. This carries the numbers.
    """


# Every store this process creates, so an abnormal exit doesn't strand
# multi-gigabyte temp files. The first cut leaked five of them (~4.1 GB)
# across crashed runs, which is what filled the disk and caused the
# failure above — a self-inflicted cascade.
_LIVE_STORES: "List[LogStore]" = []


def _cleanup_all() -> None:
    for st in list(_LIVE_STORES):
        try:
            st.cleanup()
        except Exception:  # noqa: BLE001
            pass


atexit.register(_cleanup_all)


def _install_signal_cleanup() -> None:
    """Also clean up on SIGTERM.

    `atexit` alone was not enough and the docstring that claimed
    otherwise was wrong: a SIGTERM-killed build left a 1.94 GB orphan,
    because the default SIGTERM disposition terminates the process
    without unwinding, so `atexit` never runs. (SIGINT was already safe
    only by accident — Python raises KeyboardInterrupt, which unwinds.)

    Chains to any previously-installed handler rather than replacing it,
    and stays silent if the host forbids setting handlers (e.g. when
    imported on a non-main thread, as Streamlit may do).
    """
    try:
        import signal
    except Exception:  # noqa: BLE001
        return

    try:
        prev = signal.getsignal(signal.SIGTERM)
    except Exception:  # noqa: BLE001
        return

    def _handler(signum, frame):
        _cleanup_all()
        if callable(prev):
            prev(signum, frame)
        else:
            os._exit(143)  # 128 + SIGTERM

    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError, RuntimeError):
        # Not the main thread, or the platform refuses. atexit still
        # covers normal exit and KeyboardInterrupt.
        pass


_install_signal_cleanup()

# --------------------------------------------------------------------
# Component classification
# --------------------------------------------------------------------
#
# Ordered most-specific-first, and matched as a SUBSTRING of the
# basename rather than a prefix.
#
# The prefix assumption was silently dropping whole bundles. HubSpot
# ticket exports (`file-export-<id>-*.zip`) rewrite every filename to
#   <uuid>-TICKET.hs_file_upload-ZSATunnel_2026-05-21-17-38-51.log
# so `name.startswith("ZSATunnel")` is False and the file was skipped.
# One such bundle in the corpus parsed to exactly **zero** lines while
# containing 23 MB of perfectly good tunnel logs.
# Slice 13b — five components were missing, and a file that matches no
# component is never read. Measured across 12 bundles by testing whether
# each unread log-like file actually uses the ZCC line format:
#
#   UPMServiceController    1,577,721 ZCC-format lines   31 files  <-- !
#   ZSAHelper                   4,932 lines             442 files
#   ZSAUpdater                  1,845 lines               7 files
#   ZSACredentialProvider         172 lines              13 files
#   ZSAScriptExecutorRpcClient      80 lines              4 files
#
# `com.zscaler.UPMServiceController` is the macOS/ZDX UPM service
# controller and was the single largest unread source in the corpus —
# 28.5 MB plain plus 23.2 MB of rotations. It was missed because the
# marker list only knew `ZSAUpm`.
_COMPONENT_MARKERS: List[Tuple[str, Tuple[str, ...]]] = [
    # Most specific first: UPMServiceController must be tested before
    # the bare "UPM"/"Service" markers or it lands in the wrong bucket.
    ("upm",        ("ZSAUpm", "UPMServiceController")),
    ("tray",       ("ZSATrayManager", "ZSATrayHelper", "ZSATray",
                    "TrayManager")),
    ("tunnel",     ("ZSATunnel", "TRPTunnel", "ZscalerTunnel")),
    ("service",    ("ZSAService", "com.zscaler.ZscalerService",
                    "TRPService")),
    ("updater",    ("ZSAUpdater",)),
    ("helper",     ("ZSAHelper",)),
    ("credential", ("ZSACredentialProvider",)),
    ("script",     ("ZSAScriptExecutorRpcClient",)),
]

# Files that ARE evidence but are NOT ZCC-format text logs. Declared
# explicitly so the store can report "present, not parsed" instead of
# dropping them invisibly — which is how `zapprd.log` went unnoticed.
# Measured non-ZCC-format line counts across 12 bundles:
#
#   zapprd.log        4,237,679 lines / 251.7 MB — LWF NDIS driver trace
#                     from zapprd.sys, with ndisrd.c:<fn>:<line> source
#                     markers. This is the driver whose WFP sublayer
#                     collides with Defender ATP's SenseNdr, so it is
#                     the richest unexploited evidence in the bundle.
#   setupapi.dev.log     16.2 MB — Windows driver/device install history
#   AppInfo.log           7,456 lines — XML host state
#   profiles.log          3,590 lines — macOS configuration profiles
#   pf.log                  204 lines — macOS packet-filter ruleset
#   ZSAVersionHistory.txt    11 lines — TSV upgrade history
_FOREIGN_LOG_MARKERS: Dict[str, str] = {
    "zapprd": "LWF/NDIS driver trace (zapprd.sys) — binary framed",
    "setupapi.dev": "Windows driver + device install history",
    "AppInfo.log": "XML host state snapshot",
    "profiles.log": "macOS configuration profiles",
    "pf.log": "macOS packet-filter ruleset",
    "ZSAVersionHistory": "TSV ZCC version upgrade history",
    "installbuilder": "installer transcript",
    "gpo-result": "Group Policy resultant set",
}


def classify_foreign(basename: str) -> Optional[str]:
    """Name the non-ZCC-format evidence file, or None."""
    for marker, desc in _FOREIGN_LOG_MARKERS.items():
        if marker.lower() in basename.lower():
            return desc
    return None

# Deny-list, applied BEFORE the marker loop — so anything named here is
# unreachable no matter what `_COMPONENT_MARKERS` says.
#
# It used to hold ("ZSAHelper", "ZSAUpdater") on the grounds that they
# were "tiny helper files and updater history with no
# connection-relevant signal". Measured against 12 bundles, both claims
# were wrong: ZSAHelper is 4,932 ZCC-format lines across 442 files in 7
# bundles, and ZSAUpdater is 1,845 lines carrying the version-upgrade
# history — which is the first thing you want when the complaint is "it
# broke after an update". Both parse cleanly at 87% and 100%.
#
# Kept as a mechanism, deliberately empty. If something genuinely
# unparseable turns up, name it here AND say what was measured.
_SKIP_MARKERS: Tuple[str, ...] = ()

_MIN_LOG_BYTES = 200


def classify_component(basename: str) -> Optional[str]:
    """Return the component for a log filename, or None to skip it."""
    if _SKIP_MARKERS and any(m in basename for m in _SKIP_MARKERS):
        return None
    for component, markers in _COMPONENT_MARKERS:
        if any(m in basename for m in markers):
            return component
    return None


# --------------------------------------------------------------------
# ID grammar — slice 14
# --------------------------------------------------------------------
#
# Following an identifier used to mean a text scan of every line
# (`LIKE '%<value>%'` over 44 M rows). This table turns it into a JOIN:
# one row per (record, id_type, id_value).
#
# WHICH ids, and why these:
#   The set is taken from the corpus sweep in `learned.py` (46 bundles /
#   157,068,822 lines), preferring the identifiers with MEASURED joins —
#   cid<->lid 100%, mtunnel_id<->tag_id 100%, brk_code<->tag_id 86.7%,
#   device_id<->user 81.7%. `conn_id` as a *labelled* field is dead
#   (54 occurrences in 2 of 46 bundles), so the connection identifier
#   indexed here is the `ID=` field on ZTCP lines and the
#   `UDP Proxy: ID: N` field, which are present in 46/46 bundles. Both
#   feed the same `conn_id` id_type because they are the same thing.
#
# EXTRACTED FROM THE FULL RECORD, not `line.body`:
#   27% of physical lines are continuations (slice 13), and brokerName /
#   brokerIp / destinationIps / smeIp live only there. `_Ingestor` runs
#   these patterns over body + continuation.
#
# GATES:
#   Each regex is preceded by a cheap `substring in text.lower()` test.
#   Measured on 216,661 real records from bundle 05: 3.79 s ungated vs
#   1.28 s gated = 2.96x, which is the difference between +18% and +6%
#   on ingest. The same trick took the corpus miner from 22,912 to
#   52,959 lines/s.
#
#   A gate that is not a superset of what its regex can match silently
#   deletes evidence, so `check_id_gates()` exists to prove equivalence
#   and is part of the slice-14 verification. It caught a real bug on
#   first run: the `user` gates listed "username"/"user_name" but the
#   regex allows `user[ _]?name`, so 22 records spelling it "User Name"
#   were dropped. The fix was not a longer list of spellings — it was to
#   gate on the shortest literal the regex REQUIRES ("user", "tag",
#   "session"), which makes "gate fails => regex cannot match" checkable
#   by reading one line instead of by remembering every spelling. That
#   is also faster: 1.70 s -> 1.47 s over the same 216,661 records.
_ID_NOISE_VALUES = frozenset({
    "", "true", "false", "null", "none", "nil", "unknown", "n/a", "na",
})

#: (id_type, gate literals, regex, capture group). Order is fixed so the
#: rows written for a record are deterministic. Multi-gate specs come
#: LAST (only `user` is one) so the hot loop can run the single-gate
#: specs first without changing row order.
_ID_SPECS: List[Tuple[str, Tuple[str, ...], "re.Pattern", int]] = [
    # ---- ZPA session plumbing (mtunnel_id<->tag_id measured 100%) ----
    ("tag_id", ("tag",),
     re.compile(r"tag[ _]?id\s*[=:]\s*(\d+)", re.I), 1),
    ("mtunnel_id", ("mtunnel",),
     re.compile(r"mtunnel[ _]?id\s*[=:]\s*"
                r"([A-Za-z0-9+/=_-]+,[A-Za-z0-9+/=_-]+)", re.I), 1),
    # Symbolic outcome codes. Uppercase by construction in the log, so
    # the regex is case-SENSITIVE (a case-insensitive version matched
    # prose like "brk_code" in field names); the gate is lowercased and
    # therefore still a superset.
    ("brk_code", ("brk_",), re.compile(r"\bBRK_[A-Z0-9_]{4,}"), 0),
    ("zpn_code", ("zpn_",), re.compile(r"\bZPN_[A-Z0-9_]{4,}"), 0),
    ("zevent", ("zevent_",), re.compile(r"\bZEVENT_[A-Z0-9_]{4,}"), 0),
    # ---- ZDX probe record (cid<->lid measured 100% over 20 bundles) ---
    ("cid", ("cid",), re.compile(r"\bcid\s*[=:]\s*(-?\d+)", re.I), 1),
    ("lid", ("lid",), re.compile(r"\blid\s*[=:]\s*(-?\d+)", re.I), 1),
    # ---- connection identity ----
    # `ID=` on ZTCP lines: 46/46 bundles. Case-sensitive on purpose —
    # a case-insensitive `\bid=` also matches URL query parameters
    # (`?id=1234`), which are not connections. The `(?<![Pp]rocess )`
    # guard drops `process ID=<pid>` service-start lines (39 of them in
    # bundle 05), which are PIDs wearing the same label.
    ("conn_id", ("id=",),
     re.compile(r"(?<![Pp]rocess )\bID=(0x[0-9a-fA-F]+|\d+)"), 1),
    # UDP proxy uses the colon form. Anchored on the whole prefix so it
    # cannot pick up `Logon SID session ID: 1`.
    ("conn_id", ("udp",),
     re.compile(r"UDP Proxy:\s*ID:\s*(\d+)", re.I), 1),
    # A third spec for the LABELLED `conn_id=` field was written and then
    # deleted: `learned.ID_PREVALENCE` puts it at 54 occurrences in 2 of
    # 46 bundles, while its gate ("conn") fires on 4.4% of records
    # (9,512 of 216,661 in bundle 05). Paying a regex on one record in
    # 23 to find an identifier that is absent from 96% of bundles is the
    # wrong trade; `ID=` and `UDP Proxy: ID:` carry the real thing.
    # ---- ZIA / general ----
    ("session_id", ("session",),
     re.compile(r"session[ _]?id\s*[=:]\s*\"?([A-Za-z0-9+/=_.-]{2,})",
                re.I), 1),
    ("err_code", ("err",),
     re.compile(r"err[ _]?code\s*[=:]\s*\"?(-?\d+)", re.I), 1),
    ("app", ("app",),
     re.compile(r"app[ _]?name\"?\s*[:=]\s*\"?([A-Za-z0-9._*-]{2,})",
                re.I), 1),
    ("device_id", ("device",),
     re.compile(r"device[ _]?id\"?\s*[:=]\s*\"?(\d{4,})", re.I), 1),
    # Anchored hostnames only. A generic FQDN pattern was measured in
    # `id_inventory` to match every dotted token in every line
    # (versions, class names) and was removed there; repeating it here
    # would swamp the edge table.
    ("broker", ("broker",),
     re.compile(r"\b(broker[a-z0-9_-]*\.(?:[a-z0-9_-]+\.)*"
                r"(?:zpath|zscaler|zpalb|zpaservice)\.net)\b", re.I), 1),
    # Gated on ".zscaler", not "sme": the regex requires both, and "sme"
    # fires on 6.5% of records (smeIp, SME state prose) against 0.3% for
    # ".zscaler" — 14,072 wasted regex runs per 216,661 records, for
    # zero hits in bundle 05.
    ("sme_host", (".zscaler",),
     re.compile(r"\b(?:sme|(?:[a-z0-9_-]+[-_])?sme[-_][a-z0-9_-]+"
                r"|[a-z0-9_-]+[-_]sme[0-9]*)\.zscaler[a-z0-9]*\.net\b",
                re.I), 0),
    # ipv4's only cheap gate is "contains a dot", which still skips 77%
    # of records (measured: 48,804 of 216,661 in bundle 05). Dotted-quad
    # version numbers (`4.5.0.201`) match this pattern and are stored as
    # ipv4 rows; the store does NOT guess which dotted quad is an
    # address, because guessing is inference.
    ("ipv4", (".",),
     re.compile(r"\b((?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
                r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3})\b"), 1),
    # `text.count("-") >= 4` would be a tighter gate but costs a full
    # scan; "-" alone already skips 96% of records (7,851 of 216,661).
    ("guid", ("-",),
     re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), 0),
    # The one spec whose regex has no single required literal. Gates on
    # "name" (covers login_name / user_name) plus the three alternatives
    # that do not contain it. "name" + "for user" + "login_hint" + "upn"
    # fires on 4.9% of records where ("login","user") fired on 7.2%.
    ("user", ("name", "upn", "for user", "login_hint"),
     re.compile(r"(?:login[ _]?name|user[ _]?name|upn|for user|login_hint)"
                r"\"?\s*[=:]\s*\"?"
                r"([A-Za-z0-9._%+-]+(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,})?)",
                re.I), 1),
]

#: Every id_type the store can write, in spec order, de-duplicated.
ID_TYPES: Tuple[str, ...] = tuple(
    dict.fromkeys(t for t, _g, _r, _n in _ID_SPECS))

#: Values that are lower-cased before storage, so `BROKER7-2.CHI2...`
#: and `broker7-2.chi2...` are one identifier rather than two.
_ID_LOWERCASE_TYPES = frozenset({"broker", "sme_host", "guid"})

#: Per-record cap per id_type. The forwarding-filter table is one record
#: holding hundreds of rows (up to 4,000 continuation lines), so a single
#: record can legitimately carry thousands of IPs. Capped so one such
#: record cannot dominate the table; truncation is counted, never
#: silent — see `LogStore.id_values_truncated`.
_MAX_IDS_PER_TYPE_PER_RECORD = 256

# Hot-loop split. Measured over 216,661 records from bundle 05: testing
# every spec with `any(g in low for g in gates)` costs 0.81 s in gates
# alone, while testing the single-gate specs with a direct
# `if gate in low` costs 0.30 s — 2.7x, because the per-gate cost is
# Python generator overhead, not the C substring scan. Ingest runs
# 157 M records, so this is worth the two derived lists.
#
# The two per-match booleans are precomputed here rather than tested
# inside `_collect`: at 0.76 ID rows per line on a proxy-traffic bundle
# (measured, bundle 01) that inner loop runs ~460 k times per bundle,
# and `id_type == "user"` / `id_type in _ID_LOWERCASE_TYPES` are pure
# overhead there.
_ID_SPECS_SINGLE: List[Tuple[str, str, "re.Pattern", int, bool, bool]] = [
    (t, g[0], rx, n, t in _ID_LOWERCASE_TYPES, t == "user")
    for t, g, rx, n in _ID_SPECS if len(g) == 1]
_ID_SPECS_MULTI: List[
    Tuple[str, Tuple[str, ...], "re.Pattern", int, bool, bool]] = [
    (t, g, rx, n, t in _ID_LOWERCASE_TYPES, t == "user")
    for t, g, rx, n in _ID_SPECS if len(g) > 1]

#: Longest value in `_ID_NOISE_VALUES` ("unknown"). Anything longer
#: cannot be noise, so the per-match `val.lower()` is skipped.
_MAX_NOISE_LEN = max(len(v) for v in _ID_NOISE_VALUES)


def select_id_specs(id_types: Optional[Sequence[str]]):
    """Filter the spec lists to `id_types`, or return them unchanged.

    Exists because ingest cost is proportional to ID rows written, not
    to gate count: on bundle 01 `conn_id` and `ipv4` are 98% of the
    457,793 rows and 100% of the reason that build slows by 30%. A
    caller facing a 1.7 GB bundle can index the ZPA/ZDX join keys only.
    The default indexes everything, because a store that silently omits
    identifiers is worse than a slow one.
    """
    if not id_types:
        return _ID_SPECS_SINGLE, _ID_SPECS_MULTI
    wanted = set(id_types)
    unknown = wanted - set(ID_TYPES)
    if unknown:
        raise ValueError(f"unknown id_type(s): {sorted(unknown)}; "
                         f"known: {list(ID_TYPES)}")
    return ([s for s in _ID_SPECS_SINGLE if s[0] in wanted],
            [s for s in _ID_SPECS_MULTI if s[0] in wanted])


#: Sentinels for the lazy allocation in `extract_ids`. Never mutated —
#: the first hit replaces them with real containers.
_EMPTY_SEEN: set = set()
_EMPTY_PER_TYPE: dict = {}


def _collect(id_type: str, rx, grp: int, text: str,
             out: List[Tuple[str, str]], seen: set, per_type: dict,
             lower_val: bool, is_user: bool) -> None:
    """Run one spec's regex and append its normalised, de-duped values.

    `per_type` is a plain dict, not a Counter: this runs once per record
    per firing spec, and constructing a Counter costs more than the
    `.get()` it saves.
    """
    for m in rx.finditer(text):
        val = m.group(grp)
        if not val:
            continue
        if is_user and "%40" in val:
            # login_hint carries a URL-encoded address; decoding it here
            # is what makes it join to the labelled loginName.
            val = val.replace("%40", "@")
        if lower_val:
            val = val.lower()
        if len(val) <= _MAX_NOISE_LEN and val.lower() in _ID_NOISE_VALUES:
            continue
        key = (id_type, val)
        if key in seen:
            continue
        n = per_type.get(id_type, 0)
        if n >= _MAX_IDS_PER_TYPE_PER_RECORD:
            # STOP scanning, don't just skip: the cap exists for the
            # forwarding-filter table, whose single record can run to
            # 400 k characters. `continue` kept walking all of it to
            # throw the matches away.
            break
        seen.add(key)
        per_type[id_type] = n + 1
        out.append(key)


def extract_ids(text: str, single=None, multi=None) -> List[Tuple[str, str]]:
    """Every identifier in one record's full text, as (id_type, value).

    De-duplicated *within* the record: the same value repeated on one
    record carries no extra join information, and counting it twice
    would inflate `id_summary()` occurrences. This matches the
    per-line de-dupe `id_inventory.build_inventory` already does.

    `text` is expected to be `store.record_text(line)` — body plus
    continuation. `single` / `multi` override the spec lists (see
    `select_id_specs`); the defaults index everything.
    """
    low = text.lower()
    out: List[Tuple[str, str]] = []
    # `seen` / `per_type` are built lazily: roughly half of all records
    # fire no gate at all, and allocating two containers for them is
    # pure overhead at 157 M records.
    seen: set = _EMPTY_SEEN
    per_type: dict = _EMPTY_PER_TYPE
    for id_type, gate, rx, grp, low_v, is_u in (single or _ID_SPECS_SINGLE):
        if gate in low:
            if seen is _EMPTY_SEEN:
                seen, per_type = set(), {}
            _collect(id_type, rx, grp, text, out, seen, per_type, low_v, is_u)
    for id_type, gates, rx, grp, low_v, is_u in (multi or _ID_SPECS_MULTI):
        if any(g in low for g in gates):
            if seen is _EMPTY_SEEN:
                seen, per_type = set(), {}
            _collect(id_type, rx, grp, text, out, seen, per_type, low_v, is_u)
    return out


def _extract_ids_ungated(text: str) -> List[Tuple[str, str]]:
    """`extract_ids` with the substring gates removed.

    Exists solely so `check_id_gates` can prove the gates are
    equivalence-preserving on real data. Not used at ingest. Iterates in
    the same order as `extract_ids` (singles, then multis) so a
    difference in the result means a dropped value, not a reordering.
    """
    out: List[Tuple[str, str]] = []
    seen: set = set()
    per_type: dict = {}
    for id_type, _gate, rx, grp, low_v, is_u in _ID_SPECS_SINGLE:
        _collect(id_type, rx, grp, text, out, seen, per_type, low_v, is_u)
    for id_type, _gates, rx, grp, low_v, is_u in _ID_SPECS_MULTI:
        _collect(id_type, rx, grp, text, out, seen, per_type, low_v, is_u)
    return out


def check_id_gates(texts: Sequence[str]) -> Dict[str, object]:
    """Compare gated vs ungated extraction over real record text.

    Returns `{"records", "mismatches", "gated_seconds",
    "ungated_seconds", "examples"}`. `mismatches` must be 0: a non-zero
    count means some gate is not a superset of its regex and evidence is
    being dropped before anything downstream can see it.
    """
    seq = list(texts)
    n = 0
    mismatches = 0
    examples: List[Tuple[str, List[Tuple[str, str]]]] = []
    t0 = time.monotonic()
    gated = [extract_ids(t) for t in seq]
    t_gated = time.monotonic() - t0
    t0 = time.monotonic()
    ungated = [_extract_ids_ungated(t) for t in seq]
    t_ungated = time.monotonic() - t0
    for text, a, b in zip(seq, gated, ungated):
        n += 1
        if a != b:
            mismatches += 1
            if len(examples) < 5:
                missed = [x for x in b if x not in a]
                examples.append((text[:200], missed))
    return {
        "records": n,
        "mismatches": mismatches,
        "gated_seconds": round(t_gated, 3),
        "ungated_seconds": round(t_ungated, 3),
        "speedup": round(t_ungated / t_gated, 2) if t_gated else 0.0,
        "examples": examples,
    }


# --------------------------------------------------------------------
# Lazy sequence over the SQLite table
# --------------------------------------------------------------------

_ORDER = "ORDER BY ts, source_file, line_no"


def _row_to_line(r) -> IndexedLine:
    return IndexedLine(
        ts=datetime.fromtimestamp(r[0], tz=timezone.utc),
        pid=r[1] or "",
        tid=r[2] or "",
        level=r[3] or "",
        body=r[4] or "",
        component=r[5] or "",
        source_file=r[6] or "",
        line_no=r[7] or 0,
        session_id=r[8],
        host=r[9],
    )


_COLS = "ts,pid,tid,level,body,component,source_file,line_no,session_id,host"

# Same columns, qualified. Needed by any query that joins `lines` to
# `line_ids` / `line_cont`, because `source_file` and `line_no` exist on
# both sides and SQLite rejects the ambiguous reference.
_COLS_Q = ",".join(f"lines.{c}" for c in _COLS.split(","))
_ORDER_Q = "ORDER BY lines.ts, lines.source_file, lines.line_no"


class LineSequence(Sequence):
    """Read-only, lazily-evaluated view of the stored lines in
    chronological order.

    Implements enough of the sequence protocol that existing consumers
    need no changes: `len()`, `seq[i]` (including negatives), `seq[a:b]`,
    `seq[::step]`, and plain iteration. Iteration streams from a server-
    side cursor, so walking 44 M lines never materialises them all.
    """

    def __init__(self, store: "LogStore"):
        self._store = store

    # ---- size ----
    def __len__(self) -> int:
        return self._store.total_lines

    # ---- iteration (streaming) ----
    def __iter__(self) -> Iterator[IndexedLine]:
        cur = self._store._conn.execute(f"SELECT {_COLS} FROM lines {_ORDER}")
        while True:
            rows = cur.fetchmany(20_000)
            if not rows:
                break
            for r in rows:
                yield _row_to_line(r)

    # ---- indexing ----
    def __getitem__(self, key):
        n = len(self)
        if isinstance(key, int):
            i = key + n if key < 0 else key
            if i < 0 or i >= n:
                raise IndexError("line index out of range")
            cur = self._store._conn.execute(
                f"SELECT {_COLS} FROM lines {_ORDER} LIMIT 1 OFFSET ?", (i,)
            )
            row = cur.fetchone()
            if row is None:
                raise IndexError("line index out of range")
            return _row_to_line(row)

        if isinstance(key, slice):
            start, stop, step = key.indices(n)
            if step == 1:
                if stop <= start:
                    return []
                cur = self._store._conn.execute(
                    f"SELECT {_COLS} FROM lines {_ORDER} LIMIT ? OFFSET ?",
                    (stop - start, start),
                )
                return [_row_to_line(r) for r in cur.fetchall()]
            # Strided slice — stream and keep every step'th row rather
            # than issuing one query per index.
            out: List[IndexedLine] = []
            cur = self._store._conn.execute(
                f"SELECT {_COLS} FROM lines {_ORDER} LIMIT ? OFFSET ?",
                (max(0, stop - start), start),
            )
            for offset, r in enumerate(cur):
                if offset % step == 0:
                    out.append(_row_to_line(r))
            return out

        raise TypeError(f"line indices must be int or slice, not "
                        f"{type(key).__name__}")


class _LazyGroup:
    """Dict-like accessor over a grouping column.

    `LogIndex` eagerly built `by_session_id` / `by_host` dicts. At corpus
    scale that is a second full copy of the data, so these are answered
    by query instead. Only the operations the codebase actually uses are
    supported — `len()`, `[key]`, `get()`, `in`, and `keys()`.
    """

    def __init__(self, store: "LogStore", column: str):
        self._store = store
        self._col = column

    def __len__(self) -> int:
        cur = self._store._conn.execute(
            f"SELECT COUNT(DISTINCT {self._col}) FROM lines "
            f"WHERE {self._col} IS NOT NULL AND {self._col} != ''"
        )
        return int(cur.fetchone()[0] or 0)

    def __getitem__(self, key) -> List[IndexedLine]:
        cur = self._store._conn.execute(
            f"SELECT {_COLS} FROM lines WHERE {self._col} = ? {_ORDER}",
            (key,),
        )
        return [_row_to_line(r) for r in cur.fetchall()]

    def get(self, key, default=None):
        rows = self[key]
        return rows if rows else (default if default is not None else [])

    def __contains__(self, key) -> bool:
        cur = self._store._conn.execute(
            f"SELECT 1 FROM lines WHERE {self._col} = ? LIMIT 1", (key,)
        )
        return cur.fetchone() is not None

    def keys(self) -> List[str]:
        cur = self._store._conn.execute(
            f"SELECT DISTINCT {self._col} FROM lines "
            f"WHERE {self._col} IS NOT NULL AND {self._col} != ''"
        )
        return [r[0] for r in cur.fetchall()]


# --------------------------------------------------------------------
# The store
# --------------------------------------------------------------------

class LogStore:
    """SQLite-backed replacement for `LogIndex`."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=OFF")
        self._conn.execute("PRAGMA synchronous=OFF")
        # Memory pragmas deliberately modest. The first cut used
        # `temp_store=MEMORY` with a 64 MB page cache, and peak RSS hit
        # ~950 MB during index creation on a 13.5 M-row load — on a
        # 3.9 GB box that is the next thing to fall over. Ingest itself
        # is flat at ~94 MB; it was the pragmas, not the streaming, that
        # cost the memory. Spilling temp b-trees to disk trades a little
        # index-build time for a bounded footprint.
        self._conn.execute("PRAGMA cache_size=-16384")   # ~16 MB
        self._conn.execute("PRAGMA temp_store=FILE")

        _LIVE_STORES.append(self)

        self.lines = LineSequence(self)
        self.by_session_id = _LazyGroup(self, "session_id")
        self.by_host = _LazyGroup(self, "host")

        # Counters, mirroring LogIndex plus the rotation accounting.
        self.total_lines = 0
        self.build_seconds = 0.0
        self.bytes_scanned = 0
        self.files_scanned = 0
        self.lines_skipped_unparseable = 0
        self.bundle_tz_offset: Optional[str] = None
        self.bundle_tz_label: Optional[str] = None
        self.rotations_found = 0
        self.rotations_read = 0
        self.plain_logs_read = 0
        self.archives_unreadable: List[str] = []
        self.estimated_db_bytes = 0
        # Per-component unparseable counts.
        #
        # These exist because a single global counter hid something. The
        # rotations initially appeared to skip ~10% of lines against ~1%
        # for plain logs, which looked like either a different line
        # format in older rotations or a parse regression on rotated
        # content — two very different problems.
        #
        # Split per component, the answer was immediate and benign:
        # tray and upm skip 0.0%, tunnel skips ~6%, and every rejected
        # tunnel line is a *continuation* of a multi-line record — the
        # pretty-printed App-Profile / PAC-policy JSON blobs that
        # ZSATunnel dumps across many physical lines. Zero timestamped
        # lines are lost. Tunnel is the only component that emits those
        # blobs, which is exactly why it alone shows a spike.
        #
        # As of slice 13 those blobs are no longer discarded: they are
        # attached to their owning record (see `_INSERT_CONT`). The
        # counters below therefore now mean something narrower than they
        # used to — `lines_skipped_unparseable` counts only genuinely
        # ORPHANED lines, ones with no owning record ahead of them in the
        # file. A continuation line is captured, not skipped.
        self.skipped_by_component: Counter = Counter()
        self.skipped_by_file: Counter = Counter()
        self.read_by_component: Counter = Counter()

        # Record-assembly accounting (slice 13).
        self.records_with_continuation = 0
        self.continuation_lines_attached = 0
        self.continuation_truncated_records = 0
        self.lines_orphan_unparseable = 0

        # ID-edge accounting (slice 14). `id_edges_written` is rows in
        # `line_ids`; `id_values_truncated` is records where one id_type
        # exceeded `_MAX_IDS_PER_TYPE_PER_RECORD` — non-zero means some
        # values from those records are not in the table, and the number
        # is reported rather than hidden.
        self.id_edges_written = 0
        self.id_values_truncated = 0
        self.ids_indexed = True
        self.id_types_indexed: Tuple[str, ...] = ()

        # Source-file labelling (slice 15 fix).
        #
        # `source_file` was the bare basename, and (source_file, line_no)
        # is the address every other table joins on — `line_cont`,
        # `line_ids`, `surrounding_lines`. That address is only unique if
        # basenames are. MEASURED on bundle 21: 169,912 lines share an
        # address with another line, because the bundle contains
        # `ZSATunnel_2026-05-18-12-33-10.597703.log.zip` AND an extracted
        # copy of the same log. Nested bundles inside HubSpot exports do
        # the same thing (one in the corpus held seven).
        #
        # The consequence was silent and wrong: `record_text()` could
        # return another file's continuation, and `lines_for_id()` could
        # return another file's lines. Duplicated basenames now get a
        # `#2`, `#3` suffix; both copies are still read (dropping one
        # would be inventing a de-duplication policy), and
        # `source_paths` says which file on disk each label came from.
        self.duplicate_source_files = 0
        self.source_paths: Dict[str, str] = {}

        # Evidence present in the bundle that this store does NOT parse.
        # Surfaced rather than dropped, so "we didn't look" is never
        # mistaken for "there was nothing there".
        self.foreign_files: Dict[str, str] = {}
        self.foreign_bytes = 0
        self.unclassified_files: Dict[str, int] = {}

    # ---- lifecycle ----
    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    def cleanup(self) -> None:
        """Close the connection and delete the backing file.

        Also registered with `atexit`, so a crash or SIGTERM doesn't
        strand a multi-gigabyte temp DB.
        """
        self.close()
        try:
            if self.db_path and os.path.exists(self.db_path):
                os.unlink(self.db_path)
        except OSError:
            pass
        try:
            _LIVE_STORES.remove(self)
        except ValueError:
            pass

    # Usable as a context manager so callers get deterministic cleanup.
    def __enter__(self) -> "LogStore":
        return self

    def __exit__(self, *_exc) -> None:
        self.cleanup()

    def skip_report(self, top: int = 10) -> Dict[str, object]:
        """Unparseable-line accounting, split so a format change in one
        component or one rotation is visible rather than averaged away."""
        total_seen = self.total_lines + self.lines_skipped_unparseable
        return {
            "skipped_total": self.lines_skipped_unparseable,
            "skipped_pct": (100.0 * self.lines_skipped_unparseable
                            / total_seen) if total_seen else 0.0,
            "by_component": {
                c: {
                    "skipped": self.skipped_by_component.get(c, 0),
                    "read": self.read_by_component.get(c, 0),
                    "pct": (100.0 * self.skipped_by_component.get(c, 0)
                            / (self.skipped_by_component.get(c, 0)
                               + self.read_by_component.get(c, 0)))
                    if (self.skipped_by_component.get(c, 0)
                        + self.read_by_component.get(c, 0)) else 0.0,
                }
                for c in set(list(self.skipped_by_component)
                             + list(self.read_by_component))
            },
            "worst_files": self.skipped_by_file.most_common(top),
        }

    # ---- query surface used across the app ----
    def search(self, query: str) -> Iterator[IndexedLine]:
        """Case-insensitive substring scan over line bodies.

        Runs inside SQLite, so it no longer builds a Python object per
        candidate line just to test it.
        """
        like = f"%{query}%"
        cur = self._conn.execute(
            f"SELECT {_COLS} FROM lines WHERE body LIKE ? COLLATE NOCASE "
            f"{_ORDER}", (like,),
        )
        while True:
            rows = cur.fetchmany(5_000)
            if not rows:
                break
            for r in rows:
                yield _row_to_line(r)

    def time_window(self, start: datetime, end: datetime
                    ) -> Iterator[IndexedLine]:
        cur = self._conn.execute(
            f"SELECT {_COLS} FROM lines WHERE ts BETWEEN ? AND ? {_ORDER}",
            (start.timestamp(), end.timestamp()),
        )
        while True:
            rows = cur.fetchmany(5_000)
            if not rows:
                break
            for r in rows:
                yield _row_to_line(r)

    # ---- records (slice 13) ----
    def continuation(self, line: IndexedLine) -> str:
        """The continuation text owned by `line`, or "" if none.

        Continuation lines are the untimestamped remainder of a
        multi-line record — pretty-printed JSON, the forwarding-filter
        table, PAC bodies. They are addressed by (source_file, line_no)
        because that is the store's existing line address and is already
        covered by `ix_file`.
        """
        if not line.source_file or line.line_no is None:
            return ""
        row = self._conn.execute(
            "SELECT cont FROM line_cont WHERE source_file = ? "
            "AND line_no = ?", (line.source_file, line.line_no),
        ).fetchone()
        return row[0] if row else ""

    def record_text(self, line: IndexedLine) -> str:
        """`line.body` plus its continuation, as one searchable string.

        This is what a field extractor should read. Reading `.body`
        alone is why `brokerName`, `destinationIps`, `dnsTime` and
        friends were invisible for so long.
        """
        cont = self.continuation(line)
        return f"{line.body}\n{cont}" if cont else line.body

    def search_records(self, query: str) -> Iterator[IndexedLine]:
        """Like `search`, but also matches inside continuation text.

        Returns the owning line, so a hit inside a JSON blob is
        attributable to a timestamp. Kept separate from `search` rather
        than folded into it: `search` is the hot path for the Search tab
        and this one has to consult a second table.
        """
        like = f"%{query}%"
        cur = self._conn.execute(
            f"SELECT {_COLS} FROM lines WHERE body LIKE ? COLLATE NOCASE "
            f"OR EXISTS (SELECT 1 FROM line_cont c "
            f"           WHERE c.source_file = lines.source_file "
            f"             AND c.line_no = lines.line_no "
            f"             AND c.cont LIKE ? COLLATE NOCASE) {_ORDER}",
            (like, like),
        )
        while True:
            rows = cur.fetchmany(2_000)
            if not rows:
                break
            for r in rows:
                yield _row_to_line(r)

    # ---- ID edges (slice 14) ----
    #
    # Every method here is a JOIN against `line_ids`, which is why the
    # table exists: "show me every line that mentions this tag_id" used
    # to be `LIKE '%<value>%'` over the whole bundle.
    def ids_for_line(self, line: IndexedLine) -> List[Tuple[str, str]]:
        """Every (id_type, id_value) extracted from `line`'s record.

        "Record", not "line" — the values may have come from the
        continuation block attached to it.
        """
        if not line.source_file or line.line_no is None:
            return []
        cur = self._conn.execute(
            "SELECT id_type, id_value FROM line_ids WHERE source_file = ? "
            "AND line_no = ? ORDER BY id_type, id_value",
            (line.source_file, line.line_no),
        )
        return [(r[0], r[1]) for r in cur.fetchall()]

    def lines_for_id(self, id_type: str, id_value: str,
                     limit: Optional[int] = None) -> List[IndexedLine]:
        """Every line whose record carries this identifier, oldest first.

        Returns a list rather than an iterator because the caller is
        almost always rendering a session; use `limit` on the pathological
        values (a busy `ipv4`, or `conn_id` after ID reuse).
        """
        sql = (f"SELECT {_COLS_Q} FROM lines "
               f"JOIN line_ids e ON e.source_file = lines.source_file "
               f"AND e.line_no = lines.line_no "
               f"WHERE e.id_type = ? AND e.id_value = ? {_ORDER_Q}")
        params: Tuple = (id_type, id_value)
        if limit:
            sql += " LIMIT ?"
            params = (id_type, id_value, int(limit))
        return [_row_to_line(r) for r in self._conn.execute(sql, params)]

    def id_summary(self) -> Dict[str, Dict[str, int]]:
        """Per id_type: `occurrences` (records carrying it) and
        `distinct` (distinct values).

        `occurrences` counts RECORDS, not textual hits — `extract_ids`
        de-dupes within a record, so a line repeating the same tag_id
        four times contributes one.
        """
        cur = self._conn.execute(
            "SELECT id_type, COUNT(*), COUNT(DISTINCT id_value) "
            "FROM line_ids GROUP BY id_type ORDER BY id_type"
        )
        return {r[0]: {"occurrences": r[1], "distinct": r[2]}
                for r in cur.fetchall()}

    def id_values(self, id_type: str, limit: int = 100
                  ) -> List[Tuple[str, int]]:
        """The most-carried values for one id_type, as (value, records).

        The drill-down list for a UI that must never render every value
        of `ipv4`.
        """
        cur = self._conn.execute(
            "SELECT id_value, COUNT(*) c FROM line_ids WHERE id_type = ? "
            "GROUP BY id_value ORDER BY c DESC, id_value LIMIT ?",
            (id_type, int(limit)),
        )
        return [(r[0], r[1]) for r in cur.fetchall()]

    def related_ids(self, id_type: str, id_value: str,
                    limit_per_type: int = 50,
                    ) -> Dict[str, List[Tuple[str, int]]]:
        """Identifiers co-occurring on the same records as this one.

        `{other_type: [(value, shared_records), ...]}`, each list sorted
        by shared-record count descending. This is co-occurrence and
        nothing more — it is NOT a claim that the two identify the same
        thing. `learned.FALSE_JOINS` records pairs with high raw
        co-occurrence and no real relationship (fqdn<->ipv4 20.9%,
        ipv4<->session_id 0.4%), so a caller comparing shared-record
        counts against the total record count for each value is doing
        the right thing and a caller treating one shared record as a
        join is not.
        """
        cur = self._conn.execute(
            "SELECT b.id_type, b.id_value, COUNT(*) c FROM line_ids a "
            "JOIN line_ids b ON b.source_file = a.source_file "
            "AND b.line_no = a.line_no "
            "WHERE a.id_type = ? AND a.id_value = ? "
            "AND NOT (b.id_type = a.id_type AND b.id_value = a.id_value) "
            "GROUP BY b.id_type, b.id_value ORDER BY b.id_type, c DESC, "
            "b.id_value",
            (id_type, id_value),
        )
        out: Dict[str, List[Tuple[str, int]]] = {}
        for r in cur.fetchall():
            bucket = out.setdefault(r[0], [])
            if len(bucket) < limit_per_type:
                bucket.append((r[1], r[2]))
        return out

    def continuation_report(self) -> dict:
        """How much of this bundle lives in continuation blocks."""
        row = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(cont_lines),0), "
            "COALESCE(SUM(LENGTH(cont)),0) FROM line_cont"
        ).fetchone()
        recs, cont_lines, cont_chars = row or (0, 0, 0)
        total = self.total_lines + cont_lines
        return {
            "records_with_continuation": recs,
            "continuation_lines": cont_lines,
            "continuation_chars": cont_chars,
            "truncated_records": self.continuation_truncated_records,
            "orphan_unparseable": self.lines_orphan_unparseable,
            "pct_of_physical": (
                round(100.0 * cont_lines / total, 2) if total else 0.0),
        }

    def surrounding_lines(self, source_file: str, line_no: int,
                          radius: int = 5) -> List[IndexedLine]:
        if not source_file or line_no is None:
            return []
        cur = self._conn.execute(
            f"SELECT {_COLS} FROM lines WHERE source_file = ? "
            f"AND line_no BETWEEN ? AND ? ORDER BY line_no",
            (source_file, line_no - radius, line_no + radius),
        )
        return [_row_to_line(r) for r in cur.fetchall()]

    def lines_for_file(self, source_file: str) -> List[IndexedLine]:
        cur = self._conn.execute(
            f"SELECT {_COLS} FROM lines WHERE source_file = ? ORDER BY line_no",
            (source_file,),
        )
        return [_row_to_line(r) for r in cur.fetchall()]

    def source_files(self) -> List[Tuple[str, int]]:
        cur = self._conn.execute(
            "SELECT source_file, COUNT(*) FROM lines GROUP BY source_file "
            "ORDER BY source_file"
        )
        return [(r[0], r[1]) for r in cur.fetchall()]

    def component_file_bounds(
        self, component: str
    ) -> List[Tuple[str, int, float, float]]:
        """``[(source_file, records, first_ts, last_ts), ...]`` for one component.

        One aggregate query rather than a probe per file. Needed to answer
        "which of these is the *current* log?" — file labels are deduplicated
        (``ZSATunnel.log``, ``ZSATunnel.log#2``, ...) and a rotation can carry
        the same basename as the live file, so the newest last-record time is
        the only reliable discriminator.
        """
        cur = self._conn.execute(
            "SELECT source_file, COUNT(*), MIN(ts), MAX(ts) FROM lines "
            "WHERE component = ? GROUP BY source_file",
            (component,),
        )
        return [(r[0], int(r[1]), float(r[2] or 0.0), float(r[3] or 0.0))
                for r in cur.fetchall()]

    def count_by(self, column: str) -> Dict[str, int]:
        cur = self._conn.execute(
            f"SELECT {column}, COUNT(*) FROM lines GROUP BY {column}"
        )
        return {(r[0] or ""): r[1] for r in cur.fetchall()}

    def distinct(self, column: str) -> List[str]:
        cur = self._conn.execute(
            f"SELECT DISTINCT {column} FROM lines "
            f"WHERE {column} IS NOT NULL AND {column} != '' ORDER BY {column}"
        )
        return [r[0] for r in cur.fetchall()]


# --------------------------------------------------------------------
# Builder
# --------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE lines (
    ts REAL NOT NULL,
    pid TEXT, tid TEXT, level TEXT,
    body TEXT,
    component TEXT,
    source_file TEXT,
    line_no INTEGER,
    session_id TEXT,
    host TEXT
);
CREATE TABLE line_cont (
    source_file TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    cont TEXT NOT NULL,
    cont_lines INTEGER NOT NULL
);
CREATE TABLE line_ids (
    source_file TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    id_type TEXT NOT NULL,
    id_value TEXT NOT NULL
);
"""

_INSERT = ("INSERT INTO lines "
           "(ts,pid,tid,level,body,component,source_file,line_no,"
           "session_id,host) VALUES (?,?,?,?,?,?,?,?,?,?)")

# Slice 13 — record assembly.
#
# 27% of physical lines in the corpus (59,339,178 of 219,677,837) carry
# no timestamp. They are not junk: they are continuation lines of the
# preceding timestamped line's multi-line JSON, and they are the ONLY
# place these fields appear —
#
#   brokerIp  brokerName  brokerType  destinationIps  destPorts
#   dnsTime   pacParseTime  smeIp  smePort  nwType  requestType
#   resolvedIp  bypassReason  zpaAuthState  systemProxyHost/Port
#
# each ~1,061,017 occurrences across 41/46 bundles. Treating a line as
# the unit of analysis made every one of them invisible.
#
# Continuation text lives in its own table rather than as a column on
# `lines`, for two reasons: the `lines` row shape stays byte-identical
# so `_COLS`, `_row_to_line` and every downstream consumer are
# untouched, and the common case (a record with no continuation) costs
# nothing. Keyed on (source_file, line_no) because that is already the
# store's addressing scheme — `surrounding_lines` uses it and `ix_file`
# already indexes it, so no new dataclass field and no new index.
_INSERT_CONT = ("INSERT INTO line_cont "
                "(source_file,line_no,cont,cont_lines) VALUES (?,?,?,?)")

# Slice 14 — ID edges. Written from the same `_close_record()` hook as
# the continuation text, because that is the only moment the FULL record
# (body + every continuation line) is known. Extracting at line-append
# time would have re-created exactly the bug slice 13 fixed: every
# brokerName / destinationIps / smeIp value invisible.
#
# Addressed by (source_file, line_no) like `line_cont`, so a row joins
# straight back to `lines` with no new column on the hot table and no
# new dataclass field.
_INSERT_ID = ("INSERT INTO line_ids "
              "(source_file,line_no,id_type,id_value) VALUES (?,?,?,?)")

#: Per-record continuation caps. The forwarding-filter table dumps
#: hundreds of rows into one record, so these are generous; they exist
#: only to bound a pathological file.
_MAX_CONT_LINES = 4_000
_MAX_CONT_CHARS = 400_000

_BATCH = 20_000


def _tz_from_match(m) -> Tuple[Optional[str], Optional[str]]:
    raw = m.group("tz") or ""
    if raw.startswith("(") and raw.endswith(")"):
        raw = raw[1:-1]
    raw = raw.replace(":", "")
    if not raw:
        return (None, None)
    sign = raw[0]
    try:
        hh, mm = int(raw[1:3]), int(raw[3:5])
        return (raw, f"UTC{sign}{hh:02d}:{mm:02d}")
    except (ValueError, IndexError):
        return (raw, f"UTC{raw}")


class _Ingestor:
    """Accumulates parsed rows and flushes them in batches."""

    def __init__(self, store: LogStore, index_ids: bool = True,
                 id_types: Optional[Sequence[str]] = None):
        self.store = store
        self.index_ids = index_ids
        self._id_single, self._id_multi = select_id_specs(id_types)
        self.batch: List[tuple] = []
        self.cont_batch: List[tuple] = []
        self.id_batch: List[tuple] = []
        #: Record currently open for continuation lines to attach to.
        self._owner: Optional[Tuple[str, int]] = None
        #: Its body, kept so ID extraction can see the WHOLE record.
        self._owner_body: str = ""
        self._cont: List[str] = []
        self._cont_chars = 0
        self._cont_dropped = False

    # -- record assembly ----------------------------------------------
    def _close_record(self) -> None:
        """Finish the open record: attach continuation text, index IDs."""
        if self._owner is not None:
            src, ln = self._owner
            cont = "\n".join(self._cont) if self._cont else ""
            if cont:
                self.cont_batch.append((src, ln, cont, len(self._cont)))
                self.store.records_with_continuation += 1
                self.store.continuation_lines_attached += len(self._cont)
                if self._cont_dropped:
                    self.store.continuation_truncated_records += 1
            if self.index_ids:
                text = f"{self._owner_body}\n{cont}" if cont \
                    else self._owner_body
                ids = extract_ids(text, self._id_single, self._id_multi)
                if ids:
                    for id_type, val in ids:
                        self.id_batch.append((src, ln, id_type, val))
                    self.store.id_edges_written += len(ids)
                    # Only a record that hit the per-type cap can have
                    # been truncated, so this Counter runs on the rare
                    # forwarding-filter-table-sized record, not on all
                    # 157 M of them.
                    if len(ids) >= _MAX_IDS_PER_TYPE_PER_RECORD:
                        per = Counter(t for t, _v in ids)
                        if max(per.values()) >= _MAX_IDS_PER_TYPE_PER_RECORD:
                            self.store.id_values_truncated += 1
        self._owner = None
        self._owner_body = ""
        self._cont = []
        self._cont_chars = 0
        self._cont_dropped = False

    def feed(self, text_iter, basename: str, component: str) -> None:
        st = self.store
        for line_no, raw in enumerate(text_iter, start=1):
            m = _LINE_RE.match(raw)
            if not m:
                # No timestamp. If a record is open this is one of its
                # continuation lines, not a parse failure — the old code
                # counted it as "skipped", which is why the reported skip
                # rate looked like data loss when it was mostly
                # multi-line JSON.
                stripped = raw.strip()
                if not stripped:
                    continue
                if self._owner is not None:
                    if (len(self._cont) < _MAX_CONT_LINES
                            and self._cont_chars < _MAX_CONT_CHARS):
                        self._cont.append(stripped)
                        self._cont_chars += len(stripped) + 1
                    else:
                        self._cont_dropped = True
                    continue
                # Genuinely orphaned: no owning record yet in this file.
                st.lines_orphan_unparseable += 1
                st.lines_skipped_unparseable += 1
                st.skipped_by_component[component] += 1
                st.skipped_by_file[basename] += 1
                continue
            try:
                ts = datetime.strptime(
                    m.group("ts"), "%Y-%m-%d %H:%M:%S.%f",
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                st.lines_skipped_unparseable += 1
                st.skipped_by_component[component] += 1
                st.skipped_by_file[basename] += 1
                continue
            # A new timestamped line ends the previous record.
            self._close_record()
            if st.bundle_tz_offset is None:
                off, label = _tz_from_match(m)
                if off:
                    st.bundle_tz_offset, st.bundle_tz_label = off, label
            body = m.group("body")
            self.batch.append((
                ts.timestamp(), m.group("pid"), m.group("tid"),
                m.group("level"), body, component, basename, line_no,
                _extract_session_id(body), _extract_host(body),
            ))
            self._owner = (basename, line_no)
            self._owner_body = body
            st.total_lines += 1
            st.read_by_component[component] += 1
            if len(self.batch) >= _BATCH:
                self.flush()
        # Continuation blocks never span files.
        self._close_record()
        self.flush()

    def flush(self) -> None:
        if self.batch:
            self.store._conn.executemany(_INSERT, self.batch)
            self.batch.clear()
        if self.cont_batch:
            self.store._conn.executemany(_INSERT_CONT, self.cont_batch)
            self.cont_batch.clear()
        if self.id_batch:
            self.store._conn.executemany(_INSERT_ID, self.id_batch)
            self.id_batch.clear()


def _iter_candidates(bundle_root: str):
    """Yield `(kind, path, basename, size)` for everything worth reading.

    `kind` is "plain" for a `.log` file or "zip" for a `.log.zip`
    rotation. Nested plain zips that themselves contain logs are also
    reported so the caller can recurse into them.
    """
    for dirpath, _dirs, files in os.walk(bundle_root):
        for fn in files:
            path = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            low = fn.lower()
            if low.endswith(".log.zip"):
                yield ("zip", path, fn, size)
            elif low.endswith(".log"):
                if size < _MIN_LOG_BYTES:
                    continue
                yield ("plain", path, fn, size)
            elif low.endswith(".zip"):
                yield ("archive", path, fn, size)
            elif low.endswith((".7z", ".rar")):
                yield ("unsupported", path, fn, size)


# Bytes of SQLite per byte of source log text.
#
# MEASURED, and the first value here was wrong in the dangerous
# direction. It was set to 0.95 from a back-of-envelope on total log
# text, but a controlled run gave 255 MB of database from 104 MB of
# estimated source — a ratio of **2.45**. At 0.95 the preflight reserved
# 1.6 GB for a bundle that needs ~4.1 GB, so the guard cheerfully waved
# through the exact build that then died disk-full. An estimator that
# under-predicts is worse than no estimator, because it converts a clear
# refusal into a late crash.
#
# 2.6 was the measured 2.45 plus headroom. Over-reserving costs a caller
# an occasional unnecessary refusal, which they can override with
# db_dir= or a rotation cap; under-reserving costs them a 4-minute build
# that fails at minute 3 and leaves a multi-gigabyte orphan.
#
# RAISED to 3.4 for slice 14, because the `line_ids` table pushed the
# measured ratio past the old value on all three bundles measured:
#
#              ids OFF   ids ON
#   bundle 05    2.26     2.67
#   bundle 01    1.99     2.68
#   bundle 21    2.29     2.93   <-- worst, 0.53 ID rows per line
#
# Leaving it at 2.6 would have reproduced the original failure exactly:
# a preflight that waves through a build it cannot fit. 3.4 is the
# measured worst case (2.93) plus the same kind of headroom.
_DB_BYTES_PER_SOURCE_BYTE = 3.4
# Refuse to start unless this much slack remains beyond the estimate.
_FREE_SPACE_MARGIN = 512 * 1024 * 1024


def estimate_source_bytes(bundle_root: str,
                          read_rotations: bool = True,
                          max_rotations_per_component: Optional[int] = None
                          ) -> Tuple[int, int, int]:
    """Return `(uncompressed_log_bytes, plain_files, rotation_files)`.

    Rotation sizes come from the zip central directory (`file_size`), so
    this is the real uncompressed figure rather than a compression-ratio
    guess — and it costs only a directory read per archive.
    """
    plain_bytes = 0
    plain_n = 0
    rot_bytes_by_comp: Dict[str, List[Tuple[str, int]]] = {}

    for kind, path, fn, size in _iter_candidates(bundle_root):
        comp = classify_component(fn)
        if comp is None:
            continue
        if kind == "plain":
            plain_bytes += size
            plain_n += 1
        elif kind == "zip" and read_rotations:
            try:
                with zipfile.ZipFile(path) as zf:
                    inner = sum(i.file_size for i in zf.infolist()
                                if i.filename.lower().endswith(".log"))
            except (zipfile.BadZipFile, OSError, RuntimeError):
                continue
            rot_bytes_by_comp.setdefault(comp, []).append((fn, inner))

    rot_bytes = 0
    rot_n = 0
    for comp, entries in rot_bytes_by_comp.items():
        entries.sort(key=lambda t: t[0], reverse=True)
        if max_rotations_per_component:
            entries = entries[:max_rotations_per_component]
        rot_bytes += sum(b for _f, b in entries)
        rot_n += len(entries)

    return (plain_bytes + rot_bytes, plain_n, rot_n)


def _free_bytes(path: str) -> Optional[int]:
    try:
        os.makedirs(path, exist_ok=True)
        return shutil.disk_usage(path).free
    except OSError:
        return None


def _pick_db_dir(preferred: Optional[str], needed: int) -> str:
    """Choose a writable directory with room for `needed` bytes.

    **An explicit `preferred` wins whenever it has room.** The first cut
    returned whichever candidate had the most free space, which meant a
    caller who pointed at a specific volume — usually for a good reason,
    like "this is the only disk with 50 GB" — could be silently
    redirected to the temp dir. Honouring the request unless it
    genuinely cannot fit is both less surprising and what the parameter
    name promises.

    Raises `InsufficientDiskSpace` with concrete numbers if nothing
    qualifies — before a single row is written.
    """
    need_total = needed + _FREE_SPACE_MARGIN
    report: List[str] = []

    if preferred:
        free = _free_bytes(preferred)
        if free is not None:
            report.append(f"{preferred} has {free / 1e9:.1f} GB free")
            if free >= need_total:
                return preferred

    fallback = tempfile.gettempdir()
    if fallback and fallback != preferred:
        free = _free_bytes(fallback)
        if free is not None:
            report.append(f"{fallback} has {free / 1e9:.1f} GB free")
            if free >= need_total:
                return fallback

    if not report:
        raise InsufficientDiskSpace(
            f"No writable directory found for the line database (tried: "
            f"{[d for d in (preferred, fallback) if d]})."
        )
    raise InsufficientDiskSpace(
        f"Indexing this bundle needs about {needed / 1e9:.1f} GB for the "
        f"line database plus {_FREE_SPACE_MARGIN / 1e9:.1f} GB working "
        f"margin ({need_total / 1e9:.1f} GB total), but "
        f"{'; '.join(report)}. Either free space, pass "
        f"db_dir=<somewhere roomier>, or reduce the read with "
        f"max_rotations_per_component=N / read_rotations=False."
    )


def build_store(bundle_root: str,
                max_rotations_per_component: Optional[int] = None,
                db_path: Optional[str] = None,
                db_dir: Optional[str] = None,
                read_rotations: bool = True,
                preflight: bool = True,
                index_ids: bool = True,
                id_types: Optional[Sequence[str]] = None) -> LogStore:
    """Index every readable log line under `bundle_root` into SQLite.

    `max_rotations_per_component` caps how many `.log.zip` rotations are
    read per component, newest-first by filename (ZCC embeds the start
    timestamp, so filename order is chronological). `None` reads them
    all — the point of the SQLite backing.

    `read_rotations=False` reproduces the old plain-`.log`-only
    behaviour: a fast first look at a very large bundle.

    `db_dir` selects where the database lives; by default the roomiest
    of (caller's choice, system temp). `preflight=True` estimates the
    space needed from the zip central directories and refuses up front
    rather than dying mid-build with a bare disk-full error.

    `index_ids=True` (slice 14) also populates `line_ids`, the identifier
    edge table behind `lines_for_id` / `related_ids`. Measured on three
    bundles with the database on local disk, ids OFF vs ON:

        bundle 05   27.3 MB src    216,661 lines  0.34 ids/line
                    45,864 -> 37,378 lines/s (-18.5%)  DB 2.26 -> 2.67
        bundle 01   99.9 MB src    602,106 lines  0.76 ids/line
                    39,829 -> 27,876 lines/s (-30.0%)  DB 1.99 -> 2.68
        bundle 21  138.2 MB src  1,126,322 lines  0.53 ids/line
                    81,170 -> 52,505 lines/s (-35.3%)  DB 2.29 -> 2.93

    (DB figures are database bytes per source byte — see
    `_DB_BYTES_PER_SOURCE_BYTE`, raised from 2.6 to 3.4 for this.)

    The cost tracks ID rows written, not gate count: on bundle 01
    `conn_id` + `ipv4` are 98% of the 457,793 rows, and on bundle 21
    dropping `ipv4` alone removes 179,432 of 593,939. `id_types=` limits
    which identifiers are indexed, for a caller who needs a cheaper
    build on a very large bundle; `index_ids=False` reproduces the
    slice-13 store exactly, for a caller who only wants to read lines.

    Scale note, so the cost is stated rather than discovered: a bundle
    with ~1,100 rotations expands to roughly 4 GB of log text, ~3.6 GB
    of database, and a few minutes of ingest.
    """
    t0 = time.monotonic()

    needed = 0
    if preflight or db_path is None:
        src_bytes, _pn, _rn = estimate_source_bytes(
            bundle_root, read_rotations, max_rotations_per_component,
        )
        needed = int(src_bytes * _DB_BYTES_PER_SOURCE_BYTE)

    if db_path is None:
        target_dir = _pick_db_dir(db_dir, needed)
        fd, db_path = tempfile.mkstemp(
            prefix="log-analyzer-", suffix=".sqlite", dir=target_dir,
        )
        os.close(fd)
        if os.path.exists(db_path):
            os.unlink(db_path)
    elif preflight:
        _pick_db_dir(os.path.dirname(os.path.abspath(db_path)) or ".", needed)

    store = LogStore(db_path)
    store.estimated_db_bytes = needed
    store._conn.executescript(_SCHEMA)
    store.ids_indexed = index_ids
    store.id_types_indexed = (tuple(id_types) if id_types
                              else (ID_TYPES if index_ids else ()))
    ing = _Ingestor(store, index_ids=index_ids, id_types=id_types)

    plains: List[Tuple[str, str, str, int]] = []
    rots: Dict[str, List[Tuple[str, str, str, int]]] = {}
    nested: List[str] = []

    for kind, path, fn, size in _iter_candidates(bundle_root):
        if kind == "unsupported":
            store.archives_unreadable.append(
                f"{fn} (no extractor for this archive type in this "
                f"environment)"
            )
            continue
        if kind == "archive":
            nested.append(path)
            continue
        comp = classify_component(fn)
        if comp is None:
            # Not a ZCC-format log. If it is known evidence in another
            # format, record it so the UI can say "present, not parsed"
            # — silently dropping it is how 251 MB of zapprd.sys driver
            # trace stayed invisible across 8 bundles.
            desc = classify_foreign(fn)
            if desc:
                store.foreign_files[fn] = desc
                store.foreign_bytes += size
            else:
                store.unclassified_files[fn] = size
            continue
        if kind == "plain":
            plains.append((path, fn, comp, size))
        else:
            store.rotations_found += 1
            rots.setdefault(comp, []).append((path, fn, comp, size))

    # Unique label per ingested file — see LogStore.duplicate_source_files.
    used_names: Dict[str, int] = {}

    def _label(name: str, path: str) -> str:
        n = used_names.get(name, 0) + 1
        used_names[name] = n
        label = name if n == 1 else f"{name}#{n}"
        if n > 1:
            store.duplicate_source_files += 1
        store.source_paths[label] = path
        return label

    # ---- plain logs ----
    for path, fn, comp, size in sorted(plains, key=lambda t: t[1]):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                ing.feed(fh, _label(fn, path), comp)
        except OSError:
            continue
        store.files_scanned += 1
        store.plain_logs_read += 1
        store.bytes_scanned += size

    # ---- compressed rotations ----
    if read_rotations:
        for comp, entries in rots.items():
            # newest-first: ZCC filenames embed the start timestamp
            entries.sort(key=lambda t: t[1], reverse=True)
            if max_rotations_per_component:
                entries = entries[:max_rotations_per_component]
            for path, fn, _c, size in entries:
                try:
                    with zipfile.ZipFile(path) as zf:
                        for info in zf.infolist():
                            inner = os.path.basename(info.filename)
                            if not inner.lower().endswith(".log"):
                                continue
                            icomp = classify_component(inner) or comp
                            with zf.open(info) as raw:
                                text = (ln.decode("utf-8", "replace")
                                        for ln in raw)
                                ing.feed(text,
                                         _label(inner, f"{path}!{inner}"),
                                         icomp)
                except (zipfile.BadZipFile, OSError, RuntimeError) as e:
                    store.archives_unreadable.append(f"{fn} ({e})")
                    continue
                store.rotations_read += 1
                store.files_scanned += 1
                store.bytes_scanned += size

    ing.flush()

    # Indexes are created AFTER bulk insert — building them incrementally
    # roughly triples ingest time on a multi-million-row load.
    #
    # Only two, and each earns its place. The first cut created five; on
    # 13.5 M rows each index costs a few hundred MB of disk and a memory
    # spike during construction, and three of them served queries that
    # run rarely (session/host grouping) or are GROUP BY scans anyway.
    #   ix_order  — composite matching the ORDER BY exactly, so the main
    #               chronological read needs no sort step at all.
    #   ix_file   — powers surrounding_lines() and the Raw file browser.
    # Created separately rather than in one executescript so a failure
    # names the index that failed.
    index_stmts = [
        "CREATE INDEX ix_order ON lines(ts, source_file, line_no)",
        "CREATE INDEX ix_file ON lines(source_file, line_no)",
        # Continuation lookup is by line address. Without this, every
        # record_text() call is a full scan of line_cont.
        "CREATE INDEX ix_cont ON line_cont(source_file, line_no)",
    ]
    if index_ids:
        index_stmts += [
            # The whole point of slice 14: value -> lines is an index
            # seek, not a LIKE scan. Also serves id_summary() and
            # id_values() as a covering index.
            "CREATE INDEX ix_ids_val ON line_ids(id_type, id_value)",
            # line -> ids, and the self-join in related_ids().
            "CREATE INDEX ix_ids_line ON line_ids(source_file, line_no)",
        ]
    for stmt in index_stmts:
        store._conn.execute(stmt)
    store._conn.commit()

    store.build_seconds = time.monotonic() - t0
    return store


def nested_archives(bundle_root: str) -> List[str]:
    """Plain `.zip` files inside a bundle that are not `.log.zip`
    rotations — i.e. whole bundles nested inside a container export.

    HubSpot ticket exports (`file-export-<id>-*.zip`) wrap several
    complete ZCC bundles this way; one in the corpus held seven.
    """
    out = []
    for dirpath, _d, files in os.walk(bundle_root):
        for fn in files:
            low = fn.lower()
            if low.endswith(".zip") and not low.endswith(".log.zip"):
                out.append(os.path.join(dirpath, fn))
    return out
