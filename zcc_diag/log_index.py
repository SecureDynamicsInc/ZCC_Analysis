"""
Shared in-memory tunnel-log index.

Why this exists:
  * The toolkit's hot path is parsing tunnel logs. Multiple consumers
    (summary banner harvest, policy extractor, bypass resolver, search
    module, session correlator) USED to each open every tunnel log file
    and walk it line-by-line. On a 350 MB bundle with 30 rotated logs,
    that's 30+ full reads = multiple gigabytes of redundant I/O.
  * This module parses every tunnel log ONCE during bundle load and
    exposes the result as a flat, sorted list of ``IndexedLine``
    records. All consumers query the in-memory index instead of
    re-opening files.

What's indexed:
  * Tunnel logs (ZSATunnel, TRPTunnel)
  * Service logs (ZSAService, com.zscaler.ZscalerService, TRPService)
  * Tray logs (ZSATrayManager, ZSATray)
  * UPM logs (ZSAUpm)

NOT indexed:
  * ZSAHelper (hundreds of tiny files, no triage value)
  * ZSAUpdater (auto-update history, not connection-relevant)

Memory profile:
  * Each ``IndexedLine`` is ~250 bytes (the raw body string dominates).
  * A 350 MB tunnel-log bundle yields ~3 M lines -> ~750 MB resident.
    On bundles with a `tunnel_byte_budget`, this is well under that
    budget (because the budget caps how many BYTES are read, not how
    many lines result -- but it's roughly linear).
  * For really big bundles a caller can pass ``max_lines`` to cap the
    index size; the trimming preserves the MOST RECENT lines, which
    is what an engineer is triaging.

API:
    build_index(bundle_root, max_lines=None) -> LogIndex
    LogIndex.lines           # flat list of IndexedLine
    LogIndex.by_session_id   # Dict[sid] -> List[IndexedLine]
    LogIndex.by_host         # Dict[host_lower] -> List[IndexedLine]
    LogIndex.search(query)   # iterate lines whose body contains query
"""

from __future__ import annotations

import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Tuple


# --------------------------------------------------------------------
# Line parsing -- mirrors session_correlator but is the SINGLE source
# of truth for tunnel-log line structure across the toolkit.
# --------------------------------------------------------------------

# Phase 58e-C7 (2026-07-08): tz group now accepts both Format A
# ((-0600)) and Format B ((+05:30)) — the sibling log_parser has
# always accepted both, but this regex only accepted Format A,
# silently dropping every line from Indian / Nepal / Iranian /
# half-hour-zone bundles.
# Phase 61 (2026-08-14): added WAR to the level alternation.
#
# Measured across the whole 26-bundle corpus (4.4 M indexed lines): the
# regex listed `WRN` but ZCC actually emits **`WAR`**. Every warning line
# in every bundle was therefore rejected by the parser and became
# invisible to every tab — 14,898 of them in the sampled subset alone,
# 3.7% of all rejected lines, present in 19 of 26 bundles. Their format
# is byte-identical to INF/DBG/ERR (`<ts>(<tz>)[pid:tid] WAR <body>`), so
# the only thing wrong was the token.
#
# `WRN` is kept in the alternation: it costs nothing and guards against a
# future build that uses it. Same for CRT/TRC, which this corpus never
# emitted but which are documented ZCC levels.
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+)"
    r"(?P<tz>\([+-]\d{2}:?\d{2}\))?"
    r"\[(?P<pid>\d+):(?P<tid>\d+)\]\s+"
    r"(?P<level>DBG|INF|WAR|WRN|ERR|CRT|TRC)\s+"
    r"(?P<body>.*)$"
)
_ID_RE = re.compile(r"\bID=(?P<id>\d+)")

# Quick host extractors -- compiled once at module load. Order matters:
# more-specific patterns first so HTTPS SNI catches before bare host.
_HOST_PATTERNS = [
    re.compile(r"resolveDnsWithFamilyPriority(?:GW)?:\s+Host:\s+([^\s]+)"),
    re.compile(r"Encoded URL:\s+https?://([^/\s]+)"),
    re.compile(r"Encoded Host:\s+([^\s]+)"),
    re.compile(r"PAC Parse Host:\s+([^\s]+)"),
    re.compile(r"SNI-Host=([^\s,]+)"),
    re.compile(r"readFromClient:\s+Host(?:\s+Address)?:\s+([^\s]+)"),
    re.compile(r'"host"\s*:\s*"([^"]+)"'),
]


def _extract_session_id(body: str) -> Optional[str]:
    m = _ID_RE.search(body)
    return m.group("id") if m else None


def _extract_host(body: str) -> Optional[str]:
    for p in _HOST_PATTERNS:
        m = p.search(body)
        if m:
            h = m.group(1).lower()
            # Strip trailing port if any (e.g. host:443)
            if ":" in h and not h.startswith("["):
                h = h.rsplit(":", 1)[0]
            return h
    return None


# --------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------

# IndexedLine is intentionally a tuple-backed dataclass with __slots__
# so we keep memory in check. Each line is the cost of: a small object
# header + 1 datetime + 5 short strings + 2 optional strings.

@dataclass(slots=True)
class IndexedLine:
    ts: datetime
    pid: str
    tid: str
    level: str           # DBG / INF / WRN / ERR / CRT / TRC
    body: str
    component: str       # tunnel / service / tray / upm
    source_file: str     # basename only
    line_no: int
    session_id: Optional[str] = None
    host: Optional[str] = None


@dataclass
class LogIndex:
    """Parsed tunnel + service + tray + upm logs as a single in-memory
    structure. Built once per bundle via ``build_index()``."""
    lines: List[IndexedLine] = field(default_factory=list)
    by_session_id: Dict[str, List[IndexedLine]] = field(
        default_factory=lambda: defaultdict(list))
    by_host: Dict[str, List[IndexedLine]] = field(
        default_factory=lambda: defaultdict(list))
    build_seconds: float = 0.0
    bytes_scanned: int = 0
    files_scanned: int = 0
    lines_skipped_unparseable: int = 0
    # Bundle-wide timezone, captured from the FIRST parseable log line.
    # ZCC log timestamps are wall-clock-local on the source machine and
    # carry the UTC offset in the line (e.g. "(-0600)" for Mountain
    # Time). We capture the offset string once so renderers can annotate
    # times with the bundle's TZ — critical because customers report
    # incidents in their LOCAL TZ ("around 9:30 Mountain Time") and
    # the toolkit must match.
    bundle_tz_offset: Optional[str] = None  # e.g. "-0600"
    bundle_tz_label: Optional[str] = None   # e.g. "UTC-06:00"

    def search(self, query: str) -> Iterator[IndexedLine]:
        """Iterate every line whose body (case-insensitively) contains
        ``query``. O(n) scan; fast because the index is in memory."""
        q = query.lower()
        for ln in self.lines:
            if q in ln.body.lower():
                yield ln

    def time_window(self, start: datetime, end: datetime
                    ) -> Iterator[IndexedLine]:
        """Iterate lines within [start, end] inclusive. Linear scan
        for now -- if profiling shows this is hot we'd binary-search a
        sorted ts list."""
        for ln in self.lines:
            if start <= ln.ts <= end:
                yield ln

    def surrounding_lines(
        self,
        source_file: str,
        line_no: int,
        radius: int = 5,
    ) -> List["IndexedLine"]:
        """Return up to ``2 * radius + 1`` lines from ``source_file``
        centred on ``line_no`` (the matched line plus ``radius`` lines
        before and after, all from the same source file).

        Used by the UI finding-card evidence renderer to give engineers
        the surrounding context for a single matched evidence line.
        Pain point this addresses: a SAML-expiry finding's evidence
        shows only the matched line ("saml force expired has been set"),
        but the engineer needs the broker-state lines above and below
        to figure out WHY the SAML expired. Returning surrounding lines
        inline solves that without a separate UI navigation.

        Implementation: linear scan filtered to one file. Index size is
        typically 1-3M lines globally; per-file is 50-200K. A single
        evidence lookup is O(file_size) but only called when the user
        clicks to expand, so latency is fine for the workflow.
        """
        if not source_file or line_no is None:
            return []
        lo = line_no - radius
        hi = line_no + radius
        out: List[IndexedLine] = []
        for ln in self.lines:
            if ln.source_file != source_file:
                continue
            if lo <= ln.line_no <= hi:
                out.append(ln)
        out.sort(key=lambda x: x.line_no)
        return out


# --------------------------------------------------------------------
# File discovery
# --------------------------------------------------------------------

_TUNNEL_PREFIXES = ("ZSATunnel", "TRPTunnel")
_SERVICE_PREFIXES = ("ZSAService", "com.zscaler.ZscalerService", "TRPService")
_TRAY_PREFIXES = ("ZSATrayManager", "ZSATray", "ZSATrayHelper")
_UPM_PREFIXES = ("ZSAUpm",)


def _iter_log_files(bundle_root: str
                    ) -> Iterator[Tuple[str, str]]:
    """Yield (component, abs_path) for every log file we index. Skips:
      * ZSAHelper -- hundreds of tiny files, no triage value
      * ZSAUpdater -- auto-update history, not connection-relevant
      * Files ending in .snapshot -- partial/in-progress logs
      * Files smaller than 200 bytes -- empty header-only files
    """
    for root, _, files in os.walk(bundle_root):
        for f in files:
            if not f.endswith(".log"):
                continue
            path = os.path.join(root, f)
            try:
                if os.path.getsize(path) < 200:
                    continue
            except OSError:
                continue
            if f.startswith("ZSAHelper") or f.startswith("ZSAUpdater"):
                continue
            if any(f.startswith(p) for p in _TUNNEL_PREFIXES):
                yield ("tunnel", path)
            elif any(f.startswith(p) for p in _SERVICE_PREFIXES):
                yield ("service", path)
            elif any(f.startswith(p) for p in _TRAY_PREFIXES):
                yield ("tray", path)
            elif any(f.startswith(p) for p in _UPM_PREFIXES):
                yield ("upm", path)


# --------------------------------------------------------------------
# Index builder
# --------------------------------------------------------------------

def build_index(bundle_root: str,
                max_lines: Optional[int] = None,
                tunnel_byte_budget: Optional[int] = None,
                ) -> LogIndex:
    """Parse every (tunnel/service/tray/upm) log file in ``bundle_root``
    into a ``LogIndex``. Single pass, no re-reads.

    ``tunnel_byte_budget`` is applied PER component: when set, the
    builder stops reading additional FILES of that component once the
    cumulative byte count exceeds the budget. Files are processed in
    sort order (which for ZSA logs is chronological because the
    filenames embed the start timestamp), so the budget naturally
    keeps the MOST RECENT logs.
    """
    t0 = time.monotonic()
    idx = LogIndex()
    seen_files: List[Tuple[str, str, int]] = []

    # Discover all candidate files first so we can apply the budget in
    # a consistent (chronological) order.
    for component, path in _iter_log_files(bundle_root):
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        seen_files.append((component, path, size))
    # Sort NEWEST-FIRST so the byte budget naturally keeps the most
    # recent logs (where active-incident signal lives). ZSA log
    # filenames embed the start timestamp, so sorting by basename
    # descending gives newest-first.
    #
    # Fixed 2026-06-17 (Phase 12): previously sorted ascending, which
    # caused the budget to drop the newest rotations on bundles whose
    # tunnel logs exceed UI_BUDGET. That was the opposite of intent —
    # see run_detectors() in issues/__init__.py for the documented
    # "newest-first" convention.
    seen_files.sort(key=lambda t: os.path.basename(t[1]), reverse=True)

    component_bytes: Dict[str, int] = defaultdict(int)

    for component, path, size in seen_files:
        if (tunnel_byte_budget is not None
                and component_bytes[component] + size > tunnel_byte_budget
                and component_bytes[component] > 0):
            continue  # over budget for this component
        component_bytes[component] += size
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                basename = os.path.basename(path)
                for line_no, raw in enumerate(fp, start=1):
                    m = _LINE_RE.match(raw)
                    if not m:
                        idx.lines_skipped_unparseable += 1
                        continue
                    try:
                        # Phase 58a (2026-07-02): numeric ts is UTC.
                        # Attach tzinfo=timezone.utc so downstream
                        # comparisons in relations.py / rca_view /
                        # investigate all use a consistent aware type.
                        ts = datetime.strptime(
                            m.group("ts"), "%Y-%m-%d %H:%M:%S.%f",
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        idx.lines_skipped_unparseable += 1
                        continue
                    # Capture the bundle's TZ offset from the FIRST
                    # parseable log line. The regex's "tz" group is e.g.
                    # "(-0600)"; we strip the parens for storage.
                    if idx.bundle_tz_offset is None:
                        tz_raw = m.group("tz") or ""
                        if tz_raw.startswith("(") and tz_raw.endswith(")"):
                            tz_raw = tz_raw[1:-1]
                        # Phase 58e-C7 (2026-07-08): normalize colon
                        # form "+05:30" → "+0530" so downstream helpers
                        # like ui/tz_display._offset_to_timedelta (which
                        # requires 5-char form) work for Format B
                        # bundles too.
                        tz_raw = tz_raw.replace(":", "")
                        if tz_raw:
                            idx.bundle_tz_offset = tz_raw
                            # Build a human label like "UTC-06:00" from
                            # the "-0600" form.
                            sign = tz_raw[0]
                            try:
                                hh = int(tz_raw[1:3])
                                mm = int(tz_raw[3:5])
                                idx.bundle_tz_label = (
                                    f"UTC{sign}{hh:02d}:{mm:02d}"
                                )
                            except ValueError:
                                idx.bundle_tz_label = f"UTC{tz_raw}"

                    body = m.group("body")
                    sid = _extract_session_id(body)
                    host = _extract_host(body)
                    ln = IndexedLine(
                        ts=ts,
                        pid=m.group("pid"),
                        tid=m.group("tid"),
                        level=m.group("level"),
                        body=body,
                        component=component,
                        source_file=basename,
                        line_no=line_no,
                        session_id=sid,
                        host=host,
                    )
                    idx.lines.append(ln)
                    if sid:
                        idx.by_session_id[sid].append(ln)
                    if host:
                        idx.by_host[host].append(ln)
                    if max_lines and len(idx.lines) >= max_lines:
                        break
        except OSError:
            continue
        idx.files_scanned += 1
        if max_lines and len(idx.lines) >= max_lines:
            break

    # Phase 60 (2026-08-14): sort the flat line list CHRONOLOGICALLY.
    #
    # Files are discovered newest-first (see the `seen_files.sort(...)`
    # above, which exists so the byte budget keeps recent rotations), and
    # each file's lines were appended in file order. That left
    # `idx.lines` ordered by *filename descending*, not by time — so
    # `lines[0]` was the first line of the alphabetically-last file and
    # `lines[-1]` the last line of the alphabetically-first.
    #
    # Everything downstream treats `lines[0]` / `lines[-1]` as the
    # bundle's time bounds: facts_extract's first_ts/last_ts/duration
    # (which routinely came out NEGATIVE on multi-rotation bundles),
    # timeline's default centre, and the order search results are
    # presented in. Sorting once here fixes all of them at the source.
    #
    # Tie-break on (source_file, line_no) so lines sharing a timestamp —
    # common, since ZCC logs at millisecond resolution — keep a stable,
    # reproducible order rather than depending on sort implementation.
    idx.lines.sort(key=lambda ln: (ln.ts, ln.source_file, ln.line_no))

    idx.bytes_scanned = sum(component_bytes.values())
    idx.build_seconds = time.monotonic() - t0
    print(
        f"[log_index] {idx.files_scanned} files / "
        f"{idx.bytes_scanned // (1024*1024)} MB / "
        f"{len(idx.lines)} lines / "
        f"{len(idx.by_session_id)} session IDs / "
        f"{len(idx.by_host)} unique hosts / "
        f"{idx.build_seconds:.2f}s",
        file=sys.stderr,
    )
    return idx
