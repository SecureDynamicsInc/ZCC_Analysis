"""
Streaming line-by-line parser for ZCC log files.

Two log line formats in the wild:

  Format A (newer; ZSAService / ZSATunnel / ZSAUpm / ZSATray):
      2025-03-25 16:51:20.127977(+0530)[3524:3512] INF Some message

  Format B (older / zep_service):
      2024-04-22 14:13:02.064(+05:30)[2472:356] [debug] [MOD] [Foo:42] msg

The parser yields :class:`LogLine` objects in O(1) memory per file and is
robust against truncated tails, non-UTF-8 bytes, multi-line messages, and
timestamp lines that don't fully match either format.

Performance notes (this is the hot path of the toolkit):
  * Single latin-1 decode per line; ASCII content decodes identically.
  * Timestamp parsed by hand (strptime is ~5x slower).
  * Per-tz cache; usually one entry hit for an entire file.
  * Continuation lines accumulated in a list, joined once on flush.
  * ``LogLine`` uses ``__slots__``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterator, List, Optional

log = logging.getLogger(__name__)

# Format A: 2025-03-25 16:51:20.127977(+0530)[pid:tid] LEVEL message
_RE_FORMAT_A = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
    r"\((?P<tz>[+-]\d{2}:?\d{2})\)"
    r"\[(?P<pid>\d+):(?P<tid>\d+)\]\s+"
    r"(?P<level>INF|DBG|ERR|WRN|TRC|VRB|FTL)\s+"
    r"(?P<msg>.*)$"
)

# Format B: 2024-04-22 14:13:02.064(+05:30)[pid:tid] [debug] [MOD] msg
_RE_FORMAT_B = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
    r"\((?P<tz>[+-]\d{2}:?\d{2})\)"
    r"\[(?P<pid>\d+):(?P<tid>\d+)\]\s+"
    r"\[(?P<level>\w+)\]\s*"
    r"(?P<msg>.*)$"
)

# Fast pre-filter for "could this start a new record?"
_RE_TS_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.")

# Format A uses 3-letter all-caps; Format B uses lowercase words.
# Two dicts, one merged lookup.
_LEVEL_NORMALISE = {
    "INF": "INFO", "DBG": "DEBUG", "ERR": "ERROR", "WRN": "WARN",
    "TRC": "TRACE", "VRB": "VERBOSE", "FTL": "FATAL",
    "info": "INFO", "debug": "DEBUG", "error": "ERROR",
    "warn": "WARN", "warning": "WARN", "trace": "TRACE",
    "verbose": "VERBOSE", "fatal": "FATAL",
}


@dataclass(slots=True)
class LogLine:
    """A single parsed log record. ``source_path.name`` gives the basename."""
    timestamp: datetime          # UTC-aware
    level: str                   # Normalised to {INFO, DEBUG, ERROR, ...}
    pid: int
    tid: int
    message: str
    source_path: Path
    raw: str = field(repr=False)
    line_no: int = 0


@lru_cache(maxsize=64)
def _tz_for(tz: str) -> timezone:
    """Cache tz objects keyed on the literal string. Real bundles
    typically use one or two distinct offsets, so the cache is tiny."""
    tz = tz.replace(":", "")
    sign = 1 if tz[0] == "+" else -1
    return timezone(
        sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
    )


def _parse_ts(ts: str, tz: str) -> Optional[datetime]:
    """Manual parse of ``YYYY-MM-DD HH:MM:SS.ffffff``. ~5x faster than
    ``strptime`` because we know the exact layout.

    Phase 58a (2026-07-02): the numeric ``YYYY-MM-DD HH:MM:SS.ffffff``
    portion of a Zscaler log line is **already UTC**. The ``(-HHMM)``
    that follows is *metadata about the device's local offset*, not
    the timestamp's own timezone. Proof:

      * Filename ``Zscaler-YYYY-MM-DD-HH-MM-SS-*.zip`` embeds local
        time; log's last line matches that filename only if the log
        timestamp is UTC.
      * Linux file mtimes (native UTC) on rotated logs match the log
        line timestamp exactly, ruling out any local-wall-clock
        interpretation.

    Prior to Phase 58a we treated the numeric ts as local and used
    ``astimezone(UTC)`` to shift by ``tz`` — that produced a wall-clock
    that was ``|tz|`` hours off (6h for MDT bundles) for every finding,
    every correlator, every RCA. The bug was masked because engineers
    reading the log side-by-side saw matching numbers and moved on.

    We keep the ``tz`` argument for backward-compat but ignore it for
    building the datetime. Callers that need the local-offset for
    display should read it from ``LogIndex.bundle_tz_offset`` and
    format at render time (see :func:`ui.tz_display.format_dual`).
    """
    try:
        # ts: "2025-03-25 16:51:20.127977"
        date_part, time_part = ts.split(" ", 1)
        y, mo, d = date_part.split("-")
        h, mi, rest = time_part.split(":", 2)
        s, frac = rest.split(".", 1)
        # Pad / truncate fractional to microseconds.
        us = int((frac + "000000")[:6])
        # Attach UTC directly; do NOT shift by ``tz``.
        return datetime(
            int(y), int(mo), int(d),
            int(h), int(mi), int(s), us,
            tzinfo=timezone.utc,
        )
    except (ValueError, KeyError, IndexError):
        # IndexError covers malformed tz strings like "+5" that survive
        # _tz_for's split / index slicing. ValueError catches bad date
        # components; KeyError is retained for legacy callers of
        # _LEVEL_NORMALISE if _parse_ts is ever extended.
        return None


def _match_record(text: str):
    """Return a regex match for whichever format applies, or None."""
    return _RE_FORMAT_A.match(text) or _RE_FORMAT_B.match(text)


def parse_file(
    path: Path,
    max_lines: Optional[int] = None,
) -> Iterator[LogLine]:
    """Yield :class:`LogLine` records for ``path``.

    ``max_lines`` -- safety cap on yielded records. ``None`` means unbounded.
    Missing or unreadable files yield zero records (logged at debug level).
    """
    path = Path(path)
    if not path.is_file():
        log.debug("parse_file: not a file: %s", path)
        return

    yielded = 0
    pending: Optional[LogLine] = None
    cont_buf: List[str] = []  # continuation lines for `pending`

    def _flush() -> Optional[LogLine]:
        """Attach any buffered continuation lines to ``pending`` and return
        it for yielding. Caller must clear ``pending`` afterwards."""
        if pending is None:
            return None
        if cont_buf:
            pending.message = pending.message + "\n" + "\n".join(cont_buf)
            cont_buf.clear()
        return pending

    try:
        with open(path, "rb") as f:
            for raw_line_no, raw_bytes in enumerate(f, start=1):
                # latin-1 never raises on bytes; ASCII content (which is
                # all we match on) decodes identically to UTF-8. The
                # rstrip arg covers both Windows (CRLF) and Mac/Unix (LF)
                # line endings in one pass -- the previous two-call form
                # was a no-op on the second call after the first stripped
                # both characters.
                text = raw_bytes.decode("latin-1").rstrip("\r\n")
                if not text:
                    continue

                if not _RE_TS_PREFIX.match(text):
                    # Continuation of previous record (multi-line message).
                    if pending is not None:
                        cont_buf.append(text)
                    continue

                m = _match_record(text)
                if m is None:
                    # Has TS prefix but doesn't match either format -- treat
                    # as continuation rather than dropping.
                    if pending is not None:
                        cont_buf.append(text)
                    continue

                # New record starts. Flush any pending one.
                if pending is not None:
                    out = _flush()
                    pending = None
                    if out is not None:
                        yield out
                        yielded += 1
                        if max_lines is not None and yielded >= max_lines:
                            return

                ts = _parse_ts(m.group("ts"), m.group("tz"))
                if ts is None:
                    continue

                level_raw = m.group("level")
                pending = LogLine(
                    timestamp=ts,
                    level=_LEVEL_NORMALISE.get(level_raw, level_raw.upper()),
                    pid=int(m.group("pid")),
                    tid=int(m.group("tid")),
                    message=m.group("msg"),
                    source_path=path,
                    raw=text,
                    line_no=raw_line_no,
                )

        # Flush trailing record.
        out = _flush()
        if out is not None:
            yield out
    except OSError as e:
        log.warning("Could not read %s: %s", path, e)


# --- Filename classification -------------------------------------------

# Order matters: more specific prefixes first.
# Both Windows and macOS component filenames are covered here. The log
# CONTENT format is identical across platforms (Format A); only the
# component filenames differ.
_CLASSIFY_RULES = (
    # ZIA / tunnel proxy
    ("zsatunnel",                       "tunnel"),   # Windows
    ("trptunnel",                       "tunnel"),   # macOS (Tunnel Routing Process)
    # Main service binaries
    ("zsaservice",                      "service"),  # Windows
    ("com.zscaler.zscalerservice",      "service"),  # macOS (launchd captures)
    # UPM telemetry (cross-platform filenames)
    ("ztraceroute",                     "zdx_traceroute"),
    ("zwebload",                        "zdx_webload"),
    ("devicestats",                     "upm_devicestats"),
    ("zsystemevents",                   "upm_sysevents"),
    ("zdeviceevents",                   "upm_devevents"),
    # Tray UI
    ("zsatraymanager",                  "tray_manager"),  # Windows-specific
    ("zsatray",                         "tray"),
    # Helpers / updaters
    ("zsahelper",                       "helper"),
    ("zsaupm",                          "upm"),
    # macOS-only: UPM controller (the Mac equivalent of Windows
    # service-side UPM plumbing)
    ("com.zscaler.upmservicecontroller", "upm_controller"),
    # ZEP (Zscaler Endpoint Protection) -- older deployments.
    # Phase 53d (2026-06-26): Example Tenant A User B bundle carried
    # ``zep_msi_install_26.05.0.36.log`` which the prior two-rule
    # match missed (because "msi" sits between "zep_" and "install").
    # Broadening to a single "zep_" needle catches every ZEP filename
    # variant seen so far without risking collisions — no other Zscaler
    # log family starts with "zep_".
    ("zep_",                            "zep"),
    ("zsaupdater",                      "updater"),
)

_ZDX_KINDS = frozenset({"zdx_traceroute", "zdx_webload"})


def classify_log_file(path: Path) -> str:
    """Categorise a log file by its basename.

    Compressed rotated logs (``*.log.zip``) classify as ``other`` so
    detectors and the parser don't try to read them as text -- the
    bundle extractor auto-extracts them at open time, so the inner
    ``*.log`` is already present alongside.
    """
    n = path.name.lower()
    # Skip compressed rotated logs -- the bundle extractor already
    # unzipped them, so the matching .log sits next to the .log.zip.
    if n.endswith(".zip"):
        return "other"
    for needle, kind in _CLASSIFY_RULES:
        if needle in n:
            return kind
    return "other"


def is_zdx_log(path: Path) -> bool:
    return classify_log_file(path) in _ZDX_KINDS


# ZCC log filename pattern: <Component>_YYYY-MM-DD-HH-MM-SS.NNNNNN.log
# Used as a robust "newest-first" sort key, since file mtime reflects
# when the bundle was extracted, not when the log was written.
_RE_LOG_FILENAME_TS = re.compile(
    r"_(?P<ts>\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.\d+)"
)


def filename_timestamp_key(path: Path) -> str:
    """Return a sort key derived from the timestamp embedded in a ZCC
    log filename. Lexicographic compare on the normalised string is
    chronological because the format is fixed-width.

    Falls back to the file mtime if the filename has no embedded
    timestamp -- this keeps non-ZCC files (which shouldn't be in a real
    bundle anyway) from blowing up the sort.
    """
    m = _RE_LOG_FILENAME_TS.search(path.name)
    if m:
        return m.group("ts")
    try:
        # epoch as zero-padded string so it lexsorts numerically
        return f"0_{path.stat().st_mtime:020.6f}"
    except OSError:
        return "0_00000000000000.000000"


def detect_zdx_enabled(log_files: List[Path]) -> bool:
    """ZDX is "active" if at least one ZDX log has > 4 KB of data
    (a freshly-init log is ~1 KB; real probe data pushes it past 4 KB)."""
    for p in log_files:
        if not is_zdx_log(p):
            continue
        try:
            if p.stat().st_size > 4096:
                return True
        except OSError:
            continue
    return False
