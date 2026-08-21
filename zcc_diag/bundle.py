# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Secure ZCC log-bundle handling.

Untrusted .zip in, safely-extracted directory out, or a clear error.

Guardrails:
  * Zip-slip       -- member paths resolved against root, escapes rejected
  * Absolute paths -- ``/foo`` and ``C:\\foo`` rejected
  * Null bytes     -- in member names rejected
  * Symlinks       -- POSIX-mode symlink members rejected
  * Member cap     -- ``max_members`` files total
  * Per-member cap -- ``max_member_uncompressed`` bytes
  * Total cap      -- ``max_total_uncompressed`` bytes (enforced on the wire)
  * Ratio cap      -- ``max_compression_ratio`` (uncompressed / compressed)
  * Recursion cap  -- nested zips extracted up to ``max_zip_depth`` levels
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class BundleLimits:
    max_total_uncompressed: int = 2 * 1024 * 1024 * 1024  # 2 GB
    max_member_uncompressed: int = 512 * 1024 * 1024      # 512 MB
    max_members: int = 50_000
    max_compression_ratio: int = 200
    max_zip_depth: int = 2  # outer + one level of nested .zip


class BundleError(Exception):
    """Any problem opening or extracting a ZCC bundle."""


class BundleSecurityError(BundleError):
    """A security guardrail blocked extraction."""


@dataclass
class ExtractedBundle:
    source_zip: Path
    root: Path
    files: List[Path] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    bytes_written: int = 0

    def cleanup(self) -> None:
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)


# --- Internals ---------------------------------------------------------

def _is_symlink(zi: zipfile.ZipInfo) -> bool:
    if zi.create_system != 3:  # 3 == Unix
        return False
    return stat.S_ISLNK((zi.external_attr >> 16) & 0xFFFF)


def _safe_target(root: Path, name: str) -> Optional[str]:
    """Return None if ``name`` is safe under ``root``, else a reject reason."""
    if not name:
        return "empty member name"
    if name.startswith(("/", "\\")):
        return "absolute path"
    if len(name) >= 2 and name[1] == ":":
        return "drive-letter path"
    if "\x00" in name:
        return "null byte in path"
    if any(p == ".." for p in name.replace("\\", "/").split("/")):
        return "path traversal"
    try:
        (root / name).resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return "zip-slip rejected"
    return None


# Max parallel workers when extracting nested .log.zip files. ZCC bundles
# routinely have 20-40 rotated logs each shipped as a nested zip; the
# default zip extraction is pure I/O (zlib decompress + disk write), so a
# thread pool gives near-linear speedup up to ~8 cores' worth of disk
# bandwidth. Capped at 8 to avoid spawning more threads than is useful
# on commodity SSDs.
_NESTED_ZIP_WORKERS = 8


def _extract_zip(
    zip_path: Path,
    dest: Path,
    limits: BundleLimits,
    state: ExtractedBundle,
    depth: int,
    state_lock: Optional[threading.Lock] = None,
) -> None:
    """Extract one zip into ``dest``. Recurses on nested zips up to
    ``limits.max_zip_depth``. Mutates ``state`` in place; pass a
    ``state_lock`` when invoking under a thread pool so concurrent
    writers don't race on the shared counters."""
    # ``_with_state`` is a no-op when called serially (no lock); under
    # threading, it serialises every state mutation.
    def _with_state(fn):
        if state_lock is None:
            fn()
        else:
            with state_lock:
                fn()

    if depth > limits.max_zip_depth:
        _with_state(lambda: state.skipped.append(
            f"{zip_path.name}: max recursion depth"))
        return

    try:
        zf = zipfile.ZipFile(zip_path, "r")
    except zipfile.BadZipFile as e:
        if depth == 1:
            raise BundleError(f"Corrupt zip: {e}") from e
        _with_state(lambda: state.skipped.append(f"{zip_path.name}: not a zip"))
        return

    nested_zips: List[Path] = []
    with zf:
        members = zf.infolist()
        if len(members) > limits.max_members:
            raise BundleSecurityError(
                f"Too many members: {len(members)} > {limits.max_members}"
            )

        for zi in members:
            if _is_symlink(zi):
                _with_state(lambda zi=zi: state.skipped.append(
                    f"{zi.filename}: symlink rejected"))
                continue

            reason = _safe_target(dest, zi.filename)
            if reason:
                _with_state(lambda zi=zi, r=reason: state.skipped.append(
                    f"{zi.filename}: {r}"))
                continue

            if zi.file_size > limits.max_member_uncompressed:
                _with_state(lambda zi=zi: state.skipped.append(
                    f"{zi.filename}: member size exceeds cap"))
                continue

            if (
                zi.compress_size > 0
                and zi.file_size / zi.compress_size
                > limits.max_compression_ratio
            ):
                _with_state(lambda zi=zi: state.skipped.append(
                    f"{zi.filename}: compression ratio too high"))
                continue

            target = dest / zi.filename
            if zi.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)

            with zf.open(zi, "r") as src, open(target, "wb") as dst:
                written = 0
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    # Bytes-written counter is the only hot-path shared
                    # state. Under threading we increment under the lock.
                    if state_lock is None:
                        state.bytes_written += len(chunk)
                    else:
                        with state_lock:
                            state.bytes_written += len(chunk)
                    if state.bytes_written > limits.max_total_uncompressed:
                        raise BundleSecurityError(
                            "total uncompressed bytes exceeded limit"
                        )
                    if written > limits.max_member_uncompressed:
                        raise BundleSecurityError(
                            f"{zi.filename}: size exceeded during stream"
                        )
                    dst.write(chunk)

            # Preserve the zipinfo's recorded mtime on the extracted file.
            # Without this, every extracted file gets the same extract-time
            # mtime, which breaks newest-first ordering downstream (the
            # ``filename_timestamp_key`` fallback in log_parser.py uses
            # mtime when the filename has no embedded timestamp -- Mac
            # rotated logs typically lack one, so all of them end up
            # sorting identically).
            try:
                mtime = time.mktime(zi.date_time + (0, 0, -1))
                os.utime(target, (mtime, mtime))
            except (OverflowError, ValueError, OSError):
                # ZipInfo.date_time can be (1980,0,0,...) or otherwise
                # invalid; skip mtime restore in that case.
                pass

            _with_state(lambda t=target: state.files.append(t))
            if target.suffix.lower() == ".zip":
                nested_zips.append(target)

    # Recurse on nested zips after the outer handle is closed. At depth=1
    # (outer extraction) we fan the nested zips out across a thread pool
    # because they're typically 20-40 rotated logs that take ~60-90s
    # serially on enterprise bundles. Each nested zip extracts into its
    # OWN subdirectory so no two workers write the same file path; the
    # only shared state is the bytes-written counter + files / skipped
    # lists, all guarded by ``thread_lock`` below.
    if not nested_zips:
        return

    if depth == 1 and len(nested_zips) > 1:
        thread_lock = state_lock or threading.Lock()
        with ThreadPoolExecutor(max_workers=_NESTED_ZIP_WORKERS) as pool:
            futures = [
                pool.submit(
                    _extract_zip,
                    nz,
                    nz.parent / (nz.stem + "_extracted"),
                    limits,
                    state,
                    depth + 1,
                    thread_lock,
                )
                for nz in nested_zips
            ]
            for f in futures:
                # Re-raise any worker exception; BundleSecurityError etc
                # must propagate so the cleanup path runs.
                f.result()
    else:
        for nz in nested_zips:
            _extract_zip(
                nz,
                nz.parent / (nz.stem + "_extracted"),
                limits,
                state,
                depth + 1,
                state_lock,
            )


# --- Public API --------------------------------------------------------

def open_bundle(
    bundle_path: Path,
    limits: Optional[BundleLimits] = None,
    *,
    temp_parent: Optional[Path] = None,
) -> ExtractedBundle:
    """Validate and extract ``bundle_path`` to a fresh temp dir.

    The caller MUST invoke ``.cleanup()`` or use :func:`bundle_session`.
    """
    bundle_path = Path(bundle_path).expanduser().resolve()
    if not bundle_path.is_file():
        raise BundleError(f"Not a regular file: {bundle_path}")
    if not zipfile.is_zipfile(bundle_path):
        raise BundleError(f"Not a valid ZIP archive: {bundle_path}")

    limits = limits or BundleLimits()
    root = Path(tempfile.mkdtemp(
        prefix="extracted-",
        dir=str(temp_parent) if temp_parent is not None else None,
    ))
    state = ExtractedBundle(source_zip=bundle_path, root=root)

    try:
        _extract_zip(bundle_path, root, limits, state, depth=1)
    except BaseException:
        state.cleanup()
        raise

    return state


@contextmanager
def bundle_session(
    bundle_path: Path,
    limits: Optional[BundleLimits] = None,
) -> Iterator[ExtractedBundle]:
    """Context manager: ``with bundle_session(zip) as b: ...``"""
    b = open_bundle(bundle_path, limits)
    try:
        yield b
    finally:
        b.cleanup()


def list_log_files(bundle: ExtractedBundle,
                   include_helper: bool = False,
                   include_updater: bool = False,
                   ) -> Iterable[Path]:
    """Yield every ``*.log`` file in the extracted bundle.

    ZSAHelper logs are SKIPPED by default. ZCC writes one tiny
    ZSAHelper log per ZSCTool action (often 200-400 of them per
    bundle, each <2 KB). They contain no triage-relevant content --
    just ``ZSAHelper App Version`` banners and timezone strings. Every
    iteration of ``list_log_files`` used to pay an O(N) cost
    enumerating them, multiplied by the number of consumers (summary,
    detectors, correlator, policy extract, search). Skipping them
    typically removes 95% of returned paths and shaves real time off
    every consumer.

    Pass ``include_helper=True`` if a caller specifically needs them
    (currently no caller does). Same for ``include_updater``.
    """
    for p in bundle.root.rglob("*.log"):
        if not p.is_file():
            continue
        name = p.name
        if not include_helper and name.startswith("ZSAHelper"):
            continue
        if not include_updater and name.startswith("ZSAUpdater"):
            continue
        yield p
