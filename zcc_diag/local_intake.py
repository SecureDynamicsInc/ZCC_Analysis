# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Normalize browser uploads into the bundle shape used by the analyzer.

The analysis engine deliberately has one security boundary: a ZIP bundle is
opened by :mod:`zcc_diag.bundle`. The desktop UI also accepts one or more
standalone logs, so this module packages those files into a small in-memory ZIP
and sends them through that same hardened path.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, Tuple


SUPPORTED_INPUT_EXTENSIONS = frozenset({
    ".zip", ".log", ".txt", ".xml", ".json", ".csv", ".tsv",
    ".conf", ".ini",
})

_MAX_STANDALONE_FILES = 250
_MAX_STANDALONE_BYTES = 1 * 1024 * 1024 * 1024
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")


class IntakeError(ValueError):
    """The selected input cannot be normalized safely."""


@dataclass(frozen=True)
class PreparedInput:
    bundle_bytes: bytes
    display_name: str
    source_kind: str
    file_count: int


def _safe_name(raw: str, fallback: str) -> str:
    name = Path(str(raw or "")).name.strip()
    name = _SAFE_CHARS.sub("_", name).strip(" .")
    return name or fallback


def _dedupe_name(name: str, used: set[str]) -> str:
    candidate = name
    stem = Path(name).stem
    suffix = Path(name).suffix
    counter = 2
    while candidate.casefold() in used:
        candidate = f"{stem} ({counter}){suffix}"
        counter += 1
    used.add(candidate.casefold())
    return candidate


def prepare_inputs(files: Sequence[Tuple[str, bytes]]) -> PreparedInput:
    """Return a bundle-ready payload for ZIP, single-log, or log-set input."""
    if not files:
        raise IntakeError("Choose a ZCC bundle or at least one log file.")
    if len(files) > _MAX_STANDALONE_FILES:
        raise IntakeError(
            f"Too many individual files ({len(files)}); the limit is "
            f"{_MAX_STANDALONE_FILES}. Use a ZIP bundle for larger sets."
        )

    normalized = []
    total = 0
    used: set[str] = set()
    for index, (raw_name, raw_bytes) in enumerate(files, 1):
        name = _dedupe_name(_safe_name(raw_name, f"log-{index}.log"), used)
        suffix = Path(name).suffix.lower()
        if suffix not in SUPPORTED_INPUT_EXTENSIONS:
            allowed = ", ".join(sorted(SUPPORTED_INPUT_EXTENSIONS))
            raise IntakeError(f"Unsupported file type for {name}. Allowed: {allowed}")
        data = bytes(raw_bytes)
        total += len(data)
        if total > _MAX_STANDALONE_BYTES:
            raise IntakeError(
                "Selected files exceed the 1 GB local intake limit. "
                "Use a smaller set or the CLI for an intentionally larger run."
            )
        normalized.append((name, data))

    if len(normalized) == 1 and Path(normalized[0][0]).suffix.lower() == ".zip":
        name, data = normalized[0]
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise IntakeError(f"{name} is named .zip but is not a readable ZIP archive.")
        return PreparedInput(data, name, "bundle", 1)

    if any(Path(name).suffix.lower() == ".zip" for name, _ in normalized):
        raise IntakeError(
            "Choose one ZIP bundle, or choose individual log files without a ZIP."
        )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in normalized:
            zf.writestr(f"standalone/{name}", data)

    if len(normalized) == 1:
        display = normalized[0][0]
        kind = "individual log"
    else:
        display = f"{len(normalized)} individual logs"
        kind = "log set"
    return PreparedInput(buffer.getvalue(), display, kind, len(normalized))
