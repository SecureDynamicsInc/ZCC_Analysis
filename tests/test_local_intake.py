from __future__ import annotations

import io
import zipfile

import pytest

from zcc_diag.local_intake import IntakeError, prepare_inputs


def test_native_zip_is_not_repacked() -> None:
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as zf:
        zf.writestr("ZSATunnel.log", "2026-08-19 10:00:00.000 ERR test")
    payload = source.getvalue()
    prepared = prepare_inputs([("bundle.zip", payload)])
    assert prepared.bundle_bytes == payload
    assert prepared.source_kind == "bundle"
    assert prepared.display_name == "bundle.zip"


def test_single_log_is_wrapped_for_the_hardened_bundle_path() -> None:
    prepared = prepare_inputs([("ZSATunnel.log", b"one\ntwo\n")])
    assert prepared.source_kind == "individual log"
    assert prepared.file_count == 1
    with zipfile.ZipFile(io.BytesIO(prepared.bundle_bytes)) as zf:
        assert zf.namelist() == ["standalone/ZSATunnel.log"]
        assert zf.read(zf.namelist()[0]) == b"one\ntwo\n"


def test_log_set_sanitizes_and_deduplicates_names() -> None:
    prepared = prepare_inputs([
        ("../ZSAService.log", b"a"),
        ("ZSAService.log", b"b"),
    ])
    assert prepared.source_kind == "log set"
    with zipfile.ZipFile(io.BytesIO(prepared.bundle_bytes)) as zf:
        assert zf.namelist() == [
            "standalone/ZSAService.log",
            "standalone/ZSAService (2).log",
        ]


def test_mixed_zip_and_individual_logs_is_rejected() -> None:
    with pytest.raises(IntakeError, match="one ZIP bundle"):
        prepare_inputs([("bundle.zip", b"not relevant"), ("ZSATunnel.log", b"x")])


def test_invalid_zip_is_rejected() -> None:
    with pytest.raises(IntakeError, match="not a readable ZIP"):
        prepare_inputs([("bundle.zip", b"not a zip")])
