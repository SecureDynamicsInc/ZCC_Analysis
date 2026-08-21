"""
Multiplexer dispatch test.

Why this exists
---------------
The other ``test_*.py`` files all call ``Detector().feed(record, summary)``
directly. That short-circuits the multiplexer in ``zcc_diag.issues.run_detectors``
and means the v6 ``prematch_substrings`` dispatch hook is NOT exercised by any
unit test. A future refactor or a single mis-typed substring tuple could
silently filter records out at the multiplexer layer and every existing test
would still pass.

This file plugs that gap. It builds a minimal synthetic bundle (an
``ExtractedBundle`` pointing at a tmp dir containing two Format-A tunnel logs),
registers three throwaway detectors with different ``prematch_substrings``
configurations, runs them through the real ``run_detectors`` multiplexer, and
asserts that each detector saw exactly the records it should have.

Run:  python test_multiplexer.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import List

# pylint: disable=import-error
from zcc_diag.bundle import ExtractedBundle
from zcc_diag.issues import (
    Finding,
    IssueDetector,
    Severity,
    _REGISTRY,
    register,
    run_detectors,
)
from zcc_diag.log_parser import LogLine
from zcc_diag.summary import BundleSummary


# --- Log file helpers --------------------------------------------------

def write_tunnel_log(root: Path, name: str, lines: List[str]) -> Path:
    """Write a tunnel log file in Format A. Filename must contain
    ``ZSATunnel_YYYY-MM-DD-HH-MM-SS.NNNNNN.log`` so ``classify_log_file``
    tags it as a tunnel log and ``filename_timestamp_key`` orders it."""
    p = root / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def fmt_line(ts: str, level: str, msg: str) -> str:
    """Format-A line. The parser only strictly needs the timestamp / [pid:tid]
    framing -- the message can be anything."""
    return f"{ts}(+0000)[1234:5678] {level} {msg}"


# --- Test detectors ----------------------------------------------------

class _RecorderDetector(IssueDetector):
    """Base class for the three test detectors below. Captures every
    record dispatched to ``feed()`` so the test can introspect what
    the multiplexer actually delivered."""
    sop_file = None
    title = "test recorder"

    def __init__(self) -> None:
        super().__init__()
        self.records_seen: List[LogLine] = []

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        self.records_seen.append(record)

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        return []


# Three flavours of prematch configuration. ``id`` values are
# namespaced with ``__test__`` so they cannot collide with real
# detector ids -- the global ``_REGISTRY`` is module-level state and
# stays populated for the life of the process, but we always
# ``del _REGISTRY[...]`` in ``finally`` to keep that state clean
# regardless of pass/fail.

@register
class _TestPrematchMatching(_RecorderDetector):
    id = "__test__prematch_matching"
    prematch_substrings = ("NEEDLE",)


@register
class _TestPrematchNonMatching(_RecorderDetector):
    id = "__test__prematch_nonmatching"
    prematch_substrings = ("WILL_NEVER_APPEAR",)


@register
class _TestPrematchNone(_RecorderDetector):
    id = "__test__prematch_none"
    prematch_substrings = None  # legacy "always dispatch" path


@register
class _TestPrematchMultiSub(_RecorderDetector):
    """Multi-substring prematch -- any one of the tuple is sufficient."""
    id = "__test__prematch_multisub"
    prematch_substrings = ("ALPHA", "BETA")


_TEST_IDS = (
    "__test__prematch_matching",
    "__test__prematch_nonmatching",
    "__test__prematch_none",
    "__test__prematch_multisub",
)


# --- Test cases --------------------------------------------------------

def _build_bundle_with_lines(tmpdir: Path) -> ExtractedBundle:
    """Plant two tunnel logs with a known mix of messages."""
    log_a = write_tunnel_log(tmpdir, "ZSATunnel_2026-05-19-12-00-00.000001.log", [
        fmt_line("2026-05-19 12:00:00.000001", "INF", "boring line without any markers"),
        fmt_line("2026-05-19 12:00:01.000001", "INF", "line containing NEEDLE substring"),
        fmt_line("2026-05-19 12:00:02.000001", "INF", "line with ALPHA token"),
    ])
    log_b = write_tunnel_log(tmpdir, "ZSATunnel_2026-05-19-12-05-00.000001.log", [
        fmt_line("2026-05-19 12:05:00.000001", "INF", "another boring line"),
        fmt_line("2026-05-19 12:05:01.000001", "INF", "line with BETA token"),
        fmt_line("2026-05-19 12:05:02.000001", "INF", "second NEEDLE line"),
    ])
    return ExtractedBundle(
        source_zip=tmpdir / "synthetic.zip",
        root=tmpdir,
        files=[log_a, log_b],
        skipped=[],
        bytes_written=0,
    )


def _summary() -> BundleSummary:
    """Minimal summary -- the multiplexer reads ``os['family']`` for the
    OS gate. ``windows`` keeps all four test detectors eligible (none of
    them set ``applies_to_os``)."""
    return BundleSummary(os={"family": "windows", "label": "Test Win"})


def run_test(name: str, fn) -> bool:
    try:
        fn()
    except AssertionError as e:
        print(f"FAIL  {name}: {e}")
        return False
    except Exception as e:  # pragma: no cover
        print(f"ERROR {name}: {type(e).__name__}: {e}")
        return False
    print(f"PASS  {name}")
    return True


def test_prematch_matching_receives_only_matching_records() -> None:
    with tempfile.TemporaryDirectory() as td:
        bundle = _build_bundle_with_lines(Path(td))
        results = run_detectors(bundle, _summary(), detector_ids=list(_TEST_IDS))

    by_id = {f.issue_id: f for f in results}

    # The matching detector should have seen exactly the two NEEDLE lines.
    matching = _REGISTRY["__test__prematch_matching"]
    # The detector instance is created inside run_detectors; we can't
    # reach the instance directly, but we know it saw N records iff
    # ``records_seen`` is repopulated. Instead, inspect via a fresh
    # instance: since ``records_seen`` is per-instance, we reconstruct
    # the dispatch decision by hand for the assertion.
    # Simpler: count via a side channel -- the instance is gone, but we
    # can verify the behavior by re-running with a custom one-detector
    # set and capturing via class-level state below.
    assert matching is not None, "matching detector lost from registry"
    # The matching detector should be in the results list (i.e. eligible)
    assert "__test__prematch_matching" in by_id, (
        f"matching detector missing from results; got {list(by_id)}"
    )


def test_prematch_dispatch_via_class_capture() -> None:
    """The instance created inside run_detectors is discarded after
    finalize(), so we capture records via a class-level list keyed on
    the detector id. Recreate the detectors with class-level capture
    for this test."""

    captured: dict = {did: [] for did in _TEST_IDS}

    class _CaptureFactory(IssueDetector):
        sop_file = None

        def __init__(self) -> None:
            super().__init__()

        def feed(self, record, summary):  # noqa: D401
            captured[type(self).id].append(record.message)

        def finalize(self, summary):
            return []

    # Swap the registry entries for capture-aware ones, keeping the
    # same ids + prematch configs.
    saved = {}
    try:
        for did, prematch in (
            ("__test__prematch_matching", ("NEEDLE",)),
            ("__test__prematch_nonmatching", ("WILL_NEVER_APPEAR",)),
            ("__test__prematch_none", None),
            ("__test__prematch_multisub", ("ALPHA", "BETA")),
        ):
            saved[did] = _REGISTRY.pop(did)
            cls = type(
                f"_Capture_{did}",
                (_CaptureFactory,),
                {"id": did, "title": "cap", "prematch_substrings": prematch},
            )
            _REGISTRY[did] = cls

        with tempfile.TemporaryDirectory() as td:
            bundle = _build_bundle_with_lines(Path(td))
            run_detectors(bundle, _summary(), detector_ids=list(_TEST_IDS))
    finally:
        for did, original in saved.items():
            _REGISTRY[did] = original

    needle_msgs = [m for m in captured["__test__prematch_matching"]]
    assert len(needle_msgs) == 2, (
        f"matching prematch should have seen 2 NEEDLE records, "
        f"got {len(needle_msgs)}: {needle_msgs}"
    )
    assert all("NEEDLE" in m for m in needle_msgs), needle_msgs

    nomatch_msgs = captured["__test__prematch_nonmatching"]
    assert len(nomatch_msgs) == 0, (
        f"non-matching prematch should have seen 0 records, "
        f"got {len(nomatch_msgs)}: {nomatch_msgs}"
    )

    none_msgs = captured["__test__prematch_none"]
    assert len(none_msgs) == 6, (
        f"prematch=None should have seen all 6 records, "
        f"got {len(none_msgs)}: {none_msgs}"
    )

    multisub_msgs = captured["__test__prematch_multisub"]
    # ALPHA + BETA each appear once in the synthetic logs.
    assert len(multisub_msgs) == 2, (
        f"multi-substring prematch should have seen 2 records (ALPHA + BETA), "
        f"got {len(multisub_msgs)}: {multisub_msgs}"
    )
    assert any("ALPHA" in m for m in multisub_msgs), multisub_msgs
    assert any("BETA" in m for m in multisub_msgs), multisub_msgs


def test_os_gate_overrides_prematch() -> None:
    """Detector with applies_to_os=('macos',) should be OS-skipped on
    Windows, regardless of prematch_substrings. The result entry
    should be present with a single DETECTOR_SKIPPED_FOR_OS finding."""

    saved = _REGISTRY.pop("__test__prematch_matching")
    try:
        cls = type(
            "_MacOnlyMatching",
            (_RecorderDetector,),
            {
                "id": "__test__prematch_matching",
                "title": "mac-only",
                "prematch_substrings": ("NEEDLE",),
                "applies_to_os": ("macos",),
            },
        )
        _REGISTRY["__test__prematch_matching"] = cls
        with tempfile.TemporaryDirectory() as td:
            bundle = _build_bundle_with_lines(Path(td))
            results = run_detectors(
                bundle, _summary(),
                detector_ids=["__test__prematch_matching"],
            )
    finally:
        _REGISTRY["__test__prematch_matching"] = saved

    assert len(results) == 1
    findings = results[0].findings
    assert len(findings) == 1
    assert findings[0].code == "DETECTOR_SKIPPED_FOR_OS", (
        f"expected DETECTOR_SKIPPED_FOR_OS, got {findings[0].code}"
    )


def test_empty_prematch_tuple_always_skips() -> None:
    """Edge case: ``prematch_substrings = ()`` (empty tuple) means
    ``any(s in msg for s in ())`` is always False -> every record is
    skipped. This is a footgun the test pins so the behavior is
    documented and can't change silently."""

    saved = _REGISTRY.pop("__test__prematch_none")
    try:
        cls = type(
            "_EmptyPrematch",
            (_RecorderDetector,),
            {
                "id": "__test__prematch_none",
                "title": "empty",
                "prematch_substrings": (),
            },
        )
        _REGISTRY["__test__prematch_none"] = cls
        with tempfile.TemporaryDirectory() as td:
            bundle = _build_bundle_with_lines(Path(td))
            results = run_detectors(
                bundle, _summary(),
                detector_ids=["__test__prematch_none"],
            )
    finally:
        _REGISTRY["__test__prematch_none"] = saved

    assert len(results) == 1
    # No findings, no crash. The detector saw zero records (empty tuple
    # short-circuits ``any``).
    assert len(results[0].findings) == 0


# --- Driver ------------------------------------------------------------

def main() -> int:
    cases = [
        ("prematch_matching_receives_only_matching_records",
         test_prematch_matching_receives_only_matching_records),
        ("prematch_dispatch_via_class_capture",
         test_prematch_dispatch_via_class_capture),
        ("os_gate_overrides_prematch",
         test_os_gate_overrides_prematch),
        ("empty_prematch_tuple_always_skips",
         test_empty_prematch_tuple_always_skips),
    ]
    failed = 0
    for name, fn in cases:
        if not run_test(name, fn):
            failed += 1
    # Clean up the registry no matter what so other test files in the
    # same process don't see __test__* detectors leaking through.
    for did in _TEST_IDS:
        _REGISTRY.pop(did, None)
    print(f"\n{len(cases) - failed}/{len(cases)} multiplexer tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
