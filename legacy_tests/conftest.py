"""
Pytest collection hook for BundleScope (Phase 43a, 2026-06-24).

The existing test_*.py files (36 of them) were written with a
``def main() -> int`` pattern: print PASS/FAIL counts to stdout,
return 0 on success and 1 on failure. They run standalone via
``python test_<name>.py``.

This conftest.py adds a uniform pytest wrapper so the whole suite
can run via:

    cd zcc_diag && pytest

It works by adding a synthetic ``test_main`` function to each module
during collection. When pytest invokes it, the function calls the
module's ``main()`` and asserts the return value is 0.

Test files that DO follow pytest conventions (``def test_*(): ...``)
are unaffected — they collect normally alongside the wrapper.

Bundle-driven tests (test_issues.py, test_summary.py, test_pii.py)
take a CLI arg for the bundle path. They are SKIPPED here unless a
``--bundle=<path>`` option is passed; see ``pytest_addoption``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# Files that require a --bundle arg to run meaningfully. They have a
# main() that calls sys.argv[1] for the bundle path. Without a bundle
# they'd crash on IndexError, so we skip them unless the arg is given.
_BUNDLE_DRIVEN_TESTS = frozenset({
    "test_issues",
    "test_summary",
    "test_pii",
})


def pytest_addoption(parser):
    """Expose --bundle=<path> so bundle-driven tests can run."""
    parser.addoption(
        "--bundle",
        action="store",
        default=None,
        help="Path to a ZCC support bundle (.zip) for bundle-driven tests.",
    )


def pytest_collect_file(parent, file_path: Path):
    """Collect test_*.py files that don't define any test_* functions
    by wrapping their main() with a pytest test.

    pytest's default collector handles the pytest-native files; we
    only step in for the legacy main()-pattern files.
    """
    if file_path.suffix != ".py":
        return None
    if not file_path.name.startswith("test_"):
        return None
    # Read first ~200 lines to decide whether the file has pytest-style
    # test functions or only main().
    try:
        head = file_path.read_text(encoding="utf-8", errors="replace")[:50_000]
    except OSError:
        return None
    has_test_funcs = any(
        line.startswith("def test_") for line in head.splitlines()
    )
    has_main = "def main(" in head and "if __name__ ==" in head
    if has_test_funcs or not has_main:
        return None  # pytest's default collector handles these
    return LegacyMainFile.from_parent(parent, path=file_path)


class LegacyMainFile(pytest.File):
    """A pytest File node that wraps a single legacy main()-pattern test."""

    def collect(self):
        module_stem = self.path.stem
        yield LegacyMainItem.from_parent(self, name=module_stem)


class LegacyMainItem(pytest.Item):
    """One pytest test item per legacy file: imports the module, calls
    main(), asserts return value is 0."""

    def runtest(self):
        # Skip bundle-driven tests unless --bundle was provided.
        bundle = self.config.getoption("--bundle") if hasattr(self, "config") else None
        if self.name in _BUNDLE_DRIVEN_TESTS:
            if not bundle:
                pytest.skip(
                    f"{self.name} needs --bundle=<path>; not provided"
                )
            self._run_main(bundle_path=bundle)
            return
        self._run_main(bundle_path=None)

    def _run_main(self, bundle_path=None):
        # Import the module from its file path. We use the runpy-ish
        # approach instead of __import__ because the test files live
        # alongside the package and may have name collisions if loaded
        # via the standard import machinery.
        import importlib.util
        import inspect
        spec = importlib.util.spec_from_file_location(
            f"_legacy_test.{self.path.stem}", self.path,
        )
        if spec is None or spec.loader is None:
            pytest.fail(f"Couldn't load module spec for {self.path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Inspect main()'s signature so we can call it correctly:
        #   - main()                       — legacy synthetic test, call with no args
        #   - main(zip_path)               — bundle-driven test, pass bundle_path
        #   - main(argv=None) / variants   — fall back to no-args
        main_fn = module.main
        try:
            sig = inspect.signature(main_fn)
            required_pos = [
                p for p in sig.parameters.values()
                if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                              inspect.Parameter.POSITIONAL_OR_KEYWORD)
                and p.default is inspect.Parameter.empty
            ]
        except (TypeError, ValueError):
            required_pos = []

        if required_pos:
            # main() needs at least one positional. Pass the bundle path
            # if we have one; skip if we don't.
            if bundle_path is None:
                pytest.skip(
                    f"{self.path.name} main() requires a positional arg "
                    f"(likely a bundle path); pass --bundle=<path>"
                )
            rc = main_fn(bundle_path)
        else:
            # ALSO wedge bundle path into sys.argv if available, in case
            # the legacy script reads sys.argv[1] internally regardless
            # of main()'s signature.
            saved_argv = sys.argv[:]
            if bundle_path is not None:
                sys.argv = [self.path.name, bundle_path]
            try:
                rc = main_fn()
            finally:
                sys.argv = saved_argv

        if rc not in (None, 0):
            pytest.fail(
                f"{self.path.name} main() returned {rc} (non-zero = failure)"
            )

    def repr_failure(self, excinfo):
        # Show a clean traceback rather than the conftest-internals.
        return excinfo.exconly()

    def reportinfo(self):
        return (self.path, 0, f"legacy_main:{self.name}")
