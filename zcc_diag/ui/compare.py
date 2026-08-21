"""
Bundle compare module — REMOVED in Phase 31 (2026-06-19).

This module previously implemented a side-by-side diff of two
analysed bundles. It was retired after Shameel confirmed it wasn't
being reached for on real triage tickets — the cross-bundle diffs
the engineer actually needs are already covered by Detected Issues
plus the Markdown export.

The file is kept as a tombstone (rather than deleted from Drive)
so any stale import in pycache or external integration fails
loudly with a clear message instead of silently routing to nothing.
"""

from __future__ import annotations


_REMOVED_MSG = (
    "zcc_diag.ui.compare was removed in Phase 31 (2026-06-19). "
    "If you're hitting this from production code, the sidebar "
    "should no longer offer 'Bundle Compare' — clear any stale "
    "?m=Bundle+Compare URL parameter and reload."
)


def module_compare(*_args, **_kwargs):
    raise ImportError(_REMOVED_MSG)


# Backwards-compat alias kept so a stale dispatcher branch raises
# the SAME error instead of an AttributeError.
_module_compare = module_compare
