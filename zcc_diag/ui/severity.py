"""
Severity colour / badge / tag helpers.

A finding's severity drives several visual treatments across the UI:
  * HTML badges with bg/fg colour pairs
  * Plain-text tags for expander labels (where HTML doesn't render)
  * CSS class names used by the card stylesheet
  * Emoji shortcuts for inline use

Keeping all severity decoration in one module ensures consistency --
the colour scheme can be tweaked here without hunting through render
sites scattered across the codebase.
"""

from __future__ import annotations

from zcc_diag.issues import Severity


# Light-fg / dark-bg pairs used in the HTML badge below. Chosen to
# match the design tokens defined in ``ui.styles``.
SEV_COLORS = {
    Severity.CRITICAL: ("#FCEBEB", "#501313"),
    Severity.WARNING:  ("#FAEEDA", "#412402"),
    Severity.INFO:     ("#E6F1FB", "#042C53"),
}

# Plain-text severity word — used everywhere HTML can't render.
# Examples: ``st.expander`` labels (Streamlit strips HTML there),
# ``st.dataframe`` cells, plain markdown bodies. Sentence-case so it
# reads as a label rather than a console tag — "Critical" / "Warning"
# / "Info", NOT [CRIT] / [WARN] / [INFO].
#
# ``SEV_WORD`` is the preferred name; ``SEV_TAG`` is the legacy alias
# kept until callers migrate.
SEV_WORD = {
    Severity.CRITICAL: "Critical",
    Severity.WARNING:  "Warning",
    Severity.INFO:     "Info",
}
SEV_TAG = SEV_WORD  # legacy alias

# CSS class fragment appended to the finding card div. Maps to
# ``.zd-finding.crit``, ``.zd-finding.warn``, ``.zd-finding.info`` in
# ``ui.styles``.
SEV_CLS = {
    Severity.CRITICAL: "crit",
    Severity.WARNING:  "warn",
    Severity.INFO:     "info",
}

# Legacy alias — ``sev_emoji()`` used to return a coloured dot. Now
# returns the same word as ``SEV_WORD`` so any straggling call site
# stays consistent with the rest of the UI.
SEV_EMOJI = SEV_WORD


def sev_badge_html(sev: Severity) -> str:
    """HTML-styled badge. Only safe inside
    ``st.markdown(..., unsafe_allow_html=True)``."""
    bg, fg = SEV_COLORS[sev]
    return (
        f'<span style="background:{bg};color:{fg};font-size:11px;'
        f'padding:2px 8px;border-radius:4px;font-weight:500;">'
        f'{sev.value}</span>'
    )


def sev_tag(sev: Severity) -> str:
    """Plain-text severity tag. Safe everywhere (expander labels,
    subheaders, plain-text contexts)."""
    return SEV_TAG[sev]


def sev_emoji(sev: Severity) -> str:
    """Single-glyph severity indicator."""
    return SEV_EMOJI.get(sev, "•")


# Aliases for backwards compatibility with the old underscore-prefixed
# names that existed inside zcc_diag_ui.py. New code should use the
# public names above.
_sev_badge_html = sev_badge_html
_sev_tag = sev_tag
_SEV_CLS = SEV_CLS
_SEV_WORD = SEV_WORD
