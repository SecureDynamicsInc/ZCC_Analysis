"""Shared UI primitives — Slice 9 (2026-08-14).

`st.metric` renders a very large value font and reserves a lot of
vertical space per field. That's right for a 4-tile KPI header and
wrong for a Facts page carrying 30+ fields: values like
`user@example.invalid` or `2026-08-11 17:02:07 UTC` overflow their
tile and get clipped, and the page becomes a long scroll of mostly
whitespace.

`kv_grid` renders the same information as a dense CSS-grid of
label/value pairs at normal body font. Long values are ellipsised with
the full text available on hover (`title=`), so nothing is silently
lost. An optional `source` line under each value carries provenance —
which matters here because a value can come either from a config blob
or from counted log evidence, and the engineer needs to know which.

Pure presentation. No extraction, no interpretation.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

import streamlit as st


# --------------------------------------------------------------------------
# Style — injected once per page via `inject_css()`
# --------------------------------------------------------------------------

GRID_CSS = """
<style>
:root {
    --la-accent: #25C2A0;
    --la-accent-2: #4FA3E3;
    --la-ink: #F7FAFC;
    --la-muted: #93A4B8;
    --la-panel: rgba(13, 26, 43, 0.82);
    --la-line: rgba(148, 163, 184, 0.17);
}

/* ---- Desktop application shell ---- */
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(circle at 74% -10%, rgba(37, 194, 160, 0.12), transparent 34rem),
        radial-gradient(circle at 8% 4%, rgba(79, 163, 227, 0.09), transparent 30rem),
        #07111f;
}
[data-testid="stHeader"] { background: transparent; }
[data-testid="stMainBlockContainer"] {
    max-width: 1540px;
    padding-top: 2rem;
    padding-bottom: 4rem;
}
#MainMenu, footer { visibility: hidden; }
[data-testid="stSkillsNudge"], [data-testid="stSkillsNudgeAnchor"] { display: none !important; }

.la-hero {
    position: relative;
    overflow: hidden;
    border: 1px solid var(--la-line);
    border-radius: 18px;
    padding: 28px 34px 30px;
    margin: 0 0 14px;
    background: linear-gradient(125deg, rgba(14, 29, 48, 0.98), rgba(8, 20, 36, 0.86));
    box-shadow: 0 20px 55px rgba(0, 0, 0, 0.23);
}
.la-hero::after {
    content: "";
    position: absolute;
    right: -80px;
    top: -150px;
    width: 420px;
    height: 420px;
    border: 1px solid rgba(37, 194, 160, 0.14);
    border-radius: 50%;
    box-shadow: 0 0 0 54px rgba(79, 163, 227, 0.025),
                0 0 0 110px rgba(37, 194, 160, 0.018);
}
.la-brand-row { display: flex; align-items: center; gap: 10px; position: relative; z-index: 1; }
.la-brand-mark {
    display: inline-grid; place-items: center; width: 28px; height: 28px;
    color: #07111f; background: var(--la-accent); border-radius: 8px;
    font-size: 14px; font-weight: 900;
}
.la-eyebrow { color: #ADC0D4; font-size: 11px; letter-spacing: .13em; font-weight: 700; }
.la-local-pill {
    margin-left: auto; color: #9FE8D8; background: rgba(37, 194, 160, .09);
    border: 1px solid rgba(37, 194, 160, .26); border-radius: 999px;
    padding: 5px 11px; font-size: 11px; font-weight: 700;
}
.la-hero h1 {
    position: relative; z-index: 1; margin: 22px 0 8px; color: var(--la-ink);
    font-size: 42px; line-height: 1.03; letter-spacing: -.035em; font-weight: 720;
}
.la-hero p {
    position: relative; z-index: 1; max-width: 760px; color: #A9B8C9;
    margin: 0; font-size: 16px; line-height: 1.55;
}
.la-pipeline { position: relative; z-index: 1; margin-top: 18px; color: #6F839A; font-size: 11px; }

.la-trustbar {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px;
    border: 1px solid var(--la-line); border-radius: 12px; overflow: hidden;
    margin: 0 0 18px; background: var(--la-line);
}
.la-trustbar > div { background: rgba(10, 24, 41, .93); padding: 14px 17px; min-width: 0; }
.la-trustbar strong { display: block; color: #DCE7F1; font-size: 12px; margin-bottom: 3px; }
.la-trustbar span { display: block; color: #71869C; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

[data-testid="stFileUploader"] {
    border: 1px solid rgba(79, 163, 227, .23);
    background: rgba(11, 25, 43, .74);
    border-radius: 14px;
    padding: 6px 10px 10px;
}
[data-testid="stFileUploaderDropzone"] {
    min-height: 118px; border: 1px dashed rgba(79, 163, 227, .42);
    background: rgba(79, 163, 227, .035); border-radius: 10px;
}
[data-testid="stFileUploaderDropzone"] button {
    border-color: rgba(37, 194, 160, .45); color: #C7F7EC;
}

.la-start-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 18px 0 12px; }
.la-start-grid-novice { grid-template-columns: repeat(2, 1fr); }
.la-start-card {
    position: relative; display: grid; grid-template-columns: max-content minmax(0, 1fr); column-gap: 10px;
    border: 1px solid var(--la-line); border-radius: 12px; padding: 17px 18px;
    background: rgba(12, 27, 46, .68);
}
.la-start-card b {
    grid-row: 1 / span 2; display: grid; place-items: center; align-self: start;
    min-width: 30px; width: max-content; height: 30px; padding: 0 9px;
    box-sizing: border-box; border-radius: 8px; color: #8BE1CE;
    background: rgba(37, 194, 160, .09); border: 1px solid rgba(37, 194, 160, .2);
}
.la-start-card strong { color: #DCE7F1; font-size: 13px; }
.la-start-card span { color: #71869C; font-size: 12px; line-height: 1.45; margin-top: 4px; }

/* ---- Readiness light (MaxMind endpoint ownership) ---- */
.la-status-card { height: 100%; }
.la-status-card b { background: rgba(37, 194, 160, .07); border-color: rgba(37, 194, 160, .18); }
.la-status-card-off b { background: rgba(239, 96, 96, .08); border-color: rgba(239, 96, 96, .24); }
.la-status-dot {
    display: block; width: 11px; height: 11px; border-radius: 50%;
}
.la-status-dot-ok {
    background: #22C55E;
    box-shadow: 0 0 0 3px rgba(34, 197, 94, .18), 0 0 9px rgba(34, 197, 94, .5);
}
.la-status-dot-off {
    background: #EF4444;
    box-shadow: 0 0 0 3px rgba(239, 68, 68, .16), 0 0 9px rgba(239, 68, 68, .45);
}
.la-status-line {
    display: flex; align-items: center; gap: 8px; margin: 2px 0 10px;
    color: #93A4B8; font-size: 12px;
}
.la-status-line .la-status-dot { flex: none; }
.la-view-map { display: flex; gap: 7px; justify-content: center; margin: 22px 0; }
.la-view-map span {
    color: #71869C; font-size: 9px; letter-spacing: .08em; border: 1px solid var(--la-line);
    background: rgba(9, 22, 38, .6); border-radius: 999px; padding: 5px 9px;
}
.la-input-summary {
    display: grid; grid-template-columns: 2fr 1fr .7fr .8fr; gap: 1px;
    overflow: hidden; border: 1px solid var(--la-line); border-radius: 11px;
    background: var(--la-line); margin: 16px 0 12px;
}
.la-input-summary > div { background: rgba(12, 27, 46, .9); padding: 10px 14px; min-width: 0; }
.la-input-summary span { display: block; color: #71869C; font-size: 9px; text-transform: uppercase; letter-spacing: .08em; }
.la-input-summary strong { display: block; color: #DCE7F1; font-size: 12px; margin-top: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Streamlit controls and tabs become a cohesive desktop workbench. */
[data-baseweb="select"] > div, [data-baseweb="input"] > div {
    background: rgba(11, 25, 43, .8); border-color: var(--la-line);
}
[data-baseweb="tab-list"] {
    gap: 4px; padding: 5px; border: 1px solid var(--la-line);
    border-radius: 11px; background: rgba(8, 20, 35, .8);
}
button[data-baseweb="tab"] { border-radius: 7px; padding-left: 16px; padding-right: 16px; }
button[data-baseweb="tab"][aria-selected="true"] {
    background: rgba(37, 194, 160, .09); color: #9FE8D8 !important;
}
div[data-baseweb="tab-highlight"] { display: none; }

/* ---- Dense key/value grid ---- */
.la-kv {
    display: grid;
    gap: 6px 14px;
    margin: 2px 0 12px 0;
}
.la-kv .cell {
    background: rgba(127, 168, 210, 0.07);
    border: 1px solid rgba(127, 168, 210, 0.18);
    border-radius: 6px;
    padding: 6px 10px 7px 10px;
    min-width: 0;              /* lets ellipsis work inside grid tracks */
    overflow: hidden;
}
.la-kv .k {
    font-size: 0.70rem;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    opacity: 0.62;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.la-kv .v {
    font-size: 0.95rem;
    font-weight: 600;
    line-height: 1.32;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-variant-numeric: tabular-nums;
}
.la-kv .v.muted  { opacity: 0.38; font-weight: 400; }
.la-kv .v.wrap   { white-space: normal; word-break: break-word; }
.la-kv .src {
    font-size: 0.66rem;
    opacity: 0.48;
    margin-top: 2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* ---- Section heading ---- */
.la-sec {
    font-size: 0.80rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    opacity: 0.75;
    margin: 14px 0 6px 0;
    padding-bottom: 3px;
    border-bottom: 1px solid rgba(127, 168, 210, 0.22);
}

/* ---- Inline chips ---- */
.la-chips { display: flex; flex-wrap: wrap; gap: 5px; margin: 2px 0 8px 0; }
.la-chip {
    font-size: 0.74rem;
    padding: 2px 8px;
    border-radius: 10px;
    background: rgba(127, 168, 210, 0.14);
    border: 1px solid rgba(127, 168, 210, 0.25);
    white-space: nowrap;
}
.la-chip .n { opacity: 0.6; margin-left: 4px; }

/* ---- Coverage bar ---- */
.la-bar {
    height: 7px; border-radius: 4px; overflow: hidden;
    background: rgba(127, 168, 210, 0.16); margin: 3px 0 2px 0;
}
.la-bar > span { display: block; height: 100%; background: var(--la-accent); }

/* ---- Guided findings ---- */
.la-finding {
    border: 1px solid var(--la-line); border-left: 4px solid #6B7F94;
    border-radius: 12px; padding: 15px 18px; margin: 10px 0;
    background: linear-gradient(120deg, rgba(11, 26, 44, .96), rgba(7, 18, 32, .92));
}
.la-finding-primary { padding: 20px 22px; margin: 14px 0 18px 0; }
.la-finding-critical { border-left-color: #FF667A; }
.la-finding-warning { border-left-color: #F4B860; }
.la-finding-info { border-left-color: #62A8EA; }
.la-finding-success { border-left-color: #25C2A0; }
.la-finding-top { display: flex; justify-content: space-between; gap: 16px; align-items: center; }
.la-finding-label { color: #91A7BC; text-transform: uppercase; letter-spacing: .08em; font-size: 10px; font-weight: 700; }
.la-finding-code { color: #70869B; font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; }
.la-finding h3 { margin: 8px 0 6px 0; color: #F2F7FB; font-size: 1.12rem; }
.la-finding-primary h3 { font-size: 1.45rem; }
.la-finding p { color: #C1CFDB; margin: 0 0 12px 0; line-height: 1.5; }
.la-evidence, .la-action { display: grid; grid-template-columns: 92px 1fr; gap: 10px; margin-top: 8px; font-size: 13px; }
.la-evidence b, .la-action b { color: #87A0B6; text-transform: uppercase; font-size: 10px; letter-spacing: .06em; padding-top: 2px; }
.la-action { padding: 10px 12px; border-radius: 8px; background: rgba(37, 194, 160, .08); }
.la-finding a { display: inline-block; margin-top: 10px; color: #7FDCC7 !important; font-size: 12px; }
.la-start-grid-compact { margin-bottom: 14px; }
.la-start-grid-compact .la-start-card { min-height: 108px; }

/* ---- Bundle recap + evidence checklist ---- */
.la-recap-grid {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px;
    border: 1px solid var(--la-line); border-radius: 11px; overflow: hidden;
    background: var(--la-line); margin: 4px 0 10px;
}
.la-recap-cell { background: rgba(12, 27, 46, .9); padding: 10px 14px; min-width: 0; }
.la-recap-cell span {
    display: block; color: #71869C; font-size: 9px; text-transform: uppercase;
    letter-spacing: .08em;
}
.la-recap-cell strong {
    display: block; color: #DCE7F1; font-size: 12.5px; margin-top: 3px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.la-recap-muted strong { color: #6F839A; font-style: italic; font-size: 11.5px; }

.la-check-row {
    display: grid; grid-template-columns: 22px minmax(0, 1fr); gap: 10px;
    padding: 9px 2px; border-bottom: 1px solid rgba(148, 163, 184, .09);
}
.la-check-row:last-child { border-bottom: 0; }
.la-check-mark { font-size: 14px; line-height: 1.3; text-align: center; }
.la-check-on .la-check-mark { color: #22C55E; }
.la-check-off .la-check-mark { color: #64748B; }
.la-check-row strong { display: block; color: #DCE7F1; font-size: 12.5px; }
.la-check-off strong { color: #93A4B8; }
.la-check-row em {
    display: block; color: #6F839A; font-size: 10.5px; font-style: normal;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2px 0 3px;
}
.la-check-row span { display: block; color: #A9B8C9; font-size: 11.5px; line-height: 1.45; }
.la-check-off span { color: #8194A8; }
.la-check-reach { color: #7FDCC7 !important; margin-top: 3px; }

/* ---- PAC source view: editor-accurate JavaScript rendering ----
 *
 * Streamlit renders st.code through react-syntax-highlighter, so the token
 * classes below are Prism's, not Pygments'. Everything is scoped to
 * `language-javascript`, which in this app is only the PAC source view, so
 * log samples and Wireshark filters keep the app's own styling.
 *
 * `tab-size` is as much the point as the colours. Streamlit inherits the
 * browser default of 8, and a PAC that indents with tabs — the measured MSSP
 * template mixes tabs and spaces — then renders at twice the depth an editor
 * shows. VSCode's default is 4, so tab- and space-indented lines only line up
 * with each other at that setting.
 *
 * One unavoidable difference: Prism emits a single `keyword` class, so `var`
 * and `function` take the control-flow colour here. VSCode splits them
 * (#569CD6 for declarations, #C586C0 for control flow) and CSS cannot.
 */
/* line-height is editor-tight on purpose. Streamlit's code default is airy
 * enough that a PAC's own blank lines read as double spacing, which makes a
 * 400-line file far taller than the same file in an editor. */
code.language-javascript {
    tab-size: 4;
    -moz-tab-size: 4;
    line-height: 1.35 !important;
}
code.language-javascript span { line-height: 1.35 !important; }
pre:has(code.language-javascript) {
    background: #1E1E1E !important;
    border: 1px solid rgba(148, 163, 184, .18);
    border-radius: 10px;
    line-height: 1.35 !important;
}
code.language-javascript,
code.language-javascript span:not([class*="token"]) { color: #D4D4D4 !important; }
code.language-javascript .token.comment { color: #6A9955 !important; font-style: italic; }
code.language-javascript .token.keyword { color: #C586C0 !important; }
code.language-javascript .token.function,
code.language-javascript .token.maybe-class-name,
code.language-javascript .token.class-name { color: #DCDCAA !important; }
code.language-javascript .token.string,
code.language-javascript .token.template-string { color: #CE9178 !important; }
code.language-javascript .token.number { color: #B5CEA8 !important; }
code.language-javascript .token.boolean,
code.language-javascript .token.constant,
code.language-javascript .token.builtin { color: #569CD6 !important; }
code.language-javascript .token.operator,
code.language-javascript .token.punctuation { color: #D4D4D4 !important; }
code.language-javascript .token.parameter,
code.language-javascript .token.property,
code.language-javascript .token.variable { color: #9CDCFE !important; }
/* Declared after `keyword` on purpose: a regex's internal alternation carries
 * both classes, and the regex colour has to win inside a literal. */
code.language-javascript .token.regex,
code.language-javascript .token.regex-delimiter,
code.language-javascript .token.regex-source,
code.language-javascript .token.regex-flags { color: #D16969 !important; }
/* `span.linenumber`, not `.linenumber`: the base rule above is
 * `span:not([class*="token"])`, whose attribute selector makes it more
 * specific than a lone class, so the gutter would otherwise inherit the
 * foreground colour and compete with the code. */
code.language-javascript span.linenumber {
    color: #6E7681 !important;
    min-width: 3.4em !important;
    padding-right: 1.2em !important;
}

/* ---- Global density trims ---- */
div[data-testid="stDataFrame"] { font-size: 0.86rem; }
button[data-baseweb="tab"] { font-size: 0.92rem; font-weight: 600; }
button[data-baseweb="tab"][aria-selected="true"] { color: var(--la-accent); }
</style>
"""

LIGHT_THEME_CSS = """
<style>
:root {
    --la-accent: #087F6B;
    --la-accent-2: #216EA6;
    --la-ink: #182536;
    --la-muted: #5E7084;
    --la-panel: rgba(255, 255, 255, .94);
    --la-line: rgba(40, 61, 82, .16);
}
[data-testid="stAppViewContainer"] {
    color: var(--la-ink);
    background:
        radial-gradient(circle at 74% -10%, rgba(8, 127, 107, .10), transparent 34rem),
        radial-gradient(circle at 8% 4%, rgba(33, 110, 166, .08), transparent 30rem),
        #F4F7FA !important;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li, [data-testid="stMetricValue"],
[data-testid="stMetricLabel"] { color: var(--la-ink) !important; }
h1, h2, h3, h4, h5, h6 { color: #182536 !important; }
[data-testid="stExpander"] details,
[data-testid="stExpander"] summary {
    background: #FFFFFF !important;
    color: #182536 !important;
}
[data-testid="stExpander"] summary p,
[data-testid="stExpander"] summary span,
[data-testid="stExpander"] summary svg {
    color: #182536 !important;
    fill: #182536 !important;
}
[data-testid="stExpander"] details { border-color: rgba(40, 61, 82, .22) !important; }
.la-hero {
    background: linear-gradient(125deg, rgba(255, 255, 255, .98), rgba(238, 247, 247, .96));
    box-shadow: 0 18px 45px rgba(44, 62, 80, .10);
}
.la-eyebrow { color: #53687C; }
.la-local-pill { color: #086E5D; background: rgba(8, 127, 107, .08); border-color: rgba(8, 127, 107, .22); }
.la-hero p { color: #526579; }
.la-pipeline { color: #718295; }
[data-testid="stFileUploader"], [data-testid="stFileUploader"] section,
[data-testid="stFileUploaderDropzone"] {
    background: rgba(255, 255, 255, .74) !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] span { color: #5E7084 !important; }
[data-testid="stFileUploaderDropzone"] [data-testid="stBaseButton-secondary"] {
    color: #086E5D !important; background: #FFFFFF !important; border-color: rgba(8, 127, 107, .28) !important;
}
[data-testid="stFileUploaderDropzone"] [data-testid="stBaseButton-secondary"] p { color: #086E5D !important; }
.la-start-card, .la-input-summary > div {
    background: rgba(255, 255, 255, .90);
    box-shadow: 0 5px 18px rgba(40, 61, 82, .04);
}
.la-start-card b { color: #086E5D; background: rgba(8, 127, 107, .08); border-color: rgba(8, 127, 107, .18); }
.la-start-card strong, .la-input-summary strong { color: #213246; }
.la-start-card span, .la-input-summary span { color: #64768A; }
.la-recap-cell { background: rgba(255, 255, 255, .92); }
.la-recap-cell span { color: #64768A; }
.la-recap-cell strong { color: #213246; }
.la-recap-muted strong { color: #75879A; }
.la-check-row { border-bottom-color: rgba(40, 61, 82, .10); }
.la-check-row strong { color: #213246; }
.la-check-off strong { color: #56697D; }
.la-check-row em { color: #75879A; }
.la-check-row span { color: #405368; }
.la-check-off span { color: #5E7084; }
.la-check-on .la-check-mark { color: #15803D; }
.la-check-reach { color: #08705F !important; }
.la-status-card-off b { background: rgba(198, 40, 40, .07); border-color: rgba(198, 40, 40, .2); }
.la-status-dot-ok { background: #15803D; box-shadow: 0 0 0 3px rgba(21, 128, 61, .14); }
.la-status-dot-off { background: #C62828; box-shadow: 0 0 0 3px rgba(198, 40, 40, .13); }
.la-status-line { color: #5E7084; }
[data-baseweb="select"] > div, [data-baseweb="input"] > div {
    background: #FFFFFF !important; border-color: var(--la-line) !important;
}
[data-baseweb="select"] *, [data-baseweb="input"] input { color: #182536 !important; }
[data-baseweb="tab-list"] { background: rgba(255, 255, 255, .88); }
button[data-variant="segmented_control"] { background: #FFFFFF !important; color: #405368 !important; }
button[data-variant="segmented_control"] p { color: #405368 !important; }
button[data-variant="segmented_control"][data-selected="true"] {
    background: rgba(8, 127, 107, .12) !important; color: #086E5D !important;
}
button[data-variant="segmented_control"][data-selected="true"] p { color: #086E5D !important; }
button[data-baseweb="tab"] { color: #53667A !important; }
button[data-baseweb="tab"][aria-selected="true"] { background: rgba(8, 127, 107, .09); color: #086E5D !important; }
.la-kv .cell, .la-chip { background: rgba(33, 110, 166, .06); border-color: rgba(33, 110, 166, .15); }
.la-finding {
    background: linear-gradient(120deg, rgba(255, 255, 255, .98), rgba(245, 249, 251, .96));
    box-shadow: 0 7px 22px rgba(40, 61, 82, .05);
}
.la-finding h3 { color: #182536; }
.la-finding p { color: #405368; }
.la-finding-label, .la-evidence b, .la-action b { color: #60758A; }
.la-finding-code { color: #75879A; }
.la-action { background: rgba(8, 127, 107, .08); }
.la-finding a { color: #08705F !important; }
[data-testid="stAlert"] { background: rgba(255, 255, 255, .78) !important; color: #213246 !important; }
[data-testid="stDataFrame"] { background: #FFFFFF; border-radius: 8px; }
hr { border-color: var(--la-line) !important; }

/* PAC source view in light mode, following the editor's light theme. */
pre:has(code.language-javascript) {
    background: #FFFFFF !important;
    border-color: rgba(40, 61, 82, .18);
}
code.language-javascript,
code.language-javascript span:not([class*="token"]) { color: #1F1F1F !important; }
code.language-javascript .token.comment { color: #008000 !important; }
code.language-javascript .token.keyword { color: #AF00DB !important; }
code.language-javascript .token.function,
code.language-javascript .token.maybe-class-name,
code.language-javascript .token.class-name { color: #795E26 !important; }
code.language-javascript .token.string,
code.language-javascript .token.template-string { color: #A31515 !important; }
code.language-javascript .token.number { color: #098658 !important; }
code.language-javascript .token.boolean,
code.language-javascript .token.constant,
code.language-javascript .token.builtin { color: #0000FF !important; }
code.language-javascript .token.operator,
code.language-javascript .token.punctuation { color: #1F1F1F !important; }
code.language-javascript .token.parameter,
code.language-javascript .token.property,
code.language-javascript .token.variable { color: #001080 !important; }
code.language-javascript .token.regex,
code.language-javascript .token.regex-delimiter,
code.language-javascript .token.regex-source,
code.language-javascript .token.regex-flags { color: #811F3F !important; }
code.language-javascript span.linenumber { color: #9098A0 !important; }
</style>
"""

_CSS_RUN_ID = "_la_css_run_id"


def inject_css(theme: Optional[str] = None) -> None:
    """Emit `GRID_CSS` at most once per script run.

    Streamlit rebuilds the DOM on every rerun, so the stylesheet does
    have to be re-emitted each time — but several tabs call this and a
    naive "always emit" put three identical <style> blocks into the
    page per rerun. Tracking the current run's id lets the first caller
    win and the rest no-op, which is both correct across reruns and
    idempotent within one.
    """
    try:
        ctx = st.runtime.scriptrunner.get_script_run_ctx()
        run_id = id(ctx) if ctx is not None else None
    except Exception:  # noqa: BLE001 - older/newer Streamlit internals
        run_id = None

    if run_id is not None:
        if st.session_state.get(_CSS_RUN_ID) == run_id:
            return
        st.session_state[_CSS_RUN_ID] = run_id

    selected = theme or ("light" if st.session_state.get("light_mode") else "dark")
    st.markdown(
        GRID_CSS + (LIGHT_THEME_CSS if selected == "light" else ""),
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------
# Key/value grid
# --------------------------------------------------------------------------

@dataclass
class KV:
    """One label/value cell.

    `source` — short provenance note rendered under the value
               (e.g. "tray log x412" or "App Profile").
    `wrap`   — allow the value to wrap onto multiple lines instead of
               ellipsising. Use for genuinely long free text.
    """
    label: str
    value: Optional[str]
    source: str = ""
    wrap: bool = False


_PLACEHOLDER = "—"  # em dash — "no evidence for this field"


def kv_grid(items: Sequence[KV], columns: int = 4) -> None:
    """Render `items` as a dense responsive grid of label/value cells.

    A `None` or empty value renders as an em dash in muted styling —
    never as "unknown" or "N/A", which would read as an extracted
    finding rather than an absence of evidence.
    """
    items = [i for i in items if i is not None]
    if not items:
        return

    parts: List[str] = [
        f'<div class="la-kv" style="grid-template-columns:'
        f'repeat({max(1, columns)}, minmax(0, 1fr));">'
    ]
    for it in items:
        raw = it.value
        missing = raw is None or str(raw).strip() == ""
        shown = _PLACEHOLDER if missing else str(raw)
        cls = "v muted" if missing else ("v wrap" if it.wrap else "v")
        esc_val = html.escape(shown)
        # title= carries the untruncated value so ellipsised cells stay
        # fully readable on hover.
        title = "" if missing else f' title="{html.escape(str(raw))}"'
        src = (f'<div class="src">{html.escape(it.source)}</div>'
               if it.source else "")
        parts.append(
            f'<div class="cell">'
            f'<div class="k">{html.escape(it.label)}</div>'
            f'<div class="{cls}"{title}>{esc_val}</div>'
            f'{src}</div>'
        )
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def section(title: str) -> None:
    """A compact section heading — quieter and tighter than
    `st.subheader`, which is oversized for a page with many sections."""
    st.markdown(
        f'<div class="la-sec">{html.escape(title)}</div>',
        unsafe_allow_html=True,
    )


def chips(pairs: Iterable[tuple], limit: int = 40) -> None:
    """Render `(label, count)` pairs as inline chips — a compact way to
    show a distribution (levels, components, lanes) without spending a
    whole dataframe on it."""
    items = list(pairs)[:limit]
    if not items:
        return
    parts = ['<div class="la-chips">']
    for label, count in items:
        parts.append(
            f'<span class="la-chip">{html.escape(str(label))}'
            f'<span class="n">{count:,}</span></span>'
        )
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def bar(pct: float) -> None:
    """A thin horizontal fill bar for a 0-100 percentage."""
    pct = max(0.0, min(100.0, float(pct)))
    st.markdown(
        f'<div class="la-bar"><span style="width:{pct:.1f}%"></span></div>',
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------
# Formatters shared across views
# --------------------------------------------------------------------------

def fmt_bytes(n: Optional[int]) -> Optional[str]:
    if n is None:
        return None
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(f) < 1024:
            return f"{int(f)} B" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024.0
    return f"{f:.1f} PB"


def fmt_ts(ts) -> Optional[str]:
    if ts is None:
        return None
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_duration(seconds: Optional[float]) -> Optional[str]:
    if seconds is None:
        return None
    total = int(seconds)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def fmt_count(n: Optional[int]) -> Optional[str]:
    return None if n is None else f"{n:,}"
