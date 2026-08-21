"""
CSS injection — embedded Python string.

We had a brief experiment storing the CSS in a sibling ``styles.css``
file so editors could lint it. That broke on Drive Stream / network
filesystems where ``Path(__file__).parent / "styles.css"`` could read
0 bytes due to sync timing.

Embedding the CSS as a Python triple-quoted string is bulletproof:
the module-load step guarantees the string is in memory before
Streamlit ever calls ``inject_css()``. The ``styles.css`` file is
kept as a reference / linting source but is NOT what gets injected
at runtime.
"""

from __future__ import annotations

import streamlit as st


_CSS = """
/* Tighter page padding, more usable horizontal area. */
.block-container { padding-top: 1.0rem; padding-bottom: 2rem; max-width: 95rem; }
section[data-testid="stSidebar"] > div { padding-top: 1rem; }
section[data-testid="stSidebar"] .stRadio > div { gap: 0.4rem; }
h1#main-title { display: none; }

/* ---------- Design tokens ---------- */
:root {
  --zd-crit-accent: #e85d6f;
  --zd-crit-accent-muted: #c47681;
  --zd-warn-accent: #d6a154;
  --zd-info-accent: #6a96c9;
  --zd-ok-accent:   #6ba87f;
  --zd-crit-fill: rgba(195, 60, 80, 0.08);
  --zd-warn-fill: rgba(195, 145, 60, 0.07);
  --zd-info-fill: rgba(80, 130, 195, 0.06);
  --zd-ok-fill:   rgba(70, 145, 100, 0.06);
  --zd-text:       #e6eaf2;
  --zd-text-mute:  rgba(230, 234, 242, 0.72);
  --zd-text-dim:   rgba(230, 234, 242, 0.50);
  --zd-text-fade:  rgba(230, 234, 242, 0.35);
  --zd-surface-1: rgba(255, 255, 255, 0.025);
  --zd-surface-2: rgba(255, 255, 255, 0.045);
  --zd-divider:   rgba(255, 255, 255, 0.08);
  --zd-size-title:    22px;
  --zd-size-section:  16px;
  --zd-size-subhead:  13px;
  --zd-size-body:     14px;
  --zd-size-caption:  12px;
  --zd-size-code:     13px;
}

/* ---------- Title row ---------- */
.zd-titlebar {
  display: flex; align-items: baseline; gap: 0.85rem;
  margin: 0.25rem 0 1rem 0;
  border-bottom: 1px solid var(--zd-divider);
  padding-bottom: 0.8rem;
}
.zd-titlebar .name {
  font-size: var(--zd-size-title); font-weight: 600;
  color: var(--zd-text); letter-spacing: -0.015em; line-height: 1;
}
.zd-titlebar .tagline {
  font-size: var(--zd-size-caption); color: var(--zd-text-dim);
}

/* ---------- Header strip (3 rows × 3 cols) ---------- */
.zd-header {
  padding: 0.9rem 1.1rem; margin-bottom: 1.1rem;
  background: rgba(40, 50, 70, 0.40);
  border: 1px solid rgba(255,255,255,0.08); border-radius: 8px;
}
.zd-header .zd-header-row {
  display: grid;
  grid-template-columns: minmax(0, 1.6fr) minmax(0, 2.4fr) minmax(0, 2.0fr);
  gap: 1.4rem;
}
.zd-header .zd-header-row + .zd-header-row {
  margin-top: 0.7rem; padding-top: 0.7rem;
  border-top: 1px dashed rgba(255,255,255,0.07);
}
.zd-header .cell { min-width: 0; }
.zd-header .cell .lbl {
  font-size: 10px; color: rgba(255,255,255,0.50);
  letter-spacing: 0.07em; text-transform: uppercase;
  margin-bottom: 4px; font-weight: 500;
}
.zd-header .cell .val {
  font-size: 13.5px; font-weight: 600; color: #e6eaf2;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  line-height: 1.3;
}

/* ---------- Severity badges ---------- */
.sev {
  display: inline-block; padding: 2px 8px; border-radius: 3px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.04em;
  vertical-align: middle; color: #fff;
}
.sev.crit { background: var(--zd-crit-accent); }
.sev.warn { background: var(--zd-warn-accent); }
.sev.info { background: var(--zd-info-accent); }
.sev.ok   { background: var(--zd-ok-accent); }

/* ---------- Legacy compact finding row ---------- */
.zd-finding {
  border: 1px solid var(--zd-divider);
  border-left: 4px solid var(--zd-text-fade);
  border-radius: 8px; padding: 0.85rem 1rem 0.5rem 1rem;
  margin-bottom: 0.75rem; background: var(--zd-surface-1);
}
.zd-finding.crit { border-left-color: var(--zd-crit-accent); }
.zd-finding.warn { border-left-color: var(--zd-warn-accent); }
.zd-finding.info { border-left-color: var(--zd-info-accent); }
.zd-finding-head { display: flex; align-items: flex-start; gap: 0.6rem; flex-wrap: wrap; }
.zd-finding-title {
  flex: 1 1 auto; font-size: var(--zd-size-body); font-weight: 600;
  color: var(--zd-text); line-height: 1.35;
}
.zd-finding-meta-row {
  flex: 1 1 100%; display: flex; gap: 0.9rem; margin-top: 4px;
  color: var(--zd-text-dim); font-size: var(--zd-size-caption);
}
.zd-finding-code {
  font-family: ui-monospace, Consolas, monospace; color: var(--zd-text-dim);
}
.zd-finding-when { color: var(--zd-text-fade); }
/* Confidence pill in the metadata row. Subtle by design — sits at
   caption size next to the timestamp. Three tiers map to opacity +
   weight so "high confidence" reads as solid + present and "low
   confidence" recedes. Colour is identical across tiers so it
   doesn't fight the severity badge for the eye. */
.zd-finding-conf {
  font-size: var(--zd-size-caption);
  font-weight: 500;
  letter-spacing: 0.01em;
}
.zd-finding-conf.zd-conf-high   { color: var(--zd-text-mute); }
.zd-finding-conf.zd-conf-medium { color: var(--zd-text-dim);  }
.zd-finding-conf.zd-conf-low    { color: var(--zd-text-fade); font-style: italic; }
.zd-finding-count {
  margin-left: auto; align-self: flex-start; padding: 1px 8px;
  background: var(--zd-surface-2); border: 1px solid var(--zd-divider);
  border-radius: 10px; font-size: 11px; font-weight: 600;
  color: var(--zd-text-mute); white-space: nowrap;
}

/* ---------- Path-health pills ---------- */
.zd-pill {
  display: inline-block; padding: 1px 7px; border-radius: 10px;
  font-size: 11px; font-weight: 600;
}
.zd-pill.ok   { background: var(--zd-ok-fill);   color: var(--zd-ok-accent); }
.zd-pill.warn { background: var(--zd-warn-fill); color: var(--zd-warn-accent); }
.zd-pill.bad  { background: var(--zd-crit-fill); color: var(--zd-crit-accent); }

/* ---------- Section sub-headers ---------- */
.zd-section {
  font-size: var(--zd-size-section); color: var(--zd-text);
  margin: 1.5rem 0 0.6rem 0; font-weight: 600;
  letter-spacing: -0.005em; padding-left: 10px;
  border-left: 3px solid var(--zd-divider);
}

/* ---------- Modern finding card ---------- */
.zd-finding-card {
  background: var(--zd-surface-1); border: 1px solid var(--zd-divider);
  border-left-width: 4px; border-radius: 8px;
  padding: 14px 18px; margin: 18px 0;
}
.zd-finding-card .zd-finding-title {
  font-size: var(--zd-size-body); font-weight: 600; margin-bottom: 4px;
}
.zd-finding-card .zd-finding-meta {
  font-size: var(--zd-size-caption); color: var(--zd-text-dim); margin-top: 6px;
}
.zd-finding-card.zd-sev-bad,
.zd-finding-card.zd-sev-critical {
  border-left-color: var(--zd-crit-accent); background: var(--zd-crit-fill);
}
.zd-finding-card.zd-sev-warn,
.zd-finding-card.zd-sev-warning {
  border-left-color: var(--zd-warn-accent); background: var(--zd-warn-fill);
}
.zd-finding-card.zd-sev-info {
  border-left-color: var(--zd-info-accent); background: var(--zd-info-fill);
}
.zd-finding-card.zd-sev-ok {
  border-left-color: var(--zd-ok-accent); background: var(--zd-ok-fill);
}

/* ---------- Severity overview tiles ---------- */
.zd-sev-tiles {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 14px; margin: 6px 0 14px 0;
}
.zd-sev-tile {
  background: var(--zd-surface-1); border: 1px solid var(--zd-divider);
  border-radius: 10px; padding: 14px 18px;
}
.zd-sev-tile .zd-sev-tile-label {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--zd-text-dim); margin-bottom: 6px;
}
.zd-sev-tile .zd-sev-tile-value {
  font-size: 28px; font-weight: 600; line-height: 1.1; color: var(--zd-text);
}
.zd-sev-tile.zd-tile-crit.has-value { background: var(--zd-crit-fill); border-color: rgba(232, 93, 111, 0.32); }
.zd-sev-tile.zd-tile-crit.has-value .zd-sev-tile-value { color: var(--zd-crit-accent); }
.zd-sev-tile.zd-tile-warn.has-value { background: var(--zd-warn-fill); border-color: rgba(214, 161, 84, 0.30); }
.zd-sev-tile.zd-tile-warn.has-value .zd-sev-tile-value { color: var(--zd-warn-accent); }
.zd-sev-tile.zd-tile-info.has-value { background: var(--zd-info-fill); border-color: rgba(106, 150, 201, 0.30); }
.zd-sev-tile.zd-tile-info.has-value .zd-sev-tile-value { color: var(--zd-info-accent); }

/* ---------- Timeline (Overview swim-lane view) ---------- */
/* Horizontal time-axis layout: one row per detector group, bars
   positioned absolutely within each row's track. The 140px label
   column is fixed so multiple lanes line up; the track is fluid so
   bars rescale with the container. */
.zd-tl {
  margin: 12px 0 18px 0;
  padding: 14px 16px;
  background: var(--zd-surface-1);
  border: 1px solid var(--zd-divider);
  border-radius: 8px;
}
.zd-tl-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  font-size: 11.5px;
  color: var(--zd-text-dim);
  margin-bottom: 12px;
  gap: 1rem;
  flex-wrap: wrap;
}
.zd-tl-header strong {
  color: var(--zd-text-mute);
  font-weight: 600;
}
.zd-tl-header em {
  font-style: italic;
  color: var(--zd-text-fade);
}
.zd-tl-grid {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.zd-tl-lane {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 12px;
  align-items: center;
}
.zd-tl-lane-label {
  font-size: 11.5px;
  color: var(--zd-text-mute);
  text-align: right;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.zd-tl-track {
  position: relative;
  height: 22px;
  background: rgba(255, 255, 255, 0.025);
  border-radius: 3px;
  border: 1px solid rgba(255, 255, 255, 0.04);
}
/* Severity drives visual weight: Critical is tall + fully opaque,
   Info recedes into the background. The track is 22px; each tier is
   vertically centred. Sizes and colours are carried via CSS custom
   properties so the same severity class works on either a solid bar
   (sustained condition) or an occurrence dot (discrete event) without
   colour drift between shapes. */
.zd-tl-sev-bad  { --h: 14px; --tt: 4px;   opacity: 1.00; z-index: 3; --c: var(--zd-crit-accent); }
.zd-tl-sev-warn { --h: 10px; --tt: 6px;   opacity: 0.88; z-index: 2; --c: var(--zd-warn-accent); }
/* Info was 0.55 opacity — too dim on a dark canvas, small Info dots
   blended into the surface. 0.72 keeps them subordinate to Crit/Warn
   without disappearing. */
.zd-tl-sev-info { --h: 7px;  --tt: 7.5px; opacity: 0.72; z-index: 1; --c: var(--zd-info-accent); }

/* Solid bar — a single sustained-condition finding spanning a real
   duration (e.g. "tunnel was down from T1 to T2"). */
.zd-tl-bar {
  position: absolute;
  top: var(--tt);
  height: var(--h);
  border-radius: 2px;
  background: var(--c);
  cursor: default;
  transition: filter 0.12s;
}
.zd-tl-bar:hover { filter: brightness(1.35); z-index: 10; }

/* Occurrence dot — one circular mark per actual event. Used when a
   finding has count > 1 with usable evidence timestamps; we plot one
   dot per evidence ts at its precise moment instead of a span. The
   ``transform: translateX(-50%)`` anchors the dot CENTRE on the
   timestamp rather than the left edge, which reads more accurately. */
.zd-tl-dot-mark {
  position: absolute;
  top: var(--tt);
  width: var(--h);
  height: var(--h);
  border-radius: 50%;
  background: var(--c);
  transform: translateX(-50%);
  cursor: default;
  transition: filter 0.12s;
}
.zd-tl-dot-mark:hover { filter: brightness(1.35); z-index: 10; }

/* Cluster marker — a dot that visually represents N events at the
   same position. A thin outer ring distinguishes it from a singleton
   so the eye reads "this point has density" without re-introducing
   the blob shape we just got rid of. The colour-matched halo uses
   the severity ``--c`` so it tracks Critical/Warning/Info tinting. */
.zd-tl-dot-mark.zd-tl-cluster {
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--c) 35%, transparent);
}
/* Axis row: same 2-col layout as a lane so ticks line up under the
   tracks. Label column is empty (track lanes already labelled). */
.zd-tl-axis {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 12px;
  margin-top: 8px;
  font-size: 10.5px;
  color: var(--zd-text-fade);
}
.zd-tl-axis-label {}
.zd-tl-axis-track {
  position: relative;
  height: 14px;
  border-top: 1px dashed rgba(255, 255, 255, 0.07);
}
.zd-tl-tick {
  position: absolute;
  top: 3px;
  transform: translateX(-50%);
  white-space: nowrap;
  font-feature-settings: "tnum";  /* tabular numerals for alignment */
}
/* First / last ticks abut the track edges — anchor them so the text
   doesn't clip off the container. */
.zd-tl-tick:first-child { transform: translateX(0); }
.zd-tl-tick:last-child  { transform: translateX(-100%); }

/* ---------- Streamlit widget tweaks ---------- */
div[data-testid="stStatus"] { border-radius: 8px; margin-bottom: 0.5rem !important; }
[data-testid="stMetricValue"] {
  font-size: 28px; font-weight: 600; color: var(--zd-text);
}
[data-testid="stMetricLabel"] {
  font-size: 12px; color: var(--zd-text-dim);
  text-transform: uppercase; letter-spacing: 0.05em;
}
[data-testid="stCaptionContainer"],
[data-testid="stCaption"] {
  font-size: var(--zd-size-caption); color: var(--zd-text-dim);
}
[data-testid="stMarkdownContainer"] p { font-size: var(--zd-size-body); line-height: 1.55; }
[data-testid="stMarkdownContainer"] code,
[data-testid="stCodeBlock"] { font-size: var(--zd-size-code); }
h1 a, h2 a, h3 a { display: none !important; }
h1, h2, h3 { color: var(--zd-text); letter-spacing: -0.01em; }
h1 { font-size: var(--zd-size-title); font-weight: 600; }
h2 { font-size: var(--zd-size-section); font-weight: 600; }
h3 {
  font-size: var(--zd-size-subhead); font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--zd-text-mute);
}

/* ---------- Sidebar -- compact nav, slim uploader ---------- */
section[data-testid="stSidebar"] > div {
  padding-top: 1rem !important;
  padding-left: 0.85rem !important;
  padding-right: 0.85rem !important;
}
section[data-testid="stSidebar"] h3 {
  font-size: 11px !important; color: var(--zd-text-dim) !important;
  text-transform: uppercase; letter-spacing: 0.08em;
  margin: 0.4rem 0 0.5rem 0 !important; font-weight: 600;
  border: none !important; padding: 0 !important;
}
section[data-testid="stSidebar"] .stRadio > div { gap: 2px; }
section[data-testid="stSidebar"] .stRadio label {
  padding: 0.32rem 0.55rem; border-radius: 5px;
  transition: background 0.12s; font-size: 13px;
}
section[data-testid="stSidebar"] .stRadio label:hover { background: rgba(255, 255, 255, 0.05); }
section[data-testid="stSidebar"] .stRadio [data-baseweb="radio"][aria-checked="true"] + div {
  color: var(--zd-text); font-weight: 500;
}
section[data-testid="stSidebar"] [data-testid="stFileUploader"] { padding-top: 0; }
section[data-testid="stSidebar"] [data-testid="stFileUploader"] section {
  padding: 0.8rem !important; border-style: dashed;
}
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzoneInstructions"] { font-size: 11px; }
section[data-testid="stSidebar"] .stButton button,
section[data-testid="stSidebar"] .stDownloadButton button {
  padding: 0.32rem 0.7rem !important; font-size: 12.5px !important;
}

/* ---------- Verdict block (top of Overview) ---------- */
/* Wide bordered card with severity-tinted left border + larger
   headline font. Severity tile cluster aligned right. */
.zd-verdict {
  border-radius: 10px;
  padding: 16px 18px 14px 22px;
  margin: 6px 0 18px 0;
  background: var(--zd-info-fill);
  border-left: 4px solid var(--zd-info-accent);
}
.zd-verdict.zd-crit {
  background: var(--zd-crit-fill);
  border-left-color: var(--zd-crit-accent);
}
.zd-verdict.zd-warn {
  background: var(--zd-warn-fill);
  border-left-color: var(--zd-warn-accent);
}
.zd-verdict.zd-info {
  background: var(--zd-info-fill);
  border-left-color: var(--zd-info-accent);
}
.zd-verdict.zd-verdict-clean {
  background: var(--zd-ok-fill);
  border-left-color: var(--zd-ok-accent);
}
.zd-verdict-row {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 16px;
}
.zd-verdict-text { flex: 1 1 auto; min-width: 0; }
.zd-verdict-headline {
  font-size: 1.18rem; font-weight: 600; line-height: 1.35;
  color: var(--zd-text);
}
.zd-verdict-meta {
  margin-top: 6px; font-size: 12.5px; color: var(--zd-text-mute);
}
.zd-verdict-when { color: var(--zd-text-mute); }

.zd-verdict-tiles {
  display: flex; gap: 6px; flex-shrink: 0;
  align-items: center;
}
.zd-vtile {
  padding: 4px 10px; border-radius: 6px;
  font-size: 12px; color: var(--zd-text-mute);
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.06);
}
.zd-vtile b { color: var(--zd-text); font-weight: 600; }
.zd-vt-crit b { color: var(--zd-crit-accent); }
.zd-vt-warn b { color: var(--zd-warn-accent); }
.zd-vt-info b { color: var(--zd-info-accent); }

/* ---------- Lifecycle-downgrade chip (on finding cards) ---------- */
/* Small pill next to the severity badge on findings that were
   auto-downgraded from Critical/Warning to Info because they
   correlated with a system sleep/wake event. */
.zd-downgrade-chip {
  display: inline-block;
  font-size: 11px;
  padding: 2px 7px;
  border-radius: 999px;
  margin-left: 6px;
  color: var(--zd-text-mute);
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.08);
}
.zd-downgrade-chip b { color: var(--zd-warn-accent); }

/* ---------- Documented-category chips (2026-06-12 phase 2 UI) ---------- */
/* When a finding's code matches a documented Zscaler status code, show
   which documentation category the code belongs to: Info / Error / Policy Block.
   Helps engineers immediately see "this is a normal closure per docs"
   vs "this is a real failure per docs" vs "this is intentional policy
   enforcement per docs". Hidden when the code isn't in our data
   module. */
.zd-cat-chip {
  display: inline-block;
  font-size: 11px;
  padding: 2px 7px;
  border-radius: 999px;
  margin-left: 6px;
  font-weight: 600;
  letter-spacing: 0.01em;
  border: 1px solid transparent;
  white-space: nowrap;
}
.zd-cat-chip.zd-cat-info {
  color: var(--zd-text-mute);
  background: rgba(120, 180, 255, 0.10);
  border-color: rgba(120, 180, 255, 0.20);
}
.zd-cat-chip.zd-cat-error {
  color: var(--zd-text-mute);
  background: rgba(220, 90, 90, 0.10);
  border-color: rgba(220, 90, 90, 0.20);
}
.zd-cat-chip.zd-cat-policy {
  color: var(--zd-text-mute);
  background: rgba(255, 180, 70, 0.10);
  border-color: rgba(255, 180, 70, 0.22);
}

/* ====================================================================
   Phase 21 (2026-06-17) — Modern dashboard polish.
   Card-based layout, refined typography, traffic-light accents,
   hover affordances on interactive tiles.
   ==================================================================== */

/* Slight refinement to section headers — more breathing room, more
   weight, subtle accent bar on the left. */
.zd-section {
  font-size: var(--zd-size-section);
  font-weight: 600;
  color: var(--zd-text);
  margin: 1.5rem 0 0.65rem 0;
  padding: 0.15rem 0 0.15rem 0.65rem;
  border-left: 3px solid var(--zd-info-accent);
  letter-spacing: 0.01em;
}

/* ---- Launchpad: critical findings mini-list (Overview Phase 20) ---- */
.zd-launchpad-finding {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.6rem 0.75rem;
  margin-bottom: 0.4rem;
  background: var(--zd-surface-1);
  border: 1px solid var(--zd-divider);
  border-radius: 6px;
  transition: background 120ms ease, border-color 120ms ease;
}
.zd-launchpad-finding:hover {
  background: var(--zd-surface-2);
  border-color: rgba(255, 255, 255, 0.14);
}
.zd-launchpad-finding-title {
  flex: 1 1 auto;
  font-size: var(--zd-size-body);
  color: var(--zd-text);
  line-height: 1.35;
}
.zd-launchpad-finding-meta {
  font-size: var(--zd-size-caption);
  color: var(--zd-text-dim);
  white-space: nowrap;
}

/* ---- Launchpad: bundle vitals tile (Overview Phase 20) ---- */
.zd-vital-tile {
  padding: 0.6rem 0.85rem;
  margin-bottom: 0.5rem;
  background: var(--zd-surface-1);
  border: 1px solid var(--zd-divider);
  border-radius: 6px;
  border-left: 3px solid var(--zd-info-accent);
}
.zd-vital-label {
  font-size: var(--zd-size-caption);
  color: var(--zd-text-dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 0.15rem;
}
.zd-vital-value {
  font-size: 15px;
  color: var(--zd-text);
  font-weight: 500;
  font-feature-settings: "tnum";
}

/* ---- Launchpad: where-to-go-next grid (Overview Phase 20) ---- */
.zd-where-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 0.6rem;
  margin: 0.4rem 0 0.6rem 0;
}
.zd-where-tile {
  padding: 0.7rem 0.9rem;
  background: var(--zd-surface-1);
  border: 1px solid var(--zd-divider);
  border-radius: 6px;
  border-left: 3px solid var(--zd-info-accent);
  transition: transform 120ms ease,
              background 120ms ease,
              border-color 120ms ease,
              box-shadow 160ms ease;
  cursor: default;
}
.zd-where-tile:hover {
  transform: translateY(-1px);
  background: var(--zd-surface-2);
  border-color: rgba(255, 255, 255, 0.14);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.18);
}
.zd-where-tile.tone-crit { border-left-color: var(--zd-crit-accent); }
.zd-where-tile.tone-warn { border-left-color: var(--zd-warn-accent); }
.zd-where-tile.tone-ok   { border-left-color: var(--zd-ok-accent); }
.zd-where-tile.tone-neutral { border-left-color: var(--zd-divider); }
.zd-where-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.5rem;
  margin-bottom: 0.3rem;
}
.zd-where-label {
  font-size: 15px;
  font-weight: 600;
  color: var(--zd-text);
}
.zd-where-badge {
  font-size: var(--zd-size-caption);
  color: var(--zd-text-mute);
  background: var(--zd-surface-2);
  padding: 0.1rem 0.45rem;
  border-radius: 3px;
  font-feature-settings: "tnum";
}
.zd-where-tile.tone-crit .zd-where-badge {
  color: var(--zd-crit-accent);
  background: var(--zd-crit-fill);
}
.zd-where-tile.tone-warn .zd-where-badge {
  color: var(--zd-warn-accent);
  background: var(--zd-warn-fill);
}
.zd-where-tile.tone-ok .zd-where-badge {
  color: var(--zd-ok-accent);
  background: var(--zd-ok-fill);
}
.zd-where-desc {
  font-size: var(--zd-size-caption);
  color: var(--zd-text-mute);
  line-height: 1.45;
}

/* ---- Tables: tighter row height + alternating background ---- */
[data-testid="stDataFrame"] table {
  font-size: var(--zd-size-body);
  font-feature-settings: "tnum";
}
[data-testid="stDataFrame"] table tbody tr:nth-child(odd) > td {
  background: rgba(255, 255, 255, 0.012);
}
[data-testid="stDataFrame"] table tbody tr:hover > td {
  background: rgba(255, 255, 255, 0.04) !important;
}

/* ---- Sidebar nav: tighter radio rows + active-row highlight ---- */
section[data-testid="stSidebar"] .stRadio label {
  padding: 0.35rem 0.55rem;
  border-radius: 4px;
  transition: background 100ms ease;
}
section[data-testid="stSidebar"] .stRadio label:hover {
  background: var(--zd-surface-2);
}

/* ---- Expander: lighter border, subtle hover ---- */
[data-testid="stExpander"] details {
  border: 1px solid var(--zd-divider);
  border-radius: 6px;
  background: var(--zd-surface-1);
  transition: background 120ms ease;
}
[data-testid="stExpander"] details:hover {
  background: var(--zd-surface-2);
}
[data-testid="stExpander"] details summary {
  font-size: var(--zd-size-body);
  font-weight: 500;
}

/* ---- Metric: cleaner number, muted delta when --- ---- */
[data-testid="stMetric"] [data-testid="stMetricValue"] {
  font-feature-settings: "tnum";
  font-weight: 600;
}
[data-testid="stMetric"] [data-testid="stMetricDelta"] {
  font-size: var(--zd-size-caption);
}

/* ---- Tabs: visual lift on active tab + smoother transition ---- */
.stTabs [data-baseweb="tab-list"] {
  gap: 0.25rem;
  border-bottom: 1px solid var(--zd-divider);
}
.stTabs [data-baseweb="tab"] {
  padding: 0.45rem 0.85rem;
  font-size: var(--zd-size-body);
  border-radius: 4px 4px 0 0;
  transition: background 120ms ease;
}
.stTabs [data-baseweb="tab"]:hover {
  background: var(--zd-surface-1);
}
.stTabs [data-baseweb="tab"][aria-selected="true"] {
  background: var(--zd-surface-2);
  border-bottom: 2px solid var(--zd-info-accent);
}
"""


def inject_css() -> None:
    """Inject the stylesheet into the Streamlit page."""
    st.markdown(f"<style>{_CSS}</style>", unsafe_allow_html=True)


# Backwards-compat alias used by older call sites.
_inject_css = inject_css
