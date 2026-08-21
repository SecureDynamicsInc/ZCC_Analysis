"""
zcc_diag UI submodules.

This package was split out of the monolithic ``zcc_diag_ui.py`` once
that file grew past 5,000 lines. Each submodule owns one cohesive
piece of the Streamlit frontend:

  * ``styles``     — CSS string + injection
  * ``severity``   — severity colour tokens, badges, tag helpers
  * ``narrators``  — one-line ``_narrate_*`` helpers (Bypass list,
                     Apps Installed, Service Edges, etc.)
  * ``clustering`` — root-cause family table + cluster renderer
  * ``findings``   — finding card rendering + "Copy as Markdown"
  * ``policy``     — policy / bypass / tenant-summary helpers
  * ``symptoms``   — symptom-triage module + slowness narrative
  * ``path_health``— Path Health module + hop tables
  * ``overview``   — Overview module + question-led focus picker
  * ``search``     — Search module + session detail view
  * ``header``     — top-of-page bundle / tenant / network strip
  * ``analyse``    — cached _analyse() + version constants

``zcc_diag_ui.py`` is now a thin orchestrator that imports + wires
these together. Adding a new module section means:
  (a) create ``ui/<name>.py`` with the render function, then
  (b) wire it into the sidebar nav router in ``zcc_diag_ui.py``.

Keeping each file under ~600 lines makes the codebase reviewable.
"""
