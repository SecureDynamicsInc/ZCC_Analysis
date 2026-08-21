"""Log-Analyzer CLI — v1 (Slice 9, 2026-08-14).

Subcommands:

    facts      <bundle.zip>                 summary of a bundle
    buckets    <bundle.zip>                 classify every line by
                                            service x subsystem + coverage
    search     <query> <bundle.zip>         run a query, print matching rows
    session    <id> <bundle.zip>            reconstruct a session by ID
    inventory  <bundle.zip>                 list every extracted ID by tag type
    timeline   <ts> <bundle.zip>            events grouped by lane in a window
    diff       <ts_a> <ts_b> <bundle.zip>   side-by-side compare of two windows
    snapshots  <bundle.zip>                 config + non-log artifact snapshots
    lookup     <code>                       reference lookup across data/ modules
                                            (no bundle needed)
    raw        <bundle.zip> --file=<name>   dump one source log file's parsed
                                            lines with optional line-range slice

Query language documented in `zcc_diag/query.py`. Session reconstruction,
ID inventory, and timeline in `zcc_diag/session_recon.py`,
`zcc_diag/id_inventory.py`, `zcc_diag/timeline.py`.

Slice 8 (2026-08-14) additions:
    * `inventory` now also extracts `zia_cloud`, `zpa_cloud`, `dc`,
      `username`, `device_hostname`, `org_id`, `zcc_version` — pulled
      from EVERY log line, not just one best-effort App Profile pluck.
    * `inventory --by-module` groups the same data by log module
      (tunnel/service/tray/upm) instead of tag type.
    * `session --group-by=component` groups reconstructed lines by log
      module, preserving chronological order within each group.

Slice 9 (2026-08-14) additions:
    * `buckets` — classifies EVERY parsed line on two axes (service:
      zia/zpa/zdx/zcc_core/os_platform; subsystem: auth/tunnel/policy/
      network/dns/cert/posture/power/update/ipc/ui/capture/diagnostics/
      data) and reports coverage plus the recurring shapes of whatever
      matched nothing.
    * ZIA and ZPA clouds are now separate inventory tag types — a
      tenant is routinely on different clouds for each.

Usage:
    python -m zcc_diag facts bundle.zip
    python -m zcc_diag buckets bundle.zip
    python -m zcc_diag buckets bundle.zip --format=md
    python -m zcc_diag buckets bundle.zip --service=zpa --subsystem=auth
    python -m zcc_diag search "event:saml_expired" bundle.zip
    python -m zcc_diag session 65660 bundle.zip
    python -m zcc_diag session z5FNabc123,DATAxyz456 bundle.zip --format=jsonl
    python -m zcc_diag session 65660 bundle.zip --group-by=component
    python -m zcc_diag inventory bundle.zip
    python -m zcc_diag inventory bundle.zip --type=err_code
    python -m zcc_diag inventory bundle.zip --by-module
    python -m zcc_diag timeline 2026-07-07T18:02:18 bundle.zip --radius=5m
    python -m zcc_diag diff 2026-07-07T18:02 2026-07-07T20:00 bundle.zip \\
        --radius=15m --format=md

No findings, no RCA, no interpretation.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .bundle import bundle_session, ExtractedBundle
from .code_lookup import lookup_code, known_sources
from .id_inventory import IdInventory, IdStat, build_inventory, group_by_component
from .line_buckets import (
    SERVICES,
    SUBSYSTEMS,
    BucketReport,
    build_buckets,
)
from .log_index import build_index, LogIndex
from .query import QueryError, find_matches
from .raw_view import (
    get_file_lines,
    list_source_files,
    to_raw_lines,
)
from .session_recon import (
    ReconLine,
    SessionRecon,
    group_lines_by_component,
    reconstruct_session,
)
from .snapshots import BundleSnapshots, build_snapshots
from .timeline import (
    LANE_ORDER,
    TimelineWindow,
    WindowDiff,
    build_timeline,
    diff_windows,
    flatten_events,
)

# --------------------------------------------------------------------------
# Version tag — mirrors zcc_diag_ui.py's _PIPELINE_VERSION for `--version`.
# --------------------------------------------------------------------------
_CLI_VERSION = "log-analyzer-v3-slice18-2026-08-19"


# --------------------------------------------------------------------------
# facts
# --------------------------------------------------------------------------

def _cmd_facts(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2

    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))

    lines = idx.lines
    print(f"Bundle: {ns.bundle.name}")
    print(f"Log files scanned: {idx.files_scanned}")
    print(f"Bytes scanned: {idx.bytes_scanned:,}")
    print(f"Total lines: {len(lines):,}")
    print(f"Unparseable lines: {idx.lines_skipped_unparseable:,}")
    if lines:
        print(f"Span (UTC): {lines[0].ts} -> {lines[-1].ts}")
    if idx.bundle_tz_offset:
        print(f"Bundle TZ offset: {idx.bundle_tz_offset}  ({idx.bundle_tz_label or '?'})")
    distinct_pids = sorted({ln.pid for ln in lines if ln.pid})
    distinct_components = sorted({ln.component for ln in lines if ln.component})
    print(f"Distinct PIDs: {len(distinct_pids)}")
    print(f"Distinct components: {len(distinct_components)}")
    if ns.components:
        for c in distinct_components:
            print(f"  {c}")
    if ns.files:
        distinct_files = sorted({ln.source_file for ln in lines})
        print(f"Source files: {len(distinct_files)}")
        for f in distinct_files:
            print(f"  {f}")
    return 0


# --------------------------------------------------------------------------
# search
# --------------------------------------------------------------------------

def _cmd_search(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2

    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        try:
            results = list(find_matches(idx, ns.query, limit=ns.limit))
        except QueryError as e:
            print(f"query error: {e}", file=sys.stderr)
            return 3

    _emit_rows(results, ns.format, kind="search")

    if ns.count:
        print(f"\n# matched: {len(results):,}", file=sys.stderr)
    if ns.limit is not None and len(results) == ns.limit:
        print(f"# note: hit --limit={ns.limit}; increase to see more",
              file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------

def _cmd_session(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2

    force_type = None if ns.type == "auto" else ns.type

    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        recon = reconstruct_session(idx, ns.id, id_type=force_type)

    grouped = (
        group_lines_by_component(recon)
        if getattr(ns, "group_by", "time") == "component"
        else None
    )

    if ns.format == "text":
        _emit_session_text(recon, grouped=grouped)
    elif ns.format == "csv":
        _emit_session_csv(recon)
    elif ns.format == "jsonl":
        _emit_session_jsonl(recon)
    elif ns.format == "md":
        _emit_session_markdown(recon, grouped=grouped)
    return 0


def _emit_session_text(recon: SessionRecon,
                       grouped: "Optional[dict]" = None) -> None:
    print(f"# id={recon.query_id}  type={recon.id_type}  "
          f"lines={recon.line_count}")
    if recon.first_ts and recon.last_ts:
        print(f"# span={recon.first_ts} -> {recon.last_ts}  "
              f"({recon.duration_seconds:.1f}s)")
    print(f"# files_touched={dict(recon.files_touched)}")
    print(f"# phases={dict(recon.phase_histogram)}")
    if recon.related_id_summary:
        for k, vs in sorted(recon.related_id_summary.items()):
            print(f"# related.{k}: {vs}")
    print()

    if grouped is None:
        for ln in recon.lines:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ")[:400]
            print(f"{ts}  {ln.level:<5}  {ln.component:<8}  {ln.phase:<20}  "
                  f"{ln.source_file}:{ln.line_no}  {body}")
        return

    # Grouped by component — preserves chronological order WITHIN each
    # group (see session_recon.group_lines_by_component).
    for comp in sorted(grouped, key=lambda c: -len(grouped[c])):
        comp_lines = grouped[comp]
        print(f"## component={comp}  ({len(comp_lines)} lines)")
        for ln in comp_lines:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ")[:400]
            print(f"{ts}  {ln.level:<5}  {ln.phase:<20}  "
                  f"{ln.source_file}:{ln.line_no}  {body}")
        print()


def _emit_session_csv(recon: SessionRecon) -> None:
    w = csv.writer(sys.stdout)
    w.writerow(["ts_utc", "level", "component", "phase",
                "source_file", "line_no", "body", "related_json"])
    for ln in recon.lines:
        w.writerow([
            ln.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if ln.ts else "",
            ln.level or "",
            ln.component or "",
            ln.phase,
            ln.source_file or "",
            ln.line_no,
            (ln.body or "").replace("\n", " "),
            json.dumps(ln.related, default=str),
        ])


def _emit_session_jsonl(recon: SessionRecon) -> None:
    # First line: the header record (metadata)
    print(json.dumps({
        "_type": "session_header",
        "query_id": recon.query_id,
        "id_type": recon.id_type,
        "line_count": recon.line_count,
        "first_ts": recon.first_ts.isoformat() if recon.first_ts else None,
        "last_ts": recon.last_ts.isoformat() if recon.last_ts else None,
        "duration_seconds": recon.duration_seconds,
        "files_touched": recon.files_touched,
        "components_touched": recon.components_touched,
        "phase_histogram": recon.phase_histogram,
        "related_id_summary": recon.related_id_summary,
    }, default=str))
    for ln in recon.lines:
        print(json.dumps({
            "_type": "line",
            "ts_utc": ln.ts.isoformat() if ln.ts else None,
            "level": ln.level,
            "component": ln.component,
            "phase": ln.phase,
            "source_file": ln.source_file,
            "line_no": ln.line_no,
            "body": ln.body,
            "related": ln.related,
        }, default=str))


def _emit_session_markdown(recon: SessionRecon,
                           grouped: "Optional[dict]" = None) -> None:
    print(f"# Session `{recon.query_id}` ({recon.id_type})")
    print()
    print(f"- Lines: **{recon.line_count:,}**")
    if recon.first_ts and recon.last_ts:
        print(f"- Span (UTC): {recon.first_ts} → {recon.last_ts}  "
              f"({recon.duration_seconds:.1f}s)")
    print(f"- Files touched: {dict(recon.files_touched)}")
    print(f"- Phase histogram: {dict(recon.phase_histogram)}")
    print()

    if grouped is None:
        print("| ts (UTC) | level | component | phase | source:line | body |")
        print("|---|---|---|---|---|---|")
        for ln in recon.lines:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ").replace("|", "\\|")[:200]
            print(f"| {ts} | {ln.level} | {ln.component} | {ln.phase} | "
                  f"{ln.source_file}:{ln.line_no} | {body} |")
        return

    for comp in sorted(grouped, key=lambda c: -len(grouped[c])):
        comp_lines = grouped[comp]
        print(f"\n## Component: {comp}  ({len(comp_lines)} lines)\n")
        print("| ts (UTC) | level | phase | source:line | body |")
        print("|---|---|---|---|---|")
        for ln in comp_lines:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ").replace("|", "\\|")[:200]
            print(f"| {ts} | {ln.level} | {ln.phase} | "
                  f"{ln.source_file}:{ln.line_no} | {body} |")


# --------------------------------------------------------------------------
# inventory
# --------------------------------------------------------------------------

def _cmd_inventory(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2

    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        inv = build_inventory(idx)

    if getattr(ns, "by_module", False):
        by_module = group_by_component(inv)
        if ns.format == "text":
            _emit_module_inventory_text(by_module, ns.type)
        elif ns.format == "csv":
            _emit_module_inventory_csv(by_module, ns.type)
        elif ns.format == "jsonl":
            _emit_module_inventory_jsonl(by_module, ns.type)
        elif ns.format == "md":
            _emit_module_inventory_markdown(by_module, ns.type)
        return 0

    if ns.type:
        types = [ns.type]
    else:
        types = inv.tag_types()

    if ns.format == "text":
        _emit_inventory_text(inv, types)
    elif ns.format == "csv":
        _emit_inventory_csv(inv, types)
    elif ns.format == "jsonl":
        _emit_inventory_jsonl(inv, types)
    elif ns.format == "md":
        _emit_inventory_markdown(inv, types)
    return 0


def _emit_inventory_text(inv: IdInventory, types) -> None:
    for t in types:
        stats = inv.values_for(t, sort="count")
        print(f"\n## {t}  ({len(stats)} distinct)")
        for s in stats:
            first = s.first_ts.strftime("%Y-%m-%d %H:%M:%S") if s.first_ts else "-"
            last = s.last_ts.strftime("%Y-%m-%d %H:%M:%S") if s.last_ts else "-"
            print(f"  {s.count:>7,}  {s.value:<40}  {first} -> {last}  "
                  f"[{len(s.files)} files]")


def _emit_inventory_csv(inv: IdInventory, types) -> None:
    w = csv.writer(sys.stdout)
    w.writerow(["tag_type", "value", "count", "first_ts", "last_ts",
                "files_count", "components"])
    for t in types:
        for s in inv.values_for(t, sort="count"):
            w.writerow([
                t, s.value, s.count,
                s.first_ts.isoformat() if s.first_ts else "",
                s.last_ts.isoformat() if s.last_ts else "",
                len(s.files),
                ",".join(sorted(s.components)),
            ])


def _emit_inventory_jsonl(inv: IdInventory, types) -> None:
    for t in types:
        for s in inv.values_for(t, sort="count"):
            print(json.dumps({
                "tag_type": t,
                "value": s.value,
                "count": s.count,
                "first_ts": s.first_ts.isoformat() if s.first_ts else None,
                "last_ts": s.last_ts.isoformat() if s.last_ts else None,
                "files": sorted(s.files),
                "components": sorted(s.components),
            }, default=str))


def _emit_inventory_markdown(inv: IdInventory, types) -> None:
    for t in types:
        stats = inv.values_for(t, sort="count")
        print(f"\n## {t}  ({len(stats)} distinct)\n")
        print("| value | count | first (UTC) | last (UTC) | files |")
        print("|---|---:|---|---|---:|")
        for s in stats:
            first = s.first_ts.strftime("%Y-%m-%d %H:%M:%S") if s.first_ts else "-"
            last = s.last_ts.strftime("%Y-%m-%d %H:%M:%S") if s.last_ts else "-"
            print(f"| `{s.value}` | {s.count} | {first} | {last} | {len(s.files)} |")


# --------------------------------------------------------------------------
# inventory --by-module — same data, pivoted component-first (2026-08-14)
# --------------------------------------------------------------------------

def _emit_module_inventory_text(by_module, type_filter: "Optional[str]") -> None:
    for module in sorted(by_module.keys()):
        types = [type_filter] if type_filter else sorted(by_module[module].keys())
        print(f"\n=== module: {module} ===")
        for t in types:
            stats = by_module[module].get(t, [])
            if not stats:
                continue
            print(f"\n## {t}  ({len(stats)} distinct)")
            for s in stats:
                first = s.first_ts.strftime("%Y-%m-%d %H:%M:%S") if s.first_ts else "-"
                last = s.last_ts.strftime("%Y-%m-%d %H:%M:%S") if s.last_ts else "-"
                print(f"  {s.count:>7,}  {s.value:<40}  {first} -> {last}")


def _emit_module_inventory_csv(by_module, type_filter: "Optional[str]") -> None:
    w = csv.writer(sys.stdout)
    w.writerow(["module", "tag_type", "value", "count", "first_ts", "last_ts"])
    for module in sorted(by_module.keys()):
        types = [type_filter] if type_filter else sorted(by_module[module].keys())
        for t in types:
            for s in by_module[module].get(t, []):
                w.writerow([
                    module, t, s.value, s.count,
                    s.first_ts.isoformat() if s.first_ts else "",
                    s.last_ts.isoformat() if s.last_ts else "",
                ])


def _emit_module_inventory_jsonl(by_module, type_filter: "Optional[str]") -> None:
    for module in sorted(by_module.keys()):
        types = [type_filter] if type_filter else sorted(by_module[module].keys())
        for t in types:
            for s in by_module[module].get(t, []):
                print(json.dumps({
                    "module": module,
                    "tag_type": t,
                    "value": s.value,
                    "count": s.count,
                    "first_ts": s.first_ts.isoformat() if s.first_ts else None,
                    "last_ts": s.last_ts.isoformat() if s.last_ts else None,
                }, default=str))


def _emit_module_inventory_markdown(by_module, type_filter: "Optional[str]") -> None:
    for module in sorted(by_module.keys()):
        types = [type_filter] if type_filter else sorted(by_module[module].keys())
        print(f"\n# Module: {module}\n")
        for t in types:
            stats = by_module[module].get(t, [])
            if not stats:
                continue
            print(f"## {t}  ({len(stats)} distinct)\n")
            print("| value | count | first (UTC) | last (UTC) |")
            print("|---|---:|---|---|")
            for s in stats:
                first = s.first_ts.strftime("%Y-%m-%d %H:%M:%S") if s.first_ts else "-"
                last = s.last_ts.strftime("%Y-%m-%d %H:%M:%S") if s.last_ts else "-"
                print(f"| `{s.value}` | {s.count} | {first} | {last} |")


# --------------------------------------------------------------------------
# buckets — service x subsystem classification of every parsed line
# --------------------------------------------------------------------------

def _cmd_buckets(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2

    want_lines = bool(ns.service or ns.subsystem or ns.lines)

    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        rep = build_buckets(idx, keep_lines=want_lines)

    if want_lines:
        rows = rep.lines_for(service=ns.service, subsystem=ns.subsystem)
        if ns.limit:
            rows = rows[:ns.limit]
        _emit_bucket_lines(rows, ns.format)
        return 0

    if ns.format == "text":
        _emit_buckets_text(rep)
    elif ns.format == "csv":
        _emit_buckets_csv(rep)
    elif ns.format == "jsonl":
        _emit_buckets_jsonl(rep)
    elif ns.format == "md":
        _emit_buckets_markdown(rep)
    return 0


def _emit_buckets_text(rep: BucketReport) -> None:
    print(f"# total_lines={rep.total_lines:,}")
    print(f"# service_coverage={rep.service_coverage_pct():.1f}%  "
          f"subsystem_coverage={rep.subsystem_coverage_pct():.1f}%")
    print(f"# unclassified_both={rep.unclassified_both:,} "
          f"({100.0 * rep.unclassified_both / max(1, rep.total_lines):.1f}%)")
    print(f"# service_via={rep.service_via_counts}")
    print(f"# subsystem_via={rep.subsystem_via_counts}")

    print("\n## by service")
    for s in SERVICES:
        n = rep.by_service.get(s)
        if n:
            print(f"  {s:<12}  {n:>9,}")

    print("\n## by subsystem")
    for s in SUBSYSTEMS:
        n = rep.by_subsystem.get(s)
        if n:
            print(f"  {s:<12}  {n:>9,}")

    print("\n## service x subsystem")
    for (svc, sub), n in rep.pairs_sorted():
        print(f"  {svc:<12}  {sub:<12}  {n:>9,}")

    if rep.top_unclassified_shapes:
        print("\n## top unclassified shapes")
        for shape, n in rep.top_unclassified_shapes:
            print(f"  {n:>8,}  {shape}")


def _emit_buckets_csv(rep: BucketReport) -> None:
    w = csv.writer(sys.stdout)
    w.writerow(["kind", "service", "subsystem", "count"])
    for s, n in sorted(rep.by_service.items(), key=lambda kv: -kv[1]):
        w.writerow(["service", s, "", n])
    for s, n in sorted(rep.by_subsystem.items(), key=lambda kv: -kv[1]):
        w.writerow(["subsystem", "", s, n])
    for (svc, sub), n in rep.pairs_sorted():
        w.writerow(["pair", svc, sub, n])
    for shape, n in rep.top_unclassified_shapes:
        w.writerow(["unclassified_shape", "", shape, n])


def _emit_buckets_jsonl(rep: BucketReport) -> None:
    print(json.dumps({
        "_type": "buckets_header",
        "total_lines": rep.total_lines,
        "service_coverage_pct": round(rep.service_coverage_pct(), 2),
        "subsystem_coverage_pct": round(rep.subsystem_coverage_pct(), 2),
        "unclassified_service": rep.unclassified_service,
        "unclassified_subsystem": rep.unclassified_subsystem,
        "unclassified_both": rep.unclassified_both,
        "service_via_counts": rep.service_via_counts,
        "subsystem_via_counts": rep.subsystem_via_counts,
    }))
    for s, n in sorted(rep.by_service.items(), key=lambda kv: -kv[1]):
        print(json.dumps({"_type": "service", "service": s, "count": n}))
    for s, n in sorted(rep.by_subsystem.items(), key=lambda kv: -kv[1]):
        print(json.dumps({"_type": "subsystem", "subsystem": s, "count": n}))
    for (svc, sub), n in rep.pairs_sorted():
        print(json.dumps({"_type": "pair", "service": svc,
                          "subsystem": sub, "count": n}))
    for shape, n in rep.top_unclassified_shapes:
        print(json.dumps({"_type": "unclassified_shape",
                          "shape": shape, "count": n}))


def _emit_buckets_markdown(rep: BucketReport) -> None:
    print("# Line buckets\n")
    print(f"- Total lines: **{rep.total_lines:,}**")
    print(f"- Service coverage: **{rep.service_coverage_pct():.1f}%**")
    print(f"- Subsystem coverage: **{rep.subsystem_coverage_pct():.1f}%**")
    print(f"- Neither axis resolved: **{rep.unclassified_both:,}**\n")

    print("## Service × subsystem\n")
    print("| service | subsystem | lines |")
    print("|---|---|---:|")
    for (svc, sub), n in rep.pairs_sorted():
        print(f"| {svc} | {sub} | {n:,} |")

    if rep.top_unclassified_shapes:
        print("\n## Top unclassified shapes\n")
        print("| lines | shape |")
        print("|---:|---|")
        for shape, n in rep.top_unclassified_shapes:
            safe = shape.replace("|", "\\|")
            print(f"| {n:,} | `{safe}` |")


def _emit_bucket_lines(rows, fmt: str) -> None:
    if fmt == "text":
        for ln in rows:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ")[:400]
            print(f"{ts}  {ln.service:<11}  {ln.subsystem:<12}  "
                  f"{ln.level:<5}  {ln.source_file}:{ln.line_no}  {body}")
    elif fmt == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["ts_utc", "service", "subsystem", "service_via",
                    "subsystem_via", "level", "component",
                    "source_file", "line_no", "body"])
        for ln in rows:
            w.writerow([
                ln.ts.isoformat() if ln.ts else "",
                ln.service, ln.subsystem, ln.service_via, ln.subsystem_via,
                ln.level, ln.component, ln.source_file, ln.line_no,
                (ln.body or "").replace("\n", " "),
            ])
    elif fmt == "jsonl":
        for ln in rows:
            print(json.dumps({
                "ts_utc": ln.ts.isoformat() if ln.ts else None,
                "service": ln.service, "subsystem": ln.subsystem,
                "service_via": ln.service_via,
                "subsystem_via": ln.subsystem_via,
                "level": ln.level, "component": ln.component,
                "source_file": ln.source_file, "line_no": ln.line_no,
                "body": ln.body,
            }, default=str))
    elif fmt == "md":
        print("| ts (UTC) | service | subsystem | level | source:line | body |")
        print("|---|---|---|---|---|---|")
        for ln in rows:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ").replace("|", "\\|")[:200]
            print(f"| {ts} | {ln.service} | {ln.subsystem} | {ln.level} | "
                  f"{ln.source_file}:{ln.line_no} | {body} |")


# --------------------------------------------------------------------------
# timeline / diff
# --------------------------------------------------------------------------

_TS_FMTS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d",
]


def _parse_ts(s: str) -> datetime:
    s = s.strip()
    for fmt in _TS_FMTS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise SystemExit(f"error: bad timestamp {s!r}")


_DUR_RE = re.compile(
    r"^\s*(\d+)\s*(s|sec|m|min|h|hr|d|day)s?\s*$",
    re.IGNORECASE,
)


def _parse_radius(s: str) -> timedelta:
    m = _DUR_RE.match(s)
    if not m:
        raise SystemExit(f"error: bad radius {s!r} "
                         f"(examples: 30s, 5m, 1h, 2d)")
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit.startswith("s"):
        return timedelta(seconds=n)
    if unit.startswith("m"):
        return timedelta(minutes=n)
    if unit.startswith("h"):
        return timedelta(hours=n)
    if unit.startswith("d"):
        return timedelta(days=n)
    raise SystemExit(f"error: bad radius unit in {s!r}")


def _cmd_timeline(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2
    centre = _parse_ts(ns.ts)
    radius = _parse_radius(ns.radius)
    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        window = build_timeline(idx, centre, radius)

    if ns.format == "text":
        _emit_timeline_text(window)
    elif ns.format == "csv":
        _emit_timeline_csv(window)
    elif ns.format == "jsonl":
        _emit_timeline_jsonl(window)
    elif ns.format == "md":
        _emit_timeline_markdown(window)
    return 0


def _emit_timeline_text(w: TimelineWindow) -> None:
    print(f"# centre={w.centre_ts}  radius={w.radius}  "
          f"span={w.start_ts} -> {w.end_ts}")
    print(f"# total_events={w.total_events}")
    print("# lane_counts:")
    for lane in LANE_ORDER:
        c = w.lane_counts.get(lane, 0)
        print(f"#   {lane:<10}  {c:>7,}")
    print()
    for e in flatten_events(w):
        ts = e.ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        body = (e.body or "").replace("\n", " ")[:400]
        print(f"{ts}  {e.lane:<9}  {e.phase:<20}  {e.level:<5}  "
              f"{e.component:<8}  {e.source_file}:{e.line_no}  {body}")


def _emit_timeline_csv(w: TimelineWindow) -> None:
    wr = csv.writer(sys.stdout)
    wr.writerow(["ts_utc", "lane", "phase", "level", "component",
                 "source_file", "line_no", "body"])
    for e in flatten_events(w):
        wr.writerow([
            e.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            e.lane, e.phase, e.level, e.component,
            e.source_file, e.line_no,
            (e.body or "").replace("\n", " "),
        ])


def _emit_timeline_jsonl(w: TimelineWindow) -> None:
    print(json.dumps({
        "_type": "timeline_header",
        "centre_ts": w.centre_ts.isoformat(),
        "radius_seconds": w.radius.total_seconds(),
        "start_ts": w.start_ts.isoformat(),
        "end_ts": w.end_ts.isoformat(),
        "total_events": w.total_events,
        "lane_counts": w.lane_counts,
        "ids_seen": {k: sorted(v) for k, v in w.ids_seen.items()},
    }, default=str))
    for e in flatten_events(w):
        print(json.dumps({
            "_type": "event",
            "ts_utc": e.ts.isoformat(),
            "lane": e.lane,
            "phase": e.phase,
            "level": e.level,
            "component": e.component,
            "source_file": e.source_file,
            "line_no": e.line_no,
            "body": e.body,
        }, default=str))


def _emit_timeline_markdown(w: TimelineWindow) -> None:
    print(f"# Timeline `{w.centre_ts:%Y-%m-%d %H:%M:%S UTC}` ± {w.radius}")
    print()
    print(f"- Total events: **{w.total_events:,}**")
    print(f"- Span: {w.start_ts:%H:%M:%S} → {w.end_ts:%H:%M:%S}")
    print()
    print("| lane | count |")
    print("|---|---:|")
    for lane in LANE_ORDER:
        print(f"| {lane} | {w.lane_counts.get(lane, 0)} |")
    print()
    print("| ts (UTC) | lane | phase | level | component | source:line | body |")
    print("|---|---|---|---|---|---|---|")
    for e in flatten_events(w):
        body = (e.body or "").replace("\n", " ").replace("|", "\\|")[:200]
        print(f"| {e.ts:%Y-%m-%d %H:%M:%S} | {e.lane} | {e.phase} | "
              f"{e.level} | {e.component} | "
              f"{e.source_file}:{e.line_no} | {body} |")


def _cmd_diff(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2
    centre_a = _parse_ts(ns.ts_a)
    centre_b = _parse_ts(ns.ts_b)
    radius = _parse_radius(ns.radius)
    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        w_a = build_timeline(idx, centre_a, radius)
        w_b = build_timeline(idx, centre_b, radius)
        d = diff_windows(w_a, w_b)

    if ns.format == "text":
        _emit_diff_text(d)
    elif ns.format == "csv":
        _emit_diff_csv(d)
    elif ns.format == "jsonl":
        _emit_diff_jsonl(d)
    elif ns.format == "md":
        _emit_diff_markdown(d)
    return 0


def _emit_diff_text(d: WindowDiff) -> None:
    a, b = d.window_a, d.window_b
    print(f"# A: centre={a.centre_ts}  events={a.total_events}")
    print(f"# B: centre={b.centre_ts}  events={b.total_events}")
    print(f"# radius={a.radius}")
    print()
    print(f"{'lane':<10}  {'A':>7}  {'B':>7}  {'delta':>6}")
    for ld in d.lane_deltas:
        arrow = f"{ld.delta:+d}" if ld.delta else "0"
        print(f"{ld.lane:<10}  {ld.count_a:>7,}  {ld.count_b:>7,}  {arrow:>6}")
    print()
    print("# ID deltas:")
    for idd in d.id_deltas:
        print(f"  {idd.tag_type}")
        if idd.only_in_a:
            print(f"    only in A: {idd.only_in_a}")
        if idd.only_in_b:
            print(f"    only in B: {idd.only_in_b}")
        if idd.in_both:
            print(f"    in both:   {idd.in_both}")


def _emit_diff_csv(d: WindowDiff) -> None:
    wr = csv.writer(sys.stdout)
    wr.writerow(["kind", "lane_or_tag_type", "a_value", "b_value", "delta_or_note"])
    for ld in d.lane_deltas:
        wr.writerow(["lane", ld.lane, ld.count_a, ld.count_b, ld.delta])
    for idd in d.id_deltas:
        wr.writerow(["id_only_a", idd.tag_type, "|".join(idd.only_in_a), "", ""])
        wr.writerow(["id_only_b", idd.tag_type, "", "|".join(idd.only_in_b), ""])
        wr.writerow(["id_in_both", idd.tag_type, "|".join(idd.in_both),
                     "|".join(idd.in_both), ""])


def _emit_diff_jsonl(d: WindowDiff) -> None:
    print(json.dumps({
        "_type": "diff_header",
        "window_a": {
            "centre_ts": d.window_a.centre_ts.isoformat(),
            "radius_seconds": d.window_a.radius.total_seconds(),
            "total_events": d.window_a.total_events,
        },
        "window_b": {
            "centre_ts": d.window_b.centre_ts.isoformat(),
            "radius_seconds": d.window_b.radius.total_seconds(),
            "total_events": d.window_b.total_events,
        },
    }, default=str))
    for ld in d.lane_deltas:
        print(json.dumps({
            "_type": "lane_delta",
            "lane": ld.lane,
            "count_a": ld.count_a,
            "count_b": ld.count_b,
            "delta": ld.delta,
        }))
    for idd in d.id_deltas:
        print(json.dumps({
            "_type": "id_delta",
            "tag_type": idd.tag_type,
            "only_in_a": idd.only_in_a,
            "only_in_b": idd.only_in_b,
            "in_both": idd.in_both,
        }))


def _emit_diff_markdown(d: WindowDiff) -> None:
    a, b = d.window_a, d.window_b
    print(f"# Diff `A={a.centre_ts:%Y-%m-%d %H:%M:%S}` "
          f"vs `B={b.centre_ts:%Y-%m-%d %H:%M:%S}`  (±{a.radius})")
    print()
    print("## Lane counts")
    print()
    print("| lane | A | B | delta |")
    print("|---|---:|---:|---:|")
    for ld in d.lane_deltas:
        arrow = f"{ld.delta:+d}" if ld.delta else "0"
        print(f"| {ld.lane} | {ld.count_a} | {ld.count_b} | {arrow} |")
    print()
    print("## ID deltas")
    print()
    for idd in d.id_deltas:
        print(f"### {idd.tag_type}")
        print()
        if idd.only_in_a:
            print(f"- **only in A** ({len(idd.only_in_a)}): "
                  f"{', '.join('`'+v+'`' for v in idd.only_in_a)}")
        if idd.only_in_b:
            print(f"- **only in B** ({len(idd.only_in_b)}): "
                  f"{', '.join('`'+v+'`' for v in idd.only_in_b)}")
        if idd.in_both:
            print(f"- in both ({len(idd.in_both)}): "
                  f"{', '.join('`'+v+'`' for v in idd.in_both)}")
        print()


# --------------------------------------------------------------------------
# snapshots / lookup
# --------------------------------------------------------------------------

def _cmd_snapshots(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2
    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        snaps = build_snapshots(extracted, idx, os_family=ns.os_family)

    if ns.format == "text":
        _emit_snapshots_text(snaps, ns.section)
    elif ns.format == "csv":
        _emit_snapshots_csv(snaps, ns.section)
    elif ns.format == "jsonl":
        _emit_snapshots_jsonl(snaps, ns.section)
    elif ns.format == "md":
        _emit_snapshots_markdown(snaps, ns.section)
    return 0


_SECTIONS = ("app_profile", "profile_details", "posture", "bypass",
             "session_info", "pcaps", "upm", "xml", "other", "diagnostics")


def _want(section: str, filter_: str) -> bool:
    return filter_ in ("all", section)


def _emit_snapshots_text(s: BundleSnapshots, section: str) -> None:
    if _want("app_profile", section):
        print(f"## App Profile ({len(s.app_profile)} keys)")
        for k, v in sorted(s.app_profile.items()):
            print(f"  {k} = {v!r}")
    if _want("profile_details", section):
        print(f"\n## Forwarding Profile details ({len(s.profile_details)} keys)")
        for k, v in sorted(s.profile_details.items()):
            print(f"  {k} = {v!r}")
    if _want("posture", section):
        print(f"\n## Posture profiles ({len(s.posture_profiles)})")
        for p in s.posture_profiles:
            print(f"  - {p}")
        print(f"\n## Trust conditions ({len(s.trust_conditions)})")
        for c in s.trust_conditions:
            print(f"  - {c}")
    if _want("bypass", section):
        print(f"\n## Configured VPN bypass")
        for k, v in sorted(s.configured_bypass.items()):
            print(f"  {k}: {v}")
    if _want("session_info", section):
        print(f"\n## Session info")
        for k, v in sorted(s.session_info.items()):
            print(f"  {k} = {v!r}")
    if _want("pcaps", section):
        print(f"\n## PCAPs ({len(s.pcaps)})")
        for p in s.pcaps:
            print(f"  {p.filename}  {p.packet_count:,} pkts  "
                  f"{p.ts_first} -> {p.ts_last}")
    if _want("upm", section):
        print(f"\n## UPM SQLite DBs ({len(s.upm_dbs)})")
        for db in s.upm_dbs:
            print(f"  {db.filename}")
            for t, n in sorted(db.tables.items()):
                print(f"    {t}  {n:,} rows")
    if _want("xml", section):
        print(f"\n## XML event files ({len(s.xml_events)})")
        for a in s.xml_events:
            print(f"  {a.filename}  {a.size_bytes:,} B")
    if _want("other", section):
        print(f"\n## Other files ({len(s.other_files)})")
        for a in s.other_files:
            print(f"  {a.filename}  {a.size_bytes:,} B")
    if _want("diagnostics", section) and s.extract_errors:
        print(f"\n## Extractor diagnostics ({len(s.extract_errors)} errors)")
        for e in s.extract_errors:
            print(f"  {e}")


def _emit_snapshots_csv(s: BundleSnapshots, section: str) -> None:
    w = csv.writer(sys.stdout)
    w.writerow(["section", "key_or_filename", "value_or_meta"])
    if _want("app_profile", section):
        for k, v in sorted(s.app_profile.items()):
            w.writerow(["app_profile", k, str(v)])
    if _want("posture", section):
        for p in s.posture_profiles:
            w.writerow(["posture_profile", p.get("name", ""), json.dumps(p, default=str)])
        for c in s.trust_conditions:
            w.writerow(["trust_condition", c.get("name", ""), json.dumps(c, default=str)])
    if _want("pcaps", section):
        for p in s.pcaps:
            w.writerow(["pcap", p.filename,
                        json.dumps({
                            "packets": p.packet_count,
                            "ts_first": p.ts_first.isoformat() if p.ts_first else None,
                            "ts_last": p.ts_last.isoformat() if p.ts_last else None,
                            "size_bytes": p.size_bytes,
                        }, default=str)])
    if _want("upm", section):
        for db in s.upm_dbs:
            for t, n in db.tables.items():
                w.writerow(["upm_table", f"{db.filename}/{t}", n])
    if _want("xml", section):
        for a in s.xml_events:
            w.writerow(["xml", a.filename, a.size_bytes])
    if _want("other", section):
        for a in s.other_files:
            w.writerow(["other", a.filename, a.size_bytes])
    if _want("diagnostics", section):
        for e in s.extract_errors:
            w.writerow(["diagnostic", "", e])


def _emit_snapshots_jsonl(s: BundleSnapshots, section: str) -> None:
    if _want("app_profile", section):
        print(json.dumps({"_type": "app_profile", "data": s.app_profile}, default=str))
    if _want("profile_details", section):
        print(json.dumps({"_type": "profile_details", "data": s.profile_details}, default=str))
    if _want("posture", section):
        print(json.dumps({"_type": "posture_profiles", "data": s.posture_profiles}, default=str))
        print(json.dumps({"_type": "trust_conditions", "data": s.trust_conditions}, default=str))
    if _want("bypass", section):
        print(json.dumps({"_type": "configured_bypass", "data": s.configured_bypass}, default=str))
    if _want("session_info", section):
        print(json.dumps({"_type": "session_info", "data": s.session_info}, default=str))
    if _want("pcaps", section):
        for p in s.pcaps:
            print(json.dumps({
                "_type": "pcap", "filename": p.filename,
                "packet_count": p.packet_count,
                "ts_first": p.ts_first.isoformat() if p.ts_first else None,
                "ts_last": p.ts_last.isoformat() if p.ts_last else None,
                "size_bytes": p.size_bytes,
                "top_dns": p.top_dns, "top_sni": p.top_sni,
                "top_dest_ips": p.top_dest_ips,
            }, default=str))
    if _want("upm", section):
        for db in s.upm_dbs:
            print(json.dumps({
                "_type": "upm_db", "filename": db.filename,
                "size_bytes": db.size_bytes, "tables": db.tables,
            }, default=str))
    if _want("xml", section):
        for a in s.xml_events:
            print(json.dumps({"_type": "xml", "filename": a.filename,
                              "size_bytes": a.size_bytes}))
    if _want("other", section):
        for a in s.other_files:
            print(json.dumps({"_type": "other", "filename": a.filename,
                              "size_bytes": a.size_bytes}))
    if _want("diagnostics", section):
        for e in s.extract_errors:
            print(json.dumps({"_type": "diagnostic", "message": e}))


def _emit_snapshots_markdown(s: BundleSnapshots, section: str) -> None:
    if _want("app_profile", section):
        print("## App Profile")
        print()
        print("```json")
        print(json.dumps(s.app_profile, indent=2, default=str))
        print("```")
    if _want("posture", section):
        print("\n## Posture profiles")
        for p in s.posture_profiles:
            print(f"- {p}")
    if _want("pcaps", section):
        print("\n## PCAPs")
        print()
        print("| filename | packets | first | last | size |")
        print("|---|---:|---|---|---:|")
        for p in s.pcaps:
            first = p.ts_first.strftime("%Y-%m-%d %H:%M:%S") if p.ts_first else "-"
            last = p.ts_last.strftime("%Y-%m-%d %H:%M:%S") if p.ts_last else "-"
            print(f"| {p.filename} | {p.packet_count:,} | {first} | {last} | "
                  f"{p.size_bytes:,} B |")
    if _want("upm", section):
        print("\n## UPM SQLite DBs")
        for db in s.upm_dbs:
            print(f"\n### {db.filename}\n")
            print("| table | row_count |")
            print("|---|---:|")
            for t, n in sorted(db.tables.items()):
                print(f"| {t} | {n:,} |")


def _cmd_lookup(ns) -> int:
    hits = lookup_code(ns.code, limit=ns.limit)
    if ns.format == "text":
        for h in hits:
            print(f"[{h.source:<24}] {h.match_reason:<16} {h.code}")
            desc = (h.fields.get("description")
                    or h.fields.get("session_status")
                    or h.fields.get("meaning") or "")
            if desc:
                print(f"    {desc}")
            res = h.fields.get("resolution")
            if res:
                print(f"    resolution: {res}")
    elif ns.format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["source", "match_reason", "code", "description", "resolution"])
        for h in hits:
            desc = (h.fields.get("description")
                    or h.fields.get("session_status")
                    or h.fields.get("meaning") or "")
            w.writerow([h.source, h.match_reason, h.code, desc,
                        h.fields.get("resolution", "")])
    elif ns.format == "jsonl":
        for h in hits:
            print(json.dumps({
                "source": h.source, "module": h.module,
                "match_reason": h.match_reason,
                "code": h.code, "fields": h.fields,
            }, default=str))
    elif ns.format == "md":
        print(f"# Lookup: `{ns.code}` — {len(hits)} hit(s)")
        print()
        print("| source | match | code | description |")
        print("|---|---|---|---|")
        for h in hits:
            desc = (h.fields.get("description")
                    or h.fields.get("session_status")
                    or h.fields.get("meaning") or "").replace("|", "\\|")[:200]
            print(f"| {h.source} | {h.match_reason} | `{h.code}` | {desc} |")
    if ns.count:
        print(f"\n# matched: {len(hits)}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# raw — file-by-file dump of parsed lines
# --------------------------------------------------------------------------

def _cmd_raw(ns) -> int:
    if not ns.bundle.exists():
        print(f"error: bundle not found: {ns.bundle}", file=sys.stderr)
        return 2

    with bundle_session(ns.bundle) as extracted:
        assert isinstance(extracted, ExtractedBundle)
        idx = build_index(str(extracted.root))
        files = list_source_files(idx)

        if ns.list_files:
            for name, count in files:
                print(f"{count:>9,}  {name}")
            return 0

        # Choose file. If --file not given and only one file exists, use it.
        if ns.file:
            chosen = ns.file
        elif len(files) == 1:
            chosen = files[0][0]
        else:
            print("error: multiple source files; use --list-files to see them "
                  "and --file=<name> to pick one.", file=sys.stderr)
            for name, count in files[:20]:
                print(f"  {name} ({count:,})", file=sys.stderr)
            return 3

        rows = get_file_lines(idx, chosen,
                              substring=ns.substring,
                              regex=ns.regex)

    # Line-range slice
    if ns.lines:
        try:
            start_s, end_s = ns.lines.split("-", 1)
            start = int(start_s) if start_s else 1
            end = int(end_s) if end_s else 10 ** 12
        except ValueError:
            print(f"error: bad --lines={ns.lines!r} (want START-END)",
                  file=sys.stderr)
            return 4
        rows = [ln for ln in rows if start <= ln.line_no <= end]

    # Emit
    if ns.format == "text":
        for r in to_raw_lines(rows):
            print(f"{r.line_no:>7}  {r.ts_iso}  {r.level:<5}  {r.body}")
    elif ns.format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["line_no", "ts_utc", "level", "component",
                    "pid", "tid", "body"])
        for ln in rows:
            w.writerow([
                ln.line_no,
                ln.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if ln.ts else "",
                ln.level or "", ln.component or "",
                ln.pid or "", ln.tid or "",
                (ln.body or "").replace("\n", " "),
            ])
    elif ns.format == "jsonl":
        for ln in rows:
            print(json.dumps({
                "line_no": ln.line_no,
                "ts_utc": ln.ts.isoformat() if ln.ts else None,
                "level": ln.level, "component": ln.component,
                "pid": ln.pid, "tid": ln.tid,
                "source_file": ln.source_file,
                "body": ln.body,
            }, default=str))
    elif ns.format == "md":
        print("| line_no | ts (UTC) | level | body |")
        print("|---:|---|---|---|")
        for ln in rows:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ").replace("|", "\\|")[:400]
            print(f"| {ln.line_no} | {ts} | {ln.level or ''} | {body} |")
    return 0


# --------------------------------------------------------------------------
# Shared row emitters (for search)
# --------------------------------------------------------------------------

def _emit_rows(rows, fmt, kind="search") -> None:
    if fmt == "text":
        for ln in rows:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ")[:400]
            print(f"{ts}  {ln.level:<5}  {ln.component:<8}  "
                  f"{ln.source_file}:{ln.line_no}  {body}")
    elif fmt == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["ts_utc", "level", "component", "pid", "tid",
                    "source_file", "line_no", "session_id", "host", "body"])
        for ln in rows:
            w.writerow([
                ln.ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if ln.ts else "",
                ln.level or "", ln.component or "",
                ln.pid or "", ln.tid or "",
                ln.source_file or "", ln.line_no,
                ln.session_id or "", ln.host or "",
                (ln.body or "").replace("\n", " "),
            ])
    elif fmt == "jsonl":
        for ln in rows:
            print(json.dumps({
                "ts_utc": ln.ts.isoformat() if ln.ts else None,
                "level": ln.level, "component": ln.component,
                "pid": ln.pid, "tid": ln.tid,
                "source_file": ln.source_file, "line_no": ln.line_no,
                "session_id": ln.session_id, "host": ln.host,
                "body": ln.body,
            }, default=str))
    elif fmt == "md":
        print("| ts (UTC) | level | component | source:line | body |")
        print("|---|---|---|---|---|")
        for ln in rows:
            ts = ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-"
            body = (ln.body or "").replace("\n", " ").replace("|", "\\|")[:200]
            print(f"| {ts} | {ln.level or ''} | {ln.component or ''} | "
                  f"{ln.source_file}:{ln.line_no} | {body} |")


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="zcc_diag",
        description="Log-Analyzer CLI (v1)",
    )
    ap.add_argument(
        "--version", action="version", version=_CLI_VERSION,
        help="Print the pipeline version and exit.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # facts
    p = sub.add_parser("facts", help="Print a bundle summary")
    p.add_argument("bundle", type=Path)
    p.add_argument("--components", action="store_true")
    p.add_argument("--files", action="store_true")
    p.set_defaults(func=_cmd_facts)

    # search
    p = sub.add_parser("search", help="Run a query. See zcc_diag/query.py.")
    p.add_argument("query")
    p.add_argument("bundle", type=Path)
    p.add_argument("--limit", type=int, default=1000)
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.add_argument("--count", action="store_true")
    p.set_defaults(func=_cmd_search)

    # session
    p = sub.add_parser(
        "session",
        help="Reconstruct a session by ID (tag_id / mtunnel_id / "
             "broker_session / conn_id / session_id / free).",
    )
    p.add_argument("id", help="Identifier to reconstruct")
    p.add_argument("bundle", type=Path)
    p.add_argument(
        "--type",
        choices=["auto", "tag_id", "session_id", "mtunnel_id",
                 "broker_session", "conn_id", "free"],
        default="auto",
        help="Force an ID type (default: auto-detect).",
    )
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.add_argument(
        "--group-by",
        choices=["time", "component"],
        default="time",
        help="'time' (default): one chronological stream. 'component': "
             "group lines by log module (tunnel/service/tray/upm), "
             "chronological within each group. Only affects "
             "--format=text/md (csv/jsonl already carry a component "
             "column per row).",
    )
    p.set_defaults(func=_cmd_session)

    # inventory
    p = sub.add_parser(
        "inventory",
        help="List every extracted identifier by tag type.",
    )
    p.add_argument("bundle", type=Path)
    p.add_argument(
        "--type",
        help="Restrict to a single tag type "
             "(tag_id, mtunnel_id, broker_session, conn_id, session_id, "
             "err_code, symbolic_code, app, broker, sme_host, ipv4, "
             "http_status, data_channel, zia_cloud, zpa_cloud, dc, "
             "username, device_hostname, org_id, zcc_version).",
    )
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.add_argument(
        "--by-module", action="store_true",
        help="Group by log module (tunnel/service/tray/upm) first, "
             "tag type second, instead of tag type only.",
    )
    p.set_defaults(func=_cmd_inventory)

    # buckets
    p = sub.add_parser(
        "buckets",
        help="Classify every parsed line by service x subsystem, with a "
             "coverage report.",
    )
    p.add_argument("bundle", type=Path)
    p.add_argument(
        "--service", choices=SERVICES,
        help="Emit the matching LINES for this service instead of the "
             "summary.",
    )
    p.add_argument(
        "--subsystem", choices=SUBSYSTEMS,
        help="Emit the matching LINES for this subsystem instead of the "
             "summary.",
    )
    p.add_argument(
        "--lines", action="store_true",
        help="Emit lines rather than the summary (all buckets). Implied "
             "by --service/--subsystem.",
    )
    p.add_argument("--limit", type=int, default=2000,
                   help="Cap emitted lines (default 2000; 0 = no cap).")
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"],
                   default="text")
    p.set_defaults(func=_cmd_buckets)

    # timeline
    p = sub.add_parser(
        "timeline",
        help="Events grouped by lane in a ±window around a centre timestamp.",
    )
    p.add_argument("ts", help="Centre timestamp (UTC). Formats: YYYY-MM-DD[T]HH:MM[:SS]")
    p.add_argument("bundle", type=Path)
    p.add_argument("--radius", default="5m",
                   help="Window radius (e.g. 30s, 5m, 1h, 2d). Default 5m.")
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.set_defaults(func=_cmd_timeline)

    # diff
    p = sub.add_parser(
        "diff",
        help="Side-by-side compare of two windows in the same bundle.",
    )
    p.add_argument("ts_a", help="Centre A (UTC)")
    p.add_argument("ts_b", help="Centre B (UTC)")
    p.add_argument("bundle", type=Path)
    p.add_argument("--radius", default="15m",
                   help="Shared window radius (default 15m).")
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.set_defaults(func=_cmd_diff)

    # snapshots
    p = sub.add_parser(
        "snapshots",
        help="Config snapshots + non-log artifact inventories.",
    )
    p.add_argument("bundle", type=Path)
    p.add_argument(
        "--section",
        choices=("all",) + _SECTIONS,
        default="all",
        help="Emit only one section.",
    )
    p.add_argument("--os-family", default="",
                   help="Force os_family (windows|macos). Default: auto.")
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.set_defaults(func=_cmd_snapshots)

    # lookup
    p = sub.add_parser(
        "lookup",
        help="Look up a code / status across every documented Zscaler "
             "reference data module. No bundle required.",
    )
    p.add_argument("code", help="Symbolic (BRK_MT_SETUP_FAIL_SAML_EXPIRED) "
                                "or numeric (5008) or keyword.")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.add_argument("--count", action="store_true")
    p.set_defaults(func=_cmd_lookup)

    # raw
    p = sub.add_parser(
        "raw",
        help="Dump one source log file's parsed lines with optional filters.",
    )
    p.add_argument("bundle", type=Path)
    p.add_argument("--file",
                   help="Source log filename (basename). "
                        "Auto-selects if the bundle has only one log file. "
                        "Use --list-files to enumerate.")
    p.add_argument("--list-files", action="store_true",
                   help="Print every parsed source file (basename + line count) "
                        "and exit.")
    p.add_argument("--substring",
                   help="Case-insensitive substring filter on body.")
    p.add_argument("--regex",
                   help="Regex filter on body (case-insensitive).")
    p.add_argument("--lines",
                   help="Line-number range START-END (inclusive). "
                        "Either bound optional (e.g. 100-, -500).")
    p.add_argument("--format", choices=["text", "csv", "jsonl", "md"], default="text")
    p.set_defaults(func=_cmd_raw)

    ns = ap.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
