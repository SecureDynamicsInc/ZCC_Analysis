"""Smoke-test the issue framework with all seven detectors."""
import sys
from pathlib import Path

from zcc_diag.bundle import open_bundle
from zcc_diag.summary import build_summary
from zcc_diag.issues import run_detectors
from zcc_diag.correlate import correlate_for_finding
import zcc_diag.issues.zia_auth_failures  # noqa: F401  -- registers
import zcc_diag.issues.zpa_auth_failures  # noqa: F401  -- registers
import zcc_diag.issues.tunnel_not_established  # noqa: F401
import zcc_diag.issues.endpoint_fw_av  # noqa: F401
import zcc_diag.issues.captive_portal  # noqa: F401
import zcc_diag.issues.driver_error  # noqa: F401
import zcc_diag.issues.network_error  # noqa: F401


def main(zip_path: str) -> int:
    bundle = open_bundle(Path(zip_path))
    try:
        s = build_summary(bundle)
        print(f"=== {Path(zip_path).name} ===")
        print(f"OS: {s.os['name']}, ZCC: {s.versions.components}")

        results = run_detectors(bundle, s)
        for fr in results:
            print(f"\n--- Detector: {fr.issue_id} ({fr.issue_title}) ---")
            print(f"SOP file:       {fr.sop_path}")
            print(f"Findings:       {len(fr.findings)}")
            print(f"Has critical:   {fr.has_critical}")

            # Identify the top critical finding (if any) so we can show
            # one correlation window per detector group. "Top" = first
            # CRITICAL with a defined time_range. Skipping non-CRITICAL
            # because correlation is expensive enough to gate on
            # severity in a smoke run.
            top_critical = None
            for f in fr.findings:
                if (top_critical is None
                        and f.severity.value == "CRITICAL"
                        and f.time_range is not None):
                    top_critical = f

            for f in fr.findings:
                print(f"\n  [{f.severity.value}] {f.code}: {f.title}")
                print(f"    count: {f.count}")
                if f.time_range:
                    t0, t1 = f.time_range
                    print(f"    range: {t0.isoformat()} -> {t1.isoformat()}")
                print(f"    sop:   {f.sop_anchor}")
                if f.evidence:
                    sample = f.evidence[0]
                    print(f"    e.g.   {sample.raw[:140]}")

            # Correlation summary for the top critical finding.
            if top_critical is not None:
                print(
                    f"\n  Correlation (±5 min) around top critical "
                    f"finding {top_critical.code}:"
                )
                win = correlate_for_finding(
                    top_critical, bundle.files,
                    delta_minutes=5, max_records=100,
                )
                if win is None or not win.records:
                    print("    (no surrounding log activity found)")
                else:
                    by_level = {}
                    err_examples = []
                    for r in win.records:
                        by_level[r.level] = by_level.get(r.level, 0) + 1
                    levels_str = ", ".join(
                        f"{k}={v}" for k, v in sorted(by_level.items())
                    )
                    kinds_str = ", ".join(
                        f"{k}={v}" for k, v in sorted(
                            win.sources_seen.items(),
                            key=lambda kv: -kv[1],
                        )
                    )
                    # Surface the first 2 ERROR/WARN records as
                    # near-evidence the human can scan
                    for r in win.records:
                        if r.level in ("ERROR", "FATAL", "WARN"):
                            err_examples.append(r)
                            if len(err_examples) >= 2:
                                break
                    print(f"    records={len(win.records)}  "
                          f"levels: {levels_str}")
                    print(f"    log kinds: {kinds_str}")
                    for r in err_examples:
                        print(f"    near: [{r.timestamp.isoformat()}] "
                              f"{r.source_path.name}: "
                              f"{r.message[:120]}")
        return 0
    finally:
        bundle.cleanup()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
