#!/usr/bin/env python3
"""Reject code patterns that can retain, export, or transmit diagnostics."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (ROOT / "zcc_diag",)
STATIC_CACHE_ALLOWLIST = {
    "zcc_diag/ui/status_code_reference.py",
    "zcc_diag/ui/update_notice.py",
}
FORBIDDEN_PATH_PARTS = {"known_cases", "knowledge", "corpus"}
FORBIDDEN_SOURCE = {
    "st.download_button": "diagnostic download/export",
    ".download_button(": "diagnostic download/export",
    ".zcc_diag_cache": "persistent diagnostic cache",
    "bundle_cache": "persistent diagnostic cache",
    "agent_handoff": "diagnostic agent handoff",
    "write_sidecar": "customer-derived redaction sidecar",
}
PERSISTENCE_MARKERS = (
    ".write_bytes(", ".write_text(", "NamedTemporaryFile(",
    "TemporaryDirectory(", "mkdtemp(", "sqlite3.connect(",
)
NETWORK_MARKERS = (
    "urllib.request.urlopen(", "requests.get(", "requests.post(",
    "httpx.get(", "httpx.post(", "socket.create_connection(", "urlopen(",
)
PERSISTENCE_ALLOWLIST = {
    "zcc_diag/bundle.py",
    "zcc_diag/endpoint_intel.py",  # MaxMind reference data only
    "zcc_diag/log_store.py",
    "zcc_diag/snapshots.py",  # opens extracted configuration DBs read-only
    "zcc_diag/transient_runtime.py",
    "zcc_diag/update_check.py",
    "zcc_diag/zdx_db_extract.py",  # opens extracted telemetry read-only
    "zcc_diag_ui.py",
}


def findings() -> list[str]:
    problems: list[str] = []
    paths = [ROOT / "zcc_diag_ui.py"]
    for source_root in SOURCE_ROOTS:
        paths.extend(source_root.rglob("*.py"))
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        if any(part in FORBIDDEN_PATH_PARTS for part in path.relative_to(ROOT).parts):
            problems.append(f"{relative}: forbidden retained-case path")
            continue
        text = path.read_text(encoding="utf-8")
        for marker, label in FORBIDDEN_SOURCE.items():
            if marker in text:
                problems.append(f"{relative}: {label} ({marker})")
        if "@st.cache_data" in text or "@st.cache_resource" in text:
            if relative not in STATIC_CACHE_ALLOWLIST:
                problems.append(f"{relative}: customer-derived Streamlit cache")
        if any(marker in text for marker in PERSISTENCE_MARKERS):
            if relative not in PERSISTENCE_ALLOWLIST and not relative.startswith("zcc_diag/tools/"):
                problems.append(f"{relative}: unapproved filesystem/database persistence")
        if "subprocess.run(" in text and relative != "zcc_diag/update_check.py":
            problems.append(f"{relative}: unapproved process handoff")
        if (any(marker in text for marker in NETWORK_MARKERS)
                and relative != "zcc_diag/update_check.py"):
            problems.append(f"{relative}: unapproved runtime network client")

    entry = (ROOT / "zcc_diag_ui.py").read_text(encoding="utf-8")
    required = (
        "RUN_MANAGER.activate_session",
        "RUN_MANAGER.begin",
        "RUN_MANAGER.purge",
        "clear_customer_session_state",
    )
    for marker in required:
        if marker not in entry:
            problems.append(f"zcc_diag_ui.py: missing lifecycle control {marker}")
    return sorted(set(problems))


def main() -> int:
    problems = findings()
    if not problems:
        print("Privacy architecture is fail-closed: no retention, export, or handoff path found.")
        return 0
    print("Privacy architecture violations:")
    for problem in problems:
        print(f"  {problem}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
