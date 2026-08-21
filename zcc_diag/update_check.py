# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Small, privacy-preserving GitHub update check for the local analyzer."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.request import Request, urlopen


LATEST_MAIN_API = "https://api.github.com/repos/SecureDynamicsInc/ZCC_Analysis/commits/main"


@dataclass(frozen=True)
class UpdateStatus:
    state: str  # current | update_available | unavailable
    local_sha: str = ""
    latest_sha: str = ""
    error: str = ""


def source_repo_path(runtime_root: Path) -> Path:
    marker = runtime_root / ".source_repo_path"
    if marker.is_file():
        value = marker.read_text(encoding="utf-8").strip()
        if value:
            return Path(value).expanduser()
    return runtime_root


def local_main_sha(runtime_root: Path) -> str:
    marker = runtime_root / ".build_main_commit"
    if marker.is_file():
        value = marker.read_text(encoding="utf-8").strip()
        if value:
            return value
    root = source_repo_path(runtime_root)
    for ref in ("refs/remotes/origin/main", "main", "HEAD"):
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--verify", ref],
                check=True, capture_output=True, text=True, timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        sha = result.stdout.strip()
        if sha:
            return sha
    return ""


def latest_main_sha(
    opener: Callable = urlopen, *, timeout: float = 3.0,
) -> str:
    request = Request(
        LATEST_MAIN_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "SecureDynamics-ZCC-Log-Explorer",
        },
    )
    with opener(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return str(payload.get("sha") or "").strip()


def latest_origin_main_sha(runtime_root: Path) -> str:
    """Read origin/main using the clone's existing Git authentication."""
    root = source_repo_path(runtime_root)
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-remote", "--exit-code",
             "origin", "refs/heads/main"],
            check=True, capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    first = result.stdout.strip().splitlines()
    return first[0].split()[0] if first and first[0].split() else ""


def check_for_update(runtime_root: Path, opener: Callable = urlopen) -> UpdateStatus:
    local = local_main_sha(runtime_root)
    if not local:
        return UpdateStatus("unavailable", error="Local version could not be identified.")
    latest = latest_origin_main_sha(runtime_root)
    if not latest:
        try:
            latest = latest_main_sha(opener)
        except Exception as exc:  # noqa: BLE001 - network failures must not block analysis
            return UpdateStatus("unavailable", local_sha=local, error=str(exc))
    if not latest:
        return UpdateStatus("unavailable", local_sha=local, error="GitHub returned no commit identifier.")
    return UpdateStatus(
        "current" if local == latest else "update_available",
        local_sha=local, latest_sha=latest,
    )


def agent_update_prompt(repo_path: Path) -> str:
    return (
        f"Update my local ZCC Log Explorer clone at {repo_path} from origin/main. "
        "First inspect git status, including ignored files, and run both repository privacy "
        "checks. Stop if any diagnostic, customer-derived file, or unexplained local change "
        "is present; do not preserve or commit it. MaxMind databases belong outside the "
        "clone and must not be moved. Run ./scripts/update_install.sh so the official "
        "checkout is replaced from a validated fresh origin/main clone rather than merged "
        "in place. Before confirming its replacement warning, preserve any customization "
        "in a separate fork or checkout path. Never join histories, use reset --hard, or "
        "overwrite reviewed source work. Confirm the full test suite passes and the "
        "always-on 127.0.0.1 HTTP "
        "service uses the updated version. Do not open or merge a pull request. Community "
        "changes are "
        "Issues only; any official source change requires separate maintainer "
        "authorization and approval from the other appointed maintainer. Independent "
        "Codex and Claude review is recommended administrative practice, not a required "
        "or technically attested gate."
    )
