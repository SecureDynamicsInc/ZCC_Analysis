#!/usr/bin/env python3
"""Verify Developer Certificate of Origin sign-offs for a commit range."""

from __future__ import annotations

import re
import subprocess
import sys


SIGNOFF_RE = re.compile(r"^Signed-off-by:\s+.+\s+<[^<>\s]+@[^<>\s]+>\s*$", re.I)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def unsigned_commits(base: str, head: str) -> list[tuple[str, str]]:
    commits = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    missing: list[tuple[str, str]] = []
    for commit in commits:
        subject = git("show", "-s", "--format=%s", commit).strip()
        body = git("show", "-s", "--format=%B", commit)
        if not any(SIGNOFF_RE.match(line.strip()) for line in body.splitlines()):
            missing.append((commit, subject))
    return missing


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_dco.py BASE_SHA HEAD_SHA", file=sys.stderr)
        return 2
    try:
        missing = unsigned_commits(sys.argv[1], sys.argv[2])
    except subprocess.CalledProcessError as exc:
        print(exc.stderr or str(exc), file=sys.stderr)
        return 2
    if not missing:
        print("DCO sign-off present on every introduced commit.")
        return 0
    print("The following commits lack a valid Signed-off-by line:", file=sys.stderr)
    for commit, subject in missing:
        print(f"  {commit[:12]} {subject}", file=sys.stderr)
    print("\nAmend each commit with `git commit --amend -s` and update the branch.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
