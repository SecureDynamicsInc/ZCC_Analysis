from pathlib import Path
import os
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "update_install.sh"


def test_updater_always_uses_a_fresh_replacement_checkout():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "git clone --branch main --single-branch" in text
    assert "Type REPLACE to continue" in text
    assert "preserve that work in a" in text
    assert "separate fork or checkout path" in text
    assert "ls-files --others --ignored --exclude-standard -z" in text
    assert text.count('ensure_clean_checkout "$ROOT"') == 2
    assert "--allow-unrelated-histories" not in text
    assert "merge --ff-only" not in text
    assert "reset --hard" not in text
    assert "rm -rf" not in text


def test_updater_is_valid_bash():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def _git(directory: Path, *arguments: str, check: bool = True):
    return subprocess.run(
        ["git", "-C", str(directory), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def _write_synthetic_checkout(directory: Path, marker: str):
    (directory / "scripts").mkdir(parents=True)
    (directory / "tests").mkdir()
    (directory / "scripts" / "update_install.sh").write_text(
        SCRIPT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (directory / "scripts" / "update_install.sh").chmod(0o755)
    for name in ("check_public_tree.py", "check_privacy_architecture.py"):
        (directory / "scripts" / name).write_text(
            "print('synthetic check passed')\n", encoding="utf-8"
        )
    (directory / "tests" / "test_smoke.py").write_text(
        "def test_synthetic_checkout():\n    assert True\n", encoding="utf-8"
    )
    (directory / "pytest.py").write_text(
        "raise SystemExit(0)\n", encoding="utf-8"
    )
    (directory / "server.sh").write_text(
        "#!/usr/bin/env bash\nset -eu\ntest \"${1:-}\" = install\n",
        encoding="utf-8",
    )
    (directory / "server.sh").chmod(0o755)
    (directory / "requirements-dev.txt").write_text("", encoding="utf-8")
    (directory / ".gitignore").write_text(
        ".venv/\n.run/\n.pytest_cache/\n__pycache__/\n", encoding="utf-8"
    )
    (directory / "marker.txt").write_text(marker, encoding="utf-8")


def _commit_all(directory: Path, message: str):
    _git(directory, "add", "--all")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Synthetic Maintainer",
            "GIT_AUTHOR_EMAIL": "user@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic Maintainer",
            "GIT_COMMITTER_EMAIL": "user@example.invalid",
        }
    )
    subprocess.run(
        ["git", "-C", str(directory), "commit", "-m", message],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_updater_replaces_related_and_unrelated_histories_from_fresh_clones(tmp_path):
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)

    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "-b", "main")
    _write_synthetic_checkout(seed, "baseline")
    _commit_all(seed, "Synthetic baseline")
    _git(seed, "remote", "add", "origin", str(remote))
    _git(seed, "push", "-u", "origin", "main")

    installed = tmp_path / "installed"
    subprocess.run(
        ["git", "clone", "--branch", "main", str(remote), str(installed)],
        check=True,
        capture_output=True,
    )
    (installed / ".venv" / "bin").mkdir(parents=True)
    synthetic_python = installed / ".venv" / "bin" / "python"
    synthetic_python.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8"
    )
    synthetic_python.chmod(0o755)

    (seed / "marker.txt").write_text("fast-forward", encoding="utf-8")
    _commit_all(seed, "Synthetic fast-forward")
    _git(seed, "push", "origin", "main")
    prior_head = _git(installed, "rev-parse", "HEAD").stdout
    cancelled = subprocess.run(
        [str(installed / "scripts" / "update_install.sh")],
        cwd=installed,
        check=False,
        capture_output=True,
        text=True,
        input="",
    )
    assert cancelled.returncode == 5
    assert "WARNING: this updater does not merge" in cancelled.stdout
    assert "confirmation was not received" in cancelled.stdout
    assert _git(installed, "rev-parse", "HEAD").stdout == prior_head

    subprocess.run(
        [str(installed / "scripts" / "update_install.sh")],
        cwd=installed,
        check=True,
        capture_output=True,
        text=True,
        input="REPLACE\n",
    )
    related_head = _git(seed, "rev-parse", "HEAD").stdout
    assert _git(installed, "rev-parse", "HEAD").stdout == related_head
    subprocess.run(
        [str(installed / ".venv" / "bin" / "python"), "-c", "import sys"],
        check=True,
        capture_output=True,
        text=True,
    )
    first_backups = list(tmp_path.glob(".installed.obsolete.*"))
    assert len(first_backups) == 1
    assert _git(first_backups[0], "rev-parse", "HEAD").stdout != related_head

    assert _git(installed, "rev-parse", "HEAD").stdout == _git(
        seed, "rev-parse", "HEAD"
    ).stdout

    replacement = tmp_path / "replacement"
    replacement.mkdir()
    _git(replacement, "init", "-b", "main")
    _write_synthetic_checkout(replacement, "replacement")
    _commit_all(replacement, "Synthetic replacement history")
    _git(replacement, "remote", "add", "origin", str(remote))
    _git(replacement, "push", "--force", "origin", "main")

    migration = subprocess.run(
        [str(installed / "scripts" / "update_install.sh")],
        cwd=installed,
        check=False,
        capture_output=True,
        text=True,
        input="REPLACE\n",
    )
    assert migration.returncode == 0, migration.stderr
    assert "Replaced the clean official checkout" in migration.stdout
    assert _git(installed, "rev-parse", "HEAD").stdout == _git(
        replacement, "rev-parse", "HEAD"
    ).stdout
    backups = list(tmp_path.glob(".installed.obsolete.*"))
    assert len(backups) == 2
    backup_heads = {_git(path, "rev-parse", "HEAD").stdout for path in backups}
    assert related_head in backup_heads
