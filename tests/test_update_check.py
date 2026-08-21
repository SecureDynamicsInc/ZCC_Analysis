import io
import json

from types import SimpleNamespace

from zcc_diag import update_check
from zcc_diag.update_check import agent_update_prompt, check_for_update


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _opener_for(sha):
    def opener(request, timeout=0):
        assert request.full_url.endswith("/commits/main")
        assert timeout > 0
        return _Response(json.dumps({"sha": sha}).encode())
    return opener


def test_update_check_detects_new_github_main(tmp_path):
    (tmp_path / ".build_main_commit").write_text("a" * 40)
    status = check_for_update(tmp_path, _opener_for("b" * 40))
    assert status.state == "update_available"
    assert status.local_sha == "a" * 40
    assert status.latest_sha == "b" * 40


def test_update_check_reports_current_and_tolerates_network_failure(tmp_path):
    (tmp_path / ".build_main_commit").write_text("c" * 40)
    assert check_for_update(tmp_path, _opener_for("c" * 40)).state == "current"

    def broken(*_args, **_kwargs):
        raise OSError("offline")

    status = check_for_update(tmp_path, broken)
    assert status.state == "unavailable"
    assert status.local_sha == "c" * 40


def test_agent_prompt_blocks_diagnostic_local_work_and_reinstalls(tmp_path):
    prompt = agent_update_prompt(tmp_path)
    assert "Stop if any diagnostic" in prompt
    assert "do not preserve or commit it" in prompt
    assert "MaxMind databases belong outside the clone" in prompt
    assert "reset --hard" in prompt
    assert "./scripts/update_install.sh" in prompt
    assert "replaced from a validated fresh origin/main clone" in prompt
    assert "Before confirming its replacement warning" in prompt
    assert "separate fork or checkout path" in prompt
    assert "Never join histories" in prompt
    assert "Community changes are Issues only" in prompt
    assert "Do not open or merge a pull request" in prompt
    assert "recommended administrative practice, not a required" in prompt
    assert str(tmp_path) in prompt


def test_private_repo_check_uses_configured_origin(monkeypatch, tmp_path):
    source = tmp_path / "clone"
    source.mkdir()
    (tmp_path / ".source_repo_path").write_text(str(source))

    def fake_run(command, **kwargs):
        assert command == [
            "git", "-C", str(source), "ls-remote", "--exit-code",
            "origin", "refs/heads/main",
        ]
        assert kwargs["timeout"] == 5
        return SimpleNamespace(stdout=f"{'d' * 40}\trefs/heads/main\n")

    monkeypatch.setattr(update_check.subprocess, "run", fake_run)
    assert update_check.latest_origin_main_sha(tmp_path) == "d" * 40
