from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_community_contribution_path_is_issues_only():
    contributing = _read("CONTRIBUTING.md")
    governance = _read("GOVERNANCE.md")
    agents = _read("AGENTS.md")

    assert "Community contribution path: Issues only" in contributing
    assert "External pull requests are not accepted" in contributing
    assert "External pull requests" in governance
    assert "private forks are disabled" in governance
    assert "Community participation is Issues only" in agents


def test_issue_forms_require_no_customer_evidence_or_code_attachments():
    for relative in (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/missing_error_code.yml",
    ):
        form = _read(relative)
        assert "customer evidence" in form
        assert "patches" in form
        assert "Issues only" in form


def test_main_push_guard_requires_issue_and_other_maintainer_with_model_reminder():
    hook = _read(".githooks/pre-push")

    assert "ZCC_CHANGE_ISSUE" in hook
    assert "ZCC_APPROVING_MAINTAINER" in hook
    assert "ZCC_DUAL_MODEL_REVIEW" not in hook
    assert "model review is recommended administrative practice" in hook
    assert "git merge-base --is-ancestor" in hook
    assert "python scripts/check_public_tree.py --commits-range" in hook
    assert "python scripts/check_dco.py" in hook
    assert "python -m pytest -q" in hook


def test_coding_agent_instructions_treat_model_review_as_advisory():
    for relative in ("AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md"):
        instructions = _read(relative)
        assert "not required" in instructions or "not a required" in instructions
        assert "approval from" in instructions or "must approve" in instructions


def test_privacy_workflow_scans_pull_requests_and_main_push_ranges():
    workflow = _read(".github/workflows/privacy.yml")

    assert "pull_request:" in workflow
    assert "branches: [main]" in workflow
    assert "BEFORE_SHA" in workflow
    assert "PR_BASE_SHA" in workflow
    assert "Initial root commit" in workflow
    assert "--commits-range" in workflow
