from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_official_origin_and_trademark_policy_are_published():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    policy = (ROOT / "TRADEMARKS.md").read_text(encoding="utf-8")

    assert "https://github.com/SecureDynamicsInc/ZCC_Analysis" in notice
    assert "Forks and derivative distributions must use their own name" in policy
    assert "may not be used" in policy


def test_app_displays_license_and_official_source():
    source = (ROOT / "zcc_diag_ui.py").read_text(encoding="utf-8")

    assert 'with st.expander("About, license, and official distribution")' in source
    assert "Apache License 2.0" in source
    assert "SecureDynamicsInc/ZCC_Analysis" in source


def test_primary_entrypoints_have_spdx_headers():
    for relative in ("zcc_diag_ui.py", "run_local.py", "start.sh", "server.sh", "run_ui.ps1"):
        beginning = (ROOT / relative).read_text(encoding="utf-8")[:240]
        assert "Copyright 2026 SecureDynamics, Inc." in beginning
        assert "SPDX-License-Identifier: Apache-2.0" in beginning
