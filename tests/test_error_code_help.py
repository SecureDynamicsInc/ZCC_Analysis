from types import SimpleNamespace

from zcc_diag.error_code_help import detect_documented_codes, explain_code


def test_exact_numeric_code_lookup_returns_documented_action():
    rows = explain_code("4")
    assert rows
    assert any("system time" in row.resolution.lower() for row in rows)


def test_detects_numeric_code_only_in_error_code_context():
    idx = SimpleNamespace(lines=[
        SimpleNamespace(body="retry 4 of 5"),
        SimpleNamespace(body="cloud authentication error code: -13"),
    ])
    rows = detect_documented_codes(idx)
    assert any(row.code == "-13" and row.occurrences == 1 for row in rows)
    assert not any(row.code in {"4", "5"} for row in rows)


def test_detects_documented_session_code_from_signal_counts():
    rows = detect_documented_codes(
        SimpleNamespace(lines=[]),
        signal_counts={"AST_MT_SETUP_ERR_AST_IN_PAUSE_STATE_FOR_UPGRADE": 2},
    )
    assert any(
        row.code == "AST_MT_SETUP_ERR_AST_IN_PAUSE_STATE_FOR_UPGRADE"
        and row.occurrences == 2
        for row in rows
    )


def test_signal_count_is_not_double_counted_by_reconstructed_sessions():
    session = SimpleNamespace(
        ack_error="AST_MT_SETUP_ERR_AST_IN_PAUSE_STATE_FOR_UPGRADE",
        end_error="",
    )
    rows = detect_documented_codes(
        SimpleNamespace(lines=[]),
        sessions=[session],
        signal_counts={"AST_MT_SETUP_ERR_AST_IN_PAUSE_STATE_FOR_UPGRADE": 2},
    )
    assert any(row.occurrences == 2 for row in rows)
