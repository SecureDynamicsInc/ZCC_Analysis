from scripts.check_privacy_architecture import findings


def test_repository_has_no_diagnostic_retention_export_or_handoff_path():
    assert findings() == []
