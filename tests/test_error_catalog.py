from types import SimpleNamespace

from zcc_diag.error_catalog import catalog_entries, lookup_entries, match_known_codes
from zcc_diag.rapid_triage import build_rapid_triage, scan_tunnel_signals


def test_catalog_contains_all_bundled_reference_rows():
    entries = catalog_entries()
    assert len(entries) == 749
    assert {entry.product for entry in entries} == {"ZCC", "ZIA", "ZPA", "ZDX"}
    assert all(entry.source_url.startswith("https://help.zscaler.com/") for entry in entries)


def test_previously_invisible_families_are_exactly_searchable():
    cases = {
        "Driver Error": "ZCC Connection Status",
        "Access denied due to bad server certificate": "ZIA Policy Reasons",
        "tcp_connection_was_reset": "ZDX Web Probe",
        "ZUPM_WORKFLOW_E_CODE_EXECUTION_TIMEOUT": "ZDX Remediation",
    }
    for query, family in cases.items():
        entry, reason = lookup_entries(query)[0]
        assert reason == "exact_code"
        assert entry.family == family


def test_log_matching_is_contextual_and_covers_symbolic_hex_and_messages():
    assert match_known_codes("retry 4 of 5") == []
    assert [e.code for e in match_known_codes("error code: -13")] == ["-13"]
    assert [e.code for e in match_known_codes("err code=0x13BC")] == ["0x13BC"]
    assert any(
        e.code == "ZUPM_WORKFLOW_E_CODE_EXECUTION_TIMEOUT"
        for e in match_known_codes("zupm_workflow_e_code_execution_timeout")
    )
    assert any(
        e.code == "tcp_connection_was_reset"
        for e in match_known_codes("TCP connection was reset")
    )


def test_documented_critical_error_leads_triage_with_sample():
    line = SimpleNamespace(
        body="tunnel failed with error code: -13",
        component="tunnel", source_file="ZSATunnel.log", line_no=44, ts=None,
    )
    signals = scan_tunnel_signals(SimpleNamespace(lines=[line]))
    triage = build_rapid_triage([], signals, [])
    finding = triage.findings[0]
    assert finding.code == "-13"
    assert finding.severity == "critical"
    assert finding.sample.body == line.body
