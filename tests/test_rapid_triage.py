from datetime import datetime, timezone
from types import SimpleNamespace

from zcc_diag.log_index import IndexedLine, LogIndex
from zcc_diag.rapid_triage import (
    TunnelSignals,
    build_rapid_triage,
    scan_tunnel_signals,
    session_category,
)
from zcc_diag.ui.quick_triage import _plain_text
from zcc_diag.ui.tunnel_apps import _novice_row


def _line(body: str, line_no: int = 1) -> IndexedLine:
    return IndexedLine(
        ts=datetime(2026, 8, 19, 12, 0, line_no, tzinfo=timezone.utc),
        pid="1", tid="2", level="INF", body=body,
        component="tunnel", source_file="ZSATunnel.log", line_no=line_no,
    )


def _session(**overrides):
    values = dict(
        ack_error="", end_error="", outcome="closed",
        app_name="payroll.internal", bytes_to_server=100,
        bytes_from_server=100, has_byte_imbalance=False,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_recovered_server_down_is_soft_failure():
    index = LogIndex(lines=[
        _line("ZApp Status getSmeProxyState:SERVER_DOWN_ERROR", 1),
        _line("ZApp Status getSmeProxyState:TUNNEL_FORWARDING", 2),
    ])
    signals = scan_tunnel_signals(index)
    triage = build_rapid_triage([], signals, [])

    finding = next(f for f in triage.findings if f.area == "ZIA")
    assert finding.kind == "soft"
    assert "recovered" in finding.title.lower()
    assert signals.zia_last_state == "TUNNEL_FORWARDING"


def test_policy_block_uses_documented_resolution():
    session = _session(
        ack_error="BRK_MT_SETUP_FAIL_NO_POLICY_FOUND",
        outcome="setup_failed",
    )
    signals = scan_tunnel_signals(LogIndex(lines=[_line("ordinary tunnel record")]))
    triage = build_rapid_triage([session], signals, [])

    assert session_category(session) == "Policy blocked"
    finding = next(f for f in triage.findings if f.code.endswith("NO_POLICY_FOUND"))
    assert finding.kind == "policy"
    assert "policy" in finding.next_action.lower()


def test_packet_failures_surface_before_metadata():
    pcap = SimpleNamespace(
        path=SimpleNamespace(name="CaptureLWF.pcapng"),
        dns_nxdomain={"missing.internal  [NXDOMAIN]": 2},
        tcp_resets={"10.0.0.1:50000 -> 10.0.0.2:443": 1},
        tcp_retransmits={}, tls_alerts={},
    )
    signals = scan_tunnel_signals(LogIndex(lines=[_line("ordinary tunnel record")]))
    triage = build_rapid_triage([], signals, [pcap])

    assert triage.findings[0].area == "DNS"
    assert triage.findings[0].kind == "hard"
    assert any(f.area == "TCP" for f in triage.findings)


def test_missing_tunnel_log_is_explicit_coverage_gap():
    triage = build_rapid_triage([], scan_tunnel_signals(LogIndex()), [])
    assert triage.findings[0].kind == "coverage"
    assert "ZSATunnel" in triage.findings[0].next_action


def test_unknown_caller_is_not_misread_as_unknown_ca_tls_alert():
    signals = scan_tunnel_signals(LogIndex(lines=[
        _line("updateProxySettings called: reason=UNKNOWN_CALLER")
    ]))
    assert signals.phrase_counts["ssl_interception"] == 0


def test_phrase_finding_keeps_one_matching_log_sample():
    index = LogIndex(lines=[
        _line("connect failed: No route to host", 7),
        _line("connect failed: No route to host", 8),
    ])
    triage = build_rapid_triage([], scan_tunnel_signals(index), [])

    finding = next(f for f in triage.findings if "no route" in f.title.lower())
    assert finding.evidence == "2 matching record(s)"
    assert finding.sample is not None
    assert finding.sample.line_no == 7
    assert finding.sample.body == "connect failed: No route to host"


def test_packet_findings_include_ready_to_copy_wireshark_filter():
    pcap = SimpleNamespace(
        path=SimpleNamespace(name="sample.pcapng"),
        dns_nxdomain={"missing.example.test  [A]": 2},
        tcp_resets={}, tcp_reset_endpoints={}, tcp_retransmits={},
        tls_alerts={}, tls_alert_endpoints={},
    )
    triage = build_rapid_triage([], TunnelSignals(tunnel_records=1), [pcap])
    finding = next(item for item in triage.findings if item.area == "DNS")
    assert 'dns.qry.name == "missing.example.test"' in finding.wireshark_filter
    assert "Wireshark" in finding.next_action


def test_novice_copy_translates_internal_connection_shorthand():
    result = _plain_text(
        "ZIA tunnel recovered from SERVER_DOWN_ERROR after TCP RST"
    )
    assert "ZIA" not in result
    assert "SERVER_DOWN_ERROR" not in result
    assert "TCP RST" not in result
    assert "internet connection" in result


def test_novice_session_row_hides_codes_tags_and_ids():
    session = _session(
        ack_error="BRK_MT_SETUP_FAIL_NO_POLICY_FOUND",
        outcome="setup_failed",
    )
    row = _novice_row(session)
    assert row["Problem"] == "Blocked by a rule"
    assert "Code" not in row
    assert "Tag" not in row


def test_service_scope_keeps_shared_network_evidence_but_hides_other_service():
    pcap = SimpleNamespace(
        path=SimpleNamespace(name="Capture.pcapng"),
        dns_nxdomain={"missing.internal [NXDOMAIN]": 1},
        tcp_resets={}, tcp_retransmits={}, tls_alerts={},
    )
    session = _session(
        ack_error="BRK_MT_SETUP_FAIL_NO_POLICY_FOUND",
        outcome="setup_failed",
    )
    index = LogIndex(lines=[
        _line("ZApp Status getSmeProxyState:SERVER_DOWN_ERROR", 1),
    ])
    triage = build_rapid_triage([session], scan_tunnel_signals(index), [pcap])

    zia = triage.for_scope("ZIA")
    zpa = triage.for_scope("ZPA")
    assert any(f.area == "ZIA" for f in zia)
    assert any(f.area == "DNS" for f in zia)
    assert not any(f.area == "ZPA" for f in zia)
    assert any(f.area == "ZPA" for f in zpa)
    assert not any(f.area == "ZIA" for f in zpa)
