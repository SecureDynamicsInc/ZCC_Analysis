from __future__ import annotations

from pathlib import Path

from zcc_diag.flow_ledger import build_ledger
from zcc_diag.log_store import build_store
from zcc_diag.setupapi_extract import network_driver_events, parse_lines


def _line(ts: str, body: str, level: str = "INF") -> str:
    return f"{ts}(+0000)[100:200] {level} {body}\n"


def test_store_assembles_records_and_builds_final_byte_ledger(tmp_path: Path) -> None:
    log = tmp_path / "ZSATunnel_2026-08-19-10-00-00.log"
    log.write_text(
        _line(
            "2026-08-19 10:00:00.000",
            "ID=123, HTTP Request Version: HTTP/1.1 Host=private.example:443",
        )
        + "destinationIps: [10.0.0.8]\n"
        + _line(
            "2026-08-19 10:00:03.000",
            "ID=123, ~ZTCPServerConnection state=closed ServerConnections=1 "
            "clt_bytes=100, srv_bytes=250!",
        ),
        encoding="utf-8",
    )

    store = build_store(str(tmp_path), read_rotations=False, db_dir=str(tmp_path))
    try:
        assert store.total_lines == 2
        assert "destinationIps" in store.record_text(store.lines[0])
        ledger = build_ledger(store)
        assert ledger.totals()["flows"] == 1
        assert ledger.totals()["total_bytes"] == 350
        assert ledger.flows[0].destination == "private.example:443"
        assert ledger.flows[0].lifetime_lines == 2
    finally:
        store.cleanup()


def test_setupapi_driver_history_keeps_device_local_time_and_provenance() -> None:
    parsed = parse_lines([
        ">>>  [Device Install (Hardware initiated) - SWD\\DRIVERENUM\\ZSCALER]\n",
        ">>>  Section start 2026/08/19 10:15:30.125\n",
        "     dvi:      {Install Device - Zscaler Network Adapter}\n",
        "     inf:      Class GUID = {4d36e972-e325-11ce-bfc1-08002be10318}\n",
        "<<<  Section end 2026/08/19 10:15:31.125\n",
        "<<<  [Exit status: SUCCESS]\n",
    ], source="setupapi.dev.log")

    assert parsed.present
    assert parsed.section_count == 1
    events = network_driver_events(parsed)
    assert len(events) == 1
    assert events[0].source == "setupapi.dev.log"
    assert events[0].when_local.tzinfo is None
    assert events[0].succeeded is True
