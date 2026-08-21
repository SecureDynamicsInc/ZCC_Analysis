"""The bundle recap and the evidence checklist.

The checklist has to be right about *absence* as much as presence: a missing
tunnel log is a collection gap an engineer should be told about, and reporting
it as present would send them looking for evidence that was never collected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

import pytest

from zcc_diag.evidence_catalog import (
    COMPONENT_CATALOG,
    FOREIGN_CATALOG,
    PACKET_CAPTURE,
    BundleRecap,
    build_recap,
)


@dataclass
class _Facts:
    """Only the fields the recap reads."""

    user_login: Optional[str] = "jsmith"
    user_hostname: Optional[str] = "LT-JSMITH-01"
    zcc_version: Optional[str] = "4.4.0.245"
    os_family: Optional[str] = "windows"
    first_ts: Optional[datetime] = datetime(2026, 8, 14, 9, 30, tzinfo=timezone.utc)
    last_ts: Optional[datetime] = datetime(2026, 8, 18, 17, 5, tzinfo=timezone.utc)
    duration_seconds: Optional[float] = 4 * 86400 + 7 * 3600
    bundle_tz_label: Optional[str] = "UTC-06:00"
    total_lines: int = 1_204_331
    bundle_log_file_count: int = 42
    lines_by_component: Dict[str, int] = field(default_factory=lambda: {
        "tunnel": 812_004, "service": 301_222, "upm": 60_120, "tray": 30_985,
    })
    lines_by_level: Dict[str, int] = field(default_factory=lambda: {
        "INFO": 900_000, "ERROR": 4_120, "WARN": 30_000,
    })
    distinct_source_files: List[str] = field(default_factory=lambda: [
        "ZSATunnel.log", "ZSAService.log", "ZSAUpm.log", "ZSATrayManager.log",
    ])


@dataclass
class _Pcap:
    ts_first: datetime
    ts_last: datetime


def _row(recap: BundleRecap, key: str):
    return next(row for row in recap.evidence if row.kind.key == key)


def test_recap_reads_identity_and_window_from_the_parsed_facts():
    recap = build_recap(_Facts())

    assert recap.user == "jsmith"
    assert recap.device == "LT-JSMITH-01"
    assert recap.os_label == "Windows"
    assert recap.zcc_version == "4.4.0.245"
    assert recap.span_label == "2026-08-14 09:30 → 2026-08-18 17:05 UTC"
    assert recap.duration_label == "4d 7h"
    assert recap.timezone_label == "UTC-06:00"


def test_absent_identity_is_reported_as_absent_not_invented():
    recap = build_recap(_Facts(user_login=None, user_hostname="", first_ts=None))

    assert recap.user == ""
    assert recap.device == ""
    # An unresolved window must not render as a plausible-looking range.
    assert recap.span_label == BundleRecap.UNKNOWN


def test_present_components_are_marked_from_the_parsers_own_classification():
    recap = build_recap(_Facts())

    assert _row(recap, "tunnel").present is True
    assert "812,004 records" in _row(recap, "tunnel").detail
    assert _row(recap, "service").present is True
    assert _row(recap, "upm").present is True
    # Nothing classified these, so they must read as missing.
    assert _row(recap, "updater").present is False
    assert _row(recap, "credential").present is False
    assert _row(recap, "updater").detail == ""


def test_a_bundle_with_no_tunnel_log_flags_the_gap():
    facts = _Facts(
        lines_by_component={"tray": 900},
        distinct_source_files=["ZSATrayManager.log"],
    )

    recap = build_recap(facts)

    assert _row(recap, "tunnel").present is False
    missing = {row.kind.key for row in recap.missing_important}
    # These four change what an investigation can conclude.
    assert {"tunnel", "service", "upm", "pcap"} == missing


def test_packet_capture_presence_and_window_come_from_the_captures():
    pcaps = [
        _Pcap(datetime(2026, 8, 18, 16, 40, tzinfo=timezone.utc),
              datetime(2026, 8, 18, 16, 52, tzinfo=timezone.utc)),
        _Pcap(datetime(2026, 8, 18, 16, 55, tzinfo=timezone.utc),
              datetime(2026, 8, 18, 17, 4, tzinfo=timezone.utc)),
    ]

    recap = build_recap(_Facts(), pcaps=pcaps)

    assert recap.pcap_count == 2
    assert _row(recap, "pcap").present is True
    assert recap.pcap_window == "2026-08-18 16:40 → 17:04 UTC"
    assert "pcap" not in {row.kind.key for row in recap.missing_important}


def test_no_packet_capture_is_stated_rather_than_left_blank():
    recap = build_recap(_Facts())

    assert recap.pcap_count == 0
    assert _row(recap, "pcap").present is False
    assert PACKET_CAPTURE.tells_you  # the educational text is always available


def test_pac_recovery_count_feeds_the_checklist():
    assert _row(build_recap(_Facts(), pac_documents=0), "pac").present is False
    assert _row(build_recap(_Facts(), pac_documents=2), "pac").present is True


def test_foreign_evidence_is_detected_by_filename():
    facts = _Facts(distinct_source_files=[
        "ZSATunnel.log", "setupapi.dev.log", "zapprd.log",
    ])

    recap = build_recap(facts)

    assert _row(recap, "setupapi.dev").present is True
    assert _row(recap, "zapprd").present is True
    assert _row(recap, "profiles.log").present is False


def test_debug_verbosity_is_reported_because_absence_means_less_without_it():
    quiet = build_recap(_Facts())
    verbose = build_recap(_Facts(lines_by_level={"DEBUG": 5000, "INFO": 10}))

    assert quiet.has_debug_logging is False
    assert verbose.has_debug_logging is True


def test_every_catalog_entry_can_teach_what_it_is_for():
    # The checklist is the educational surface, so no row may be silent.
    for kind in (*COMPONENT_CATALOG, *FOREIGN_CATALOG, PACKET_CAPTURE):
        assert kind.label and kind.filenames
        assert len(kind.tells_you) > 40, kind.key
        assert kind.reach_for_it, kind.key


@pytest.mark.parametrize("pro_mode", [True, False])
def test_novice_wording_falls_back_to_the_engineering_text(pro_mode):
    tunnel = next(k for k in COMPONENT_CATALOG if k.key == "tunnel")
    updater = next(k for k in COMPONENT_CATALOG if k.key == "updater")

    assert tunnel.label_for(pro_mode=pro_mode)
    # The tunnel log has plain wording; the updater does not and must not blank.
    assert updater.label_for(pro_mode=pro_mode) == "Updater log"
    assert updater.tells_you_for(pro_mode=pro_mode) == updater.tells_you
    if not pro_mode:
        assert tunnel.label_for(pro_mode=False) == "Connection log"


def test_rotation_coverage_is_carried_through_for_the_caption():
    recap = build_recap(_Facts(), rotations_read=10, rotations_found=1_183)

    assert (recap.rotations_read, recap.rotations_found) == (10, 1_183)
    assert recap.present_count >= 4
