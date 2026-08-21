"""Per-line severity in the raw viewer, and safe match marking.

Severity has two sources and the stronger wins: the documented error catalog,
which is the authority on impact, and the record's own level, which catches
failures carrying no documented code. Getting the precedence backwards would
colour a documented terminal state as ordinary because it was logged at INFO.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import pytest

from zcc_diag.raw_view import (
    SEVERITY_CRITICAL,
    SEVERITY_MEDIUM,
    line_severity,
    severity_counts,
    to_raw_lines,
)
from zcc_diag.ui.raw import _mark_matches


@dataclass
class _Indexed:
    line_no: int
    level: str
    body: str
    ts: Optional[datetime] = None


def test_record_level_sets_severity_when_no_code_is_documented():
    assert line_severity("ERROR", "adapter enumeration failed")[0] == SEVERITY_CRITICAL
    assert line_severity("FATAL", "service aborting")[0] == SEVERITY_CRITICAL
    assert line_severity("WARN", "retrying in 5s")[0] == SEVERITY_MEDIUM
    assert line_severity("INFO", "tunnel forwarding")[0] == ""
    assert line_severity("DEBUG", "loop tick")[0] == ""


def test_short_level_spellings_are_recognised():
    # ZCC's Format A writes three-letter levels.
    assert line_severity("ERR", "something failed")[0] == SEVERITY_CRITICAL
    assert line_severity("WRN", "something odd")[0] == SEVERITY_MEDIUM
    assert line_severity("FTL", "gone")[0] == SEVERITY_CRITICAL


def test_severity_explains_itself():
    _, why = line_severity("ERROR", "adapter enumeration failed")

    # The colour has to be accountable, not decorative.
    assert why == "ERROR record"


def test_a_documented_critical_code_outranks_an_info_level():
    """The catalog is the authority on impact.

    Several terminal states are logged at INFO. If the level won, the row would
    render as ordinary traffic.
    """
    from zcc_diag.error_catalog import catalog_entries

    critical = next(
        entry for entry in catalog_entries()
        if entry.severity == "critical" and entry.code and len(entry.code) > 4
    )
    severity, why = line_severity("INFO", f"session closed: {critical.code}")

    assert severity == SEVERITY_CRITICAL
    assert "documented critical" in why
    assert critical.code in why


def test_an_unremarkable_info_line_stays_uncoloured():
    severity, why = line_severity("INFO", "ZSATunnel: periodic keepalive sent")

    assert severity == ""
    assert why == ""


def test_to_raw_lines_classifies_and_keeps_the_body_intact():
    rows = to_raw_lines([
        _Indexed(1, "INFO", "tunnel forwarding"),
        _Indexed(2, "ERROR", "connect failed to 165.225.60.15"),
        _Indexed(3, "WARN", "slow response"),
    ])

    assert [row.severity for row in rows] == ["", SEVERITY_CRITICAL, SEVERITY_MEDIUM]
    assert rows[1].body == "connect failed to 165.225.60.15"
    # The address is still tokenised inside a critical row.
    assert 'class="hl-ipv4"' in rows[1].highlighted


def test_severity_counts_tally_every_row():
    rows = to_raw_lines([
        _Indexed(1, "INFO", "a"), _Indexed(2, "ERROR", "b"),
        _Indexed(3, "WARN", "c"), _Indexed(4, "ERROR", "d"),
    ])

    counts = severity_counts(rows)

    assert counts[SEVERITY_CRITICAL] == 2
    assert counts[SEVERITY_MEDIUM] == 1
    assert counts["other"] == 1
    assert sum(counts.values()) == len(rows)


# --------------------------------------------------------------------------
# Match marking
# --------------------------------------------------------------------------

def test_matches_are_marked_in_plain_text():
    marked = _mark_matches("connect failed to gateway", "failed")

    assert marked == 'connect <span class="match">failed</span> to gateway'


def test_marking_never_edits_inside_a_tag():
    """A query colliding with a class name must not corrupt the markup.

    ``hl`` appears in every token class, so a naive replace would rewrite the
    attributes and destroy the line.
    """
    highlighted = '<span class="hl-ipv4">10.0.0.1</span> reached'

    marked = _mark_matches(highlighted, "hl")

    assert marked == highlighted  # nothing outside a tag contains "hl"
    assert 'class="hl-ipv4"' in marked


def test_marking_is_case_insensitive_and_preserves_original_case():
    marked = _mark_matches("SAML_EXPIRED seen", "saml")

    assert '<span class="match">SAML</span>_EXPIRED seen' == marked


def test_marking_handles_repeats_and_an_empty_query():
    assert _mark_matches("aXbXc", "X").count('class="match"') == 2
    assert _mark_matches("untouched", "") == "untouched"


@pytest.mark.parametrize("query", ["<", ">", '"', "span"])
def test_marking_with_markup_characters_leaves_tags_valid(query):
    highlighted = '<span class="hl-ts">2026-08-18 14:02:11</span> ok'

    marked = _mark_matches(highlighted, query)

    # Tag count is unchanged, so the block still renders.
    assert marked.count("<span") >= highlighted.count("<span")
    assert marked.count("</span>") >= highlighted.count("</span>")


# --------------------------------------------------------------------------
# Level handling.
#
# The store's line regex captures DBG|INF|WAR|WRN|ERR|CRT|TRC and stores the
# level unnormalised, so the three-letter forms are what reach the viewer. WAR
# and CRT were missing from the severity sets, which meant the most common
# warning spelling in a real log rendered as ordinary traffic.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("level", ["ERR", "CRT", "ERROR", "FATAL", "CRITICAL"])
def test_error_level_spellings_are_critical(level):
    assert line_severity(level, "gateway unreachable")[0] == SEVERITY_CRITICAL


@pytest.mark.parametrize("level", ["WAR", "WRN", "WARN", "WARNING"])
def test_warning_level_spellings_are_medium(level):
    assert line_severity(level, "retrying")[0] == SEVERITY_MEDIUM


@pytest.mark.parametrize("level", ["INF", "DBG", "TRC", "VRB"])
def test_ordinary_levels_stay_uncoloured(level):
    assert line_severity(level, "keepalive sent")[0] == ""


def test_level_filter_keeps_original_line_numbers():
    from zcc_diag.raw_view import (
        LEVEL_SCOPE_ALL, LEVEL_SCOPE_BOTH, LEVEL_SCOPE_ERRORS,
        LEVEL_SCOPE_WARNINGS, filter_by_level,
    )

    rows = to_raw_lines([
        _Indexed(10, "INF", "start"),
        _Indexed(11, "WAR", "odd"),
        _Indexed(12, "ERR", "failed"),
        _Indexed(13, "DBG", "tick"),
        _Indexed(14, "CRT", "fatal"),
    ])

    assert [r.line_no for r in filter_by_level(rows, LEVEL_SCOPE_ALL)] == [10, 11, 12, 13, 14]
    # The record's own position in the file survives filtering, so a filtered
    # view still says where you are.
    assert [r.line_no for r in filter_by_level(rows, LEVEL_SCOPE_BOTH)] == [11, 12, 14]
    assert [r.line_no for r in filter_by_level(rows, LEVEL_SCOPE_ERRORS)] == [12, 14]
    assert [r.line_no for r in filter_by_level(rows, LEVEL_SCOPE_WARNINGS)] == [11]


def test_content_columns_covers_the_longest_record():
    from zcc_diag.raw_view import content_columns

    rows = to_raw_lines([
        _Indexed(1, "INF", "short"),
        _Indexed(2, "ERR", "x" * 400),
    ])

    columns = content_columns(rows)

    # Must exceed the longest body, since the gutter, timestamp and level sit
    # ahead of it. Without this the scroller cannot reach the end of the line.
    assert columns > 400
    assert content_columns([]) >= 120


# --------------------------------------------------------------------------
# Synthetic (100.64.x.x) addresses.
#
# These are fabricated locally by the client, so a failure to reach one is a
# local interception problem. Presenting them as ordinary destinations sends
# an investigation to the network team for a client-side fault.
# --------------------------------------------------------------------------

def test_the_default_synthetic_range_is_explained_as_private_access():
    from zcc_diag.synthetic_ip import describe_address

    note = describe_address("100.64.12.9")

    assert note is not None
    assert note.basis == "documented"
    assert "Private Access" in note.headline
    assert "100.64.0.0/16" in note.detail


def test_the_health_check_address_carries_its_observed_role():
    from zcc_diag.synthetic_ip import describe_address

    note = describe_address("100.64.0.6")

    assert note.headline == "ZIA tunnel health check"
    # Labelled observed, because Zscaler does not publish a per-address map.
    assert note.basis == "observed"
    assert "not vendor-documented" in note.title


def test_cgnat_outside_the_default_range_is_not_called_a_synthetic_ip():
    from zcc_diag.synthetic_ip import describe_address

    note = describe_address("100.100.5.5")

    assert note is not None
    assert "RFC 6598" in note.headline


def test_ordinary_addresses_get_no_note():
    from zcc_diag.synthetic_ip import describe_address

    for value in ["165.225.60.15", "10.0.0.5", "192.168.1.1", "100.63.255.255",
                  "100.128.0.1", "not-an-ip"]:
        assert describe_address(value) is None, value


def test_synthetic_addresses_are_marked_in_the_rendered_line():
    rows = to_raw_lines([
        _Indexed(1, "INF", "checkTunTcpEchoServerUpImpl: Connecting to 100.64.0.6:80"),
        _Indexed(2, "INF", "connect 165.225.60.15:443 established"),
    ])

    assert "hl-synthetic" in rows[0].highlighted
    assert "ZIA tunnel health check" in rows[0].highlighted
    # A real service edge address must not be annotated as synthetic.
    assert "hl-synthetic" not in rows[1].highlighted


def test_notes_in_collects_each_distinct_address_once():
    from zcc_diag.synthetic_ip import notes_in

    found = notes_in(
        "probe 100.64.0.6:80 then 100.64.0.6:80 again, app at 100.64.3.44, "
        "edge 165.225.60.15"
    )

    assert sorted(found) == ["100.64.0.6", "100.64.3.44"]


def test_level_cell_is_class_tagged_for_colouring():
    from zcc_diag.raw_view import level_html

    assert 'class="lv lv-err"' in level_html("ERR")
    assert 'class="lv lv-crt"' in level_html("CRT")
    assert 'class="lv lv-war"' in level_html("WAR")
    assert 'class="lv lv-wrn"' in level_html("WRN")
    assert 'class="lv lv-trc"' in level_html("TRC")
    # An unknown level still renders, just without a colour class.
    assert level_html("XYZ").count("lv-") == 0
    assert level_html("") .count("lv-") == 0
