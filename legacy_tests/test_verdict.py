"""
Unit tests for ui/verdict.build_verdict — pure-function tests, no
Streamlit runtime needed.

What's verified
---------------
1. Clean bundle (no Critical/Warning) yields kind="clean" with a
   positive headline.
2. Bundle with only lifecycle findings yields kind="lifecycle_only".
3. Bundle with one Critical finding yields kind="incident" with a
   templated headline naming the detector family.
4. With two Critical findings, the higher-confidence one wins.
5. With equal severity + confidence, the higher count wins.
6. Lifecycle-downgraded findings DON'T become the verdict (they're
   already Info), and DO contribute to the lifecycle_note.
7. Severity counts are correctly rolled up.
8. Time window comes from the picked finding's time_range.

Run with:
    python test_verdict.py
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zcc_diag.issues import Severity
from zcc_diag.ui.verdict import build_verdict


_T0 = datetime(2026, 6, 8, 14, 32, 0, tzinfo=timezone.utc)


def _finding(
    detector_id="zia_auth_failures",
    code="ZIA_HTTP_407",
    severity=Severity.CRITICAL,
    count=5,
    confidence="high",
    title="HTTP 407 from ZIA",
    span_minutes=10,
    downgraded_from=None,
):
    end = _T0 + timedelta(minutes=span_minutes)
    f = {
        "detector_id": detector_id,
        "code": code,
        "severity": severity,
        "count": count,
        "confidence": confidence,
        "title": title,
        "description": "...",
        "time_range": (_T0, end),
        "evidence": [],
    }
    if downgraded_from:
        f["_lifecycle_downgraded_from"] = downgraded_from
    return f


class VerdictBuilderTests(unittest.TestCase):

    def test_no_findings_is_clean(self):
        v = build_verdict({"findings": []})
        self.assertEqual(v["kind"], "clean")
        self.assertEqual(v["severity"], Severity.INFO)
        self.assertIn("No incidents", v["headline"])
        self.assertIsNone(v["lifecycle_note"])

    def test_lifecycle_only_is_lifecycle_only(self):
        v = build_verdict({
            "findings": [
                _finding(
                    detector_id="system_lifecycle",
                    code="SYSTEM_WAKE_EVENT",
                    severity=Severity.INFO,
                    title="3 system wake event(s) detected",
                ),
            ],
        })
        self.assertEqual(v["kind"], "lifecycle_only")
        self.assertIn("Routine system sleep/wake", v["headline"])

    def test_single_critical_picks_it(self):
        v = build_verdict({
            "findings": [_finding(count=12, confidence="high")],
        })
        self.assertEqual(v["kind"], "incident")
        self.assertEqual(v["severity"], Severity.CRITICAL)
        self.assertIn("ZIA authentication failing", v["headline"])
        self.assertIn("12 event", v["headline"])
        self.assertEqual(v["confidence"], "high")

    def test_higher_confidence_wins(self):
        v = build_verdict({
            "findings": [
                _finding(code="A", count=8, confidence="low"),
                _finding(code="B", count=8, confidence="high"),
            ],
        })
        self.assertIn("8 event", v["headline"])
        self.assertEqual(v["confidence"], "high")
        # Both are CRITICAL with same count, the high-confidence one
        # should be the picked anchor — supporting list contains both.
        self.assertEqual(len(v["supporting"]), 2)

    def test_higher_count_breaks_confidence_tie(self):
        v = build_verdict({
            "findings": [
                _finding(code="A", count=3, confidence="high"),
                _finding(code="B", count=300, confidence="high"),
            ],
        })
        self.assertIn("300 event", v["headline"])

    def test_critical_beats_warning_even_at_higher_count(self):
        v = build_verdict({
            "findings": [
                _finding(severity=Severity.WARNING, count=999),
                _finding(severity=Severity.CRITICAL, count=2),
            ],
        })
        self.assertEqual(v["severity"], Severity.CRITICAL)
        self.assertIn("2 event", v["headline"])

    def test_downgraded_lifecycle_contributes_to_note(self):
        v = build_verdict({
            "findings": [
                _finding(
                    severity=Severity.INFO,
                    downgraded_from="CRITICAL",
                ),
            ],
        })
        # Only lifecycle-downgraded INFO findings means no Critical/Warning
        # is firing — falls back to "no incidents" or "lifecycle_only"
        self.assertIn(v["kind"], ("clean", "lifecycle_only"))
        self.assertIsNotNone(v["lifecycle_note"])
        self.assertIn("downgraded", v["lifecycle_note"])

    def test_severity_counts_rolled_up(self):
        v = build_verdict({
            "findings": [
                _finding(severity=Severity.CRITICAL),
                _finding(severity=Severity.CRITICAL),
                _finding(severity=Severity.WARNING),
                _finding(severity=Severity.INFO),
                _finding(severity=Severity.INFO),
                _finding(severity=Severity.INFO),
            ],
        })
        counts = v["severity_counts"]
        self.assertEqual(counts["critical"], 2)
        self.assertEqual(counts["warning"], 1)
        self.assertEqual(counts["info"], 3)
        self.assertEqual(counts["total"], 6)

    def test_time_window_from_picked_finding(self):
        v = build_verdict({
            "findings": [_finding(span_minutes=45)],
        })
        tw = v["time_window"]
        self.assertIsNotNone(tw)
        self.assertEqual(tw[0], _T0)
        self.assertEqual((tw[1] - tw[0]).total_seconds() / 60, 45)

    def test_skipped_detectors_are_ignored(self):
        v = build_verdict({
            "findings": [
                {"detector_id": "x", "code": "DETECTOR_SKIPPED_FOR_OS",
                 "severity": Severity.INFO, "count": 0,
                 "title": "skipped", "description": "",
                 "time_range": None, "evidence": []},
            ],
        })
        self.assertEqual(v["kind"], "clean")


if __name__ == "__main__":
    unittest.main(verbosity=2)
