"""
Synthetic-data unit tests for the new ZPA modules added in 2026-06-12.

Covers:
  1. zpa_broker_assistant_close detector — BRK_MT_CLOSED_FROM_ASSISTANT
     pattern matching, App-Name lookup via the preceding setup line,
     dedup of the drop_data:0/1 double-end pair, per-app bucketing.
  2. zpa_apps extractor — zpn_client_app JSON parsing, port range
     formatting, multi-push dedup keeping the latest state, deleted
     flag, bypass / bypass_type / icmp_access_type capture.
  3. zpa_apps broker-DC extractor — broker hostname regex.
  4. zpa_session_correlator — tag_id grouping, ack/end pairing,
     outcome derivation, double-end-dedup at session level,
     app-registry cross-reference via suffix-match.
  5. zpa_auth_failures extended ZEvent patterns — ssl_exception,
     auth_timeout, server_down, read_error, network_error,
     force_reauth_sleep / network_change_trigger.

All tests use synthetic LogLine fixtures — no real bundle needed.
Run with:
    python test_zpa_new_modules.py
"""

from __future__ import annotations

import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zcc_diag.issues import Severity
from zcc_diag.log_parser import LogLine


def _line(ts: datetime, msg: str, source="ZSATunnel.log",
          line_no=1, level="INF") -> LogLine:
    return LogLine(
        timestamp=ts, pid=1, tid=2, level=level, message=msg,
        source_path=Path(source), line_no=line_no,
        raw=f"{ts.isoformat()} {level} {msg}",
    )


def _idx_line(ts: datetime, body: str, source="ZSATunnel.log",
              line_no=1, component="tunnel"):
    """A LogIndex-style IndexedLine surrogate (just the fields the
    extractors read)."""
    return SimpleNamespace(
        ts=ts, timestamp=ts, body=body, level="INF",
        component=component, source_file=source, line_no=line_no,
        pid="1", tid="2", session_id=None, host=None,
    )


def _idx(lines):
    """A minimal LogIndex surrogate for the extractors."""
    return SimpleNamespace(lines=lines)


_T0 = datetime(2026, 6, 12, 17, 50, 0, tzinfo=timezone.utc)


# ──────────────────────────────────────────────────────────────────────
# zpa_broker_assistant_close detector
# ──────────────────────────────────────────────────────────────────────

class BrokerAssistantCloseTests(unittest.TestCase):

    def setUp(self):
        from zcc_diag.issues.zpa_broker_assistant_close import (
            ZpaAppSessionsDetector,
        )
        self.det = ZpaAppSessionsDetector()

    def _feed(self, msg, ts_offset_s=0):
        ts = _T0 + timedelta(seconds=ts_offset_s)
        self.det.feed(_line(ts, msg), summary=None)

    def test_setup_then_close_captures_app_name(self):
        self._feed(
            "===> ID=1759254811, ZPN Connection local:55984"
            "->100.64.1.1:443 App Name=storefront.corp-a.example, "
            "DoubleEncrypt=0 TAG-ID=65744",
            ts_offset_s=0,
        )
        self._feed(
            'ZPN:0: Control Message Response Data: {"zpn_mtunnel_end":'
            '{"tag_id":65744,"error":"BRK_MT_CLOSED_FROM_ASSISTANT",'
            '"err_code":5027,"drop_data":0}}',
            ts_offset_s=1,
        )
        results = self.det.finalize(summary=None)
        self.assertEqual(len(results), 1)
        self.assertIn("storefront.corp-a.example", results[0].title)
        # Per Zscaler ZPA Session Status Codes docs, BRK_MT_CLOSED_
        # FROM_ASSISTANT is the NORMAL close signal — this finding is
        # informational, NOT critical. Validated 2026-06-12 via
        # help.zscaler.com.
        self.assertEqual(results[0].severity, Severity.INFO)
        self.assertEqual(results[0].count, 1)

    def test_drop_data_double_end_deduped(self):
        """drop_data:0 + drop_data:1 within 1s for the same tag_id is
        the normal double-end pair — should count ONCE."""
        self._feed(
            "===> ID=X, ZPN Connection local:55984->1.2.3.4:443 "
            "App Name=foo.example.com, DoubleEncrypt=0 TAG-ID=99",
        )
        self._feed(
            '{"zpn_mtunnel_end":{"tag_id":99,"error":"BRK_MT_CLOSED_'
            'FROM_ASSISTANT","err_code":5027,"drop_data":0}}',
            ts_offset_s=1,
        )
        self._feed(
            '{"zpn_mtunnel_end":{"tag_id":99,"error":"BRK_MT_CLOSED_'
            'FROM_ASSISTANT","err_code":5027,"drop_data":1}}',
            ts_offset_s=1,  # 30ms later in reality, same second here
        )
        results = self.det.finalize(summary=None)
        self.assertEqual(results[0].count, 1, "Double-end should dedupe")

    def test_per_app_bucketing(self):
        """Three tag_ids targeting three different apps -> three findings."""
        for i, app in enumerate(
            ["storefront.example.com", "rds.example.com", "iris.example.com"]
        ):
            ts_setup = i * 10
            ts_close = ts_setup + 1
            self._feed(
                f"===> ID=X{i}, ZPN Connection local:{55000+i}->10.0.0.{i}:443 "
                f"App Name={app}, DoubleEncrypt=0 TAG-ID={100+i}",
                ts_offset_s=ts_setup,
            )
            self._feed(
                f'{{"zpn_mtunnel_end":{{"tag_id":{100+i},"error":'
                f'"BRK_MT_CLOSED_FROM_ASSISTANT","err_code":5027,'
                f'"drop_data":0}}}}',
                ts_offset_s=ts_close,
            )
        results = self.det.finalize(summary=None)
        self.assertEqual(len(results), 3)
        titles = " ".join(f.title for f in results)
        self.assertIn("storefront.example.com", titles)
        self.assertIn("rds.example.com", titles)
        self.assertIn("iris.example.com", titles)

    def test_close_without_setup_uses_unknown(self):
        """Close for a tag_id we never saw a setup for falls back to
        (unknown app) — common when the setup happened in a rotated
        log we don't have."""
        self._feed(
            '{"zpn_mtunnel_end":{"tag_id":999,"error":"BRK_MT_CLOSED_'
            'FROM_ASSISTANT","err_code":5027,"drop_data":0}}',
        )
        results = self.det.finalize(summary=None)
        self.assertEqual(len(results), 1)
        self.assertIn("unknown app", results[0].title)


# ──────────────────────────────────────────────────────────────────────
# zpa_apps extractor
# ──────────────────────────────────────────────────────────────────────

class ZpaAppsTests(unittest.TestCase):

    def test_extract_basic_app(self):
        from zcc_diag.zpa_apps import extract_zpa_apps
        idx = _idx([
            _idx_line(_T0, 'ZPN:0: Control Message Response Data: '
                          '{"zpn_client_app":{"app_domain":"rds.example.com",'
                          '"tcp_port_ranges":[443,443,3389,3389],'
                          '"udp_port_ranges":[],"ingress_port_ranges":[443,443],'
                          '"deleted":0,"bypass":0,"icmp_access_type":"PING",'
                          '"bypass_on_reauth":0,"double_encrypt":0,'
                          '"bypass_type":"NEVER","has_next":1}}'),
        ])
        info = extract_zpa_apps(idx)
        self.assertEqual(len(info["apps"]), 1)
        app = info["apps"][0]
        self.assertEqual(app.app_domain, "rds.example.com")
        self.assertEqual(app.tcp_port_ranges, [443, 443, 3389, 3389])
        self.assertEqual(app.bypass_type, "NEVER")
        self.assertEqual(app.icmp_access_type, "PING")
        self.assertFalse(app.bypass)
        self.assertFalse(app.deleted)

    def test_bypassed_app_recognised(self):
        from zcc_diag.zpa_apps import extract_zpa_apps
        idx = _idx([
            _idx_line(_T0, '{"zpn_client_app":{"app_domain":"iris.example.com",'
                          '"deleted":0,"bypass":1,"icmp_access_type":"NONE",'
                          '"bypass_on_reauth":0,"double_encrypt":0,'
                          '"bypass_type":"ALWAYS","has_next":1}}'),
        ])
        info = extract_zpa_apps(idx)
        app = info["apps"][0]
        self.assertTrue(app.bypass)
        self.assertEqual(app.bypass_type, "ALWAYS")

    def test_multi_push_keeps_latest_state(self):
        """Same app pushed twice — the second push has deleted=1.
        The catalog should reflect the LATEST state."""
        from zcc_diag.zpa_apps import extract_zpa_apps
        idx = _idx([
            _idx_line(_T0, '{"zpn_client_app":{"app_domain":"foo.example.com",'
                          '"tcp_port_ranges":[80,80],"deleted":0,"bypass":0,'
                          '"icmp_access_type":"PING","bypass_on_reauth":0,'
                          '"double_encrypt":0,"bypass_type":"NEVER",'
                          '"has_next":1}}'),
            _idx_line(_T0 + timedelta(hours=2),
                      '{"zpn_client_app":{"app_domain":"foo.example.com",'
                      '"tcp_port_ranges":[80,80],"deleted":1,"bypass":0,'
                      '"icmp_access_type":"NONE","bypass_on_reauth":0,'
                      '"double_encrypt":0,"bypass_type":"NEVER",'
                      '"has_next":1}}'),
        ])
        info = extract_zpa_apps(idx)
        app = info["apps"][0]
        self.assertTrue(app.deleted)
        self.assertEqual(app.push_count, 2)

    def test_empty_index_returns_empty(self):
        from zcc_diag.zpa_apps import extract_zpa_apps
        self.assertEqual(
            extract_zpa_apps(None),
            {"apps": [], "total_pushes": 0, "push_windows": []},
        )
        self.assertEqual(
            extract_zpa_apps(_idx([])),
            {"apps": [], "total_pushes": 0, "push_windows": []},
        )

    def test_find_app_for_domain_exact(self):
        from zcc_diag.zpa_apps import (
            extract_zpa_apps, find_app_for_domain,
        )
        idx = _idx([
            _idx_line(_T0, '{"zpn_client_app":{"app_domain":"rds.example.com",'
                          '"deleted":0,"bypass":0,"icmp_access_type":"NONE",'
                          '"bypass_on_reauth":0,"double_encrypt":0,'
                          '"bypass_type":"NEVER","has_next":1}}'),
        ])
        apps = extract_zpa_apps(idx)["apps"]
        match = find_app_for_domain(apps, "rds.example.com")
        self.assertIsNotNone(match)
        self.assertEqual(match.app_domain, "rds.example.com")


# ──────────────────────────────────────────────────────────────────────
# zpa_apps broker-DC extractor
# ──────────────────────────────────────────────────────────────────────

class BrokerDCTests(unittest.TestCase):

    def test_broker_hostname_extracts_dc(self):
        from zcc_diag.zpa_apps import extract_zpa_broker_dcs
        idx = _idx([
            _idx_line(_T0, 'Received event channel 0, data: {"metrics":'
                          '{"broker_hostname":"broker6-2.den3.prod.zpath.net",'
                          '"broker_ip":"136.226.87.245"}}'),
            _idx_line(_T0 + timedelta(seconds=10),
                      'broker12-1.den3.prod.zpath.net SSL closed'),
            _idx_line(_T0 + timedelta(seconds=20),
                      'broker5-1.sjc1.prod.zpath.net connect attempt'),
        ])
        info = extract_zpa_broker_dcs(idx)
        self.assertIn("den3", info["dcs"])
        self.assertIn("sjc1", info["dcs"])
        # den3 should be primary (more observations)
        self.assertEqual(info["primary_dc"], "den3")
        self.assertGreater(len(info["broker_hostnames"]), 0)

    def test_no_broker_in_index_returns_empty(self):
        from zcc_diag.zpa_apps import extract_zpa_broker_dcs
        info = extract_zpa_broker_dcs(_idx([
            _idx_line(_T0, "some unrelated line"),
        ]))
        self.assertEqual(info["dcs"], [])
        self.assertEqual(info["primary_dc"], "")


# ──────────────────────────────────────────────────────────────────────
# zpa_session_correlator
# ──────────────────────────────────────────────────────────────────────

class ZpaSessionCorrelatorTests(unittest.TestCase):

    def test_full_session_lifecycle(self):
        from zcc_diag.zpa_session_correlator import extract_zpa_sessions
        idx = _idx([
            _idx_line(_T0, '===> ID=1, ZPN Connection local:55984->'
                          '1.2.3.4:443 App Name=foo.example.com, '
                          'DoubleEncrypt=0 TAG-ID=65744'),
            _idx_line(_T0 + timedelta(seconds=1),
                      '{"zpn_mtunnel_request_ack":{"tag_id":65744,'
                      '"mtunnel_id":"x","err_code":1,"allow_all_xport":0,'
                      '"reauth_timeout_s":43200}}'),
            _idx_line(_T0 + timedelta(seconds=10),
                      '{"zpn_mtunnel_end":{"tag_id":65744,"error":'
                      '"BRK_MT_CLOSED_FROM_ASSISTANT","err_code":5027,'
                      '"drop_data":0}}'),
        ])
        sessions = extract_zpa_sessions(idx)
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual(s.tag_id, "65744")
        self.assertEqual(s.app_name, "foo.example.com")
        self.assertEqual(s.ack_err_code, 1)
        self.assertEqual(s.end_error, "BRK_MT_CLOSED_FROM_ASSISTANT")
        # Per Zscaler ZPA Session Status Codes docs, BRK_MT_CLOSED_
        # FROM_ASSISTANT is the NORMAL close signal. Validated
        # 2026-06-12 via help.zscaler.com/zpa/understanding-zpa-
        # session-status-codes.
        self.assertEqual(s.outcome, "closed")
        self.assertAlmostEqual(s.duration_s, 10, delta=0.5)

    def test_session_without_end_is_open(self):
        from zcc_diag.zpa_session_correlator import extract_zpa_sessions
        idx = _idx([
            _idx_line(_T0, '===> ID=1, ZPN Connection local:55984->'
                          '1.2.3.4:443 App Name=bar.example.com, '
                          'DoubleEncrypt=0 TAG-ID=42'),
            _idx_line(_T0 + timedelta(seconds=1),
                      '{"zpn_mtunnel_request_ack":{"tag_id":42,'
                      '"mtunnel_id":"y","err_code":1,"allow_all_xport":0,'
                      '"reauth_timeout_s":43200}}'),
        ])
        sessions = extract_zpa_sessions(idx)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].outcome, "open")

    def test_app_registry_cross_reference(self):
        from zcc_diag.zpa_session_correlator import extract_zpa_sessions
        from zcc_diag.zpa_apps import ZpaApp
        registry = [ZpaApp(app_domain="example.com", bypass=True,
                           bypass_type="ALWAYS")]
        idx = _idx([
            _idx_line(_T0, '===> ID=1, ZPN Connection local:1->2.2.2.2:443 '
                          'App Name=foo.example.com, DoubleEncrypt=0 '
                          'TAG-ID=7'),
        ])
        sessions = extract_zpa_sessions(idx, app_registry=registry)
        s = sessions[0]
        self.assertIsNotNone(s.app_registry)
        self.assertEqual(s.app_registry.app_domain, "example.com")

    def test_double_end_pair_only_first_recorded(self):
        from zcc_diag.zpa_session_correlator import extract_zpa_sessions
        idx = _idx([
            _idx_line(_T0, '===> ID=1, ZPN Connection local:1->2.2.2.2:443 '
                          'App Name=foo.example.com, DoubleEncrypt=0 '
                          'TAG-ID=8'),
            _idx_line(_T0 + timedelta(seconds=1),
                      '{"zpn_mtunnel_end":{"tag_id":8,"error":"X",'
                      '"err_code":5027,"drop_data":0}}'),
            _idx_line(_T0 + timedelta(seconds=1, milliseconds=30),
                      '{"zpn_mtunnel_end":{"tag_id":8,"error":"X",'
                      '"err_code":5027,"drop_data":1}}'),
        ])
        sessions = extract_zpa_sessions(idx)
        # Both ends are attached as lines but only the first sets end_ts.
        s = sessions[0]
        self.assertEqual(s.end_drop_data, 0)
        # Both end lines are in s.lines (2 ends + 1 setup = 3 lines)
        self.assertEqual(len(s.lines), 3)


# ──────────────────────────────────────────────────────────────────────
# zpa_auth_failures extended ZEvent patterns
# ──────────────────────────────────────────────────────────────────────

class ZpaAuthFailuresZEventTests(unittest.TestCase):

    def setUp(self):
        from zcc_diag.issues.zpa_auth_failures import (
            ZPAAuthFailuresDetector,
        )
        self.det = ZPAAuthFailuresDetector()

    def _feed(self, msg, ts_offset_s=0):
        ts = _T0 + timedelta(seconds=ts_offset_s)
        self.det.feed(_line(ts, msg), summary=None)

    def _has_code(self, code):
        results = self.det.finalize(summary=None)
        return any(f.code == code for f in results)

    def test_ssl_exception_fires(self):
        self._feed(
            'ZEvents: Raised event:  zcc_zpa_failed_ssl_exception ... '
            '{"metrics":{"broker_hostname":"broker6-2.den3.prod.zpath.net",'
            '"broker_ip":"136.226.87.245","ssl_errString":"SSL connection '
            'unexpectedly closed"}}'
        )
        self.assertTrue(self._has_code("ZPA_SSL_EXCEPTION"))

    def test_auth_timeout_fires(self):
        self._feed("ZEvents: Raised event: zcc_zpa_failed_auth_timeout")
        self.assertTrue(self._has_code("ZPA_AUTH_TIMEOUT"))

    def test_server_down_fires(self):
        self._feed("ZEvents: Raised event: zcc_zpa_server_down_error")
        self.assertTrue(self._has_code("ZPA_SERVER_DOWN"))

    def test_read_error_fires(self):
        self._feed("ZEvents: Raised event: zcc_zpa_failed_read_error")
        self.assertTrue(self._has_code("ZPA_READ_ERROR"))

    def test_network_error_fires(self):
        self._feed("ZEvents: Raised event: zcc_zpa_network_error")
        self.assertTrue(self._has_code("ZPA_NETWORK_ERROR"))

    def test_force_reauth_sleep_is_info(self):
        self._feed("ZEvents: Raised event: zcc_zpa_force_reauth_sleep_trigger")
        results = self.det.finalize(summary=None)
        f = next(r for r in results if r.code == "ZPA_FORCE_REAUTH_SLEEP")
        self.assertEqual(f.severity, Severity.INFO)

    def test_force_reauth_network_change_is_info(self):
        self._feed("ZEvents: Raised event: "
                   "zcc_zpa_force_reauth_network_change_trigger")
        results = self.det.finalize(summary=None)
        f = next(r for r in results if r.code == "ZPA_FORCE_REAUTH_NETWORK")
        self.assertEqual(f.severity, Severity.INFO)

    def test_no_zevent_no_finding(self):
        self._feed("just a regular log line with no ZPA signal")
        results = self.det.finalize(summary=None)
        # The auth-state transition tracker may produce findings on
        # ANY line if it has internal state — but we never gave it
        # any state transitions, so the result should be empty of
        # zevent codes.
        for f in results:
            self.assertNotIn("ZPA_", f.code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
