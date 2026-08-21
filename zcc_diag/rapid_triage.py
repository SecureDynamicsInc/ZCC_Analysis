# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Evidence-backed rapid triage for the local ZCC Log Explorer.

This module intentionally stays narrower than the retired detector layer.  It
does not guess a root cause from broad keyword counts.  It converts direct
signals already present in ZSATunnel records, reconstructed ZPA M-Tunnel
sessions, the bundled Zscaler status-code reference, and packet captures into a
small set of operator-facing findings.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from zcc_diag.code_lookup import lookup_code
from zcc_diag.error_catalog import match_known_codes
from zcc_diag.wireshark_filters import (
    dns_failure_filter,
    tcp_reset_filter,
    tcp_retransmission_filter,
    tls_fatal_filter,
)


ZCC_FORWARDING_RUNBOOK = (
    "https://help.zscaler.com/troubleshooting-runbooks/"
    "zscaler-client-connector-traffic-forwarding-troubleshooting-runbook"
)
ZCC_ERROR_REFERENCE = (
    "https://help.zscaler.com/zscaler-client-connector/"
    "zscaler-client-connector-errors"
)
ZPA_STATUS_REFERENCE = (
    "https://help.zscaler.com/zpa/understanding-zpa-session-status-codes"
)


_STATE_RE = re.compile(
    r"get(?P<service>Sme|Zpn)ProxyState:(?P<state>[A-Z_]+)", re.IGNORECASE
)
_ERROR_STATES = {
    "SERVER_DOWN_ERROR", "FIREWALL_BLOCK_ERROR", "CONNECTION_ERROR",
    "NETWORK_ERROR", "AUTHENTICATION_ERROR", "DRIVER_ERROR",
}
_GOOD_STATES = {"TUNNEL_FORWARDING", "LOCAL_PROXY_FORWARDING"}
_NORMAL_ZPA_CODES = {
    "BRK_MT_CLOSED_FROM_ASSISTANT",
    "BRK_MT_CLOSED_FROM_CLIENT",
    "BRK_MT_TERMINATED_IDLE_TIMEOUT",
}


@dataclass(frozen=True)
class EvidenceExample:
    ts: Optional[datetime]
    source_file: str
    line_no: int
    body: str


@dataclass
class TunnelSignals:
    tunnel_records: int = 0
    zia_states: Counter = field(default_factory=Counter)
    zpa_states: Counter = field(default_factory=Counter)
    zia_last_state: str = ""
    zpa_last_state: str = ""
    zia_last_ts: Optional[datetime] = None
    zpa_last_ts: Optional[datetime] = None
    code_counts: Counter = field(default_factory=Counter)
    code_examples: Dict[str, EvidenceExample] = field(default_factory=dict)
    phrase_counts: Counter = field(default_factory=Counter)
    phrase_examples: Dict[str, EvidenceExample] = field(default_factory=dict)


@dataclass(frozen=True)
class TriageFinding:
    severity: str          # critical | warning | info | success
    kind: str              # hard | soft | policy | coverage | healthy
    area: str              # ZIA | ZPA | DNS | TCP | TLS | Evidence
    title: str
    conclusion: str
    evidence: str
    next_action: str
    code: str = ""
    doc_url: str = ""
    rank: int = 50
    sample: Optional[EvidenceExample] = None
    wireshark_filter: str = ""
    wireshark_title: str = ""


@dataclass
class RapidTriage:
    findings: List[TriageFinding]
    zpa_sessions: Sequence[Any]
    signals: TunnelSignals
    pcap_summaries: Sequence[Any]
    successful_sessions: int = 0
    failed_sessions: int = 0
    policy_blocked_sessions: int = 0

    def for_focus(self, focus: str) -> List[TriageFinding]:
        focus_l = (focus or "").lower()
        if focus_l.startswith("private"):
            areas = {"ZPA", "DNS", "TCP", "TLS", "Evidence"}
        elif focus_l.startswith("internet"):
            areas = {"ZIA", "DNS", "TCP", "TLS", "Evidence"}
        elif focus_l.startswith("dns"):
            areas = {"DNS", "ZIA", "ZPA", "Evidence"}
        elif focus_l.startswith("slow"):
            areas = {"TCP", "TLS", "ZIA", "ZPA", "Evidence"}
        elif focus_l.startswith("packet"):
            areas = {"DNS", "TCP", "TLS", "Evidence"}
        else:
            return self.findings
        selected = [f for f in self.findings if f.area in areas]
        return selected or self.findings

    def for_scope(self, scope: str) -> List[TriageFinding]:
        """Return findings relevant to the selected Zscaler service.

        DNS, TCP, TLS, and evidence-coverage findings can affect either service,
        so they remain visible beside the service-specific tunnel findings.
        """
        if scope == "ZIA":
            areas = {"ZIA", "DNS", "TCP", "TLS", "Evidence"}
        elif scope == "ZPA":
            areas = {"ZPA", "DNS", "TCP", "TLS", "Evidence"}
        else:
            return self.findings
        selected = [finding for finding in self.findings if finding.area in areas]
        return selected or self.findings


def _example(ln: Any) -> EvidenceExample:
    return EvidenceExample(
        ts=getattr(ln, "ts", None),
        source_file=getattr(ln, "source_file", "") or "",
        line_no=int(getattr(ln, "line_no", 0) or 0),
        body=(getattr(ln, "body", "") or "")[:500],
    )


def scan_tunnel_signals(log_index: Any) -> TunnelSignals:
    """Scan indexed records once for explicit connection-state evidence."""
    out = TunnelSignals()
    phrases = {
        "host_not_found": (r"\bhost not found\b", r"\bdns resolution failed\b"),
        "connection_reset": (r"\bconnection reset by peer\b", r"\bconn reset\b"),
        "no_route": (r"\bno route to host\b",),
        "timeout": (r"\bconnection timed out\b", r"\bconnect timeout\b"),
        "ssl_interception": (r"\buntrusted root cert\b", r"\bunknown_ca\b"),
    }
    for ln in getattr(log_index, "lines", ()):
        body = getattr(ln, "body", "") or ""
        if not body:
            continue
        if (getattr(ln, "component", "") or "").lower() == "tunnel":
            out.tunnel_records += 1

        for m in _STATE_RE.finditer(body):
            state = m.group("state").upper()
            if m.group("service").lower() == "sme":
                out.zia_states[state] += 1
                out.zia_last_state = state
                out.zia_last_ts = getattr(ln, "ts", None)
            else:
                out.zpa_states[state] += 1
                out.zpa_last_state = state
                out.zpa_last_ts = getattr(ln, "ts", None)

        for entry in match_known_codes(body):
            out.code_counts[entry.code] += 1
            out.code_examples.setdefault(entry.code, _example(ln))

        lower = body.lower()
        for key, patterns in phrases.items():
            if any(re.search(pattern, lower) for pattern in patterns):
                out.phrase_counts[key] += 1
                out.phrase_examples.setdefault(key, _example(ln))
    return out


def _lookup_fields(code: str) -> Dict[str, Any]:
    hits = lookup_code(code, limit=1)
    if hits and hits[0].match_reason == "exact_code":
        return dict(hits[0].fields)
    return {}


def session_code(session: Any) -> str:
    return str(
        getattr(session, "ack_error", "")
        or getattr(session, "end_error", "")
        or ""
    ).strip()


def session_category(session: Any) -> str:
    """Stable operator category used by the one-click tunnel filters."""
    code = session_code(session).upper()
    fields = _lookup_fields(code) if code else {}
    documented = str(fields.get("category") or "").lower()
    outcome = str(getattr(session, "outcome", "") or "").lower()

    if documented == "policy_block" or any(
        token in code for token in (
            "REJECTED_BY_POLICY", "NO_POLICY_FOUND", "SAML_EXPIRED",
        )
    ):
        return "Policy blocked"
    if outcome == "setup_failed" or "SETUP_FAIL" in code or "SETUP_ERR" in code:
        return "Setup failed"
    if any(token in code for token in (
        "RESET_FROM_SERVER", "OPEN_SERVER_CLOSE", "CANNOT_CONN_TO_SERVER",
    )):
        return "Server reset"
    sent = getattr(session, "bytes_to_server", None)
    received = getattr(session, "bytes_from_server", None)
    if sent and not received:
        return "No server response"
    if getattr(session, "has_byte_imbalance", False):
        return "Data dropped"
    if outcome in {"open", "incomplete"}:
        return "Open / incomplete"
    if code and code not in _NORMAL_ZPA_CODES and documented != "info":
        return "Other failure"
    return "Normal"


def session_resolution(session: Any) -> Tuple[str, str, str]:
    """Return documented (status, resolution, severity) when available."""
    code = session_code(session)
    fields = _lookup_fields(code) if code else {}
    status = str(fields.get("session_status") or fields.get("description") or "")
    resolution = str(fields.get("resolution") or "")
    severity = str(fields.get("severity_hint") or "")
    return status, resolution, severity


def _finding_from_session_code(code: str, sessions: Sequence[Any]) -> TriageFinding:
    fields = _lookup_fields(code)
    category = str(fields.get("category") or "").lower()
    sev_hint = str(fields.get("severity_hint") or "warning").lower()
    if category == "policy_block":
        severity, kind, rank = "warning", "policy", 12
    elif sev_hint == "critical":
        severity, kind, rank = "critical", "hard", 5
    elif sev_hint == "info":
        severity, kind, rank = "info", "soft", 45
    else:
        severity, kind, rank = "warning", "soft", 20

    apps = sorted({getattr(s, "app_name", "") for s in sessions if getattr(s, "app_name", "")})
    app_text = ", ".join(apps[:3]) or "unknown application"
    if len(apps) > 3:
        app_text += f" and {len(apps) - 3} more"
    status = str(fields.get("session_status") or "M-Tunnel failure")
    description = str(fields.get("description") or code.replace("_", " ").title())
    resolution = str(fields.get("resolution") or (
        "Open Tunnel & apps, inspect the failed session evidence, then verify "
        "the application, policy, connector, or broker path named by the code."
    ))
    return TriageFinding(
        severity=severity, kind=kind, area="ZPA",
        title=status,
        conclusion=description,
        evidence=f"{len(sessions):,} session(s) · {app_text} · {code}",
        next_action=resolution,
        code=code, doc_url=ZPA_STATUS_REFERENCE, rank=rank,
    )


def _state_findings(signals: TunnelSignals) -> List[TriageFinding]:
    findings: List[TriageFinding] = []
    for area, counts, last_state in (
        ("ZIA", signals.zia_states, signals.zia_last_state),
        ("ZPA", signals.zpa_states, signals.zpa_last_state),
    ):
        errors = sum(counts.get(state, 0) for state in _ERROR_STATES)
        if not errors:
            continue
        if last_state in _ERROR_STATES:
            findings.append(TriageFinding(
                severity="critical", kind="hard", area=area,
                title=f"{area} tunnel ends in {last_state.replace('_', ' ').title()}",
                conclusion=(
                    "The last explicit proxy-state observation is an error, so "
                    "the selected evidence does not show a later recovery."
                ),
                evidence=f"{errors:,} error-state observation(s); latest state {last_state}",
                next_action=(
                    "Check gateway and service-edge reachability, PAC/DC selection, "
                    "host firewall or SSL interception, and UDP 443 versus TLS. "
                    "Use Packet capture to confirm DNS, resets, and transport loss."
                ),
                doc_url=ZCC_FORWARDING_RUNBOOK, rank=3,
            ))
        elif last_state in _GOOD_STATES:
            findings.append(TriageFinding(
                severity="warning", kind="soft", area=area,
                title=f"{area} tunnel recovered after connection errors",
                conclusion=(
                    "Error states occurred, but a later forwarding state was observed. "
                    "Treat this as intermittent until the complaint window is matched."
                ),
                evidence=f"{errors:,} error-state observation(s); latest state {last_state}",
                next_action=(
                    "Use Timeline around the user's complaint time and compare the "
                    "transition with network changes, firewall events, and packet evidence."
                ),
                doc_url=ZCC_FORWARDING_RUNBOOK, rank=18,
            ))
    return findings


def _phrase_findings(signals: TunnelSignals) -> List[TriageFinding]:
    mapping = {
        "host_not_found": (
            "DNS resolution failures are present", "DNS", "hard",
            "Verify the configured resolver and whether the failing hostname resolves "
            "on the affected network. Use Packet capture to inspect response codes.",
        ),
        "connection_reset": (
            "Connections were reset by a peer", "TCP", "soft",
            "Match the reset to the complaint time and destination. Client-side reset "
            "churn can be routine; use Packet capture to identify sender and timing.",
        ),
        "no_route": (
            "The endpoint reported no route to a host", "TCP", "hard",
            "Verify the active adapter, route table, local VPN coexistence, and network path.",
        ),
        "timeout": (
            "Connection timeouts are present", "TCP", "soft",
            "Filter Tunnel & apps by destination and inspect retransmissions or missing replies.",
        ),
        "ssl_interception": (
            "Certificate or interception evidence is present", "TLS", "hard",
            "Identify the intercepting certificate or proxy and verify Zscaler control "
            "traffic is not being re-inspected.",
        ),
    }
    out = []
    for key, count in signals.phrase_counts.items():
        if not count or key not in mapping:
            continue
        title, area, kind, action = mapping[key]
        out.append(TriageFinding(
            severity="critical" if kind == "hard" else "warning",
            kind=kind, area=area, title=title,
            conclusion="The message appears directly in the selected ZCC records.",
            evidence=f"{count:,} matching record(s)", next_action=action,
            doc_url=ZCC_ERROR_REFERENCE, rank=10 if kind == "hard" else 24,
            sample=signals.phrase_examples.get(key),
        ))
    return out


def _known_code_findings(signals: TunnelSignals) -> List[TriageFinding]:
    """Lead with documented errors before broader symptom heuristics."""
    findings: List[TriageFinding] = []
    for code, count in signals.code_counts.items():
        hits = [hit for hit in lookup_code(code, limit=None)
                if hit.match_reason == "exact_code"]
        if not hits:
            continue
        hit = hits[0]
        fields = hit.fields
        severity = str(fields.get("_severity") or fields.get("severity_hint") or "info").lower()
        if severity == "info":
            continue
        product = str(fields.get("_product") or "ZCC")
        label = str(fields.get("_label") or fields.get("error_message")
                    or fields.get("session_status") or code)
        description = str(fields.get("_description") or fields.get("description") or label)
        resolution = str(fields.get("_resolution") or fields.get("resolution")
                         or fields.get("recommended_action")
                         or "Review the sample record and the linked Zscaler reference.")
        findings.append(TriageFinding(
            severity=severity,
            kind="hard" if severity == "critical" else "soft",
            area=product if product in {"ZIA", "ZPA"} else "Evidence",
            title=f"Known {product} error: {label}",
            conclusion=description,
            evidence=f"{count:,} matching record(s) · {code}",
            next_action=resolution,
            code=code,
            doc_url=str(fields.get("_source_url") or ""),
            rank=2 if severity == "critical" else 11,
            sample=signals.code_examples.get(code),
        ))
    return findings


def _pcap_findings(pcaps: Sequence[Any]) -> List[TriageFinding]:
    out: List[TriageFinding] = []
    for p in pcaps:
        name = getattr(getattr(p, "path", None), "name", "packet capture")
        dns = sum((getattr(p, "dns_nxdomain", None) or {}).values())
        rst = sum((getattr(p, "tcp_resets", None) or {}).values())
        retx = sum((getattr(p, "tcp_retransmits", None) or {}).values())
        fatal = sum(
            count for label, count in (getattr(p, "tls_alerts", None) or {}).items()
            if str(label).startswith("fatal/")
        )
        if dns:
            display_filter = dns_failure_filter((getattr(p, "dns_nxdomain", None) or {}).keys())
            out.append(TriageFinding(
                severity="critical", kind="hard", area="DNS",
                title="Packet capture contains failed DNS responses",
                conclusion="At least one DNS response returned a non-success RCODE.",
                evidence=f"{dns:,} failed response(s) in {name}",
                next_action=(
                    "Open this capture in Wireshark, paste the display filter below, "
                    "then compare qname, RCODE, resolver, and response timing."
                ),
                rank=4,
                wireshark_filter=display_filter,
                wireshark_title="Failed DNS responses",
            ))
        if fatal:
            display_filter = tls_fatal_filter((getattr(p, "tls_alert_endpoints", None) or {}).keys())
            out.append(TriageFinding(
                severity="critical", kind="hard", area="TLS",
                title="TLS handshakes were explicitly aborted",
                conclusion="Fatal TLS Alert records are present in the capture.",
                evidence=f"{fatal:,} fatal alert(s) in {name}",
                next_action=(
                    "Open this capture in Wireshark, paste the display filter below, "
                    "and identify the fatal alert description, sender, SNI, and preceding handshake."
                ),
                rank=6,
                wireshark_filter=display_filter,
                wireshark_title="Fatal TLS alerts",
            ))
        if rst:
            display_filter = tcp_reset_filter((getattr(p, "tcp_reset_endpoints", None) or {}).keys())
            out.append(TriageFinding(
                severity="warning", kind="soft", area="TCP",
                title="TCP resets need endpoint review",
                conclusion="RST packets are present; whether they indicate failure depends on sender and timing.",
                evidence=f"{rst:,} reset packet(s) in {name}",
                next_action=(
                    "Open this capture in Wireshark, paste the display filter below, "
                    "then inspect the packets before each reset to identify the sender and trigger."
                ),
                rank=16,
                wireshark_filter=display_filter,
                wireshark_title="TCP reset packets",
            ))
        if retx:
            display_filter = tcp_retransmission_filter((getattr(p, "tcp_retransmits", None) or {}).keys())
            out.append(TriageFinding(
                severity="warning", kind="soft", area="TCP",
                title="The capture shows suspected retransmissions",
                conclusion="Repeated TCP sequence ranges suggest loss or delayed acknowledgement in this window.",
                evidence=f"{retx:,} suspected retransmission(s) in {name}",
                next_action=(
                    "Open this capture in Wireshark, paste the display filter below, "
                    "then follow the affected stream and compare sequence, ACK, RTT, and direction."
                ),
                rank=22,
                wireshark_filter=display_filter,
                wireshark_title="Suspected TCP retransmissions",
            ))
    return out


def build_rapid_triage(
    zpa_sessions: Sequence[Any],
    signals: TunnelSignals,
    pcap_summaries: Sequence[Any],
) -> RapidTriage:
    findings: List[TriageFinding] = []
    findings.extend(_known_code_findings(signals))
    findings.extend(_state_findings(signals))
    findings.extend(_phrase_findings(signals))
    findings.extend(_pcap_findings(pcap_summaries))

    by_code: Dict[str, List[Any]] = defaultdict(list)
    successful = failed = policy = 0
    for session in zpa_sessions:
        category = session_category(session)
        if category == "Normal":
            successful += 1
        elif category == "Policy blocked":
            failed += 1
            policy += 1
        elif category not in {"Open / incomplete"}:
            failed += 1
        code = session_code(session)
        if code and code not in _NORMAL_ZPA_CODES and category != "Normal":
            by_code[code].append(session)

    existing_codes = {finding.code for finding in findings if finding.code}
    for code, sessions in by_code.items():
        if code not in existing_codes:
            findings.append(_finding_from_session_code(code, sessions))

    if signals.tunnel_records == 0:
        findings.append(TriageFinding(
            severity="warning", kind="coverage", area="Evidence",
            title="No tunnel records were supplied",
            conclusion="The selected evidence cannot answer most ZIA or ZPA connection questions.",
            evidence="0 indexed tunnel records",
            next_action="Upload the complete support ZIP, or select the ZSATunnel log and its rotations for a focused investigation.",
            rank=1,
        ))
    elif not findings:
        findings.append(TriageFinding(
            severity="success", kind="healthy", area="Evidence",
            title="No explicit connection failure surfaced",
            conclusion="The selected window contains tunnel evidence but no documented hard-failure signal from this rapid pass.",
            evidence=f"{signals.tunnel_records:,} tunnel record(s); {successful:,} normal M-Tunnel session(s)",
            next_action="Match the complaint time, application, and destination in Tunnel & apps. Expand rotations if the incident is outside the current span.",
            rank=90,
        ))

    findings.sort(key=lambda f: (f.rank, f.title))
    return RapidTriage(
        findings=findings,
        zpa_sessions=zpa_sessions,
        signals=signals,
        pcap_summaries=pcap_summaries,
        successful_sessions=successful,
        failed_sessions=failed,
        policy_blocked_sessions=policy,
    )


def pcap_summaries_to_ui(pcaps: Sequence[Any]) -> List[Dict[str, Any]]:
    """Normalize PcapSummary objects for the existing packet UI."""
    out: List[Dict[str, Any]] = []
    for p in pcaps:
        flow_rows = []
        for flow_key, interval in (getattr(p, "flow_intervals", None) or {}).items():
            try:
                first_ts, last_ts, total_bytes = interval
            except (TypeError, ValueError):
                continue
            flow_rows.append({
                "flow": flow_key,
                "first_ts": first_ts,
                "last_ts": last_ts,
                "duration_s": (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0.0,
                "bytes": int(total_bytes or 0),
            })
        flow_rows.sort(key=lambda row: -row["bytes"])
        sort_dict = lambda value: dict(sorted((value or {}).items(), key=lambda kv: -kv[1]))
        out.append({
            "path": str(p.path),
            "name": p.path.name,
            "total_packets": p.total_packets,
            "ts_first": p.ts_first,
            "ts_last": p.ts_last,
            "duration_s": p.duration_s,
            "dns": sort_dict(p.dns_queries),
            "sni": sort_dict(p.sni_hosts),
            "sni_to_ips": {
                host: sorted(ips) for host, ips in (getattr(p, "sni_to_ips", {}) or {}).items()
            },
            "dns_answers": {
                ip: sorted(names) for ip, names in (getattr(p, "dns_answers", {}) or {}).items()
            },
            "dns_resolutions": {
                host: sorted(ips)
                for host, ips in (getattr(p, "dns_resolutions", {}) or {}).items()
            },
            "address_stats": {
                key: dict(row)
                for key, row in (getattr(p, "address_stats", {}) or {}).items()
            },
            "transport_stats": {
                key: dict(row)
                for key, row in (getattr(p, "transport_stats", {}) or {}).items()
            },
            "dest_ips": sort_dict(p.dest_ips),
            "endpoints": sort_dict(p.dest_endpoints),
            "bytes_per_endpoint": sort_dict(getattr(p, "bytes_per_endpoint", {})),
            "tcp_resets": sort_dict(getattr(p, "tcp_resets", {})),
            "tcp_reset_endpoints": sort_dict(getattr(p, "tcp_reset_endpoints", {})),
            "tcp_syns": sort_dict(getattr(p, "tcp_syns", {})),
            "tcp_syn_acks": sort_dict(getattr(p, "tcp_syn_acks", {})),
            "tcp_retransmits": sort_dict(getattr(p, "tcp_retransmits", {})),
            "dns_nxdomain": sort_dict(getattr(p, "dns_nxdomain", {})),
            "tls_alerts": sort_dict(getattr(p, "tls_alerts", {})),
            "tls_alert_endpoints": sort_dict(getattr(p, "tls_alert_endpoints", {})),
            "flow_intervals": flow_rows,
            "parse_errors": list(getattr(p, "parse_errors", []) or []),
        })
    return out
