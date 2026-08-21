"""
Detector: Tunnel not established / Network Error.

Issue #2 in the user spec ("Traffic forwarding / tunnel not established").
Watches tunnel-log evidence for proxy-state degradation events: the ZIA
Public Service Edge or ZPA broker becoming unreachable, the local
network adapter dropping, captive-portal failures (timeout-side),
firewall blocks, or sockets exhausted.

Distinct from the auth detectors:

  * The auth detectors care about ``SERVER_AUTH_ERROR`` and
    ``SERVER_AUTH_TERMINATED_AT_UNKNOWN`` (auth failed at a state-machine
    level) and the SAML / IdP / 42xxx chain.
  * This detector cares about *network-layer* states: tunnel can't be
    built, edge can't be reached, adapter dropped. Same registry-key
    namespace per the documentation Registry-Keys table; different remediation.

Highest-fidelity signals (in order):

  1. ``Changing (ZIA|ZPA) state from: X to Y`` -- explicit transition
     events. Authoritative state machine.
  2. ``zcc_(zia|zpa)_(server_down_error|network_error|connection_failed)``
     -- the zEvent bus fires these when ZCC raises a user-facing error.
     They map directly to the tray Service Status strings in the documentation
     (Connection Error, Network Error, Server Error).
  3. ``Skipping zpn socket reconnect as network is down`` -- local
     no-network condition (sleep/wake or actual link loss).

Bundle 1 evidence (real captures): SERVER_DOWN_ERROR transitions x3,
ADAPTER_DOWN_ERROR transitions x2, zcc_zia_server_down_error x2,
zcc_zia_network_error x1, zcc_zpa_connection_failed x3,
zcc_zpa_network_error x1.

Bundle 3 evidence (healthy enterprise): zcc_zia_state_flap_up x3
(recovery flap, INFO not error).
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- Patterns ---------------------------------------------------------

# State-transition events. Authoritative source of truth for state
# changes. Captures both ZIA and ZPA, both directions.
#   Changing ZPA state from: SERVER_DOWN_ERROR to CONNECTING
#   Changing ZIA state from: ON to SERVER_DOWN_ERROR
_RE_STATE_CHANGE = re.compile(
    r"Changing\s+(?P<svc>ZIA|ZPA)\s+state\s+from:\s*"
    r"(?P<from>\w+)\s+to\s+(?P<to>\w+)"
)

# zEvent bus error firings. Format observed in real logs:
#   ZEvents: Raised event:  zcc_zia_server_down_error / 0x300076503
#
# Two families of relevant events:
#   * zcc_(zia|zpa)_*  -- service-level state events (state_flap_up,
#     state_flap_down, server_down_error, network_error,
#     connection_failed)
#   * zcc_t2_*  -- tunnel-2 (DTLS) lifecycle events
#     (connection_timeout_zsddc, dtls_to_tls_fallback,
#     socket_readable_error_zsddc, close_notification_zsddc)
_RE_ZEVENT = re.compile(
    r"Raised event:\s*"
    r"(?P<name>"
    r"zcc_(?:zia|zpa)_(?:server_down_error|network_error"
    r"|connection_failed|state_flap_up|state_flap_down)"
    r"|zcc_t2_(?:connection_timeout_\w+|dtls_to_tls_fallback"
    r"|socket_readable_error_\w+|close_notification_\w+)"
    r")"
)

# Local-network-is-down marker.
_RE_NETWORK_DOWN = re.compile(
    r"Skipping zpn socket reconnect as network is down",
    re.IGNORECASE,
)

# SME failure counter (rising count = repeated failures to reach edge).
_RE_SME_FAIL_COUNT = re.compile(
    r"incrementSMEFailureCount.*?count:\s*(?P<n>\d+)",
    re.IGNORECASE,
)

# SSL interception signature -- per the ZCC Traffic Forwarding runbook,
# Connection Error section. The ``certificateErroCallback`` typo is
# documented from ZCC's own source code (it's misspelled there); the
# runbook quotes it exactly. This signature does NOT appear in any
# healthy bundle; matches bare.
#
# Note: the runbook pairs this with ``Data Channel establishment
# Failed.`` on the preceding line. We don't try to track the pair
# because that line ALSO appears in routine DTLS-to-TLS fallback (no
# SSL-inspection involved). The certificateErroCallback line is the
# differentiator and is unique to MITM/SSL-inspection scenarios.
_RE_SSL_INTERCEPTION = re.compile(
    r"Auth::Lib::certificateErroCallback:\s*Invalid certificate",
)

# Explicit T2->T1 fallback: when the SME list is exhausted, ZCC drops
# Tunnel 2.0 entirely and falls through to Tunnel 1.0. Distinct from
# the routine intra-T2 DTLS-to-TLS fallback (zcc_t2_dtls_to_tls_fallback
# zEvent). This signature absent in all three healthy bundles.
_RE_T2_TO_T1_FALLBACK = re.compile(
    r"SME List is empty\.\s*Fallback to ZTunnel 1\.0",
)


# Bad states from the documentation Registry-Keys table that indicate
# tunnel-establishment failure (NOT auth failure). Auth-side states
# (SERVER_AUTH_ERROR, SERVER_AUTH_TERMINATED_AT_UNKNOWN) live in the
# auth detectors. Captive-portal states will move to issue #4 when that
# detector ships. FIREWALL_BLOCK_ERROR is owned by issue #3 (FW/AV).
_BAD_TUNNEL_STATES = frozenset({
    "SERVER_DOWN_ERROR",            # PSE / broker unreachable
    "ADAPTER_DOWN_ERROR",           # local Z-tunnel adapter gone
    "INTERNET_UNREACHABLE_ERROR",   # no DNS / no upstream
    "SERVICE_DOWN_ERROR",           # ZCC microservice dead
    "SYSTEM_SOCKETS_EXHAUSTED_ERROR",
    "DRIVER_ERROR",                 # TAP/TUN/LWF won't load
    "ZPA_UNTRUSTED_SERVER_CERT_ERROR",  # ZPA-only; cert untrusted
})

# States that are healthy or transient. We compute "in bad state" by
# subtracting these from the universe.
_HEALTHY_STATES = frozenset({
    "OFF", "ON", "TUNNEL_FORWARDING", "NONE_FORWARDING",
    "LOCAL_PROXY_FORWARDING", "ENFORCE_PROXY_FORWARDING",
    "CONNECTING",  # transient on bring-up, normally short
})


# Severity & threshold knobs.
EVIDENCE_CAP = 10

# A bad-state visit longer than this duration is escalated CRITICAL.
# Shorter visits are WARNING (often just brief reconnection blips).
SUSTAINED_BAD_STATE_SECONDS = 60.0


# --- Detector ---------------------------------------------------------

@register
class TunnelNotEstablishedDetector(IssueDetector):
    id = "tunnel_not_established"
    title = "Tunnel not established / Network Error"
    sop_file = "tunnel_not_established.md"
    # Cross-suite: tracks BOTH ZIA and ZPA state machines explicitly
    # (see _timelines dict below). Suite-filtering happens inside the
    # detector via the per-suite timeline rather than at the gate.
    applies_to_suite = None

    def __init__(self) -> None:
        super().__init__()
        # Per-service state machine timeline:
        #   list of (timestamp, state) tuples, in arrival order.
        self._timelines: Dict[str, List[Tuple]] = {"ZIA": [], "ZPA": []}
        # zEvent firings keyed by event name -> list of records.
        self._zevents: Dict[str, List[LogLine]] = {}
        # network-down markers
        self._network_down: List[LogLine] = []
        # SME failure count peak
        self._sme_fail_peak: int = 0
        self._sme_fail_record: Optional[LogLine] = None

    # --- IssueDetector overrides ----------------------------------

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message

        # 1. State-transition events.
        m = _RE_STATE_CHANGE.search(msg)
        if m:
            svc = m.group("svc")
            self._timelines[svc].append((record.timestamp, m.group("to"),
                                         m.group("from"), record))
            return  # state-change line is unique enough not to also match below

        # 2. zEvent bus.
        m = _RE_ZEVENT.search(msg)
        if m:
            name = m.group("name")
            self._zevents.setdefault(name, []).append(record)
            return

        # 3. Network-down marker.
        if _RE_NETWORK_DOWN.search(msg):
            if len(self._network_down) < EVIDENCE_CAP * 2:
                self._network_down.append(record)
            return

        # 4. SME failure counter.
        m = _RE_SME_FAIL_COUNT.search(msg)
        if m:
            try:
                n = int(m.group("n"))
            except ValueError:
                return
            if n > self._sme_fail_peak:
                self._sme_fail_peak = n
                self._sme_fail_record = record
            return

        # 5. SSL interception signature.
        if _RE_SSL_INTERCEPTION.search(msg):
            f = self._bucket(
                "SSL_INTERCEPTION_DETECTED",
                Severity.CRITICAL,
                "SSL/TLS interception detected (cert validation failed)",
                "ZCC's auth layer reported ``Invalid certificate`` from "
                "``Auth::Lib::certificateErroCallback`` (documented typo "
                "from ZCC source). Per the ZCC Traffic Forwarding "
                "runbook, this is the canonical signature of a "
                "TLS-inspecting proxy in the path -- the proxy is "
                "presenting its own certificate instead of the real "
                "Zscaler service-edge cert. Resolution: bypass SSL "
                "inspection on Zscaler IP ranges in the corporate "
                "firewall / web security gateway.",
                sop_anchor="#ssl-interception-detected",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

        # 6. Explicit T2->T1 fallback.
        if _RE_T2_TO_T1_FALLBACK.search(msg):
            f = self._bucket(
                "T2_FALLBACK_TO_T1",
                Severity.CRITICAL,
                "Z-Tunnel 2.0 fell back to Z-Tunnel 1.0",
                "ZCC could not establish any SME (Service Edge "
                "Mobile) connection for Z-Tunnel 2.0 and fell back to "
                "Z-Tunnel 1.0. This is a HARD fallback (T2 unusable), "
                "distinct from the routine intra-T2 DTLS-to-TLS "
                "fallback. Z-Tunnel 1.0 only intercepts web traffic "
                "(HTTP/HTTPS via PAC), so non-web traffic now bypasses "
                "Zscaler entirely. Per the ZCC Traffic Forwarding "
                "runbook: usually caused by sustained connect timeouts "
                "to all SMEs in the PAC file -- check upstream firewall "
                "blocking outbound 443.",
                sop_anchor="#t2-fallback-to-t1",
            )
            f.add_evidence(record, cap=EVIDENCE_CAP)
            return

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        # Start with bucket-based findings (SSL_INTERCEPTION_DETECTED,
        # T2_FALLBACK_TO_T1, etc. -- bucketed by feed() via the base
        # class _bucket helper). Existing per-state and zEvent findings
        # are appended below.
        findings: List[Finding] = list(self._buckets.values())

        # Per-service: walk the timeline, find bad-state intervals.
        for svc in ("ZIA", "ZPA"):
            findings.extend(self._analyze_timeline(svc))

        # zEvent findings.
        findings.extend(self._zevent_findings())

        # Network-down findings.
        if self._network_down:
            f = Finding(
                code="LOCAL_NETWORK_DOWN",
                severity=Severity.WARNING,
                title=(
                    f"Local network reported as down "
                    f"({len(self._network_down)} record(s))"
                ),
                description=(
                    "ZCC observed 'Skipping zpn socket reconnect as "
                    "network is down'. Common during sleep/wake, VPN "
                    "transitions, or actual link drops. Single events "
                    "are usually benign; clusters point at flaky NIC, "
                    "Wi-Fi roaming, or VPN conflicts."
                ),
                sop_anchor="#local-network-down",
            )
            for rec in self._network_down[:EVIDENCE_CAP]:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            findings.append(f)

        # SME failure-counter finding.
        if self._sme_fail_peak >= 3 and self._sme_fail_record is not None:
            f = Finding(
                code="SME_FAILURE_COUNT_HIGH",
                severity=(
                    Severity.CRITICAL if self._sme_fail_peak >= 5
                    else Severity.WARNING
                ),
                title=(
                    f"SME failure count reached {self._sme_fail_peak}"
                ),
                description=(
                    "ZCC's SME (Service-Edge-Mobile) failure counter "
                    "tracks how many consecutive attempts to reach the "
                    "ZIA Public Service Edge have failed. A sustained "
                    "high count means the chosen edge is unreachable -- "
                    "verify outbound connectivity to the resolved edge "
                    "IPs (see summary.service_edges) on TCP/UDP 443."
                ),
                sop_anchor="#sme-failure-count",
            )
            f.add_evidence(self._sme_fail_record, cap=EVIDENCE_CAP)
            findings.append(f)

        return findings

    # --- helpers --------------------------------------------------

    def _analyze_timeline(self, svc: str) -> List[Finding]:
        """For ``svc`` ('ZIA' or 'ZPA'), turn the state timeline into
        findings. Each contiguous run of bad states becomes one finding;
        severity escalates if the run exceeds SUSTAINED_BAD_STATE_SECONDS."""
        timeline = self._timelines[svc]
        if not timeline:
            return []

        findings: List[Finding] = []
        # Group: walk transitions; track entries into a bad state and
        # exits back to a healthy/connecting state.
        in_bad: Optional[Tuple] = None  # (entry_ts, entry_record, [states_seen])
        bad_runs: List[Tuple] = []      # [(entry_ts, exit_ts, entry_rec,
                                        #   exit_rec, [states])]

        for ts, to_state, from_state, rec in timeline:
            is_bad = to_state in _BAD_TUNNEL_STATES
            if is_bad and in_bad is None:
                in_bad = (ts, rec, [to_state])
            elif is_bad and in_bad is not None:
                # Stay in bad-land but possibly cycling between bad states.
                in_bad[2].append(to_state)
            elif not is_bad and in_bad is not None:
                # Exiting the bad run.
                bad_runs.append(
                    (in_bad[0], ts, in_bad[1], rec, in_bad[2])
                )
                in_bad = None
            # not-bad-and-not-in-bad: nothing to do

        # If still in a bad state at end of capture, close the run with
        # the last seen timestamp.
        if in_bad is not None:
            last_ts = timeline[-1][0]
            last_rec = timeline[-1][3]
            bad_runs.append(
                (in_bad[0], last_ts, in_bad[1], last_rec, in_bad[2])
            )

        # Aggregate bad runs by (svc, primary_state) so we emit ONE
        # finding per state regardless of how many times the tunnel
        # cycled through it. Previously this loop emitted one Finding
        # per run -- with the title encoding the duration of each
        # occurrence -- which cluttered the UI when a tunnel flapped
        # repeatedly. Now we collapse all occurrences into a single
        # consolidated finding with: total occurrences, longest run,
        # cumulative bad-time, severity = max across runs, evidence
        # sampled from the worst runs.
        runs_by_state: Dict[str, List[tuple]] = {}
        for entry_ts, exit_ts, entry_rec, exit_rec, states in bad_runs:
            primary_state = list(dict.fromkeys(states))[0]
            runs_by_state.setdefault(primary_state, []).append(
                (entry_ts, exit_ts, entry_rec, exit_rec, states)
            )

        for primary_state, runs in runs_by_state.items():
            n = len(runs)
            durations = [
                (r[1] - r[0]).total_seconds() for r in runs
            ]
            max_dur = max(durations)
            total_dur = sum(durations)
            all_states_seen = []
            for r in runs:
                for s in r[4]:
                    if s not in all_states_seen:
                        all_states_seen.append(s)
            any_sustained = any(
                d >= SUSTAINED_BAD_STATE_SECONDS for d in durations
            )
            severity = (
                Severity.CRITICAL if any_sustained else Severity.WARNING
            )

            def _fmt_dur(d):
                if d < 1.0:
                    return f"<1s ({d*1000:.0f}ms)"
                if d < 60:
                    return f"{d:.0f}s"
                return f"{d/60:.1f}min"

            # Title summarises across all occurrences.
            if n == 1:
                title = (
                    f"{svc} tunnel in {primary_state} "
                    f"for {_fmt_dur(max_dur)}"
                )
            else:
                title = (
                    f"{svc} tunnel entered {primary_state} "
                    f"{n} times — longest {_fmt_dur(max_dur)}, "
                    f"total {_fmt_dur(total_dur)} bad"
                )
            if len(all_states_seen) > 1:
                title += (
                    f" (cycled through "
                    f"{', '.join(all_states_seen)})"
                )

            code = f"{svc}_TUNNEL_DOWN_{primary_state}"
            f = Finding(
                code=code,
                severity=severity,
                title=title,
                description=self._describe_state(
                    svc, primary_state, max_dur, all_states_seen
                ) + (
                    f"\n\nOccurrences: {n} bad-state run(s) "
                    f"between {runs[0][0].isoformat()} and "
                    f"{runs[-1][1].isoformat()}. "
                    f"Total bad-state time: {_fmt_dur(total_dur)}. "
                    f"Longest single run: {_fmt_dur(max_dur)}."
                ),
                sop_anchor=self._anchor_for_state(primary_state),
            )
            # Sample evidence: 1 entry + 1 exit from each of up to 3
            # worst (longest) runs.
            worst_runs = sorted(
                runs, key=lambda r: -(r[1] - r[0]).total_seconds()
            )[:3]
            for entry_ts, exit_ts, entry_rec, exit_rec, _states in worst_runs:
                f.add_evidence(entry_rec, cap=EVIDENCE_CAP)
                if exit_rec is not entry_rec:
                    f.add_evidence(exit_rec, cap=EVIDENCE_CAP)
            findings.append(f)

        return findings

    def _zevent_findings(self) -> List[Finding]:
        out: List[Finding] = []
        # Healthy events (state_flap_up) get INFO; error events get
        # CRITICAL because they map to a user-facing tray status.
        # T2 fallback events get WARNING -- they're recovery paths
        # (DTLS failed but TLS succeeded), not outright failures.
        info_events = {"zcc_zia_state_flap_up", "zcc_zpa_state_flap_up"}
        warning_events = {"zcc_t2_dtls_to_tls_fallback"}
        critical_events = {
            "zcc_zia_server_down_error",
            "zcc_zpa_server_down_error",
            "zcc_zia_network_error",
            "zcc_zpa_network_error",
            "zcc_zia_connection_failed",
            "zcc_zpa_connection_failed",
            "zcc_zia_state_flap_down",
            "zcc_zpa_state_flap_down",
        }
        # Tunnel-2 (DTLS) lifecycle errors: timeouts, socket errors,
        # close notifications. These signal tunnel-establishment trouble
        # at the DTLS layer specifically.
        t2_error_prefixes = (
            "zcc_t2_connection_timeout",
            "zcc_t2_socket_readable_error",
            "zcc_t2_close_notification",
        )

        for name, recs in sorted(self._zevents.items()):
            if name in info_events:
                f = Finding(
                    code=name.upper(),
                    severity=Severity.INFO,
                    title=(
                        f"State recovery: {name} ({len(recs)} occurrence(s))"
                    ),
                    description=(
                        "ZCC's event bus fired a recovery event. The "
                        "client's proxy state returned to healthy. Listed "
                        "here so the human can correlate with any "
                        "preceding error events."
                    ),
                    sop_anchor="#state-flap-up",
                )
            elif name in warning_events:
                f = Finding(
                    code=name.upper(),
                    severity=Severity.WARNING,
                    title=(
                        f"Tunnel transport fallback: {name} "
                        f"({len(recs)} occurrence(s))"
                    ),
                    description=(
                        "ZCC fell back from DTLS (Tunnel v2 over UDP) "
                        "to TLS (Tunnel v1 over TCP). Common when UDP/443 "
                        "is blocked by a firewall in the path. Connection "
                        "still works but throughput typically halves and "
                        "latency rises -- this is the canonical issue #5 "
                        "(performance) precursor."
                    ),
                    sop_anchor="#t2-dtls-fallback",
                )
            elif name in critical_events:
                f = Finding(
                    code=name.upper(),
                    severity=Severity.CRITICAL,
                    title=(
                        f"ZCC raised user-visible error: {name} "
                        f"({len(recs)} occurrence(s))"
                    ),
                    description=(
                        "ZCC's event bus fired an error event that the "
                        "user sees in the tray Service Status field. "
                        f"Maps to one of the documented Connection "
                        f"Status errors (Connection Error, Network "
                        f"Error, Server Error)."
                    ),
                    sop_anchor=self._anchor_for_zevent(name),
                )
            elif any(name.startswith(p) for p in t2_error_prefixes):
                # Tunnel-2 (DTLS) layer errors. WARNING individually,
                # CRITICAL if the same family fired >= 5 times (sustained).
                sev = (
                    Severity.CRITICAL if len(recs) >= 5
                    else Severity.WARNING
                )
                f = Finding(
                    code=name.upper(),
                    severity=sev,
                    title=(
                        f"Tunnel-2 (DTLS) lifecycle error: {name} "
                        f"({len(recs)} occurrence(s))"
                    ),
                    description=(
                        "ZCC's Tunnel-2 (DTLS over UDP) layer reported "
                        "a connection-lifecycle problem. Single events "
                        "are usually transient. >=5 in a window means "
                        "the DTLS path is repeatedly failing -- check "
                        "whether UDP/443 is reliably reachable, or "
                        "whether path MTU is dropping DTLS packets."
                    ),
                    sop_anchor="#t2-lifecycle-error",
                )
            else:
                continue  # unknown event name; skip rather than make up severity

            for rec in recs[:EVIDENCE_CAP]:
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            out.append(f)
        return out

    @staticmethod
    def _anchor_for_state(state: str) -> str:
        return {
            "SERVER_DOWN_ERROR": "#server-down-error",
            "ADAPTER_DOWN_ERROR": "#adapter-down-error",
            "INTERNET_UNREACHABLE_ERROR": "#internet-unreachable",
            "SERVICE_DOWN_ERROR": "#service-down-error",
            "SYSTEM_SOCKETS_EXHAUSTED_ERROR": "#sockets-exhausted",
            "DRIVER_ERROR": "#driver-error",
            "ZPA_UNTRUSTED_SERVER_CERT_ERROR": "#zpa-untrusted-cert",
        }.get(state, "#tunnel-bad-state-generic")

    @staticmethod
    def _anchor_for_zevent(name: str) -> str:
        if "server_down" in name:
            return "#server-down-error"
        if "network_error" in name:
            return "#network-error-zevent"
        if "connection_failed" in name:
            return "#connection-failed-zevent"
        return "#tunnel-bad-state-generic"

    @staticmethod
    def _describe_state(svc: str, state: str, duration: float,
                        states: List[str]) -> str:
        base_descriptions = {
            "SERVER_DOWN_ERROR": (
                f"{svc}'s Public Service Edge / broker is unreachable. "
                "Verify outbound connectivity to the resolved edge IPs "
                "(see summary.service_edges). Common upstream causes: a "
                "corporate firewall blocking ZCC's tunnel ports, "
                "TLS-inspecting proxy breaking the handshake, ISP DNS "
                "redirecting Zscaler hostnames."
            ),
            "ADAPTER_DOWN_ERROR": (
                f"{svc}: the local Z-tunnel virtual adapter is down. "
                "ZCC can't find an adapter with a default route -- often "
                "DHCP renewal in progress, or the OS reset adapters "
                "(sleep/wake, USB tether attached). Check Windows "
                "ipconfig /all output around the timestamp."
            ),
            "INTERNET_UNREACHABLE_ERROR": (
                f"{svc}: network appears connected but DNS / upstream "
                "broker name resolution failing. Verify DNS server "
                "config; check captive-portal status."
            ),
            "SERVICE_DOWN_ERROR": (
                f"{svc}: one of ZCC's microservices is not operational. "
                "Restart ZSAService and check Windows Event Viewer for "
                "service crashes."
            ),
            "SYSTEM_SOCKETS_EXHAUSTED_ERROR": (
                f"{svc}: OS socket limit reached. Investigate apps "
                "leaking sockets; consider reboot."
            ),
            "DRIVER_ERROR": (
                f"{svc}: ZCC could not load the network driver "
                "(TAP/TUN/LWF). Driver install was likely interrupted; "
                "use the Repair App option in ZCC tray."
            ),
            "ZPA_UNTRUSTED_SERVER_CERT_ERROR": (
                "ZPA: the Private Service Edge certificate failed "
                "validation. Trust-store issue or MITM (TLS-inspecting "
                "proxy in the path)."
            ),
        }
        base = base_descriptions.get(
            state,
            f"{svc} tunnel entered an unrecognised bad state: {state}.",
        )
        cycled = ""
        if len(states) > 1:
            cycled = f" Cycled through: {', '.join(states)}."
        sustained = ""
        if duration >= SUSTAINED_BAD_STATE_SECONDS:
            sustained = (
                f" Sustained for {duration:.0f}s (>={SUSTAINED_BAD_STATE_SECONDS}s),"
                " escalating to CRITICAL."
            )
        return base + cycled + sustained
