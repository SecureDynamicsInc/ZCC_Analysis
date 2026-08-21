"""What a ZCC bundle contains, and what each part is good for.

Two jobs, both aimed at the first thirty seconds of an investigation.

*Recap.* Whose device, what window the evidence covers, which client version,
and whether a packet capture came with it. Every value is read from the parsed
bundle, never assumed — an absent field is reported as absent rather than
guessed, because "we don't know the user" and "the user is blank" lead to
different next steps.

*Evidence checklist.* Which logs are present, which are missing, and what each
one is expected to tell you. Engineers learning Zscaler consistently ask "which
log do I open?", and the answer is knowable in advance, so it is stated here
rather than left to experience. Descriptions follow Zscaler's own definitions:

    Tunnel Logs        status, operation, and errors related to tunneling,
                       including which data centers the client is connecting
                       to, profile and policy downloads, and requests for
                       specific domains or websites.
    Client Connector   information about the Client Connector application and
    Logs               its usage on a device, including user interactions with
                       the UI such as enabling and disabling services.
    Packet Capture     packet captures of transactions, captured at the adapter
    Logs               level across all network adapters.

    -- help.zscaler.com/logs-fair-use/zscaler-client-connector-logs
    -- help.zscaler.com/zscaler-client-connector/enabling-packet-capture-zscaler-client-connector

Component keys match ``log_store.classify_component`` so presence is decided by
the same classification the parser used, not by a second guess at filenames.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True)
class EvidenceKind:
    """One kind of evidence a bundle can carry."""

    key: str
    label: str
    filenames: Tuple[str, ...]
    tells_you: str
    reach_for_it: str
    #: Lower sorts first. The tunnel log leads because it answers the
    #: connection question that brings most bundles in.
    rank: int = 50
    #: Novice wording, when the engineering phrasing would not land.
    plain_label: str = ""
    plain_tells_you: str = ""

    def label_for(self, *, pro_mode: bool) -> str:
        return self.label if pro_mode or not self.plain_label else self.plain_label

    def tells_you_for(self, *, pro_mode: bool) -> str:
        if pro_mode or not self.plain_tells_you:
            return self.tells_you
        return self.plain_tells_you


# The ZCC text logs, keyed by the parser's own component names.
COMPONENT_CATALOG: Tuple[EvidenceKind, ...] = (
    EvidenceKind(
        key="tunnel",
        label="Tunnel log",
        filenames=("ZSATunnel.log",),
        tells_you=(
            "Tunnel status, operation, and errors: which data centers the client "
            "connected to, profile and policy downloads, and requests for specific "
            "domains. Z-Tunnel setup and teardown, ZPA M-Tunnel sessions, and "
            "broker/service-edge selection all land here."
        ),
        reach_for_it=(
            "The first log to open for any connection question, and the single best "
            "log if you can only collect one."
        ),
        rank=10,
        plain_label="Connection log",
        plain_tells_you=(
            "How the device connected to Zscaler: which Zscaler locations it reached, "
            "which settings it downloaded, and which connections failed. This is the "
            "most useful log in most cases."
        ),
    ),
    EvidenceKind(
        key="service",
        label="Service log",
        filenames=("ZSAService.log", "com.zscaler.ZscalerService"),
        tells_you=(
            "The privileged service that enforces forwarding: driver and adapter "
            "state, route and DNS programming, and service start/stop and restart "
            "history."
        ),
        reach_for_it=(
            "When traffic is not being captured or redirected at all, or after a "
            "driver, adapter, or service-state change."
        ),
        rank=20,
        plain_label="Service log",
        plain_tells_you=(
            "The background Zscaler service that actually redirects traffic — whether "
            "it started, stayed running, and set the device's network settings."
        ),
    ),
    EvidenceKind(
        key="upm",
        label="Policy / profile log (UPM)",
        filenames=("ZSAUpm.log", "UPMServiceController"),
        tells_you=(
            "Policy and profile delivery: forwarding profile and app profile "
            "downloads, PAC retrieval and reload, and trusted-network evaluation."
        ),
        reach_for_it=(
            "When behaviour does not match the configured policy, or a PAC or profile "
            "change did not take effect on the device."
        ),
        rank=30,
    ),
    EvidenceKind(
        key="tray",
        label="Client Connector app log (tray)",
        filenames=("ZSATray.log", "ZSATrayManager.log", "ZSATrayHelper.log"),
        tells_you=(
            "The Client Connector application and its usage on the device, including "
            "user interactions with the UI such as enabling and disabling services, "
            "sign-in and authentication prompts, and notifications shown to the user."
        ),
        reach_for_it=(
            "When the complaint is about what the user saw or did — a sign-in loop, a "
            "disabled service, or a captive-portal prompt."
        ),
        rank=40,
        plain_label="App log",
        plain_tells_you=(
            "What the Zscaler app did on screen: sign-in prompts, notifications, and "
            "any time someone turned a service on or off."
        ),
    ),
    EvidenceKind(
        key="updater",
        label="Updater log",
        filenames=("ZSAUpdater.log",),
        tells_you="Client version upgrade history: what was installed, when, and whether it succeeded.",
        reach_for_it="The first thing to check when the complaint is \"it broke after an update\".",
        rank=60,
    ),
    EvidenceKind(
        key="credential",
        label="Credential provider log",
        filenames=("ZSACredentialProvider.log",),
        tells_you="Pre-login and Windows credential-provider activity, including machine-tunnel sign-in before a user logs on.",
        reach_for_it="When machine tunnel or pre-logon connectivity is in question.",
        rank=70,
    ),
    EvidenceKind(
        key="helper",
        label="Helper log",
        filenames=("ZSAHelper.log",),
        tells_you="Supporting helper-process activity, used to corroborate timing around service and app events.",
        reach_for_it="Rarely on its own; useful for cross-checking a timeline.",
        rank=80,
    ),
    EvidenceKind(
        key="script",
        label="Script executor log",
        filenames=("ZSAScriptExecutorRpcClient.log",),
        tells_you="Execution of admin-defined scripts triggered by the client.",
        reach_for_it="When a deployment relies on client-triggered scripting.",
        rank=90,
    ),
)

#: Non-ZCC-format evidence, keyed by the marker ``classify_foreign`` matches.
FOREIGN_CATALOG: Tuple[EvidenceKind, ...] = (
    EvidenceKind(
        key="zapprd",
        label="Driver trace (zapprd)",
        filenames=("zapprd.log",),
        tells_you="Low-level LWF/NDIS packet-driver trace from the Zscaler filter driver.",
        reach_for_it="When traffic is lost below the application layer, or another filter driver may be conflicting.",
        rank=100,
    ),
    EvidenceKind(
        key="setupapi.dev",
        label="Windows driver install history",
        filenames=("setupapi.dev.log",),
        tells_you="Windows driver and device install history, including when the Zscaler adapter was installed or replaced.",
        reach_for_it="After an adapter or driver change, or when the network adapter is missing.",
        rank=110,
    ),
    EvidenceKind(
        key="AppInfo.log",
        label="Host state snapshot",
        filenames=("AppInfo.log",),
        tells_you="XML snapshot of host state at collection time.",
        reach_for_it="For device context that the rolling logs do not carry.",
        rank=120,
    ),
    EvidenceKind(
        key="profiles.log",
        label="macOS configuration profiles",
        filenames=("profiles.log",),
        tells_you="Configuration profiles installed on a Mac, including the Zscaler system-extension and certificate payloads.",
        reach_for_it="On macOS when a profile or system extension may not be installed or approved.",
        rank=130,
    ),
    EvidenceKind(
        key="pf.log",
        label="macOS packet filter",
        filenames=("pf.log",),
        tells_you="The macOS packet-filter ruleset in effect.",
        reach_for_it="On macOS when a local firewall rule may be dropping traffic.",
        rank=140,
    ),
    EvidenceKind(
        key="ZSAVersionHistory",
        label="Version history",
        filenames=("ZSAVersionHistory.txt",),
        tells_you="Tab-separated record of client versions installed over time.",
        reach_for_it="To date a regression against a specific client version.",
        rank=150,
    ),
)

PACKET_CAPTURE = EvidenceKind(
    key="pcap",
    label="Packet capture",
    filenames=("*.pcapng",),
    tells_you=(
        "Packets captured at the adapter level across all network adapters, so DNS "
        "answers, TCP handshakes and resets, retransmissions, and TLS alerts can be "
        "read directly. Captures align to the logs by timestamp."
    ),
    reach_for_it=(
        "To confirm on the wire what the logs imply — an unanswered SYN, a reset, or a "
        "failed name resolution."
    ),
    rank=15,
    plain_label="Packet capture",
    plain_tells_you=(
        "A recording of the actual network traffic. It shows whether the device's "
        "requests were answered, refused, or never got a reply."
    ),
)

PAC_DOCUMENT = EvidenceKind(
    key="pac",
    label="PAC file",
    filenames=("*.pac", "inline in a log"),
    tells_you=(
        "The proxy auto-config in force: which hosts go DIRECT and which are forwarded "
        "to a service edge, plus the gateway list the client was given."
    ),
    reach_for_it="When a site appears not to be going through the tunnel at all.",
    rank=35,
    plain_label="Proxy settings file (PAC)",
    plain_tells_you=(
        "The rules deciding which websites skip Zscaler and which go through it."
    ),
)


# --------------------------------------------------------------------------
# Recap
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceRow:
    kind: EvidenceKind
    present: bool
    detail: str = ""


@dataclass(frozen=True)
class BundleRecap:
    """Everything the at-a-glance panel shows, already resolved."""

    user: str
    device: str
    os_label: str
    zcc_version: str
    first_ts: Optional[datetime]
    last_ts: Optional[datetime]
    duration_label: str
    timezone_label: str
    record_count: int
    log_file_count: int
    rotations_read: int
    rotations_found: int
    pcap_count: int
    pcap_window: str
    log_levels: Mapping[str, int]
    evidence: Tuple[EvidenceRow, ...]

    UNKNOWN = "Not evidenced in these logs"

    @property
    def span_label(self) -> str:
        if not self.first_ts or not self.last_ts:
            return self.UNKNOWN
        return (
            f"{self.first_ts:%Y-%m-%d %H:%M} → {self.last_ts:%Y-%m-%d %H:%M} UTC"
        )

    @property
    def has_debug_logging(self) -> bool:
        """Debug verbosity present, which changes what absence can prove."""
        return bool(self.log_levels.get("DEBUG"))

    @property
    def present_count(self) -> int:
        return sum(1 for row in self.evidence if row.present)

    @property
    def missing_important(self) -> Tuple[EvidenceRow, ...]:
        """Absent evidence that materially limits an investigation."""
        return tuple(
            row for row in self.evidence
            if not row.present and row.kind.key in {"tunnel", "pcap", "service", "upm"}
        )


def _label_os(family: Optional[str]) -> str:
    return {
        "windows": "Windows",
        "macos": "macOS",
        "linux": "Linux",
        "ios": "iOS",
        "android": "Android",
    }.get((family or "").lower(), (family or "").title())


def _format_duration(seconds: Optional[float]) -> str:
    if not seconds or seconds <= 0:
        return ""
    minutes, _ = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _pcap_window(pcaps: Sequence[Any]) -> str:
    starts = [getattr(p, "ts_first", None) or (p.get("ts_first") if isinstance(p, dict) else None) for p in pcaps]
    ends = [getattr(p, "ts_last", None) or (p.get("ts_last") if isinstance(p, dict) else None) for p in pcaps]
    starts = [value for value in starts if value]
    ends = [value for value in ends if value]
    if not starts or not ends:
        return ""
    return f"{min(starts):%Y-%m-%d %H:%M} → {max(ends):%H:%M} UTC"


def build_recap(
    facts: Any,
    *,
    pcaps: Sequence[Any] = (),
    pac_documents: int = 0,
    rotations_read: int = 0,
    rotations_found: int = 0,
) -> BundleRecap:
    """Resolve the recap from parsed facts. Nothing here infers a value."""
    by_component: Dict[str, int] = dict(getattr(facts, "lines_by_component", {}) or {})
    source_files = [str(name) for name in (getattr(facts, "distinct_source_files", []) or [])]

    rows: List[EvidenceRow] = []
    for kind in COMPONENT_CATALOG:
        count = by_component.get(kind.key, 0)
        files = sum(
            1 for name in source_files
            if any(marker.split(".")[0].lower() in name.lower() for marker in kind.filenames)
        )
        detail = ""
        if count:
            detail = f"{count:,} records" + (f" · {files} file(s)" if files else "")
        rows.append(EvidenceRow(kind=kind, present=bool(count), detail=detail))

    rows.append(EvidenceRow(
        kind=PACKET_CAPTURE,
        present=bool(pcaps),
        detail=(f"{len(pcaps)} capture(s)" if pcaps else ""),
    ))
    rows.append(EvidenceRow(
        kind=PAC_DOCUMENT,
        present=bool(pac_documents),
        detail=(f"{pac_documents} recovered" if pac_documents else ""),
    ))
    for kind in FOREIGN_CATALOG:
        matched = [name for name in source_files if kind.key.lower() in name.lower()]
        rows.append(EvidenceRow(
            kind=kind,
            present=bool(matched),
            detail=(f"{len(matched)} file(s)" if matched else ""),
        ))

    rows.sort(key=lambda row: (row.kind.rank, row.kind.label))

    return BundleRecap(
        user=str(getattr(facts, "user_login", "") or ""),
        device=str(getattr(facts, "user_hostname", "") or ""),
        os_label=_label_os(getattr(facts, "os_family", None)),
        zcc_version=str(getattr(facts, "zcc_version", "") or ""),
        first_ts=getattr(facts, "first_ts", None),
        last_ts=getattr(facts, "last_ts", None),
        duration_label=_format_duration(getattr(facts, "duration_seconds", None)),
        timezone_label=str(getattr(facts, "bundle_tz_label", "") or ""),
        record_count=int(getattr(facts, "total_lines", 0) or 0),
        log_file_count=int(getattr(facts, "bundle_log_file_count", 0) or 0),
        rotations_read=rotations_read,
        rotations_found=rotations_found,
        pcap_count=len(pcaps),
        pcap_window=_pcap_window(pcaps),
        log_levels=dict(getattr(facts, "lines_by_level", {}) or {}),
        evidence=tuple(rows),
    )
