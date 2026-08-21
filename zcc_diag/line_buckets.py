"""Line bucketing — Slice 9 (2026-08-14).

Classify EVERY parsed line in a bundle along two independent axes:

    service    — which Zscaler product the line belongs to
                 (zia / zpa / zdx / zcc_core / os_platform / unknown)
    subsystem  — what the line is ABOUT
                 (auth / tunnel / policy / network / dns / cert /
                  posture / power / update / ipc / ui / capture /
                  diagnostics / data / unknown)

Why two axes instead of one bucket: "is this a ZIA or a ZPA problem"
and "is this an auth or a tunnel problem" are orthogonal questions, and
collapsing them into a single flat list forces the engineer to scan
`zia_auth`, `zpa_auth`, `zdx_auth`... separately when they only wanted
"auth". Keeping them independent means one pass classifies once and
both pivots come free.

Design contract (unchanged from the rest of Log-Analyzer):
    * Deterministic. A line lands in a bucket because it matched a
      documented regex, not because anything inferred intent.
    * Zero interpretation. A bucket is a category, not a finding. We
      never say a line is "bad" — only what subsystem it concerns.
    * **Honest about coverage.** Lines that match nothing are counted
      as `unknown` and reported, not silently dropped. `BucketReport`
      carries the unclassified count, the unclassified percentage, and
      the most common unmatched *line shapes* so the gap is visible
      and fixable rather than invisible.

The shape normaliser (`line_shape`) is what makes the coverage report
actionable: it strips the variable parts of a line body (numbers, hex
blobs, IPs, GUIDs, quoted strings, paths) so that 40,000 distinct
unmatched lines collapse into a couple of dozen recurring templates.
Reading the top 30 shapes tells you exactly which patterns to add
next.

Pure library — no streamlit deps. CLI-shared.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple


# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

SERVICES: List[str] = [
    "zia",          # Internet Access — web/proxy/tunnel-to-SME
    "zpa",          # Private Access — broker/mtunnel/app segments
    "zdx",          # Digital Experience — probes, traces, metrics
    "zcc_core",     # The client itself — service lifecycle, tray, IPC, policy fetch
    "os_platform",  # OS-level: adapters, drivers, WFP, power, registry
    "unknown",
]

SUBSYSTEMS: List[str] = [
    "auth",          # SAML / IdP / token / re-auth / enrollment
    "tunnel",        # Z-Tunnel, mtunnel, DTLS, transport selection
    "proxy",         # local/TUN proxy request path, per-connection lifecycle
    "policy",        # App Profile, forwarding profile, bypass, PAC
    "network",       # adapters, routes, trusted-network, captive portal
    "dns",           # resolution, SRV lookups, DNS bypass
    "cert",          # certificate load / validation / expiry / pinning
    "process_trust", # process signature checks, app-based bypass decisions
    "posture",       # device posture, trust conditions, compliance
    "power",         # sleep/wake/Modern Standby/session change
    "update",        # client upgrade / download / install
    "service",       # ZCC service/process lifecycle + status queries
    "ipc",           # inter-process comms between ZCC components
    "ui",            # tray notifications, user-visible dialogs
    "capture",       # packet capture, log collection, diagnostics bundles
    "diagnostics",   # self-test, health, telemetry emission
    "data",          # byte counters / throughput / keepalive traffic
    "unknown",
]

# Provenance note for the three subsystems added in Phase 61
# (`proxy`, `process_trust`, `service`): each was derived by ranking the
# subsystem-unresolved line shapes across the full 26-bundle corpus, not
# invented. Their measured volumes there were roughly 35k, 25k and 2.5k
# lines respectively — the three largest coherent clusters that had no
# home in the original vocabulary.


# --------------------------------------------------------------------------
# Classification rules
# --------------------------------------------------------------------------
#
# Each rule is (service_or_None, subsystem_or_None, compiled_pattern).
# Rules are evaluated in order; the FIRST rule to match sets whichever
# axis it declares. A rule may set only one axis (None means "this rule
# says nothing about that axis"), so a line can pick up its service from
# one rule and its subsystem from another. Evaluation continues until
# BOTH axes are resolved or the rule list is exhausted.
#
# Ordering: most specific first. A `BRK_MT_*` token is unambiguously ZPA
# tunnel; a bare "authentication" is only "auth" with no service.

_RULES: List[Tuple[Optional[str], Optional[str], "re.Pattern"]] = [
    # ================= ZPA — unambiguous product markers =================
    ("zpa", "tunnel", re.compile(
        r"\bBRK_MT_[A-Z0-9_]+|\bmtunnel|\bzpn_mtunnel|\btag_id\b"
        r"|\bbroker[a-z0-9_-]*\.(?:[a-z0-9_-]+\.)*(?:zpath|zpalb|zpaservice)\.net",
        re.IGNORECASE)),
    ("zpa", "auth", re.compile(
        r"\bZPN_AUTH|ZPN_ERR_[A-Z0-9_]*AUTH|zpa.*re-?auth|SAML_EXPIRED"
        r"|BRK_REDIRECT|zpn_auth_", re.IGNORECASE)),
    ("zpa", "policy", re.compile(
        r"\bzpn_(?:trusted_networks|posture_profile|forwarding_profile|app_seg)"
        r"|application segment|app_seg|segment group", re.IGNORECASE)),
    ("zpa", "dns", re.compile(
        r"ZPN_ERR_DNS|zpa.*dns (?:check|resolve)", re.IGNORECASE)),
    # `ZPN:<n>:` (colon form) was missing — the old pattern required an
    # underscore after ZPN, so `ZPN:12: Control Message Response Data`
    # never matched. That shape alone accounted for 5,480 unclassified
    # lines in the corpus.
    ("zpa", "tunnel", re.compile(
        r"\bZPN:\s*\d+\s*:|Control Message (?:Request|Response)",
        re.IGNORECASE)),
    ("zpa", None, re.compile(
        r"\bZPN_[A-Z0-9_]{3,}|\bZPA\b|zpath\.net|processZPAPart"
        r"|TUNNEL_FORWARDING|assistant", re.IGNORECASE)),

    # ================= ZIA — unambiguous product markers =================
    ("zia", "tunnel", re.compile(
        r"\bZT2[AB]\b|Z-?Tunnel|ZSCCM::|svpn_tun|TunMTU|DataChannelCount"
        r"|raiseSessionInformationEvent|\bDTLS\b", re.IGNORECASE)),
    ("zia", "policy", re.compile(
        r"Network hostname csv|Resolved exclude hostname|\bPAC\b|pac_url"
        r"|forwardingProfileActions|proxy auto ?config", re.IGNORECASE)),
    ("zia", "auth", re.compile(
        r"mobile\.zscaler[a-z0-9]*\.(?:net|us)|mobile\.zscloud\.net"
        r"|samlsp[a-z0-9.-]*\.zscaler\.com|Tunnel api request", re.IGNORECASE)),
    ("zia", None, re.compile(
        r"\bZIA\b|\bSME\b|Service Edge|sme[a-z0-9_.-]*\.zscaler[a-z0-9]*\.net"
        r"|zscaler(?:two|three|beta|gov|ten)?\.(?:net|us)|zscloud\.net",
        re.IGNORECASE)),

    # ================= ZDX =================
    ("zdx", "diagnostics", re.compile(
        r"\bZDX\b|web ?probe|cloud ?path|deep ?trace|ZTraceroute|\bmtr_"
        r"|probe (?:result|latency)|upm_", re.IGNORECASE)),

    # ================= Subsystem-only rules (service stays open) =========
    #
    # The three blocks immediately below were added in Phase 61 from the
    # ranked corpus measurement. They sit ABOVE the older rules because
    # they're more specific: a `TUN-Proxy: connection to <ip>` line also
    # contains the word "connection", which a looser later rule would
    # otherwise claim.

    # ---- Round 4: last two named residues -----------------------------
    # UDP proxy path (~4.3k lines) and registry-read failures (~2.3k,
    # in 18 of 26 bundles). Both were the largest remaining *named*
    # shapes; everything below them is under 2k lines.
    (None, "proxy", re.compile(
        r"UDP Proxy:|endConnection called", re.IGNORECASE)),
    ("os_platform", "network", re.compile(
        r"reading registry:\s*HKEY_|ZSVpnBypassRouteManager"
        r"|refreshVPNBypassRoutes|checkAndRestartTunIfRequired",
        re.IGNORECASE)),

    # ---- Round 3: the named residue from the round-2 measurement ------
    # Each of these was a specific shape still showing in the top-12
    # unresolved list after round 2, fixed by naming the token the rule
    # was missing rather than by broadening anything.

    # `SERVICE_CONTROL_INTERROGATE` etc — the round-2 service rule only
    # listed SERVICE_(RUNNING|STOPPED|PENDING).
    (None, "service", re.compile(
        r"SERVICE_CONTROL_[A-Z_]+|serviceControllerHandler", re.IGNORECASE)),

    # Proxy teardown / destination selection that carries none of the
    # round-1 proxy keywords (~22k lines combined).
    (None, "proxy", re.compile(
        r"Disconnecting\s*\[?[0-9a-f:.]|Dest Address in local proxy"
        r"|Closing client socket|_requestBuffer|handler buf used",
        re.IGNORECASE)),

    # Proxy-health monitor (ZPHM) and the loopback/conntest self-check.
    (None, "diagnostics", re.compile(
        r"\bZPHM\b|onProxyHealthResult|Loopback Connection check|/conntest",
        re.IGNORECASE)),

    # Aggregate client status line + T1 fallback decision.
    (None, "network", re.compile(
        r"getCurrentNetworkType|getSmeProxyState|ZApp Status",
        re.IGNORECASE)),
    (None, "tunnel", re.compile(
        r"fallback to T1|Allowing T1 connection", re.IGNORECASE)),

    # ---- ZPA broker socket I/O (Phase 61 round 2) ---------------------
    # ~110k lines across the ZPA-heavy bundles. `ZpnBrokerConn:<n>:` and
    # the `Zpn client`/`_zpnRequestBuffer` family are the byte-level
    # broker transport. Tagged zpa/tunnel because the socket IS the
    # mtunnel transport.
    ("zpa", "tunnel", re.compile(
        r"ZpnBrokerConn|Zpn socket|zpnSocketRead|Zpn client|_zpnRequestBuffer"
        r"|Zpn Client socket|processResponse rxBytes|START_TLV_PARSING",
        re.IGNORECASE)),

    # ---- ZIA SME request/response path (Phase 61 round 2) -------------
    # `Use Sme:`, `SME request:`, `SME response:`, `Cnonce is:`,
    # `Use T2 for Proxied Web traffic` — the ZIA tunnel-selection and
    # SME handshake path, ~40k lines across 16 bundles.
    ("zia", "tunnel", re.compile(
        r"Use Sme:|SME re(?:quest|sponse):|\bCnonce\b|Use T2 for Proxied"
        r"|useTunnel2Prot|T2HC packet", re.IGNORECASE)),

    # ---- Server-socket lifecycle (Phase 61 round 2) -------------------
    # ~55k lines. Distinct from the proxy cluster below: this is the
    # upstream half — connect, state transitions, lookup-table churn,
    # and the very common TcpConnection teardown exception (22.7k lines
    # in 22 of 26 bundles, previously invisible).
    (None, "proxy", re.compile(
        r"Exception in TcpConnection|server socket mapping state"
        r"|Connecting server socket|Adding entry to lookup table"
        r"|Client Buffer not writable|getInterfaceIPforDestination"
        r"|GetBestInterfaceEx", re.IGNORECASE)),

    # ---- macOS XPC / prelogin + process enumeration (round 2) ---------
    # `ZSService: Forwarding connection info to PreloginUI ... XPC` is
    # 23.9k lines and the single largest remaining shape; it's macOS IPC.
    # `ProcessIDsForPath` is process enumeration -> process_trust.
    (None, "ipc", re.compile(
        r"\bXPC\b|PreloginUI|ZSService:\s*Forwarding", re.IGNORECASE)),
    (None, "process_trust", re.compile(
        r"ProcessIDsForPath", re.IGNORECASE)),

    # ---- Step-up auth tokens (round 2) --------------------------------
    (None, "auth", re.compile(
        r"StepUp\s+A[lI]\s+token|\bStepUp\b", re.IGNORECASE)),

    # ---- Local / TUN proxy request path -------------------------------
    # Largest single cluster in the unresolved set (~35k lines, 8 bundles).
    # This is ZIA's per-request proxy plumbing: socket accept, upstream
    # connect, byte accounting, teardown.
    (None, "proxy", re.compile(
        r"ZTCPServerConnection|TUN-Proxy|LCL-Proxy|readFromClient"
        r"|startServerConnection|ServerConnections\s*=|clt_bytes|srv_bytes"
        r"|SO_SNDBUF|SO_RCVBUF|Pid for local sock|sock-fd"
        r"|Disconnecting!|Dropping Https request", re.IGNORECASE)),

    # ---- Process signature / app-based-bypass decisions ---------------
    # ~25k lines. ZCC deciding whether a process is Zscaler-signed and
    # therefore whether its traffic bypasses the tunnel. Directly
    # relevant to "why is this app not going through Zscaler".
    (None, "process_trust", re.compile(
        r"Signer (?:trust|does not match)|signed by Zscaler|EV sign status"
        r"|Validating process for PID|ImpersonateLoggedOnUser"
        r"|CheckWebView2Process|Process (?:Name|executable)\s*:",
        re.IGNORECASE)),

    # ---- ZCC service / process lifecycle ------------------------------
    (None, "service", re.compile(
        r"Getting status for service|Returning service status|SERVICE_(?:RUNNING|STOPPED|PENDING)"
        r"|service (?:started|starting|stopped|initialized)"
        r"|ZSAService (?:up|start)|ZCC (?:starting|up)", re.IGNORECASE)),

    # ---- PAC / system-proxy resolution --------------------------------
    # The old `\bPAC\b` only matched PAC as a standalone word, so
    # `pacparser_find_proxy`, `ProxyChoices` and the whole
    # `ZSAWinProxyUtil:` family (~13k lines) fell through.
    (None, "policy", re.compile(
        r"pacparser|ProxyChoices|ZSAWinProxyUtil|isProxyConfigured"
        r"|WinHttpGetProxyForUrl|WinHttpDetectAutoProxyConfigUrl"
        r"|getTunnelBypass|evaluateEnterpriseVpnFailOpen", re.IGNORECASE)),

    # ---- Firewall-health monitor (ZFHM) -------------------------------
    (None, "network", re.compile(
        r"\bZFHM\b|FIREWALL_HEALTH_[A-Z]+", re.IGNORECASE)),

    # ---- Tunnel reachability probe ------------------------------------
    (None, "tunnel", re.compile(
        r"checkTunTcpEchoServerUp|getTunnelStatus", re.IGNORECASE)),

    # ---- Adapter / IP-range enumeration -------------------------------
    # `\badapter\b` (old rule, further down) cannot match "AdapterId":
    # the trailing \b fails because "I" is a word character. These lines
    # are pure network-interface inventory (~9k lines).
    (None, "network", re.compile(
        r"AdapterId|Active IPv[46] Range|IP for index|Allowing Src Ip"
        r"|is not in Ipv6 format", re.IGNORECASE)),

    (None, "power", re.compile(
        r"Power Change Event|Modern Standby|force_reauth_sleep_trigger"
        r"|\bsleep\b|\bhibernat|\bresume(?:d|ing)?\b|WM_POWERBROADCAST"
        r"|session (?:lock|unlock)|screen ?(?:lock|saver)", re.IGNORECASE)),
    (None, "update", re.compile(
        r"\bupgrade\b|\bupdater?\b|new version|download.*installer"
        r"|msiexec|\.pkg\b|install(?:ing|ed) build", re.IGNORECASE)),
    (None, "cert", re.compile(
        r"\bcertificat|\bcert\b|getCertExpiryDaySec|X509|\bCA (?:bundle|store)"
        r"|pinn?ing|SSL_ERROR|error:1[0-9A-F]{7}|TLS handshake", re.IGNORECASE)),
    (None, "posture", re.compile(
        r"\bposture\b|trust(?:ed)? condition|device (?:trust|compliance)"
        r"|\bcompliance\b|OS version check|disk encryption|antivirus check",
        re.IGNORECASE)),
    (None, "dns", re.compile(
        r"\bDNS\b|resolveDns|_kerberos\._tcp|_ldap\._tcp|_gc\._tcp|SRV record"
        r"|getaddrinfo|nslookup|resolver", re.IGNORECASE)),
    (None, "auth", re.compile(
        r"\bSAML\b|\bIdP\b|\bOAuth|\bJWT\b|bearer token|\benroll"
        r"|authentic|login_hint|loginName|\bSSO\b|\bMFA\b|credential"
        r"|AUTHENTICATION_REQUIRED|re-?authent", re.IGNORECASE)),
    (None, "network", re.compile(
        r"\badapter\b|\binterface\b|network (?:change|transition|state|type)"
        r"|trusted[_ ]?network|captive ?portal|\bgateway\b|\broute\b|\bWFP\b"
        r"|\bMTU\b|link (?:up|down)|\bWi-?Fi\b|\bethernet\b|OFF_TRUSTED"
        r"|NON_TRUSTED|TRUSTED_NETWORK", re.IGNORECASE)),
    (None, "policy", re.compile(
        r"TrayPolicy|policy (?:push|update|reload|fetch)|App Profile"
        r"|appProfile|forwarding ?profile|\bbypass\b|policy_name"
        r"|captivePortalConfig|failOpenPolicy", re.IGNORECASE)),
    (None, "capture", re.compile(
        r"\bpcap|packet capture|log ?(?:collect|upload|bundle)|\bzip\b"
        r"|diagnostic bundle|export logs", re.IGNORECASE)),
    (None, "ipc", re.compile(
        r"\bIPC\b|named ?pipe|\bRPC\b|socket (?:connect|accept|bind)"
        r"|message (?:sent|received) to (?:tray|service|tunnel)"
        r"|sendTrayPolicy|inter-?process", re.IGNORECASE)),
    (None, "ui", re.compile(
        r"ZSATray Notification|\bnotificat|\btoast\b|\bdialog\b|\btooltip\b"
        r"|user (?:clicked|selected|dismissed)|show(?:ing)? (?:popup|banner)",
        re.IGNORECASE)),
    (None, "tunnel", re.compile(
        r"\btunnel\b|\bkeepalive\b|\bheartbeat\b|transport (?:select|switch)"
        r"|\bTLS\b|\bQUIC\b|reconnect", re.IGNORECASE)),
    (None, "data", re.compile(
        r"bytes[_ ](?:in|out|sent|received)|\bthroughput\b|\bbandwidth\b"
        r"|data (?:sent|received)|\bRTT\b|\blatency\b", re.IGNORECASE)),
    (None, "diagnostics", re.compile(
        r"\bhealth ?check|self ?test|\btelemetry\b|\bmetric|\bstatistic"
        r"|memory usage|\bCPU\b|performance counter", re.IGNORECASE)),

    # ================= OS / platform (service axis only) =================
    ("os_platform", None, re.compile(
        r"\bWFP\b|\bNDIS\b|\bLWF\b|\bregistry\b|HKEY_|\bdriver\b|\bkernel\b"
        r"|\bWMI\b|\bnetsh\b|\bIOKit\b|\bkext\b|\bsystem ?extension\b"
        r"|launchd|Windows (?:Filtering|Service)", re.IGNORECASE)),
]


# --------------------------------------------------------------------------
# Component-derived fallback
# --------------------------------------------------------------------------
#
# When no rule resolves an axis, we fall back to what the *file the line
# came from* implies. This is weaker evidence than a body-text match, so
# it only ever fills a gap the rules left open — it never overrides a
# rule. `BucketedLine.service_via` / `subsystem_via` record which of the
# two produced each answer, so the UI can show "matched" vs "inferred
# from component" and the engineer knows how much to trust it.

_COMPONENT_SERVICE_DEFAULT: Dict[str, str] = {
    # A tunnel-log line with no product marker is still the ZCC tunnel
    # process talking — that's client-core, not necessarily ZIA or ZPA.
    "tunnel": "zcc_core",
    "service": "zcc_core",
    "tray": "zcc_core",
    "upm": "zdx",  # UPM is the ZDX telemetry process
}

_COMPONENT_SUBSYSTEM_DEFAULT: Dict[str, str] = {
    "upm": "diagnostics",
    "tray": "ui",
}


# --------------------------------------------------------------------------
# Shape normaliser — collapses variable tokens so unmatched lines can be
# counted as recurring templates instead of N distinct strings.
# --------------------------------------------------------------------------

_SHAPE_SUBS: List[Tuple["re.Pattern", str]] = [
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<GUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HEX>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\S*"), "<TS>"),
    (re.compile(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b"), "<VER>"),
    (re.compile(r'"[^"]*"'), '"<STR>"'),
    (re.compile(r"[A-Za-z]:\\[^\s]+"), "<PATH>"),
    (re.compile(r"/(?:[\w.-]+/){2,}[\w.-]+"), "<PATH>"),
    (re.compile(r"\b\d+\b"), "<N>"),
]

_SHAPE_MAX_LEN = 120


def line_shape(body: str) -> str:
    """Normalise a log-line body into a recurring 'template' by replacing
    variable tokens (numbers, IPs, GUIDs, hex blobs, timestamps, quoted
    strings, filesystem paths) with placeholders.

    Two lines that differ only in their identifiers collapse to the same
    shape, so the coverage report can say "this one template accounts
    for 12,000 unclassified lines" instead of listing 12,000 strings.
    """
    if not body:
        return ""
    s = body.strip()
    for pat, repl in _SHAPE_SUBS:
        s = pat.sub(repl, s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:_SHAPE_MAX_LEN]


# --------------------------------------------------------------------------
# Datamodel
# --------------------------------------------------------------------------

@dataclass(slots=True)
class BucketedLine:
    """One classified line. Mirrors the IndexedLine fields the UI needs
    plus the two bucket axes and how each was decided."""
    ts: Optional[datetime]
    level: str
    component: str
    source_file: str
    line_no: int
    body: str
    service: str
    subsystem: str
    service_via: str      # "matched" | "component" | "unresolved"
    subsystem_via: str    # "matched" | "component" | "unresolved"


@dataclass
class BucketReport:
    """Whole-bundle classification result + an honest coverage account."""
    total_lines: int = 0

    # Pivots
    by_service: Dict[str, int] = field(default_factory=dict)
    by_subsystem: Dict[str, int] = field(default_factory=dict)
    by_pair: Dict[Tuple[str, str], int] = field(default_factory=dict)

    # How each axis got resolved — the provenance account.
    service_via_counts: Dict[str, int] = field(default_factory=dict)
    subsystem_via_counts: Dict[str, int] = field(default_factory=dict)

    # Coverage
    unclassified_service: int = 0
    unclassified_subsystem: int = 0
    unclassified_both: int = 0
    # Top recurring shapes among lines whose SUBSYSTEM is unresolved.
    #
    # This used to key off "both axes unresolved", which made the panel
    # useless: the component fallback resolves `service` for essentially
    # every line in a real bundle, so "both unresolved" is ~0 by
    # construction. Measured on the 26-bundle corpus the panel reported
    # zero gaps while 23% of lines genuinely had no subsystem. Keying on
    # the subsystem axis — the one that actually has the gap — is what
    # makes this list actionable.
    top_unclassified_shapes: List[Tuple[str, int]] = field(default_factory=list)

    lines: List[BucketedLine] = field(default_factory=list)

    # ---- Derived ----
    def service_coverage_pct(self) -> float:
        if not self.total_lines:
            return 0.0
        return 100.0 * (self.total_lines - self.unclassified_service) / self.total_lines

    def subsystem_coverage_pct(self) -> float:
        if not self.total_lines:
            return 0.0
        return 100.0 * (self.total_lines - self.unclassified_subsystem) / self.total_lines

    def pairs_sorted(self) -> List[Tuple[Tuple[str, str], int]]:
        return sorted(self.by_pair.items(), key=lambda kv: -kv[1])

    def lines_for(self, service: Optional[str] = None,
                  subsystem: Optional[str] = None) -> List[BucketedLine]:
        """Every line matching the given service and/or subsystem.
        Passing None for an axis means 'any'."""
        out = []
        for ln in self.lines:
            if service is not None and ln.service != service:
                continue
            if subsystem is not None and ln.subsystem != subsystem:
                continue
            out.append(ln)
        return out


# --------------------------------------------------------------------------
# Classifier
# --------------------------------------------------------------------------

def classify_line(body: str, component: str = "") -> Tuple[str, str, str, str]:
    """Classify one line body.

    Returns `(service, subsystem, service_via, subsystem_via)`.

    Resolution order per axis:
      1. First matching rule in `_RULES` that declares that axis  → "matched"
      2. Component-derived default                                → "component"
      3. "unknown"                                                → "unresolved"
    """
    service: Optional[str] = None
    subsystem: Optional[str] = None

    if body:
        for rule_service, rule_subsystem, pat in _RULES:
            # Skip rules that can't tell us anything new.
            if (service is not None or rule_service is None) and \
               (subsystem is not None or rule_subsystem is None):
                continue
            if not pat.search(body):
                continue
            if service is None and rule_service is not None:
                service = rule_service
            if subsystem is None and rule_subsystem is not None:
                subsystem = rule_subsystem
            if service is not None and subsystem is not None:
                break

    service_via = "matched" if service is not None else "unresolved"
    subsystem_via = "matched" if subsystem is not None else "unresolved"

    if service is None:
        fallback = _COMPONENT_SERVICE_DEFAULT.get(component)
        if fallback:
            service, service_via = fallback, "component"
    if subsystem is None:
        fallback = _COMPONENT_SUBSYSTEM_DEFAULT.get(component)
        if fallback:
            subsystem, subsystem_via = fallback, "component"

    return (service or "unknown", subsystem or "unknown",
            service_via, subsystem_via)


def build_buckets(idx, keep_lines: bool = True,
                  top_shapes: int = 40) -> BucketReport:
    """Single pass over `idx.lines`, classifying every one.

    `keep_lines=False` drops the per-line list and keeps only the
    aggregate counts — useful for the CLI's summary mode on very large
    bundles where the caller only wants the distribution.
    """
    rep = BucketReport()
    by_service: Counter = Counter()
    by_subsystem: Counter = Counter()
    by_pair: Counter = Counter()
    svc_via: Counter = Counter()
    sub_via: Counter = Counter()
    unmatched_shapes: Counter = Counter()

    for line in idx.lines:
        body = line.body or ""
        comp = line.component or ""
        service, subsystem, s_via, ss_via = classify_line(body, comp)

        rep.total_lines += 1
        by_service[service] += 1
        by_subsystem[subsystem] += 1
        by_pair[(service, subsystem)] += 1
        svc_via[s_via] += 1
        sub_via[ss_via] += 1

        if service == "unknown":
            rep.unclassified_service += 1
        if subsystem == "unknown":
            rep.unclassified_subsystem += 1
            # Collect shapes on the SUBSYSTEM axis — see the note on
            # `top_unclassified_shapes`. Keying this off "both unresolved"
            # made the panel silent on real bundles.
            unmatched_shapes[line_shape(body)] += 1
        if service == "unknown" and subsystem == "unknown":
            rep.unclassified_both += 1

        if keep_lines:
            rep.lines.append(BucketedLine(
                ts=line.ts,
                level=line.level or "",
                component=comp,
                source_file=line.source_file or "",
                line_no=line.line_no,
                body=body,
                service=service,
                subsystem=subsystem,
                service_via=s_via,
                subsystem_via=ss_via,
            ))

    rep.by_service = dict(by_service)
    rep.by_subsystem = dict(by_subsystem)
    rep.by_pair = dict(by_pair)
    rep.service_via_counts = dict(svc_via)
    rep.subsystem_via_counts = dict(sub_via)
    rep.top_unclassified_shapes = unmatched_shapes.most_common(top_shapes)
    return rep
