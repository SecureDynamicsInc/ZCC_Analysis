"""
Detector: 3rd-party VPN coexistence with ZCC.

What this catches
-----------------
When a customer has both ZCC AND another VPN client (Cisco
AnyConnect, FortiClient, Palo Alto GlobalProtect, OpenVPN, etc)
installed, the adapters fight for routing decisions. Symptoms:

  * adapter_instability fires on LUID alias churn (Windows)
  * Tunnel state flapping when the other VPN connects/disconnects
  * DNS leaks when the other VPN takes over DNS

The existing ``adapter_instability`` detector catches the SYMPTOM
(NIC churn) but doesn't attribute it. This detector extracts the
3rd-party VPN identity from:
  * AppInfo.xml's network-card list (the connection names give it
    away: "Cisco AnyConnect Virtual Miniport Adapter")
  * apps_installed list — process / app names match known VPN clients
  * Tunnel log mentions of competing VPN process names

Why
---
Without attribution, the engineer sees "NIC instability" and has to
ask the customer "do you have any other VPN installed?". This
detector answers that question from the bundle alone.

The adapter and process signatures are generic vendor product identifiers, not
customer case records.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from . import Finding, IssueDetector, Severity, register
from ..log_parser import LogLine
from ..summary import BundleSummary


# --- VPN vendor identification table ---------------------------------

# (display name, adapter-name regex, app-name regex, process-name regex)
_VPN_VENDORS: List[Tuple[str, re.Pattern, re.Pattern, re.Pattern]] = [
    ("Cisco AnyConnect",
     re.compile(r"Cisco\s+AnyConnect\b", re.IGNORECASE),
     re.compile(r"Cisco\s+AnyConnect|Cisco\s+Secure\s+Client", re.IGNORECASE),
     re.compile(r"vpnagent|vpnui|csm_agent\.exe", re.IGNORECASE)),
    ("Cisco Secure Client",
     re.compile(r"Cisco\s+Secure\s+Client\b", re.IGNORECASE),
     re.compile(r"Cisco\s+Secure\s+Client", re.IGNORECASE),
     re.compile(r"vpnagent|csc_ui\.exe", re.IGNORECASE)),
    ("FortiClient VPN",
     re.compile(r"FortiClient\s+(?:VPN|SSL)|Fortinet", re.IGNORECASE),
     re.compile(r"FortiClient", re.IGNORECASE),
     re.compile(r"FortiSSLVPNdaemon|FortiTray\.exe|fcvpn\.exe",
                re.IGNORECASE)),
    ("Palo Alto GlobalProtect",
     re.compile(r"GlobalProtect|Palo\s+Alto", re.IGNORECASE),
     re.compile(r"GlobalProtect", re.IGNORECASE),
     re.compile(r"PanGPS\.exe|PanGPA\.exe", re.IGNORECASE)),
    ("OpenVPN",
     re.compile(r"OpenVPN\s+TAP-Win|TAP-Windows", re.IGNORECASE),
     re.compile(r"OpenVPN", re.IGNORECASE),
     re.compile(r"openvpn\.exe|openvpn-gui\.exe", re.IGNORECASE)),
    ("Pulse Secure / Ivanti Secure Access",
     re.compile(r"Pulse\s+Secure|Ivanti\s+Secure\s+Access|JuniperNetworks",
                re.IGNORECASE),
     re.compile(r"Pulse\s+Secure|Ivanti", re.IGNORECASE),
     re.compile(r"PulseSecure\.exe|jamCommand\.exe", re.IGNORECASE)),
    ("WireGuard",
     re.compile(r"WireGuard\s+Tunnel|wg\d+", re.IGNORECASE),
     re.compile(r"WireGuard", re.IGNORECASE),
     re.compile(r"wireguard\.exe|wg\.exe", re.IGNORECASE)),
    ("Check Point Endpoint Security VPN",
     re.compile(r"Check\s+Point|TrCAPI", re.IGNORECASE),
     re.compile(r"Check\s+Point", re.IGNORECASE),
     re.compile(r"TrGUI\.exe|TrAC\.exe", re.IGNORECASE)),
    # Phase 53c (2026-06-26): Mac-modern VPN clients seen running
    # alongside ZCC in the Example Tenant G (user-c@) bundles. WARP
    # specifically claims the system-wide DNS resolver on Mac which is
    # the same path ZCC uses for split-DNS — collision is observable
    # in production.
    ("Cloudflare WARP",
     re.compile(r"Cloudflare\s+WARP|warp-svc|warp-cli", re.IGNORECASE),
     re.compile(r"Cloudflare\s+WARP", re.IGNORECASE),
     re.compile(r"warp-svc|warp-cli|CloudflareWARP", re.IGNORECASE)),
    ("NordVPN",
     re.compile(r"NordVPN|nordlynx", re.IGNORECASE),
     re.compile(r"NordVPN", re.IGNORECASE),
     re.compile(r"nordvpn|nordlynx", re.IGNORECASE)),
    ("ExpressVPN",
     re.compile(r"ExpressVPN", re.IGNORECASE),
     re.compile(r"ExpressVPN", re.IGNORECASE),
     re.compile(r"expressvpnd|ExpressVPN", re.IGNORECASE)),
    ("ProtonVPN",
     re.compile(r"ProtonVPN", re.IGNORECASE),
     re.compile(r"ProtonVPN", re.IGNORECASE),
     re.compile(r"ProtonVPN|protonvpn", re.IGNORECASE)),
    ("Tailscale",
     re.compile(r"Tailscale", re.IGNORECASE),
     re.compile(r"Tailscale", re.IGNORECASE),
     re.compile(r"tailscaled|Tailscale", re.IGNORECASE)),
    ("Twingate",
     re.compile(r"Twingate", re.IGNORECASE),
     re.compile(r"Twingate", re.IGNORECASE),
     re.compile(r"twingate|Twingate", re.IGNORECASE)),
    ("Mullvad VPN",
     re.compile(r"Mullvad", re.IGNORECASE),
     re.compile(r"Mullvad", re.IGNORECASE),
     re.compile(r"mullvad-daemon|MullvadVPN", re.IGNORECASE)),
]


EVIDENCE_CAP = 5


# --- Detector ---------------------------------------------------------

@register
class VpnCoexistenceDetector(IssueDetector):
    id = "vpn_coexistence"
    title = "3rd-party VPN client coexistence"
    sop_file = ""
    # Cross-suite: 3rd-party VPN coexistence affects ZIA + ZPA equally.
    applies_to_suite = None

    # Cross-platform.
    applies_to_os = None

    # Per-record feed is rare — most signal comes from
    # summary.firewall_rules_zscaler + apps_installed which we
    # check in finalize(). Pre-match keeps the per-record work
    # bounded.
    prematch_substrings = ("VPN", "vpn", "AnyConnect", "FortiClient",
                           "GlobalProtect", "OpenVPN", "Pulse",
                           "WireGuard", "vpnagent", "WARP", "Cloudflare",
                           "Tailscale", "Twingate", "NordVPN", "Proton",
                           "Mullvad")

    def __init__(self) -> None:
        super().__init__()
        # Per-vendor evidence list (any tunnel-log mention).
        self._vendor_log_mentions: dict = {}

    def feed(self, record: LogLine, summary: BundleSummary) -> None:
        msg = record.message
        for name, _adapter_re, _app_re, proc_re in _VPN_VENDORS:
            if proc_re.search(msg):
                self._vendor_log_mentions.setdefault(name, []).append(record)
                # Cap evidence per vendor so a noisy log doesn't blow
                # memory.
                if len(self._vendor_log_mentions[name]) > EVIDENCE_CAP:
                    self._vendor_log_mentions[name].pop()

    def finalize(self, summary: BundleSummary) -> List[Finding]:
        seen_vendors: dict = {}  # name -> source list

        # 1. NIC-adapter pattern match. AppInfo.xml carries the
        # NIC list including third-party VPN virtual adapters.
        nic_text = ""
        try:
            for entry in (summary.bundle_meta or {}).get(
                "appinfo_text", ""
            ):
                nic_text += entry
        except Exception:
            pass
        # Bundle_meta might not carry the raw text; fall back to
        # the firewall-rules + apps_installed lists (which we DO
        # know are populated).

        # 2. apps_installed cross-reference
        apps = getattr(summary, "apps_installed", None) or []
        for app in apps:
            app_name = getattr(app, "name", "") or ""
            for name, _adapter_re, app_re, _proc_re in _VPN_VENDORS:
                if app_re.search(app_name):
                    sources = seen_vendors.setdefault(name, [])
                    if "apps_installed" not in sources:
                        sources.append("apps_installed")

        # 3. Tunnel-log mentions (captured in feed())
        for name, recs in self._vendor_log_mentions.items():
            sources = seen_vendors.setdefault(name, [])
            if recs and "tunnel_log_mentions" not in sources:
                sources.append("tunnel_log_mentions")

        # 4. Phase 53c (2026-06-26): Mac AppInfo.log <key>Process List</key>
        # scan. context_builder stashes the raw AppInfo.log content
        # under bundle_meta["mac_appinfo_text"]; if it isn't present
        # (e.g., on Windows or older bundles) this step degrades to a
        # no-op. Detecting Cloudflare WARP, Tailscale, etc on Mac
        # specifically required this because they don't surface in
        # summary.apps_installed and don't write to ZCC tunnel logs.
        mac_appinfo_text = (
            (summary.bundle_meta or {}).get("mac_appinfo_text") or ""
        )
        if mac_appinfo_text:
            # Look for the Process List block. It's a multi-line plist
            # string field — we grep the whole text since the markers
            # we care about appear inside.
            for name, _adapter_re, app_re, proc_re in _VPN_VENDORS:
                if proc_re.search(mac_appinfo_text) or app_re.search(
                    mac_appinfo_text
                ):
                    sources = seen_vendors.setdefault(name, [])
                    if "mac_process_list" not in sources:
                        sources.append("mac_process_list")

        # Fire findings per vendor.
        out = []
        for name, sources in seen_vendors.items():
            safe = re.sub(r"[^A-Za-z0-9_]", "_", name)
            sev = (
                Severity.WARNING
                if "tunnel_log_mentions" in sources
                else Severity.INFO
            )
            sources_str = ", ".join(sources)
            f = self._bucket(
                f"VPN_COEXISTENCE::{safe}",
                sev,
                f"{name} also installed alongside ZCC",
                f"This machine has both ZCC and {name} installed "
                f"(sources: {sources_str}). When two VPN clients "
                f"are active simultaneously, the adapter routing "
                f"table fights between them, which manifests as "
                f"NIC LUID flap (see the `adapter_instability` "
                f"detector if it also fires). Recommended: confirm "
                f"with the customer whether {name} is actively used "
                f"or just installed-and-forgotten; if active, "
                f"coordinate a connect-order policy (typically: "
                f"ZCC first, then {name} for legacy app access).",
                sop_anchor=None,
            )
            # Attach log-mention evidence if any
            for rec in self._vendor_log_mentions.get(name, []):
                f.add_evidence(rec, cap=EVIDENCE_CAP)
            out.append(f)
        return out
