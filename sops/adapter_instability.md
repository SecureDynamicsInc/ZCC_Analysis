# SOP: Network adapter / NIC instability

Fires when the host's NICs are repeatedly being added, removed, or reassigned during the bundle window, causing ZCC to re-discover gateways and re-apply its traffic-forwarding chain over and over. Typical of machines running a 3rd-party VPN client, Hyper-V / WSL2 / Docker, a flaky docking station, or rapidly roaming between WiFi APs.

This runbook uses generic ZCC adapter and gateway error signatures. It contains
no retained customer case, filename, timestamp, device version, or event counts.

## #adapter-instability

The detector counts four independent signals:

| Signal | What it means | WARN at | CRIT at |
|---|---|---:|---:|
| `ConvertInterfaceLuidToAlias` failures | Windows IP-helper API was asked to resolve a LUID that no longer maps to a known adapter | 30 | 100 |
| `Failed to parse NP tunnel ip` | NetworkProvider tunnel IP couldn't be assigned (adapter not in expected state) | 3 | 10 |
| `Default Interface Gateway` ERR records | Gateway re-discovery (gets logged as ERROR even though it's informational) | 20 | 35 |
| `WTSQuerySessionInformation` failures | User-session lookup failed (often due to RDP/console session changes) | 5 | 20 |

Any single signal crossing CRIT raises the finding to CRITICAL severity. Otherwise any single signal crossing WARN raises WARNING.

## Why this matters

Each adapter event causes ZCC to redo its traffic-forwarding setup. That cascades into:
- ZTUI service bus failures (tray UI can't reach the service while the service is busy reconfiguring)
- LWF filter reconfiguration churn
- DTLS-to-TLS fallback (the UDP socket gets torn down and rebuilt)
- Brief tunnel-state flaps

If you triage a bundle and see those secondary symptoms *together with* the LUID/NP-tunnel/gateway-change counts above, the adapter churn is almost certainly the root cause and the others are downstream.

## Common causes (most → least common)

1. **3rd-party VPN client coexistence.** GlobalProtect, Cisco AnyConnect, OpenVPN, NordVPN, ExpressVPN, Pulse Secure, etc. When the other VPN engages or disengages, it tears down and recreates virtual NICs. ZCC sees that as adapter instability and reacts.
2. **Hyper-V / WSL2 / Docker Desktop.** These create and destroy virtual network switches as containers and VMs start/stop. WSL2 in particular spins its switch up/down at boot.
3. **Docking station / USB-Ethernet adapter** with a flaky cable or driver. Especially common on Dell / Lenovo dock stacks where the driver version on the dock and the laptop disagree.
4. **Rapid WiFi roaming.** In a dense-AP environment (large office, conference center) the laptop may be switching SSIDs every few minutes.
5. **Power-management / sleep-wake cycles.** Older laptops with aggressive power management may aggressively park and re-energize the WiFi NIC.

## Triage steps

### 1. Look at the user's installed software

```powershell
Get-WmiObject -Class Win32_Product | Where-Object {
    $_.Name -match 'vpn|globalprotect|anyconnect|openvpn|nord|cisco|fortinet|paloalto'
} | Select-Object Name, Version
```

If found, that's almost certainly the culprit. ZCC and a 3rd-party VPN can coexist but they need ZCC's VPN-trusted forwarding profile set correctly.

### 2. Check for virtualization layers

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
# Docker check:
Get-Service docker 2>$null
```

If any are enabled, look at the user's "Network Connections" panel for adapters named `vEthernet (*)`. Those flap whenever the underlying VM/container starts and stops.

### 3. Look at the bundle's `mtuForZadapter` value

The forwarding-profile field `mtuForZadapter` defaults to `0` (auto). If it's set explicitly to something like `1240`, the policy was pushed to compensate for a known underlay (typical of a VPN-inside-ZCC topology). That's a strong signal that the customer's admin knows there's another VPN in play.

### 4. Identify the unstable adapter

```powershell
Get-NetAdapter | Sort-Object -Property MediaConnectionState | Format-Table Name, Status, MediaConnectionState, InterfaceDescription
```

Look for adapters in `Disconnected` or `Disabled` state and for any adapters whose `MediaConnectionState` keeps flipping (you can also use Performance Monitor → `Network Interface` counters).

### 5. Event Viewer trace

```
Get-WinEvent -LogName 'Microsoft-Windows-NDISGB/Operational' -MaxEvents 200
Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational' -MaxEvents 200
```

These will show adapter add/remove/change events from the OS side, time-aligned with the ZCC log evidence.

### Fix options

- **Remove the 3rd-party VPN client** if it's not actively being used. Cleanest fix.
- **Configure ZCC's VPN-trusted forwarding profile** for coexistence. Document the IP ranges the other VPN uses; configure ZCC to bypass them.
- **Disable WSL2's auto-start** of its virtual switch, or limit Hyper-V vSwitches to "internal" only when not actively used.
- **Replace the dock / USB-Ethernet adapter** if it's the source of the churn. Drivers from the vendor's most recent release pack often help.
- **Upgrade ZCC** to the latest GA — recent versions (4.8+) are much more resilient to adapter churn than 4.7 was. Many of the LUID-handling cases got rewritten to fail gracefully instead of logging at ERROR level.

## What this detector does NOT catch

- **Pure WiFi quality issues** (RSSI, retransmits) without adapter add/remove events. Use ZDX or `netsh wlan show interface` for that.
- **DNS-resolution churn** caused by an unstable DNS server (not by adapter change). The `tunnel_not_established` detector catches some of that path.
- **VPN client driver crashes** that take down the adapter only once and don't recover. Those show as a single LUID error, not a sustained pattern.

If the detector fires but you can't find the cause via the steps above, post the bundle + a Process Monitor trace of `network.exe` / the suspect VPN client's process during a 60-second window to the support thread.
