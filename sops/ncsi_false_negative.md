# SOP: Windows "no internet" icon — NCSI false-negative

This document covers the Windows yellow-triangle "no internet" icon
that appears even though the VPN tunnel is up and other traffic
works. Detected by `zcc_diag/issues/ncsi_false_negative.py`.

The root cause is Zscaler SSL interception corrupting the response
to Windows' NCSI (Network Connectivity Status Indicator) probe.
Windows' API `IsNetworkAvailable()` returns False; apps that gate
behaviour on that API (Outlook, Teams, Mimecast Sync, etc.) then
refuse to operate normally.

Detection grounded in:
- an anonymized internal case (Example Tenant O "Windows No Internet Issue").
  Zoom AI summary observed: *"Windows systems show 'no internet
  connection' warnings despite VPN connectivity being active...
  tools like Mimecast and Global Secure Access are affected by these
  false internet connection alerts, which occur when Windows checks
  for internet connectivity."*
- an anonymized internal case (Example Tenant O User F capture, same root
  cause). Mimecast IP range `216.145.216.0/24` SSL handshake failing
  through ZIA's split-tunnel configuration.

This detector is Windows-only (`applies_to_os = ("windows",)`)
because NCSI is a Windows feature. Mac and Linux have separate
captive-portal-style probes; if those start showing similar issues,
a sibling detector will be needed.

---

## Windows NCSI probe response was inspected by ZCC
<a id="ncsi-probe-ssl-fail"></a>

**Detected when:** an SSL handshake / cert validation failure fires
on a tunnel-log thread whose most recent `Host=...` line names one
of: `www.msftncsi.com`, `dns.msftncsi.com`,
`www.msftconnecttest.com`, `clients3.google.com`,
`connectivitycheck.gstatic.com`, or `captive.apple.com`.

**What it means:** Windows is probing for internet connectivity.
ZCC's SSL inspection is intercepting the probe and altering the
response in a way Windows can't validate. Windows declares "no
internet."

**Triage steps:**

1. In the ZIA admin console, find the URL category `Microsoft NCSI`
   (built-in). Add it to the customer's BLSSL bypass list, OR if
   the customer doesn't do full SSL inspection, add it to the
   URL-filtering bypass.
2. If the built-in category isn't available in the customer's
   ZIA tenant version, add the hostnames manually:
   - `*.msftncsi.com`
   - `*.msftconnecttest.com`
   - `clients3.google.com`
   - `connectivitycheck.gstatic.com`
   - `captive.apple.com`
3. Push policy. Have the user restart Network Connections (Settings
   → Network → ipconfig /release && ipconfig /renew) or simply
   restart Windows. The yellow triangle should disappear within
   30-60 seconds.
4. Confirm `IsNetworkAvailable()` returns True via PowerShell:
   ```powershell
   [Microsoft.Win32.SystemEvents].GetMethod("CheckNetworkAvailability") `
       | foreach { $_.Invoke($null, $null) }
   ```
   Or simpler: just check the system-tray network icon.

**Operator workflow:**
- This SOP fires often as a follow-up to broader bypass-policy
  audits. If you're already fixing a customer's bypass list, sweep
  the NCSI category into the same change so users stop calling in.

---

## Mimecast endpoint hit by SSL inspection
<a id="mimecast-ssl-fail"></a>

**Detected when:** an SSL handshake failure hits a destination IP in
the Mimecast secure-email-gateway range (`216.145.216.0/24`,
`216.145.217.0/24`, `216.145.218.0/24`, `194.180.157.0/24`).

**What it means:** Mimecast publishes its egress IP ranges and pins
its cert. When ZCC inspects traffic flowing through Mimecast, the
handshake breaks. This pattern was the observed root cause of the
Example Tenant O NCSI ticket — Mimecast's response corruption cascaded into the
NCSI false-negative.

**Triage steps:**

1. Pull the current Mimecast IP list from
   `https://community.mimecast.com` (search "Mimecast IP ranges").
   The IPs change occasionally; don't hardcode the detector's
   hint as the source of truth.
2. Add the IP ranges to the customer's BLSSL bypass with the
   `Mimecast Cloud` cloud-app category if available.
3. If the customer uses Mimecast Sync (the Outlook plugin), also
   bypass `*.mimecast.com` to cover the management plane.
4. Have the user resync their Outlook / Mimecast client and
   confirm mail flow.

**Operator workflow:**
- Pair this fix with the NCSI fix above when both detectors fire
  on the same bundle — they tend to co-occur.
