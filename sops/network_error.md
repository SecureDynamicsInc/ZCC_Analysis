# SOP: Network Error (-8)

This document covers ZCC Network Error failures detected by
`zcc_diag/issues/network_error.py`.

The user-facing tray status string this maps to:

  * **Network Connection Failed -8** -- ZCC's keepalive request to a
    critical Zscaler auth/policy host failed at the network layer.

Detection grounded in the official Zscaler ZCC Traffic Forwarding
Troubleshooting Runbook (Network Error section). Signatures
live in **ZSATray / ZSATrayManager** logs, not ZSATunnel.

> **Calibration notes.**
> 1. The runbook quotes an older log format with `#NORMAL #ERROR :`
>    markers. Real bundles use the standard Format A and embed the
>    same `errorMessage` JSON field. The detector matches the JSON
>    content, not the line format.
> 2. The runbook's bare `error:-8` integer is too narrow -- doesn't
>    appear in any of the three real bundles. The detector matches on
>    the runbook's specific errorMessage CATEGORY phrases instead.
> 3. Real bundles contain non-empty `errorMessage` values that aren't
>    network errors (`"Invalid user/password"` is auth,
>    `"No ZCC update available"` is informational). The detector
>    specifically avoids these by matching only the documented
>    network-error categories.

The runbook documents three critical hosts that ZCC keepalives hit:
  * `mobile.zscaler.net`
  * `login.<cloud_name>.net`
  * `mobile.<cloud_name>.net`

Each H2 below is anchored on a finding code emitted by the detector.

---

## DNS resolution failure
<a id="neterr-host-not-found"></a>

**Detected when:** tray log contains `"errorMessage":"Host not found`.

**What it means:** ZCC's tray cannot resolve the Zscaler host's name
to an IP. DNS is broken or the hostname is being filtered.

**Triage steps (documented from runbook):**

1. **Test DNS resolution manually:**
   ```
   nslookup mobile.zscaler.net
   nslookup login.<cloud_name>.net
   nslookup mobile.<cloud_name>.net
   ```
   If these fail, DNS is the problem.

2. **Try alternate DNS** (Google `8.8.8.8` / `8.8.4.4`). If alternate
   DNS resolves successfully, the configured DNS server is selectively
   blocking Zscaler hostnames or is just broken.

3. **Check the hosts file** for custom entries:
   `C:\Windows\System32\drivers\etc\hosts`
   Per the runbook: if the resolved IP isn't in the Zscaler hub IP
   range, check this file for stale or malicious overrides.

4. **Disable IPv6 on the network adapter** if `nslookup` returns IPv6
   addresses but the adapter is v4-only. ZCC may attempt v6 first and
   fail before falling back.

5. **Disable VPN / endpoint security temporarily** (with admin
   approval). A third-party VPN client can capture DNS queries to
   its own resolver, and an EDR product can block DNS to specific
   hostnames.

---

## Connection reset by peer
<a id="neterr-connection-reset"></a>

**Detected when:** tray log contains `"errorMessage":"Connection
reset by peer`.

**What it means:** DNS resolved successfully and a TCP handshake
started, but a device along the path forcibly closed the connection
(sent a TCP RST).

**Triage:**

1. **Identify what's resetting.** From the affected client, run a
   packet capture:
   ```powershell
   netsh trace start scenario=NetConnection capture=yes tracefile=C:\Temp\zcc-net.etl
   ```
   Reproduce the failure, then `netsh trace stop`. Open the trace in
   Microsoft Network Monitor / Wireshark and look for the TCP RST
   on TCP/443 to a Zscaler host.

2. **Common culprits:**
   * TLS-inspecting proxies that drop unknown TLS handshakes
   * Stateful firewalls timing out long-lived connections
   * Load balancers cycling backends
   * Aggressive intrusion-prevention systems

3. **If the reset is from a corporate device,** add Zscaler hub IPs
   to its bypass list. Zscaler publishes the hub IPs at
   `https://config.zscaler.com/<cloud_name>/hubs`.

---

## No route to host
<a id="neterr-no-route"></a>

**Detected when:** tray log contains `"errorMessage":"Net Exception.
No route to host`.

**What it means:** the OS routing table has no path that can reach
the Zscaler host's IP.

**Triage:**

1. **Check routing:**
   ```powershell
   route print
   Find-NetRoute -RemoteIPAddress <resolved-ip-of-mobile.zscaler.net>
   ```
   The `InterfaceAlias` field should show Wi-Fi / Ethernet, not a
   third-party VPN adapter.

2. **If a VPN adapter is capturing the route:** add a route exclusion
   for the Zscaler hub IP ranges from the VPN configuration.

3. **Wrong default gateway:** if a recent network change (DHCP
   reconnect, static-IP override) left the wrong gateway, the route
   to the public Internet is broken.

---

## Network is unreachable
<a id="neterr-net-unreachable"></a>

**Detected when:** tray log contains `"errorMessage":"Net Exception.
Network is unreachable`.

**What it means:** the client has no network connectivity at all --
adapter is down, DHCP lease missing, or no link layer.

**Triage:**

1. `ipconfig /all` -- confirm an active adapter has a valid IP and
   gateway.
2. Power-cycle the adapter (`Disable-NetAdapter` /
   `Enable-NetAdapter`).
3. If consistent across reboots, the network interface or driver
   itself may be the issue -- distinct from any ZCC problem.

---

## Certificate validation error (SSL interception)
<a id="neterr-cert-validation"></a>

**Detected when:** tray log contains `"errorMessage":"Certificate
validation error`.

**What it means:** the TLS certificate presented by the Zscaler host
failed validation in the tray's HTTP client. Per the runbook, this
is the canonical signature of a TLS-inspecting proxy (corporate
firewall / web security gateway) substituting its own certificate.

**Triage:**

1. **Cross-reference the tunnel detector.** If
   `SSL_INTERCEPTION_DETECTED` also fired (matching
   `Auth::Lib::certificateErroCallback: Invalid certificate`), the
   same MITM is affecting both ZSATunnel and the tray. That's strong
   confirmation.

2. **Bypass SSL inspection on Zscaler IP ranges** in the corporate
   firewall / web security gateway. Zscaler publishes the hub IPs at
   `https://config.zscaler.com/<cloud_name>/hubs`.

3. **Specifically allow direct (un-inspected) traffic to:**
   * `mobile.zscaler.net`
   * `gateway.<cloud_name>.net`
   * `mobile.<cloud_name>.net`
   * `login.<cloud_name>.net`
   * `pac.<cloud_name>.net`

4. **Don't install the corporate proxy CA into ZCC's trust store** as
   a workaround -- this defeats the cert-pinning protection Zscaler
   relies on.

5. **Check device clock skew.** Per Zscaler community guidance
   (documented: *"a skewed system clock can cause certificate
   validation to fail, so device time should be correct and set to
   automatic"*), >5-min skew between the device and an upstream
   NTP source can cause cert validation to fail because the JWT /
   X.509 `notBefore` / `notAfter` checks reject the cert as
   either not-yet-valid or already-expired. Verify on the affected
   machine:

   ```
   # Windows
   w32tm /query /status

   # macOS
   sntp -s time.apple.com

   # Linux
   timedatectl status
   ```

   If skew > 5 minutes, fix NTP sync first — this is an easy class
   of false-positive cert errors that has nothing to do with
   inspection or SSL config.

---

## SSL exception
<a id="neterr-ssl-exception"></a>

**Detected when:** tray log contains `"errorMessage":"SSL Exception`.

**What it means:** the TLS handshake itself failed -- typically with
``certificate verify failed`` further in the message. Same root cause
family as `NETERR_CERT_VALIDATION` above; treated as a separate
finding because the runbook explicitly distinguishes them.

**Triage:** same as
[Certificate validation error](#neterr-cert-validation).

---

## See also

* `tunnel_not_established.md` -- companion detector. The
  `SSL_INTERCEPTION_DETECTED` finding there matches a similar TLS
  interception signature in ZSATunnel's auth path. If both fire, you
  have strong cross-validation that a TLS-inspecting middlebox is in
  the path.
* `_runbook_signatures.md` (in `zcc_diag/issues/`) -- the structured
  reference covering all five Network Error categories side by side.
* The Errors documentation, Connection Status Errors table -- documents the
  user-facing Network Error tray string.
* The ZCC Traffic Forwarding Runbook, Network Error section
  (p.27-30).
