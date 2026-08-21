# SOP: Tunnel not established / Network Error

This document covers issue #2 in the user spec --
"Traffic forwarding / tunnel not established (Network Error)" -- detected
by `zcc_diag/issues/tunnel_not_established.py`.

The user-facing tray strings this maps to (per the Zscaler "Client
Connector Errors" documentation, Connection Status Errors table):

  * **Connection Error** -- "The Public Service Edge for Internet & SaaS
    cannot be reached."
  * **Network Error** -- "No network interface is detected."
  * **Server Error** -- "Zscaler Client Connector is unable to connect
    to the ZDX cloud."
  * **Driver Error** -- TAP/TUN/LWF won't load.
  * **Endpoint FW/AV Error** -- ZCC's loopback connection blocked.
    (Also detected by issue #3 when that detector ships.)

Each H2 below is anchored on a finding code emitted by the detector.

---

## SERVER_DOWN_ERROR
<a id="server-down-error"></a>

**Detected when:** ZIA or ZPA proxy state transitioned into
`SERVER_DOWN_ERROR`, or the `zcc_zia_server_down_error` /
`zcc_zpa_server_down_error` zEvent fired.

**What it means:** the Public Service Edge (ZIA) or broker (ZPA) is
unreachable. Per the documentation: "Service is in Server Down Error state.
Zscaler Client Connector is not able to reach the Public Service Edge
for Internet & SaaS or Public Service Edge for Private Access."

**Triage steps:**

1. From the bundle summary, note the `service_edges` and the resolved IPs
   for `gateway.<cloud>.net` and `mobile.<cloud>.net`.
2. From an unaffected client on the same network, run:
   ```
   curl -v https://mobile.<cloud>.net:443/
   curl -v https://gateway.<cloud>.net:443/zcc_conn_test
   ```
3. If both fail: a corporate firewall, DNS, or upstream is blocking
   ZCC's egress.
4. If both succeed from another client: the affected client has a local
   issue (host firewall, AV, VPN conflict).
5. Check the `Tunnel Version` in the forwarding profile. If `Tunnel v2`
   (DTLS over UDP), confirm UDP/443 is allowed outbound. Some
   firewalls only permit TCP/443.

---

## ADAPTER_DOWN_ERROR
<a id="adapter-down-error"></a>

**Detected when:** ZIA or ZPA state transitioned into
`ADAPTER_DOWN_ERROR`.

**What it means:** ZCC can't find an adapter with a default route. Per
the documentation: "This error may appear due to DHCP renewal."

**Triage steps:**

1. Run `ipconfig /all` on the affected machine and check the
   "Lease Obtained" timestamp on the active adapter.
2. If the lease-obtained time matches the error timestamp, this is a
   transient and likely benign.
3. Sustained `ADAPTER_DOWN_ERROR` (>1 minute) after DHCP completed:
   the Z-tunnel virtual adapter itself is missing or disabled.
4. Open Device Manager → Network adapters → look for "Zscaler" entries.
   If missing, the driver was removed or never installed -- run the
   ZCC tray's **Repair App** option, or reinstall ZCC.

---

## INTERNET_UNREACHABLE_ERROR
<a id="internet-unreachable"></a>

**Detected when:** state transitioned into `INTERNET_UNREACHABLE_ERROR`.

**What it means:** per the documentation: "Network appears to be connected but
Private Access is not able to resolve the broker name."

**Triage steps:**

1. From the affected client, `nslookup gateway.<cloud>.net`. If
   resolution fails, DNS is the problem.
2. Check the system DNS server — corporate DNS may be selectively
   blocking Zscaler hostnames.
3. Verify there's no captive portal (issue #4).

---

## SERVICE_DOWN_ERROR
<a id="service-down-error"></a>

**Detected when:** state transitioned into `SERVICE_DOWN_ERROR`.

**What it means:** one of ZCC's microservices is not operational.

**Triage steps:**

1. `services.msc` → confirm `ZSAService` is in Running state.
2. If Stopped, check Event Viewer → Windows Logs → Application for crash
   entries near the failure timestamp.
3. Restart the service. If it crashes again, capture a fresh bundle and
   escalate (likely a ZCC bug or AV interference).

---

## SYSTEM_SOCKETS_EXHAUSTED_ERROR
<a id="sockets-exhausted"></a>

**Detected when:** state transitioned into
`SYSTEM_SOCKETS_EXHAUSTED_ERROR`.

**What it means:** the OS socket limit has been reached. Per the documentation:
"System's limit for maximum sockets has reached."

**Triage steps:**

1. `netstat -ano | wc -l` to confirm socket count.
2. Identify the culprit process via netstat output -- usually a leaking
   client app (browsers with thousands of tabs, malformed updaters).
3. Reboot is the fastest fix; long-term, fix the leaking app.

---

## DRIVER_ERROR
<a id="driver-error"></a>

**Detected when:** state transitioned into `DRIVER_ERROR`.

**What it means:** ZCC can't load the network driver (TAP/TUN/LWF).

**Triage steps:**

1. Use **Repair App** in the ZCC tray (More → Troubleshoot → Repair App).
2. If repair fails, uninstall ZCC, reboot, reinstall.
3. On Windows, check Driver Verifier hasn't flagged any Zscaler driver.

---

## FIREWALL_BLOCK_ERROR
<a id="firewall-block"></a>

**Moved.** `FIREWALL_BLOCK_ERROR` is now owned by the
`endpoint_fw_av` detector. See `endpoint_fw_av.md`
(`#firewall-block-error-state` anchor) for triage.

The anchor here is preserved so old links don't break.

---

## ZPA_UNTRUSTED_SERVER_CERT_ERROR
<a id="zpa-untrusted-cert"></a>

**Detected when:** ZPA state transitioned into
`ZPA_UNTRUSTED_SERVER_CERT_ERROR`.

**What it means:** ZPA-specific. Per the documentation: "Private Access connection
got an SSL exception while connecting." The Private Service Edge
certificate failed validation.

**Triage steps:**

1. Most common cause: a TLS-inspecting proxy is in the path,
   substituting its own cert. Verify the corporate firewall / web
   security gateway has Zscaler hostnames on its inspection bypass.
2. Less common: the system trust store is missing the CA that signs
   the Private Service Edge. Run Windows Update; verify root cert
   updates are not blocked.

---

## Tunnel bad-state generic
<a id="tunnel-bad-state-generic"></a>

**Detected when:** state transitioned into a non-healthy state not
covered by the named sections above.

**Triage:** capture a fresh bundle. Look at the exact state name in the
finding evidence and cross-reference the Zscaler "Client Connector
Errors" documentation Windows Registry Keys section for the canonical meaning.

---

## Local network down
<a id="local-network-down"></a>

**Detected when:** ZCC logs `Skipping zpn socket reconnect as network
is down`.

**What it means:** the local network stack is down. Common during:

  * Sleep / wake transitions (laptop closed and reopened)
  * Wi-Fi roaming between APs
  * VPN connect / disconnect
  * Actual link drop (cable unplugged, Wi-Fi out of range)

Single events are usually benign. Clusters point at flaky NIC, Wi-Fi
roaming, or VPN conflicts.

**Triage:**

1. If only one or two events, ignore.
2. If a stream of these in a short window, check
   `Get-NetAdapter | ft Name,Status,LinkSpeed` history (Windows event
   logs `Microsoft-Windows-NetworkProfile/Operational`).
3. Confirm any third-party VPN client isn't fighting ZCC for the
   default route.

---

## SSL/TLS interception detected
<a id="ssl-interception-detected"></a>

**Detected when:** the log line
`Auth::Lib::certificateErroCallback: Invalid certificate` appears.
(The documented typo `Erro` is from ZCC's source code.)

**What it means:** ZCC's auth layer tried to validate the server
certificate from the Zscaler service edge and the validation failed.
Per the ZCC Traffic Forwarding runbook (Connection Error section),
this is the canonical signature of a TLS-inspecting proxy in the
path -- a corporate firewall / web security gateway is intercepting
HTTPS, presenting its own certificate, and ZCC correctly refuses to
trust it.

The runbook pairs this with a preceding
`ZST2M::ZT2A::initialize: Data Channel establishment Failed.` line.
We don't require the pair because that line ALSO appears in normal
DTLS-to-TLS fallback (already detected via the
`zcc_t2_dtls_to_tls_fallback` zEvent). The
`certificateErroCallback` line is the differentiator and unique to
SSL-inspection scenarios.

**Triage:**

1. Identify the corporate firewall / web security gateway that's
   doing TLS inspection (ask the network team, or check
   `summary.cert_expiries` -- intercepted TLS shows the proxy's CA
   in the chain).
2. **Bypass SSL inspection on Zscaler IP ranges.** Zscaler publishes
   the hub IP ranges at
   `https://config.zscaler.com/<cloud_name>/hubs`. The proxy / WAF
   should be configured to **not inspect** any traffic to these IPs.
3. Specifically allow direct traffic to:
   * `gateway.<cloud_name>.net`
   * `pac.<cloud_name>.net`
   * `mobile.<cloud_name>.net`
   * `login.<cloud_name>.net`
4. If bypass isn't possible, install the corporate proxy's CA into
   ZCC's trust store -- but this is *not recommended* by Zscaler
   because it weakens the cert-pinning protection.

---

## Z-Tunnel 2.0 fell back to Z-Tunnel 1.0
<a id="t2-fallback-to-t1"></a>

**Detected when:** the log line
`SME List is empty. Fallback to ZTunnel 1.0` appears.

**What it means:** ZCC could not establish *any* SME (Service Edge
Mobile) connection for Z-Tunnel 2.0 and fell back to Z-Tunnel 1.0
entirely. **This is a HARD fallback** -- distinct from the routine
intra-T2 DTLS-to-TLS fallback (where T2 stays active but switches
its data-channel transport).

**Why this is critical:** Z-Tunnel 1.0 only intercepts web traffic
(HTTP/HTTPS via PAC). Non-web traffic (SSH, RDP, raw TCP, UDP) now
**bypasses Zscaler entirely** -- it goes direct from the host. That
defeats the security model.

Per the ZCC Traffic Forwarding runbook, this is usually preceded by
something like
`INF ZSCCM::ACTIVE::startConnection: Failure#:0 Exception:Timeout: connect timed out: <ip>:443`
indicating sustained connect-timeouts to all SMEs in the PAC file.

**Triage:**

1. **Verify PAC file SME list.** Check `summary.pac` for the proxy
   list ZCC is using. If empty or pointing at unreachable IPs,
   that's the immediate problem.
2. **Test connectivity from the host** to each SME IP on TCP/443.
   If all fail: outbound firewall block, ISP issue, or DNS
   misdirection.
3. **Specifically test UDP/443** -- T2 can use DTLS over UDP/443 as
   primary transport. If UDP/443 is blocked, T2 may try TLS-over-TCP
   first and only fall back to T1 if BOTH fail.
4. **Force T1 explicitly** as a workaround: in the forwarding
   profile, set Z-Tunnel mode to 1.0 to avoid the failed-T2
   negotiation cycle on every connection. Treat this as a temporary
   measure while the upstream is fixed.

---

## SME failure count
<a id="sme-failure-count"></a>

**Detected when:** the `incrementSMEFailureCount` log line reports a
count >= 3.

**What it means:** ZCC tracks consecutive failures to reach the
ZIA Service Edge. >= 3 = warning; >= 5 = critical. A sustained high
count means the chosen edge is unreachable.

**Triage steps:**

1. Verify `service_edges` in the bundle summary -- which edge IPs were
   resolved.
2. Test outbound connectivity to those IPs on TCP/UDP 443 from the
   affected client.
3. If the edge is reachable, check whether ZCC selected an edge in a
   far geo (sub-optimal selection -- forces failover noise).

---

## State flap up (informational)
<a id="state-flap-up"></a>

**Detected when:** `zcc_zia_state_flap_up` or `zcc_zpa_state_flap_up`
fired.

**Severity:** INFO. Recovery event; ZCC's state returned to healthy.

**Use this section to:** correlate timestamps with whatever error
preceded the recovery. The finding's `time_range` shows when the flap
events fired.

---

## Network Error zEvent
<a id="network-error-zevent"></a>

**Detected when:** `zcc_zia_network_error` or `zcc_zpa_network_error`
fired.

**Maps to the user-facing "Network Error" tray status.**

Per the documentation: "No network interface is detected." Triage same as
`local-network-down` plus a check for adapter-level failures
(`ADAPTER_DOWN_ERROR`).

---

## Connection failed zEvent
<a id="connection-failed-zevent"></a>

**Detected when:** `zcc_zia_connection_failed` or
`zcc_zpa_connection_failed` fired.

**Maps to the user-facing "Connection Error" tray status.**

Per the documentation: "The Public Service Edge for Internet & SaaS cannot be
reached." Triage same as `server-down-error`.

---

## Tunnel-2 DTLS to TLS fallback
<a id="t2-dtls-fallback"></a>

**Detected when:** `zcc_t2_dtls_to_tls_fallback` fired.

**What it means:** ZCC tried to bring up Tunnel v2 (DTLS over UDP/443)
and failed, so it fell back to Tunnel v1 (TLS over TCP/443).

**Connection still works** -- but throughput typically halves and
latency rises. This is the canonical issue #5 (performance) precursor.

**Triage steps:**

1. Check whether UDP/443 outbound is allowed by the corporate firewall.
   Many "trust no UDP" firewalls force this fallback permanently.
2. If UDP/443 is allowed, check path-MTU. DTLS handshakes are large
   packets -- MTU < 1280 may cause silent fragmentation drops.
3. If neither: capture a packet trace on UDP/443 and look for DTLS
   handshake retransmits.

---

## Tunnel-2 DTLS lifecycle error
<a id="t2-lifecycle-error"></a>

**Detected when:** any of `zcc_t2_connection_timeout_*`,
`zcc_t2_socket_readable_error_*`, `zcc_t2_close_notification_*` fired.

**Severity:** WARNING individually, CRITICAL if >= 5 occurrences.

**What it means:** the DTLS layer of Tunnel v2 reported a
connection-lifecycle problem. Single events are transient (DTLS
session renewal, brief packet loss); clusters indicate a bad UDP path.

**Triage steps:**

1. Distinguish the variants in the finding evidence:
   * `connection_timeout_zsddc` -- DTLS handshake timed out.
   * `socket_readable_error_zsddc` -- read failure on the DTLS socket.
   * `close_notification_zsddc` -- peer initiated close. Often normal
     on session rotation; concerning only as a cluster.
2. If clustered: check UDP/443 reachability, path MTU, and any
   intermediate firewall's DTLS / UDP-flooding heuristics.

---
