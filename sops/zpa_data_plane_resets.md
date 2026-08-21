# SOP: ZPA data-plane connection resets

Fires when the bundle window shows >= 100 `Exception in onSocketReadable ... Connection reset by peer` events while the ZPA tunnel state remained healthy throughout (no SmeProxyState flap, no mtunnel reconnect, no `SERVER_DOWN_ERROR`, no `FIREWALL_BLOCK_ERROR`).

Grounded in: Example Tenant E / Google Remote Desktop bundle 2026-05-18-15-20-30, where 582 Zpn endConnection events fired across 8 rotated tunnel logs while `getZpnProxyState:TUNNEL_FORWARDING getZpnAuthState:AUTHENTICATED` stayed healthy.

## #zpa-data-plane-resets

A ZPA data-plane connection is the per-flow tunnel between the client and the App Connector. The tunnel itself is up, but individual flows are getting terminated by the remote side after the TLS handshake. The pattern in the log is:

```
ID=<n>, Zpn client socket written bytes: 72 Pending bytes: 0 tag id: <m>
ID=<n>, Zpn client onSocketReadable called. Others: [0]
ID=<n>, Exception in onSocketReadable tag id: <m> (Error: Connection reset by peer)
ID=<n>, Zpn endConnection called for tag id: <m> ShutdownMode: SHUTDOWN_BOTH
```

The `tag id` is socket-local — it doesn't carry the destination IP — so the detector knows only that resets are happening, not which target is being affected. Cross-reference with packet captures (`--pcap`) to identify the SNI / destination IP.

### Severity thresholds

- 100-499 resets in the bundle window: **WARNING**
- 500+ resets: **CRITICAL**

Below 100, the detector stays silent (one or two resets per session are normal background noise).

### Triage steps

1. **Identify the affected destination(s).** Run `python -m zcc_diag --pcap-filter <pattern> <bundle>` with progressive patterns. The pcap will show TLS SNI hostnames whose handshakes succeeded but flows then died. Common candidates:
   - Internal app behind an App Connector (most common)
   - SaaS app routed via App Connector (less common)

2. **Check App Connector logs** for the relevant connector group. The most common server-side causes:
   - **Capacity exhaustion**: `Too many open files` / `EAGAIN` / `EMFILE`. Connector ulimit needs raising or the connector group needs more nodes.
   - **Source-IP anchoring mismatch**: the backend app is allowlisting a specific source IP that no longer matches the connector's egress IP (after a connector replacement or scaling event).
   - **WAF rule blocking**: the backend WAF (F5, Cloudflare, Imperva, etc) is matching ZPA's traffic profile against a bot-detection rule.

3. **Check the customer firewall between the App Connector and the backend.** Silent drops by stateful firewalls (rule expiry, connection limit) typically present exactly this shape: TLS handshake completes, then the firewall starts dropping subsequent packets, and the backend treats the lack of ACK as a reset.

4. **Path MTU.** If the resets cluster on specific destinations and the connector is reachable via a path with MTU mismatch (VPN, Direct Connect with non-1500 MTU), TLS records that span the MTU boundary will silently fragment-and-drop. Look for ICMP frag-needed in the customer firewall logs.

5. **Cross-check against the customer-reported app.** Ask the user what app they were using when the symptom appeared. If the app's typical traffic profile is many-short-lived connections (RDP, SSH, RMM agent heartbeats), the threshold trigger may be reflecting legitimate volume, not a bug — verify by counting `Zpn endConnection` lines that DON'T have a `Connection reset by peer` exception. If most flows complete cleanly and only a subset reset, you're looking at intermittent rather than systemic failure.

### When the detector deliberately stays silent

Suppressed when ANY of these markers also appear in the bundle window:

- `SmeProxyState:LOCAL_PROXY_FORWARDING|TUNNEL_DOWN|CONNECTING`
- `ZpnProxyState:TUNNEL_DOWN`
- `ZpnAuthState:UNAUTHENTICATED|AUTH_REQUIRED`
- `SERVER_DOWN_ERROR`
- `FIREWALL_BLOCK_ERROR`
- mtunnel reconnect loops
- `TUNNEL_NOT_ESTABLISHED`

In any of those cases the resets are explained by the upstream tunnel break and the dedicated detector for the upstream cause (`tunnel_not_established`, `zpa_mtunnel_reconnect_loop`, etc) will fire instead. Double-reporting is suppressed at the source.

### Common false-positive patterns to watch for

- **Customer running pings or short-lived HTTP probes for monitoring**: those generate one connection per probe and short-circuit normally. The pattern looks like resets only if the probe explicitly closes the socket from the far side. Inspect the source thread id (`pid:tid`) — if the resets all cluster on one or two threads tied to a monitoring service, this is benign.
- **Customer running file-transfer applications over ZPA**: long-running flows getting reset after large transfers can show up as a count burst at the end of the bundle window. Look at the time spread of the resets — if they're clustered in the last 30s, suspect transfer-completion-related closure rather than infrastructure issue.
