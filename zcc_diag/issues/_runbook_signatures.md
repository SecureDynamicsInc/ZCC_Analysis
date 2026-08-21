# Zscaler runbook signatures — reference

Normalized troubleshooting signatures aligned to the official Zscaler Help
runbooks linked in `docs/REFERENCE_SOURCES.md`. Use this as a regression
reference when writing or updating detectors and SOPs; preserve literal log
signatures while keeping explanations independently maintainable.

The relevant external references cover three workflows:
- ZCC Performance Troubleshooting
- ZCC Traffic Forwarding Troubleshooting (covers Captive Portal,
  Connection Error, FW/AV Error, Network Error, Driver Error)
- ZIA Performance Troubleshooting (mostly methodology, MTR-driven)

Severity guide for the "Severity" column below: a runbook severity
isn't published; what's listed is my reading of how blocking the
condition is.

---

## Captive Portal Error (Traffic Forwarding runbook)

**Tray strings**
- `Captive Portal Detected`
- `Captive Portal Error`

**Browser symptom**
- `The page cannot be displayed`

**Identification (documented)**
> In Zscaler Client Connector logs and packet captures, look for HTTP
> requests to `http://gateway.<cloud>.net:443/generate_204`. If HTTP
> status code 204 is not returned, it indicates captive portal
> detection.

**Registry state values (from Errors documentation)**
- `CAPTIVE_PORTAL_ERROR` — user didn't resolve captive portal in time
- `CAPTIVE_PORTAL_FAILOPEN` — ZCC stopped interception briefly to
  allow captive auth

**Possible causes (documented list)**
- Captive portal login page not being prompted
- Network components blocking access to required Zscaler URLs
  (e.g., `gateway.<cloudname>.net`)

**Resolution steps (documented)**
1. Verify captive portal login: ensure the captive portal login page
   is accessible from the default or another browser.
2. Check network configuration: confirm DNS isn't blocking
   `gateway.<cloudname>.net`; ensure firewall doesn't block captive
   portal detection traffic.
3. Bypass third-party VPN configurations: if using a third-party VPN,
   allow access to `gateway.<cloudname>.net` and `pac.<cloudname>.net`.
4. Review timeout settings: increase captive portal timeout in ZCC
   settings if login pages take longer to load.
5. Update ZCC: ensure ZCC is on the latest version.

---

## Connection Error (Traffic Forwarding runbook)

**Tray string**: `Connection Error`. Logs show `Server Down Error`.

**Identification (documented)**
> Review Zscaler Client Connector logs for proxy auto-configuration
> (PAC) file parsing and connection attempts to `gateway.<cloudname>.net`.
> Keywords: `getSmeProxyState`, `Tunnel Forwarding Status`.

### Tunnel 1.0 signatures

**PAC parse trace (DBG/INF lines)**
```
DBG getProxyForUrl: Pac parse called for url: https://gateway.zscaler.net, pacRequestType: 1
DBG initPacParserSession: Pac parse success!
INF Saving default proxy string as: PROXY 165.225.120.17:80; PROXY 165.225.122.17:80; DIRECT
INF getProxyForUrl: Pac proxy array index: 0 value: 165.225.120.17
INF getProxyForUrl: Pac proxy array index: 2 value: 165.225.122.17
INF getProxyForUrl: Pac proxy array index: 3 value: 80
```

**Proxy keepalive cadence**: every 30 seconds. If keepalives fail
against all DCs from the PAC, ZCC enters connection error state.

**State sequence**
```
getSmeProxyState:TUNNEL_FORWARDING
getSmeProxyState:CONNECTING
getSmeProxyState:SERVER_DOWN_ERROR
getSmeProxyState:LOCAL_PROXY_FORWARDING   (sustained connection error)
```

### Tunnel 2.0 signatures

**Healthy DTLS T2State line**
```
DBG ZApp Status: getCurrentNetworkType:TRUSTED getSmeProxyState:TUNNEL_FORWARDING T2State: [Tx:31109 Rx:29942 IP:10.254.120.171 SME:165.225.202.56 Protocol: DTLS Status:UP]
```

**T2State sub-state during transition**
```
T2State: [... Protocol: DTLS Status: ZSCCM:TUNNEL_FORWARDING ZSDDC:CONNECTING]
```
- `ZSCCM` = control channel (always TLS)
- `ZSDDC` = data channel (DTLS or TLS based on profile)

**T2 → T1 fallback (KEY signatures)**
```
INF ZSCCM::ACTIVE::startConnection: Failure#:0 Exception:Timeout: connect timed out: 147.161.179.24:443
INF ZST2M::ACTIVE::updateZiaConfig: Updating ZIA Configuration
INF ZST2M::ACTIVE::updateZiaConfig: SME List is empty. Fallback to ZTunnel 1.0
```
This is distinct from the `zcc_t2_dtls_to_tls_fallback` zEvent that
fires when DTLS-only fails inside Tunnel 2.0.

**SSL/TLS interception (KEY signature)**
```
INF ZST2M::ZT2A::initialize: Data Channel establishment Failed.
INF Auth::Lib::certificateErroCallback: Invalid certificate
```
Note the documented typo `certificateErroCallback` (Erro, not Error) —
match it exactly.

**Possible causes (documented)**
- Network firewall or endpoint device blocking Zscaler IP ranges or
  specific ports
- SSL interception or network proxy interfering with Zscaler
  communication
- Incorrect PAC file configuration

**Resolution steps**: PAC file URL accuracy; bypass SSL inspection on
Zscaler IP ranges; allow ports 80 + 443 to `gateway.<cloud_name>.net`;
allow UDP for Z-Tunnel 2.0; switch protocol to TLS as a test.

---

## Endpoint Firewall / AV Error (Traffic Forwarding runbook)

(Already integrated into `endpoint_fw_av.py` and
`sops/endpoint_fw_av.md` — this section is for cross-reference.)

**Tray string**: `Endpoint FW/AV Error`. Registry state:
`FIREWALL_BLOCK_ERROR`.

**Canonical state pattern**
```
SmeProxyState: CONNECTING -> SERVER_DOWN_ERROR (repeating) -> FIREWALL_BLOCK_ERROR
ZpnProxyState: TUNNEL_FORWARDING -> FIREWALL_BLOCK_ERROR
```

**Explicit log signatures (documented)**
- `Firewall detected retries expired`
- `[WFP]: Bad health`

**Health-check destinations**: `100.64.0.6` and `100.64.0.8` on
ports 80 (ZIA), 9090 (ZPA, observed in real bundles), 443 / 8080
fallbacks. Local listener on port 9000 by default.

**Process allow-list (documented from runbook)**
- `ZSATunnel.exe`, `ZSATray.exe`, `ZSAService.exe`, `ZDPService.exe`

**Triage**: `Find-NetRoute -RemoteIPAddress 100.64.0.6` — verify
InterfaceAlias is Wi-Fi/Ethernet, not a third-party VPN adapter.

---

## Network Error (Traffic Forwarding runbook)

**Tray string**: `Network Connection Failed. -8`

**LIVES IN ZSATray LOGS** — different file, different format from
ZSATunnel. The detector pipeline as of stage 1 only feeds tunnel
logs to detectors. Network Error detection requires extending the
multiplexer (stage 4 decision).

**ZSTray log format (different from ZSATunnel!)**
```
2022-06-24 08:31:42.667324 #NORMAL #ERROR : Error checking updates: {"error":-8,"errorMessage":"Host not found. mobile.zscloud.net","response":"","success":"false"}
```

The `#NORMAL #ERROR :` marker style is distinct from the tunnel-log
`(+0530)[pid:tid] ERR` format. Parser needs both shapes.

**Five distinct error categories (documented errorMessage values)**

| Category | errorMessage substring |
|---|---|
| DNS failure | `Host not found.` |
| Connection interrupted | `Connection reset by peer.` |
| Missing route | `Net Exception. No route to host` |
| Network unreachable | `Net Exception. Network is unreachable` |
| SSL intercepted | `Certificate validation error. Unacceptable certificate from <host>: application verification failure` |
| SSL handshake failed | `SSL Exception. error:14090086:SSL routines:ssl3_get_server_certificate:certificate verify failed` |

**Critical hosts to which keepalives go (documented)**
- `mobile.zscaler.net`
- `login.<cloud_name>.net`
- `mobile.<cloud_name>.net`

**Triage**
- DNS resolution test against the three hosts above
- Try alternate DNS (Google `8.8.8.8` / `8.8.4.4`)
- If resolved IP isn't in the Zscaler hub IP range — check for
  custom entries in `C:\Windows\System32\drivers\etc\hosts`
- Disable IPv6 on the network adapter if resolution returns IPv6
- Disable VPN clients / endpoint security temporarily

---

## Driver Error (Traffic Forwarding runbook)

**Tray string**: `Driver Error` in Service Status section.

**LIVES IN ZSATray LOGS** (and `setupapi.dev.log`) — same multiplexer
extension required as Network Error.

**ZSATray log signatures (documented)**
```
ERR LWF: Unable to load driver!
ERR lwf: Initial driver check FAILED! LightWeightFilter not loaded! ZApp moves to DRIVER ERROR!
```

**setupapi.dev.log signatures (documented)**
```
!!! idb: Failed to create driver package object 'zapprd.inf_amd64_<hash>' in DRIVERS database node. Error = 0x00000002
!!! idb: Failed to register driver package 'C:\WINDOWS\System32\DriverStore\FileRepository\zapprd.inf_amd64_<hash>\ZAPPRD.inf'. Error = 0x00000002
!!! sto: Failed to import driver package into Driver Store. Error = 0x00000002
!!! inf: Failed to import driver package into driver store
!!! inf: Error 2: The system cannot find the file specified.
```

**Common causes (documented)**
- Driver cache corruption (`C:\Windows\System32\DriverStore`)
- Missing registry entries for ZCC driver services
- Endpoint protection blocking driver installation
- Driver Store corruption

**Resolution (documented)**
1. ZCC Tray → More → Troubleshoot → Repair App, then restart
2. Disable Carbon Black / CrowdStrike-style EDR temporarily
3. Reinstall ZCC with `--reinstallDriver 1` flag

---

## ZCC Performance (Performance runbook)

Mostly methodology, not detection signatures. Key log-level signals:

**T2State Protocol toggle = DTLS-to-TLS fallback**
```
T2State: [... Protocol: DTLS Status:UP]
... (later) ...
T2State: [... Protocol: TLS Status:UP]
```
ISP throttling UDP forces DTLS to fail repeatedly until TLS fallback.
Pair with `zcc_t2_dtls_to_tls_fallback` zEvent (already detected) and
the explicit `SME List is empty. Fallback to ZTunnel 1.0` line.

**MTU defaults**: DTLS Tunnel 2.0 default MTU = 1400, MSS = 1360.
TLS auto-negotiates. MTU mismatch causes fragmentation → throughput
collapse.

**No cleanly-greppable "MTU mismatch" log line.** The runbook says to
test by manually lowering MTU in 50-byte increments and observe
whether performance recovers; no log emits "MTU is too high."

**Runtime config endpoint** (interesting, not for detection but for
SOP guidance): `http://127.0.0.1:9000/zconfig?q=@<CustomerDomain>`
exposes per-host MTU and protocol overrides at runtime.

**Pattern-isolation methodology**

| Pattern | First steps |
|---|---|
| Slow on a specific OS | Check OS upgrade history, third-party AV/VPN updates, allow-list, CPU |
| Slow for whole org | ZCC version regression test; recent security patch / software push |
| Slow at a time of day | Scheduled big upload/download / scheduled AV scan |
| Slow at one office location | Zscaler DC issue, path congestion, office router/switch/firewall health |

---

## ZIA Performance (ZIA Performance runbook)

Even more methodology-driven. Useful for SOP guidance, no detector
signatures.

**Key concepts**
- **Subcloud configuration** — ZIA's mechanism for steering traffic
  to specific DCs
- **MTR (My Traceroute)** collection on Windows / Mac / Linux
- **Hop-by-hop latency analysis** — three-leg model:
  1. Client → Egress firewall
  2. Egress → ZIA Service Edge
  3. Service Edge → Application origin
- **Browser HAR / `chrome://net-export/`** — for user-side trace

The triage methodology is "isolate which leg is slow, then dig into
that leg." Translate this into SOP guidance for issue 5 rather than
detector logic.

---

## What this implies for the codebase

| Issue | Signatures live in | Detector status |
|---|---|---|
| Captive Portal | ZSATunnel | Stage 2 — about to build |
| Connection Error | ZSATunnel | Already covered + 2-3 missing additions for stage 3 |
| FW/AV Error | ZSATunnel | Already built + corrected (uses 100.64.x.x not 127.0.0.1) |
| Network Error | **ZSATray** | Needs multiplexer extension (stage 4) |
| Driver Error | **ZSATray + setupapi** | Needs multiplexer extension (stage 4) |
| ZCC Performance | ZSATunnel + methodology | Stage 5; partially covered by tunnel detector |
| ZIA Performance | Methodology only | Stage 5; SOP-only, no detector |
