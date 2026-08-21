# SOP: Endpoint Firewall / Antivirus errors

This document covers issue #3 in the user spec --
"Endpoint Firewall / Antivirus errors" -- detected by
`zcc_diag/issues/endpoint_fw_av.py`.

The user-facing tray status string this maps to (per the Zscaler
"Client Connector Errors" documentation, Connection Status Errors table):

  * **Endpoint FW/AV Error** -- "The device has a firewall or antivirus
    program blocking Zscaler Client Connector traffic."

Canonical state-machine value: `FIREWALL_BLOCK_ERROR` -- "ZCC's attempt
to create an outbound and/or inbound connection to itself failed." The
documentation notes this state is "applicable only for Private Access" but the
underlying problem (host firewall / EDR blocking ZCC) affects both.

> **Calibration note.** None of the bundles available during
> development contained an actual FW/AV failure. This SOP is grounded
> in the Zscaler documentation + earlier hand-curated patterns, not in real
> failure-bundle validation. When real failure data appears, the
> guidance below should be revisited.

Each H2 below is anchored on a finding code emitted by the detector.

---

## FIREWALL_BLOCK_ERROR state
<a id="firewall-block-error-state"></a>

**Detected when:** ZIA or ZPA proxy state transitioned into
`FIREWALL_BLOCK_ERROR`.

> Per the Zscaler ZCCTF runbook, the canonical pattern leading to
> this state is:
> `SmeProxyState: CONNECTING -> SERVER_DOWN_ERROR (repeating) ->
>  FIREWALL_BLOCK_ERROR` paired with
> `ZpnProxyState: TUNNEL_FORWARDING -> FIREWALL_BLOCK_ERROR`.
> If you also see `Firewall detected retries expired` or
> `[WFP] Bad health` in the same window, this detector will fire
> separate findings for those (with the same root cause).

**Triage steps:**

1. Check `summary.security_products` (also surfaced as the
   `SECURITY_PRODUCTS_PRESENT` finding) for the AV/EDR products
   detected on the system.
2. Verify the AV/EDR allow-list includes:
   * `ZSATunnel.exe`, `ZSATray.exe`, `ZSAService.exe`
   * `ZDPService.exe` (Zscaler Digital Experience service)
   * `ZSAUpdater.exe`, `ZSAUpm.exe`, `ZSAHelper.exe`
   * The `C:\Program Files\Zscaler\` directory tree (or
     `C:\Program Files (x86)\Zscaler\` on legacy installs)
   * The `C:\ProgramData\Zscaler\` directory tree (logs and config)
   * **The 100.64.0.0/24 range** ZCC uses for internal health-check
     traffic (see [Health-check connection to
     100.64.0.0/24 failed](#healthcheck-to-100-64-failed) for the
     full route-verification flow)
3. Windows Defender Firewall: verify there are no `Block` rules
   targeting Zscaler binaries. Check `summary.firewall_rules_zscaler`
   for what's currently configured. Per the ZCCTF runbook: a less-
   specific block rule will override the Zscaler App Rule even if
   that rule is enabled.
4. Specifically, if any inbound rule blocks **port 9000** or **port
   80** locally, remove or disable it (see
   [Local port 9000 bind / listen failure](#port-9000-bind-fail)).
5. If `Allow` rules are present but ineffective: a more aggressive
   firewall product (third-party AV, Group Policy IPsec) may be
   over-riding Windows Firewall.

---

## LWF driver not running
<a id="lwf-driver-not-running"></a>

**Detected when:** `lwfDriverRunning=false` reported in tunnel-status JSON.

**What it means:** the Zscaler Lightweight Filter (LWF) driver, which
intercepts traffic in modern ZCC, is not loaded. ZCC effectively
cannot intercept anything.

**Triage steps:**

1. `Get-Service` (PowerShell) and look for the Zscaler LWF service. If
   missing, the driver was never installed or has been removed.
2. Driver Verifier may have flagged it -- check Windows Event Viewer →
   System log for `Zsalwf` or similar driver names.
3. If the driver is registered but not running: try restarting
   `ZSAService` (Services.msc). On modern Windows, the driver may
   require a reboot if its kernel image was updated.
4. EDR products with kernel-driver-load policy can block this. Check
   the EDR's "blocked driver" or "untrusted driver" report for any
   Zscaler entries.

---

## Filter driver load failure
<a id="filter-driver-fail"></a>

**Detected when:** log line matches `FilterDriver.*(?:failed|error|load.*fail)`.

**What it means:** ZCC explicitly logged a driver-load failure. Often
caused by:

  * Windows code-integrity policy rejecting the driver's signature
    (after a Windows update changed signing requirements)
  * EDR product blocking kernel drivers from loading
  * Driver file corruption (rare; would also fail signature checks)

**Triage steps:**

1. Get the exact failure code from the evidence log line if present.
2. If you can match it to a Windows kernel driver-load error code,
   look that up in Microsoft's documentation.
3. Re-running the ZCC installer often re-registers the driver and
   produces a fresh signed image.

---

## Health-check connection to 100.64.0.0/24 failed
<a id="healthcheck-to-100-64-failed"></a>

**Detected when:** an explicit error phrase (`connection refused`,
`connection timed out`, `no route to host`, etc.) appears in an
ERROR/WARN-level log line alongside an IP in the `100.64.0.0/24`
range.

**What it means:** ZCC sends internal health-check probes to
`100.64.0.6` and `100.64.0.8` on ports 80 (ZIA), 9090 (ZPA), with 443
and 8080 as fallbacks. The `100.64.0.0/24` range is RFC 6598 shared
address space ZCC uses internally. If these probes fail, ZCC concludes
its tunnel can't function and flips to `FIREWALL_BLOCK_ERROR`.

**The two most common root causes:**

1. **A host firewall or EDR product is blocking ZCC's health-check
   traffic.** Allow-list ZCC's processes (see below).
2. **The 100.64.0.0/24 range is being routed onto a third-party VPN
   adapter** instead of the physical network interface. ZCC's
   internal probes never make it to the loopback driver.

**Triage:**

1. **Verify which adapter handles the route:**
   ```powershell
   Find-NetRoute -RemoteIPAddress 100.64.0.6
   ```
   The `InterfaceAlias` field should be `Wi-Fi` or `Ethernet`. If it
   shows a VPN adapter (Cisco AnyConnect, GlobalProtect, etc.), that's
   the problem. Add a route exclusion for `100.64.0.0/24` from the VPN.

2. **Allow-list ZCC processes** in your AV/EDR:
   * `ZSATunnel.exe`
   * `ZSATray.exe`
   * `ZSAService.exe`
   * `ZDPService.exe` (Zscaler Digital Experience service)
   * `ZSAUpm.exe`
   * `ZSAUpdater.exe`
   * `ZSAHelper.exe`

3. **Check the Windows Firewall rule:**
   ```
   netsh advfirewall firewall show rule name = "Zscaler App Rule"
   ```
   The rule should be `Enabled: Yes`, `Action: Allow`, applying to
   Domain, Private, and Public profiles. If a more general `Block`
   rule overrides it, even for ports 9000 or 80, remove the block.

4. **Capture a packet trace** using ZCC's built-in
   `CaptureLWF<timestamp>.pcap` and look for failed handshakes to
   `100.64.0.6:80` / `100.64.0.6:9090`.

---

## Local port 9000 bind / listen failure
<a id="port-9000-bind-fail"></a>

**Detected when:** log indicates ZCC failed to bind, listen, or accept
on port 9000.

**What it means:** Port 9000 is ZCC's default local listening port
(configurable in the forwarding profile). It's used by the DNS proxy
listener and the TUN-Proxy local listener. If ZCC can't bind to it,
traffic interception is broken.

**Triage:**

1. **Check whether something else is bound:**
   ```
   netstat -ano | findstr :9000
   ```
   Identify any non-Zscaler PID; investigate that application.

2. **Inbound firewall rule:** the Zscaler App Rule normally allows
   inbound to `ZSATunnel.exe`. If a separate rule blocks inbound to
   port 9000 specifically, remove or disable it. Per the Zscaler
   ZCCTF runbook: "If there is a rule which is blocking inbound
   connectivity to local port 9000 or port 80, Zscaler recommends
   that you remove or disable that rule."

3. **Forwarding profile may have changed the port.** If the port in
   logs differs from 9000, it was changed in the ZCC admin console.
   Check whichever port is in use.

---

## Firewall detected retries expired
<a id="firewall-retries-expired"></a>

**Detected when:** the literal string `Firewall detected retries
expired` appears in a log.

**What it means:** ZCC's Windows Filtering Platform (WFP) callout
retried blocked traffic until its retry budget ran out and gave up.
This is documented in the Zscaler ZCCTF runbook as a canonical FW/AV
failure signature.

Almost always co-occurs with `FIREWALL_BLOCK_ERROR` state and
`[WFP] Bad health` lines. Triage is the same as
[Health-check connection to 100.64.0.0/24 failed](#healthcheck-to-100-64-failed).

---

## Windows Filtering Platform reported bad health
<a id="wfp-bad-health"></a>

**Detected when:** the pattern `[WFP] ... Bad health` appears in a
log.

**What it means:** ZCC's Windows Filtering Platform (WFP) driver is
self-reporting as unhealthy. WFP is the kernel-mode framework ZCC
uses to inspect/filter traffic on Windows. Documented in the Zscaler
ZCCTF runbook as paired with `FIREWALL_BLOCK_ERROR`.

Triage is the same as
[Health-check connection to 100.64.0.0/24 failed](#healthcheck-to-100-64-failed).

---

## Firewall rule install failed
<a id="firewall-rule-install-fail"></a>

**Detected when:** ZCC tried to add a Windows Firewall allow-rule for
itself and the call failed.

**Triage steps:**

1. Verify ZCC components run with sufficient privileges. ZSAService
   should run as `LocalSystem` -- if it's been demoted (Group Policy,
   manual change), it can't modify firewall config.
2. Check for Group Policy that locks firewall configuration. Even
   `LocalSystem` is bound by GPO firewall lockdowns.
3. EDR products with "tamper protection" sometimes block firewall
   rule modifications. Check the EDR console for blocked actions.

---

## FirewallAPI call failed
<a id="firewall-api-fail"></a>

**Detected when:** generic Windows FirewallAPI failure logged.

Same triage as `firewall-rule-install-fail` above. Capture the exact
Windows error code from the evidence and look it up.

---

## Access denied launching ZCC component
<a id="access-denied-zsa"></a>

**Detected when:** log line shows `Access denied` near a `ZSA*`
process / file reference.

**What it means:** an EDR / AV / OS ACL refused to let one ZCC
component start another. Often happens when:

  * ZCC was installed under a different admin context than current
  * EDR's behavior monitor classified ZCC's spawn pattern as suspicious
  * NTFS ACLs on `C:\Program Files\Zscaler\` were tightened

**Triage steps:**

1. Verify ACLs on `C:\Program Files\Zscaler\` -- normal is `SYSTEM:F`,
   `Administrators:F`, `Users:RX`.
2. EDR console: search for blocked process-creation events near the
   failure timestamp.
3. Re-run ZCC installer to reset permissions.

---

## ControlService permission denied (0x426)
<a id="controlservice-426"></a>

**Detected when:** `ControlService failed ... Error 0x00000426`.

**What it means:** Windows error 0x426 = "The service has not been
started". Combined with `ControlService failed`, this means the caller
asked Windows to start ZSAService and Windows refused / found it not
in a startable state.

**Triage steps:**

1. `services.msc` → ZSAService → confirm Startup Type is `Automatic`.
2. If `Disabled` or `Manual`, set to `Automatic` and start.
3. If service refuses to start: Event Viewer → System / Application
   for the failure reason. Common: missing dependency, signed-driver
   policy, or AV blocking.

---

## ZCC anti-tamper violation
<a id="anti-tamper-violation"></a>

**Detected when:** `Anti-Tamper ... violation` logged by ZCC's own
self-protection logic.

**What it means:** ZCC detected that its files, registry keys, or
processes were being modified by something other than itself. Common
culprits:

  * Aggressive EDR doing "remediation" on a binary it doesn't recognize
  * Another AV product trying to "clean" ZCC
  * Manual tampering (developer poking at config)

**Triage steps:**

1. Identify the offending process from EDR / AV logs around the
   timestamp.
2. Add ZCC to that product's allow-list.
3. If the offender is *also* an AV that's officially supported on
   the endpoint, you may have two AV products fighting -- which is
   itself the bigger problem to resolve.

---

## Security products present (informational)
<a id="security-products-present"></a>

**Severity:** INFO. This finding fires whenever
`summary.security_products` is non-empty. It exists to give the human
context: "here are the AV/EDR products on this machine; if any FW/AV
finding above has fired, one of these is the most likely culprit."

This is not a problem on its own. Most enterprise endpoints have at
least one EDR product. The finding becomes actionable only in
combination with another FW/AV finding.

---

## See also

* `tunnel_not_established.md` -- companion detector. Network-state
  failures that look like FW/AV but originate elsewhere
  (`SERVER_DOWN_ERROR`, `INTERNET_UNREACHABLE_ERROR`, etc.) are
  emitted there.
* The Zscaler "Client Connector Errors" documentation, Connection Status Errors
  table, for the canonical user-facing string and its tray remediation.
