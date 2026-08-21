# SOP: macOS firewall / EDR / DNS-filter interference

This document is the Mac counterpart to `endpoint_fw_av.md` (which is
Windows-only). Detected by `zcc_diag/issues/endpoint_fw_av_mac.py`.

The macOS detection surface is fundamentally different from Windows:
- No LWF kernel filter driver — ZCC uses Apple System Extensions.
- No Windows Firewall API — Mac uses `pfctl` (packet filter) and
  `socketfilterfw` (the application firewall).
- DNS filtering products (Jamf Protect's Wandera EDNS, Cisco
  Umbrella for Mac, NextDNS, ControlD) install per-host DNS
  sinkholes that intercept queries **even when ZIA is disabled**.
- System Extension load can be denied by user or MDM policy.

Detection grounded in an anonymized internal case (Example Tenant J
JumpCloud Remote Assist on macOS, closed `ISSUE_FIXED`). observed
from the 2026-02-06 Zoom AI Summary: *"new DNS filtering problems
caused by Jamf Protect's block lists for open DNS... the
edns.wandera.com domain was causing connectivity issues, and
Patrick was instructed to exempt his computer from Jamf Protect's
configuration."*

> **Calibration caveat.** This detector was authored without a real
> Mac failure-mode bundle. The Wandera-EDNS / Jamf Protect
> signatures come from observed Zoom AI Summary quotes; the pfctl /
> socketfilterfw / sysext signatures are inferred from Apple's API
> surfaces. When a real Mac failure bundle becomes available, run
> it through this detector and tighten the regexes. False positives
> should be rare (signatures are specific endpoint / process names);
> false negatives are likely until the detector sees real failures.

---

## Wandera EDNS is intercepting DNS on this Mac
<a id="wandera-edns-intercept"></a>

**Detected when:** ZCC log mentions `edns.wandera.com`.

**What it means:** Jamf Protect's 'Open DNS threat' feature has
installed an EDNS DNS sinkhole on the Mac. The sinkhole intercepts
DNS queries and substitutes its own responses for blocked
categories. It runs **independently of ZIA**: even when the user
disables Zscaler, DNS filtering can still break the same SaaS calls.

**Triage steps:**

1. Identify the Jamf admin (the customer's IT team will know).
2. Ask them either to:
   - Exempt the affected Mac from Jamf Protect's Open DNS config
     (single-user fix, common during troubleshooting), OR
   - Reconfigure Jamf Protect to NOT sinkhole the specific category
     that's catching the failing host (fleet-wide fix).
3. Confirm via Terminal on the affected Mac:
   ```
   scutil --dns | grep -A 5 "resolver #1"
   ```
   The `nameserver[0]` should NOT be Wandera or an EDNS IP. If it
   is, Jamf Protect hasn't been reconfigured yet.

**Operator workflow:**
- This finding very often co-occurs with `JAMF_PROTECT_ACTIVITY`
  (just informational confirmation that Jamf Protect is the source).

---

## Cisco Umbrella DNS interception on this Mac
<a id="umbrella-dns-intercept"></a>

**Detected when:** ZCC log mentions `dns.umbrella.com`,
`gateway.umbrella.com`, or `208.67.222.222` / `208.67.220.220`.

**What it means:** Cisco Umbrella is doing DNS-layer filtering on
the device. Same class of problem as Wandera but a different vendor.
When deployed alongside ZIA, Umbrella + ZIA can fight over DNS
resolution with confusing results — different SaaS endpoints fail
or succeed in non-deterministic patterns.

**Triage steps:**

1. Decide which product is the primary security tool on Mac.
2. Scope Umbrella to bypass the customer's primary SaaS / SSO
   domains, OR disable Umbrella on the managed-Mac fleet.
3. If both products must coexist, configure Umbrella to use ZIA's
   DNS as the upstream resolver — that way ZIA category rules take
   precedence and Umbrella becomes a passive layer.

---

## Jamf Protect is active on this Mac
<a id="jamf-protect-activity"></a>

**Detected when:** ZCC log mentions `com.jamf.protect`,
`jamfprotectd`, or `JamfProtect`.

**What it means:** INFO-level context. Jamf Protect is running on
the device. If paired with `WANDERA_EDNS_INTERCEPT`, see that
finding for the actual fix. Standalone, Jamf Protect can still
silently:
- Deny ZCC's System Extension load via the MDM allow-list.
- Block ZCC processes via System Extension policy.

**Triage steps:**

1. If `SYSEXT_LOAD_DENIED` also fired, see
   [ZCC System Extension was denied](#sysext-load-denied) for the
   MDM fix.
2. Otherwise, no action — just note Jamf Protect in the ticket
   context.

---

## pfctl block / drop activity
<a id="pfctl-block"></a>

**Detected when:** a pfctl line in ZCC logs mentions `block` or
`drop`.

**What it means:** macOS's packet filter is dropping traffic. On a
managed fleet, the pf ruleset typically comes from MDM (Jamf,
Kandji, Mosyle) or a security product's Mac agent.

**Triage steps:**

1. On the affected Mac: `sudo pfctl -sa` to list active rules.
2. Identify which rule matched ZCC's traffic. Look for rules
   referencing ZCC's component paths or its outbound ports.
3. If MDM-managed, coordinate with the MDM admin to add an
   exemption for:
   - `/Library/Application Support/Zscaler/`
   - `/Applications/Zscaler.app/`
4. If product-managed (CrowdStrike Falcon Mac, SentinelOne Mac),
   the EDR has an admin console for adding allow-list entries.

---

## macOS application firewall denied a ZCC connection
<a id="socketfilterfw-deny"></a>

**Detected when:** `socketfilterfw` activity with `deny`, `block`,
or `reject`.

**What it means:** The application firewall (`socketfilterfw`)
denied an outbound connection from a ZCC component.

**Triage steps:**

1. Check current state on the affected Mac:
   ```
   sudo socketfilterfw --getappblocked \
       /Applications/Zscaler.app/Contents/MacOS/Zscaler
   ```
2. If blocked, fix:
   ```
   sudo socketfilterfw --add \
       /Applications/Zscaler.app/Contents/MacOS/Zscaler
   sudo socketfilterfw --unblockapp \
       /Applications/Zscaler.app/Contents/MacOS/Zscaler
   ```
3. Verify ZCC's other binaries (tunnel, UPM controller) are also
   allowed.

---

## ZCC System Extension was denied by macOS / MDM
<a id="sysext-load-denied"></a>

**Detected when:** a System Extension Request was denied / failed /
rejected, OR ZCC reports its extension is `not loaded` / `not
approved`.

**What it means:** macOS Catalina+ requires user (or MDM) approval
for ZCC's System Extension. Without it, ZCC cannot intercept
traffic — the user sees ZCC running but every connection bypasses
it.

**Triage steps:**

1. Push (or update) an MDM payload that pre-approves Zscaler's
   System Extensions. Zscaler's team ID is `7HQV7WHV9D`.
2. Bundle IDs to allow:
   - `com.zscaler.tunnel`
   - `com.zscaler.security`
   - `com.zscaler.networkextension`
3. Confirm via Terminal:
   ```
   systemextensionsctl list
   ```
   Each extension should show `[activated enabled]`. If any shows
   `[terminated]`, restart the Mac after the policy push.
4. If the customer doesn't use MDM, walk the user through:
   System Preferences → Privacy & Security → "Allow" for each
   Zscaler extension.

---

## ZCC's NEFilterDataProvider exited or was terminated
<a id="nefilter-provider-failure"></a>

**Detected when:** `NEFilterDataProvider` mentions terminated /
killed / exited / failed / timeout, OR `nesessionmanager` reports
error / fail / denied.

**What it means:** macOS's kernel-side Network Extension that ZCC
uses for traffic interception was terminated. After termination,
ZCC fails open and traffic bypasses inspection silently.

**Triage steps:**

1. `systemextensionsctl list` should show the Zscaler extensions
   as `[activated enabled]`. If `[terminated]` or absent, re-
   approve via MDM and restart the Mac.
2. Check `Console.app` filtered to subsystem `com.apple.networkextension`
   for the termination cause. Common: callback timeout (kernel
   killed it for being too slow), or another product's NE racing
   ZCC's.
3. If a competing product is racing (CrowdStrike Falcon Network
   Filter, SentinelOne Mac, or another ZCC-class product), only
   one can be active at a time. Decide which to keep and remove
   the other.

---

## Third-party DNS sinkhole present on this Mac
<a id="dns-sinkhole-generic"></a>

**Detected when:** ZCC log mentions NextDNS, ControlD, AdGuard
DNS, or Cloudflare Gateway DNS.

**What it means:** A third-party DNS sinkhole is intercepting DNS
on the device. Same risk profile as Wandera / Umbrella — it can
break SaaS connectivity even with ZIA disabled.

**Triage steps:**

1. Coordinate with the customer's IT team to confirm whether the
   third-party DNS intercept is intended.
2. If unintended, remove the competing DNS config profile (System
   Preferences → Profiles → look for DNS-related entries).
3. If intended, scope it so it doesn't sinkhole the customer's
   primary SaaS domains.
