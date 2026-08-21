# SOP: Bypass-rule misconfiguration

This document covers SSL cert-validation failures attributed to
forwarding-profile bypass-list errors, detected by
`zcc_diag/issues/bypass_misconfiguration.py`.

The user-facing symptom is "this website / app stopped working,
Zscaler is breaking it." The actual cause is almost always either
a format mistake in an existing bypass entry, or a missing bypass
entry for a cert-pinning gateway.

Detection grounded in:
- Example Tenant J JumpCloud Remote Assist case (an anonymized internal case,
  closed `ISSUE_FIXED`). observed from the 2026-02-04 Zoom AI Summary:
  *"the issue was resolved by correcting the destination IP group
  format from using a dot to a star and creating a specific URL for
  the JumpCloud agent."*
- Example Tenant K OpenVPN case (an anonymized internal case). observed:
  *"using the gateway only should be sufficient."*
- Example Tenant M + Example Tenant F + Example Tenant H / Ariba — same pattern.

The cert-callback line signature (`Auth::Lib::certificateErroCallback:
Invalid certificate`) is documented in the official ZCC Traffic
Forwarding runbook (see `_runbook_signatures.md` Connection Error
section). Note the observed typo `Erro` (not `Error`) — preserved by
ZCC across versions.

Each H2 below is anchored on a finding code emitted by the detector.

---

## Bypass entry uses leading dot but should use star wildcard
<a id="bypass-format-dot-vs-star"></a>

**Detected when:** the forwarding profile contains an entry like
`.example.com` (leading dot) and the failing host (extracted from the
same-thread `Host=…` context) matches the entry only if interpreted as
`*.example.com`.

**What it means:** the customer wrote a bypass entry intending it to
match all subdomains of a hostname, but the entry's destination-IP-
group format treats the leading dot as a literal character rather than
a wildcard. The entry is in the policy and looks correct in the admin
UI, but never actually matches anything.

**Triage steps:**

1. Locate the entry in the forwarding profile (Admin → ZIA Policy →
   URL Filtering → Bypass list, or the customer's equivalent custom
   URL category).
2. Change the entry from `.example.com` to `*.example.com` (star
   wildcard). For destination-IP-group rules specifically, the
   observed fix from the JumpCloud case was *"correcting the
   destination IP group format from using a dot to a star."*
3. If the entry is intended to match only the exact host (no
   subdomains), use the bare hostname `example.com` without the
   leading dot.
4. Re-run the failing user action and confirm the cert error no
   longer fires.

**Operator workflow (observed from the JumpCloud meeting):**
- Disable ZIA on both endpoints (sender and receiver) to confirm it's
  ZIA-side before policy editing.
- Clear ZCC logs, start packet capture, reproduce the failing action,
  stop capture.
- For multi-endpoint captures, rename the captured zip files to
  indicate sender / receiver.

---

## Cert-pinning gateway is missing from the bypass list
<a id="gateway-not-in-bypass"></a>

**Detected when:** the failing host is in the detector's known cert-
pinning gateway catalogue (`agent.jumpcloud.com`,
`*.simplepractice.com`, `*.ariba.com`, `login.microsoftonline.com`,
`*.azurewebsites.net`, etc.) AND nothing in the forwarding profile
matches it.

**What it means:** ZCC is doing SSL interception against an endpoint
that pins its certificate (refuses to trust intermediates). The
handshake fails, the customer sees the app break, and ZCC logs the
`Invalid certificate` error.

**Triage steps:**

1. Identify the SaaS or app the failing host belongs to (the host
   name almost always names it directly — `agent.jumpcloud.com`,
   `connect.jumpcloud.com`, `*.smartsupplier.ariba.com`).
2. Add the host (or its star-wildcard form) to the customer's BLSSL
   (Bypass-SSL) list. BLSSL is the correct policy surface for cert-
   pinning endpoints; the regular URL-filtering bypass doesn't stop
   SSL interception.
3. If the customer already has a similar entry that's not matching
   (e.g. `.simplepractice.com`), see
   [Bypass entry uses leading dot…](#bypass-format-dot-vs-star).
4. For partner-cloud gateways (JumpCloud, Workday, Ariba, etc.), the
   observed resolution in multiple cases was *"create a specific URL
   for the agent to bypass certificate checks"* — i.e. add the
   gateway host explicitly rather than a parent-domain wildcard.

**Operator workflow:**
- The "gateway-only" rule of thumb (Example Tenant K OpenVPN observed): *"using
  the gateway only should be sufficient."* Don't add broad wildcards;
  add the specific gateway endpoint.

---

## SSL cert error against an unknown host
<a id="cert-error-host-not-bypassed"></a>

**Detected when:** the failing host doesn't match a leading-dot entry
in the bypass list and isn't in the cert-pinning gateway catalogue.

**What it means:** Either (a) the customer is using a legitimate cert-
pinned endpoint not yet in the detector's catalogue, (b) the endpoint
trusts the Zscaler intermediate but the endpoint's local trust store
doesn't have it deployed, or (c) the customer's pack file is
out-of-date.

**Triage steps:**

1. Check the user's local trust store for the Zscaler intermediate
   cert. On Windows: `certlm.msc` → Trusted Root CAs. On Mac:
   Keychain Access → System keychain → Zscaler entries.
2. If the cert is missing, push it via GPO / MDM (Intune, Jamf,
   Kandji depending on the customer's stack).
3. If the cert is present and the endpoint still fails, the endpoint
   is likely cert-pinned. Verify with the vendor's documentation,
   then add the host to BLSSL.
4. If multiple hosts fail simultaneously, suspect an outdated pack
   file. From the ZCC tray: *More → Troubleshoot → Update Pack File*.

---

## Cert error with no resolvable target host
<a id="cert-error-unattributed"></a>

**Detected when:** a `certificateErroCallback` line appears but no
preceding `Host=…` line on the same thread was captured (e.g. the
tunnel-log byte budget truncated earlier records).

**What it means:** the detector saw the error but couldn't attribute
it. Operator must use the correlation window (±5 min around the
finding's timestamp) to identify what the user was doing.

**Triage steps:**

1. Open the finding's correlation window in the CLI.
2. Look for the most recent `Host=…` line preceding the cert error
   on the same `pid:tid` thread.
3. Once the host is identified, manually classify the finding into
   one of the three cases above.

---

## Cert errors observed but runtime bypass cache is empty
<a id="bypass-cache-empty"></a>

**Detected when:** the bundle has at least one cert error AND
`summary.bypass_cache` is empty.

**What it means:** this detector cross-references cert errors
against the runtime bypass cache (the set of hosts ZCC was
actually bypassing during the capture window). If the cache is
empty, the bundle didn't capture enough traffic to populate it —
likely because the tunnel never reached steady state (auth or
broker was broken throughout) or DEBUG-level DNS logging is
suppressed.

**Triage steps:**

1. Check the other detector findings first. If
   `zia_auth_failures`, `zpa_auth_failures`,
   `tunnel_not_established`, or `zphm_force_stop_loop` are firing,
   fix the upstream issue first.
2. After the upstream issue is fixed, ask the customer for a
   fresh bundle captured while the tunnel is operational. The
   runtime bypass cache will then populate and this detector can
   actually cross-reference cert errors against it.
3. If no upstream issue is firing AND the cache is still empty,
   the bundle's DNS DEBUG logging may be suppressed. Check ZCC
   tray → More → Troubleshoot → enable DEBUG logging, then
   recapture.
