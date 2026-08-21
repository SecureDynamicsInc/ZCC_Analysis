# SOP: ZPA DNS check fell through

This document covers ZPA app-segment-gap failures detected by
`zcc_diag/issues/zpa_dns_check_not_found.py`.

The user-facing symptom is one of:

- A user reports "I can't reach `<server>.corp.example.com` on the
  VPN" -- where the VPN is ZPA and the destination is on-prem.
- Domain-joined endpoints can't reach AD / DNS / Kerberos for hours
  after onboarding to ZPA, because the AD names aren't in any segment.
- An app that "used to work" stopped working -- usually because a
  wildcard segment was tightened.

The runbook signature is the JSON token pair
`ZPN_ERR_DNS_CHECK_NOT_FOUND` (in `zpn_dns_client_check`) and
`ZPN_ERR_APPLICATION_INVALID` -- both indicate that ZCC tried to
service a destination through ZPA and ZPA had no matching app segment.

Detection grounded in the example-tenant-c-windows-17mb calibration bundle
(180 hits across the two tokens, mostly internal AD names:
`pct-dc1.corp-c.example` and `_ldap._tcp.dc._msdcs.*`).

---

## ZPA DNS check fell through
<a id="zpa-dns-check-not-found"></a>

**Detected when:** tunnel log contains `ZPN_ERR_DNS_CHECK_NOT_FOUND`
or `ZPN_ERR_APPLICATION_INVALID` above the noise threshold (10).

**What it means:** ZCC's per-application DNS pre-check ran against
the destination and ZPA returned "no matching app segment." Three
common causes, in priority order:

1. **AD / Kerberos / domain-controller names not in any app segment.**
   The detector evidence will show internal `*.corp.local` or
   `_ldap._tcp.*` lookups. ZPA needs the AD endpoint segments to be
   present BEFORE the device tries to authenticate to the domain. If
   the customer's ZPA deployment was scoped only to user-facing apps
   (Tableau, Jira, ServiceNow, etc.) and the AD/DC segments were
   never added, this fires the moment a domain-joined endpoint
   touches an AD-aware feature.

2. **Newly-onboarded app, segment exists but connector hasn't picked
   up the policy.** This usually clears itself within a minute or so
   as the policy refresh propagates to the App Connector. If the
   detector evidence shows lookups from before a certain timestamp
   and clean lookups after, this is the case -- no action needed.

3. **Wildcard segment was purged or narrowed.** The customer had
   `*.corp.example.com` covering everything; someone narrowed it to
   specific FQDNs and now any new hostname in that domain misses the
   segment. Check the segment's domain-set history in the ZPA Admin
   Console.

**Triage steps:**

1. **Pull the distinct hostnames** from the detector's title block
   (top 10 are listed). Categorize them:
   - `*.<corp>.local`, `_ldap._tcp.*`, `_kerberos._tcp.*`,
     domain-controller hostnames -> AD-segment gap (#1 above).
   - Specific application FQDNs the customer expected to reach
     through ZPA -> #2 or #3.

2. **In the ZPA Admin Console** (Applications -> Application Segments):
   - Confirm a segment exists for each hostname the user expected
     to reach.
   - Click the segment, verify the destination resolution mode (FQDN
     vs. wildcard vs. IP CIDR).
   - Verify the connector-group mapping covers a connector with
     network reach to the destination.

3. **For wildcard regressions**, compare the segment's domain set
   today against what the customer remembers configuring. The ZPA
   audit log shows segment edits.

4. **Force a ZCC re-enrollment** as a final shake-out: tray ->
   "Logout" -> "Login" -> wait for "AUTHENTICATED" state, then
   reproduce the access attempt. If the DNS check still fails after
   re-enroll, the segment really is absent.

**Don't:**

- Don't add `*` or `*.local` as the catch-all -- it routes everything
  through ZPA and overloads connectors.
- Don't bypass ZPA at the client level (`always_bypass` in the
  forwarding profile) for AD names -- the right fix is to add the
  AD segments to ZPA, not work around it.

---

## See also

* `zpa_app_not_reachable.md` -- companion detector. If a segment
  *does* exist for the queried name but the connector can't reach it,
  the failure surfaces there instead.
* `bypass_misconfiguration.md` -- shows the runtime bypass cache so
  you can confirm what ZCC actually believes is in / out of ZPA scope.
