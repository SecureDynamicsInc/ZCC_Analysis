# SOP: ZPA authentication failures

This document covers ZPA-side authentication failures detected by
`zcc_diag/issues/zpa_auth_failures.py`. ZPA = Zscaler Private Access.

The complementary SOP for ZIA-side issues lives in
`zia_auth_failures.md`. The `[42000]` error and the generic
"An internal error occurred" message live there because Zscaler's docs
treat them as the canonical ZIA flow even though they affect both.

Each H2 below is anchored on a finding code emitted by the detector.

---

## SAML force-expired
<a id="saml-force-expired"></a>

**Detected when:** the tunnel log emits `saml force expired has been set`.

**What it means:** ZCC has explicitly invalidated the SAML assertion it
was holding and will request a fresh one. A handful of these per session
is normal (forced periodic re-auth). Many in a short window suggests the
fresh assertion isn't surviving — common causes:

1. The IdP URL is being intercepted by SSL inspection and the cert chain
   isn't trusted by ZCC.
2. The IdP traffic is being routed back through the Zscaler tunnel
   instead of going direct (bypass).
3. The IdP cookie domain doesn't match what ZCC expects.

**Triage steps:**

1. Confirm the IdP host is in the ZCC bypass list.
2. Verify the IdP host is exempted from SSL inspection in ZIA policy.
3. From the affected client, run:
   ```
   nslookup <idp-host>
   curl -v https://<idp-host>/  # check the cert chain
   ```
4. Compare cert chain returned to the client vs. the chain returned from
   an unaffected client. Mismatch == SSL inspection in the path.

---

## BRK_MT_SETUP_FAIL_SAML_EXPIRED
<a id="brk-mt-setup-fail-saml-expired"></a>

**Detected when:** broker microtunnel returns `BRK_MT_SETUP_FAIL_SAML_EXPIRED`.

**What it means:** ZCC presented a SAML assertion to the ZPA broker and
the broker rejected it as expired. Different from the `force expired`
case above — here the broker is the rejector.

**Most common root causes:**

1. **Clock skew** — client clock drifted > 5 minutes. Check via:
   ```
   w32tm /query /status   # Windows
   ```
2. **IdP session timeout < ZCC re-auth interval** — the IdP told ZCC the
   token was good for N minutes, but ZPA's policy enforces a tighter
   ceiling. Check the `saml_not_before` field in the
   `zpn_client_authenticate_ack` payload (visible in tunnel log).
3. **SSL inspection breaking the IdP path** — same as above.
4. **Repeated identical assertion size** in the log (e.g.
   `ZPA SAML size: 11460` over and over) means ZCC keeps presenting the
   same expired token.

**Triage steps:**

1. Force a sign-out and sign-in from the ZCC tray; capture a fresh log.
2. Validate clock sync against an authoritative NTP source.
3. Compare `saml_not_before` and `saml_not_on_or_after` claims (decode
   the assertion via [SAML decoder][1]).
4. If clock and claims look fine, escalate to IdP team to confirm
   session lifetime vs. ZPA tenant's `assertion_max_age`.

[1]: https://www.samltool.com/decode.php

---

## Broker: no ZPA policy matched the request
<a id="brk-mt-no-policy-found"></a>

**Detected when:** broker microtunnel returns `BRK_MT_SETUP_FAIL_NO_POLICY_FOUND`.

**What it means:** the ZPA broker received the microtunnel setup
request and found no app segment + access-policy pair that matched.
Either the destination isn't in any segment, or the user/group lacks
the access-policy rule granting this segment.

Grounded in real-bundle evidence (example-tenant-c-windows-17mb: 420
hits in a single captured window — the dominant failure mode in
that bundle).

**Triage steps:**

1. **Extract the `tag_id`** from the JSON record (the
   `{"zpn_mtunnel_end": {... "tag_id": N ...}}` payload). Cross-
   reference against the ZPA Admin Console to identify which app
   segment ZCC was trying to reach.

2. **First check: does a segment cover this destination at all?**
   ZPA Admin Console → Applications → Application Segments → search
   the destination hostname / FQDN / CIDR. If none match, this is
   purely a segment-gap problem. Add the missing segment.

3. **Second check: is there an access-policy rule that grants this
   user (or their group) access to that segment?**
   Policies → Access Policy → walk the rule set. The default
   posture is "implicit deny" — if no rule grants the user-segment
   pair, the broker emits `NO_POLICY_FOUND`.

4. **If `zpa_dns_check_not_found` is also firing,** the client-side
   DNS check is upstream symptom (the segment wasn't there at lookup
   time) and the broker-side NO_POLICY_FOUND is the same root cause
   surfacing later in the flow. Fix the segment / policy and both
   findings clear together.

5. **Don't:** don't add a catch-all "allow all" access-policy rule
   to make the finding go away. Identify the specific app segment
   that's missing and add a properly-scoped access rule for the
   correct user group.

---

## Broker: ZPA access policy denied the request
<a id="brk-mt-rejected-by-policy"></a>

**Detected when:** broker microtunnel returns `BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY`.

**What it means:** different from `NO_POLICY_FOUND` — here an
access-policy rule *did* match the request, and the matched rule
explicitly denied it. The user is authenticated and the segment
exists; the deny is intentional (whether by design or by mistake).

**Triage steps:**

1. **Extract the `tag_id`** to identify the destination segment.

2. **In ZPA Admin Console → Policies → Access Policy**, walk the
   rule list top-to-bottom for the first rule whose criteria match
   (segment + user + posture). That's the deny rule.

3. **Common patterns when the deny is unintentional:**
   - A broad deny rule was placed above the user's grant rule. Rules
     are evaluated top-to-bottom; the first match wins.
   - A negated criterion was misconfigured (e.g. "deny if user IS
     NOT in group X" actually fires for everyone outside group X).
   - A posture profile failure caused a posture-gated rule to fall
     through to a deny.

4. **If the deny is intentional and the user's complaint is "I can't
   reach this app",** explain that they don't have access; refer
   them to the application owner.

---

## BRK_MT_SETUP_FAIL (generic)
<a id="brk-mt-setup-fail-generic"></a>

**Detected when:** any `BRK_MT_SETUP_FAIL_*` reason that doesn't have a
dedicated section above.

**Triage:** treat as a network-layer broker problem first
(reachability, MTU, certificate). Cross-reference with:

- Tunnel-not-established findings.
- Resolved IPs for `gateway.<cloud>.net` and `broker*.<region>.prod.zpath.net`
  in the bundle summary.

---

## Webprobe HTTPS disabled
<a id="webprobe-https-disabled"></a>

**Detected when:** `BRK_MT_SETUP_FAIL_WEBPROBE_HTTPS_DISABLED`.

**What it means:** ZPA app segment is configured for an HTTPS web probe
but the probe is disabled at the broker level.

**Triage:** this is almost always a tenant-side config issue. Verify the
ZPA application segment definition in the admin console:

1. Application Segments → find the segment matching the destination
   in the same `ID=N` connection trace.
2. Confirm "Health Reporting" / "Application Discovery" settings.

---

## Application blocked by Private Access policy
<a id="pa-policy-blocked"></a>

**Detected when:** `Application access is blocked by Private Access policy`.

**Not an auth failure** — the user authenticated successfully but a ZPA
access-policy rule denied this specific app. Listed here because the
end-user experience looks like "login is broken."

**Triage:**

1. Find the connection ID (`ID=N`) on the failing line.
2. Use `find_connections_for_url` to extract the destination host.
3. ZPA Admin → Policies → Access Policy — match the destination against
   the rule set; check user-group membership.

---

## Auth state flapped
<a id="auth-state-flapped"></a>

**Detected when:** `getZpnAuthState` was observed transitioning between
states during the captured window.

**Healthy:** sits on `AUTHENTICATED`.

**Common transitions and meanings:**

| From | To | Likely cause |
|---|---|---|
| AUTHENTICATED | CONNECTING | Network change, sleep/wake |
| AUTHENTICATED | UNAUTHENTICATED | Token expired or rejected |
| CONNECTING | AUTHENTICATED | Healthy reconnect |
| CONNECTING | (loops) | Reachability or trusted-network flip |

**Triage:** correlate transition timestamps with `processOnNetProfile`
and trusted-network changes in the same log.

---

## Device certificate expired
<a id="device-cert-expired"></a>

**Detected when:** `Auth::Crypto::isCertificateExpired` reports `day: N`
where `N <= 0`.

**Critical.** Until renewed, ZIA/ZPA auth will fail.

**Triage:**

1. Identify the cert: the same log line includes `Certificate is not
   valid after: <date>`.
2. If it's the device-posture cert, re-enroll the device.
3. If it's a CA in the chain, refresh the trust store.
4. If it's the user's client cert (rare on Windows; common on macOS),
   re-issue from the IdP / cert authority.

---

## Private Access enrollment errors

The following sections cover the documented `42xxx` (and `2008`)
Private-Access enrollment error codes. Source: Zscaler Help Portal,
"Zscaler Client Connector: Private Access Authentication Errors".

The detector groups all 30+ codes into 5 logical buckets so the SOP
stays navigable. Each finding carries the specific code; all findings
in a bucket deep-link to the bucket section below.

### PA error: user input / domain identification
<a id="pa-error-user-input"></a>

**Codes in this group:** `2008`, `42000`, `42001`, `42029`, `42035`.

**What it means:** Private Access enrollment failed because of
user-input or username-domain mismatch.

| Code | Detail |
|---|---|
| 2008 | Authentication failed due to an invalid redirection URL. User likely delayed PA authentication. |
| 42000 | Inconsistency in user credentials. The user is presenting a different username (or IdP NameID) than at initial enrollment. |
| 42001 | User logged in without a domain in the username (e.g. `user` instead of `user@example.invalid`). |
| 42029 | Username domain isn't associated with this organization. |
| 42035 | Domain mismatch between the user's username and the domains configured on the org. |

**Triage:**

1. Verify the user is typing the same username they used at initial
   enrollment.
2. Check the IdP claim mapping — has the NameID source changed (e.g.
   from `mail` to `userPrincipalName`)?
3. Have the user log out via the ZCC tray and re-enroll fresh.
4. If 42029 or 42035 persist, verify the org's auth-domain list in the
   Admin Console: Identity → Authentication → Auth Domains.

---

### PA error: tenant / IdP configuration
<a id="pa-error-tenant-config"></a>

**Codes in this group:** `42002`, `42004`, `42005`, `42036`, `42037`,
`42039`, `42042`, `42043`, `42044`.

**What it means:** Tenant-side configuration problem on Zscaler. The
IdP isn't configured (or is disabled) for ZPA, or the SP/IdP mapping
is wrong.

| Code | Detail |
|---|---|
| 42002 | ZPA isn't configured for the company. No IdP found for enrollment. |
| 42004 | ZCC didn't send the expected information during enrollment. SSO config issue. |
| 42005 | ZPA couldn't interpret the info ZCC sent. SSO config issue. |
| 42036 | Couldn't verify the IdP entity ID. |
| 42037 | IdP is not enabled for admin SSO. |
| 42039 | Couldn't verify the SP configuration for this domain. |
| 42042 | Configured IdP is disabled for SSO on ZPA. |
| 42043 | IdP configuration is incomplete. |
| 42044 | IdP configuration has mismatched SSO type/usage. |

**Triage:**

1. ZPA Admin Console → Identity → IdP Configuration → confirm an IdP
   is configured for User SSO (and Admin SSO if 42037/42033 are seen).
2. Verify the IdP's entity ID in the Zscaler config matches the IdP
   side exactly — case-sensitive.
3. Verify the SP metadata configured at the IdP matches what Zscaler
   publishes for that tenant.
4. For 42042, the IdP is disabled — re-enable in the Admin Console.

---

### PA error: SAML validation
<a id="pa-error-saml-validation"></a>

**Codes in this group:** `42006`, `42013`, `42014`, `42015`, `42016`,
`42017`, `42018`, `42019`, `42020`, `42021`, `42022`, `42032`, `42033`,
`42034`, `42045`.

**What it means:** Private Access rejected the SAML response from the
IdP. The response was either malformed, signature-invalid, or the
assertion conditions failed.

| Code | Detail |
|---|---|
| 42006 | Generic SAML response validation failure. Often clock skew, expired IdP cert, signature mismatch, or entity-ID lookup failure. |
| 42013 | Response is not the expected SAML response object type. |
| 42014 | SAML response status is unsuccessful. |
| 42015 | SAML response signature failed validation. IdP cert may be misconfigured or expired. |
| 42016 | Clock skew >120s between IdP and ZPA. **The detector extracts and quotes the actual timestamps from the message.** |
| 42017 | IdP-initiated SSO not supported. ZPA only supports SP-initiated SSO. |
| 42018 | ZPA couldn't find the SAML request matching this response. |
| 42019 | SAML response destination doesn't match any configured endpoint. |
| 42020 | Issuer in SAML response failed validation. Entity ID is case-sensitive. |
| 42021 | Assertion validation failed: too old, `notBefore` not yet, `notOnOrAfter` already passed. |
| 42022 | NameID is missing from the SAML response. |
| 42032 | IdP issued a SAML assertion with a `OneTimeUse` condition. Not supported. |
| 42033 | Couldn't validate SAML response for the Private Access admin. |
| 42034 | Couldn't validate SAML response for the Private Access user. |
| 42045 | SAML assertion is too large. |

**Triage:**

1. **42016 / 42021 first** — clock skew is the most common cause of the
   whole group. Check the client and IdP clocks against an authoritative
   NTP source. The 42016 finding includes the exact IdP-issue-time and
   accepted-range from the message.
2. **42015 / 42020** — verify the IdP signing certificate is current and
   matches what Zscaler has configured. Verify the entity ID
   character-for-character.
3. **42022** — the IdP isn't including NameID in the assertion subject.
   Fix the IdP's claim mapping.
4. **42017 / 42032** — fix the IdP to use SP-initiated SSO and to not
   issue `OneTimeUse` assertions.
5. Use a SAML decoder (e.g. `samltool.com/decode.php`) to inspect the
   raw assertion if needed.

---

### PA error: certificate / CA / signing
<a id="pa-error-certificate"></a>

**Codes in this group:** `42007`, `42023`, `42024`, `42025`, `42026`,
`42046`, `42047`, `42048`.

**What it means:** Certificate or signing-key problem on the
Private Access enrollment path.

| Code | Detail |
|---|---|
| 42007 | Certificate signing request failed during enrollment. |
| 42023 | ZCC CA (signing) certificate is expired. |
| 42024 | ZCC CA certificate is missing. |
| 42025 | Private key for ZCC CA certificate is missing. |
| 42026 | ZCC failed to obtain a valid client certificate for this user. |
| 42046 | All IdP signing certificates have expired. |
| 42047 | SAML request signing certificate has expired. |
| 42048 | SAML request signing certificate is invalid. |

**Triage:**

1. **42023 / 42024 / 42025** — provision a valid CA certificate for
   ZCC. Admin Console → Mobile Admin → CA / Cert Management.
2. **42046 / 42047 / 42048** — IdP signing cert needs to be rotated.
   Update the IdP config to upload a current certificate.
3. **42007 / 42026** — broader enrollment-path failures; usually
   contact Zscaler Support.

---

### PA error: internal / capacity
<a id="pa-error-internal"></a>

**Codes in this group:** `42010`, `42027`, `42028`, `42030`, `42031`,
`42038`, `42040`.

**What it means:** Internal Zscaler errors, capacity limits, or
catch-all conditions.

| Code | Detail |
|---|---|
| 42010 | Missing expected information during enrollment. |
| 42027 | Org has reached its maximum allowed users. |
| 42028 | Missing or unexpected info in enrollment request. |
| 42030 | Couldn't look up the user's organization. |
| 42031 | Couldn't authorize ZCC enrollment request. |
| 42038 | Internal: Object Store insert failed. |
| 42040 | Internal: encryption failed. |

**Triage:**

1. **42027** — review the org's PA license vs. user count. Either
   remove unused users or upgrade subscription.
2. All other codes in this group: capture a fresh bundle and contact
   Zscaler Support. These are server-side conditions the customer
   cannot directly remediate.
