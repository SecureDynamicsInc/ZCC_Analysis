# SOP: ZIA authentication failures

This document covers ZIA-side authentication failures detected by
`zcc_diag/issues/zia_auth_failures.py`. ZIA = Zscaler Internet Access.

The complementary SOP for ZPA-side issues (broker / SAML rejected by
ZPA, plus the documented `42xxx` Private Access enrollment error
codes) lives in `zpa_auth_failures.md`.

> The generic "An internal error occurred" message is the canonical ZIA
> "Authentication Internal Error" symptom — usually an auth-domain
> provisioning mismatch on the tenant.

---

## Mobile API: keepAlive error
<a id="mobile-api-keepalive-error"></a>

**Detected when:** the URL `mobile.<cloud>.net/api/mobile/policy/v2/keepAlive`
returns a JSON response with an `error` field set to a non-zero number.

**What it means:** the client periodically calls keepAlive to renew its
ZIA session. Failure means the server-side session record was lost,
expired, or the request was rejected.

**Common error codes** (paraphrased from Zscaler's documented mobile API):

| Error | Meaning | First step |
|---|---|---|
| 51 | Session expired / token invalid | Sign out, sign back in. |
| 52 | Device record missing | Force a re-enrollment from the tray. |
| 53 | Tenant policy blocked the device | Check ZCC enrollment policy. |
| Other | Generic API error | Capture a fresh bundle, escalate to TAC. |

**Triage:**

1. From the same client, sign out via the ZCC tray.
2. Sign in again. Capture a fresh bundle. Confirm the `error` field is
   now absent / `0`.
3. If the same code persists, check the ZIA admin portal:
   Administration → Authentication Settings → User Auth.

---

## Mobile API: policy download error
<a id="mobile-api-policy-download-error"></a>

**Detected when:** `policy/v2/download` returns an `error`.

**What it means:** ZCC could not fetch its forwarding/app/posture policy
from the tenant. Until this succeeds, ZCC operates with stale policy
(or none).

**Triage:**

1. Confirm `mobile.<cloud>.net:443` is reachable from the client (the
   bundle summary's `service_edges` field shows the resolved IPs).
2. Confirm the user is provisioned: ZIA Admin → Administration → User
   Management.
3. If a captive-portal exemption was added recently, verify it didn't
   accidentally block `mobile.<cloud>.net`.

---

## Mobile API: device unregister error
<a id="mobile-api-unregister-error"></a>

**Detected when:** `device/unregisterDevice` returned an error.

**What it means:** the client tried to clean up its enrollment but the
tenant rejected the request. Usually benign (the device record was
already gone) but a stream of these means ZCC keeps trying to re-enroll
and the server keeps refusing.

---

## Mobile API: generic device error
<a id="mobile-api-device-error"></a>

**Detected when:** any `/api/mobile/device/...` endpoint returned an
error not specifically handled above.

**Triage:** capture a fresh bundle and check the JSON response body for
the full error context (visible in the same record's raw line).

---

## Mobile API: generic error
<a id="mobile-api-generic-error"></a>

**Detected when:** any other mobile API endpoint returned an `error`.

**Triage:** identify the path (visible in the evidence record), look up
the error code in Zscaler's API documentation for that endpoint.

---

## HTTP 407 from ZIA Service Edge
<a id="http-407"></a>

**Detected when:** `SME response: ... Status: 407` in the tunnel log.

**Acceptable transiently.** Sustained 407s mean:

1. The auth cookie was lost (browser flush, profile reset, ZCC restart
   without proper sign-in).
2. The captive-portal exemption broke and the edge thinks the user
   needs web-based auth.
3. PAC pushed traffic to the edge before auth completed.

**Triage:**

1. Sign out + sign in via ZCC tray; capture a fresh bundle.
2. If 407s persist, inspect `summary.captive_portal` and
   `summary.forwarding_profile`.

---

## Forced device unregister
<a id="forced-unregister"></a>

**Detected when:** ZCC called `device/unregisterDevice` (regardless of
response).

**Why it matters:** ZCC self-triggers re-enrollment when policy pushes
fail repeatedly. A stream of unregisters means the client is stuck in
an enrollment loop.

**Triage:**

1. Count the unregisters in the bundle.
2. If > 3 in an hour, this is the smoking gun. Cross-reference with
   keepAlive / policy-download errors at the same timestamps.
3. Force a clean re-enroll: uninstall ZCC, reboot, reinstall, sign in
   fresh.

---

## ZTUI service-bus failure
<a id="ztui-bus-fail"></a>

**Detected when:** `ZTUI failed to send ZTunnel Status`.

**What it means:** the tray UI couldn't reach the ZCC service over its
local IPC bus. Common causes:

1. The service crashed (check Windows Event Viewer for ZSAService).
2. Endpoint AV blocked the IPC channel (this overlaps with issue #3,
   FW/AV errors).
3. ZSAService is stuck waiting on a slow HTTP call to the tenant.

**Triage:**

1. `services.msc` → confirm ZSAService is running.
2. If running, restart it. If not, check Event Viewer for crashes.
3. Cross-reference timestamps with FW/AV-error findings.

---

## SME proxy in bad state
<a id="sme-proxy-bad-state"></a>

**Detected when:** `getSmeProxyState` reported one of:
`SERVER_AUTH_ERROR`, `SERVER_AUTH_TERMINATED_AT_UNKNOWN`.

| State | Means | First step |
|---|---|---|
| SERVER_AUTH_ERROR | Edge actively rejected the auth credentials. | Sign out + sign in. If persists, check ZPA detector for matching `42xxx` enrollment errors and verify auth-domain provisioning. |
| SERVER_AUTH_TERMINATED_AT_UNKNOWN | Chaining auth error: realm/user mismatch (intermediate proxy intercepted auth). | Check upstream proxy / SSL inspection that's intercepting the auth request. This is the "Intermediate Authentication Error" / "Chaining Authentication Error" surface in the tray. |

> **Network-layer states moved.** `SERVER_DOWN_ERROR`,
> `ADAPTER_DOWN_ERROR`, `INTERNET_UNREACHABLE_ERROR`,
> `SERVICE_DOWN_ERROR`, `SYSTEM_SOCKETS_EXHAUSTED_ERROR` used to be
> reported here. They now belong to the `tunnel_not_established`
> detector -- see `tunnel_not_established.md`.

> Note: `TURNED_OFF` is **not** an error -- it just means ZIA forwarding
> is disabled in the active forwarding profile. Some bundles you'll see
> are ZPA-only and `TURNED_OFF` will be the only state observed.

---

## ZIA Authentication Internal Error
<a id="auth-internal-error"></a>

**Detected when:** "An internal error occurred" co-occurs with auth /
SAML / credential / login / enroll / policy keywords.

**Per Zscaler's troubleshooting guide,** this is the canonical "ZIA
Authentication Internal Error" symptom. Root cause is usually:

1. The user's email domain is not provisioned on the Zscaler tenant.
2. The IdP claim doesn't match what Zscaler expects (case, domain).
3. The tenant has multiple IdPs configured and the user's domain isn't
   linked to the right one.

**Triage:**

1. Identify the user's email domain (visible in the SAML assertion;
   sidecar JSON has the redacted -> raw mapping).
2. ZIA Admin → Administration → Authentication Settings →
   Authentication Profile → check Auth Domains list.
3. If the domain is missing, file an Auth Domain Provisioning Request
   with Zscaler support.
4. If present, verify the IdP claim mapping matches.

---

## macOS Mobile API failure
<a id="mac-mobile-api-failure"></a>

**Detected when:** on a macOS bundle, `Auth::Lib::executeMobileAdminPostAPI:
Response: <CODE>` in `ZSATray*.log` shows a non-2xx HTTP code.

**Why this is different from the Windows finding:** on Windows ZCC logs
the entire Mobile API call (request + response body) on a single
`Tunnel api request: {...} response: {...}` line in `ZSATunnel`, and
the failure signal is the `"error":N` field inside the JSON body. On
macOS the call sequence is logged as a multi-line trace in `ZSATray`:

```
INF Auth::Lib::executeMobileAdminPostAPI: Begin
INF Auth::Lib::executeMobileAdminPostAPI: Trial: 0
INF Auth::Lib::executeMobileAdminPostAPI: https://mobile.<cloud>.net/api/mobile/policy/forceKeepAlive
INF Auth::Lib::executeMobileAdminPostAPI: Response: 200, Length: 772
INF Auth::Lib::executeMobileAdminPostAPI: Finish
```

The detector groups the in-flight URL with its response status code
(matched by pid+tid) and fires when the code is non-2xx.

**What the codes typically mean:**

| Code | Likely meaning |
|---|---|
| 401 | Session expired -- sign out / sign back in. |
| 403 | Tenant policy blocked the device -- check ZCC enrollment policy. |
| 407 | Upstream proxy requires auth (corporate proxy in the path). See [HTTP 407 from ZIA Service Edge](#http-407-from-sme). |
| 5xx | Zscaler service edge-side failure -- usually transient; if persistent, check Zscaler trust portal status. |

**Triage:**

1. **Identify the endpoint.** The finding's evidence and code group
   include the path (e.g. `/api/mobile/policy/forceKeepAlive`,
   `/api/mobile/policy/v2/forcePolicyDownload`).
2. Apply the same triage as the corresponding Windows finding:
   - keepAlive failures: see [Mobile API: keepAlive error](#mobile-api-keepalive-error)
   - policy download failures: see [Mobile API: policy download error](#mobile-api-policy-download-error)
   - unregister failures: see [Mobile API: device unregister error](#mobile-api-unregister-error)
3. Cross-reference the tunnel detector's findings -- a Mobile API
   failure paired with `SERVER_DOWN_ERROR` transitions suggests the
   ZIA service edge itself is the problem, not the mobile admin path.

---

## OneID / OIDC device registration failed
<a id="oneid-device-registration-fail"></a>

**Detected when:** the log emits
`ERR One::ID::Device <ZIA|ZPA> registration fail with error: <N>`.
The product token (`ZIA` or `ZPA`) and the integer error code go
into the finding code (`ONEID_DEVICE_REG_FAIL_<PRODUCT>_<CODE>`).

**What it means:** ZCC's OneID library handles the OAuth/OpenID-
Connect device-registration flow against the customer's IdP. When
this fails, the device cannot get a valid OneID session token, and
**both ZIA and ZPA auth subsequently fail in cascading fashion**:

- ZPA broker → empty SAML assertion → `SERVER_AUTH_ERROR`
- ZIA mobile API → 401 / unauthorised on subsequent keepAlive calls
- ZCC tray → stuck in `REGISTRATION_REQUIRED` state
- ZPHM → force-stop loop (the `zphm_force_stop_loop` detector picks
  this up as a separate WARN-level downstream symptom)

**Grounded in a synthetic reference bundle**, which exhibits:

- `ERR One::ID::ZS_Device_Registration_ZIA_Req failed type 3, errCode: -9, reason: App Internal Error, Please Contact Administrator.`
- `INF One::ID::error on service: ZS_Device_Registration_ZIA_Req type: 3, err code: -9, error = App Internal Error, Please Contact Administrator.`
- `ERR One::ID::Device ZIA registration fail with error: -9`
- Same trio for `ZS_Device_Registration_ZPA_Req`

The `-9` code surfaces as `App Internal Error, Please Contact
Administrator` — a generic catch-all that hides the actual upstream
fault.

**Triage:**

1. **Open the finding's correlation window** (±5 min around the
   error timestamp). Look earlier on the same thread for:
   - `One::ID::initiate http request to URL:
     https://<tenant>.zslogin.net/.well-known/openid-configuration`
     -- the OIDC discovery call. Response must be 200 with a valid
     JSON document.
   - `One::ID::launch browser for user authentication with
     https://<tenant>.zslogin.net/oauth2/v1/authorize?...` -- the
     browser-based authorize redirect.
2. **Verify the OIDC tenant config is reachable.** In a browser:
   open the discovery URL from step 1 directly. Should return a
   JSON document with `authorization_endpoint`, `token_endpoint`,
   `jwks_uri`. If it 404s or 5xx's, the customer's tenant is
   misconfigured on the Zscaler side -- raise a Zscaler support
   case.
3. **Confirm the user actually completed the browser flow.** ZCC
   logs `launch browser for user authentication` and waits for the
   redirect callback. If the user closed the browser, abandoned the
   flow, was blocked by a corporate proxy, or hit a redirect-chain
   break (see `idp_redirect_fail` detector), the registration call
   comes back failed with errCode -9.
4. **If the IdP succeeds but ZCC still reports -9**, the OneID
   library couldn't reconcile the IdP's response with the user's
   expected tenant binding. Check ZIA admin →
   Administration → Authentication Settings for the user's email-
   domain → auth-domain mapping. The mapping must include the
   user's exact email domain, and the tenant must be flagged as
   OIDC-enabled.
5. **Cross-check the `zpa_auth_failures` detector's findings.** If
   `BRK_MT_SETUP_FAIL_SAML_EXPIRED` or `ZPA SAML size: 0` are also
   firing, they're cascading consequences of the OneID failure --
   fixing OneID will also clear those.

**Why this is CRITICAL severity:** OneID is the auth front-end for
both ZIA and ZPA. A persistent OneID failure blocks the user from
either product entirely. False positives are rare (the regex
matches an explicit error log line; transient OneID failures
during normal sign-in cycles produce different log shapes).

---

## OneID keep-alive returned 401 INVALID TOKEN
<a id="oneid-keepalive-401"></a>

**Detected when:** the log emits
`ERR One::ID::ZS_Keep_Alive_Req http status code 401`.

**What it means:** ZCC's OneID library tried to keep its session
token alive against the IdP and the IdP rejected the token. The
content of the error is typically `content: INVALID TOKEN, reason:
Unauthorized`.

Common causes:

- IdP-side session expired (refresh-token lifetime elapsed)
- Admin revoked the user's session manually
- Conditional-access policy change on the IdP forced re-auth
- Clock skew on the device (the JWT `exp` claim is past, IdP
  considers it expired even though the device thinks it's valid)

**Triage:**

1. **Single 401 is usually benign.** ZCC will trigger a re-auth
   prompt and recover. No action needed unless the symptom is
   user-reported.
2. **Sustained 401s** (more than ~3 in 10 minutes) indicate a stale
   local token that needs cleanup. From the ZCC tray:
   *More → Troubleshoot → unregisterDevice* (forces a fresh OneID
   sign-in cycle on next launch).
3. **All-users 401** pattern (multiple bundles from the same tenant
   showing this same finding) suggests a tenant-side IdP config
   change broke the existing session class. Check IdP admin for
   recent conditional-access or token-lifetime policy changes.
4. **Cross-check device clock**: `w32tm /query /status` on Windows,
   `sntp -s time.apple.com` on macOS. >5-min skew breaks JWT
   validation.

---

## ZPN client-authenticate handshake failed
<a id="zpn-client-authenticate-fail"></a>

**Detected when:** the log contains the verbatim token
`ERR_zpn_client_authenticate`. Source: Zscaler help docs (Kerberos /
ZIA auth error codes page).

**What it means:** the client-side auth handshake against the
Public Service Edge failed for an unspecified reason. Almost always
a *downstream symptom* of a more specific failure earlier on the
same thread (OneID registration fail, SAML expiry, mobile-API
rejection).

**Triage steps:**

1. Open the finding's correlation window (±5 min).
2. Look for upstream findings on the same bundle that would explain
   the auth failure:
   - `ONEID_DEVICE_REG_FAIL_*` -> OneID handshake broke; fix that
     first.
   - `MOBILE_API_ERROR_KEEPALIVE_*` -> Mobile API rejected the
     session; fix that first.
   - `SAML_FINGERPRINT_MISMATCH` -> IdP cert rotation propagation;
     fix that first.
3. If no upstream finding fires, this is a Zscaler-side glitch
   worth a TAC ticket — include the verbatim
   `ERR_zpn_client_authenticate` line in the case notes.

---

## SAML assertion signing-certificate fingerprint mismatch
<a id="saml-fingerprint-mismatch"></a>

**Detected when:** the log contains the verbatim token
`BRK_MT_AUTH_SAML_FINGER_PRINT_FAIL`. Source: Zscaler help docs
(microtunnel setup failures reference).

**What it means:** the SAML assertion that the IdP returned was
signed with a certificate whose fingerprint doesn't match what the
Zscaler tenant config has on file. The IdP-side certificate was
rotated, but the new certificate (or its fingerprint) wasn't
uploaded to Zscaler.

**Triage steps:**

1. In the customer's IdP (Entra ID / Okta / Ping / etc.), export
   the **current** SAML signing certificate. It will be a `.cer` or
   `.pem` file containing the public key.
2. In ZIA admin → Administration → Authentication Settings → SAML,
   replace the existing certificate (or update the configured
   fingerprint) with the new one from step 1.
3. Have the affected user sign out of ZCC and sign back in. The
   new SAML response will match the updated fingerprint.
4. **Preventive**: ask the customer's IdP team to add Zscaler to
   their cert-rotation runbook so this doesn't happen again. Most
   IdPs rotate the SAML signing cert on a documented schedule
   (Entra: 3 years, Okta: 5 years by default).

**Why this is CRITICAL:** every user authenticating against this
IdP will fail until the cert is updated on the Zscaler side. The
blast radius is "entire tenant," not "individual user."
