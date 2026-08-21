# ZPA re-authentication loop

## What this finding means

ZCC's tray-log state machine logged repeated transitions of `ZPA Auth
state changed, From: AUTHENTICATED To: AUTHENTICATION_REQUIRED`.
Each transition is one **IdP session expiry** — the upstream identity
provider told ZPA "this user's SAML/OIDC token is no longer valid,"
and ZPA's broker turned that into a re-authentication prompt.

The detector reports the *cadence* (median interval between expiries),
the *time-of-day clustering* (whether the first expiry of every day
fires at the same hour), the *user recovery time* (how long the user
takes to re-auth when prompted), and any *tray crashes* correlated
with the expiry events.

Three patterns to read off the report:

1. **Cadence ≈ 90 minutes, time-clustered at user's login hour, IdP
   = Azure AD/Entra ID** → almost always Conditional Access Sign-in
   Frequency. See first section below.
2. **Cadence ≈ 60 minutes (1 hour), no time clustering** → likely
   the IdP's default access-token lifetime expiring without refresh.
3. **Cadence ≈ 15 minutes, irregular** → typically an MFA challenge
   policy or a session-cookie problem; see "Short cadence" below.

---

## Azure AD Conditional Access Sign-in Frequency

This is the most common cause of a clean ~90-min cadence pattern, and
it's what the Example Tenant A-2026-06-18 bundle that drove this detector showed.

### What's happening

Microsoft Entra ID (Azure AD) has a Conditional Access policy that
includes **Session controls → Sign-in frequency** set to 1.5 hours
(or another value below ZPA's configured Idle Timeout). When the
configured interval elapses, AAD invalidates the SAML assertion for
the Zscaler app, ZPA's broker rejects the next tunnel setup with
`BRK_MT_SETUP_FAIL_SAML_EXPIRED`, and ZCC prompts the user.

### Confirmation steps

1. In the **Entra ID admin center** → Protect → Conditional Access →
   Policies, list every policy and look for one that:
   - Targets the **Zscaler Private Access** application (or the
     user's group)
   - Has **Session controls → Sign-in frequency** set
   - Note the configured value (1-24 hours typical)

2. Cross-check the tenant-wide token lifetime policy:
   ```powershell
   Get-AzureADPolicy |
     Where-Object { $_.Type -eq "TokenLifetimePolicy" }
   ```
   If a policy applies to the Zscaler service principal with
   `AccessTokenLifetime: 01:30:00`, that's the source.

3. Check whether **MFA on every sign-in** is in effect for the
   target user / app — MFA + short Sign-in frequency = the
   observed behaviour.

### Recommended fix

Pick the right Sign-in frequency for the customer's compliance
posture:

- **8 hours** — common for general workforce, balances security
  and productivity. Aligns with one workday.
- **12 hours** — common for power users + persistent VPN-replacement
  ZPA use cases.
- **24 hours** — for users on managed devices with strong MDM.
- **Remove the override entirely** — let AAD's default behaviour
  (1h ID token, 90d refresh, 24h session) apply. Often the right
  call if no compliance constraint requires shorter.

ZPA's own Idle Timeout should be set ≥ the chosen IdP frequency
so it doesn't trigger first. ZPA's Auth Timeout sets the absolute
maximum.

---

## Okta Authorization Server access-token lifetime

### What's happening

Okta's Authorization Server access policies set per-rule
**Access token lifetime**. Default is 1 hour. Some compliance
configurations shorten this to 15-90 min.

### Confirmation steps

1. Okta admin → Security → API → Authorization Servers → the
   server used by the Zscaler integration → **Access Policies**
   tab → check each Rule's **Access token lifetime**.

2. Check Security → Authentication Policies — the policy
   applied to the Zscaler app may include
   **Re-authenticate after**.

3. Check sign-on policies (Admin → Security → Authentication
   Policies → Global Session Policy) for Zscaler-specific rules
   forcing re-challenge.

### Recommended fix

Raise access-token lifetime to at least the customer's ZPA
Idle Timeout. Refresh tokens handle silent renewal up to the
refresh-token lifetime.

---

## ADFS TokenLifetime

### Confirmation steps

```powershell
Get-AdfsRelyingPartyTrust -Name "<Zscaler RP Trust Name>" |
  Format-List TokenLifetime, *Claim*

Get-AdfsProperties | Format-List SsoLifetime
```

`TokenLifetime` of 0 means "use the global SsoLifetime" (default
480 min = 8 hours). A non-zero value overrides for this RP.

### Recommended fix

Set `TokenLifetime` to 0 (use global default) or align with the
customer's other apps. Make sure `Get-AdfsProperties` SsoLifetime
isn't unexpectedly short.

---

## Short cadence (≈ 15 min, irregular)

If the detector reports a short median (under 30 min) AND the
cadence is irregular (high variance), the cause is usually one
of:

- **MFA Remembered-Device policy** with a short expiration
  forcing re-MFA without re-SSO. The user sees prompts on the MFA
  cadence even though the SSO session is still valid.
- **Session cookie storage problem** — ZCC's embedded auth
  WebView lost the cookie store, so every tunnel setup looks like
  first-login. Check whether `WebView2Process` is being launched
  by a non-Zscaler parent (look for the
  `[CheckWebView2Process] msedgewebview2.exe is not directly
  launched by a Zscaler process` warning).
- **Network changes** breaking sticky-session affinity to the
  broker.

---

## Tray-crash correlation

If the report shows expiries correlated with `ZSATray.exe.<pid>.dmp`
files (timestamps within 60 s), that's a tray-side defect handling
the auth-required RPC. The user never sees the prompt because the
tray crashed before rendering it; the session sits in
`AUTHENTICATION_REQUIRED` state until ZCC restarts.

Escalation pattern:

1. Collect every `ZSATray.exe.<pid>.dmp.zip` file from the bundle.
2. Open a Zscaler support ticket and attach the dumps + the
   relevant tray-log slice ±2 min around each crash.
3. Note that the crash is **secondary** to the IdP issue. Fix the
   IdP frequency first; the tray crash is a Zscaler-side bug
   that should still be reported but doesn't fix the customer's
   experience on its own.

---

## What this detector replaces

In an earlier cut (Phase 34, 2026-06-19 morning) this detector
counted `ZSATUNNEL_ZPN_AUTHENTICATION_REQUIRED` RPC notifications.
That number is the broker's per-tag_id retry rate (many per actual
expiry) — not the true IdP-expiry rate. The Phase 40 rewrite
switched the primary signal to ZSATray's
`ZPA Auth state changed → AUTHENTICATION_REQUIRED` transitions, which
fire exactly once per IdP-driven expiry.

The RPC count is still reported as a "for context" tally so the
engineer can see the broker amplification factor: a 90-min expiry
cadence can generate 5-10× as many RPC events when ZCC keeps
retrying every failed session.

---

## Customer-facing message template

> Your ZCC bundle shows {N} ZPA re-authentication events over the
> {duration} capture window, at a median cadence of {X} minutes.
> The first re-auth event of every day fired in the {HH}:00 hour
> across {Y} days — that alignment with your login time is the
> signature of an upstream identity-provider Sign-in Frequency
> policy.
>
> Your configured ZPA Auth Timeout ({A}) and Idle Timeout ({I})
> are well above this cadence, meaning ZPA itself isn't what's
> forcing the prompts. The most likely cause is a {IdP-family}
> session-lifetime policy applied to your Zscaler app.
>
> [Tailored IdP recommendations follow.]
