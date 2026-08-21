# SOP: IdP redirect chain broken by SSL inspection

This document covers SSO failures where Zscaler SSL inspection
disrupts a redirect chain between a third-party app (typically a VPN
client) and the customer's IdP. Detected by
`zcc_diag/issues/idp_redirect_fail.py`.

The user-facing symptom is "VPN won't authenticate" or "SSO redirect
loops." The actual ZCC log signature is a cert error against an IdP
host (`login.microsoftonline.com`, `*.okta.com`, etc.) — not against
the VPN gateway itself. The customer's network is healthy, ZCC's
tunnels are up, and the VPN gateway hostname resolves and responds
fine.

Detection grounded in:
- an anonymized internal case (Example Tenant N AWS VPN). Ticket text
  observed: *"Our VPN typically requires a redirect to our IdP,
  Entra ID, but that redirect is not occurring when connected to
  Zscaler. Another VPN of ours, OpenVPN, does allow the redirect
  and successfully connects."*
- Similar pattern likely behind multiple AnyConnect tickets in the
  inventory (43734275938, 43585990802) — those weren't fully
  grounded but the failure shape matches.

---

## VPN SSO chain breaks at an IdP hop
<a id="idp-redirect-fail-vpn"></a>

**Detected when:** an SSL handshake / cert error fires against a
host in the IdP catalogue (Entra ID / Okta / Auth0 / Ping /
OneLogin / Google / Duo / JumpCloud SSO) AND, earlier on the same
thread, traffic was flowing to a known third-party VPN gateway
endpoint.

**What it means:** the VPN client delegated authentication to the
customer's IdP via HTTP redirect. Zscaler intercepted one of the
intermediate hops, resigned the cert, and the IdP refused the
resigned cert. The redirect chain dies silently — the VPN client
shows "auth failed" with no useful diagnostic.

**Triage steps:**

1. Identify both endpoints involved:
   - The IdP host the cert error fired against (visible in the
     finding's title).
   - The third-party VPN gateway in the same thread context
     (visible in the correlation window — look for the most
     recent VPN-vendor-suffixed `Host=...` line preceding the IdP
     error).
2. Add **BOTH** endpoints to the customer's BLSSL bypass:
   - The IdP host: e.g. `*.okta.com`, `login.microsoftonline.com`,
     `*.duosecurity.com`. Use star prefix for tenant subdomains.
   - The VPN gateway: e.g. the specific AWS Verified Access
     endpoint, Cisco AnyConnect concentrator FQDN, GlobalProtect
     portal, etc.
3. **Bypassing only one side leaves the chain still broken.** The
   redirect goes A → B → C → A; ZCC inspecting B or C breaks
   the chain even if A is exempt.
4. Push policy. Have the user retry the VPN connect. Auth should
   succeed within the redirect timeout (typically 30s).

**Operator workflow (Example Tenant N observed):**

The Example Tenant N case had an important diagnostic step: the customer
confirmed *another* VPN (OpenVPN) worked fine while AWS VPN failed.
That isolates the issue to the IdP-redirect dependency — OpenVPN
doesn't use SSO redirect, so it bypasses the broken hop.

When triaging similar tickets, ask the user *"is there another VPN
without SSO that you can test?"* — if yes, and it works, this
detector's diagnosis is confirmed.

---

## IdP cert error without obvious VPN context
<a id="idp-redirect-fail"></a>

**Detected when:** SSL inspection breaks a handshake against an IdP
host, but no VPN gateway appeared on the same thread within the
detection window.

**What it means:** the SSO chain in play is uncertain. It could be:
- A web app's SSO flow (Slack, Salesforce, custom SaaS).
- An IdP-managed device-registration / posture-check call.
- A legitimate cert error against the IdP itself (less common —
  major IdPs trust Zscaler intermediates if cert is current).

**Triage steps:**

1. Use the finding's correlation window to identify what was
   initiating the auth. Look for browser-style URLs or app names
   in adjacent records.
2. If the app is identifiable, treat as a standard
   [Bypass entry uses leading dot…](./bypass_misconfiguration.md#bypass-format-dot-vs-star)
   or [Gateway not in bypass](./bypass_misconfiguration.md#gateway-not-in-bypass)
   finding and add the IdP host to BLSSL.
3. If the app is unclear, add the IdP host to BLSSL anyway — IdP
   hosts are almost never legitimately broken by SSL inspection in
   a production tenant, and bypass is the right default.

---

## Entra ID rejected the user — AADSTS error code
<a id="aadsts-error"></a>

**Detected when:** the log contains an `AADSTS<N>` token (4-7
digits) surfaced from an Entra ID redirect response. The detector
includes a built-in catalogue of the most common codes; uncatalogued
codes still fire but with a generic description.

**What it means:** the IdP (Microsoft Entra ID) rejected the user's
sign-in attempt. **This is an IdP-side failure, not a Zscaler SSL-
inspection issue.** No amount of bypass configuration on the
Zscaler side will fix it; the fix lives in the customer's Entra
admin portal.

**Triage by code:**

| Code | Meaning | Fix |
|---|---|---|
| `AADSTS53003` | Conditional Access blocked | Check the user's CA policy assignment; device may need to be Intune-compliant or pass a location filter |
| `AADSTS50105` | User not assigned to Zscaler enterprise app | Entra admin → Enterprise Applications → Zscaler → Users and groups → Add user |
| `AADSTS50020` | User from external IdP not in tenant | Invite as B2B guest first |
| `AADSTS50158` | MFA challenge not satisfied | Verify the user has an MFA method registered |
| `AADSTS50012` | Invalid client secret | Rotate the secret in Entra and update the Zscaler app config |
| `AADSTS70008` | Authorization code expired | Usually clock skew; check device time and IdP request latency |
| `AADSTS65001` | User has not consented | Have admin grant consent on behalf of all users |
| `AADSTS50034` | User account does not exist | UPN typo on the Zscaler-side mapping, or user was deprovisioned |
| `AADSTS500011` | Resource principal not found | Service principal mismatch — the Zscaler enterprise app may have been deleted |
| `AADSTS900971` | No reply address provided | Zscaler app registration missing a Redirect URI |

**Triage steps:**

1. Identify the specific AADSTS code from the finding's title.
2. Apply the per-code fix from the table above.
3. If the code isn't in the table, search the Microsoft docs:
   `https://login.microsoftonline.com/error?code=<N>` redirects to
   the canonical explanation page for any AADSTS code.
4. **Coordinate with the customer's Entra admin** — the fix is
   always on their side, not yours.

**Why this is CRITICAL:** AADSTS failures block the user from
auth'ing entirely. Some codes (especially 53003, 50105) can
block an entire user group simultaneously when a policy changes —
those are high-blast-radius incidents.
