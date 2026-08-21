# SOP: Cert-pinned SaaS broken by SSL inspection

This document covers SSL inspection failures against the canonical
"must-bypass" SaaS apps Zscaler itself documents as cert-pinning.
Detected by `zcc_diag/issues/cert_pinned_saas_inspection.py`.

The user-visible symptom is a SaaS app that "just doesn't work" —
Outlook won't sync, Teams calls drop, Dropbox shows persistent
errors, FaceTime can't connect. The fix is always the same: add
the vendor's endpoints to the customer's BLSSL bypass list.

Detection grounded in:
- Zscaler help docs (`help.zscaler.com/zia/zscaler-traffic-bypasses`)
  verbatim: *"Zscaler cannot inspect TLS traffic from sites or
  applications that use certificate pinning including Microsoft 365
  and apps like WebEx, Dropbox and others."*
- Zscaler community discussions confirming the standard bypass list
  for cert-pinned SaaS apps.
- Real-bundle confirmation: the Example Tenant C calibration bundles
  show 50+ Microsoft 365 + Zoom hosts already in bypass cache,
  validating that mature tenants bypass these by default.

---

## SSL inspection breaking a cert-pinned SaaS endpoint
<a id="cert-pinned-saas-inspection"></a>

**Detected when:** an SSL handshake / cert validation failure fires
on a tunnel-log thread whose most recent `Host=...` line names a
host in the cert-pinned SaaS catalogue (Microsoft 365, Apple, WebEx,
Dropbox, GoTo / LogMeIn, Salesforce, Zoom), AND that host is NOT in
the customer's runtime bypass cache.

**What it means:** the SaaS vendor pins its certificate. ZCC's
inspection-and-resign approach replaces the cert with a Zscaler-
signed copy mid-flight, the SaaS client refuses to trust it, and
the user-facing app breaks. This isn't a network failure or a Zscaler
infrastructure issue — it's a policy gap.

**Triage steps:**

1. **Identify the vendor.** The finding title names it (e.g.
   "SSL inspection breaking Microsoft 365 (Outlook)").
2. **Add the vendor's endpoints to BLSSL bypass.** Recommended
   wildcards by vendor:
   - **Microsoft 365**: `*.outlook.office.com`, `*.teams.microsoft.com`,
     `*.sharepoint.com`, `graph.microsoft.com`, `*.office.com`,
     `*.office365.com`, `*.microsoft365.com`. Alternative: use the
     Zscaler built-in "Microsoft 365" cloud-app category which
     bundles the full list.
   - **Apple**: `*.icloud.com`, `*.apple.com`, `*.itunes.apple.com`,
     `*.apple-cloudkit.com`, `*.facetime.apple.com`.
   - **WebEx**: `*.webex.com`, `*.webexcontent.com`.
   - **Dropbox**: `*.dropbox.com`, `*.dropboxusercontent.com`.
   - **GoTo / LogMeIn**: `*.gotomeeting.com`, `*.goto.com`,
     `*.logmein.com`.
   - **Salesforce**: `*.salesforce.com`, `*.force.com`.
   - **Zoom**: `*.zoom.us`, `*.zoomgov.com`.
3. **Push the policy.** Have the affected user retry the failing
   action. Cert error should disappear immediately (no client-side
   cache to clear).
4. **Audit other vendors.** If one cert-pinned SaaS is missing from
   bypass, others probably are too. Use the calibration corpus's
   Example Tenant C bundles as a reference of what a fully-configured
   tenant looks like (85-97 bypassed hosts).

**Why this is CRITICAL:** these SaaS apps are the customer's daily
productivity stack. Outlook not syncing affects every user; Teams
not calling is a same-day incident. The fix is a single policy
push that resolves the issue across the entire tenant.

---

## Why this detector is separate from `bypass_misconfiguration`

`bypass_misconfiguration` fires when a cert-pinned gateway (JumpCloud,
Ariba, SimplePractice — partner/SSO-class endpoints) is missing
from bypass. `cert_pinned_saas_inspection` fires for the broader
end-user SaaS class (M365, Apple, WebEx, Dropbox, Zoom — the canonical
"must-bypass" list Zscaler itself publishes).

In practice both detectors can fire on the same bundle — they're
complementary. `bypass_misconfiguration` covers gateways the
customer chose to integrate; `cert_pinned_saas_inspection` covers
the universally-cert-pinned consumer SaaS apps.
