# SOP: RMM agent cert pinning

This document covers SSL inspection failures against RMM (Remote
Monitoring & Management) agent endpoints, detected by
`zcc_diag/issues/rmm_agent_pin.py`.

The user-facing symptom is "our RMM platform stopped reaching
endpoints" or "Datto / Kaseya / NinjaOne stopped seeing this site's
agents." The root cause is almost always Zscaler SSL interception
breaking the agent's pinned cert handshake. Fix is a policy edit,
typically BLSSL bypass + a File Type Control exception.

Detection grounded in:
- an anonymized internal case (Example Tenant E Datto). observed from the
  Zoom AI summary: the resolution added Amazon S3 East URL to file-
  type control to allow Datto-style RMM payloads through.
- an anonymized internal case (Example Tenant F Datto Unanet block).
  PDF/binary block on Datto/Unanet traffic was the trigger.

This pattern is the second-most-common "Zscaler broke our tooling"
report we've seen across the 50-ticket grounding sweep, after AI
tools.

---

## SSL inspection breaking an RMM agent endpoint
<a id="rmm-agent-pin"></a>

**Detected when:** an SSL handshake / cert validation failure fires
on a tunnel-log thread whose most recent `Host=...` line names a
host in the RMM vendor catalogue (Datto, Kaseya, NinjaOne,
ConnectWise Automate, N-able, Atera, Intune-Manage endpoints,
etc.).

**What it means:** the RMM vendor pins their agent certificate. ZCC
inspects-and-resigns the connection mid-flight; the agent rejects
the resigned cert and the management channel breaks. This is NOT a
network failure — the customer's network is fine.

**Triage — do BOTH steps:**

### Step 1: BLSSL bypass (stops the SSL inspection)

1. In the ZIA admin console, open the BLSSL (Bypass-SSL) list.
   *URL Filtering bypass is not enough — BLSSL is the correct
   surface for stopping SSL inspection.*
2. Add the RMM domain with a star prefix:
   - Datto: `*.centrastage.net`, `*.datto.com`, `*.autotask.net`
   - Kaseya: `*.kaseya.com`, `*.kaseyaplus.com`
   - NinjaOne: `*.ninjarmm.com`, `*.ninjaone.com`
   - ConnectWise Automate: `*.labtechsoftware.com`
   - N-able: `*.n-able.com`, `*.solarwindsmsp.com`
   - Atera: `*.atera.com`
3. Push policy. The next agent check-in should succeed without
   touching the endpoint.

### Step 2: File Type Control exception (Example Tenant E pattern)

Even after BLSSL bypass, RMM agents push binary payloads
(installers, scripts, telemetry archives) that can hit File Type
Control / MIME filtering rules. The Example Tenant E case specifically had
this layered failure:

1. In ZIA → Policy → File Type Control, identify any rule that
   blocks `.exe`, `.msi`, `.ps1`, `.bat`, or generic binary MIME
   types.
2. Add the RMM endpoint URLs (or their CDN ranges) to the
   exception list. For Datto, the CDN is Amazon S3 East
   (`*.s3.amazonaws.com`, `*.s3.us-east-1.amazonaws.com`); for
   Kaseya, often CloudFront-backed (`*.cloudfront.net`).
3. For broad agent-CDN bypass, consider scoping to the customer's
   admin user / service account rather than allowing the CDN
   wholesale.

### Step 3: Validate

4. Have the customer's MSP re-launch a console action that touches
   the previously-failing endpoint. Agent check-ins should succeed
   within one polling interval (typically 1-5 minutes).
5. If the agent is offline-managed (Datto often is), wait for the
   next scheduled check-in before declaring the fix verified.

---

## Why this is CRITICAL severity

RMM is how the MSP/IT team patches, monitors, and remediates the
customer's fleet. A broken RMM channel often goes unnoticed until a
critical action fails — at which point the customer is multiple
days behind on patches or alerts. The cost of false-positives is
low; the cost of false-negatives is high.

---

## Operator notes

- Catalogue lives in `rmm_agent_pin.py:_RMM_DOMAINS`. Add new
  vendors as customers report them; pair every addition with a
  regression test in `test_rmm_agent_pin.py`.
- This detector intentionally overlaps with `bypass_misconfiguration`'s
  `GATEWAY_NOT_IN_BYPASS` finding. The RMM detector fires CRITICAL
  vs the gateway detector's CRITICAL, but the RMM SOP is more
  actionable for this specific vendor class. Both findings can
  legitimately fire on the same bundle; treat them as
  complementary.
