# SOP: AI tool / CLI cert pinning

This document covers SSL inspection failures against AI tooling
endpoints (Claude.ai, Cursor, OpenAI, Copilot, Gemini, Perplexity,
etc.), detected by `zcc_diag/issues/ai_cli_pin.py`.

The user-facing symptom is "this AI tool stopped working with
Zscaler enabled." The root cause is almost always that the AI
vendor's endpoint pins its certificate, so ZCC's SSL interception
fails the handshake. The fix is a policy edit, not an
infrastructure change.

Detection grounded in:
- an anonymized internal case (Example Tenant H, Cursor IDE failures)
- an anonymized internal case (Example Tenant I, Claude.ai). observed: *"zscaler
  intermediate certificate was not showing up for claude.ai."*
- Example Tenant M 2026-04-08 Zoom session: created an ``A_AI_testing`` AD
  group to give Dean / Adrian access to unsanctioned AI without the
  caution prompt blocking them.

---

## SSL inspection breaking an AI tool endpoint
<a id="ai-cli-pin"></a>

**Detected when:** an SSL handshake / cert validation failure fires
on a tunnel-log thread whose most recent `Host=...` line names a host
in the AI domain catalogue (`claude.ai`, `anthropic.com`, `openai.com`,
`cursor.sh`, `copilot.microsoft.com`, `gemini.google.com`, etc.).

**What it means:** the AI vendor pins their certificate. ZCC's
inspection-and-resign approach replaces the cert with a Zscaler-
signed copy mid-flight, the client refuses to trust it, the
handshake fails, the tool breaks.

This is NOT an infrastructure failure. The customer's network is
healthy, the user's cert store has the Zscaler intermediate. The
problem is policy.

**Triage steps — choose ONE based on customer intent:**

### Option 1: BLSSL bypass (broad, fast)

Use when the customer wants the AI tool to work for everyone, or is
in active rollout mode.

1. In the customer's ZIA admin console, open the BLSSL (Bypass-SSL)
   list. This is the right policy surface — the *URL Filtering*
   bypass doesn't stop SSL interception.
2. Add the AI domain with a star prefix: `*.claude.ai`,
   `*.cursor.sh`, `*.openai.com`, etc. Use the bare domain that the
   detector flagged.
3. Push the policy and have the user re-launch the tool. Cert error
   should disappear immediately (no client-side cache to clear).

### Option 2: AI testing AD group (selective, governed)

Use when the customer wants AI tooling sanctioned only for specific
users (Example Tenant M pattern).

1. Create an AD security group named `A_AI_testing` (or per the
   customer's naming convention).
2. Add the specific users / departments who should have access.
3. SCIM-sync the group to ZIA (Identity → Groups → Sync if not
   already covered).
4. In ZIA Policy → Cloud App Control:
   - Risk 1-4 AI tools: **Allow** for the `A_AI_testing` group.
   - Risk 5 AI tools (anything explicitly blocked corporate-wide):
     leave as **Block** unless the customer has a different policy.
5. In BLSSL, add the AI domains scoped to the `A_AI_testing` group.
   Most ZIA UIs let you scope BLSSL by user group; if not, use the
   broader Option 1 BLSSL entry and rely on Cloud App Control to
   gate everyone else.

### Either way

6. Document the AI tool in the customer's SOP runbook so the
   support team knows the bypass is intentional. AI tools shift
   often; if the customer's pack file changes vendors next quarter
   (e.g. swapping Copilot for Cursor), the old bypass becomes stale
   and the new one needs adding.

---

## Operator notes

- The Example Tenant I ticket text — *"zscaler intermediate certificate was not
  showing up for claude.ai"* — was originally diagnosed as a cert-
  store deployment issue. After confirming the cert was present in
  the user's keychain, the team realised Claude.ai was pinning. The
  zcc_diag detector skips that misdiagnosis loop entirely.
- This catalogue grows. Add new vendors to `_AI_DOMAINS` in
  `ai_cli_pin.py` as customers report them. Pair every addition with
  a regression test in `test_ai_cli_pin.py`.
