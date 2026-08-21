# SOP: ZCC client version drift

This document covers ZCC client versions detected as significantly
behind the known-recent GA baseline, by
`zcc_diag/issues/zcc_client_version_drift.py`.

Detection grounded in WestStar 2-04 Zoom AI Summary (verbatim):
*"TimG was on version 141 while Dan was on 202... determined the
problem might be machine-specific rather than a general issue."*
Two coworkers in the same office produced different Zscaler behaviour
because they were on dramatically different ZCC versions — and
recognising that immediately would have skipped hours of triage.

Baseline is hardcoded in the detector and should be updated when
Zscaler ships a new GA. The current baseline is in
`zcc_client_version_drift.py` under `_BASELINE_GA`.

---

## ZCC component is 50+ builds behind GA
<a id="zcc-version-far-behind"></a>

**Detected when:** the largest version gap across all components is
50 or more builds (or a major/minor/patch difference, which is
treated as definitely "very behind").

**What it means:** the client is several months behind Zscaler's
current GA. The risk surface includes:
- Cert-store fixes (Zscaler intermediate updates, root rotations)
- LWF / kext driver compatibility with newer host OS releases
- Mobile-API endpoint changes (`mobile.<cloud>.net` shape)
- DTLS Tunnel 2.0 protocol improvements / fallback fixes

**Triage steps:**

1. Update the ZCC client FIRST, before any policy / network triage.
   Even if the bug isn't ZCC-version-related, having the client on a
   stale build introduces a confounding variable.
2. Use the customer's normal client-deployment channel (Intune,
   Jamf, SCCM, ZCC Portal scheduled push). Don't side-channel a
   single user's update unless that's part of the test plan.
3. After the update, have the user re-test the failing action. If it
   still fails, proceed to deeper triage.
4. If the customer can't update right away, document the gap in the
   ticket and re-evaluate at the next maintenance window.

**Operator workflow:**
- This is the very first thing to check when "one user broken, others
  fine" symptoms appear. Per the WestStar transcript, checking
  versions on both machines was what unblocked the investigation.

---

## ZCC component is 10-49 builds behind GA
<a id="zcc-version-behind"></a>

**Detected when:** the largest version gap is between 10 and 49 builds.

**What it means:** the client is meaningfully behind but not
catastrophically. Still worth considering an update before deeper
work, but not strictly required.

**Triage steps:**

1. Note the version in the ticket as part of the bundle's
   environmental context.
2. If the failing symptom matches a known-fixed Zscaler bug in a
   later build, prioritise the update. Otherwise proceed with normal
   triage and update at the next maintenance window.
3. Do NOT fix the version on a single test machine and assume that
   represents the customer's fleet — most ZCC deployments have a
   long tail of out-of-date clients that will hit the same bug.
