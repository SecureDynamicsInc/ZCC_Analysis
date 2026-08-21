# SOP: Overly-permissive bypass policy

This document covers the indirect detection of overly-permissive
bypass policy via runtime bypass-cache size, by
`zcc_diag/issues/wildcard_app_segment_purge.py`.

**Note**: this detector was redesigned 2026-05-19 after multi-bundle
calibration confirmed that wildcard literals (`*`, `0.0.0.0/0`)
inside the policy config are not present in ZCC support bundles.
The detector now uses an indirect signal — the **size** of
`summary.bypass_cache` — to surface policy that's probably too
permissive.

Detection grounded in:
- Classic Home Machine Tunnel session (2026-05-06 Zoom): *"keeping
  the wildcard for now but mentioned it would need to be removed
  eventually."*
- Example Tenant H — maintainer guidance: *"warned against wildcarding large
  platforms like Amazon S3 or Azure storage."*
- Example Tenant D (2026-05): bypass list had 221k wildcard entries.
- Reference healthy range: Example Tenant C bundles A+B yielded 85 /
  97 unique bypass-cache hosts.

---

## Runtime bypass cache holds 1000+ hosts (very large)
<a id="bypass-cache-very-large"></a>

**Detected when:** `summary.bypass_cache` contains 1000 or more
unique hosts.

**What it means:** the customer almost certainly has wildcard
rules on very large platforms (Amazon S3, Azure storage,
CloudFront) or a broad cloud-app-control policy bypassing huge
swathes of the internet. At 1000+ hosts the runtime cache is well
past the 50-200 healthy range and the policy needs an audit.

**Triage steps:**

1. Open the CLI's bundle-completeness summary and scan the cache
   for obvious broad platforms (`*.s3.amazonaws.com`,
   `*.azurewebsites.net`, `*.cloudfront.net`, `*.blob.core.windows.net`).
2. In ZIA admin, find the bypass / cloud-app-control rules that
   produced those hosts. Narrow each broad bypass to the specific
   endpoint(s) actually needed.
3. Per Gideon's observed guidance from the Example Tenant H calibration:
   never wildcard at the platform level (S3, Azure storage) — use
   the specific bucket or service hostname.

---

## Runtime bypass cache holds 300-999 hosts (large)
<a id="bypass-cache-large"></a>

**Detected when:** `summary.bypass_cache` contains 300-999 unique
hosts.

**What it means:** larger than the typical enterprise range but
not yet alarming. Worth a periodic audit if growth continues.

**Triage steps:**

1. Compare against prior bundles for the same customer (if
   available). If the cache size has grown significantly month-
   over-month, that's a sign of policy drift — accumulated
   one-off exceptions.
2. No immediate action required.

---

## Below — retained legacy guidance for context

---

## Wildcard inside a destination/match field
<a id="wildcard-in-destination"></a>

**Detected when:** the forwarding profile JSON contains a literal
`*`, `*.*`, `0.0.0.0/0`, `::/0`, `any`, or `ANY` inside a field whose
name contains `destination`, `host`, `match`, `url`, `domain`, or
`ip`.

**What it means:** ZCC will route or bypass *every* host that the
parent rule's other conditions match. If this is a ZPA app segment,
every reachable destination flows through that segment; if this is a
ZIA bypass, every URL skips inspection.

**Triage steps:**

1. Locate the parent rule in the customer's policy. The JSON path
   the detector prints (e.g. `bypassRules[2]/destinations[0]`)
   maps roughly to the admin-UI rule name and condition.
2. Ask the operator: *was this intentional?* If yes, document it
   in the rule's description so the next reviewer doesn't flag it
   again. If no (the usual answer), proceed.
3. Replace the wildcard with the actual hostnames / IP ranges the
   rule should cover. The Classic Home case used `192.168.0.0/16`
   instead of `0.0.0.0/0` for the on-prem network bypass.
4. For very large legitimate sets (e.g. an entire SaaS like S3 or
   Azure storage), use a star-prefixed wildcard (`*.s3.amazonaws.com`)
   rather than bare `*`. Gideon's observed warning was specifically
   about avoiding the bare wildcard for large platforms.
5. After narrowing, re-test the original user action to confirm it
   still works.

**Operator workflow:**
- Wildcards are almost always temporary. Pair the detector finding
  with a follow-up ticket so the rule is reviewed within 30 days.

---

## Wildcard in a non-destination field
<a id="wildcard-in-profile"></a>

**Detected when:** a wildcard literal appears in a profile field
that doesn't obviously map to destination/match — e.g. a description,
a tag, or a metadata column.

**What it means:** usually benign (a literal `*` in a description
or comment is fine). The detector surfaces it at INFO level for
review, not action.

**Triage steps:**

1. Open the entry in the admin UI and confirm it's just text /
   metadata, not a load-bearing match condition.
2. If it IS load-bearing, treat as
   [Wildcard inside a destination/match field](#wildcard-in-destination).
3. If purely text, no action — but consider editing it to something
   less ambiguous so future detector runs don't re-flag it.
