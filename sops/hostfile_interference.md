# SOP: Hosts-file override bypassing ZPA/ZIA

This document covers stale or GPO-pushed hosts-file entries that
override DNS resolution at the OS level, bypassing Zscaler entirely.
Detected by `zcc_diag/issues/hostfile_interference.py`.

The user-facing symptom is "this internal app stopped working" or
"site loads sometimes but not others." The root cause is the system
hosts file (`C:\Windows\System32\drivers\etc\hosts` on Windows,
`/etc/hosts` on Mac / Linux) carrying an entry that short-circuits
DNS before Zscaler gets a chance to resolve it.

Detection grounded in:
- an anonymized internal case (Example Tenant L "portal not working").
  Zoom AI summary observed: *"Jack's machine had an incorrect host
  file entry that was causing DNS requests to be sent directly to
  the IP address instead of through Zscaler."*
- a synthetic internal case (Example Tenant M). Resolution
  was *"reset host files on all affected computers to resolve
  internal site access issues."*

**Critical operational note**: many enterprises push the hosts file
via Group Policy. Removing the override on a single machine **is not
enough** — GPO will re-push it within 30 minutes. Always identify
the GPO source and fix the policy.

---

## Internal hostname mapped to a private IP
<a id="hostfile-private-override"></a>

**Detected when:** the hosts file contains a non-comment line
mapping an internal-looking hostname (single label, or ending in
`.local`, `.internal`, `.corp`, `.lan`, etc.) to a private IP
(RFC1918, link-local, CGNAT). Standard `localhost` / IPv6 boilerplate
is excluded.

**What it means:** the OS resolver returns the override IP before
ZPA's TUN driver / Network Extension sees the DNS query. ZPA's app
segment configuration is irrelevant — the override always wins.
Either the resulting connection fails (the IP isn't routable
without ZPA's tunnel), or it succeeds but bypasses Zscaler
inspection entirely.

**Triage steps:**

1. Confirm the override is active on the affected machine:
   - Windows: `nslookup <hostname>` should return the override IP,
     not the ZPA synthetic IP.
   - Mac: `scutil --dns | grep -B 2 <hostname>` and `cat /etc/hosts`.
2. Identify the GPO that owns the hosts file. On Windows, run
   `gpresult /h gpresult.html` and search the output for "hosts"
   or for the specific override entry. The GPO name typically
   includes "Hosts" or "DNS" in the title.
3. Coordinate with the customer's AD admin to either:
   - Remove the override entirely from the GPO (preferred — most
     overrides are stale from before the ZPA rollout), OR
   - Scope the GPO away from the user / OU experiencing the issue.
4. **Verify by running gpupdate on a fresh machine.** The hosts
   file should NOT pick the override back up after `gpupdate /force`.
5. If the entry is intentional (e.g. a legacy app that needs a
   specific override) but should still flow through ZPA, move the
   override into ZPA's app segment configuration — that's the
   right policy surface for the same effect.

**Operator workflow:**

This finding is more common than the JumpCloud-style detection
patterns. Treat the operator's first instinct ("just remove the
line and reboot") as INCOMPLETE — the GPO source is what needs
fixing.

---

## Internal hostname mapped to a public IP
<a id="hostfile-public-override"></a>

**Detected when:** the hosts file contains a non-comment line
mapping a hostname (likely internal) to a public-internet IP.

**What it means:** less clear-cut than the private-IP case. Common
scenarios:
- Legitimate split-DNS shortcut, e.g. pinning `app.saas-vendor.com`
  to a specific edge IP for performance.
- Stale entry from a SaaS migration (the IP has since changed).
- Manual override used during a troubleshooting session that was
  never cleaned up.

**Triage steps:**

1. Compare the override IP against the current DNS answer for the
   same hostname. If they differ, the override is at minimum
   stale — and may be actively pointing at a wrong / decommissioned
   endpoint.
2. Check whether the hostname is in any of the customer's ZPA app
   segments or ZIA cloud-app categories. If yes, remove the
   override — Zscaler should handle that resolution.
3. If the override is intentional (rare), leave it but document
   it in the customer's runbook so future detector hits don't
   re-trigger triage.
