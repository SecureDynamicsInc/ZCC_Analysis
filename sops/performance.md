# SOP: Performance / bandwidth degradation through the ZCC tunnel

This document covers issue #5 in the user spec --
"Performance / bandwidth degradation through the tunnel" -- when users
report slow downloads, laggy apps, or generally worse network
performance after ZCC is enabled.

**No dedicated detector ships for this issue.** Performance is
diagnosed by isolation, not by log pattern-matching. The relevant log
signals are already emitted by other detectors:

  * `zcc_t2_dtls_to_tls_fallback` (tunnel detector) -- DTLS over
    UDP/443 failed, ZCC fell back to TLS over TCP/443 within T2
  * `zcc_t2_connection_timeout_*` / `zcc_t2_socket_readable_error_*`
    / `zcc_t2_close_notification_*` (tunnel detector) -- DTLS
    lifecycle errors that often indicate UDP path problems
  * `T2_FALLBACK_TO_T1` (tunnel detector) -- hard fallback to
    Z-Tunnel 1.0 when no SMEs were reachable. Web-only interception;
    non-web traffic bypasses Zscaler.
  * `SSL_INTERCEPTION_DETECTED` (tunnel detector) -- TLS-inspecting
    proxy mangling the handshake; almost always degrades performance
    even when it doesn't outright break things.

This SOP is the **methodology guide** for working from those signals
(or from the absence of them) to a root cause. Grounded in the
Zscaler ZCC Performance Runbook (p.3-15) and the ZIA Performance
Runbook (p.34-60).

---

## When to use this SOP

User reports any of:
  * "Things got slow after Zscaler was installed/enabled"
  * "Browser pages load slowly"
  * "Large downloads/uploads are much slower than before"
  * "Apps that were responsive are now laggy"
  * "Performance is intermittent -- fine some times, terrible others"

**Don't use this SOP when** the user's report sounds like a binary
failure (can't connect, app says "no internet"). Those route to
`tunnel_not_established.md`, `endpoint_fw_av.md`, or `captive_portal.md`.

---

## Step 1: Establish baseline + isolate the variable

Before trying changes, get a quantitative baseline so we can tell
whether anything we change actually helped. Then identify which
variable is the culprit.

**Baseline metrics to capture:**

  1. **Throughput** -- run `speedtest.net` or `fast.com` from the
     affected client, with ZCC enabled. Record down/up Mbps + latency.
  2. **Compare against ZCC disabled** (with admin approval, briefly).
     If performance is identical with/without ZCC, the issue is not in
     ZCC's path -- look at the underlying ISP / LAN.
  3. **Compare against an unaffected client on the same network.** If
     unaffected client is fine, isolate to OS / endpoint config.

**Isolation matrix** (from the ZCC Performance Runbook):

| Pattern | Likely culprit | First steps |
|---|---|---|
| Slow on one specific OS only | OS-vendor change (e.g. recent Windows feature update); third-party AV/VPN with new version | Check OS upgrade history; check AV/EDR allow-list still has ZCC components |
| Slow for whole org all at once | ZCC version regression; recent corporate software push | Roll back to previous ZCC version on one test machine; check what changed in last `Get-AppLog` window |
| Slow at a time of day | Scheduled big upload/download; scheduled AV scan; ISP peak congestion | Check Windows Task Scheduler; check what's running per `Get-Process` during slow window |
| Slow only at one office location | Zscaler DC near that office having issues; path congestion; office router/switch/firewall health | Cross-check from another office; check Zscaler trust portal for DC status |
| Slow only on Wi-Fi (not Ethernet) | RF / driver / DHCP issue, NOT a ZCC issue | Same client on Ethernet should be fast |

---

## Step 2: DTLS vs TLS swap test

The single most diagnostic change for ZCC performance is forcing the
T2 transport from DTLS (UDP) to TLS (TCP) and observing whether
performance changes.

**Background:** T2 prefers DTLS over UDP/443 because it avoids
TCP-over-TCP head-of-line blocking. But many corporate firewalls
treat UDP/443 poorly -- aggressive timeouts, packet drops on bursts,
no jumbo MTU support. When this happens DTLS underperforms TLS even
though it should outperform it.

**How to test:**

  1. In the ZCC admin console, edit the user's App Profile.
  2. Change Z-Tunnel 2.0 transport from "Tunnel with DTLS preferred"
     to "Tunnel with TLS only".
  3. Have the user restart ZCC and re-test performance.

**Interpretation:**

  * **TLS faster than DTLS** -- UDP/443 path is broken. Look for:
    upstream firewall doing per-flow UDP rate limiting; ISP UDP
    deprioritization (rare but documented); intermediate device
    fragmenting DTLS packets.
  * **DTLS faster than TLS** (expected baseline) -- not a UDP issue.
    Move to step 3.
  * **No difference** -- not a transport-layer issue at all. Move to
    step 4.

**Existing detector findings to cross-reference:**

If the tunnel detector reported `zcc_t2_dtls_to_tls_fallback`,
`zcc_t2_connection_timeout_*`, or `zcc_t2_socket_readable_error_*`,
that's strong corroboration that the DTLS path is the problem. The
DTLS-to-TLS swap is the right next move.

---

## Step 3: MTU mismatch test

If the swap test pointed at a transport-layer issue, MTU mismatch is
the next variable to isolate.

**Background:** DTLS Tunnel 2.0 has a default tunnel MTU of 1400 and
MSS of 1360. The underlying network path's MTU has to be at least
that (plus ~80 bytes of DTLS+IP overhead), otherwise packets get
fragmented at the IP layer. Some firewalls/routers silently drop
fragments, causing TCP retransmits, which collapse throughput.

**How to test:**

  1. In the App Profile, set the T2 MTU to 1380 (50 bytes lower than
     default).
  2. User restart ZCC, re-test.
  3. If improved but not fully: lower by another 50 (to 1330), retry.
  4. Continue in 50-byte steps until performance plateaus.
  5. The MTU at the plateau is the largest your path supports; either
     ship that value in the profile, or fix the underlying network
     to support proper MTU/PMTUD.

**Diagnostic alternative -- the runtime config endpoint:**

ZCC exposes its current per-host MTU and protocol overrides at:
```
http://127.0.0.1:9000/zconfig?q=@<CustomerDomain>
```

Useful for checking whether the running config matches what the
admin pushed.

**No log signal exists** for "MTU is too high; packets are
fragmenting." The runbook is explicit that this test is empirical --
change the MTU and observe whether throughput recovers.

---

## Step 4: Hop-by-hop latency analysis (MTR)

If neither DTLS-vs-TLS nor MTU changed the picture, the bottleneck is
elsewhere on the path. The ZIA Performance Runbook (p.34-60) is the
authoritative source for this; the methodology is:

**Three legs to instrument:**

  1. Client to corporate egress firewall
  2. Corporate egress to Zscaler Service Edge
  3. Zscaler Service Edge to destination application

**Collect an MTR trace from the client** to:

  * The Zscaler hub IP the user's bundle says they connected to
    (`summary.service_edges`)
  * The destination application origin

**Windows:**
```powershell
# Install WinMTR from https://winmtr.net/, then GUI; or:
tracert -h 30 -d <zscaler-hub-ip>
pathping <zscaler-hub-ip>
```

**Mac/Linux:**
```bash
mtr -rwzbc 100 <zscaler-hub-ip>
```

**Interpretation:**

  * High packet loss on a specific hop -- bad equipment / link on
    that hop. Contact the network team / ISP with the hop's IP.
  * High latency added at a specific hop -- congestion at that hop.
  * Latency stable but throughput low -- bandwidth bottleneck, not
    loss-related. Capacity issue.

The runbook explicitly maps "where the trace gets bad" to "which
party should fix it" (corporate IT vs Zscaler vs ISP).

---

## Step 5: Browser HAR / chrome://net-export/

For per-application latency (single slow site, not whole-tunnel
slow), the user-side trace is more useful than network-side traces:

  * **Chrome:** `chrome://net-export/` -> Start Logging -> reproduce
    -> Stop Logging -> open the resulting JSON in
    `https://netlog-viewer.appspot.com/`
  * **Browser DevTools:** Network tab -> reload -> right-click -> Save
    as HAR

These tell you which specific HTTP requests are slow and where in
their lifecycle the time was spent (DNS / connect / TLS / wait /
download).

Not part of the ZCC log bundle, but worth requesting from the user
when ZCC log signals don't pinpoint the problem.

---

## Step 6: Look for recently-introduced variables

Performance regressions almost always have a "what changed?" answer.
From the bundle summary:

  * `summary.versions.components` -- has ZCC been upgraded recently?
    Cross-reference against last-known-good version.
  * `summary.os_info` -- recent OS build update? Windows feature
    updates have historically broken third-party network drivers.
  * `summary.security_products` -- AV/EDR update?

If something changed, **revert that one thing** before chasing
deeper. Surface this hypothesis to the user early -- they often know
"oh yes, our security team pushed CrowdStrike v8 last week."

---

## When to escalate

Escalate to Zscaler Support with the captured bundle when:

  * Step 1 isolation matrix doesn't point at a specific variable
  * Step 2 swap doesn't change anything AND step 3 MTU tests don't help
  * MTR (step 4) shows the bad hop is inside the Zscaler network
  * Performance regressed after a ZCC version upgrade

Include in the ticket:
  * The captured bundle (compressed)
  * Baseline numbers + measurements after each test
  * MTR output to the hub IP
  * Browser HAR or net-export, if relevant

---

## See also

* `tunnel_not_established.md` -- the existing tunnel detector's
  findings (T2 lifecycle, DTLS-to-TLS fallback) are the in-bundle
  signals that point toward performance issues; this SOP is the
  decision tree for what to do about them.
* `_runbook_signatures.md` (in `zcc_diag/issues/`) -- structured
  reference doc; the ZCC Performance and ZIA Performance sections
  cover the same methodology in more compressed form.
* The ZCC Performance Runbook.
* The ZIA Performance Runbook.
