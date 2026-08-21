# SOP: macOS connectivity probe SSL failure

This document is the macOS counterpart to `ncsi_false_negative.md`
(which covers Windows NCSI). Detected by
`zcc_diag/issues/ncsi_false_negative_mac.py`.

The user-visible symptom on Mac is one of:
- A captive-portal sign-in window pops up unexpectedly on a
  corporate network.
- Mail.app shows "Cannot connect" intermittently despite the
  network actually working.
- App Store / system updates won't download.
- Office for Mac apps show offline indicators.

The root cause is the same as Windows NCSI: macOS uses Captive
Network Assistant + connectivity probes to decide whether the
network is online; when ZCC's SSL inspection corrupts the probe
response, macOS misinterprets connectivity state.

Detection grounded in:
- Zscaler community discussions about Mac captive-portal issues
  (community.zscaler.com search results).
- Apple's published connectivity-probe documentation.
- Confirmed via the Example Tenant J Mac bundles in the multi-bundle
  calibration (both bypass `captive.apple.com` correctly,
  validating the detector's expected healthy state).

---

## Mac connectivity probe SSL failure
<a id="mac-connectivity-probe-ssl-fail"></a>

**Detected when:** an SSL handshake / cert validation failure fires
on a tunnel-log or tray-log thread whose most recent `Host=...`
line names one of:

- `captive.apple.com` (Apple Captive Network Assistant probe)
- `www.apple.com` (Apple secondary probe)
- `detectportal.firefox.com` (Firefox captive-portal probe)
- `www.msftconnecttest.com` (Microsoft Edge / Office for Mac probe)
- `ipv6.msftconnecttest.com` (Microsoft IPv6 connectivity probe)

**What it means:** macOS thought the network might require captive-
portal sign-in because the probe response looked wrong. macOS may
then pop up a sign-in window, or apps that gate on
`SCNetworkReachability` may declare offline status incorrectly.

**Triage steps:**

1. In the ZIA admin console, find the URL category `Captive Portal`
   (built-in). Add it to the customer's BLSSL bypass list.
2. If the built-in category isn't available, add the hostnames
   manually:
   - `*.apple.com` (broadest; covers Apple's probes)
   - `captive.apple.com` (specific)
   - `detectportal.firefox.com`
   - `*.msftconnecttest.com`
3. Push policy. Have the user run `Cmd+Space` → "Captive Network
   Assistant" to force a re-probe, OR toggle Wi-Fi off/on. The
   spurious captive-portal popup should disappear.

**Verification on the affected Mac (Terminal):**
```
curl -s -o /dev/null -w "%{http_code}\n" http://captive.apple.com/hotspot-detect.html
# expected: 200 (with body "Success")
```
If this returns anything other than 200, ZCC's SSL inspection is
still corrupting the probe.

---

## Why this is separate from the Windows `ncsi_false_negative`

The Windows detector (`ncsi_false_negative.py`) covers
`msftncsi.com` / `msftconnecttest.com` + the Mimecast IP range —
the Windows-specific failure mode. This Mac detector covers
`captive.apple.com` and the broader Apple/Firefox probe family
that's most-broken on Mac specifically.

In practice both can fire on a cross-platform fleet — the customer
needs to bypass both Windows NCSI and Mac connectivity probes,
which is why ZIA bundles the `Captive Portal` URL category for
exactly this purpose.
