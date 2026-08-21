# SOP: Captive Portal errors

This document covers issue #4 in the user spec --
"Captive portal detection problems" -- detected by
`zcc_diag/issues/captive_portal.py`.

The user-facing tray status strings this maps to (per the Zscaler
"Client Connector Errors" documentation, Connection Status Errors table):

  * **Captive Portal Detected** -- "ZCC is in a fail-open state because
    ZCC detected a captive portal." Click *Open Browser* to authenticate.
  * **Captive Portal Error** -- "The user has not resolved the captive
    portal within the time configured in the Zscaler Admin Console."

Canonical state-machine values:

  * `CAPTIVE_PORTAL_FAILOPEN` -- ZCC saw a captive portal, briefly
    stopped intercepting traffic to let the user auth via browser
  * `CAPTIVE_PORTAL_ERROR` -- the user didn't authenticate in time

Detection is grounded in the official Zscaler ZCC Traffic Forwarding
Troubleshooting Runbook (Captive Portal Error section) plus
the ZCPM (Zscaler Captive Portal Module) lifecycle observed in healthy
real bundles.

> **Calibration note.** None of the bundles available during
> development contained a captive-portal failure. Detector grounded in
> the runbook + healthy-bundle absence of failure shapes. Synthetic
> tests verify both the planted-failure paths and that the healthy
> NOT_DETECTED / DETECTING / 204-response patterns don't false-fire.

Each H2 below is anchored on a finding code emitted by the detector.

---

## Captive portal detected by ZCPM
<a id="zcpm-portal-detected"></a>

**Detected when:** the log line
`ZCPM sending captive detected notification to observers: DETECTED`
appears.

**What it means:** ZCC's Captive Portal Module probed
`gateway.<cloud>.net/zcc_conn_test` (or `/generate_204`) and got a
non-204 response, so it concluded a captive portal is intercepting
traffic. The notification fans out to observers (tray UI, tunnel
state machine).

**Triage steps (documented from runbook):**

1. **Verify captive portal login.** Open the default browser; the
   captive portal sign-in page should auto-display. If it doesn't,
   manually browse to a non-HTTPS URL such as `http://example.com`.

2. **Check network configuration.**
   * Confirm DNS isn't blocking traffic to `gateway.<cloudname>.net`.
   * Ensure firewall or network security devices don't block captive
     portal detection traffic.

3. **Bypass third-party VPN configurations.** If using a third-party
   VPN, the VPN must allow access to `gateway.<cloudname>.net` and
   `pac.<cloudname>.net` outside the tunnel.

4. **Review timeout settings.** If users routinely take more than 5
   minutes to sign in (e.g., complex hotel auth pages), increase the
   captive portal timeout in the ZCC App Profile.

5. **Update ZCC** to the latest version to avoid outdated captive
   portal handling issues.

---

## Tray showed 'Captive Portal Detected'
<a id="tray-captive-portal-detected"></a>

**Detected when:** the user-facing tray string `Captive Portal
Detected` is echoed in any log file.

**Severity:** WARNING. Tray strings can be transient (the user
clicked *Open Browser* and authenticated), so this alone isn't
critical. It becomes critical when paired with
`CAPTIVE_PORTAL_ERROR_STATE` (timeout expired).

**Triage:** same as
[Captive portal detected by ZCPM](#zcpm-portal-detected).

---

## ZCPM probe returned non-204
<a id="zcpm-probe-non-204"></a>

**Detected when:** `ZCPM detectCaptive: Response Status <CODE>` shows
a code that isn't 204.

**What the codes typically mean:**

| Code | Likely meaning |
|---|---|
| 200 | Captive portal page returned HTML |
| 301 / 302 / 307 / 308 | Captive portal sent redirect to login page |
| 401 / 403 | Some networks return auth-required from filtering proxies |
| 4xx (other) | The gateway URL is being intercepted/transformed |
| 5xx | The gateway itself is unreachable through the local network (treat as Connection Error / Network Error too) |
| 204 | Healthy. This finding does NOT fire on 204. |

**Triage:** same as
[Captive portal detected by ZCPM](#zcpm-portal-detected) for 200/3xx;
for 5xx, also work the [Connection Error](tunnel_not_established.md)
or [Network Error] flow.

---

## CAPTIVE_PORTAL_FAILOPEN state
<a id="captive-portal-failopen-state"></a>

**Detected when:** ZIA or ZPA proxy state transitioned into
`CAPTIVE_PORTAL_FAILOPEN`.

**Severity:** WARNING. This is the *normal* transient state when ZCC
notices a captive portal -- it stops intercepting for a configurable
window so the user can authenticate via browser.

Per the Errors documentation Registry-Keys table:
> ZCC has detected a captive portal on the network and it has
> stopped traffic interception for some time to allow captive
> authentication.

**It only becomes a problem if the next state transition is to
`CAPTIVE_PORTAL_ERROR`** (the user didn't auth in time). If you see
the state cycle `FAILOPEN → ON / TUNNEL_FORWARDING`, the user
authenticated successfully and there's nothing to do.

**Triage:** confirm the user resolved the portal. If they did and the
state went back to healthy, this finding is informational. If
followed by `CAPTIVE_PORTAL_ERROR_STATE`, follow that triage.

---

## CAPTIVE_PORTAL_ERROR state
<a id="captive-portal-error-state"></a>

**Detected when:** ZIA or ZPA proxy state transitioned into
`CAPTIVE_PORTAL_ERROR`.

**Severity:** CRITICAL. The user is stuck because they didn't
authenticate in time.

Per the Errors documentation Registry-Keys table:
> Captive portal has been detected on the system and the open
> timeout has expired.

**Triage:**

1. **First, did the captive-portal page actually load for the user?**
   If `ZCPM_PORTAL_DETECTED` fired but no auth completed, ask the
   user whether they saw a sign-in page at all. If not -- the portal
   isn't being prompted; check DNS / VPN bypass / browser settings.

2. **Increase the timeout.** ZCC App Profile → captive portal timeout
   (default ~5 min). Some hotel / airport portals take longer.

3. **Same triage as
[Captive portal detected by ZCPM](#zcpm-portal-detected)** for the
   underlying portal-detection conditions.

---

## See also

* The Zscaler ZCC Traffic Forwarding Runbook, "Captive Portal Error"
  section (p.16-18).
* The Errors documentation, Connection Status Errors table -- documents the
  tray strings.
* The Errors documentation, Windows Registry Keys → ZWS_State table --
  documents `CAPTIVE_PORTAL_ERROR` and `CAPTIVE_PORTAL_FAILOPEN`.
