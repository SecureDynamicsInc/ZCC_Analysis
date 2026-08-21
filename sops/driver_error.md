# SOP: ZCC Driver Error

This document covers ZCC driver-load failures detected by
`zcc_diag/issues/driver_error.py`.

The user-facing tray status string this maps to (per the Zscaler
"Client Connector Errors" documentation, Connection Status Errors table):

  * **Driver Error** -- "A Windows driver installation issue has been
    detected, and the tunnel interface cannot be started." ZCC enters
    fail-open mode unless the app profile has fail-close enabled.

Detection grounded in the official Zscaler ZCC Traffic Forwarding
Troubleshooting Runbook (Driver Error section). Signatures
live in **ZSATray** logs (not ZSATunnel), so this detector opts in to
tray-log feeding via the multiplexer's `wants_tray_logs` mechanism.

> **Calibration note.** None of the bundles available during
> development contained a Driver Error. Detector grounded in the
> runbook quotes + healthy-bundle absence of the failure shapes.
> Synthetic tests (`test_driver_error.py`) verify both planted-failure
> paths and that healthy tray logs don't false-fire.

Each H2 below is anchored on a finding code emitted by the detector.

---

## LWF driver failed to load
<a id="lwf-unable-to-load"></a>

**Detected when:** the ZSATray log line `ERR LWF: Unable to load
driver!` appears.

**What it means:** ZCC's tray attempted to load the Lightweight Filter
(LWF) kernel driver and Windows refused.

**Triage steps (documented from runbook):**

1. **Use ZCC's Repair App.** From the ZCC tray:
   *More → Troubleshoot → Repair App* and restart the device.
2. **Disable endpoint protection temporarily** (with admin approval).
   The runbook specifically calls out Carbon Black and CrowdStrike-
   style EDR products as common culprits for blocking driver
   installation.
3. **Reinstall ZCC with `--reinstallDriver 1`** flag if the Repair
   App didn't help:
   ```
   ZSAInstaller.exe install --reinstallDriver 1
   ```
4. If the failure persists, check the DriverStore at
   `C:\Windows\System32\DriverStore\FileRepository\` for the
   `zapprd.inf_amd64_<hash>` directory. If missing or partial,
   driver install was interrupted -- a clean reinstall is the fix.

---

## LWF driver check failed at startup
<a id="lwf-initial-check-failed"></a>

**Detected when:** the ZSATray log line `ERR lwf: Initial driver
check FAILED! LightWeightFilter not loaded! ZApp moves to DRIVER
ERROR!` appears.

**What it means:** ZCC started up, queried for the driver, and got a
not-loaded response -- so the tray transitioned to Driver Error state
immediately. This is the most explicit signature of the issue.

**Triage:** same as
[LWF driver failed to load](#lwf-unable-to-load).

---

## LightWeightFilter not loaded (backstop)
<a id="lightweightfilter-not-loaded"></a>

**Detected when:** a log line contains `LightWeightFilter not loaded`
outside the two canonical phrases above.

**What it means:** Defensive backstop. Some ZCC versions / platforms
may emit the phrase outside the canonical tray-error path; this
finding ensures we still catch them.

**Triage:** same as
[LWF driver failed to load](#lwf-unable-to-load).

---

## Tray showed 'Driver Error'
<a id="tray-driver-error"></a>

**Detected when:** the literal string `Driver Error` appears in a
tray log.

**Severity:** WARNING. Tray-string echoes can be transient and may
overlap with the more specific findings above. Becomes critical when
combined with `LWF_UNABLE_TO_LOAD` or `LWF_INITIAL_CHECK_FAILED`.

**Triage:** same as
[LWF driver failed to load](#lwf-unable-to-load).

---

## See also

* `endpoint_fw_av.md` -- companion detector. The FW/AV detector
  watches `lwfDriverRunning:false` in ZSATunnel status JSON. That's
  an INDIRECT symptom (the periodic status poll noticed the driver
  isn't running). The Driver Error detector here watches the DIRECT
  driver-load failure signal at startup time.
* The Errors documentation, Connection Status Errors table -- documents the
  user-facing Driver Error tray string.
* The ZCC Traffic Forwarding Runbook, Driver Error section (p.30-33).
