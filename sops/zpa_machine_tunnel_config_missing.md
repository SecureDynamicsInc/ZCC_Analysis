# SOP: ZPA Machine Tunnel config missing

This document covers Windows machine-tunnel config failures detected
by `zcc_diag/issues/zpa_machine_tunnel_config_missing.py`. The
detector is gated to `applies_to_os = ("windows",)` because Machine
Tunnel uses the Windows credential-provider model; macOS handles
pre-logon coverage differently (Network Extensions + persistent
network services) and Linux has no equivalent.

The user-facing symptom is one of:

- **Pre-logon AD sign-in fails** -- user sees "username or password
  incorrect" on the lock screen even when credentials are valid,
  because Kerberos pre-auth can't reach the domain controller.
- **First-boot Group Policy** doesn't apply -- newly-imaged Windows
  endpoints come up with no GPO state because they can't reach AD
  before the user signs in.
- **Lock-screen sign-in via SmartCard / WHfB fails over ZPA** even
  though the user can sign in once they're past the lock screen
  (because user-mode ZCC kicks in later than pre-logon).

The runbook signature is a trio of log strings on a Windows tunnel
log:
- `ERR machine tunnel, tunnel config file doesn't exist`
- `Failed to read the machine tunnel config data`
- `Failed to disable credential provider`

The first two are the symptom; the third is the user-facing
consequence.

Detection grounded in three of five synthetic Windows calibration bundles.

---

## ZPA Machine Tunnel config missing
<a id="zpa-machine-tunnel-config-missing"></a>

**Detected when:** any of the three error strings above fires above
the noise threshold (>= 1).

**Severity escalation:**
- INFO if only "config file doesn't exist" / "failed to read" fire
  but the credential-provider line doesn't -- the customer probably
  doesn't intend to use Machine Tunnel; the ZCC client is just
  noisily reporting absence.
- WARNING if "Failed to disable credential provider" also fires --
  pre-logon AD coverage is genuinely broken.

**Triage step 1: confirm the customer's intent.**

Ask:

1. *Is the customer using Machine Tunnel?* (ZPA Admin Console ->
   Configuration -> Machine Tunnel -> Machine Tunnel Policy. If no
   policy is configured at all, the customer doesn't use Machine
   Tunnel.)
2. *Do they need pre-logon AD / Kerberos coverage on Windows
   endpoints?* If yes and they're not using Machine Tunnel, they
   should be. If no, the log noise is harmless.

**If the customer doesn't use Machine Tunnel** (most common case --
log noise only): clean up the forwarding profile on the endpoint to
stop ZCC from logging these errors every cycle.

```
# On the affected Windows endpoint:
# Open Registry Editor (regedit) and navigate to:
HKLM\SOFTWARE\Zscaler\App\Tunnel
# Check that "MachineTunnel" key/value is absent or = 0.
# If present and = 1, the forwarding profile is forcing it on; fix
# the profile in the ZIA / ZPA admin console.
```

**If the customer DOES use Machine Tunnel** (and "disable credential
provider" is failing): the config push failed or the file was
deleted. Triage:

1. **Verify the config file path exists:**
   ```
   dir "%ProgramData%\Zscaler\App\Tunnel\"
   ```
   You should see `tunnel.conf` or equivalent. If the directory is
   empty or missing, ZCC never received the config.

2. **Force a config refresh** -- in the tray, right-click ZCC ->
   Logout -> Login. Watch for the file to appear after re-enroll.

3. **If the file still doesn't appear after re-enroll**, check the
   ZPA Admin Console:
   - Configuration -> Machine Tunnel -> verify a Machine Tunnel
     forwarding profile exists.
   - Verify the device is assigned to a policy that includes Machine
     Tunnel coverage.
   - Verify the device's AD computer object is in the right OU /
     group for the policy.

4. **If everything looks right server-side but the file still
   doesn't come down**, escalate to Zscaler Support with the
   bundle -- there's likely a backend push failure or a tenant-config
   mismatch.

---

## Why this is Windows-only

Machine Tunnel uses the Windows Credential Provider model: ZCC
installs a Credential Provider COM object that intercepts the lock
screen, brings up a tunnel before the user signs in, and lets
Winlogon's MSV1_0 (or Kerberos) authenticate against the domain
controller over that tunnel.

macOS has no credential-provider concept; pre-logon AD sign-in over
ZPA on Mac is achieved differently (persistent network extensions +
on-demand connection, or login window plugins for AD users). Those
mechanisms have entirely separate failure modes.

Linux has no equivalent; ZCC on Linux runs as a user-mode service
that starts after sign-in.

---

## See also

* `zpa_auth_failures.md` -- if ZPA enrollment itself is failing, the
  Machine Tunnel config can't load even if the customer is configured
  to use it. Fix the enrollment first.
* `tunnel_not_established.md` -- if the tunnel can't come up at all,
  Machine Tunnel won't load regardless. Triage tunnel state first.
