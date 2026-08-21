# SOP: ZPHM force-stop loop

This document covers the ZPHM (Zscaler Proxy Health Monitor)
force-stop loop pattern, detected by
`zcc_diag/issues/zphm_force_stop_loop.py`.

This is a **downstream symptom** detector. ZPHM force-stops don't
tell you *why* the tunnel is broken — they tell you that
*something else* in the auth / connectivity stack is broken and
the health monitor is reacting to it. Use ZPHM hits as confirmation
that one of the other detector findings is the real root cause.

Detection grounded in a synthetic multi-bundle calibration:
the reference bundle (ZCC
4.8.0.156 on a WORKGROUP Windows 11 machine) exhibits **239
`ZPHM stopAndJoinManager Called!! Join Time: 5000`** events
co-occurring with 4811 `SERVER_AUTH_ERROR` state lines, 8 ZPA
`SERVER_DOWN_ERROR` transitions, and an empty SAML
(`ZPA SAML size: 0`). The ZPHM loop is the most visible symptom
but the upstream cause is the SAML failure.

---

## ZPHM force-stopped in a loop
<a id="zphm-force-stop-loop"></a>

**Detected when:** 20 or more `ZPHM stopAndJoinManager Called!!`
log lines appear in a single bundle.

**What it means:** the proxy health monitor is repeatedly trying
to bring the proxy state up, failing, and dropping into FORCESTOP.
Each force-stop blocks up to 5 seconds on the manager-thread join
(the `Join Time: 5000` value in the log). At 239 force-stops that
adds up to roughly 20 minutes of cumulative housekeeping latency.

**Triage steps:**

1. **Do NOT treat ZPHM force-stops as the root cause.** They are
   a downstream symptom. Look at the other detector findings on
   the same bundle first.
2. Most likely upstream finding patterns:
   - `zia_auth_failures` firing on `SERVER_AUTH_ERROR` repeats —
     the ZIA mobile-API auth path is broken.
   - `zpa_auth_failures` firing with empty SAML / `BRK_MT_SETUP_FAIL_*`
     codes — the ZPA enrollment / SAML chain is broken.
   - `tunnel_not_established` firing on `SERVER_DOWN_ERROR` flap —
     the broker can't be reached.
   - `endpoint_fw_av` firing on `FIREWALL_BLOCK_ERROR` —
     a host firewall is interfering.
3. Whichever upstream finding has fired, fix that one first. The
   ZPHM loop will stop on its own once the proxy can stay up.
4. If ZPHM is firing but NO upstream detector is, the cause is
   something the toolkit doesn't yet cover. Capture additional
   diagnostic context (process state, network trace) and consider
   filing a new detector candidate.

**Operator workflow:**

When the CLI menu shows `zphm_force_stop_loop` as a WARN finding,
your first move should be to filter the menu to CRIT-level findings
on the same bundle. The CRIT finding is the cause; the ZPHM loop
confirms the impact.
