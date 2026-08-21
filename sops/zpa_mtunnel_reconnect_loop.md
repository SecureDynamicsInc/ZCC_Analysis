# SOP: ZPA microtunnel reconnect loop

This document covers ZPA microtunnel teardown clustering detected by
`zcc_diag/issues/zpa_mtunnel_reconnect_loop.py`.

The user-facing symptom is one of:

- App access to ZPA destinations is "flaky" -- works for a few
  seconds, drops, reconnects, drops again.
- Sustained battery drain on laptops while connected to ZPA, even
  when the user isn't actively using ZPA apps.
- Connector-side CPU spikes / connection limits hit (visible in the
  ZPA Admin Console -> Connectors dashboard).

The detector counts three teardown tokens together because a real
reconnect loop usually involves multiple of them in alternation:

- `BRK_MT_CLOSED_FROM_ASSISTANT` -- App Connector assistant closed.
- `BRK_MT_RESET_FROM_SERVER` -- broker or app sent forcible RST.
- `BRK_MT_TERMINATED` -- ZPA backend terminated (policy refresh / admin).

In isolation each is benign; in clusters they compound into a loop.

Detection grounded in example-tenant-c-windows-17mb (192 / 221 / 27
teardowns of the three tokens respectively in a single captured
window -- a clean reconnect-loop signature).

---

## ZPA microtunnel reconnect loop
<a id="zpa-mtunnel-reconnect-loop"></a>

**Detected when:** combined teardown count >= 30 (informational) or
>= 100 (sustained, warning). The detector reports the per-token
breakdown so the operator can see which reason dominates.

**The breakdown tells you the root cause.** Triage by which token is
the loudest:

### If `BRK_MT_CLOSED_FROM_ASSISTANT` dominates

The App Connector assistant is the one closing sessions. Most common
causes:

1. **AC idle-timeout is too aggressive** for the workload. The
   connector closes a tunnel after N seconds of TCP idleness; ZCC
   reconnects immediately because the user is still actively browsing
   on a different tab.
2. **AC restart loop** -- the connector is restarting (crash, OOM,
   policy push), tearing down every active tunnel each time.
3. **AC version mismatch** -- if the connector was recently upgraded
   and the version is incompatible with the broker, the broker may
   recycle sessions defensively.

Diagnosis:
- ZPA Admin Console -> Connectors -> select the AC -> "Logs" tab.
  Look for crash / restart / OOM lines on the AC.
- Check AC uptime; if it's < the bundle window, you've got a restart
  loop.
- Compare AC version vs. fleet baseline (`zpactl --version` on the
  AC).

Fix:
- Tune AC idle-timeout (most customers leave it at default; if the
  workload is bursty, increase).
- Stabilize the AC (memory, version, capacity).

### If `BRK_MT_RESET_FROM_SERVER` dominates

A stateful device in the broker-side path is sending RST. Most common:

1. **Stateful firewall in front of the broker** clearing TCP state
   faster than ZCC's keepalive interval.
2. **Load balancer / proxy cycling backends** -- the LB closes the
   front-end connection when it switches the backend.
3. **Peer-process death** -- the broker process restarted; pre-existing
   tunnels get RST.

Diagnosis:
- Run a tcpdump on the affected client (`tcpdump -i any -nn host
  gateway.<cloud>.net`) and look for the RST source IP. If it's the
  Zscaler hub IP, the broker is sending it. If it's an intermediate
  IP, you've found the middlebox.

Fix:
- If middlebox: tune its stateful-connection timeout up, or add a
  bypass for Zscaler hub IPs (publishes at
  `https://config.zscaler.com/<cloud>/hubs`).
- If broker: file with Zscaler Support; this isn't customer-side.

### If `BRK_MT_TERMINATED` dominates

ZPA backend terminated. Most common:

1. **Policy refresh** -- admin pushed a policy change. Healthy on
   its own; pathological if the policy is unstable (admin pushes
   changes constantly).
2. **License / capacity limit reached** -- the org hit a per-user or
   per-app-segment limit and ZPA terminated lower-priority tunnels.
3. **Admin action** -- someone explicitly disconnected the user.

Diagnosis:
- ZPA Admin Console -> Reports -> Audit Logs. Filter on the user /
  device. Policy edits, user-disconnect events, license-limit events
  are all logged.
- Check the customer's user count vs. licensed cap.

Fix:
- If a runaway script is editing policies, stop it.
- If a licensing limit, address the licensing.

---

## See also

* `zpa_auth_failures.md` -- if the reconnect loop is paired with
  `BRK_MT_SETUP_FAIL_*` findings, the loop is symptom and the
  setup-failure is cause; fix the setup-failure first.
* `tunnel_not_established.md` -- a tunnel state flap (state-machine
  level) often causes microtunnel teardowns as a downstream effect.
  If both fire, the state flap is upstream.
* `zphm_force_stop_loop.md` -- ZPHM force-stops are a related
  downstream-symptom detector; if both fire, the upstream root cause
  is the same broken-tunnel state.
