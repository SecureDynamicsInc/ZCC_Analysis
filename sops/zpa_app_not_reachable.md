# SOP: ZPA application reachability failures

This document covers connector-side reachability failures detected by
`zcc_diag/issues/zpa_app_not_reachable.py`.

The user-facing symptom: the user tried to reach an internal app over
ZPA, got "connection failed" or a TCP timeout, but the ZPA tunnel
itself is healthy (the user is authenticated, other apps work).

The detector emits a separate finding code per error token so the
triage path differs by which kind of reachability problem fired.

Detection grounded in:
- iatwater Mac bundle: `APP_NOT_REACHABLE` (err_code 4002) on 18
  `zpn_mtunnel_end` records.
- Cyderes ZPA troubleshooting KB (NO_CONNECTOR_AVAILABLE,
  INVALID_DOMAIN documented as connector-reachability tokens).
- Zscaler PSE training materials
  (AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER).

---

## App not reachable (connector reached, backend dead)
<a id="zpa-app-not-reachable"></a>

**Detected when:** `zpn_mtunnel_end` JSON contains
`"error":"APP_NOT_REACHABLE"`, typically with `"err_code":4002`.

**What it means:** ZCC reached an App Connector, the connector
accepted the microtunnel setup, then tried to open a TCP session to
the actual destination application and that TCP session failed (RST,
timeout, ICMP unreachable). The connector is fine; the destination
application's listener or the network between connector and app is
the problem.

**Triage steps:**

1. **Extract the `tag_id`** from the detector evidence (listed in
   the finding title). Cross-reference against ZPA Admin Console ->
   Applications -> Application Segments to identify which app segment.

2. **From the App Connector that handled the request, test
   reachability** to the destination:
   ```
   # Connector-side (Linux):
   curl -v telnet://<app-host>:<port>
   tcpdump -i any -nn host <app-host> and port <port>
   ```
   If the connector can't open the TCP socket, the destination is
   genuinely unreachable from there.

3. **Most common causes:**
   - App is down / restarting.
   - Firewall in front of the app dropped the connector's source IP.
   - DNS at the connector resolves the destination differently than
     expected (asymmetric resolution).
   - Connector is on the wrong network segment for this app.

4. **Fix:** correct the connector's network reach (add firewall rule,
   place connector in the correct segment, etc.), or bring the
   destination back up.

---

## No connector available
<a id="zpa-no-connector-available"></a>

**Detected when:** `zpn_mtunnel_end` JSON contains
`"error":"NO_CONNECTOR_AVAILABLE"`.

**What it means:** ZPA broker tried to assign an App Connector to
service the request and found no eligible connector online. Either
every connector in the matching connector group is offline, or the
app segment is mapped to a connector group that has no live members.

**Triage steps:**

1. **ZPA Admin Console -> Connectors:** check each App Connector's
   "Status" column. Anything not `Connected` is not eligible. Look
   at `Last Seen` to see when the connector last checked in.

2. **Find the segment's connector-group mapping:**
   Applications -> Application Segments -> click the segment ->
   "Connector Groups" tab.

3. **If the connector group exists but has zero connected members:**
   bring at least one back online. If the group is empty by design
   (orphaned config), re-map the segment to a connector group with
   active members.

4. **Validate with a fresh attempt** from the affected client; the
   finding should clear within minutes once a connector is back.

---

## Invalid domain
<a id="zpa-invalid-domain"></a>

**Detected when:** `zpn_mtunnel_end` JSON contains
`"error":"INVALID_DOMAIN"`.

**What it means:** the App Connector received the request, looked up
the destination domain against its expected serve-list, and rejected
it. Most often a segment-to-connector-group mapping mistake (the
segment was mapped to a connector group that doesn't serve this
domain), or a stale connector that hasn't received the current policy.

**Triage steps:**

1. **On the connector, check the loaded segment list:**
   ```
   # Linux connector:
   sudo /opt/zscaler/connector/bin/zpactl status
   sudo less /var/log/zscaler/connector/connector.log
   ```
   Look for the segment-policy refresh timestamp and confirm the
   destination domain is in the loaded set.

2. **If the connector's loaded set is stale,** force a policy refresh
   (admin console -> Connectors -> select connector -> "Reload Policy"),
   or restart the connector service.

3. **If the loaded set is current but doesn't include the domain,**
   the segment-to-connector-group mapping is the bug. Re-map.

---

## App Connector setup timeout
<a id="zpa-ast-setup-timeout"></a>

**Detected when:** `zpn_mtunnel_end` JSON contains
`"error":"AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER"`.

**What it means:** App Service Tunnel (AST) on the App Connector
timed out trying to establish the back-end TCP session to the
destination application. Same family as `APP_NOT_REACHABLE` but
emitted by the connector-side timeout path. Common with one-way
network paths -- the connector can send SYN but never receives
SYN-ACK -- which usually means asymmetric routing or a stateful
firewall that's dropping return traffic.

**Triage steps:**

1. **From the affected connector, run a packet-level test** to
   confirm the asymmetric path:
   ```
   sudo tcpdump -i any -nn host <app-host> and port <port>
   # in another shell, try to connect:
   nc -vz <app-host> <port>
   ```
   If you see SYN going out but no SYN-ACK coming back, you've
   confirmed one-way reachability.

2. **Common culprits:**
   - The destination's stateful firewall is configured to allow
     traffic only from a specific source-IP / source-subnet, and the
     connector's source IP isn't in it.
   - A NAT or load-balancer in front of the app drops state after a
     short timeout and the SYN-ACK gets misrouted.
   - The destination has IPv6 enabled and the connector tries v6
     first; v6 path is broken but v4 would work.

3. **Fix:** add the connector's egress source IP to the destination's
   allow-list, disable v6 on the connector or destination as
   appropriate, or fix the asymmetric routing.

---

## See also

* `zpa_dns_check_not_found.md` -- if the request fails *before*
  reaching the connector (segment doesn't exist), the failure surfaces
  there instead.
* `zpa_auth_failures.md` -- `pa-policy-blocked` covers the case where
  the user is authorized to ZPA but the specific app is denied by
  Private Access policy (different from connector-side reachability).
