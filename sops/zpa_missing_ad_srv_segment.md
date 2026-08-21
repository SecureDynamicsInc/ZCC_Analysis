# ZPA Missing AD Service-Discovery App Segment

## <a id="zpa-missing-ad-srv-segment"></a>Overview

The customer's ZPA Application Segments cover the **hostnames** of internal
domain controllers / file servers but not the **Active Directory service-
discovery DNS records** that Windows uses to find those hosts. Because the
DC hostnames resolve but the Kerberos SRV records don't, Windows can't
acquire Kerberos tickets and every downstream domain-authenticated operation
fails.

**Diagnostic log signature (ZSATunnel):**

```
INF ZPN:0: Control Message Response Data:
{"zpn_dns_client_check": {
    "name": "_kerberos._tcp.dc._msdcs.<ad-domain>",
    "type": "SRV",
    "error": "ZPN_ERR_DNS_CHECK_NO_ASSISTANT",
    "err_code": 3002,
    ...}}
```

Companion (downstream) signature — the ACTUAL user-visible failure:

```
INF ZPN:0: Control Message Response Data:
{"zpn_mtunnel_end": {
    "tag_id": <N>,
    "error": "BRK_MT_CLOSED_FROM_ASSISTANT",
    "err_code": 5027,
    "drop_data": 1}}
```

The `zpn_mtunnel_end` event fires 100-1000s of times because Windows retries
SMB persistently; each attempt sets up, does SMB2 NEGOTIATE, fails
SESSION_SETUP (due to missing Kerberos), and gets RST'd by the App
Connector at ~140-160 ms.

## Symptoms

- Cannot open `\\<dc-hostname>\share` from Explorer
- "Windows cannot access \\server..." error dialogs
- Slow / hanging Group Policy processing at login
- Slow Outlook connection (Autodiscover uses the same SRV records)
- Kerberos error events in Windows Event Log (Event ID 4771 / 4776)
- SMB retry storm in ZSATunnel logs — sequential TAG-IDs each closing
  ~144 ms after successful setup

## Triage flow

1. **Confirm the signature.** In ZSATunnel:
   ```
   grep "ZPN_ERR_DNS_CHECK_NO_ASSISTANT" ZSATunnel_*.log | grep -oE '"name":"[^"]+"' | sort -u
   ```
   If you see names like `_kerberos._tcp.*`, `_ldap._tcp.*`, `_gc._tcp.*`,
   or `*._msdcs.*` — you have this exact issue. If you only see WPAD or
   one-off app hostnames, this isn't your problem — check
   `zpa_dns_check_not_found` instead.

2. **Identify the affected AD domain.** From the failing names, extract
   the domain suffix (labels after the last `_*` component). Example:
   `_kerberos._tcp.site-a._sites.dc._msdcs.corp.example.com` → AD domain
   is `corp.example.com`.

3. **Verify a hostname under that domain DOES resolve.** Look for a
   successful zpn_dns_client_check for a name like `dc01.<ad-domain>` or
   `fileserver.<ad-domain>`. If those succeed but the SRV records fail,
   you've confirmed the App Segment gap. If BOTH fail, this is a
   full-domain coverage gap (the customer has no App Segment at all
   for this domain).

4. **Check the customer's ZPA App Segments.** In the ZPA admin console
   under Applications → Application Segments, find the segments
   matching the AD domain. You'll typically see specific hostnames
   listed with no wildcard or SRV coverage.

## Remediation

### Option A — Wildcard segment (Zscaler reference architecture)

The simplest and Zscaler's recommended approach. Add one Application
Segment covering the AD domain wildcard.

```
Name:           <Customer> AD - <ad-domain> (wildcard)
FQDN:           *.<ad-domain>
Ports (TCP):    53, 88, 135, 389, 445, 464, 636, 3268, 3269
                49152-65535   (RPC ephemeral range)
Ports (UDP):    53, 88, 123, 389, 464
Server Group:   <the App Connector group hosting this AD domain>
```

Pros:
- One entry covers current + future servers
- Matches Zscaler's published AD-through-ZPA reference

Cons:
- All hosts under `*.<ad-domain>` become reachable — no per-host access
  restriction possible. Use segment-level ACLs if per-host policy needed.

### Option B — Explicit SRV coverage (per-record)

Keeps the existing per-hostname segments and adds ONE additional segment
listing every AD service-discovery record type.

```
Name:           <Customer> AD - Service Discovery (<ad-domain>)
FQDN:           _kerberos._tcp.<ad-domain>
                _kerberos._udp.<ad-domain>
                _kerberos._tcp.*.<ad-domain>
                _kerberos._udp.*.<ad-domain>
                _ldap._tcp.<ad-domain>
                _ldap._tcp.*.<ad-domain>
                _gc._tcp.<ad-domain>
                _gc._tcp.*.<ad-domain>
                _kpasswd._tcp.<ad-domain>
                _kpasswd._udp.<ad-domain>
                <ad-domain>
Ports (TCP):    88, 389, 464, 636, 3268, 3269
Ports (UDP):    88, 389, 464
Server Group:   <the App Connector group hosting this AD domain>
```

Pros:
- Preserves narrower per-server ZPA policy
- No blanket wildcard exposure

Cons:
- More segments to maintain when AD sites change or GUIDs rotate

### Recommended default

**Option A** unless the customer has a specific compliance / policy reason
for per-host restriction. In practice, Option A is what Zscaler PSE
architects deploy 90% of the time.

## Verification

After the App Segment is pushed:

1. From the affected client, run:
   ```
   nltest /dsgetdc:<ad-domain>
   ```
   This should return a DC name with no Kerberos errors.

2. From the affected client:
   ```
   klist            (should show current tickets)
   net use Z: \\<dc-hostname>\netlogon
   ```
   Should mount without prompting.

3. Re-export a fresh ZCC bundle 5 minutes after the segment push.
   In the new bundle:
   ```
   grep -c "ZPN_ERR_DNS_CHECK_NO_ASSISTANT" ZSATunnel*.log
   grep -c "BRK_MT_CLOSED_FROM_ASSISTANT" ZSATunnel*.log
   ```
   Both should be 0 (or dramatically reduced — a handful of
   NO_ASSISTANT on non-AD-related names is fine).

## Reference cases

- **Synthetic example**: `corp.example.com` had `dc01` and `member01`
  segments but NO SRV coverage. 10 distinct SRV/A NO_ASSISTANT
  failures within 300ms → 211 BRK_MT_CLOSED SMB attempts to
  `dc01.corp.example.com:445` before the diagnostic export.
  Fixed by adding a `*.corp.example.com` wildcard segment.

## Related detectors

- `zpa_dns_check_not_found` — catches ANY missing app segment via
  `ZPN_ERR_DNS_CHECK_NOT_FOUND`. If the customer's DNS query has never
  been resolved by ANY segment, that detector fires. `NO_ASSISTANT`
  (this detector) is subtly different: the segment exists in policy
  but no App Connector is currently serving it.
- `zpa_broker_assistant_close` — surfaces the DOWNSTREAM
  `BRK_MT_CLOSED_FROM_ASSISTANT` pattern. When both fire, this
  detector's finding is the root cause; that one is the symptom.
