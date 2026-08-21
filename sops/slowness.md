# Slowness / performance degradation — triage runbook

## Background

Zscaler's official Traffic Forwarding Troubleshooting Runbook treats
performance as a *methodology-only* issue: diagnose by isolation (bypass
test, direct-vs-tunneled compare, ZDX cloud-path scoring), not by log
pattern matching. The `slowness` detector adds a log-grounded layer on
top of that methodology by consolidating the signals ZCC actually
emits about slowness into a single finding.

This SOP documents how to read the consolidated finding and what to do
about each signal.

## #slowness

### What the detector aggregates

The detector pulls from **six** independent signal sources:

1. **ZTraceroute elbow** (`zdx_traceroute` files). Per-hop RTT probes
   to one or more destinations. The detector finds the "elbow" — the
   hop where RTT jumps the most — and classifies its hop index into
   a path segment:

   | Hop range | Segment                          |
   |-----------|----------------------------------|
   | 1–3       | Customer LAN / WiFi              |
   | 3–7       | Local ISP / regional transit     |
   | 7–12      | Zscaler edge ingress             |
   | >12       | Zscaler back-end (rare)          |

   This is the **highest-value** signal because it tells you *where*
   in the path the latency lives, which determines who you escalate
   to.

2. **DTLS → TLS fallback frequency** (`ZSATunnel` log). UDP being
   shaped or dropped between the endpoint and the Service Edge causes
   ZCC to fall back to TLS, which costs handshake latency and reduces
   throughput.

3. **`zpn_dns_client_check elapsed_us`** (`ZSATunnel` log). The
   cloud-connectivity DNS check. Sustained values above 50ms indicate
   a slow upstream resolver — typically bad-WiFi DNS or a SOHO router
   DNS sinkhole.

4. **Probe RTT excursion** (`ZSATunnel` log). Zen probe RTT to the
   edge. The detector flags when p90 is more than 2x the median *and*
   p90 > 100ms.

5. **PMTU / fragmentation events**. Path-MTU black-holing. Causes
   retransmits and "slow but eventually works" feel. Fix by lowering
   `mtuForZadapter` in the forwarding profile to 1240.

6. **ZDX Webload TTFB / total** (`zdx_webload` files). When present,
   gives per-page DNS / TCP / TLS / TTFB / total timings. High TTFB
   with low DNS/TCP/TLS means slowness is server-side, not Zscaler.

### Severity rules

- **CRITICAL** when any of: 3+ signals contributing, ZTraceroute elbow
  delta ≥ 150ms, DTLS-fallback rate ≥ 5/hour sustained, TTFB p90 ≥ 5s.
- **WARNING** when 1–2 signals contributing at WARN threshold.
- **INFO** ("ZTraceroute not present") when the bundle has no
  `ztraceroute` log file — see the next section.

### Triage flow

1. **Bypass test first**. Disconnect ZCC and re-test the slow app.
   If the slowness goes away, the bottleneck is somewhere in ZCC's
   path (probably edge / cloud). If the slowness persists, it's NOT a
   ZCC issue and the rest of this runbook doesn't apply.

2. **Read the path segment** the ZTraceroute signal localized to
   (printed in the finding description).

3. **If LAN/WiFi**: escalate to customer endpoint / desktop team.
   Common causes: weak WiFi signal, switch port saturation, faulty NIC
   driver. Also check `adapter_instability` detector — if it fired
   alongside, the underlying issue is adapter churn.

4. **If local ISP / regional transit**: escalate to the customer's
   network team and have them open an ISP ticket with the
   ZTraceroute output. Common causes: ISP egress congestion,
   asymmetric routing, BGP path change.

5. **If Zscaler edge ingress**: open a Zscaler support case with the
   bundle attached. Mention which SME they're connected to (from the
   Network Identity panel) and the elbow hop / RTT.

6. **If DTLS fallback dominates**: corporate firewall or ISP is
   probably rate-limiting or blocking UDP. Have the customer's
   network team check QoS / UDP policy on the upstream path.

7. **If webload TTFB dominates**: the slowness is server-side.
   Confirm with a direct-to-app test (bypassing ZCC) — same TTFB
   means the app or its upstream dependencies are slow.

## #cpt-event

This INFO finding fires when ZTraceroute records a cluster of probes
egressing through an SME IP that's listed in the bundle's SME→DC map
(i.e. an SME that ZCC knows by name from the customer's regional
gateway pool). This is the signature of the user opening the Zscaler
Cloud Performance Test page at `https://zscaler.com/test`.

### Use it to

- Match a Cloud Performance Test screenshot the customer sent you to a
  specific moment in the bundle window. The DC named on the test page
  ("TLV2", "CPH3", etc.) should match the DC listed in this finding.
- Confirm the customer is connecting through the correct regional DC.
  If the CPT-page DC matches the active tunnel SME, routing is healthy.
  If they differ, ZCC and the browser are taking different paths to
  Zscaler — investigate PAC, bypass, or subcloud config.

## #ztraceroute-missing

This INFO finding fires when the bundle has no `ztraceroute` log file
present, which means the customer's app profile does NOT have
**Diagnostic Route Collection** enabled.

Without ZTraceroute the slowness detector can only fall back to
secondary signals (DTLS fallback, DNS elapsed, probe RTT, PMTU). These
tell you *that* something is slow but not *where* in the path the
latency lives.

### Action

1. In **Mobile Admin** → **App Profiles** → (customer's profile) →
   **ZCC Settings**, enable **Diagnostic Route Collection**.
2. Have the customer reproduce the slowness with the flag on.
3. Re-export the ZCC support bundle.
4. Re-run this analysis.

The ZTraceroute file will allow the detector to localize the elbow
to a specific path segment — turning "the app feels slow" into an
actionable escalation to the right team.
