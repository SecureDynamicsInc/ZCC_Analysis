# ZCC Log Explorer User Guide

This guide is for support engineers investigating Zscaler Client Connector
(ZCC) behavior on a user workstation. The explorer processes evidence locally
and helps you move from a broad support bundle to the exact records behind a
session, state change, network flow, or configuration fact.

The explorer is an investigation aid, not a Zscaler product and not an
automatic root-cause engine. Its output should be combined with the reported
symptom, the complaint time, current tenant policy, and any cloud-side evidence.

## 1. Start the explorer

### macOS or Linux

```bash
git clone https://github.com/SecureDynamicsInc/ZCC_Analysis.git
cd ZCC_Analysis
./start.sh
```

### Windows PowerShell

```powershell
git clone https://github.com/SecureDynamicsInc/ZCC_Analysis.git
cd ZCC_Analysis
.\run_ui.ps1
```

The first start creates a private Python environment and installs Streamlit.
The explorer opens at `http://127.0.0.1:8501`, or the next free local port.
Leave the terminal window open while using it. Stop the app with `Control-C`.

**Use HTTP, not HTTPS.** Copy the printed address exactly, including
`http://`. The local analyzer does not serve HTTPS. If the browser upgrades the
address, enter `http://127.0.0.1:8501` again or disable HTTPS-only upgrading for
this local address. On macOS or Linux, `./server.sh open` opens the explicit
HTTP URL for you.

On a Mac, install it as an always-on user service when you do not want to keep
a Terminal window open:

```bash
./server.sh install
./server.sh status
./server.sh logs
```

The service starts at login and restarts the analyzer after an unexpected exit.
Run `./server.sh install` again after updating the repo, or remove the service
with `./server.sh uninstall`.

The listener is restricted to the workstation. The explorer does not send the
selected logs to a hosted analyzer or third-party enrichment service. Optional
Agent assist is off by default and has a separate review-and-consent boundary.

### Choose an experience level and appearance

The controls at the top apply to the whole workspace:

- **Novice** is the default. It automatically uses a useful recent history
  window, leads with one plain-language conclusion, shows only a few supporting
  checks, and hides packet streams, status tags, identifiers, and raw records.
- **Pro** exposes history depth, all technical signals, M-Tunnel details,
  packet-stream analysis, metadata, arbitrary search, traffic grouping,
  inventories, and raw evidence.
- **Light mode** switches the complete interface to a high-contrast light
  palette. Turn it off to return to dark mode. The selection persists while the
  local browser session remains open.
- **All / ZIA / ZPA** focuses the entire guided workspace. Choose ZIA for
  Internet & SaaS, ZPA for private applications, or All when the service is
  unknown. Shared DNS, TCP, TLS, and evidence-coverage findings remain visible
  where they can affect either service.

Start in Novice even if you are an experienced engineer. Move to Pro when the
guided result does not settle the case, the incident is older than the analyzed
window, or you need to prove the conclusion from lower-level evidence.

## 2. Capture the case context first

Before opening logs, write down:

- user and device name
- operating system and ZCC version
- exact symptom and any visible error text
- incident date, local time, and time zone
- whether the issue is continuous or intermittent
- whether Internet & SaaS (ZIA), Private Access (ZPA), or both are affected
- affected destination, application, or domain
- network context, such as office, home, hotspot, VPN, wired, or Wi-Fi
- what changed immediately before the issue

This context prevents a common mistake: finding a real but unrelated error
outside the user's complaint window.

Zscaler's troubleshooting runbooks similarly begin by narrowing the affected
traffic, location, forwarding method, and client-side or intermediate-network
conditions before escalating to deeper analysis. See the official
[ZCC performance runbook][zcc-performance] and
[Internet & SaaS performance runbook][zia-performance].

## 3. Collect useful evidence

Whenever possible, collect a complete exported ZIP after reproducing the issue.
The current logs show the newest activity; compressed rotations carry older
history and are essential when the complaint predates the newest files.

On supported clients, open Zscaler Client Connector and go to **More >
Troubleshoot**. Availability depends on the organization's supportability and
privacy settings. Zscaler documents **Start Packet Capture**, **Report an
Issue**, **Export Logs**, logging modes, service restart, and repair options in
[Troubleshooting Zscaler Client Connector][zcc-troubleshoot].

Recommended collection sequence:

1. Record the current time and time zone.
2. If authorized, select an appropriate log mode. `Info` is a useful general
   baseline; `Debug` captures more detail but grows logs faster. Zscaler notes
   that a user-selected mode applies only to the current connection session.
3. If packet capture is enabled and relevant, start it before reproducing the
   issue. Packet captures are particularly useful for timing, DNS, transport,
   and path questions that application logs alone cannot settle.
4. Reproduce the problem once and record the exact time.
5. Stop the capture, if used, and choose **Export Logs**.
6. Preserve the ZIP unchanged. Do not clear logs until the case is complete.

Important distinctions:

- Zscaler states that exported Windows and macOS logs from ZCC 2.1.2 or later
  are not encrypted, while logs attached through **Report an Issue** are
  encrypted. Use the normal exported ZIP for this local explorer. See
  [Configuring User Access to Logging Controls][logging-controls].
- A packet capture can contain sensitive traffic metadata or content. Handle it
  under the customer's data-handling rules. Zscaler's
  [User Privacy documentation][user-privacy] describes the controls for packet
  capture, log-folder access, hostname, and device-owner collection.
- Zscaler notes that packet-capture files are not included automatically in the
  archive generated by **Report an Issue**. Preserve them separately when they
  are part of the investigation. See [Enabling Packet Capture][packet-capture].

## 4. Choose the right input

The upload area accepts either the entire ZCC support ZIP or individual log
files. If the cause is unknown, upload the entire ZIP. For the fastest focused
connection check, upload `ZSATunnel.log` by itself; it is the single best log in
most cases.

### Complete support bundle

Select one `.zip` file. This is the preferred input because it preserves
component logs, rotations, configuration artifacts, identities, and system
information together.

### One individual log

Select one `.log`, `.txt`, `.xml`, `.json`, `.csv`, `.tsv`, `.conf`, or `.ini`
file when only a targeted artifact is available. The explorer wraps it in a
temporary local bundle and runs the same evidence pipeline.

### Several individual logs

Select multiple supported files together when an engineer has collected a
focused set. Do not mix a ZIP and individual files in the same upload.

For a focused connection case, `ZSATunnel.log` is the most useful individual
file: it carries Internet and Private Access tunnel states, M-Tunnel setup and
close records, destinations, application names, and many documented status
codes. An individual log can answer a narrow question, but it cannot prove
what was absent from components that were not supplied. The explorer calls out
that evidence boundary explicitly.

## 5. Pro only: choose the history depth

Novice chooses the recent history window automatically and does not expose
rotation terminology. In Pro, **Pro analysis settings** controls how much
compressed history is indexed for each log component.

| Choice | Best use | Tradeoff |
| --- | --- | --- |
| Current logs only | Very recent incident or quick orientation | Fastest, but older evidence is excluded |
| Newest 10 rotations | Recommended first pass | Good recent history with moderate processing time |
| Newest 50 rotations | Older or intermittent incident | More disk use and processing time |
| Newest 200 rotations | Long-running or infrequent problem | Can take several minutes |
| Everything | Full historical reconstruction | Highest time and disk cost |

Start with the newest 10 rotations. Compare the incident time with the parsed
span on **Guided summary**. Increase the depth only when the complaint falls outside
that span or when a longer baseline is necessary. The banner states exactly how
many rotations were found and read.

## 6. Use the views in investigation order

### What we found / Guided summary

Choose the symptom closest to the user's report. Novice labels this view
**What we found**; Pro labels it **Guided summary**. The explorer reorders direct
evidence around that question and leads with one of four outcomes:

- **Hard failure:** an explicit terminal tunnel state, failed DNS response,
  fatal TLS alert, no route, or other direct failure evidence.
- **Intermittent or degraded:** a failure followed by recovery, a reset that
  needs sender/timing review, retransmission evidence, or a timeout.
- **Policy decision:** the M-Tunnel was denied by a documented ZPA policy or
  session status rather than failing at transport setup.
- **Evidence gap:** the selected files or rotations cannot answer the question.

Before those broader symptoms, the analyzer checks each record for a known,
documented Zscaler code or unambiguous status message. A critical or warning
match leads the result, shows how often it recurred, preserves one inline sample,
and gives the documented next step. Informational close/status codes do not
displace an actual failure.

Read the leading card in order: **Conclusion**, **Evidence**, then **Do this
next**. Confirm that the parsed time span covers the complaint. A high count
alone is not a root cause; the explorer prioritizes terminal state, recovery,
documented status, and packet behavior.

#### This bundle at a glance

Directly under the leading conclusion, a recap answers the questions that
determine how that conclusion should be read: which user and device the evidence
came from, the client version, the time span and device time zone it covers, and
whether a packet capture was included. Pro adds the parsed record count, how many
compressed rotations were read, and a note when no DEBUG records are present —
because without Debug log mode a quiet subsystem may simply not have been logged.

Every field is read from the parsed bundle. A blank one reads *Not evidenced in
these logs*, which means the value was not found in the material read, not that
it is empty on the device.

#### What is in this bundle

The recap expands into a checklist of every evidence type Zscaler Client
Connector can include — present or not — with what each one is expected to tell
you and, in Pro, when to reach for it. The missing rows are the useful ones: an
absence here is a collection gap, not a finding, and the checklist says what the
missing log would have shown so it can be requested by name.

When the tunnel log, service log, policy/profile log, or a packet capture is
absent, the recap says so explicitly above the checklist, because each one limits
what any conclusion below it can establish.

Descriptions follow Zscaler's own definitions of Client Connector logs. The most
useful ones to recognise:

| Evidence | What it holds |
| --- | --- |
| `ZSATunnel.log` | Tunnel status, operation, and errors: which data centers the client connected to, profile and policy downloads, and requests for specific domains. The first log to open, and the single best one if you can collect only one. |
| `ZSAService.log` | The privileged service that enforces forwarding: driver and adapter state, route and DNS programming, service start/stop history. |
| `ZSAUpm.log` | Policy and profile delivery: forwarding and app profile downloads, PAC retrieval and reload, trusted-network evaluation. |
| `ZSATray*.log` | The Client Connector application and its usage on the device, including user interactions with the UI such as enabling and disabling services. |
| `ZSAUpdater.log` | Client version upgrade history — the first thing to check for "it broke after an update". |
| `*.pcapng` | Packets captured at the adapter level across all adapters. Aligns to the logs by timestamp. |

Sources: [Zscaler Client Connector Logs](https://help.zscaler.com/logs-fair-use/zscaler-client-connector-logs)
and [Enabling Packet Capture](https://help.zscaler.com/zscaler-client-connector/enabling-packet-capture-zscaler-client-connector).

### Raw ZSATunnel log

Its own tab, in both Novice and Pro. The **entire current `ZSATunnel.log`** in
one scrolling window, in file order, with nothing filtered out.

This exists because a filtered page cannot answer the question that usually
matters. A reset, a rejected assertion, or a failed lookup is rarely
self-explanatory: the setup attempt above it and the retry below it are what
identify the cause. So this view removes nothing by default and lets you read
the log the way you would in an editor.

Records are coloured by severity — **critical red, medium orange** — on the same
basis as the paged Raw viewer: the documented error catalog first, the record's
own level as fallback. The counters above the window give the totals for the
whole log, not just a page, so "825 critical" is a fact about the file.

**Jump to a critical record** lists the critical records and scrolls the window
to any of them, landing it mid-window with the surrounding log still in place.
That is the point of the list: it moves you *to* a record in context rather than
filtering the log down to it.

**Show levels** filters by the level the client logged — `ERR + WAR`, `ERR only`,
or `WAR only` — and every record keeps its own line number, so a filtered view
still tells you where you are in the file. `All records` is the default on
purpose.

Flagged records are high contrast across the whole line in both light and dark
mode: red for `ERR` and `CRT`, orange for `WAR` and `WRN`, with the wash reaching
the end of the longest line rather than stopping at the window edge. The level
column itself is colour-coded per level, so a log can be scanned by level without
reading the text: `ERR`/`CRT` red, `WAR`/`WRN` orange, `INF` blue, `DBG` grey,
`TRC` grey italic.

#### 100.64.x.x addresses

An address in this range is almost never a real destination, and treating it as
one sends an investigation to the network team for a client-side fault. Each
occurrence is underlined in the log and carries a hover note, and the view lists
every one it found with an explanation.

`100.64.0.0/10` is shared address space (RFC 6598). Zscaler Client Connector's
default **synthetic IP range is `100.64.0.0/16`**: when DNS matches a Private
Access application, the client answers with an address from this pool and
captures traffic sent there into the tunnel — see
[Configuring the Synthetic IP Range](https://help.zscaler.com/zscaler-client-connector/configuring-zscaler-client-connector-synthetic-ip-range).
The range is configurable per tenant, and a tenant whose LAN overlaps it can
enable *Drop Non-Zscaler Packets in Synthetic IP Range*.

So a failure to reach one of these is a local interception problem, never an
unreachable server. To find which application a synthetic address stands for,
look for the DNS record in the log that handed it out.

Zscaler does not publish a per-address map, and the analyzer does not invent one.
Two low addresses carry roles that appear in the bundles this analyzer was
measured on, and those are labelled **observed** rather than documented so the
distinction is visible: `100.64.0.6:80` as the client's own ZIA tunnel health
check (`checkTunTcpEchoServerUpImpl`), and `100.64.0.8:9090` as a probe target. Long lines
do not wrap, and the window scrolls horizontally to the end of the record; turn
on **Wrap long lines** to read a long line without scrolling.

Which log is "current" is decided by the newest last-record time, not by the
filename. Rotations can carry the same basename as the live file and the store
deduplicates labels (`ZSATunnel.log`, `ZSATunnel.log#2`), so the timestamp is
the only reliable discriminator. The caption names the file chosen and says how
many candidates it was chosen from.

A live tunnel log is tens of thousands of records, which the window handles by
letting the browser skip offscreen rows. If a bundle read at full rotation depth
presents more than 120,000 records, the **most recent** are shown and the view
states how many older records it left out — the newest records are where an
incident lives. Use **Deep evidence → Raw** to page through everything.

Novice gets the same tab with plain-language framing, since reading the log is
useful whether or not you know the product yet.

### Fix a connection / Tunnels & apps

Use this tab for most connection cases. Novice presents plain-language problem
filters and recommended actions. Pro shows the full ZIA/ZPA evidence. Its top row shows the last
explicit `getSmeProxyState` and `getZpnProxyState`, plus how many error states
were observed. An error count can include retries, so the latest state matters:
`SERVER_DOWN_ERROR` followed by `TUNNEL_FORWARDING` is an intermittent recovery,
not a current hard failure.

For ZPA, the explorer reconstructs M-Tunnel sessions and provides one-click
filters:

- **Setup failed** for attempts that never established
- **Policy blocked** for documented policy/session decisions
- **Server reset** when the session code identifies a server-side close/reset
- **No server response** when bytes went toward the server with no observed reply
- **Data dropped** for explicit byte-flow imbalance evidence
- **Other failure** for a documented non-normal code outside the common groups
- **Open / incomplete** when the selected log window ends before the outcome
- **Normal** for a baseline comparison

Filter further by application, hostname, IP, port, status code, tag, or
M-Tunnel ID. Select one session to see the documented meaning, recommended
resolution, and exact correlated records. The status-code text comes from the
bundled Zscaler reference, not from a generic keyword guess.

### Error code help

Use this tab when ZCC displays a numeric code such as `1`, `2`, `3`, `4`, or
`5`, when the user reports a signed authentication code such as `-13`, or when
the tunnel log contains a symbolic ZPA session code. Codes detected in the
selected logs appear first with their documented meaning and next action.
Each detected code includes one representative matching log record with its
source file, line number, and timestamp. The occurrence count still reflects
all matches in the selected evidence.

You can also enter a code manually, even before uploading logs. For example,
code `2` points to an expired or invalid ZIA authentication cookie and directs
the engineer to reauthenticate the user; code `4` identifies a device/server
time mismatch and directs the engineer to correct system time. Treat the code
as a focused lead, then confirm it occurs in the complaint window and matches
the user's symptom.

### Known error reference

This tab exposes all 749 locally bundled entries across ZCC, ZIA, ZPA, and ZDX.
Filter by product and analyzer severity pills, narrow to one or more reference
families, or search the code, message, symptom, component, and likely fix. When
logs are loaded, matching entries sort first and show their occurrence count.

The severity is a local triage hint derived from documented impact; it is not a
Zscaler support priority. The source link on each entry opens the applicable
official Zscaler reference. The catalog works offline after cloning, including
before a bundle is uploaded.

If an engineer finds a missing or incorrect code, use **Report a missing or
incorrect code to SecureDynamics**. Include the exact value and, when needed,
one minimal synthetic line created from scratch. Never transform or redact a
real record for an Issue, and never attach customer logs, screenshots, captures,
patches, or code. Issues are the only community contribution path;
SecureDynamics independently verifies and implements accepted corrections.

### PAC files

A PAC decides, per host, whether traffic goes DIRECT or is forwarded to a
Zscaler service edge, so it is the first thing to read when a site appears not
to be going through the tunnel. The bundle never presents it as a file, so this
tab recovers it from two places:

- a standalone `.pac` or `.js` artefact carried in the bundle, and
- the copy ZCC writes into its own tunnel, service, or UPM log when it
  downloads or reloads one — including a PAC logged one preamble-prefixed line
  at a time, or stored as an escaped configuration string.

The source is shown unmodified and complete, with syntax colouring, line
numbers, the file's own indentation at 4-space tabs, and no line wrapping, so it
reads as it would in an editor. Only the log preamble and string escaping are
removed; indentation and comments are preserved.

#### Live rules only

The counts above the source — DIRECT returns, proxy returns, host patterns,
subnet tests — cover **live rules only**. A PAC is a working document, and a
deployment's history stays in it as commented-out bypasses: the measured MSSP
template carries 38 commented-out host patterns, and two of its three PROXY
returns are inactive. Counting those as live would answer "is this host
bypassed?" with a yes for a rule that is switched off, so anything inside `//`
or `/* */` is excluded from the counts and listed under **Commented out — not
in effect**. Read that list as deployment history; a host named there is not
currently bypassed.

The counts describe what the file does and pass no judgement on whether a given
bypass is correct for the tenant. Expanders list the live proxy return
statements, every host pattern named in a live `shExpMatch`,
`localHostOrDomainIs`, or `dnsDomainIs` call, and the surrounding raw log text
for confirming the recovered boundaries.

#### Forwarding targets

Below the counts, **Forwarding targets** breaks the live PROXY return into its
ordered failover list — the sequence the client tries before falling through to
DIRECT.

Zscaler's PAC server substitutes real Public Service Edge addresses for the
`${GATEWAY}` family when it serves the file, allocating healthy gateway
addresses across the variables, and the `_FX` suffix issues them per country
based on the client fingerprint (see
[Writing a PAC File](https://help.zscaler.com/zia/writing-pac-file)). So the
authored template names variables while a PAC recovered from a client's own logs
names literal addresses. The view labels which one it is: an **Authored
template** notice lists the unsubstituted placeholders, and a delivered PAC is
identified as the forwarding list a client was actually served.

Literal gateway addresses get the same local MaxMind treatment as any other
endpoint, so Organization, ASN, Country, and City confirm a gateway is
Zscaler-owned and show which data centre the client was pointed at — for
example `165.225.60.15` as ZSCALER, INC. AS22616 in Chicago.

Identical copies collapse into one entry with an occurrence count, so a PAC
re-downloaded across dozens of rotations is shown once. When two genuinely
different PACs are present — for example a current and a superseded tenant
configuration — each is listed separately and selectable.

Anchoring is strict: only an actual `function FindProxyForURL(...) {` definition
counts, so ordinary log prose such as "PAC fetch successful" never produces a
PAC entry. An empty result therefore means no PAC body was present in the files
read, **not** that the tenant has no PAC. A PAC configured by URL is fetched at
runtime and is only visible here when ZCC recorded its contents in a log that
was included and read. The Pro view prints its coverage — files read and bytes
scanned — and says so explicitly when a scan cap was reached.

Novice shows this tab as **Proxy settings (PAC)** only when a PAC was found.

### Pro only: Agent assist

Agent assist detects an installed Codex or Claude Code command and offers a
single second-opinion turn. It is optional and is not part of normal analysis.

1. Select the correct All, ZIA, or ZPA service view.
2. Open **Agent assist** and review the exact derived briefing.
3. Download it instead if you prefer a manual handoff.
4. Only after review, select the consent checkbox and ask the agent.
5. Verify its response against the analyzer evidence and official Zscaler
   documentation.

The briefing contains a bounded set of conclusions, evidence summaries, codes,
and recommended next steps. It does not attach the raw ZIP, raw log records, or
packet capture. The app remains on `127.0.0.1`, but Codex or Claude may send the
displayed briefing to its configured model provider. Do not use Agent assist
when the case's data-handling rules prohibit that disclosure.

### Problem endpoints (Pro)

Use this tab to find destinations that deserve attention before opening raw
streams. One row combines the remote IP and port with:

- TCP SYN attempts and captured SYN-ACK replies
- TCP resets, suspected retransmissions, and TLS alerts
- a hostname learned from captured DNS answers or TLS SNI, when present
- byte and packet context
- optional ASN, network owner, provider classification, country, and city from
  local MaxMind GeoLite data

The label “SYN without captured SYN-ACK” means only that the reply was not
observed inside this capture. A capture may start late, end early, omit an
adapter, or miss packets, so use it as an investigation lead rather than proof
of a failed remote host. Open **Packet analysis** to inspect the relevant
stream, sender, timing, and sequence.

Hostname resolution is passive: the analyzer correlates DNS answers and TLS
SNI already present in the capture. It does not perform reverse DNS or send
customer IP addresses to an external service.

#### Endpoint statistics

Below the signal table, **Endpoint statistics** presents the same columns as
Wireshark's **Statistics → Endpoints**, summed across every capture in the
bundle: Address, Packets, Bytes, Tx Packets, Tx Bytes, Rx Packets, and Rx
Bytes, plus the hostname the capture proves and the Country, City,
Organization, and ASN that local MaxMind data supplies.

Tx is what that address **sent**; Rx is what it **received**. Tx and Rx
therefore add up to Packets on every row. Bytes are captured frame lengths, the
same quantity Wireshark reports, so the two tools can be compared directly — a
capture taken with a short snaplen truncates frames and lowers both counts.

The scope selector matches Wireshark's tabs. **IPv4** and **IPv6** list
addresses; **TCP** and **UDP** list address and port. Ethernet endpoints are
not offered: MAC addresses are not extracted, they carry no ASN, geography, or
hostname context, and they would add a hardware identifier to exports.

#### Captured hostnames and resolved addresses

DNS evidence joined to packet evidence. Each row is one hostname/address pair —
every A and AAAA address a name was actually observed to resolve to, with its
family, the traffic seen against that address, and its ASN context. A name that
resolved to several addresses produces several rows, because owner and
geography can differ between the addresses behind one name.

An address that was answered but never contacted inside the capture is listed
with zero packets rather than omitted, so the operator can see that the
resolver offered it. Packets and Bytes count all traffic to and from that
address, which can include flows unrelated to the hostname when an address is
shared by many services.

The same answers appear per query in **Packet analysis → Raw tables → DNS
queries**, split into IPv4 and IPv6 columns. An empty answer cell means no
address answer was captured for that name: a cached lookup, an encrypted
resolution over DoH or DoT, or a response outside the capture window leaves no
record to read.

#### Optional local MaxMind data

The landing page shows an **Endpoint ownership** status light next to the upload
box, so the state is visible before a capture is analyzed rather than after. A
green dot means a local `GeoLite2-ASN.mmdb` was found and packet-capture
endpoints will resolve to a named network. A red dot means they will be listed
as bare addresses, and **Fix this · enable endpoint ownership** opens the setup
view. Without ASN data a reset, retransmission, or unanswered SYN cannot be
attributed to a Zscaler service edge, the customer's own server, or an
unrelated provider.

For ownership and ASN context, create a free MaxMind account and download the
binary `GeoLite2-ASN.mmdb` database. `GeoLite2-City.mmdb` is optional. Use the
landing-page setup view, or in **Problem endpoints** expand **Manage local
MaxMind databases**, choose the files, and explicitly save them on the
workstation. Both routes drive the same panel. They are validated and stored
under `~/.zcc-log-explorer/geoip`, or under `ZCC_GEOIP_DIR` when that
environment variable is set. They are never uploaded by the analyzer or added
to Git automatically.

The repository intentionally does not distribute MaxMind databases. Review the
current GeoLite license, provide the required attribution, keep the data
current, and remove superseded copies. City-level results are approximate and
must not be used to identify a person, household, or street address.

This product includes GeoLite Data created by MaxMind, available from
https://www.maxmind.com.

### Packet analysis and Wireshark display filters (Pro)

For each selected capture, **Verify in Wireshark** builds filters from signals
actually found in that file. Failed DNS filters include the observed query names;
TCP reset, retransmission, TLS alert, and unmatched-SYN filters include the
affected captured endpoint addresses. Use the copy button on the code block,
open the named `.pcapng` in Wireshark, and paste the complete expression into
the **Display Filter** bar.

The **Zscaler Wireshark display-filter library** also provides reusable recipes
for unsuccessful DNS responses, NXDOMAIN, SERVFAIL, slow DNS, SYN attempts,
resets, retransmissions, receive-window pressure, TLS alerts, SNI, proxy CONNECT,
UDP/TCP 443 tunnel transport, and ICMP/ICMPv6 errors. These are display filters,
not capture filters. Parentheses and logical operators are already included.

```text
(dns.flags.response == 1) && (dns.flags.rcode != 0)
tcp.flags.reset == 1
tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission
tls.alert_message.level == 2
```

ZCC can capture at the adapter layer and, on supported clients, at the packet-
filter-driver layer. Wireshark's view is bounded by the selected capture,
adapter, start/end time, and dissector behavior. A missing packet or SYN-ACK is
therefore a lead, not proof that it never existed.

### Update notice after upload

Selecting an input triggers a cached, read-only check of the clone's configured
GitHub `origin/main` using existing Git authentication. No filename, log
content, endpoint, identity, or customer data is
sent. When a newer baseline exists, copy either the safe fast-forward command
or the provided Codex/Claude prompt. The prompt tells the agent to preserve
local and untracked changes, inspect the diff, integrate `origin/main`, run the
tests, and reinstall the always-on service. If the fast-forward command stops,
do not force it; use the agent prompt or review the branch manually.

### Packet analysis (Pro)

Use this tab to confirm what happened on the wire. The explorer suggests
problem streams when it observes:

- DNS responses with a non-success response code
- TCP RST packets
- suspected TCP retransmissions
- fatal TLS alerts

Choose a suggestion or enter an application hostname, IP address, or port, then
select **Follow matching streams**. For a reset, inspect sender, direction, and
timing; a RST is evidence of a reset, but its meaning depends on where it occurs
in the conversation. For DNS, confirm the queried name, resolver, and response
code. For TLS, identify the alert and which endpoint sent it.

ZCC packet capture can observe adapter and packet-filter paths that may not be
equivalent to a conventional Wireshark capture. Use the capture as bounded
evidence for its recorded window, not proof that an uncaptured event did not
occur. See [Enabling Packet Capture][packet-capture].

#### Raw log viewer

The Raw tab inside Deep evidence reads a single log file page by page, straight
out of the parsed index. Pages go up to 50,000 records, so a log is scrolled
rather than clicked through, and long lines do not wrap by default so the record
structure stays intact — turn on **Wrap long lines** when you would rather read
a long line than scroll it.

Each record is coloured by severity: **critical in red, medium in orange**,
everything else uncoloured. Severity comes from two places and the stronger
wins:

- the **documented error catalog** — 310 critical and 360 warning entries — which
  is the authority on impact, so a documented critical code colours the record
  even when it was logged at INFO, and
- the **record's own level**, where ERROR, FATAL, and CRITICAL are critical and
  WARN is medium, which catches failures carrying no documented code.

Hovering a coloured record says which of the two earned it. The legend above the
listing counts critical, medium, and other records on the current page, and
**Show** narrows the page to critical only or critical plus medium.

Token colouring is unchanged in meaning but now readable in both themes:
timestamps, symbolic ZS codes, `tag_id`, `err_code`, session and tunnel
identifiers, broker hosts, log levels, and IPv4 addresses each have their own
colour. A substring filter additionally highlights every hit in place.

Note that severity here describes a single record. It is a reading aid, not a
verdict: a red record is not automatically the cause, and the guided summary
remains the place where evidence is weighed.

### Deep evidence (Pro)

Load this workspace only when the guided tabs do not settle the case. It
contains precise search, session and timeline correlation, traffic grouping,
facts and coverage, configuration inventories, and the raw record browser.

For traffic-forwarding cases, useful searches include the exact visible error,
application or destination, `getSmeProxyState`, `Tunnel Forwarding Status`,
`SERVER_DOWN_ERROR`, `FIREWALL_BLOCK_ERROR`, and the ZPA session code. Zscaler's
official runbook uses the same PAC, gateway, proxy-state, firewall/interception,
and UDP 443 versus TLS failure domains. See the
[ZCC traffic-forwarding runbook][zcc-forwarding].

Use traffic bytes only when they answer a question, such as which destination
dominated a window or whether a reconstructed session shows one-way data. Use
the raw browser as the final evidence check before quoting a record in a case
note or escalation. Missing data means **not evidenced in the selected
material**, not proof of absence.

## 7. Investigation recipes

### Authentication or repeated sign-in

1. Confirm the complaint time and whether ZIA, ZPA, or both lost authentication.
2. Use **What we found** to check whether the authentication symptom coincides
   with a more basic tunnel or DNS failure.
3. In Pro, load **Deep evidence**, then search for the username, authentication
   status, reauthentication, IdP, PRT, token, and session identifiers.
4. Use its session and timeline views to separate user action, policy refresh,
   token state, and service or network transitions.
5. Verify quoted evidence in the raw view.

### Internet or SaaS connectivity

1. Record whether all destinations or only one domain is affected.
2. Choose **Internet access is not working** in Novice, or **Internet tunnel
   won't connect** in Pro, and confirm the
   complaint window.
3. Review the latest Internet tunnel state and any recovered errors in
   **Fix a connection** or **Tunnels & apps**.
4. If a PCAP exists, follow the affected domain/IP and check DNS, resets,
   retransmissions, and TLS alerts. Otherwise use **Deep evidence** to
   search PAC parsing, gateway, proxy state, and visible error text.
5. Use **Deep evidence > Traffic** only when destination or flow volume
   helps answer the case.
6. Correlate client evidence with the applicable ZIA logs and current service
   status before assigning the failure domain.

### Private Access application failure

1. Record the private application and whether other private applications work.
2. Choose **A private app is not working** in Novice, or **Private app won't
   connect** in Pro.
3. In **Fix a connection** or **Tunnels & apps**, select the relevant quick filter and narrow by the
   application domain or destination. Open the failed M-Tunnel session and read
   its documented meaning and resolution.
4. In Pro, use **Packet analysis** to confirm DNS, reset sender, retransmissions,
   or TLS behavior. Use **Deep evidence** for broker, policy, and timeline context.
5. Separate client-to-broker evidence from App Connector and application-side
   evidence. A client bundle alone may not establish the server-side cause.

### Slowness or intermittent performance

1. Narrow the scope by destination, location, network, and time of day.
2. Choose **Connections are slow or unreliable** in Novice, or **Slow or
   intermittent** in Pro, and check whether a tunnel
   error later recovered.
3. In **Fix a connection** or **Tunnels & apps**, filter to the application and optionally require slow
   setup. Compare with normal sessions for the same application.
4. In Pro, open **Packet analysis**, review retransmissions, and follow the affected stream.
   Use path testing when the capture cannot settle MTU, loss, latency, or
   UDP-throttling questions.
5. Load **Deep evidence** only when traffic-by-destination or network-event
   timing adds value.
6. Follow the official [ZCC performance runbook][zcc-performance] before making
   configuration changes. The runbook cautions that a single MTR is not enough
   to identify every transport problem.

### Windows service or driver issue

1. Review service lifecycle events in **Deep evidence > Timeline**.
2. Open **Deep evidence > Evidence map** for Windows driver history.
3. Correlate installation or repair timing with the first reported symptom.
4. Check endpoint security, VPN, operating-system, and network-adapter changes.
5. Do not use an old driver event by itself as proof of current causation.

## 8. Build a defensible case note

Use this structure:

1. **Reported symptom:** what the user experienced.
2. **Scope:** user, device, location, network, service, destination, and time.
3. **Evidence coverage:** files, rotations read, and parsed time span.
4. **Observed sequence:** timestamped facts in order.
5. **Most likely failure domain:** endpoint, local network, ZCC forwarding,
   ZIA, ZPA, identity provider, destination, or unknown.
6. **Confidence and limitations:** what supports the conclusion and what is
   missing.
7. **Next evidence or action:** the smallest step that can confirm or reject the
   current hypothesis.

Avoid absolute language when the bundle is incomplete. Prefer statements such
as “No matching event was found in the 18 rotations read” over “The event did
not happen.”

## 9. Privacy and safe sharing

- Keep the explorer bound to `127.0.0.1`.
- Treat support bundles, logs, and packet captures as customer-confidential data.
- The explorer permits one active run and provides no diagnostic export or AI
  handoff. Refreshing, resetting, or selecting different input destroys the
  prior run and its temporary workspace.
- Never copy analyzer output into the repository, a coding-agent prompt, an
  Issue, or a pull request. Redaction does not make customer evidence suitable
  project material.
- When another engineer needs the evidence, use the approved support exchange
  for the original bundle and have them perform a separate ephemeral run.

## 10. Common questions

### The explorer chose port 8502 or another port

Port 8501 was already in use. Open the exact URL printed in the terminal.

### The page says it is disconnected

Confirm the terminal is still running, then reload the printed local URL. A tab
from a previous app run may point to an old port.

### Analysis is taking a long time

Large bundles with many rotations can contain millions of records. Start with
the newest 10 rotations and expand only when the incident time requires it.

### A field, component, or driver event is missing

Confirm the selected files and time span first. Missing evidence is not proof
of absence.

### The encrypted Report an Issue attachment will not open

Use **Export Logs** from ZCC when policy permits. Zscaler documents that Report
an Issue logs are encrypted, while normal exported logs on current Windows and
macOS clients are not.

## Source basis

This guide was developed with BoostZ evidence retrieval and then cross-checked
against current public Zscaler documentation. Zscaler documentation is the
authority for product behavior, collection controls, and supported
troubleshooting procedures. The local analyzer's README and source code are the
authority for its interface and processing behavior.

[zcc-troubleshoot]: https://help.zscaler.com/zscaler-client-connector/troubleshooting-zscaler-client-connector
[logging-controls]: https://help.zscaler.com/zscaler-client-connector/configuring-user-access-logging-controls-zscaler-client-connector
[packet-capture]: https://help.zscaler.com/zscaler-client-connector/enabling-packet-capture-zscaler-client-connector
[user-privacy]: https://help.zscaler.com/zscaler-client-connector/about-user-privacy
[zcc-performance]: https://help.zscaler.com/troubleshooting-runbooks/zscaler-client-connector-performance-troubleshooting-runbook
[zia-performance]: https://help.zscaler.com/troubleshooting-runbooks/zia-performance-troubleshooting-runbook
[zcc-forwarding]: https://help.zscaler.com/troubleshooting-runbooks/zscaler-client-connector-traffic-forwarding-troubleshooting-runbook
