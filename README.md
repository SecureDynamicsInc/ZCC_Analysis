# ZCC Log Explorer

A desktop-first investigation workspace for Zscaler Client Connector
support bundles and individual log files. Engineers clone it, run it on their
own laptop, and open the interface at `http://127.0.0.1:8501`.

ZCC Log Explorer is an independent SecureDynamics community project. It is not
affiliated with, endorsed by, or supported by Zscaler. Analyzer results are
best-effort troubleshooting guidance and do not replace an authorized Zscaler
support determination.

> **Use HTTP, not HTTPS.** Copy `http://127.0.0.1:8501` exactly. This
> loopback-only application does not serve HTTPS, so a browser's automatic
> HTTPS upgrade will fail. `./server.sh open` opens the explicit HTTP address.

The uploaded data is processed locally for one browser run. The app does not
upload logs or findings to Google, GitHub, SecureDynamics, Zscaler, an AI agent,
or any third-party service. Refreshing, resetting, or choosing a different
upload destroys the prior run and its temporary workspace.

## Official project and licensing

SecureDynamics, Inc. is the original project steward. The official source is
[SecureDynamicsInc/ZCC_Analysis](https://github.com/SecureDynamicsInc/ZCC_Analysis),
and official project information is published at
[securedynamics.net/zcc-log-explorer](https://securedynamics.net/zcc-log-explorer).

The code is licensed under the [Apache License 2.0](LICENSE), which permits
use, modification, and redistribution while requiring preservation of the
license and applicable notices. That license does not grant rights to
SecureDynamics names, logos, or release branding. Forks must use their own name
and identity and may not imply SecureDynamics endorsement or official status.
See [TRADEMARKS.md](TRADEMARKS.md) and [NOTICE](NOTICE).

## What engineers get

- A conclusion-first guided summary that separates hard failures, intermittent
  recovery, policy decisions, and evidence gaps
- A **bundle recap** under the leading conclusion: user, device, OS, client
  version, the time span and time zone the evidence covers, and whether a packet
  capture was included
- An **evidence checklist** of every log ZCC can include, present or not, stating
  what each one holds and when to reach for it — so a missing log reads as a
  collection gap to request by name rather than as an absence of evidence
- A **Novice / Pro** control: Novice is the default guided workflow; Pro exposes
  history depth, packet streams, status codes, identifiers, and raw evidence
- A persistent-in-session **Light mode / Dark mode** control
- Tunnel-first triage using explicit ZIA/ZPA proxy states and reconstructed ZPA
  M-Tunnel setup, acknowledgement, close-code, destination, and byte-flow evidence
- An **All / ZIA / ZPA** service pill that keeps Internet & SaaS and Private
  Access investigations focused while retaining shared DNS, TCP, and TLS evidence
- One-click application filters for setup failures, policy blocks, server resets,
  missing replies, dropped data, incomplete attempts, and normal sessions
- Packet-capture problem suggestions for failed DNS responses, TCP resets,
  retransmissions, and fatal TLS alerts, plus complete TCP/UDP stream following
- Ready-to-copy Wireshark display filters generated from the selected capture's
  actual failed DNS names and affected endpoints, plus a reusable Zscaler filter library
- A problem-endpoint table showing unanswered SYN attempts, resets,
  retransmissions, TLS alerts, captured DNS/SNI hostnames, and optional local
  MaxMind ASN/provider/geography enrichment
- Wireshark-format endpoint statistics — Address, Packets, Bytes, and
  Tx/Rx split, per IPv4, IPv6, TCP, and UDP scope — with the captured hostname
  and MaxMind Country, City, Organization, and ASN on the same row
- Captured DNS answers in both families: every A and AAAA address a hostname
  resolved to, joined to the traffic and ASN context for that address
- An endpoint-ownership status light beside the upload box: green when a local
  MaxMind ASN database is present, red with a one-click setup view when it is
  not, so the gap is visible before a capture is analyzed rather than after
- A **PAC files** view that recovers the proxy auto-config from the bundle —
  standalone `.pac`/`.js` artefacts and the copy ZCC writes into its own log —
  and shows the source unmodified with editor-accurate syntax colouring, line
  numbers, and 4-space tabs, with identical copies collapsed to one entry
- PAC rule counts that cover live rules only, with commented-out bypasses listed
  separately instead of being counted as active
- PAC forwarding targets as an ordered failover list, labelled as an authored
  template or as the delivered list a client was served, with MaxMind ASN,
  organization, country, and city on each substituted gateway address
- Individual `.log`, `.txt`, `.xml`, `.json`, `.csv`, `.tsv`, `.conf`, and `.ini` support
- Multi-file intake for an ad hoc set of logs
- Compressed ZCC rotation support with an explicit depth control
- Disposable disk-backed indexing for large bundles, removed with the run
- An optional advanced workspace for facts, entities, ZCC-aware search, timelines,
  traffic grouping, Windows driver history, configuration inventories, and raw evidence
- A raw log viewer with pages up to 50,000 records, severity colouring —
  critical red, medium orange, from the documented catalog and the record level —
  in-place filter-match highlighting, and a wrap toggle
- A **Raw ZSATunnel log** tab in both Novice and Pro: the entire current tunnel
  log in one scrolling window, severity-coloured, with jump-to-critical
  navigation that keeps the surrounding records in view
- An `ERR` / `WAR` level filter that preserves each record's own line number, and
  high-contrast full-line highlighting in both light and dark mode
- Per-level colouring of the level column, and inline notes on `100.64.x.x`
  addresses explaining that they are Client Connector synthetic IPs rather than
  real destinations, with vendor-documented and observed roles distinguished
- Honest coverage notes showing which rotations were and were not read
- A local catalog of 749 documented ZCC, ZIA, ZPA, and ZDX errors/statuses,
  with product, severity, meaning, likely next step, and official source
- First-order documented-error detection: critical and warning matches
  lead the guided findings and retain one inline sample record
- A one-run privacy boundary with no recent-upload recovery, retained cases,
  learned customer knowledge, diagnostic exports, or agent handoff
- ZIP-slip, symlink, member-size, total-size, recursion, and compression-ratio guardrails
- A cached GitHub-main version check before diagnostic selection, with a safe update
  command and a copyable Codex/Claude update prompt when a newer version exists

## Project team

Shamil Ahmed and Kevin Peterson served as project leads, with collaborative
help from Amit, Gideon, Conor, and Nathan.

<table>
  <tr>
    <td align="center"><a href="https://github.com/shameel-sd"><img src="https://github.com/shameel-sd.png?size=96" width="72" height="72" alt="Shamil"><br><sub><b>Shamil</b></sub></a></td>
    <td align="center"><a href="https://github.com/kpex-sd"><img src="https://github.com/kpex-sd.png?size=96" width="72" height="72" alt="Kevin"><br><sub><b>Kevin</b></sub></a></td>
    <td align="center"><a href="https://github.com/amitsd01"><img src="https://github.com/amitsd01.png?size=96" width="72" height="72" alt="Amit"><br><sub><b>Amit</b></sub></a></td>
    <td align="center"><a href="https://github.com/0GideonBennett"><img src="https://github.com/0GideonBennett.png?size=96" width="72" height="72" alt="Gideon"><br><sub><b>Gideon</b></sub></a></td>
    <td align="center"><a href="https://github.com/cpsd038"><img src="https://github.com/cpsd038.png?size=96" width="72" height="72" alt="Conor"><br><sub><b>Conor</b></sub></a></td>
    <td align="center"><a href="https://github.com/nathansd12"><img src="https://github.com/nathansd12.png?size=96" width="72" height="72" alt="Nathan"><br><sub><b>Nathan</b></sub></a></td>
  </tr>
</table>

No customer corpus, case library, learned customer knowledge, or source support
bundle is distributed or maintained by this repository.

## Run it

### macOS or Linux

```bash
git clone https://github.com/SecureDynamicsInc/ZCC_Analysis.git
cd ZCC_Analysis
./start.sh
```

If macOS blocks the first start, run `chmod +x start.sh` once.

### Windows PowerShell

```powershell
git clone https://github.com/SecureDynamicsInc/ZCC_Analysis.git
cd ZCC_Analysis
.\run_ui.ps1
```

The first run creates `.venv` and installs Streamlit. Later starts reuse that
environment. In a Git clone, the launchers also enable the repository's local
privacy and protected-main hooks automatically. Python 3.10 or newer is required.

### Manual start

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run_local.py
```

`run_local.py` binds only to `127.0.0.1`. If port 8501 is busy, it selects the
next available local port and prints the URL. Always use the printed `http://`
address. If a browser changes it to `https://`, type the full HTTP address again
or turn off HTTPS-only upgrading for this local address.

### Keep it running in the background

On macOS or Linux, use the included supervisor when you want to close the
Terminal window or automatically restart the analyzer after an unexpected exit:

```bash
./server.sh start
./server.sh status
./server.sh logs
./server.sh open
./server.sh stop
```

The background server stays restricted to `127.0.0.1`, normally at port 8501.
`.run/server.log` records only neutral supervisor starts, exits, and restart
status. Analyzer output is discarded because parser errors can expose customer
filenames. Use `./server.sh restart`
after pulling a new version of the analyzer. This keeps the service running
after the launching Terminal closes; run `./server.sh start` again after a
workstation restart.

For an always-on Mac installation that also starts again after login, run:

```bash
./server.sh install
```

Check it with `./server.sh status` and remove it later with
`./server.sh uninstall`. The macOS service restarts the analyzer after a crash
without retaining analyzer stdout or stderr.
Because macOS blocks user services from running code directly inside Documents,
the installer keeps a private runtime copy under `~/Library/Application Support`.
Run `./server.sh install` again after pulling an updated version of the repo.

## Using the explorer

1. Leave **Novice** selected for a short guided answer, or choose **Pro** for
   the complete investigation workbench. Choose light or dark mode at any time.
   Select **ZIA** for internet/SaaS, **ZPA** for private applications, or **All**
   when the affected service is unknown.
2. Upload your ZCC log files. If the cause is unknown, use the entire support
   ZIP. For the fastest connection check, upload `ZSATunnel.log` by itself; it
   is the single best log in most cases. Novice automatically analyzes a useful
   recent history window.
3. In Pro, expand **Pro analysis settings** only when you need older history.
   Reading everything can take minutes and several gigabytes for a large bundle.
4. Start with the guided summary, choose the user's symptom, and read the leading
   conclusion, direct evidence, and next action. In Pro, use **Tunnels & apps** for a
   destination or M-Tunnel failure, **Problem endpoints** for a destination-level
   view, and **Packet analysis** to confirm DNS, reset, retransmission, or TLS
   behavior on the wire.
   Packet-based findings include **Verify this in Wireshark**. Open the named
   `.pcapng`, copy the complete display filter, and paste it into Wireshark's
   Display Filter bar.
5. Open **PAC files** when a site may be bypassing the tunnel. It shows the
   proxy auto-config recovered from the bundle exactly as it was found, whether
   it was a standalone file or written inline into a tunnel log. An empty result
   means no PAC body was present in the material read, not that the tenant has
   no PAC.
6. Open **Error code help** to review documented codes detected in the logs, or
   enter a code reported by the user to see its meaning and recommended action.
   Open **Known error reference** to browse all 749 bundled entries by ZCC, ZIA,
   ZPA, ZDX, severity, family, or text. Entries found in the current logs sort
   first. Use its reporting link when a code is missing or incorrect.
7. In Pro, open **Deep evidence** only when the guided path does not settle the
   case or you need a raw record, timeline, inventory, or traffic grouping.
8. Treat an absent field as “not evidenced in the selected material,” not as
   proof that the setting or event does not exist.

### Optional MaxMind endpoint ownership

The analyzer never sends endpoint addresses to a lookup service. For ASN owner,
provider, country, and city context, create a free MaxMind account and download
`GeoLite2-ASN.mmdb`; `GeoLite2-City.mmdb` is optional.

The landing page reports the current state next to the upload box. A green dot
means an ASN database was found; a red dot means packet captures will show bare
addresses, and **Fix this · enable endpoint ownership** opens the setup view
with the download steps and the local save control. The same panel is available
in Pro under **Problem endpoints** → **Manage local MaxMind databases**.

The files persist under `~/.zcc-log-explorer/geoip` by default and remain outside
the repository. Set `ZCC_GEOIP_DIR` to use a different local directory. The app
also recognizes the standard Wireshark MaxMind database folders on macOS. Do not
commit or redistribute GeoLite database files unless your MaxMind license and
attribution obligations explicitly permit it. MaxMind requires users to keep
GeoLite data current and remove superseded copies.

This product includes GeoLite Data created by MaxMind, available from
https://www.maxmind.com.

### Version check before file selection

Before diagnostic bytes enter the session, the app makes one cached read-only check of the
clone's configured GitHub `origin/main` using the engineer's existing Git
authentication. It sends no log name, log content, endpoint,
customer identifier, or capture data. If GitHub `main` is newer than the
installed baseline, the app shows a replacement-only updater and a copyable
prompt for Codex or Claude. The updater validates a fresh clone before replacing
the official checkout and warns users to preserve custom work separately. A
failed or blocked version check never blocks local analysis.

## Development and verification

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

Engineers should use the source-backed [`User Guide`](docs/USER_GUIDE.md) for
evidence collection, rotation selection, view-by-view workflows, investigation
recipes, interpretation limits, and privacy guidance.

The error catalog is normalized from ten locally bundled reference families.
Its severity is an analyzer triage hint derived from documented impact, not a
Zscaler support priority. Numeric values are detected only when a log explicitly
labels them as an error code; this avoids treating ordinary counters and version
numbers as failures. The reference remains usable without uploading a bundle.

### Experiment locally, then share the idea

We encourage engineers to adapt and experiment with their own local copy. If a
local improvement proves useful, tell us what problem it solves, how the
workflow should behave, and how success can be verified by opening an
**Enhancement Issue**. We want to learn from practical improvements developed by
the community.

Community participation is **Issues only**. Do not submit a pull request, patch,
branch, repository archive, or code attachment. SecureDynamics maintainers will
evaluate the idea and independently implement accepted requests with synthetic
tests and approval from the other appointed maintainer. Independent model review
is recommended administrative practice, not a required gate. Repository pull
requests and private forks are disabled. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) before reporting anything.

### Never contribute real diagnostic data

This repository must never contain real customer support bundles, individual
logs, packet captures, PAC files, screenshots, exports, deployment snapshots,
MaxMind databases, credentials, tenant or organization IDs, usernames, email
addresses, device names, customer domains, internal hostnames, public or private
customer IP addresses, case numbers, timestamps tied to an incident, or any
other production-derived evidence. This applies even while the repository is
private and includes Issues, pull requests, comments, attachments, Actions
artifacts, releases, Git history, and forks.

Do not create a public fixture by editing, masking, hashing, truncating, or
redacting a real log. Metadata and combinations of otherwise harmless fields can
still identify a customer. Build test evidence from scratch with invented names,
`example.com`/`example.invalid` domains, RFC documentation addresses, and fake
identifiers. Prefer short inline test strings or a deterministic synthetic-data
generator over committed log-shaped files.

Before every maintainer commit, run:

```bash
python scripts/check_public_tree.py --staged
python scripts/check_privacy_architecture.py
pytest -q
```

The automated check blocks common diagnostic/archive formats, evidence folders,
opaque binary files, large tracked files, user-specific home paths, non-example
email addresses, and common secret patterns. It is a safety net, not proof that
content is anonymous; the author and reviewer must still inspect every changed
file. See the complete [Diagnostic Data Handling Standard](docs/DATA_HANDLING.md)
and follow [SECURITY.md](SECURITY.md) immediately if anything sensitive reaches
Git history.

## Community and licensing

ZCC Log Explorer is licensed under the [Apache License 2.0](LICENSE). The
[trademark and project identity policy](TRADEMARKS.md) separately protects the
SecureDynamics name, project identity, and official distribution designation.
Maintainer commits use the lightweight [Developer Certificate of Origin](DCO):
sign each commit with `git commit -s`. See [CONTRIBUTING](CONTRIBUTING.md),
[GOVERNANCE](GOVERNANCE.md), [SUPPORT](SUPPORT.md),
[SECURITY](SECURITY.md), and the [Code of Conduct](CODE_OF_CONDUCT.md).

Official product references are linked from the analyzer's **Known error
reference** view and [`docs/REFERENCE_SOURCES.md`](docs/REFERENCE_SOURCES.md);
selecting a source link opens the corresponding complete external reference.

Zscaler, ZIA, ZPA, ZDX, and Zscaler Client Connector are trademarks or
registered trademarks of Zscaler, Inc. Other names and marks belong to their
respective owners.

## Security and data handling

- Keep the listener on `127.0.0.1`; do not expose it on `0.0.0.0`.
- Exactly one diagnostic run is active; refresh, reset, a new session, or a new
  upload destroys the prior extracted files, derived state, and SQLite index.
- Large or suspicious ZIP members are rejected before they can exhaust the workstation.
- Diagnostic exports and agent handoffs are disabled.
- Never commit exports, logs, captures, support bundles, screenshots, MaxMind
  databases, or production-derived test fixtures. Keep case evidence outside the
  clone and follow [`docs/DATA_HANDLING.md`](docs/DATA_HANDLING.md).
- No customer-derived data is sent to external enrichment, AI, telemetry, an
  MCP server, or another process.
- Read the enforced design in
  [`docs/PRIVACY_ARCHITECTURE.md`](docs/PRIVACY_ARCHITECTURE.md).
