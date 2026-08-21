# Diagnostic Data Handling Standard

ZCC Log Explorer is built to analyze sensitive endpoint diagnostics locally.
That does not make GitHub an approved place to store those diagnostics. This
standard applies to maintainers, employees, customers, community contributors,
agents, automation, and every private or public copy of this repository.

## Non-negotiable rule

Never put real customer or production-derived evidence in the repository or any
GitHub surface associated with it. The rule applies before and after public
release and includes:

- support ZIPs and extracted bundle contents;
- current or rotated logs in any format;
- packet captures, HAR, ETL, crash dumps, database files, and exports;
- PAC files or customer-specific configuration;
- screenshots, copied terminal output, analyzer exports, and generated reports;
- MaxMind database files;
- customer, partner, or employee names and email addresses;
- usernames, device names, serial numbers, tenant or organization IDs;
- customer domains, internal hostnames, IP or MAC addresses, and DNS answers;
- case, ticket, project, account, or incident identifiers;
- credentials, tokens, cookies, certificates, keys, or authentication material;
- timestamps, locations, and field combinations that could re-identify a case.

The boundary includes the tracked tree, Git history, branches, tags, forks,
Issues, pull requests, comments, code-review suggestions, attachments, Actions
logs and artifacts, caches, releases, packages, wikis, and Discussions.

## Redaction is not an acceptable fixture strategy

Do not start with a real log and replace obvious names. Residual metadata,
structure, identifiers, domains, addresses, timestamps, line sequences, and
field combinations may still identify a customer or incident. Hashing,
truncation, tokenization, renaming, or partial copying does not turn customer
evidence into project source.

Create test evidence from scratch. Use:

- fictional organizations and people that do not resemble a real case;
- `example.com`, `example.net`, `example.org`, or `example.invalid` domains;
- IPv4 ranges `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`;
- IPv6 range `2001:db8::/32`;
- locally administered fake MAC addresses;
- invented identifiers and timestamps; and
- the smallest record set necessary to prove the behavior.

Prefer inline test strings or deterministic generators. If a parser needs a
file, generate it inside the test's temporary directory and delete it when the
test ends. Do not commit log-shaped fixture files.

## Local case-data workflow

Keep real support bundles outside the repository and outside folders synced to
GitHub. Select them only through the running loopback UI. Do not register a
corpus path, retain recent uploads, generate fingerprints or snapshots, or copy
any source or derived content into a branch. Do not create known cases,
customer-specific policies, issue records, learned-knowledge files, redaction
sidecars, or reports from a diagnostic run.

The analyzer permits one active run. Refresh, reset, a new browser session, or
a replacement upload destroys the prior temporary workspace. Diagnostic exports
and agent handoffs are disabled. Only user-installed MaxMind reference databases
may persist outside the repository; they contain no customer diagnostic data.

Never send raw or derived diagnostic content to a coding agent, model, MCP
server, API, telemetry service, or subprocess. When another engineer needs to
work the same case, they must receive the original evidence through the
separately approved support system and run their own ephemeral analysis. GitHub
is not that system, even when a repository, Issue, or pull request is private.

## Required author check

Before every commit:

1. Review `git status --short` and every line of `git diff` and
   `git diff --cached`.
2. Confirm every example and fixture was created synthetically from scratch.
3. Run `python scripts/check_public_tree.py --staged`.
4. Run `python scripts/check_privacy_architecture.py`.
5. Run `pytest -q`.
6. Review generated files, screenshots, archives, and untracked files before
   staging exact paths. Never use a bulk stage command without reviewing them.
7. Complete the maintainer data-handling review checklist truthfully.

The automated check inspects ignored files too; `.gitignore` is not a privacy
boundary. It rejects common diagnostic/archive/database formats,
evidence-directory names, opaque binary files, oversized tracked files,
user-specific home paths, non-example email addresses, and common secret
patterns. It cannot recognize every company name, identifier, domain, address,
or re-identifying combination. Human author and maintainer review remains
mandatory.

## Required maintainer review

For every maintainer-authored change, the other appointed maintainer must:

1. Inspect the entire changed-file list, diff, attachments, and workflow output.
2. Challenge any fixture, screenshot, example, copied error record, hostname,
   domain, address, timestamp, or identifier whose origin is unclear.
3. Require the author to regenerate questionable evidence from scratch; do not
   attempt to improve its redaction in the branch or review record.
4. Confirm the public-tree check and tests pass.
5. Reject binary, archive, log, capture, database, export, or unexplained large
   files unless a SecureDynamics organization owner approves a documented,
   license-safe, fully synthetic exception.
6. Refuse integration when the author cannot establish synthetic provenance.

Independent Codex and Claude review of the complete diff is recommended as an
administrative reminder for privacy, persistence, caching, network, process,
workflow, binary, and synthetic-data risks. It is not required or technically
attested.

Community members submit Issues only. Do not download or apply patches,
branches, archives, or code attachments from an Issue. Restate an accepted
requirement and implement it independently with synthetic evidence.

## Incident response

If customer data, secrets, or production-derived evidence is committed or
uploaded, stop work and notify SecureDynamics privately under `SECURITY.md`.
Do not open a public cleanup Issue and do not merely delete the file in a new
commit. Git history, forks, caches, pull-request refs, and downloaded clones may
retain the object.

Organization owners will determine containment, credential rotation, artifact
removal, history rewrite or repository replacement, clone invalidation,
customer/legal notification, and the evidence needed before work resumes. The
repository must pass a new full-tree and reachable-history audit before any
public release.

## Exceptions

There is no routine exception for real customer data. Any proposal to add an
otherwise prohibited binary or synthetic asset requires prior written approval
from a SecureDynamics organization owner, documented synthetic provenance,
license review, and a narrow scanner allowlist reviewed by both current models
and the other appointed maintainer.
Approval to investigate a customer case is never approval to publish its data.
