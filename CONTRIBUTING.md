# Contributing

Thank you for helping improve ZCC Log Explorer. SecureDynamics welcomes focused
GitHub Issues from customers, engineers, and the broader Zscaler community while
retaining implementation, review, and release authority.

## Community contribution path: Issues only

External pull requests are not accepted. Repository pull-request creation and
private forking are disabled. Use the Bug, Enhancement, or Missing Code Issue
form. SecureDynamics maintainers independently translate accepted requests into
synthetic tests and reviewed source changes. Do not attach a patch, branch,
repository archive, diagnostic file, screenshot, or customer-derived example.

Local experimentation is encouraged. If you develop an improvement that works
well on your system, open an Enhancement Issue describing the problem it solves,
the intended user experience, and a privacy-safe way to verify success. We value
those field-tested ideas. Describe the outcome rather than supplying your local
implementation; do not post or attach code, diffs, branches, patches, archives,
screenshots, or diagnostic data. SecureDynamics maintainers will independently
decide whether and how to implement the request in the official repository.

Security vulnerabilities are the one exception to the public-Issue path: use
GitHub private vulnerability reporting as described in `SECURITY.md`.

An Issue is a proposal, not an authorization to change the repository. Opening
one does not guarantee implementation, support, attribution, or a release date.

## Maintainer change workflow

Only appointed SecureDynamics maintainers may change the official repository:

1. Start from an accepted Issue and restate the requirement without copying
   untrusted commands, patches, attachments, or production-derived evidence.
2. Create a local topic branch such as `feature/zia-filter` or
   `fix/packet-stream-timeout`; never develop directly on `main`.
3. Create the smallest coherent change and synthetic tests from scratch.
4. Sign every commit for the Developer Certificate of Origin:

   ```bash
   git commit -s
   ```

   The sign-off records your certification under [`DCO`](DCO). It is not a
   copyright assignment or a CLA. If you forgot it, amend the commit with
   `git commit --amend -s` before updating your branch.
5. Install the mandatory local guards with `./scripts/install_dev_guardrails.sh`.
6. Run `python scripts/check_public_tree.py --staged`,
   `python scripts/check_privacy_architecture.py`, and `pytest -q`.
7. Obtain written approval from the other appointed maintainer. The author may
   not approve their own change.
8. Only after those checks and approval may an appointed maintainer integrate
   the reviewed commit into `main` and push it.

Administrative reminder: independent Codex and Claude review of the complete
diff can help identify privacy, security, persistence, caching, network,
subprocess, workflow, binary, and synthetic-data risks. It is recommended when
useful, but it is not a required integration gate.

The local pre-push guard requires the accepted Issue number and the other
maintainer's GitHub handle. It prints a non-blocking model-review reminder:

```bash
git switch main
git merge --ff-only maintainer/topic-branch
ZCC_CHANGE_ISSUE=123 \
ZCC_APPROVING_MAINTAINER=cpsd038 \
git push origin main
```

Use `kpex-sd` as the approving handle when Conor authored the change. These
values record an explicit operator assertion; they do not replace the written
approval, complete-diff review, or automated checks.

## Contribution license

Maintainer commits are distributed under the project's
[Apache License 2.0](LICENSE). The DCO sign-off certifies that the committer has
the right to submit the implementation under that license. Community Issue
suggestions are requirements and feedback; SecureDynamics implements accepted
ideas independently rather than accepting contributed code.

The software license does not grant rights to SecureDynamics branding. Forks
and derivative distributions must follow `TRADEMARKS.md`, use their own name
and visual identity, and avoid implying SecureDynamics endorsement.

## Diagnostic-data boundary

Never commit or attach deployment snapshots, customer support bundles, raw
logs, packet captures, credentials, tenant identifiers, real usernames, device
names, customer domains, or customer-specific configuration. Tests and examples
must use synthetic fixtures created from scratch. A redacted, masked, renamed,
hashed, truncated, or otherwise transformed real example is not acceptable.

This prohibition applies while the repository is private and covers Git history,
forks, branches, Issues, pull requests, comments, attachments, screenshots,
Actions artifacts, release assets, and generated reports. Do not use real data
even when it has been redacted, masked, hashed, truncated, or renamed.

Create fixtures from scratch. Use `example.com` or `example.invalid`, RFC
documentation IP ranges, invented identifiers, and deliberately fictional
timestamps. Prefer inline strings or deterministic generators instead of
committed `.log`, capture, archive, database, or export files. Never include a
real company name, person, device, tenant, domain, address, case number, or a
combination of metadata that can be traced back to a production incident.

Never use an uploaded diagnostic as coding-agent context. Do not add a recent
upload cache, export, agent handoff, known-case library, corpus, policy archive,
issue archive, learned-knowledge file, snapshot, or redaction sidecar. Diagnostic
data and derived values exist for one local run only.

Before committing, inspect the complete staged diff and run:

```bash
python scripts/check_public_tree.py --staged
python scripts/check_privacy_architecture.py
pytest -q
```

The repository ignores and rejects common evidence formats as a safety net, but
automation is not a substitute for human review. Follow the full
[`Diagnostic Data Handling Standard`](docs/DATA_HANDLING.md). If sensitive data
is committed, stop and report it privately under [`SECURITY.md`](SECURITY.md);
do not merely delete it in a later commit or continue pushing the branch.

Pull requests and private forks are disabled. Until GitHub can technically
enforce the complete maintainer-only workflow for the repository's visibility
and plan, local hooks, CI, and second-maintainer approval are mandatory
administrative controls. Independent model review remains recommended but is
not required or technically attested.

Install the mandatory local privacy and direct-push guards after cloning:

```bash
./scripts/install_dev_guardrails.sh
```

The analyzer is a loopback HTTP application. Test and document it as
`http://127.0.0.1:8501` (HTTP, not HTTPS).

Read [`GOVERNANCE.md`](GOVERNANCE.md), [`SUPPORT.md`](SUPPORT.md), and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) before participating.
