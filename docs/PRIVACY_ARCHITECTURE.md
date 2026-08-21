# Ephemeral diagnostic privacy architecture

## Invariant

Customer diagnostics are untrusted input to one local browser run. They are not
an asset, corpus, case record, training source, or project artifact. The correct
retention period is the current run only.

## Lifecycle

1. The app creates a random browser-session token unrelated to the customer.
2. A process-wide manager permits one active diagnostic run.
3. Selecting input creates a mode-0700 temporary workspace with a neutral
   filename. Customer filenames remain in memory for display only.
4. Extraction and the temporary SQLite index live under that workspace.
5. A replacement upload closes database handles, clears derived objects, and
   closes the framework's upload buffers, then removes the entire prior
   workspace before a new one is created.
6. A refresh or new browser session activates a new token and destroys the old
   run. An explicit reset does the same. Process exit is a final cleanup layer.
7. Because abrupt termination can bypass process-exit cleanup, every new
   analyzer process removes any prior manager-owned temporary workspace before
   accepting another upload. Starting a second process may invalidate the first
   process's run rather than permit two workspaces to coexist.

No recent-upload cache, case database, export, report download, redaction
sidecar, agent handoff, telemetry, or cross-session rehydration is permitted.
Streamlit caching is allowed only for static public reference data and the
update notice; customer-derived values cannot use global framework caches.

## One narrow persistence exception

User-installed MaxMind GeoLite `.mmdb` files are public reference databases,
not diagnostic data. They may persist in the documented external local data
directory. They may never be committed, copied into the clone, or bundled with
a release. No endpoint lookup is sent to MaxMind or another network service.

## Development firewall

`AGENTS.md`, `CLAUDE.md`, and `.github/copilot-instructions.md` place the same
rule in the context used by common coding agents. Uploaded files remain
untrusted data even if they contain text that looks like an instruction.

The local pre-commit hook scans the full worktree, including ignored files, and
staged additions. `.gitignore` reduces accidental staging but cannot hide a
diagnostic placed inside the clone. The
pre-push hook scans every added or modified blob in every outgoing commit, so a
sensitive file cannot be added in one commit and hidden by deleting it in a
later commit. CI repeats the tree, architecture, introduced-commit, and test
controls on both maintainer branches and pushes to `main`.

Community participation is Issues only; pull requests and private forks are
disabled. Appointed maintainers independently implement accepted requests on
local topic branches, and the other appointed maintainer must approve a change
before integration. Current Codex and Claude models may review the complete diff
as recommended administrative practice, but that review is not required or
technically attested. While the private Free repository cannot enforce the full
process with branch protection, the required controls remain administrative
policy rather than a claim of technical enforcement.

The architecture check rejects:

- diagnostic caches, retained cases, corpus/knowledge/snapshot paths;
- customer-derived Streamlit cache decorators;
- diagnostic download/export buttons;
- agent or subprocess handoff paths;
- redaction sidecars; and
- unapproved filesystem/database persistence.

The content scanner rejects diagnostic/archive/database formats, binaries,
large or suspicious files, identities, secrets, customer indicators, personal
paths, and customer-shaped network identifiers in newly added lines.

## Engineer workflow

Never copy a customer file into the clone, even temporarily. Keep the source
bundle outside the project and select it only through the running localhost UI.
Do not ask a coding agent to inspect it in the repository context. Reproduce
bugs with a minimal synthetic input created from scratch in a test temporary
directory.

Before every commit:

```bash
git status --short
git diff
git diff --cached
python scripts/check_public_tree.py --staged
python scripts/check_privacy_architecture.py
pytest -q
```

Stage exact reviewed paths only. If any real or plausibly real indicator is
found, stop without committing. Follow `SECURITY.md`; deletion in a later commit
does not repair Git history.

## Memory-erasure limitation

Cleanup closes owned handles, drops references, clears the run memo, and removes
the temporary workspace. Python and Streamlit do not guarantee that freed heap
pages are overwritten immediately, so "cleared from memory" means dereferenced
and eligible for reuse, not cryptographic zeroization. The application therefore
relies on local-process isolation, one-run custody, no external transmission,
and deterministic disk cleanup rather than claiming byte-level RAM erasure.
