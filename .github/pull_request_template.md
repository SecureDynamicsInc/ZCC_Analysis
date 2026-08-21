> **Maintainer-only safeguard:** External pull requests are not accepted. The
> community contribution path is Issues only. If pull-request creation is ever
> re-enabled for maintenance or incident recovery, only an appointed
> SecureDynamics maintainer may use this template.

## What changed

Describe the user problem and the resulting behavior.

## Evidence and verification

- [ ] I worked on a topic branch, not `main`.
- [ ] Every commit includes a `Signed-off-by:` line for the Developer Certificate of Origin.
- [ ] I ran `pytest -q` locally.
- [ ] I ran `python scripts/check_public_tree.py --staged` and `python scripts/check_privacy_architecture.py`.
- [ ] I tested both Novice and Pro when the UI changed.
- [ ] I verified ZIA, ZPA, and All service views when filtering changed.
- [ ] I did not add automatic sharing of raw customer logs or packet captures.
- [ ] I used only synthetic test evidence created from scratch and added no retained cases, corpus data, learned knowledge, policies, issues, or snapshots.
- [ ] I did not derive fixtures, screenshots, or examples from real customer evidence, even by redacting or renaming it.
- [ ] I inspected the complete diff and ran `python scripts/check_public_tree.py`.
- [ ] I added no customer/person/device/tenant identifiers, domains, addresses, case metadata, secrets, binaries, archives, MaxMind databases, or Actions artifacts.
- [ ] I added no diagnostic cache, export/download, AI or subprocess handoff, telemetry, cross-session state, or persistence path.
- [ ] The other appointed maintainer approved this change; I did not approve my own work.

Reminder: independent Codex and Claude review of the complete diff is
recommended administrative practice, but it is not a required checklist gate.

## Screenshots or sample output

Use synthetic screenshots or sample output created from scratch. Never include
an image or output from a real customer run, even after redaction.
