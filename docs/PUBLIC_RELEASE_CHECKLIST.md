# Public release checklist

Do not change repository visibility until every required item below is complete
and verified against the live GitHub repository.

## Content and history

- [x] Remove tracked deployment snapshots from the current tree.
- [x] Ignore deployment snapshots, raw logs, captures, and support archives.
- [x] Publish the sanitized tree into a new repository with one root commit and
      no legacy branches, tags, pull-request refs, or historical objects.
- [x] Run Gitleaks against the complete reachable history and exported tree.
- [x] Review synthetic fixtures for customer names, real domains, public IPs,
      usernames, device names, tenant identifiers, and tokens.
- [x] Confirm no MaxMind database, support ZIP, capture, or raw customer log is
      tracked in the clean repository.
- [x] Re-audit the one-commit reachable history and working tree for prohibited
      evidence, known customer identifiers, opaque files, and common secrets
      before publication (completed 2026-08-20).

## Rights and project identity

- [x] Add Apache License 2.0, NOTICE, third-party notices, and DCO.
- [x] Record SecureDynamics stewardship and maintainer governance.
- [x] Link official external product references without retaining internal
      acquisition or audit notes.
- [x] SecureDynamics leadership approved the final license, trademark statement,
      notices, and contributor terms (confirmed 2026-08-20).
- [x] Add a separate trademark and project identity policy, official source
      links, source-file SPDX notices, and a visible in-app license panel.

## Community safety

- [x] Add contribution, support, security, conduct, and governance policies.
- [x] Require Issues to use only synthetic evidence created from scratch.
- [x] Disable community pull requests and document Issues as the only public
      contribution path.
- [x] Enable GitHub private vulnerability reporting when the repository becomes
      public.
- [ ] Confirm the conduct-report contact route reaches at least two maintainers.
- [ ] Add an Issue form for general questions only if maintainers want to accept
      that support load.

## GitHub controls to apply immediately before visibility changes

- [x] Confirm the target is `SecureDynamicsInc/ZCC_Analysis` and the default
      branch is `main`.
- [ ] Make the repository public only after the final history, rights, runtime,
      detector, and crash-residue reviews.
- [ ] Keep repository pull-request creation disabled; community participation
      remains Issues only after publication.
- [ ] Create and activate a `main` ruleset that restricts updates to appointed
      maintainers and blocks force pushes and deletion.
- [ ] Require signed maintainer commits and the strongest checks GitHub can
      enforce without reopening community pull requests.
- [ ] Confirm only Kevin and Conor retain official change authority.
- [ ] Verify an outside user can open an Issue but cannot open a pull request.

## Release verification

- [x] Run `pytest -q` after the post-audit hardening work (173 passed on
      2026-08-20).
- [x] Start the app and verify it binds only to `http://127.0.0.1`.
- [x] Confirm update checks and Issue links use `SecureDynamicsInc/ZCC_Analysis`.
- [x] Check GitHub's community profile (100% complete while private).
- [ ] Check GitHub's security overview after public security features are
      available.
- [ ] Publish a release only after the public repository and controls have been
      independently verified.
