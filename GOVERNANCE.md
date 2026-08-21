# Project governance

## Stewardship

SecureDynamics, Inc. is the project steward and final decision-maker for ZCC
Log Explorer. The public repository is intended to welcome useful community
participation without transferring control of releases, security decisions, or
the protected default branch away from SecureDynamics.

## Roles

- **Users** run the project and may open Issues.
- **Community reporters** submit Issues for bugs, enhancements, documentation,
  or missing error references. External code contributions are not accepted.
- **Reviewers** provide technical review but do not receive merge authority by
  reviewing.
- **Maintainers** are appointed by SecureDynamics and may triage, review, merge,
  manage releases, and apply repository policy within their assigned access.
- **Organization owners** appoint or remove maintainers and retain final
  administrative authority.

Contribution history, employment, or frequent participation does not by itself
grant maintainer status or merge authority.

## Decisions

Maintainers prefer documented, evidence-based consensus. For routine changes,
the maintainer who did not author the change must approve it after required
checks pass. Independent Codex and Claude review is recommended administrative
practice but is not a required or technically attested gate. For security,
privacy, licensing, architecture, or project-scope decisions,
SecureDynamics may require additional review or decline a change. If consensus
cannot be reached, the organization owners make the final decision.

## Change control

The community contribution path is Issues only. External pull requests and
private forks are disabled and are not an accepted contribution channel.
Security vulnerabilities use private vulnerability reporting instead of a
public Issue.

Appointed maintainers implement accepted requests independently on local topic
branches using synthetic evidence. Before `main` changes, the complete diff
must pass the privacy checks and tests and receive written approval by the other
appointed maintainer. The author may not approve their own work. Independent
model reviews may be used administratively but are non-blocking. Maintainers
may close or decline reports
that are unsafe, out of scope, insufficiently reproducible, disclose sensitive
data, or create an unreasonable maintenance burden.

## Releases

Maintainers create releases from the protected default branch after tests pass.
Release notes should describe user-visible behavior, security implications, and
known limitations. SecureDynamics controls project naming, release signing,
official distribution points, and supported release designations. Community
forks and derivative distributions must follow `TRADEMARKS.md` and may not
represent themselves as official SecureDynamics releases.

## Conduct and security

All participation is governed by `CODE_OF_CONDUCT.md`. Vulnerabilities follow
`SECURITY.md`; support expectations follow `SUPPORT.md`.

## Governance changes

Governance changes use the same maintainer-only implementation and review
process and require approval from a SecureDynamics organization owner.
SecureDynamics may update this policy as the project and community mature.
