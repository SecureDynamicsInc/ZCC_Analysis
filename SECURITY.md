# Security policy

## Supported versions

Security fixes are applied to the latest revision of `main`. Older commits,
forks, and locally modified copies are not maintained by SecureDynamics.

## Report a vulnerability privately

Do not open a public Issue for a suspected vulnerability. Use the repository's
**Security** tab and select **Report a vulnerability**. If private vulnerability
reporting is unavailable, contact SecureDynamics through
https://securedynamics.net/contact and ask for a private security-reporting
channel. Do not include exploit details, credentials, customer information,
logs, packet captures, or other sensitive evidence in the initial message.

Include, when safe:

- the affected version or commit;
- the impact and prerequisites;
- minimal reproduction steps using synthetic data; and
- any suggested mitigation.

Maintainers will acknowledge reports as capacity permits, validate the issue,
coordinate a fix and disclosure where appropriate, and credit reporters who
want attribution. This community project does not promise a response or repair
service-level agreement.

## Sensitive diagnostic data

ZCC support bundles, individual logs, packet captures, endpoint names, IP
addresses, tenant identifiers, usernames, and tokens can be sensitive. Never
attach raw customer evidence to a public Issue or pull request. Reproduce the
problem with synthetic, fully anonymized fixtures.

The same rule applies to this private repository, forks, branches, comments,
attachments, Actions artifacts, and releases. Do not upload a redacted real log;
create a synthetic reproduction from scratch. See
[`docs/DATA_HANDLING.md`](docs/DATA_HANDLING.md).

If sensitive evidence enters GitHub:

1. Stop pushing, merging, downloading, or copying the affected material.
2. Privately notify the SecureDynamics organization owners and security contact.
3. Identify every affected repository, fork, branch, pull request, artifact,
   release, cache, and local clone without reposting the sensitive content.
4. Rotate exposed credentials or tokens immediately through their owning system.
5. Remove public attachments or artifacts through an authorized maintainer.
6. Rewrite or replace Git history before publication; a later deletion commit
   does not remove the earlier object. Coordinate clone invalidation and fresh
   cloning with all contributors.
7. Re-run the full-tree, full-history, secret, and customer-identifier review
   before normal development resumes.

Do not describe the customer, affected fields, or secret values in a public
Issue created to track the cleanup.
