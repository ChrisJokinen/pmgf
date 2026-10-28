# Security policy

## Scope and support

pmgf is an offline research prototype. No production-supported release or
security response service is currently declared. Do not use it to authorize
real financial transfers, contact people, or process sensitive records.

The core trusts its embedding host and administrator. Same-process components
are not security isolation. Synthetic actor identifiers are not authenticated
human identities. SQLite and an internal hash chain do not protect against a
host administrator rewriting the database and recomputing hashes.

## Reporting

Private security contact: **[maintainers must supply a verified contact]**.
If the repository offers GitHub private vulnerability reporting, use it;
otherwise wait for a verified private channel before sharing sensitive details.
Public issues may describe a nonsensitive concern, but should not contain
credentials, personal data, exploit payloads affecting third parties, or
unredacted records.

Include affected revision, synthetic reproduction steps, expected behavior,
observed behavior, and relevant trust assumptions. No response deadline,
disclosure schedule, bounty, or remediation guarantee is promised.

See [threat model](docs/threat-model.md) and
[limitations](docs/limitations.md) for boundaries and residual risks.
