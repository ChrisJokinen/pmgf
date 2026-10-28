# Persistence and retention

SQLite stores task identity, plans, reviews, decisions, revisions, authorization
state, delegation links, and simulated outcomes. Records include schema
version, UTC timestamps, provenance, and links sufficient to trace a decision
to its inputs and applicable policy.

## Durable invariants

- The application audit API is append-only. Corrections and superseding
  decisions are new linked records, not silent edits to historical events.
- Persistent action-block fingerprints hash each tool/resource pair, ignoring
  content, signals, labels, units, and task IDs. Every non-permitted decision
  adds blocks. Any matching action blocks later plans across actors, delegation,
  and restarts, unless the host explicitly records resolution evidence and
  submits a corrected plan for fresh evaluation.
- Authorization is single-use through the durable per-decision execution
  outcome. All synthetic effects, invocation records, ancestor budget charges,
  and the outcome commit or roll back in one SQLite transaction.
- Approvals and authorizations bind the current gate `boot_id`; a new gate on
  restart invalidates old unused approvals and permits without deleting them.
- Internal hash chaining detects some accidental or uncoordinated edits when
  verified against retained history.

An internal hash chain is **not tamperproof storage**. A host administrator
can rewrite the database and recompute it; an attacker may remove a suffix
without an external checkpoint proving that suffix existed. There is no
cryptographic external trust anchor.

`Store` uses SQLite WAL, full synchronous mode, and `BEGIN IMMEDIATE`
transactions. It verifies sequence continuity and the internal chain at open
and transaction entry. Record envelopes use schema version 1, UTC timestamps,
fixed host provenance (`pmgf/deterministic-host-v1`), links, and previous hash.
That provenance identifies the recording implementation, not independently
verified evidence sources or authenticated human authors.

## Retention and operations

There is no automated deletion or retention-expiry mechanism. Treat records,
database copies, and backups as persistent. Use synthetic data only: never
store sensitive task text, personal data, credentials, or real transaction
details. Encryption at rest and backup protection are host responsibilities,
not promised application features.

Manual deletion, migration, restoration, and backup handling require trusted
operator procedures. A stale backup may restore old authorization state or
lose decisions; restoration must fail closed, invalidate unused permits, and
preserve known restrictions rather than be treated as an ordinary retry.
This is an operational requirement, not a claim of automated rollback defense.
