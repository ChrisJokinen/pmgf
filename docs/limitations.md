# Limitations

- **Prototype scope:** only synthetic reads, artifact creation, and simulated
  communication, financial, and delegation proposals are supported. No real
  external effects or real-tool support are provided.
- **Trusted host:** components share a Python process. There is no process
  isolation, network sandbox, or defense against a malicious embedding host.
- **Synthetic identity:** role checks do not authenticate humans or establish
  organizational, legal, or financial authority.
- **Review quality:** deterministic rule-based review is not true independence,
  general reasoning, or a truth oracle. Risk depends on supplied evidence and
  may miss omitted or deceptive context.
- **Semantic identity:** persistent blocks fingerprint tool/resource pairs only,
  ignoring content, signals, units, and descriptive labels. This intentionally
  overblocks some benign tasks and cannot recognize equivalent goals using
  different tool/resource pairs. Evidence-backed host resolution requires fresh
  evaluation and does not make an old refused decision executable.
- **Audit integrity:** append-only APIs and internal hash chains are not
  tamperproof. No cryptographic external trust anchor prevents privileged
  rewriting, truncation, or database rollback.
- **Retention:** no automated deletion exists. Sensitive records are
  unsupported; use synthetic data only, including in backups.
- **Authorization:** expiry trusts the host clock; single-use transactional
  simulation is enforced per decision through its execution outcome. Approvals
  and permits bind the gate's `boot_id` and become invalid on gate recreation.
  Atomic local simulation is not an exactly-once guarantee for external tools.
- **Delegation:** typed grants attenuate authority and retain `parent_task`,
  but there is no explicit depth cap or autonomous child runner. The host grant
  management service is separate from the proposal-only `delegate` tool.
- **Evidence and provenance:** the host records evidence strings and a fixed
  implementation provenance marker; neither proves source authenticity.
  Rule-based prohibited-signal checks do not interpret all charter prose.
- **Governance:** trusted administrators control revisions. No approval,
  including a human one, overrides hard prohibitions; escalation is not an
  execution permission.

These are scope boundaries, not defects that can be removed by a reassuring
score or an additional same-process reviewer. Any expansion requires explicit
design, threat modeling, implementation, and evaluation.
