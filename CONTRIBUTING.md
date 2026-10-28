# Contributing

Contributions should preserve the project's conservative, offline scope.
Start with an issue or proposed change describing the problem, assumptions,
affected policy, and evidence needed to validate it.

## Review expectations

- Keep changes focused and explain security and compatibility implications.
- Add or update relevant tests when changing behavior; report actual results,
  not assumed success. Documentation-only changes should be checked for
  consistency with implementation and terminology.
- Use synthetic identities, tasks, and financial examples. Never submit
  credentials, personal information, or confidential incident records.
- Preserve refusal and deferral history across restarts. A new task identifier,
  paraphrase, or delegate must not provide a route around an existing decision.
- Treat charter and policy revisions as trusted-administrator operations, not
  agent proposals that take effect automatically.
- Never resolve a hard prohibition by increasing a utility score or obtaining
  a human approval.

The implementation targets Python 3.11 with Pydantic validation, SQLite
persistence, pytest, Ruff, and mypy. Follow the repository's actual documented
commands and configuration; this document does not assert that any check ran.

Contributors follow CODE_OF_CONDUCT.md. Report suspected security issues using
SECURITY.md rather than publishing sensitive details.
