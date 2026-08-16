# ADR 0002: Rename the tool to BenchSeal and ship a validation MVP

- Status: Accepted
- Date: 2026-08-16

## Context

The original RepoLab idea covered historical task mining, agent execution, benchmark comparison, and automatic configuration improvement. The red-team review found that this broad product direction overlaps existing tools and research.

The repository nevertheless contains one useful, self-contained capability: deterministic checks that reject benchmark tasks with known evidence problems. Until now, that capability was hidden behind research fixtures and milestone terminology. A user could not install the project, validate their own evidence file, and receive a clear decision.

The old name also described the broad repository-laboratory concept rather than the narrower tool being built.

## Decision

Rename the tool and Python package to **BenchSeal**.

Ship an MVP with one primary command:

```bash
benchseal validate evidence.json
```

The command accepts a strict, standalone evidence document, applies the existing twelve falsification checks, and returns:

- a human-readable explanation by default;
- deterministic JSON when requested;
- exit code `0` for `ELIGIBLE`;
- exit code `1` for `HOLD`; and
- exit code `2` for invalid input or usage.

The MVP validates recorded observations. It does not collect evidence, execute repository code, run an agent, or certify a sandbox.

The older controlled replay and isolation commands remain available as internal research tools. They do not define the MVP and must keep their security gates closed.

## Consequences

- A new user can understand and run the useful part of the project in a few minutes.
- CI systems can consume a stable receipt without parsing prose.
- The package and command now have one consistent name.
- The rename is intentionally breaking: imports move from `repolab_reference` to `benchseal`.
- The GitHub repository URL may retain its historical name until the repository itself is renamed; this does not change the installed command or package name.
- Future work should prioritize evidence adapters and independently verifiable collection methods, not a broader agent platform.
