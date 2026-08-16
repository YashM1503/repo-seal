# ADR 0006: Rename BenchSeal to RepoSeal

Date: 2026-08-16

Status: Accepted

## Context

BenchSeal accurately suggested verification, but it did not make the repository scope obvious. The public name should tell a new user what the command acts on without requiring prior knowledge of the project history.

The product remains the narrow validator accepted in ADR 0004. It checks recorded evidence for coding-agent benchmark tasks and produces deterministic `ELIGIBLE` or `HOLD` receipts. This decision does not expand the product into repository mining, agent execution, benchmark optimization, or general-purpose sandboxing.

## Decision

Rename the product from **BenchSeal** to **RepoSeal** for version 1.1.0.

Use these names consistently:

- product and documentation: `RepoSeal`;
- GitHub repository and Python distribution: `repo-seal`;
- Python package, CLI command, and receipt tool identifier: `reposeal`;
- opt-in Docker integration variable: `REPOSEAL_RUN_DOCKER_INTEGRATION`.

The rename is intentionally breaking. Version 1.1.0 does not install a `benchseal` command or provide a `benchseal` import package. Historical changelog entries, release tags, and ADRs keep their original names so the audit trail remains accurate.

## Consequences

- New users get one direct and consistent name across the repository, package, command, and receipts.
- Existing scripts written against version 1.0 must replace `benchseal` with `reposeal`.
- Receipt consumers must accept `tool: "reposeal"` for 1.1.0 receipts.
- The Apache-2.0 license and contribution terms remain unchanged.
- `security_gate_passed` and `safe_for_real_agents` remain `false`; the rename does not approve the research runners for hostile repositories or real agents.
