---
name: validate-agent-benchmarks-with-reposeal
description: Validate and explain recorded evidence for coding-agent benchmark tasks with RepoSeal. Use for benchmark eligibility, ELIGIBLE or HOLD decisions, flaky or weak verifiers, hidden-answer exposure, grader tampering, isolation observations, evidence JSON, or reviewable receipts.
---

# Validate coding-agent benchmarks with RepoSeal

Use RepoSeal as a fail-closed check on evidence already collected for a coding-agent benchmark task. It answers whether the supplied observations reveal a blocking benchmark-quality problem.

## Respect the trust boundary

- Treat the evidence file as an observation record, not as proof that collection was honest or complete.
- Never use RepoSeal's research replay, mock-agent, or Docker commands on arbitrary repositories or real agents.
- Do not ask RepoSeal to collect evidence, execute a repository, mine history, or secure an agent runtime. Those are outside the supported validator.
- Reject guesses. Unknown observations remain `null` and cannot pass validation.
- Never describe `ELIGIBLE` as a security certification or proof that tests are ground truth.

## Choose the surface

- Prefer the read-only MCP tools when available:
  - `reposeal_validate_evidence` validates one JSON file or a nonrecursive directory and returns a deterministic receipt.
  - `reposeal_explain_evidence` explains the fields and the strict interpretation boundary without reading or writing files.
- Use the `reposeal` CLI when creating a new evidence draft or saving a receipt is an explicit part of the task.

## Follow the evidence workflow

1. Identify the evidence file or directory and the trusted process that collected its observations.
2. Validate it without editing the input.
3. Interpret `ELIGIBLE` only as “no supplied check produced a blocking finding.”
4. For `HOLD`, list each stable finding code and connect it to the recorded observation. Do not soften or bypass a failed check.
5. For invalid input, correct the schema, type, duplicate-key, path, symlink, size, or task-ID problem before interpreting the benchmark.
6. Preserve the evidence hash or task-set hash with the underlying collection logs and environment metadata.
7. Revalidate a new evidence document after the collection process or task design changes.

## Use the CLI deliberately

```bash
reposeal validate path/to/evidence.json --json
reposeal validate path/to/evidence-directory --json
reposeal new-evidence path/to/new-evidence.json --task-id task-123
```

`new-evidence` writes a new, deliberately incomplete file and refuses to overwrite an existing path. The MCP surface remains read-only and does not expose this write operation.

## Report claims precisely

- `ELIGIBLE` means the supplied observations passed RepoSeal's deterministic rules.
- `HOLD` means at least one blocking finding must be investigated or corrected.
- State separately whether evidence provenance, semantic completeness, isolation, and generalization have been independently established.
- Keep the receipt beside the source observations. A receipt without its supporting logs is not a complete audit trail.
