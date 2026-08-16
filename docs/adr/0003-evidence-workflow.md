# ADR 0003: Add fail-closed drafts and task-set validation

- Status: Accepted
- Date: 2026-08-16

## Context

BenchSeal 0.8 validated one complete evidence file. Users still had to copy the JSON structure by hand, and validating several tasks required a separate loop around the command.

Automatically collecting these observations would require executing repository code and designing a trusted collection boundary. That work is not safe to imply or silently introduce in this MVP.

## Decision

Add two local, non-executing workflows:

```bash
benchseal new-evidence evidence.json --task-id issue-123
benchseal validate evidence-directory
```

`new-evidence` writes every uncollected observation as JSON `null`. The draft is deliberately invalid until a person or trusted collector replaces every placeholder. It never assumes a favorable answer.

Directory validation reads only direct `.json` children, rejects symlinks through the existing file validator, caps a batch at 1,000 files, rejects duplicate task IDs, sorts reports by task identity and evidence digest, and returns `HOLD` if any task has a blocking finding.

Receipt schema 0.2 adds an explicit `report_kind` of `task` or `task_set`. Task-set receipts include counts, individual task reports, and a `task_set_sha256` derived only from sorted task IDs and evidence digests.

## Consequences

- Users no longer need to remember the evidence-file shape.
- A repository or CI job can validate a small task set with one command.
- Aggregate receipts are deterministic and do not expose input filenames or absolute paths.
- BenchSeal still does not execute tests, repositories, agents, or collection commands.
- Building a trusted automated collector remains a separate security-sensitive milestone.
