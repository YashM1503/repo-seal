# ADR 0004: Close the BenchSeal MVP at 1.0

- Status: Accepted
- Date: 2026-08-16

## Context

BenchSeal 0.9 already performed its main job: it created fail-closed evidence drafts, validated one task or a directory of tasks, and produced deterministic receipts. Calling the MVP complete still required a release boundary that a user or contributor could verify.

The release audit also found two CI defects left by the RepoLab-to-BenchSeal rename. Several jobs invoked the removed `repolab_reference` module, and the Docker job set a different opt-in environment variable from the one checked by its integration test. Those defects could make source checks fail or make the Docker test skip unintentionally.

## Decision

BenchSeal 1.0 is the completed MVP for trusted, recorded task-evidence validation. The release is accepted when all of these statements are true:

1. `benchseal new-evidence` creates a complete-shape draft without inventing favorable observations or overwriting an existing path.
2. `benchseal validate` accepts one strict JSON evidence file or one bounded, nonrecursive directory of evidence files.
3. Missing, malformed, ambiguous, duplicated, oversized, or unavailable evidence fails closed.
4. A task with any blocking finding returns `HOLD`; a task set returns `HOLD` when any member is held.
5. JSON receipts are deterministic, include content digests, and never depend on temporary paths, filenames, timestamps, or filesystem enumeration order.
6. Receipt output never overwrites an existing file or symbolic link.
7. Exit codes remain `0` for `ELIGIBLE`, `1` for `HOLD`, and `2` for invalid input or command use.
8. The packaged console command is exercised on Python 3.9, 3.11, and 3.13 in CI.
9. Documentation explains the evidence fields, limits, decisions, security boundary, and contribution workflow in plain language.
10. Unit, adversarial-fixture, packaging, and installed-command checks pass for the release commit.

The evidence input schema remains `0.1`, and task and task-set receipts remain schema `0.2`. The tool version moves to `1.0.0`; a tool release does not require an artificial schema-version change.

## Explicitly outside the MVP

The following are separate projects or later milestones, not blockers for closing this MVP:

- automatically collecting observations;
- executing arbitrary repository code;
- connecting a real or untrusted coding agent;
- certifying Docker or another runtime as a secure sandbox;
- mining repository history or generating benchmark tasks;
- hosting a service, dashboard, leaderboard, or prompt optimizer; and
- claiming that an `ELIGIBLE` receipt proves the underlying observations are honest.

The advanced replay and isolation commands remain research tools for repository-owned fixtures. They keep `security_gate_passed` and `safe_for_real_agents` false.

## Compatibility

During the 1.x series, the three documented exit-code meanings and the current evidence/report schemas are compatibility commitments. New optional behavior may be added, but an incompatible command or schema change requires an explicit decision and a new major release.

## Consequences

- The MVP can be tagged and handed to users without implying that unsafe collection or agent execution is ready.
- CI must exercise the installed BenchSeal package and must not silently skip an explicitly enabled security integration test.
- Work after 1.0 should be chosen as a new milestone with its own threat model and acceptance criteria.
