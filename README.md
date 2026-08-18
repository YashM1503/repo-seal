# RepoSeal

RepoSeal checks whether the recorded evidence for a coding-agent benchmark task is strong enough to use.

Give it a JSON evidence file. RepoSeal checks for common reasons a benchmark task can mislead you: the test already passed before the fix, the accepted fix still fails, the verifier is flaky, hidden answers are exposed, future Git history is visible, the grader can be changed, the network is open, or known-broken solutions still pass. It then returns one of two decisions:

- `ELIGIBLE` — none of the recorded checks found a blocking problem.
- `HOLD` — at least one problem must be investigated or corrected.

RepoSeal is intentionally small. It does not mine pull requests, run a coding agent, or claim that tests are ground truth. The MVP validates evidence collected by a trusted process and produces a reviewable receipt.

## Try RepoSeal

RepoSeal requires Python 3.9 or newer and has no runtime dependencies outside the standard library.

```bash
python -m pip install -e .
reposeal --version
reposeal validate examples/evidence.json
```

The example produces a human-readable report:

```text
RepoSeal task evidence report
Task: example-fix-001
Decision: ELIGIBLE
Evidence: sha256:...
Checks evaluated: 12

No blocking findings were recorded.
```

Create a draft for your own task:

```bash
reposeal new-evidence ./payment-fix.json --task-id payment-fix-123
```

Every observation in a new draft is `null`. The draft cannot pass validation until you replace each `null` with evidence collected by a trusted process. RepoSeal never fills unknown values with optimistic defaults.

Validate a directory when you have more than one task:

```bash
reposeal validate examples/evidence-set
```

Directory validation reads the `.json` files directly inside that directory, rejects duplicate task IDs, and produces one aggregate decision. If any task is on hold, the task set is on hold. The JSON receipt identifies itself with `report_kind: "task_set"` and includes a filename-independent `task_set_sha256`.

For CI or another tool, request JSON and save the receipt:

```bash
reposeal validate examples/evidence.json \
  --json \
  --output /tmp/reposeal-receipt.json
```

RepoSeal uses predictable exit codes:

| Exit code | Meaning |
| --- | --- |
| `0` | The task is `ELIGIBLE`. |
| `1` | The task is on `HOLD` because findings were reported. |
| `2` | The command or evidence document is invalid. |

## What the evidence file means

The MVP consumes observations; it does not collect them. A trusted validation process is responsible for running the base revision, accepted patch, repeated tests, isolation probes, mutation tests, and semantic review that produced these values.

The complete input is shown in [examples/evidence.json](examples/evidence.json). Its fields are grouped below in plain language.

| Evidence | Question it answers |
| --- | --- |
| `task_id` | Which benchmark task is this? |
| `base_fails` | Does the intended behavior fail before the fix? |
| `gold_passes` | Does the accepted fix pass the verifier? |
| `flake_rate` | Did repeated clean verifier runs disagree? |
| `oracle_artifacts` | Could the solver see a hidden test or accepted answer? |
| `future_history_accessible` | Could the solver recover the fix from later Git history? |
| `verifier_writable` | Could the solver change the trusted verifier? |
| `network_egress_observed` | Did outbound access work despite a deny policy? |
| `grader_tamper_vectors` | Could repository-controlled hooks influence grading? |
| `declared_requirements` | What behavior was disclosed to the solver? |
| `verified_requirements` | What behavior did the verifier actually enforce? |
| `rejected_valid_alternatives` | Did a reviewed alternative solution fail unfairly? |
| `broken_patch_passes` | How many known-broken solutions passed? |
| `broken_patch_trials` | How many known-broken solutions were tried? |
| `cache_leaks` | Did shared state expose an answer or oracle material? |

Input parsing is strict. Missing fields, unknown fields, duplicate JSON keys, incorrect types, symlinks, and files larger than 1 MiB are rejected instead of guessed at. A directory may contain at most 1,000 JSON evidence files and is processed non-recursively.

## What an `ELIGIBLE` decision does not prove

`ELIGIBLE` means only that the supplied observations passed RepoSeal's deterministic rules. It does not prove that:

- the observations were collected honestly or correctly;
- the task statement is complete in every semantic detail;
- the verifier catches every possible incorrect implementation;
- an execution environment is secure against hostile code; or
- benchmark results will generalize to future work.

Keep the evidence receipt beside the collection logs and environment metadata that support it.

## Project status

Version 1.1 is the first RepoSeal release. It keeps the completed 1.0 validator boundary while giving the product, distribution, import package, and command a name that describes what users actually run. The supported command-line workflow is installable, tested on Python 3.9, 3.11, and 3.13, and documented with stable exit codes and fail-closed input handling.

MVP completion does not include collecting the observations, running a coding agent, executing an arbitrary repository, or certifying an isolation system. Those are separate security-sensitive products, not unfinished pieces hidden behind the 1.0 label. The older controlled replay, mock-agent boundary, and Docker isolation experiments remain in the repository as research tools. They are not the primary product surface and are not approved for arbitrary repositories or real agents.

The exact acceptance boundary is recorded in [ADR 0004](docs/adr/0004-mvp-closure.md), and release changes are listed in [CHANGELOG.md](CHANGELOG.md).

The original project was called RepoLab Reference. Its broad “mine history and optimize coding agents” direction was rejected because it overlaps existing systems. The narrow validator first shipped as BenchSeal and is now called RepoSeal: a direct description of its job as a repository-evidence gate. The reasoning is preserved in the [red-team analysis](docs/analysis.md), [original scope decision](docs/adr/0001-private-reference-scope.md), [BenchSeal MVP decision](docs/adr/0002-benchseal-mvp.md), [evidence workflow decision](docs/adr/0003-evidence-workflow.md), [MVP closure decision](docs/adr/0004-mvp-closure.md), and [RepoSeal rename decision](docs/adr/0006-reposeal-rename.md).

## Advanced research commands

These commands exercise repository-owned fixtures and controlled probes. They are for development of RepoSeal's evidence model, not for evaluating untrusted projects.

```bash
python -m reposeal check-fixtures tests/fixtures/falsification
python -m reposeal controlled-replay /tmp/reposeal-controlled-replay
python -m reposeal controlled-agent-replay /tmp/reposeal-controlled-agent
python -m reposeal isolation-preflight /tmp/reposeal-isolation-preflight
python -m reposeal docker-isolation-plan /tmp/reposeal-docker-plan
```

The live Docker probe and security-review handoff have additional requirements documented in [the Docker backend guide](docs/m2b-docker-backend.md). Independent review is still unavailable, so `security_gate_passed` and `safe_for_real_agents` remain false.

## Agent integration

The repository includes an installable agent skill and a read-only MCP server
for validating evidence and explaining RepoSeal's checks. It does not expose
agent execution, arbitrary repository execution, controlled replay, Docker
probes, or evidence writes. See the
[agent integration guide](docs/agent-integration.md) for installation and tool
boundaries.

## Repository layout

```text
src/reposeal/        package and command-line implementation
examples/            small inputs you can run locally
tests/               unit, replay, and adversarial fixtures
docs/                design decisions and security research
.agents/              repository plugin marketplace
plugins/              installable agent skill and read-only MCP server
SECURITY.md          current security boundaries
CONTRIBUTING.md      development workflow
```

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Changes that add a validation rule must include a failing fixture, a passing control, a stable machine-readable code, tests, and a plain-language explanation.

## Security

Read [SECURITY.md](SECURITY.md) before changing any runner, verifier, Docker policy, export rule, or receipt. Do not connect a real coding agent or execute untrusted repository code with the current research runners.

## License

RepoSeal is licensed under the [Apache License 2.0](LICENSE). The license includes an explicit patent grant from contributors. See [ADR 0005](docs/adr/0005-public-apache-release.md) for the public-release decision and its scope.
