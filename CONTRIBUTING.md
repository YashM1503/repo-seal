# Contributing to BenchSeal

Thanks for helping improve BenchSeal. This guide explains what belongs in the project, how to make a change, and which safety rules must remain intact.

## Start with the project boundary

BenchSeal's MVP has one primary job: read recorded evidence about a coding-agent benchmark task, apply deterministic checks, and return an `ELIGIBLE` or `HOLD` decision with a reproducible receipt.

Good contributions make that workflow clearer, safer, easier to integrate, or better tested. Examples include:

- a deterministic check for a well-defined benchmark defect;
- clearer validation messages;
- import or export adapters for an existing evaluation format;
- stronger schema validation;
- adversarial fixtures;
- documentation improvements; and
- fixes to receipt reproducibility or secret handling.

Please do not expand BenchSeal into an agent platform, model leaderboard, dashboard, automatic prompt optimizer, hosted service, or general-purpose sandbox. Those ideas require a separate scope and security decision.

## Set up a development environment

BenchSeal supports Python 3.9 and newer. The runtime uses only the Python standard library.

```bash
git clone https://github.com/YashM1503/repolab-reference.git
cd repolab-reference
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Run the MVP against the included example:

```bash
benchseal new-evidence /tmp/my-evidence.json --task-id my-task
benchseal validate examples/evidence.json
benchseal validate examples/evidence-set
benchseal validate examples/evidence.json --json
```

## Make a focused change

Create a branch, keep unrelated edits out of the change, and add tests that demonstrate the behavior before asking for review.

```bash
git switch -c your-name/short-description
```

Code in `src/benchseal/` should remain compatible with Python 3.9. Prefer immutable data structures, explicit limits, deterministic ordering, and standard-library solutions. Validation must fail closed: missing, malformed, unavailable, or ambiguous evidence must never be treated as a pass.

User-facing errors should explain what is wrong and what the user can do next. Receipts must not contain temporary absolute paths, secrets, hidden-test contents, or unstable timestamps.

Evidence drafts must remain fail closed. Use `null` for observations that have not been collected; never generate a passing value merely to make a template convenient. Directory reports must remain independent of filenames and filesystem enumeration order.

## Add or change a validation rule

Every rule needs all of the following:

1. a stable code in `ValidationCode`;
2. one check with a plain-language message;
3. a broken fixture that triggers only that code;
4. confirmation that the valid control still passes;
5. unit tests for malformed and boundary inputs; and
6. an update to the evidence table in `README.md` when the input contract changes.

Checks run in the declared order in `CHECKS`. Do not reorder them casually because receipt consumers may rely on stable finding order.

## Work on security-sensitive code

Changes to agent boundaries, isolation probes, Docker commands, verifier handling, exports, Git operations, or security receipts need additional care.

Before opening a pull request:

- read [SECURITY.md](SECURITY.md);
- preserve network denial and least privilege by default;
- do not expose provider credentials, Git history, hidden tests, or writable verifier state;
- add a negative test for the failure or attack being addressed;
- keep output, time, memory, process, and file-size limits explicit;
- update the internal review findings when the threat model changes; and
- leave `security_gate_passed` and `safe_for_real_agents` false unless a separately authenticated independent review covers the exact commit and scope digest.

Do not test dangerous changes against valuable repositories, credentials, or infrastructure.

## Run the checks

The minimum local verification is:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m benchseal check-fixtures tests/fixtures/falsification
```

If Ruff is installed, also run it on the files you changed:

```bash
ruff check path/to/changed_file.py
```

Docker integration is opt-in because it requires the pinned image and a policy-supported engine. Follow [the Docker backend guide](docs/m2b-docker-backend.md); never bypass a failed engine or isolation check just to make the test green.

## Open a pull request

A useful pull request includes:

- a short explanation of the user problem;
- the smallest reasonable implementation;
- tests showing both success and failure behavior;
- documentation for any visible command, field, or decision change;
- the security impact, even when the answer is “none”; and
- any compatibility or receipt-schema impact.

Use clear commit messages written as actions, for example `Reject duplicate evidence fields`. Reviewers should be able to understand the change without reconstructing the entire project history.

## Report a vulnerability

Do not open a public issue containing an exploit, secret, or private-repository detail. Follow the private reporting instructions in [SECURITY.md](SECURITY.md).
