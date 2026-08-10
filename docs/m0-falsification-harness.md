# M0 falsification harness

## Outcome

M0 is complete. The fixture suite contains one valid control and twelve intentionally invalid evaluation-task records. Each invalid fixture produces exactly its declared machine-readable failure code, and the suite proves that every code is covered once.

## Trust boundary

The harness consumes **evidence recorded by a trusted collection process**. It does not execute a repository, probe a live sandbox, inspect secrets, or decide that semantic requirements are correct.

```text
future trusted collectors
  -> FalsificationEvidence
  -> deterministic checks
  -> FalsificationResult
```

This distinction matters. A result can only be as trustworthy as the process that produced observations such as `verifier_writable`, `network_egress_observed`, or `rejected_valid_alternatives`.

## Fixture contract

Each JSON fixture is an expectation envelope:

```json
{
  "fixture_version": "0.1",
  "name": "history-leak",
  "expected_failures": ["HISTORY_LEAK"],
  "evidence": {
    "task_id": "fixture-history-leak",
    "base_fails": true,
    "gold_passes": true,
    "flake_rate": 0.0,
    "oracle_artifacts": [],
    "future_history_accessible": true,
    "verifier_writable": false,
    "network_egress_observed": false,
    "grader_tamper_vectors": [],
    "declared_requirements": [],
    "verified_requirements": [],
    "rejected_valid_alternatives": 0,
    "broken_patch_passes": 0,
    "broken_patch_trials": 0,
    "cache_leaks": []
  }
}
```

Unknown fields, missing observations, ambiguous boolean strings, invalid numeric ranges, duplicate expectations, and impossible trial counts are rejected rather than coerced. Evidence therefore fails closed instead of treating an omitted check as a pass.

## Covered failure classes

| Code | Triggering observation |
|---|---|
| `BASE_NOT_FAILING` | Verifier is already green at the base snapshot |
| `GOLD_NOT_PASSING` | Accepted patch does not pass |
| `FLAKY_VERIFIER` | Repeated clean runs disagree |
| `ORACLE_EXPOSED` | Hidden verifier or oracle artifacts are visible |
| `HISTORY_LEAK` | Future Git history remains accessible |
| `VERIFIER_MUTABLE` | Solver can modify trusted verifier state |
| `NETWORK_POLICY_FAILURE` | Egress succeeds under a deny policy |
| `GRADER_TAMPER_SURFACE` | Solver can influence the grading path |
| `SPEC_TEST_MISMATCH` | Verifier enforces an undisclosed requirement ID |
| `OVERCONSTRAINED_TEST` | A reviewed valid alternative is rejected |
| `UNDERPOWERED_TEST` | A known-broken patch passes |
| `CACHE_LEAK` | Shared cache exposes oracle or solution state |

## Run the gate

```bash
PYTHONPATH=src python -m repolab_reference check-fixtures tests/fixtures/falsification
```

Success requires all fixture expectations to match the actual findings. The command emits a JSON receipt and exits non-zero on a mismatch or malformed fixture.

## What M0 does not establish

- It does not prove that observations were collected correctly.
- It does not provide a secure execution environment.
- Requirement IDs do not replace human semantic review.
- A clean result does not prove that an unmodeled attack is absent.
- It does not make a mined historical task suitable for model comparison.

The next gate must build trusted collectors around a single controlled repository while preserving this evidence/result boundary.
