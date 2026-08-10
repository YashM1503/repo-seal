# RepoLab Reference

Private research incubator for repository-derived coding-agent evaluation primitives.

## Status

**NO-GO for the original standalone product thesis.** The private repository exists to preserve and test a small set of reusable engineering patterns, not to launch another end-to-end agent benchmark platform.

The August 2026 red-team review found that the proposed loop—mine merged pull requests, replay them against multiple agent configurations, and optimize the repository's agent setup—substantially overlaps with Stet and a dense set of open-source and research projects. The research need remains real: OpenAI's July 2026 audit estimated that roughly 30% of SWE-Bench Pro tasks are broken.

## Kept scope

- versioned task and run manifests;
- explicit benchmark-quality records;
- immutable-verifier boundary contracts;
- reproducible decision receipts;
- falsification fixtures for invalid tasks;
- interoperability experiments with existing ecosystems.

## Explicit non-goals

- an agent-evaluation SaaS or dashboard;
- an automatic `AGENTS.md` optimizer;
- a model or harness leaderboard;
- a coding-agent router;
- a generic benchmark auditor;
- execution of untrusted repository code in this starter package.

## Repository map

```text
docs/                 decision record and analysis
examples/             minimal portable manifests
src/repolab_reference schemas, falsification, and controlled replay
tests/                deterministic contracts and replay gates
```

## Quick start

The starter uses only the Python standard library.

```bash
python -m unittest discover -s tests -v
PYTHONPATH=src python -m repolab_reference check-fixtures tests/fixtures/falsification
PYTHONPATH=src python -m repolab_reference controlled-replay /tmp/repolab-controlled-replay
PYTHONPATH=src python -m repolab_reference controlled-agent-replay /tmp/repolab-controlled-agent
PYTHONPATH=src python -m repolab_reference isolation-preflight /tmp/repolab-isolation-preflight
PYTHONPATH=src python -m repolab_reference docker-isolation-plan /tmp/repolab-docker-plan
# Requires Docker and the exact image digest documented below.
PYTHONPATH=src python -m repolab_reference docker-isolation-preflight /tmp/repolab-docker-preflight
PYTHONPATH=src python -m repolab_reference security-review-bundle . /tmp/repolab-security-review
```

## Current milestone

**M0 complete:** the deterministic falsification harness includes one valid control and twelve invalid task fixtures. Every invalid fixture is rejected for exactly the expected reason. See [M0 falsification harness](docs/m0-falsification-harness.md).

**M1 complete:** a controlled ten-task Python history is reconstructed into source-only base/gold snapshots, replayed with an external read-only verifier, and recorded in deterministic receipts. See [M1 controlled replay](docs/m1-controlled-replay.md).

**M2a complete:** a trusted mock adapter receives source through a path-free JSON protocol and returns only bounded replacements of existing allowlisted files. Ten controlled tasks pass the deterministic contract gate. The accompanying security gate intentionally remains false because filesystem, network, resource, and kernel isolation are not implemented. See [M2a controlled agent boundary](docs/m2a-controlled-agent-boundary.md).

**M2b preflight complete:** an active host-process negative control demonstrates that the isolation probe harness detects filesystem escape, history and sentinel exposure, verifier mutation, cache leakage, and unauthorized output. The preflight cannot approve a backend and keeps the real-agent security gate closed. See [M2b isolation preflight](docs/m2b-isolation-preflight.md).

**M2b Docker backend hardened:** the trusted probe has a digest-pinned Docker policy with a read-only root, no network, three controlled mounts, a non-root identity, measured runtime restrictions, and bounded resources and output. The internal security review added an explicit local-daemon boundary, non-recursive binds, an Engine 29.4.3–29.x security range, image-volume rejection, and a deterministic independent-review handoff. The local Engine 29.2.1 is now rejected because its kernel patch status cannot be proven. Independent review remains `UNAVAILABLE`, so `security_gate_passed` and `safe_for_real_agents` remain false. See [M2b Docker backend](docs/m2b-docker-backend.md) and [internal security review](docs/security/m2b-internal-review-2026-08-10.md).

The runners execute only built-in controlled fixture code and the trusted mock adapter; they are not active scanners or sandboxes for arbitrary repositories or real agents.

## Next gate

The next gate is an **independent security review of the exact M2b scope digest**, using the generated handoff bundle. The handoff sequence is:

1. upgrade the execution host to Docker Engine 29.4.3 through 29.x without bypassing the version check;
2. pull the pinned image, run the live Docker preflight, and retain its receipt and rejected-export evidence;
3. generate a fresh review bundle from the exact commit under review and independently verify every file hash in `manifest.json`;
4. resolve or explicitly owner-accept SR-007 (image provenance and vulnerability maintenance) and SR-008 (runtime/kernel containment); and
5. obtain a separately authenticated review decision that identifies the reviewer, commit, scope digest, evidence, finding dispositions, and residual risks.

Until all five steps pass, `INDEPENDENT_REVIEW` stays `UNAVAILABLE` and both security flags stay false. One real-agent adapter may be considered for M2c only in a later reviewed change; the current Docker command must not be repurposed to execute an agent.

## Evidence

- [Red-team analysis](docs/analysis.md)
- [Scope decision](docs/adr/0001-private-reference-scope.md)
- [M0 falsification harness](docs/m0-falsification-harness.md)
- [M1 controlled replay](docs/m1-controlled-replay.md)
- [M2a controlled agent boundary](docs/m2a-controlled-agent-boundary.md)
- [M2b isolation preflight](docs/m2b-isolation-preflight.md)
- [M2b Docker backend](docs/m2b-docker-backend.md)
- [M2b internal security review](docs/security/m2b-internal-review-2026-08-10.md)
- [Stet methodology](https://www.stet.sh/methodology)
- [OpenAI: Separating signal from noise in coding evaluations](https://openai.com/index/separating-signal-from-noise-coding-evaluations/)
- [SWE-smith](https://github.com/SWE-bench/SWE-smith)

## Security

This code models and probes trust boundaries; it is not approved for real-agent or untrusted-code execution. See [SECURITY.md](SECURITY.md) before connecting any executor.
