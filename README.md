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
```

## Current milestone

**M0 complete:** the deterministic falsification harness includes one valid control and twelve invalid task fixtures. Every invalid fixture is rejected for exactly the expected reason. See [M0 falsification harness](docs/m0-falsification-harness.md).

**M1 complete:** a controlled ten-task Python history is reconstructed into source-only base/gold snapshots, replayed with an external read-only verifier, and recorded in deterministic receipts. See [M1 controlled replay](docs/m1-controlled-replay.md).

The runner executes only built-in controlled fixture code; it is not an active scanner or sandbox for arbitrary repositories.

## Next gate

The next milestone is **M2: one real agent adapter** behind an independently reviewed execution boundary. Provider credentials must remain outside verification, agent output must be reduced to an explicit patch artifact, and the unmeasured M1 checks must remain visible rather than being assumed safe.

## Evidence

- [Red-team analysis](docs/analysis.md)
- [Scope decision](docs/adr/0001-private-reference-scope.md)
- [M0 falsification harness](docs/m0-falsification-harness.md)
- [M1 controlled replay](docs/m1-controlled-replay.md)
- [Stet methodology](https://www.stet.sh/methodology)
- [OpenAI: Separating signal from noise in coding evaluations](https://openai.com/index/separating-signal-from-noise-coding-evaluations/)
- [SWE-smith](https://github.com/SWE-bench/SWE-smith)

## Security

This code models trust boundaries; it does not provide a hardened sandbox. See [SECURITY.md](SECURITY.md) before connecting any executor.
