# M2a controlled patch-agent boundary

## Outcome

M2a adds a deterministic integration boundary for one trusted mock adapter. Across the ten controlled M1 tasks, the adapter receives a JSON request containing the task statement and UTF-8 source bytes, returns one explicit file-replacement artifact, and never receives a host workspace path through the protocol. Each patched candidate is then checked twice by the external read-only verifier.

The contract gate passes when the protocol, patch policy, and verification flow behave as specified. The separate security gate remains false by design. M2a is not approved for a real or untrusted agent.

## Flow

```text
source-only base snapshot
  -> capture task + source bytes + immutable digests
  -> trusted mock subprocess in a fresh scratch cwd
  -> strict JSON replacement artifact
  -> schema, byte-budget, path, allowlist, and stale-base checks
  -> replace existing candidate file
  -> stage trusted verifier only after adapter exits
  -> verify twice
  -> deterministic receipt
```

The protocol exports content, not a checkout path. The subprocess receives a replacement environment containing only `HOME`, locale, timezone, Python bytecode, and temporary-directory settings, so the parent environment is not inherited. This does not isolate host credential brokers or other operating-system capabilities. The per-task verifier copy is staged after the adapter exits and remains outside the candidate workspace; without a filesystem sandbox, M2a cannot prove that the adapter could not discover the original verifier source elsewhere on the host.

## Patch artifact policy

M2a accepts only UTF-8 JSON with an exact versioned schema. Each replacement must:

- target an existing path captured in the request;
- be explicitly allowlisted by the orchestrator;
- use a relative canonical path with no traversal, backslashes, control characters, or `.git` component;
- carry the digest of the unchanged source file;
- fit within the file and total artifact byte budgets;
- change the file rather than submit a no-op.

All replacements are validated before any is written. Replacement bytes are staged in the target directory and moved over the original file while preserving its mode. Symlinks, special files, source mutation after capture, duplicate paths, unknown schema fields, and stale snapshot or file digests fail closed.

## Run locally

```bash
PYTHONPATH=src python -m benchseal controlled-agent-replay /tmp/benchseal-controlled-agent
```

The destination must not already exist. The command creates the controlled Git history, ten base snapshots, per-task adapter scratch directories, externally staged verifiers, and `receipt.json`.

Expected top-level receipt facts are:

```json
{
  "contract_gate_passed": true,
  "safe_for_real_agents": false,
  "security_gate_passed": false,
  "task_count": 10
}
```

Receipts contain digests, control observations, and changed paths, but no replacement source, host paths, secrets, or temporary locations.

## Adversarial coverage

The tests reject:

- parent traversal and `.git` targets;
- unknown schema capabilities;
- wrong task and base-snapshot identities;
- stale per-file digests and post-capture workspace mutation;
- symlink swaps;
- disallowed paths and no-op replacements;
- artifacts exceeding the configured byte budget.

Two complete fresh runs must produce an identical suite receipt and a checked-in golden SHA-256 digest. CI repeats the contract on Python 3.9, 3.11, and 3.13.

## Explicitly unimplemented

The adapter is repository-owned trusted fixture code that includes the known toy fixes. The subprocess can still access whatever the host operating system permits. M2a does not implement or claim:

- a filesystem sandbox;
- network denial;
- CPU, memory, or process limits beyond a wall-clock timeout;
- kernel or virtual-machine isolation;
- isolation from host credential brokers and ambient OS capabilities;
- support for an untrusted or real adapter.

The receipt therefore keeps leakage, verifier mutation, network policy, grader tampering, semantic test quality, and cache isolation findings unmeasured. The trusted mock is also an oracle-bearing integration fixture, not a benchmark subject.

## M2b promotion gate

Before connecting one real agent, M2b must provide an independently reviewed disposable execution environment with the controls below. The first fail-closed probe layer is described in [M2b isolation preflight](m2b-isolation-preflight.md).

1. an explicit filesystem capability model and no access to repository history, gold changes, verifier material, or host credentials;
2. default-denied network with active probes;
3. CPU, memory, process-count, output, and wall-clock limits;
4. fresh per-run caches and a clean post-run export boundary that permits only the validated patch artifact;
5. adversarial escape, tamper, secret-discovery, network, and cache-leak fixtures;
6. receipts that make every unavailable control fail or remain visibly unmeasured.

Only an independent review and a passing security gate can change `safe_for_real_agents` to true.
