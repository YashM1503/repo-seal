# M2b isolation preflight

## Outcome

The first M2b slice adds executable, fail-closed probes before any real isolation backend or agent is admitted. Its built-in backend is an intentionally unsafe plain host subprocess. The expected result is a mixture of `FAIL`, `PASS`, and `UNAVAILABLE` findings that proves the harness can see missing boundaries.

A successful preflight command means `probe_harness_passed: true`. It does not mean the security gate passed. The receipt always reports `safe_for_real_agents: false` in this milestone.

## Active negative control

The trusted probe attempts to:

- write outside its assigned workspace;
- read a future-history sentinel under `.git`;
- change a read-only trusted-verifier sentinel;
- read a credential sentinel outside the workspace;
- connect to an orchestrator-owned loopback listener when the surrounding runtime permits that probe;
- read a cache sentinel belonging to another run;
- export both an allowed artifact and an unauthorized extra file.

The parent independently observes the outside write, verifier digest change, loopback connection, and export decision. Read-only discovery probes return only sentinel digests. Receipts contain evidence digests and stable relative control names, never sentinel contents, ports, or temporary host paths.

## Orchestrator controls

Even the unsafe negative control exercises three useful controls:

- the child receives a complete replacement environment rather than the parent's environment;
- the subprocess has a fixed wall-clock timeout;
- the export boundary rejects the complete export when any path falls outside the exact allowlist.

The export policy accepts only bounded, non-executable, single-link regular files at canonical relative paths. It rejects traversal, control characters, `.git` components, symlinks, hard links, executable or special files, missing required artifacts, unapproved paths, and byte-budget violations.

## Fail-closed interpretation

The host negative control expects these results:

| Control | Expected status |
| --- | --- |
| Workspace confinement | `FAIL` |
| Repository history hidden | `FAIL` |
| Verifier protected | `FAIL` |
| Credential sentinel hidden | `FAIL` |
| Network denied | `FAIL` when a connection is observed; otherwise `UNAVAILABLE` |
| Cross-run cache isolated | `FAIL` |
| Parent environment replaced | `PASS` |
| Export allowlist | `PASS` |
| Wall timeout | `PASS` |
| Streaming output limit | `UNAVAILABLE` |
| CPU, memory, and process limits | `UNAVAILABLE` |
| Distinct unprivileged identity | `UNAVAILABLE` |
| Kernel isolation | `UNAVAILABLE` |
| Host credential-broker isolation | `UNAVAILABLE` |
| Independent review | `UNAVAILABLE` |

If the surrounding runtime prevents creation of the loopback listener or blocks the connection through an unattributed ambient policy, the network finding is `UNAVAILABLE`, not `PASS`. An inability to run or attribute a probe never counts as proof of isolation.

## Run locally

```bash
PYTHONPATH=src python -m repolab_reference isolation-preflight /tmp/repolab-isolation-preflight
```

Expected top-level receipt facts are:

```json
{
  "backend_id": "host-process-negative-control/0.1",
  "probe_harness_passed": true,
  "safe_for_real_agents": false,
  "security_gate_passed": false
}
```

Receipt digests are deterministic across repeated runs in the same environment. Network-probe availability is environment-dependent and is therefore explicit evidence rather than a cross-platform golden constant.

## Next backend gate

The next M2b slice must execute the same probes inside a disposable, digest-pinned container or microVM with:

1. a read-only root filesystem and only the candidate workspace mounted writable;
2. no mount containing repository history, verifier bytes, host sockets, credentials, or foreign caches;
3. default-denied network verified by the active probe;
4. a distinct unprivileged UID with dropped capabilities and no privilege escalation;
5. enforced CPU, memory, process-count, file-size, output, and wall-clock limits;
6. a fresh per-run temporary filesystem and cache namespace;
7. a dedicated export channel containing only the bounded patch artifact;
8. immutable backend and policy digests in the receipt;
9. independent security review before the real-agent flag can change.

The host negative control must remain in CI after a real backend is added so probe regressions cannot silently turn missing isolation into passing evidence.
