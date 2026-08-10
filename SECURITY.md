# Security Policy

## Prototype warning

This repository executes only its built-in controlled fixtures and trusted M2a mock adapter. The subprocess protocol and patch validator are not a secure sandbox. Do not point either runner at arbitrary repositories, substitute an untrusted adapter, connect a real coding agent, mount provider credentials, or expose hidden tests until an independently reviewed isolation layer exists.

M2a receipts intentionally report `security_gate_passed: false` and `safe_for_real_agents: false`. A passing contract gate means only that the controlled protocol, replacement policy, and verifier flow behaved as specified.

The M2b preflight adds an intentionally unsafe host-process negative control. `probe_harness_passed: true` means the probes correctly detected the missing boundary; it is not a sandbox approval. Preflight receipts also keep `security_gate_passed: false` and `safe_for_real_agents: false`.

The M2b Docker backend executes only the repository-owned isolation probe in one pinned Python image. A `backend_gate_passed` value is technical evidence about that exact probe command, image, engine, and policy—not approval to substitute an agent or arbitrary repository code. Policy 0.2 requires a local Unix-socket daemon and Docker Engine 29.4.3 through 29.x, rejects image-declared volumes, mounts only a temporary read-only probe copy, and measures runtime privilege state. A future Engine major version requires policy review rather than passing automatically. The implementation has not received the required independent review. Docker receipts therefore keep `security_gate_passed: false` and `safe_for_real_agents: false`.

The 2026-08-10 internal review found that the local Engine 29.2.1 does not meet the fail-closed security floor because its Linux kernel patch status for CVE-2026-31431 is not independently known. Do not bypass the version check. Upgrade Docker, regenerate live evidence, resolve the review's image-provenance and runtime-containment findings, and obtain independent review before connecting an untrusted workload.

## Required invariants for future execution

1. Treat repository code, task text, dependencies, and agent output as hostile.
2. Keep the verifier outside the agent-writable workspace.
3. Deny network access by default.
4. Use disposable, unprivileged execution environments.
5. Never combine an untrusted checkout with privileged GitHub tokens or secrets.
6. Provide source snapshots without future Git objects or refs.
7. Keep caches isolated across trust domains.
8. Record immutable digests for snapshots, environments, verifiers, patches, and decisions.
9. Prevent the optimizer from changing task selection, holdouts, graders, or promotion rules.
10. Export only explicitly permitted artifacts from an untrusted run.

## Reporting

Keep this repository private while the security model is experimental. Report suspected vulnerabilities privately to the repository owner; do not open a public disclosure without coordination.
