# Security Policy

## Prototype warning

This repository does not yet execute untrusted code and must not be treated as a secure sandbox. Do not connect a coding agent, mount provider credentials, expose hidden tests, or run repository-controlled code until an independently reviewed isolation layer exists.

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
