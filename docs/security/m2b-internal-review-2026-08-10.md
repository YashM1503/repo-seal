# M2b internal security review — 2026-08-10

## Review status

This is an internal adversarial review performed during implementation. It is not independent and does not satisfy the `INDEPENDENT_REVIEW` control. The security gate remains closed and the backend remains prohibited for real-agent or untrusted-code execution.

Scope: the M2b Docker command policy, Docker client and daemon selection, image inspection, bind mounts, in-container probes, resource limits, process supervision, export validation, receipts, tests, CI, and security documentation.

## Threat model

The future adversary is repository content, task text, dependencies, and an agent process. The trusted computing base currently includes the host user account, local Docker CLI, selected local Docker daemon, daemon runtime and kernel, digest-pinned image, RepoLab orchestrator, trusted probe, export validator, and independent reviewer. A hostile host administrator or code already executing as the orchestrator user is out of scope.

The current command executes only the trusted probe. This review does not authorize substituting an agent or repository command.

## Findings

| ID | Severity | Finding | Disposition |
| --- | --- | --- | --- |
| SR-001 | High | Ambient `DOCKER_HOST`, `DOCKER_CONTEXT`, Docker configuration, or `PATH` selection could redirect or replace the client/daemon used to produce evidence. | Remediated: resolve an absolute non-group/world-writable CLI, record its digest, strip `DOCKER_*`, require an existing local Unix socket, and pass that socket explicitly to every command. |
| SR-002 | High | Local Engine 29.2.1 is below Docker's 29.4.3 mitigation floor for CVE-2026-31431 unless its Linux kernel is separately proven patched. | Remediated fail-closed: policy requires Engine 29.4.3 through 29.x, a native-architecture image, and AppArmor or SELinux where the legacy x86 `socketcall` path exists. The current machine cannot produce a passing live receipt until Docker is upgraded, and a future major version requires a new policy review. |
| SR-003 | Medium | Capabilities, no-new-privileges, seccomp, and mount hardening were inferred from command flags rather than measured in the running container. | Remediated: the probe now reads `/proc/self/status` and mount information; findings require zero effective capabilities, no-new-privileges, filter mode seccomp, read-only root/probe mounts, writable workspace/export mounts, and hardened temporary storage. |
| SR-004 | Medium | Bind mounts included recursive submounts by default, and the whole Python package was visible to the probe. | Remediated: writable binds use `bind-recursive=disabled` and private propagation; only a temporary read-only copy of the trusted probe is mounted. The host work root is mode `0700`. |
| SR-005 | Medium | An image can declare automatic volumes outside the three command-line binds. | Remediated: image inspection rejects any declared `Config.Volumes`. |
| SR-006 | Medium | Credential-broker isolation relied only on an absent sentinel. | Partially remediated: the probe also checks labeled Docker, Docker Desktop, SSH-agent, and runtime-secret paths. Unknown broker paths and kernel/runtime compromise remain residual risks. |
| SR-007 | Medium | A digest pin provides integrity but not publisher identity, vulnerability freshness, an SBOM, or provenance. | Open and blocking before real-agent work: independently verify image provenance and add a maintained vulnerability/SBOM gate or replace the general Python image with a minimal reviewed runtime. A local Docker Scout high/critical scan was attempted but required account authentication; no credentials were supplied. |
| SR-008 | Medium | Docker shares the host kernel on native Linux, and a daemon/runtime/kernel escape remains possible even with seccomp and dropped capabilities. | Open and blocking: independent review must decide whether patched rootless Docker, Docker Desktop Enhanced Container Isolation, gVisor, or a microVM is required for the intended threat model. |
| SR-009 | Low | Export validation has filesystem time-of-check/time-of-use edges if another host process races it. | Reduced: the container exits before validation and the work root is `0700`. A hostile process already running as the orchestrator user remains out of scope; descriptor-based export copying is recommended before widening scope. |
| SR-010 | Low | Docker injects container-local `/etc`, `/dev`, and virtual-kernel mounts beyond the three explicit bind mounts. Some are writable even with a read-only image root. | Accepted for the trusted probe because they are daemon-managed and contain no host repository or credential material. Before real-agent work, inspect the created container's complete runtime mount table and decide whether additional masking is required. |

## Evidence and external basis

Docker documents that `--host` overrides environment and context selection, that `DOCKER_*` variables can alter CLI behavior, that bind submounts are recursive unless disabled, and that the built-in seccomp profile is only moderately protective. Docker's May 2026 CVE-2026-31431 advisory states that Engine versions before 29.4.3 require a separately patched host kernel to avoid exposure.

Relevant primary sources:

- <https://docs.docker.com/reference/cli/docker/>
- <https://docs.docker.com/engine/manage-resources/contexts/>
- <https://docs.docker.com/engine/storage/bind-mounts/>
- <https://docs.docker.com/reference/cli/docker/container/run>
- <https://docs.docker.com/engine/security/seccomp/>
- <https://www.docker.com/blog/mitigating-cve-2026-31431-copy-fail-in-docker-engine/>

## Decision

No critical finding was identified in the trusted-probe-only workflow after remediation. Two medium residual risks remain blocking for any real-agent transition: image provenance/vulnerability maintenance and the daemon/runtime/kernel containment choice. The independent-review control remains `UNAVAILABLE`.

The deterministic `security-review-bundle` handoff now requires the Git worktree root, rejects tracked and untracked changes, and records the exact commit object ID and object format. The reviewer must confirm that commit, verify the manifest hashes, inspect fresh plan/live/CI evidence on a policy-supported Engine, and record explicit dispositions for SR-006 through SR-010. The final decision must identify the reviewer, organization, date, commit, scope digest, environment, evidence, residual risks, and pass or fail result, and must be authenticated separately from the generated bundle.

M2c real-agent execution must not begin until an independent reviewer signs off on that exact scope digest, SR-007 and SR-008 are closed or explicitly accepted by the owner, and the resulting approval is applied in a separate reviewed change. Any subsequent change to a scoped file requires a new bundle and review decision.
