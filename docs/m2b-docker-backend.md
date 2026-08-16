# M2b Docker isolation backend

## Outcome

The second M2b slice executes only the trusted isolation probe in a disposable Docker container. Policy 0.2 supersedes the initial live proof after an internal security review found that the local Docker Engine 29.2.1 could not prove mitigation for CVE-2026-31431. The backend now refuses to start a container unless the Engine is 29.4.3 through 29.x; a future major version requires a new policy review. `INDEPENDENT_REVIEW` remains `UNAVAILABLE`, so any eventual passing live receipt must still report:

```json
{
  "backend_gate_passed": true,
  "safe_for_real_agents": false,
  "security_gate_passed": false
}
```

This is a controlled-probe backend, not a general-purpose agent sandbox. Do not replace the probe entrypoint with an agent, untrusted repository code, a shell, or an installer.

## Immutable inputs

The default policy uses this canonical image reference:

```text
docker.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0
```

The code rejects tag-only and malformed image references, runs with `--pull=never`, inspects the local image, and requires its repository digest to match the policy. The default policy and normalized command template also have golden SHA-256 digests enforced by tests:

```text
policy:   sha256:fc77873cea7f9c4afa53a41a93fdb1554f8ffa2deb6c39deac79ad2a641d52fc
command:  sha256:5995e3d9868a94a09b27946f85f0c0dbf92c5520f76d1a8398de94b03bf29726
```

Pull the exact image before running the live probe:

```bash
docker pull "docker.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
```

## Execution policy

The generated `docker run` command enforces:

- an absolute, hashed Docker CLI and an explicitly selected existing local Unix socket, with ambient `DOCKER_*` variables removed;
- Docker Engine 29.4.3 through 29.x, an explicit built-in seccomp profile, and AppArmor or SELinux on architectures with the legacy x86 `socketcall` path;
- a read-only root filesystem and a fresh 64 MiB `tmpfs` at `/tmp`;
- `--network=none`, `--ipc=none`, and a private cgroup namespace;
- UID and GID `65532:65532`, all Linux capabilities dropped, and no new privileges;
- 256 MiB memory with no additional swap, 32 processes, and half of one CPU;
- `nofile=64`, `fsize=1 MiB`, `core=0`, a 64 KiB streaming-output cap, and a 15-second wall deadline;
- exactly three private bind mounts: one temporary trusted-probe file read-only, a writable disposable workspace, and a dedicated writable export directory; writable binds exclude recursive submounts;
- a complete explicit runtime environment layered over the inspected fixed keys from the pinned image;
- an exact `python3 -I -B /benchseal-isolation-probe.py` entrypoint.

The validator rejects remote Docker endpoints, cross-architecture emulation, privileged mode, host network/PID/IPC namespaces, added capabilities, devices, environment files, Docker API sockets, generic volumes, unexpected mount destinations, and arbitrary container names. Image inspection also rejects image-declared volumes.

## Active evidence

The in-container probe verifies that the root and paths outside the allowed mounts are not writable; the workspace remains writable; host history, credential, foreign-cache, and labeled broker paths are absent; only loopback is active and a connection cannot be made; the effective UID/GID and cgroup/process limits match policy; effective capabilities are zero; no-new-privileges and filter-mode seccomp are active; root and probe mounts are read-only; writable mounts are correctly classified; temporary storage is `noexec,nosuid,nodev`; and environment keys are exact. The parent verifies that the temporary trusted-probe copy is unchanged.

The parent process separately applies the export allowlist and records image, engine, probe, policy, command, stdout, stderr, finding, and receipt digests. Any extra export path rejects the complete export. Docker stdout and stderr are bounded while streaming, and timeout or output-limit failures kill the CLI process group and attempt named-container cleanup.

The kernel finding also requires a Linux image and engine, built-in seccomp, a private cgroup namespace, cgroup v2, and a reported storage driver. These observations are useful evidence, not a proof that the Docker daemon or host kernel is invulnerable.

## Run locally

Render the deterministic policy without contacting Docker:

```bash
PYTHONPATH=src python -m benchseal docker-isolation-plan /tmp/benchseal-docker-plan
```

Run the live backend after pulling the pinned image and upgrading the Docker Engine into the supported 29.4.3–29.x range:

```bash
PYTHONPATH=src python -m benchseal docker-isolation-preflight /tmp/benchseal-docker-isolation
```

Run the opt-in integration test directly:

```bash
BENCHSEAL_RUN_DOCKER_INTEGRATION=1 \
  python -W error::ResourceWarning -m unittest \
  tests.test_docker_backend.DockerLiveIntegrationTests -v
```

Each output directory must not already exist. The CLI writes `receipt.json`; the live command also leaves the disposable workspace and rejected export evidence under `docker-probe` for inspection.

Generate the deterministic handoff for an independent reviewer:

```bash
PYTHONPATH=src python -m benchseal \
  security-review-bundle . /tmp/benchseal-security-review
```

The repository must be at its Git worktree root with no tracked or untracked changes. Bundle version 0.2 resolves the commit twice around file hashing, rejects a moving or dirty source tree before writing output, and records `git_commit_oid`, `git_object_format`, and `git_worktree_clean: true`. The generated manifest otherwise contains only relative paths, file hashes, policy and command-template digests, and closed-gate review status. Its checklist cannot itself approve the boundary.

The CI research job runs the live probe only when the hosted runner's Docker Engine satisfies the pinned policy range. An older or future-major Engine is reported as an explicit skipped test: that means live evidence is unavailable, not that the backend passed. Independent review still requires evidence from a policy-supported host.

### Independent-review handoff

Prepare and review evidence in this order:

1. Check out the exact candidate commit in a clean worktree. Confirm the manifest's `git_commit_oid` equals `git rev-parse HEAD` and its `git_object_format` matches the repository.
2. Confirm the selected daemon is local, the Engine reports 29.4.3 through 29.x, the image is native architecture, and the required AppArmor or SELinux boundary is active where policy requires it.
3. Pull the canonical digest, run `docker-isolation-plan`, run `docker-isolation-preflight`, and retain both receipts plus the live probe's complete output directory. Do not weaken a failed control to obtain a passing receipt.
4. Run the opt-in integration test and the normal unit suite from the same commit. Record the CI run URL or another independently retrievable test record.
5. Generate a new `security-review-bundle` into an empty directory. Recompute every SHA-256 listed in `manifest.json`; reject missing, additional, or mismatched review-scope files.
6. Establish image publisher provenance and an SBOM/vulnerability-maintenance process for SR-007. Record the scanner, database timestamp, severity policy, exceptions, and image digest.
7. Decide and document the runtime boundary for SR-008, including whether patched rootless Docker, Docker Desktop Enhanced Container Isolation, gVisor, or a microVM is required for the intended adversary.
8. Review the daemon selection, generated command, complete container inspection, mounts, credentials, active probes, supervisor cleanup, export allowlist, receipts, and CI evidence against the internal findings.
9. Produce a separately authenticated decision naming the reviewer and organization, date, Git commit, scope digest, host and Engine, inspected evidence, disposition of every open or partially remediated finding, residual risks, and explicit pass or fail result.

A passing backend receipt proves only that the trusted probe satisfied policy on one recorded environment. CI proves only that the automated checks ran. Neither is an independent approval, and the review bundle deliberately has no command that can self-approve it.

## Remaining gate

An independent reviewer must assess the Docker daemon and host threat model, command construction, mount and credential boundaries, image provenance and vulnerability maintenance, active-probe coverage, streaming supervisor, cleanup behavior, export validation, and CI evidence. See the [internal review](security/m2b-internal-review-2026-08-10.md) for remediated and residual findings. Only a separately authenticated passed review covering the exact commit and scope digest may authorize a later reviewed change to `INDEPENDENT_REVIEW`, `security_gate_passed`, or `safe_for_real_agents`.

After that gate closes, M2c may design one narrowly scoped real-agent adapter as a new command and policy. It must not reuse this trusted-probe command by substitution.
