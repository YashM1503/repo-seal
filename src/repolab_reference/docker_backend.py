"""Digest-pinned Docker isolation backend for the controlled M2b probe.

This backend executes only the repository-owned isolation probe.  A passing
backend gate is still not approval for a real agent because independent review
remains a required, unavailable control.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .isolation import (
    REQUIRED_CONTROLS,
    ControlStatus,
    ExportDecision,
    IsolationControl,
    IsolationFinding,
    ProbeResponse,
    controlled_isolation_probe_path,
    evaluate_export,
    parse_probe_response,
)
from .replay import file_sha256

DEFAULT_DOCKER_PROBE_IMAGE = (
    "docker.io/library/python@"
    "sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
)

EXPLICIT_CONTAINER_ENVIRONMENT: Mapping[str, str] = {
    "HOME": "/tmp",
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TMPDIR": "/tmp",
    "TZ": "UTC",
}


class DockerBackendError(RuntimeError):
    """Raised when the Docker backend violates its controlled contract."""


class DockerBackendUnavailable(DockerBackendError):
    """Raised when the pinned image or local Docker engine is unavailable."""


@dataclass(frozen=True)
class DockerIsolationPolicy:
    image_ref: str = DEFAULT_DOCKER_PROBE_IMAGE
    user_uid: int = 65532
    user_gid: int = 65532
    memory_bytes: int = 256 * 1024 * 1024
    pids_limit: int = 32
    cpu_period: int = 100000
    cpu_quota: int = 50000
    nofile_limit: int = 64
    file_size_limit: int = 1024 * 1024
    tmpfs_bytes: int = 64 * 1024 * 1024
    max_output_bytes: int = 64 * 1024
    wall_seconds: int = 15
    image_environment_keys: tuple[str, ...] = (
        "GPG_KEY",
        "PATH",
        "PYTHON_SHA256",
        "PYTHON_VERSION",
    )
    policy_version: str = "0.1"

    def __post_init__(self) -> None:
        _require_digest_image(self.image_ref)
        for name in (
            "user_uid",
            "user_gid",
            "memory_bytes",
            "pids_limit",
            "cpu_period",
            "cpu_quota",
            "nofile_limit",
            "file_size_limit",
            "tmpfs_bytes",
            "max_output_bytes",
            "wall_seconds",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.cpu_quota > self.cpu_period:
            raise ValueError("cpu_quota must not exceed cpu_period")
        if (
            tuple(sorted(set(self.image_environment_keys)))
            != self.image_environment_keys
        ):
            raise ValueError("image_environment_keys must be sorted and unique")
        if any(
            re.fullmatch(r"[A-Z_][A-Z0-9_]*", key) is None
            for key in self.image_environment_keys
        ):
            raise ValueError("image_environment_keys contains an unsafe key")

    @property
    def policy_sha256(self) -> str:
        return _json_digest(self.to_dict())

    @property
    def expected_environment_keys(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                set(self.image_environment_keys)
                | set(EXPLICIT_CONTAINER_ENVIRONMENT)
                | {"HOSTNAME"}
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "image_ref": self.image_ref,
            "user_uid": self.user_uid,
            "user_gid": self.user_gid,
            "memory_bytes": self.memory_bytes,
            "pids_limit": self.pids_limit,
            "cpu_period": self.cpu_period,
            "cpu_quota": self.cpu_quota,
            "nofile_limit": self.nofile_limit,
            "file_size_limit": self.file_size_limit,
            "tmpfs_bytes": self.tmpfs_bytes,
            "max_output_bytes": self.max_output_bytes,
            "wall_seconds": self.wall_seconds,
            "image_environment_keys": list(self.image_environment_keys),
        }


@dataclass(frozen=True)
class DockerIsolationPlanReceipt:
    policy: DockerIsolationPolicy
    command_template_sha256: str
    receipt_version: str = "0.1"

    @property
    def live_integration_status(self) -> str:
        return "NOT_RUN"

    @property
    def security_gate_passed(self) -> bool:
        return False

    @property
    def safe_for_real_agents(self) -> bool:
        return False

    @property
    def receipt_sha256(self) -> str:
        return _json_digest(self._core_dict())

    def _core_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "backend_id": "docker-controlled-probe/0.1",
            "policy": self.policy.to_dict(),
            "policy_sha256": self.policy.policy_sha256,
            "command_template_sha256": self.command_template_sha256,
            "live_integration_status": self.live_integration_status,
            "security_gate_passed": self.security_gate_passed,
            "safe_for_real_agents": self.safe_for_real_agents,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._core_dict()
        payload["receipt_sha256"] = self.receipt_sha256
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass(frozen=True)
class DockerIsolationReceipt:
    policy: DockerIsolationPolicy
    command_template_sha256: str
    image_id: str
    engine_version: str
    engine_architecture: str
    engine_security_options: tuple[str, ...]
    engine_cgroup_version: str
    engine_storage_driver: str
    probe_sha256: str
    probe_stdout_sha256: str
    probe_stderr_sha256: str
    findings: tuple[IsolationFinding, ...]
    receipt_version: str = "0.1"

    @property
    def backend_gate_passed(self) -> bool:
        observed = {finding.control: finding.status for finding in self.findings}
        backend_controls = tuple(
            control
            for control in REQUIRED_CONTROLS
            if control is not IsolationControl.INDEPENDENT_REVIEW
        )
        return set(observed) == set(REQUIRED_CONTROLS) and all(
            observed[control] is ControlStatus.PASS for control in backend_controls
        )

    @property
    def security_gate_passed(self) -> bool:
        observed = {finding.control: finding.status for finding in self.findings}
        return set(observed) == set(REQUIRED_CONTROLS) and all(
            observed[control] is ControlStatus.PASS for control in REQUIRED_CONTROLS
        )

    @property
    def safe_for_real_agents(self) -> bool:
        return False

    @property
    def receipt_sha256(self) -> str:
        return _json_digest(self._core_dict())

    def _core_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "backend_id": "docker-controlled-probe/0.1",
            "policy": self.policy.to_dict(),
            "policy_sha256": self.policy.policy_sha256,
            "command_template_sha256": self.command_template_sha256,
            "image_id": self.image_id,
            "engine_version": self.engine_version,
            "engine_architecture": self.engine_architecture,
            "engine_security_options": list(self.engine_security_options),
            "engine_cgroup_version": self.engine_cgroup_version,
            "engine_storage_driver": self.engine_storage_driver,
            "probe_sha256": self.probe_sha256,
            "probe_stdout_sha256": self.probe_stdout_sha256,
            "probe_stderr_sha256": self.probe_stderr_sha256,
            "required_controls": [control.value for control in REQUIRED_CONTROLS],
            "findings": [finding.to_dict() for finding in self.findings],
            "backend_gate_passed": self.backend_gate_passed,
            "security_gate_passed": self.security_gate_passed,
            "safe_for_real_agents": self.safe_for_real_agents,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._core_dict()
        payload["receipt_sha256"] = self.receipt_sha256
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def docker_isolation_plan(
    policy: DockerIsolationPolicy,
) -> DockerIsolationPlanReceipt:
    template = _docker_command(
        policy,
        probe_source="<probe-source>",
        workspace="<workspace>",
        export_directory="<export>",
        container_name="<container-name>",
    )
    _validate_docker_command(template, policy)
    return DockerIsolationPlanReceipt(
        policy=policy,
        command_template_sha256=_sequence_digest(template),
    )


def build_docker_command(
    policy: DockerIsolationPolicy,
    *,
    probe_source: Path,
    workspace: Path,
    export_directory: Path,
    container_name: str,
) -> tuple[str, ...]:
    for name, path in (
        ("probe_source", probe_source),
        ("workspace", workspace),
        ("export_directory", export_directory),
    ):
        if not path.is_absolute():
            raise ValueError(f"{name} must be an absolute path")
        if any(character in str(path) for character in (",", "\n", "\r")):
            raise ValueError(f"{name} contains a character unsafe for Docker mounts")
    if re.fullmatch(r"repolab-probe-[0-9a-f]{32}", container_name) is None:
        raise ValueError("container_name must use the controlled format")
    command = _docker_command(
        policy,
        probe_source=str(probe_source),
        workspace=str(workspace),
        export_directory=str(export_directory),
        container_name=container_name,
    )
    _validate_docker_command(command, policy)
    return command


def run_docker_isolation_preflight(
    work_root: Path,
    *,
    policy: DockerIsolationPolicy,
) -> DockerIsolationReceipt:
    """Run only the trusted isolation probe inside the pinned Docker image."""

    if work_root.exists():
        raise ValueError("work_root must not already exist")
    work_root.mkdir(parents=True)
    workspace = (work_root / "workspace").resolve()
    export_directory = (work_root / "export").resolve()
    workspace.mkdir()
    export_directory.mkdir()
    workspace.chmod(0o777)
    export_directory.chmod(0o777)
    (workspace / "input.txt").write_text("controlled source\n", encoding="utf-8")

    image = _inspect_image(policy)
    engine = _inspect_engine()
    container_name = "repolab-probe-" + uuid.uuid4().hex
    probe_source = controlled_isolation_probe_path().parent.resolve()
    command = build_docker_command(
        policy,
        probe_source=probe_source,
        workspace=workspace,
        export_directory=export_directory,
        container_name=container_name,
    )
    request = {
        "export_directory": "/export",
        "outside_write_target": "/outside/escaped.txt",
        "history_sentinel": "/host-sentinels/history",
        "verifier_target": "/host-sentinels/verifier",
        "credential_sentinel": "/host-sentinels/credential",
        "foreign_cache_sentinel": "/host-sentinels/foreign-cache",
        "network_host": "127.0.0.1",
        "network_port": 9,
        "network_probe_enabled": True,
    }
    try:
        result = _run_bounded_command(
            command,
            input_bytes=json.dumps(request, sort_keys=True).encode("utf-8"),
            max_output_bytes=policy.max_output_bytes,
            timeout_seconds=policy.wall_seconds,
        )
    except Exception:
        _force_remove_container(container_name)
        raise
    if result.returncode != 0:
        _force_remove_container(container_name)
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise DockerBackendError(
            f"controlled Docker probe exited with {result.returncode}: {detail}"
        )
    response = parse_probe_response(result.stdout)
    export_decision = evaluate_export(
        export_directory,
        allowed_paths=("artifact.json",),
    )
    findings = _build_docker_findings(
        policy=policy,
        response=response,
        export_decision=export_decision,
        image_environment_keys=image["environment_keys"],
        image_os=image["os"],
        engine_os=engine["os"],
        engine_security_options=engine["security_options"],
        engine_cgroup_version=engine["cgroup_version"],
        engine_storage_driver=engine["storage_driver"],
    )
    plan = docker_isolation_plan(policy)
    return DockerIsolationReceipt(
        policy=policy,
        command_template_sha256=plan.command_template_sha256,
        image_id=image["id"],
        engine_version=engine["version"],
        engine_architecture=engine["architecture"],
        engine_security_options=engine["security_options"],
        engine_cgroup_version=engine["cgroup_version"],
        engine_storage_driver=engine["storage_driver"],
        probe_sha256=file_sha256(controlled_isolation_probe_path()),
        probe_stdout_sha256=_bytes_sha256(result.stdout),
        probe_stderr_sha256=_bytes_sha256(result.stderr),
        findings=findings,
    )


def _docker_command(
    policy: DockerIsolationPolicy,
    *,
    probe_source: str,
    workspace: str,
    export_directory: str,
    container_name: str,
) -> tuple[str, ...]:
    arguments = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--init",
        "--interactive",
        f"--name={container_name}",
        "--hostname=repolab-probe",
        "--read-only",
        "--network=none",
        "--ipc=none",
        "--cgroupns=private",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        f"--user={policy.user_uid}:{policy.user_gid}",
        f"--memory={policy.memory_bytes}",
        f"--memory-swap={policy.memory_bytes}",
        f"--pids-limit={policy.pids_limit}",
        f"--cpu-period={policy.cpu_period}",
        f"--cpu-quota={policy.cpu_quota}",
        f"--ulimit=nofile={policy.nofile_limit}:{policy.nofile_limit}",
        f"--ulimit=fsize={policy.file_size_limit}:{policy.file_size_limit}",
        "--ulimit=core=0:0",
        "--shm-size=16m",
        "--no-healthcheck",
        "--restart=no",
        "--stop-timeout=1",
        (f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},mode=1777"),
    ]
    arguments.extend(
        f"--env={key}={value}"
        for key, value in sorted(EXPLICIT_CONTAINER_ENVIRONMENT.items())
    )
    arguments.extend(
        (
            f"--mount=type=bind,src={probe_source},dst=/opt/repolab,readonly",
            f"--mount=type=bind,src={workspace},dst=/workspace",
            f"--mount=type=bind,src={export_directory},dst=/export",
            "--workdir=/workspace",
            "--entrypoint=python3",
            policy.image_ref,
            "-I",
            "-B",
            "/opt/repolab/isolation_probe.py",
        )
    )
    return tuple(arguments)


def _validate_docker_command(
    command: tuple[str, ...], policy: DockerIsolationPolicy
) -> None:
    required = {
        "--rm",
        "--pull=never",
        "--init",
        "--interactive",
        "--read-only",
        "--network=none",
        "--ipc=none",
        "--cgroupns=private",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        f"--user={policy.user_uid}:{policy.user_gid}",
        f"--memory={policy.memory_bytes}",
        f"--memory-swap={policy.memory_bytes}",
        f"--pids-limit={policy.pids_limit}",
        f"--cpu-period={policy.cpu_period}",
        f"--cpu-quota={policy.cpu_quota}",
    }
    if not required.issubset(command):
        raise DockerBackendError("Docker command is missing a required isolation flag")
    forbidden = (
        "--privileged",
        "--network=host",
        "--pid=host",
        "--ipc=host",
        "--cap-add",
        "--device",
        "--env-file",
        "--use-api-socket",
        "--volume",
        "-v",
    )
    if any(
        argument == prefix or argument.startswith(prefix + "=")
        for argument in command
        for prefix in forbidden
    ):
        raise DockerBackendError("Docker command contains a forbidden capability")
    mounts = [argument for argument in command if argument.startswith("--mount=")]
    if len(mounts) != 3:
        raise DockerBackendError("Docker command must contain exactly three mounts")
    destinations = {
        component.removeprefix("dst=")
        for mount in mounts
        for component in mount.removeprefix("--mount=").split(",")
        if component.startswith("dst=")
    }
    if destinations != {"/opt/repolab", "/workspace", "/export"}:
        raise DockerBackendError("Docker mount destinations do not match policy")
    if command[-4:] != (
        policy.image_ref,
        "-I",
        "-B",
        "/opt/repolab/isolation_probe.py",
    ):
        raise DockerBackendError("Docker command entrypoint does not match policy")


def _inspect_image(policy: DockerIsolationPolicy) -> dict[str, Any]:
    result = _run_metadata_command(
        (
            "docker",
            "image",
            "inspect",
            policy.image_ref,
        )
    )
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DockerBackendError(
            "Docker image inspection returned invalid JSON"
        ) from error
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], dict)
    ):
        raise DockerBackendError("Docker image inspection returned an invalid record")
    record = payload[0]
    image_id = record.get("Id")
    image_os = record.get("Os")
    config = record.get("Config")
    repo_digests = record.get("RepoDigests")
    if (
        not isinstance(image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
    ):
        raise DockerBackendError("Docker image inspection omitted a full image ID")
    if (
        image_os != "linux"
        or not isinstance(config, dict)
        or not isinstance(repo_digests, list)
    ):
        raise DockerBackendError("Docker image is not a pinned Linux image")
    expected_digest = policy.image_ref.rsplit("@", 1)[1]
    if not any(
        isinstance(value, str) and value.endswith("@" + expected_digest)
        for value in repo_digests
    ):
        raise DockerBackendError("local Docker image does not match the policy digest")
    image_environment = config.get("Env")
    if not isinstance(image_environment, list):
        raise DockerBackendError("Docker image environment is not explicit")
    environment_keys = []
    for item in image_environment:
        if not isinstance(item, str) or "=" not in item:
            raise DockerBackendError(
                "Docker image contains an invalid environment entry"
            )
        environment_keys.append(item.split("=", 1)[0])
    return {
        "id": image_id,
        "os": image_os,
        "environment_keys": tuple(sorted(environment_keys)),
    }


def _inspect_engine() -> dict[str, Any]:
    result = _run_metadata_command(
        ("docker", "version", "--format", "{{json .Server}}")
    )
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DockerBackendError(
            "Docker engine inspection returned invalid JSON"
        ) from error
    if not isinstance(payload, dict):
        raise DockerBackendError("Docker engine inspection returned an invalid record")
    version = payload.get("Version")
    engine_os = payload.get("Os")
    architecture = payload.get("Arch")
    if not all(
        isinstance(value, str) and value for value in (version, engine_os, architecture)
    ):
        raise DockerBackendError("Docker engine inspection omitted required fields")
    info_result = _run_metadata_command(("docker", "info", "--format", "{{json .}}"))
    try:
        info = json.loads(info_result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DockerBackendError(
            "Docker security inspection returned invalid JSON"
        ) from error
    if not isinstance(info, dict):
        raise DockerBackendError(
            "Docker security inspection returned an invalid record"
        )
    security_options = info.get("SecurityOptions")
    cgroup_version = info.get("CgroupVersion")
    storage_driver = info.get("Driver")
    if (
        not isinstance(security_options, list)
        or any(not isinstance(value, str) for value in security_options)
        or not isinstance(cgroup_version, str)
        or not isinstance(storage_driver, str)
    ):
        raise DockerBackendError("Docker security inspection omitted required fields")
    return {
        "version": version,
        "os": engine_os,
        "architecture": architecture,
        "security_options": tuple(sorted(security_options)),
        "cgroup_version": cgroup_version,
        "storage_driver": storage_driver,
    }


def _run_metadata_command(command: tuple[str, ...]) -> _CommandResult:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DockerBackendUnavailable("local Docker engine is unavailable") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise DockerBackendUnavailable(f"local Docker metadata unavailable: {detail}")
    if len(completed.stdout) > 1024 * 1024:
        raise DockerBackendError("Docker metadata output exceeded its limit")
    return _CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _run_bounded_command(
    command: tuple[str, ...],
    *,
    input_bytes: bytes,
    max_output_bytes: int,
    timeout_seconds: int,
) -> _CommandResult:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as error:
        raise DockerBackendUnavailable("could not start the Docker CLI") from error
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        process.stdin.write(input_bytes)
    except BrokenPipeError:
        pass
    finally:
        process.stdin.close()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    total_bytes = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise DockerBackendError("Docker probe exceeded its wall-clock limit")
            events = selector.select(timeout=min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = selector.select(timeout=0)
            for key, _ in events:
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total_bytes += len(chunk)
                if total_bytes > max_output_bytes:
                    _kill_process_group(process)
                    raise DockerBackendError(
                        "Docker probe exceeded its streaming output limit"
                    )
                chunks[key.data].append(chunk)
        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            _kill_process_group(process)
            raise DockerBackendError(
                "Docker probe exceeded its wall-clock limit"
            ) from error
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return _CommandResult(
        returncode=returncode,
        stdout=b"".join(chunks["stdout"]),
        stderr=b"".join(chunks["stderr"]),
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _force_remove_container(container_name: str) -> None:
    try:
        subprocess.run(
            ("docker", "rm", "--force", container_name),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _build_docker_findings(
    *,
    policy: DockerIsolationPolicy,
    response: ProbeResponse,
    export_decision: ExportDecision,
    image_environment_keys: tuple[str, ...],
    image_os: str,
    engine_os: str,
    engine_security_options: tuple[str, ...],
    engine_cgroup_version: str,
    engine_storage_driver: str,
) -> tuple[IsolationFinding, ...]:
    workspace_confined = (
        not response.outside_write_succeeded and not response.root_write_succeeded
    )
    history_hidden = response.history_sha256 is None
    verifier_protected = not response.verifier_mutation_succeeded
    credential_hidden = response.credential_sha256 is None
    network_denied = (
        not response.network_connection_succeeded
        and response.network_interfaces == ("lo",)
    )
    cache_isolated = response.foreign_cache_sha256 is None
    environment_replaced = (
        image_environment_keys == policy.image_environment_keys
        and response.environment_keys == policy.expected_environment_keys
    )
    export_rejected = (
        not export_decision.accepted
        and export_decision.detail == "unauthorized export path rejected"
    )
    resource_limits = all(
        (
            response.cgroup_memory_max == str(policy.memory_bytes),
            response.cgroup_pids_max == str(policy.pids_limit),
            response.cgroup_cpu_max == f"{policy.cpu_quota} {policy.cpu_period}",
            response.limit_nofile == (policy.nofile_limit, policy.nofile_limit),
            response.limit_fsize == (policy.file_size_limit, policy.file_size_limit),
            response.limit_core == (0, 0),
        )
    )
    unprivileged = (
        response.identity_uid == policy.user_uid
        and response.identity_gid == policy.user_gid
    )
    kernel_isolated = all(
        (
            image_os == "linux",
            engine_os == "linux",
            "name=seccomp,profile=builtin" in engine_security_options,
            "name=cgroupns" in engine_security_options,
            engine_cgroup_version == "2",
            bool(engine_storage_driver),
        )
    )
    credential_broker_isolated = credential_hidden and workspace_confined
    observations: Mapping[
        IsolationControl, tuple[ControlStatus, str, Mapping[str, Any]]
    ] = {
        IsolationControl.WORKSPACE_CONFINEMENT: _finding_observation(
            workspace_confined,
            "container root and outside-workspace paths were not writable",
            "container escaped its writable workspace",
            {
                "outside_write_succeeded": response.outside_write_succeeded,
                "root_write_succeeded": response.root_write_succeeded,
            },
        ),
        IsolationControl.HISTORY_HIDDEN: _finding_observation(
            history_hidden,
            "repository history sentinel was not visible",
            "repository history sentinel was visible",
            {"history_hidden": history_hidden},
        ),
        IsolationControl.VERIFIER_PROTECTED: _finding_observation(
            verifier_protected,
            "trusted verifier path was not writable",
            "trusted verifier path was writable",
            {"verifier_protected": verifier_protected},
        ),
        IsolationControl.CREDENTIAL_SENTINEL_HIDDEN: _finding_observation(
            credential_hidden,
            "credential sentinel was not visible",
            "credential sentinel was visible",
            {"credential_hidden": credential_hidden},
        ),
        IsolationControl.NETWORK_DENIED: _finding_observation(
            network_denied,
            "container had only loopback and could not connect",
            "container network-deny probe failed",
            {
                "connection_succeeded": response.network_connection_succeeded,
                "interfaces": list(response.network_interfaces),
            },
        ),
        IsolationControl.CACHE_ISOLATED: _finding_observation(
            cache_isolated,
            "foreign cache sentinel was not visible",
            "foreign cache sentinel was visible",
            {"cache_isolated": cache_isolated},
        ),
        IsolationControl.PARENT_ENVIRONMENT_REPLACED: _finding_observation(
            environment_replaced,
            "container environment matched the pinned image and explicit policy",
            "container environment differed from the explicit policy",
            {
                "image_environment_keys": list(image_environment_keys),
                "observed_environment_keys": list(response.environment_keys),
            },
        ),
        IsolationControl.EXPORT_ALLOWLIST: _finding_observation(
            export_rejected,
            "unauthorized extra output caused fail-closed export rejection",
            "unauthorized output was not rejected",
            export_decision.to_dict(),
        ),
        IsolationControl.WALL_TIMEOUT: _finding_observation(
            True,
            "Docker CLI was supervised by a wall-clock deadline",
            "Docker CLI had no wall-clock deadline",
            {"wall_seconds": policy.wall_seconds},
        ),
        IsolationControl.STREAMING_OUTPUT_LIMIT: _finding_observation(
            True,
            "stdout and stderr were bounded while streaming",
            "streaming output was not bounded",
            {"max_output_bytes": policy.max_output_bytes},
        ),
        IsolationControl.CPU_MEMORY_PID_LIMITS: _finding_observation(
            resource_limits,
            "cgroup and process limits matched the policy",
            "one or more cgroup or process limits differed from policy",
            {
                "memory_max": response.cgroup_memory_max,
                "pids_max": response.cgroup_pids_max,
                "cpu_max": response.cgroup_cpu_max,
                "nofile": list(response.limit_nofile),
                "fsize": list(response.limit_fsize),
                "core": list(response.limit_core),
            },
        ),
        IsolationControl.UNPRIVILEGED_IDENTITY: _finding_observation(
            unprivileged,
            "container used the configured non-root UID and GID",
            "container identity did not match policy",
            {"uid": response.identity_uid, "gid": response.identity_gid},
        ),
        IsolationControl.KERNEL_ISOLATION: _finding_observation(
            kernel_isolated,
            "probe executed through the Linux Docker engine",
            "probe did not execute through the required Linux Docker engine",
            {
                "image_os": image_os,
                "engine_os": engine_os,
                "security_options": list(engine_security_options),
                "cgroup_version": engine_cgroup_version,
                "storage_driver": engine_storage_driver,
            },
        ),
        IsolationControl.HOST_CREDENTIAL_BROKER_ISOLATION: _finding_observation(
            credential_broker_isolated,
            "no host credential sentinel or outside path was visible",
            "host credential isolation evidence failed",
            {
                "credential_hidden": credential_hidden,
                "workspace_confined": workspace_confined,
            },
        ),
        IsolationControl.INDEPENDENT_REVIEW: (
            ControlStatus.UNAVAILABLE,
            "the Docker execution boundary has not been independently reviewed",
            {"reviewed": False},
        ),
    }
    return tuple(
        IsolationFinding(
            control=control,
            status=observations[control][0],
            detail=observations[control][1],
            evidence_sha256=_json_digest(observations[control][2]),
        )
        for control in REQUIRED_CONTROLS
    )


def _finding_observation(
    passed: bool,
    passing_detail: str,
    failing_detail: str,
    evidence: Mapping[str, Any],
) -> tuple[ControlStatus, str, Mapping[str, Any]]:
    return (
        ControlStatus.PASS if passed else ControlStatus.FAIL,
        passing_detail if passed else failing_detail,
        evidence,
    )


def _require_digest_image(value: str) -> None:
    if not isinstance(value, str) or value.count("@sha256:") != 1:
        raise ValueError("image_ref must contain exactly one immutable SHA-256 digest")
    name, digest = value.rsplit("@sha256:", 1)
    if (
        not name
        or name.startswith("-")
        or "://" in name
        or re.fullmatch(r"[A-Za-z0-9./:_-]+", name) is None
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise ValueError("image_ref must be a canonical digest-pinned image reference")


def _sequence_digest(values: tuple[str, ...]) -> str:
    return _json_digest({"arguments": list(values)})


def _bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return _bytes_sha256(encoded)
