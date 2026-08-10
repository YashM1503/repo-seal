"""Fail-closed M2b isolation preflight and active negative-control probes.

The host-process backend in this module is intentionally unsafe.  Its purpose is
to prove that the probe harness observes missing boundaries before a real
container or microVM backend is admitted.  It never executes a real agent.
"""

# ruff: noqa: UP045 -- public package compatibility includes Python 3.9.

from __future__ import annotations

import hashlib
import json
import socket
import stat
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from .replay import file_sha256

PROBE_RESPONSE_VERSION = "0.1"
PREFLIGHT_RECEIPT_VERSION = "0.1"
MAX_PROBE_OUTPUT_BYTES = 64 * 1024
PROBE_TIMEOUT_SECONDS = 5


class IsolationProbeError(RuntimeError):
    """Raised when the isolation probe infrastructure cannot produce evidence."""


class ControlStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


class IsolationControl(str, Enum):
    WORKSPACE_CONFINEMENT = "WORKSPACE_CONFINEMENT"
    HISTORY_HIDDEN = "HISTORY_HIDDEN"
    VERIFIER_PROTECTED = "VERIFIER_PROTECTED"
    CREDENTIAL_SENTINEL_HIDDEN = "CREDENTIAL_SENTINEL_HIDDEN"
    NETWORK_DENIED = "NETWORK_DENIED"
    CACHE_ISOLATED = "CACHE_ISOLATED"
    PARENT_ENVIRONMENT_REPLACED = "PARENT_ENVIRONMENT_REPLACED"
    EXPORT_ALLOWLIST = "EXPORT_ALLOWLIST"
    WALL_TIMEOUT = "WALL_TIMEOUT"
    STREAMING_OUTPUT_LIMIT = "STREAMING_OUTPUT_LIMIT"
    CPU_MEMORY_PID_LIMITS = "CPU_MEMORY_PID_LIMITS"
    UNPRIVILEGED_IDENTITY = "UNPRIVILEGED_IDENTITY"
    KERNEL_ISOLATION = "KERNEL_ISOLATION"
    HOST_CREDENTIAL_BROKER_ISOLATION = "HOST_CREDENTIAL_BROKER_ISOLATION"
    INDEPENDENT_REVIEW = "INDEPENDENT_REVIEW"


REQUIRED_CONTROLS: tuple[IsolationControl, ...] = tuple(IsolationControl)

HOST_NEGATIVE_EXPECTATIONS: Mapping[IsolationControl, ControlStatus] = {
    IsolationControl.WORKSPACE_CONFINEMENT: ControlStatus.FAIL,
    IsolationControl.HISTORY_HIDDEN: ControlStatus.FAIL,
    IsolationControl.VERIFIER_PROTECTED: ControlStatus.FAIL,
    IsolationControl.CREDENTIAL_SENTINEL_HIDDEN: ControlStatus.FAIL,
    IsolationControl.NETWORK_DENIED: ControlStatus.FAIL,
    IsolationControl.CACHE_ISOLATED: ControlStatus.FAIL,
    IsolationControl.PARENT_ENVIRONMENT_REPLACED: ControlStatus.PASS,
    IsolationControl.EXPORT_ALLOWLIST: ControlStatus.PASS,
    IsolationControl.WALL_TIMEOUT: ControlStatus.PASS,
    IsolationControl.STREAMING_OUTPUT_LIMIT: ControlStatus.UNAVAILABLE,
    IsolationControl.CPU_MEMORY_PID_LIMITS: ControlStatus.UNAVAILABLE,
    IsolationControl.UNPRIVILEGED_IDENTITY: ControlStatus.UNAVAILABLE,
    IsolationControl.KERNEL_ISOLATION: ControlStatus.UNAVAILABLE,
    IsolationControl.HOST_CREDENTIAL_BROKER_ISOLATION: ControlStatus.UNAVAILABLE,
    IsolationControl.INDEPENDENT_REVIEW: ControlStatus.UNAVAILABLE,
}


@dataclass(frozen=True)
class IsolationFinding:
    control: IsolationControl
    status: ControlStatus
    detail: str
    evidence_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "control": self.control.value,
            "status": self.status.value,
            "detail": self.detail,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True)
class ExportedArtifact:
    path: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class ExportDecision:
    accepted: bool
    detail: str
    artifacts: tuple[ExportedArtifact, ...]

    @property
    def evidence_sha256(self) -> str:
        return _json_digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "detail": self.detail,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class IsolationPreflightReceipt:
    backend_id: str
    probe_sha256: str
    probe_stdout_sha256: str
    probe_stderr_sha256: str
    findings: tuple[IsolationFinding, ...]
    receipt_version: str = PREFLIGHT_RECEIPT_VERSION

    @property
    def probe_harness_passed(self) -> bool:
        observed = {finding.control: finding.status for finding in self.findings}
        if set(observed) != set(HOST_NEGATIVE_EXPECTATIONS):
            return False
        for control, expected in HOST_NEGATIVE_EXPECTATIONS.items():
            if control is IsolationControl.NETWORK_DENIED:
                if observed[control] not in {
                    ControlStatus.FAIL,
                    ControlStatus.UNAVAILABLE,
                }:
                    return False
            elif observed[control] is not expected:
                return False
        return True

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
            "backend_id": self.backend_id,
            "probe_sha256": self.probe_sha256,
            "probe_stdout_sha256": self.probe_stdout_sha256,
            "probe_stderr_sha256": self.probe_stderr_sha256,
            "required_controls": [control.value for control in REQUIRED_CONTROLS],
            "findings": [finding.to_dict() for finding in self.findings],
            "probe_harness_passed": self.probe_harness_passed,
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
class ProbeResponse:
    history_sha256: Optional[str]
    credential_sha256: Optional[str]
    foreign_cache_sha256: Optional[str]
    outside_write_succeeded: bool
    verifier_mutation_succeeded: bool
    network_connection_succeeded: bool
    environment_keys: tuple[str, ...]


def controlled_isolation_probe_path() -> Path:
    return Path(__file__).with_name("isolation_probe.py")


def evaluate_export(
    export_root: Path,
    *,
    allowed_paths: tuple[str, ...],
    max_file_bytes: int = 256 * 1024,
    max_total_bytes: int = 256 * 1024,
) -> ExportDecision:
    """Accept only the exact bounded regular files named by the export policy."""

    if min(max_file_bytes, max_total_bytes) <= 0:
        raise ValueError("export byte limits must be positive")
    if not allowed_paths or len(set(allowed_paths)) != len(allowed_paths):
        raise ValueError("allowed_paths must be non-empty and unique")
    allowed = frozenset(allowed_paths)
    for path in allowed:
        _require_safe_relative_path(path)
    if not export_root.is_dir() or export_root.is_symlink():
        return ExportDecision(False, "export root is not a regular directory", ())

    artifacts = []
    total_bytes = 0
    observed = set()
    for path in sorted(
        export_root.rglob("*"),
        key=lambda item: item.relative_to(export_root).as_posix(),
    ):
        relative = path.relative_to(export_root).as_posix()
        if path.is_symlink() or ".git" in relative.split("/"):
            return ExportDecision(False, "unsafe export entry rejected", ())
        if path.is_dir():
            continue
        metadata = path.lstat()
        if not path.is_file() or not stat.S_ISREG(metadata.st_mode):
            return ExportDecision(False, "non-regular export entry rejected", ())
        if metadata.st_nlink != 1:
            return ExportDecision(False, "hard-linked export entry rejected", ())
        if metadata.st_mode & 0o111:
            return ExportDecision(False, "executable export entry rejected", ())
        observed.add(relative)
        if relative not in allowed:
            return ExportDecision(False, "unauthorized export path rejected", ())
        size = metadata.st_size
        total_bytes += size
        if size > max_file_bytes or total_bytes > max_total_bytes:
            return ExportDecision(False, "export byte limit exceeded", ())
        artifacts.append(
            ExportedArtifact(
                path=relative,
                sha256=file_sha256(path),
                size_bytes=size,
            )
        )
    if observed != allowed:
        return ExportDecision(False, "required export artifact missing", ())
    return ExportDecision(True, "exact export allowlist accepted", tuple(artifacts))


def run_host_process_negative_control(
    work_root: Path,
) -> IsolationPreflightReceipt:
    """Prove the harness detects that a plain host subprocess is not isolated."""

    if work_root.exists():
        raise ValueError("work_root must not already exist")
    selected_probe = controlled_isolation_probe_path()
    if not selected_probe.is_file():
        raise ValueError("probe_script must be a file")
    work_root.mkdir(parents=True)
    workspace = work_root / "workspace"
    export_directory = work_root / "export"
    outside = work_root / "outside"
    history = work_root / "repository" / ".git"
    trusted = work_root / "trusted"
    credential = work_root / "credential-broker"
    foreign_cache = work_root / "foreign-cache"
    scratch = work_root / "probe-scratch"
    for directory in (
        workspace,
        export_directory,
        outside,
        history,
        trusted,
        credential,
        foreign_cache,
        scratch,
    ):
        directory.mkdir(parents=True)

    (workspace / "input.txt").write_text("controlled source\n", encoding="utf-8")
    history_sentinel = history / "future-object"
    history_sentinel.write_text("repolab-secret-history-value\n", encoding="utf-8")
    verifier = trusted / "trusted_verifier.py"
    verifier.write_text("trusted verifier\n", encoding="utf-8")
    verifier.chmod(0o444)
    credential_sentinel = credential / "token"
    credential_sentinel.write_text(
        "repolab-secret-credential-value\n", encoding="utf-8"
    )
    cache_sentinel = foreign_cache / "cache-key"
    cache_sentinel.write_text("repolab-secret-cache-value\n", encoding="utf-8")
    outside_target = outside / "escaped.txt"

    expected_history_sha256 = file_sha256(history_sentinel)
    expected_verifier_sha256 = file_sha256(verifier)
    expected_credential_sha256 = file_sha256(credential_sentinel)
    expected_cache_sha256 = file_sha256(cache_sentinel)

    listener = None
    network_probe_available = False
    network_host = "127.0.0.1"
    network_port = 0
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((network_host, 0))
        listener.listen(1)
        network_host, network_port = listener.getsockname()
        network_probe_available = True
    except OSError:
        if listener is not None:
            listener.close()
        listener = None
    request = {
        "export_directory": str(export_directory),
        "outside_write_target": str(outside_target),
        "history_sentinel": str(history_sentinel),
        "verifier_target": str(verifier),
        "credential_sentinel": str(credential_sentinel),
        "foreign_cache_sentinel": str(cache_sentinel),
        "network_host": network_host,
        "network_port": network_port,
        "network_probe_enabled": network_probe_available,
    }
    environment = {
        "HOME": str(scratch),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(scratch),
        "TZ": "UTC",
    }
    network_observed = False
    try:
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(selected_probe)],
                cwd=workspace,
                env=environment,
                input=json.dumps(request, sort_keys=True).encode("utf-8"),
                check=False,
                capture_output=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                close_fds=True,
                start_new_session=True,
            )
        except subprocess.TimeoutExpired as error:
            raise IsolationProbeError(
                "host negative-control probe timed out"
            ) from error
        if listener is not None:
            listener.settimeout(0.2)
            try:
                connection, _ = listener.accept()
                with connection:
                    network_observed = connection.recv(64) == b"repolab-isolation-probe"
            except (socket.timeout, OSError):
                network_observed = False
    finally:
        if listener is not None:
            listener.close()

    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise IsolationProbeError(
            f"host negative-control probe exited with {completed.returncode}: {detail}"
        )
    if len(completed.stdout) > MAX_PROBE_OUTPUT_BYTES:
        raise IsolationProbeError(
            "host negative-control probe output exceeded its limit"
        )
    response = parse_probe_response(completed.stdout)
    export_decision = evaluate_export(
        export_directory, allowed_paths=("artifact.json",)
    )

    findings = _build_host_findings(
        response=response,
        expected_history_sha256=expected_history_sha256,
        expected_verifier_sha256=expected_verifier_sha256,
        observed_verifier_sha256=file_sha256(verifier),
        expected_credential_sha256=expected_credential_sha256,
        expected_cache_sha256=expected_cache_sha256,
        outside_write_observed=outside_target.is_file(),
        network_observed=network_observed,
        network_probe_available=network_probe_available,
        environment_keys=tuple(sorted(environment)),
        export_decision=export_decision,
    )
    return IsolationPreflightReceipt(
        backend_id="host-process-negative-control/0.1",
        probe_sha256=file_sha256(selected_probe),
        probe_stdout_sha256=_bytes_sha256(completed.stdout),
        probe_stderr_sha256=_bytes_sha256(completed.stderr),
        findings=findings,
    )


def parse_probe_response(raw: bytes) -> ProbeResponse:
    if not raw or len(raw) > MAX_PROBE_OUTPUT_BYTES:
        raise IsolationProbeError("probe response is empty or oversized")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IsolationProbeError("probe response must be valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise IsolationProbeError("probe response must be a JSON object")
    expected_keys = {
        "response_version",
        "history_sha256",
        "credential_sha256",
        "foreign_cache_sha256",
        "outside_write_succeeded",
        "verifier_mutation_succeeded",
        "network_connection_succeeded",
        "environment_keys",
    }
    if set(payload) != expected_keys:
        raise IsolationProbeError("probe response fields do not match the schema")
    if payload["response_version"] != PROBE_RESPONSE_VERSION:
        raise IsolationProbeError("unsupported probe response version")
    for field in (
        "outside_write_succeeded",
        "verifier_mutation_succeeded",
        "network_connection_succeeded",
    ):
        if type(payload[field]) is not bool:
            raise IsolationProbeError(f"{field} must be a boolean")
    environment_keys = payload["environment_keys"]
    if (
        not isinstance(environment_keys, list)
        or any(not isinstance(value, str) for value in environment_keys)
        or environment_keys != sorted(set(environment_keys))
    ):
        raise IsolationProbeError("environment_keys must be sorted unique strings")
    digests = {}
    for field in ("history_sha256", "credential_sha256", "foreign_cache_sha256"):
        value = payload[field]
        if value is not None and not _is_sha256(value):
            raise IsolationProbeError(f"{field} must be null or a SHA-256 digest")
        digests[field] = value
    return ProbeResponse(
        history_sha256=digests["history_sha256"],
        credential_sha256=digests["credential_sha256"],
        foreign_cache_sha256=digests["foreign_cache_sha256"],
        outside_write_succeeded=payload["outside_write_succeeded"],
        verifier_mutation_succeeded=payload["verifier_mutation_succeeded"],
        network_connection_succeeded=payload["network_connection_succeeded"],
        environment_keys=tuple(environment_keys),
    )


def _build_host_findings(
    *,
    response: ProbeResponse,
    expected_history_sha256: str,
    expected_verifier_sha256: str,
    observed_verifier_sha256: str,
    expected_credential_sha256: str,
    expected_cache_sha256: str,
    outside_write_observed: bool,
    network_observed: bool,
    network_probe_available: bool,
    environment_keys: tuple[str, ...],
    export_decision: ExportDecision,
) -> tuple[IsolationFinding, ...]:
    observations = {
        IsolationControl.WORKSPACE_CONFINEMENT: (
            ControlStatus.FAIL if outside_write_observed else ControlStatus.PASS,
            "host subprocess wrote outside its workspace"
            if outside_write_observed
            else "outside-workspace write was blocked",
            {
                "probe_claimed_write": response.outside_write_succeeded,
                "parent_observed_write": outside_write_observed,
            },
        ),
        IsolationControl.HISTORY_HIDDEN: (
            ControlStatus.FAIL
            if response.history_sha256 == expected_history_sha256
            else ControlStatus.PASS,
            "host subprocess read repository history"
            if response.history_sha256 == expected_history_sha256
            else "repository history was not readable",
            {"history_read": response.history_sha256 == expected_history_sha256},
        ),
        IsolationControl.VERIFIER_PROTECTED: (
            ControlStatus.FAIL
            if observed_verifier_sha256 != expected_verifier_sha256
            else ControlStatus.PASS,
            "host subprocess changed trusted verifier bytes"
            if observed_verifier_sha256 != expected_verifier_sha256
            else "trusted verifier bytes were unchanged",
            {
                "probe_claimed_mutation": response.verifier_mutation_succeeded,
                "parent_observed_change": observed_verifier_sha256
                != expected_verifier_sha256,
            },
        ),
        IsolationControl.CREDENTIAL_SENTINEL_HIDDEN: (
            ControlStatus.FAIL
            if response.credential_sha256 == expected_credential_sha256
            else ControlStatus.PASS,
            "host subprocess read the credential sentinel"
            if response.credential_sha256 == expected_credential_sha256
            else "credential sentinel was not readable",
            {
                "credential_read": response.credential_sha256
                == expected_credential_sha256
            },
        ),
        IsolationControl.NETWORK_DENIED: (
            ControlStatus.FAIL if network_observed else ControlStatus.UNAVAILABLE,
            (
                "host subprocess opened a loopback TCP connection"
                if network_observed
                else "network connection was not observed; policy attribution is unavailable"
            )
            if network_probe_available
            else "active loopback network probe is unavailable in this environment",
            {
                "network_probe_available": network_probe_available,
                "probe_claimed_connection": response.network_connection_succeeded,
                "network_connection_observed": network_observed,
            },
        ),
        IsolationControl.CACHE_ISOLATED: (
            ControlStatus.FAIL
            if response.foreign_cache_sha256 == expected_cache_sha256
            else ControlStatus.PASS,
            "host subprocess read a foreign-run cache sentinel"
            if response.foreign_cache_sha256 == expected_cache_sha256
            else "foreign-run cache sentinel was not readable",
            {
                "foreign_cache_read": response.foreign_cache_sha256
                == expected_cache_sha256
            },
        ),
        IsolationControl.PARENT_ENVIRONMENT_REPLACED: (
            ControlStatus.PASS
            if response.environment_keys == environment_keys
            else ControlStatus.FAIL,
            "probe received only the replacement environment"
            if response.environment_keys == environment_keys
            else "probe received unexpected environment keys",
            {"environment_keys": list(response.environment_keys)},
        ),
        IsolationControl.EXPORT_ALLOWLIST: (
            ControlStatus.PASS
            if not export_decision.accepted
            and export_decision.detail == "unauthorized export path rejected"
            else ControlStatus.FAIL,
            "unauthorized extra output caused fail-closed export rejection"
            if not export_decision.accepted
            else "unauthorized output was exported",
            export_decision.to_dict(),
        ),
        IsolationControl.WALL_TIMEOUT: (
            ControlStatus.PASS,
            "probe subprocess had a fixed wall-clock timeout",
            {"timeout_seconds": PROBE_TIMEOUT_SECONDS},
        ),
    }
    unavailable_details = {
        IsolationControl.STREAMING_OUTPUT_LIMIT: "streaming output enforcement is not implemented",
        IsolationControl.CPU_MEMORY_PID_LIMITS: "CPU, memory, and process limits are not implemented",
        IsolationControl.UNPRIVILEGED_IDENTITY: "a distinct unprivileged identity is not configured",
        IsolationControl.KERNEL_ISOLATION: "container or microVM isolation is not configured",
        IsolationControl.HOST_CREDENTIAL_BROKER_ISOLATION: "host credential brokers are not isolated",
        IsolationControl.INDEPENDENT_REVIEW: "the execution boundary has not been independently reviewed",
    }
    findings = []
    for control in REQUIRED_CONTROLS:
        if control in observations:
            status, detail, evidence = observations[control]
        else:
            status = ControlStatus.UNAVAILABLE
            detail = unavailable_details[control]
            evidence = {"available": False}
        findings.append(
            IsolationFinding(
                control=control,
                status=status,
                detail=detail,
                evidence_sha256=_json_digest(evidence),
            )
        )
    return tuple(findings)


def _require_safe_relative_path(path: str) -> None:
    if (
        not isinstance(path, str)
        or not path
        or len(path) > 240
        or "\\" in path
        or path.startswith("/")
        or path.endswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise ValueError(f"unsafe export path: {path}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts) or ".git" in parts:
        raise ValueError(f"unsafe export path: {path}")


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise IsolationProbeError(f"duplicate probe response field: {key}")
        payload[key] = value
    return payload


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return _bytes_sha256(encoded)
