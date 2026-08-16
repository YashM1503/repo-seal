"""Capability-reduced protocol for trusted, controlled agent test doubles.

The protocol deliberately carries source bytes rather than host filesystem paths
and accepts only bounded replacements of existing files.  The subprocess helper
does not provide operating-system filesystem or network isolation; callers must
not use it with an untrusted or real agent.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .replay import SnapshotSecurityError, file_sha256, tree_sha256

REQUEST_VERSION = "0.1"
ARTIFACT_VERSION = "0.1"
DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024
DEFAULT_MAX_REPLACEMENT_BYTES = 128 * 1024
DEFAULT_MAX_FILES = 16
DEFAULT_MAX_REQUEST_BYTES = 512 * 1024
DEFAULT_MAX_SOURCE_FILES = 64


class AgentBoundaryError(RuntimeError):
    """Raised when the controlled adapter process violates its contract."""


class PatchValidationError(AgentBoundaryError):
    """Raised when a patch artifact fails closed validation."""


@dataclass(frozen=True)
class SourceFile:
    path: str
    sha256: str
    content_utf8: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "content_utf8": self.content_utf8,
        }


@dataclass(frozen=True)
class AgentRequest:
    task_id: str
    statement: str
    base_snapshot_sha256: str
    files: tuple[SourceFile, ...]
    request_version: str = REQUEST_VERSION

    def __post_init__(self) -> None:
        if self.request_version != REQUEST_VERSION:
            raise ValueError("unsupported request_version")
        _require_task_id(self.task_id)
        if not isinstance(self.statement, str) or not self.statement.strip():
            raise ValueError("statement must be a non-blank string")
        _require_sha256(self.base_snapshot_sha256, "base_snapshot_sha256")
        if not self.files:
            raise ValueError("at least one source file is required")
        seen = set()
        for source_file in self.files:
            _require_safe_path(source_file.path)
            _require_sha256(source_file.sha256, "source file sha256")
            if source_file.path in seen:
                raise ValueError(f"duplicate source path: {source_file.path}")
            seen.add(source_file.path)
            if (
                _bytes_sha256(source_file.content_utf8.encode("utf-8"))
                != source_file.sha256
            ):
                raise ValueError(f"source digest mismatch: {source_file.path}")

    @property
    def request_sha256(self) -> str:
        return _json_digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_version": self.request_version,
            "task_id": self.task_id,
            "statement": self.statement,
            "base_snapshot_sha256": self.base_snapshot_sha256,
            "files": [source_file.to_dict() for source_file in self.files],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class FileReplacement:
    path: str
    expected_sha256: str
    content_utf8: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "expected_sha256": self.expected_sha256,
            "content_utf8": self.content_utf8,
        }


@dataclass(frozen=True)
class PatchArtifact:
    adapter_id: str
    task_id: str
    base_snapshot_sha256: str
    replacements: tuple[FileReplacement, ...]
    artifact_version: str = ARTIFACT_VERSION

    def __post_init__(self) -> None:
        if self.artifact_version != ARTIFACT_VERSION:
            raise ValueError("unsupported artifact_version")
        if not isinstance(self.adapter_id, str) or not self.adapter_id.strip():
            raise ValueError("adapter_id must be a non-blank string")
        _require_task_id(self.task_id)
        _require_sha256(self.base_snapshot_sha256, "base_snapshot_sha256")
        if not self.replacements:
            raise ValueError("at least one replacement is required")

    @property
    def artifact_sha256(self) -> str:
        return _json_digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_version": self.artifact_version,
            "adapter_id": self.adapter_id,
            "task_id": self.task_id,
            "base_snapshot_sha256": self.base_snapshot_sha256,
            "replacements": [
                replacement.to_dict() for replacement in self.replacements
            ],
        }


@dataclass(frozen=True)
class AgentInvocation:
    artifact: PatchArtifact
    request_sha256: str
    adapter_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    environment_keys: tuple[str, ...]
    timeout_seconds: int


def capture_request(
    workspace: Path,
    task_id: str,
    statement: str,
    *,
    max_source_bytes: int = DEFAULT_MAX_REPLACEMENT_BYTES,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    max_source_files: int = DEFAULT_MAX_SOURCE_FILES,
) -> AgentRequest:
    """Capture a UTF-8 source-only request without including a host path."""

    if min(max_source_bytes, max_request_bytes, max_source_files) <= 0:
        raise ValueError("request byte and file limits must be positive")
    snapshot_sha256 = tree_sha256(workspace)
    source_files = []
    for path in sorted(
        workspace.rglob("*"), key=lambda item: item.relative_to(workspace).as_posix()
    ):
        if path.is_symlink():
            raise SnapshotSecurityError(f"symlink is not allowed: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SnapshotSecurityError(f"special file is not allowed: {path}")
        if len(source_files) >= max_source_files:
            raise AgentBoundaryError("source file count exceeds the request limit")
        relative = path.relative_to(workspace).as_posix()
        _require_safe_path(relative)
        raw = path.read_bytes()
        if len(raw) > max_source_bytes:
            raise AgentBoundaryError(f"source file exceeds byte limit: {relative}")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AgentBoundaryError(f"source file is not UTF-8: {relative}") from error
        source_files.append(
            SourceFile(path=relative, sha256=_bytes_sha256(raw), content_utf8=content)
        )
    request = AgentRequest(
        task_id=task_id,
        statement=statement,
        base_snapshot_sha256=snapshot_sha256,
        files=tuple(source_files),
    )
    if len(request.to_json().encode("utf-8")) > max_request_bytes:
        raise AgentBoundaryError("serialized request exceeds the byte limit")
    return request


def parse_patch_artifact(
    raw: bytes,
    *,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    max_replacement_bytes: int = DEFAULT_MAX_REPLACEMENT_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> PatchArtifact:
    """Parse an adapter response using a strict, bounded JSON schema."""

    if not raw:
        raise PatchValidationError("adapter returned an empty artifact")
    if len(raw) > max_artifact_bytes:
        raise PatchValidationError("artifact exceeds byte limit")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PatchValidationError("artifact must be valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise PatchValidationError("artifact must be a JSON object")
    _require_exact_keys(
        payload,
        {
            "artifact_version",
            "adapter_id",
            "task_id",
            "base_snapshot_sha256",
            "replacements",
        },
        "artifact",
    )
    replacements_payload = payload["replacements"]
    if not isinstance(replacements_payload, list):
        raise PatchValidationError("replacements must be a JSON array")
    if not 1 <= len(replacements_payload) <= max_files:
        raise PatchValidationError("replacement count is outside the allowed range")
    replacements = []
    seen = set()
    for item in replacements_payload:
        if not isinstance(item, dict):
            raise PatchValidationError("each replacement must be a JSON object")
        _require_exact_keys(
            item,
            {"path", "expected_sha256", "content_utf8"},
            "replacement",
        )
        path = _require_string(item["path"], "replacement path")
        expected_sha256 = _require_string(
            item["expected_sha256"], "replacement expected_sha256"
        )
        content = _require_string(item["content_utf8"], "replacement content_utf8")
        _require_safe_path(path)
        try:
            _require_sha256(expected_sha256, "replacement expected_sha256")
        except ValueError as error:
            raise PatchValidationError(str(error)) from error
        if path in seen:
            raise PatchValidationError(f"duplicate replacement path: {path}")
        seen.add(path)
        if len(content.encode("utf-8")) > max_replacement_bytes:
            raise PatchValidationError(f"replacement exceeds byte limit: {path}")
        replacements.append(
            FileReplacement(
                path=path,
                expected_sha256=expected_sha256,
                content_utf8=content,
            )
        )
    try:
        return PatchArtifact(
            artifact_version=_require_string(
                payload["artifact_version"], "artifact_version"
            ),
            adapter_id=_require_string(payload["adapter_id"], "adapter_id"),
            task_id=_require_string(payload["task_id"], "task_id"),
            base_snapshot_sha256=_require_string(
                payload["base_snapshot_sha256"], "base_snapshot_sha256"
            ),
            replacements=tuple(replacements),
        )
    except ValueError as error:
        raise PatchValidationError(str(error)) from error


def validate_patch_artifact(
    request: AgentRequest,
    artifact: PatchArtifact,
    workspace: Path,
    *,
    allowed_paths: Iterable[str],
) -> tuple[str, ...]:
    """Fail closed unless an artifact replaces only approved, unchanged files."""

    allowed = frozenset(allowed_paths)
    if not allowed:
        raise ValueError("allowed_paths must not be empty")
    for path in allowed:
        _require_safe_path(path)
    if artifact.task_id != request.task_id:
        raise PatchValidationError("artifact task_id does not match the request")
    if artifact.base_snapshot_sha256 != request.base_snapshot_sha256:
        raise PatchValidationError("artifact base snapshot does not match the request")
    if tree_sha256(workspace) != request.base_snapshot_sha256:
        raise PatchValidationError("workspace changed after request capture")

    request_files = {source_file.path: source_file for source_file in request.files}
    validated_paths = []
    for replacement in artifact.replacements:
        if replacement.path not in allowed:
            raise PatchValidationError(
                f"replacement path is not allowed: {replacement.path}"
            )
        source_file = request_files.get(replacement.path)
        if source_file is None:
            raise PatchValidationError(
                f"replacement path was not present in the request: {replacement.path}"
            )
        target = workspace.joinpath(*replacement.path.split("/"))
        if target.is_symlink():
            raise PatchValidationError(
                f"replacement target is a symlink: {replacement.path}"
            )
        if not target.is_file() or not _is_relative_to(target, workspace):
            raise PatchValidationError(
                f"replacement target is not a regular workspace file: {replacement.path}"
            )
        current_sha256 = file_sha256(target)
        if replacement.expected_sha256 != source_file.sha256:
            raise PatchValidationError(
                f"replacement digest does not match the request: {replacement.path}"
            )
        if current_sha256 != replacement.expected_sha256:
            raise PatchValidationError(
                f"replacement target changed after capture: {replacement.path}"
            )
        if replacement.content_utf8.encode("utf-8") == target.read_bytes():
            raise PatchValidationError(f"replacement is a no-op: {replacement.path}")
        validated_paths.append(replacement.path)
    return tuple(validated_paths)


def apply_patch_artifact(
    request: AgentRequest,
    artifact: PatchArtifact,
    workspace: Path,
    *,
    allowed_paths: Iterable[str],
) -> tuple[str, ...]:
    """Atomically replace each validated file while preserving its mode."""

    changed_paths = validate_patch_artifact(
        request, artifact, workspace, allowed_paths=allowed_paths
    )
    staged: list[tuple[Path, Path]] = []
    try:
        for index, replacement in enumerate(artifact.replacements):
            target = workspace.joinpath(*replacement.path.split("/"))
            temporary = target.parent / f".benchseal-replacement-{os.getpid()}-{index}"
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(replacement.content_utf8.encode("utf-8"))
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            os.chmod(temporary, stat.S_IMODE(target.stat().st_mode))
            staged.append((temporary, target))
        for temporary, target in staged:
            os.replace(temporary, target)
    finally:
        for temporary, _ in staged:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return changed_paths


def run_controlled_adapter(
    request: AgentRequest,
    adapter_script: Path,
    scratch_directory: Path,
    *,
    timeout_seconds: int = 5,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> AgentInvocation:
    """Run the repository's trusted mock adapter with a minimal environment.

    This is a process/protocol boundary only.  It is not safe for an untrusted
    command because it does not deny host filesystem or network access.
    """

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if scratch_directory.exists():
        raise ValueError("scratch_directory must not already exist")
    if not adapter_script.is_file():
        raise ValueError("adapter_script must be a file")
    scratch_directory.mkdir(parents=True, mode=0o700)
    environment = {
        "HOME": str(scratch_directory),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(scratch_directory),
        "TZ": "UTC",
    }
    request_bytes = request.to_json().encode("utf-8")
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(adapter_script)],
            cwd=scratch_directory,
            env=environment,
            input=request_bytes,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
            close_fds=True,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as error:
        raise AgentBoundaryError("controlled adapter exceeded its timeout") from error
    if len(completed.stdout) > max_artifact_bytes:
        raise AgentBoundaryError("controlled adapter output exceeds the byte limit")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AgentBoundaryError(
            f"controlled adapter exited with {completed.returncode}: {detail}"
        )
    artifact = parse_patch_artifact(
        completed.stdout, max_artifact_bytes=max_artifact_bytes
    )
    return AgentInvocation(
        artifact=artifact,
        request_sha256=request.request_sha256,
        adapter_sha256=file_sha256(adapter_script),
        stdout_sha256=_bytes_sha256(completed.stdout),
        stderr_sha256=_bytes_sha256(completed.stderr),
        environment_keys=tuple(sorted(environment)),
        timeout_seconds=timeout_seconds,
    )


def _require_safe_path(path: str) -> None:
    if not isinstance(path, str) or not path or len(path) > 240:
        raise PatchValidationError(
            "path must be a non-empty string of at most 240 characters"
        )
    if "\\" in path or path.startswith("/") or path.endswith("/"):
        raise PatchValidationError(f"unsafe artifact path: {path}")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise PatchValidationError(f"unsafe artifact path: {path}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts) or ".git" in parts:
        raise PatchValidationError(f"unsafe artifact path: {path}")


def _require_task_id(task_id: str) -> None:
    if (
        not isinstance(task_id, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", task_id) is None
    ):
        raise ValueError("task_id must be a safe non-blank identifier")


def _require_sha256(value: str, name: str) -> None:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
    ):
        raise ValueError(f"{name} must use sha256:<64 lowercase hex characters>")


def _require_string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise PatchValidationError(f"{name} must be a string")
    return value


def _require_exact_keys(
    value: Mapping[str, object], expected: set[str], name: str
) -> None:
    actual = set(value)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise PatchValidationError(
            f"{name} fields do not match schema; missing={missing}, unexpected={unexpected}"
        )


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise PatchValidationError(f"duplicate JSON field: {key}")
        payload[key] = value
    return payload


def _bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return _bytes_sha256(encoded)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True
