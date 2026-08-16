"""Controlled source-snapshot replay with deterministic receipts.

This module is intentionally limited to trusted fixtures. It does not provide
process, filesystem, credential, or network isolation for arbitrary code.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any, Iterable

from .schemas import ValidationCode


class ReplayError(RuntimeError):
    """Raised when trusted replay infrastructure cannot produce a result."""


class SnapshotSecurityError(ReplayError):
    """Raised when an archive contains unsafe or unsupported entries."""


@dataclass(frozen=True)
class ReplayTask:
    task_id: str
    statement: str
    base_commit: str
    gold_commit: str

    def __post_init__(self) -> None:
        for name in ("task_id", "statement", "base_commit", "gold_commit"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-blank string")
        if self.base_commit == self.gold_commit:
            raise ValueError("base_commit and gold_commit must differ")
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", self.task_id) is None:
            raise ValueError("task_id must be safe for use as one path component")
        for name in ("base_commit", "gold_commit"):
            value = getattr(self, name)
            if len(value) not in {40, 64} or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ValueError(f"{name} must be a full lowercase Git object ID")


@dataclass(frozen=True)
class VerificationRun:
    passed: bool
    detail: str
    stdout_sha256: str
    stderr_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "detail": self.detail,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
        }


@dataclass(frozen=True)
class ReplayReceipt:
    task: ReplayTask
    base_snapshot_sha256: str
    gold_snapshot_sha256: str
    verifier_sha256: str
    base_runs: tuple[VerificationRun, ...]
    gold_runs: tuple[VerificationRun, ...]
    source_only_snapshots: bool
    verifier_outside_workspaces: bool
    verifier_read_only: bool
    verifier_unchanged: bool
    unmeasured_checks: tuple[ValidationCode, ...]
    receipt_version: str = "0.1"

    @property
    def base_fails(self) -> bool:
        return bool(self.base_runs) and all(not run.passed for run in self.base_runs)

    @property
    def gold_passes(self) -> bool:
        return bool(self.gold_runs) and all(run.passed for run in self.gold_runs)

    @property
    def stable(self) -> bool:
        return _runs_are_identical(self.base_runs) and _runs_are_identical(
            self.gold_runs
        )

    @property
    def gate_passed(self) -> bool:
        return all(
            (
                self.base_fails,
                self.gold_passes,
                self.stable,
                self.source_only_snapshots,
                self.verifier_outside_workspaces,
                self.verifier_read_only,
                self.verifier_unchanged,
            )
        )

    @property
    def receipt_sha256(self) -> str:
        return _json_digest(self._core_dict())

    def _core_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "task": {
                "task_id": self.task.task_id,
                "statement": self.task.statement,
                "base_commit": self.task.base_commit,
                "gold_commit": self.task.gold_commit,
            },
            "base_snapshot_sha256": self.base_snapshot_sha256,
            "gold_snapshot_sha256": self.gold_snapshot_sha256,
            "verifier_sha256": self.verifier_sha256,
            "base_runs": [run.to_dict() for run in self.base_runs],
            "gold_runs": [run.to_dict() for run in self.gold_runs],
            "source_only_snapshots": self.source_only_snapshots,
            "verifier_outside_workspaces": self.verifier_outside_workspaces,
            "verifier_read_only": self.verifier_read_only,
            "verifier_unchanged": self.verifier_unchanged,
            "unmeasured_checks": [code.value for code in self.unmeasured_checks],
            "base_fails": self.base_fails,
            "gold_passes": self.gold_passes,
            "stable": self.stable,
            "gate_passed": self.gate_passed,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._core_dict()
        payload["receipt_sha256"] = self.receipt_sha256
        return payload


@dataclass(frozen=True)
class ReplaySuiteReceipt:
    receipts: tuple[ReplayReceipt, ...]
    suite_version: str = "0.1"

    @property
    def gate_passed(self) -> bool:
        return bool(self.receipts) and all(
            receipt.gate_passed for receipt in self.receipts
        )

    @property
    def suite_sha256(self) -> str:
        return _json_digest(self._core_dict())

    def _core_dict(self) -> dict[str, Any]:
        return {
            "suite_version": self.suite_version,
            "task_count": len(self.receipts),
            "gate_passed": self.gate_passed,
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._core_dict()
        payload["suite_sha256"] = self.suite_sha256
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


UNMEASURED_M1_CHECKS: tuple[ValidationCode, ...] = (
    ValidationCode.ORACLE_EXPOSED,
    ValidationCode.NETWORK_POLICY_FAILURE,
    ValidationCode.GRADER_TAMPER_SURFACE,
    ValidationCode.SPEC_TEST_MISMATCH,
    ValidationCode.OVERCONSTRAINED_TEST,
    ValidationCode.UNDERPOWERED_TEST,
    ValidationCode.CACHE_LEAK,
)


def replay_suite(
    repository: Path,
    tasks: Iterable[ReplayTask],
    verifier_source: Path,
    work_root: Path,
    repetitions: int = 2,
) -> ReplaySuiteReceipt:
    task_tuple = tuple(tasks)
    if not task_tuple:
        raise ValueError("at least one replay task is required")
    if len({task.task_id for task in task_tuple}) != len(task_tuple):
        raise ValueError("task_id values must be unique")
    if work_root.exists():
        raise ValueError("work_root must not already exist")
    work_root.mkdir(parents=True)

    receipts = tuple(
        replay_task(
            repository=repository,
            task=task,
            verifier_source=verifier_source,
            work_root=work_root / task.task_id,
            repetitions=repetitions,
        )
        for task in task_tuple
    )
    return ReplaySuiteReceipt(receipts=receipts)


def replay_task(
    repository: Path,
    task: ReplayTask,
    verifier_source: Path,
    work_root: Path,
    repetitions: int = 2,
) -> ReplayReceipt:
    if repetitions < 2:
        raise ValueError("repetitions must be at least 2 to check stability")
    if work_root.exists():
        raise ValueError("work_root must not already exist")
    work_root.mkdir(parents=True)

    base_workspace = work_root / "candidate-base"
    gold_workspace = work_root / "candidate-gold"
    trusted_directory = work_root / "trusted-verifier"
    verifier = _stage_verifier(verifier_source, trusted_directory)

    snapshot_commit(repository, task.base_commit, base_workspace)
    snapshot_commit(repository, task.gold_commit, gold_workspace)

    verifier_sha256 = file_sha256(verifier)
    base_runs = tuple(
        _run_verifier_once(verifier, base_workspace, task.task_id)
        for _ in range(repetitions)
    )
    gold_runs = tuple(
        _run_verifier_once(verifier, gold_workspace, task.task_id)
        for _ in range(repetitions)
    )

    source_only = not any(
        path.name == ".git"
        for workspace in (base_workspace, gold_workspace)
        for path in workspace.rglob("*")
    )
    outside = all(
        not _is_relative_to(verifier, workspace)
        for workspace in (base_workspace, gold_workspace)
    )
    read_only = stat.S_IMODE(verifier.stat().st_mode) & 0o222 == 0
    unchanged = file_sha256(verifier) == verifier_sha256

    return ReplayReceipt(
        task=task,
        base_snapshot_sha256=tree_sha256(base_workspace),
        gold_snapshot_sha256=tree_sha256(gold_workspace),
        verifier_sha256=verifier_sha256,
        base_runs=base_runs,
        gold_runs=gold_runs,
        source_only_snapshots=source_only,
        verifier_outside_workspaces=outside,
        verifier_read_only=read_only,
        verifier_unchanged=unchanged,
        unmeasured_checks=UNMEASURED_M1_CHECKS,
    )


def snapshot_commit(repository: Path, commit: str, destination: Path) -> str:
    """Export one Git tree without refs, objects, hooks, or other `.git` data."""

    if destination.exists():
        raise ValueError("snapshot destination must not already exist")
    if not (repository / ".git").is_dir():
        raise ValueError("repository must be a Git working tree")

    completed = subprocess.run(
        ["git", "archive", "--format=tar", commit],
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReplayError(f"git archive failed for {commit}: {detail}")

    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            _extract_member(archive, member, destination)

    if any(path.name == ".git" for path in destination.rglob("*")):
        raise SnapshotSecurityError("source snapshot contains forbidden .git data")
    return tree_sha256(destination)


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise SnapshotSecurityError(f"symlink is not allowed: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SnapshotSecurityError(f"special file is not allowed: {path}")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        executable = b"1" if path.stat().st_mode & 0o111 else b"0"
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(executable)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return "sha256:" + digest.hexdigest()


def file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _stage_verifier(source: Path, directory: Path) -> Path:
    if not source.is_file():
        raise ValueError("verifier_source must be a file")
    directory.mkdir(parents=True)
    verifier = directory / "trusted_verifier.py"
    verifier.write_bytes(source.read_bytes())
    verifier.chmod(0o444)
    return verifier


def _run_verifier_once(
    verifier: Path, workspace: Path, task_id: str
) -> VerificationRun:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(verifier), str(workspace), task_id],
        cwd=workspace,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    if completed.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise ReplayError(f"trusted verifier failed for {task_id}: {detail}")
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReplayError(f"trusted verifier returned invalid JSON for {task_id}") from error
    if not isinstance(payload, dict) or type(payload.get("passed")) is not bool:
        raise ReplayError(f"trusted verifier returned an invalid result for {task_id}")
    detail = payload.get("detail")
    if not isinstance(detail, str):
        raise ReplayError(f"trusted verifier omitted detail for {task_id}")
    return VerificationRun(
        passed=payload["passed"],
        detail=detail,
        stdout_sha256="sha256:" + hashlib.sha256(stdout).hexdigest(),
        stderr_sha256="sha256:" + hashlib.sha256(stderr).hexdigest(),
    )


def _extract_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, destination: Path
) -> None:
    name = PurePosixPath(member.name)
    if name.is_absolute() or ".." in name.parts or ".git" in name.parts:
        raise SnapshotSecurityError(f"unsafe archive path: {member.name}")
    target = destination.joinpath(*name.parts)
    if not _is_relative_to(target, destination):
        raise SnapshotSecurityError(f"archive path escapes destination: {member.name}")
    if member.isdir():
        target.mkdir(parents=True, exist_ok=True)
        return
    if not member.isfile():
        raise SnapshotSecurityError(f"unsupported archive entry: {member.name}")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise SnapshotSecurityError(f"archive file has no content: {member.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(extracted.read())
    target.chmod(0o755 if member.mode & 0o111 else 0o644)


def _runs_are_identical(runs: tuple[VerificationRun, ...]) -> bool:
    if len(runs) < 2:
        return False
    first = runs[0]
    return all(run == first for run in runs[1:])


def _json_digest(payload: MappingLike) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


MappingLike = dict[str, Any]
