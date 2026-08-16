"""M2a controlled patch-agent replay and evidence receipts."""

from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .agent_boundary import (
    AgentInvocation,
    apply_patch_artifact,
    capture_request,
    run_controlled_adapter,
)
from .replay import (
    ReplayTask,
    VerificationRun,
    _run_verifier_once,
    _stage_verifier,
    file_sha256,
    snapshot_commit,
    tree_sha256,
)
from .schemas import ValidationCode

UNMEASURED_M2A_CHECKS: tuple[ValidationCode, ...] = (
    ValidationCode.ORACLE_EXPOSED,
    ValidationCode.HISTORY_LEAK,
    ValidationCode.VERIFIER_MUTABLE,
    ValidationCode.NETWORK_POLICY_FAILURE,
    ValidationCode.GRADER_TAMPER_SURFACE,
    ValidationCode.SPEC_TEST_MISMATCH,
    ValidationCode.OVERCONSTRAINED_TEST,
    ValidationCode.UNDERPOWERED_TEST,
    ValidationCode.CACHE_LEAK,
)

UNIMPLEMENTED_M2A_CONTROLS: tuple[str, ...] = (
    "filesystem_sandbox",
    "network_deny",
    "cpu_memory_pid_limits",
    "kernel_isolation",
    "host_credential_broker_isolation",
    "untrusted_adapter_support",
)


@dataclass(frozen=True)
class ControlledAgentReceipt:
    task: ReplayTask
    base_snapshot_sha256: str
    patched_snapshot_sha256: str
    request_sha256: str
    artifact_sha256: str
    adapter_id: str
    adapter_sha256: str
    agent_stdout_sha256: str
    agent_stderr_sha256: str
    agent_environment_keys: tuple[str, ...]
    agent_timeout_seconds: int
    changed_paths: tuple[str, ...]
    verifier_sha256: str
    verifier_runs: tuple[VerificationRun, ...]
    source_only_snapshot: bool
    request_contains_no_host_paths: bool
    parent_environment_replaced: bool
    task_verifier_copy_staged_after_adapter: bool
    verifier_outside_workspace: bool
    verifier_read_only: bool
    verifier_unchanged: bool
    unmeasured_checks: tuple[ValidationCode, ...]
    unimplemented_controls: tuple[str, ...]
    receipt_version: str = "0.1"

    @property
    def verifier_passes(self) -> bool:
        return bool(self.verifier_runs) and all(
            run.passed for run in self.verifier_runs
        )

    @property
    def stable(self) -> bool:
        return len(self.verifier_runs) >= 2 and all(
            run == self.verifier_runs[0] for run in self.verifier_runs[1:]
        )

    @property
    def contract_gate_passed(self) -> bool:
        return all(
            (
                self.verifier_passes,
                self.stable,
                bool(self.changed_paths),
                self.source_only_snapshot,
                self.request_contains_no_host_paths,
                self.parent_environment_replaced,
                self.task_verifier_copy_staged_after_adapter,
                self.verifier_outside_workspace,
                self.verifier_read_only,
                self.verifier_unchanged,
            )
        )

    @property
    def security_gate_passed(self) -> bool:
        return not self.unimplemented_controls and not self.unmeasured_checks

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
            "patched_snapshot_sha256": self.patched_snapshot_sha256,
            "request_sha256": self.request_sha256,
            "artifact_sha256": self.artifact_sha256,
            "adapter_id": self.adapter_id,
            "adapter_sha256": self.adapter_sha256,
            "agent_stdout_sha256": self.agent_stdout_sha256,
            "agent_stderr_sha256": self.agent_stderr_sha256,
            "agent_environment_keys": list(self.agent_environment_keys),
            "agent_timeout_seconds": self.agent_timeout_seconds,
            "changed_paths": list(self.changed_paths),
            "verifier_sha256": self.verifier_sha256,
            "verifier_runs": [run.to_dict() for run in self.verifier_runs],
            "source_only_snapshot": self.source_only_snapshot,
            "request_contains_no_host_paths": self.request_contains_no_host_paths,
            "parent_environment_replaced": self.parent_environment_replaced,
            "task_verifier_copy_staged_after_adapter": self.task_verifier_copy_staged_after_adapter,
            "verifier_outside_workspace": self.verifier_outside_workspace,
            "verifier_read_only": self.verifier_read_only,
            "verifier_unchanged": self.verifier_unchanged,
            "verifier_passes": self.verifier_passes,
            "stable": self.stable,
            "contract_gate_passed": self.contract_gate_passed,
            "security_gate_passed": self.security_gate_passed,
            "safe_for_real_agents": False,
            "unmeasured_checks": [code.value for code in self.unmeasured_checks],
            "unimplemented_controls": list(self.unimplemented_controls),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._core_dict()
        payload["receipt_sha256"] = self.receipt_sha256
        return payload


@dataclass(frozen=True)
class ControlledAgentSuiteReceipt:
    receipts: tuple[ControlledAgentReceipt, ...]
    suite_version: str = "0.1"

    @property
    def contract_gate_passed(self) -> bool:
        return bool(self.receipts) and all(
            receipt.contract_gate_passed for receipt in self.receipts
        )

    @property
    def security_gate_passed(self) -> bool:
        return bool(self.receipts) and all(
            receipt.security_gate_passed for receipt in self.receipts
        )

    @property
    def suite_sha256(self) -> str:
        return _json_digest(self._core_dict())

    def _core_dict(self) -> dict[str, Any]:
        return {
            "suite_version": self.suite_version,
            "task_count": len(self.receipts),
            "contract_gate_passed": self.contract_gate_passed,
            "security_gate_passed": self.security_gate_passed,
            "safe_for_real_agents": False,
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._core_dict()
        payload["suite_sha256"] = self.suite_sha256
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def controlled_mock_adapter_path() -> Path:
    return Path(__file__).with_name("mock_agent.py")


def replay_controlled_agent_suite(
    repository: Path,
    tasks: Iterable[ReplayTask],
    verifier_source: Path,
    work_root: Path,
    *,
    adapter_script: Optional[Path] = None,
    repetitions: int = 2,
) -> ControlledAgentSuiteReceipt:
    """Replay trusted mock artifacts across controlled source snapshots only."""

    task_tuple = tuple(tasks)
    if not task_tuple:
        raise ValueError("at least one replay task is required")
    if len({task.task_id for task in task_tuple}) != len(task_tuple):
        raise ValueError("task_id values must be unique")
    if repetitions < 2:
        raise ValueError("repetitions must be at least 2 to check stability")
    if work_root.exists():
        raise ValueError("work_root must not already exist")
    work_root.mkdir(parents=True)
    selected_adapter = adapter_script or controlled_mock_adapter_path()
    receipts = tuple(
        _replay_controlled_agent_task(
            repository=repository,
            task=task,
            verifier_source=verifier_source,
            adapter_script=selected_adapter,
            work_root=work_root / task.task_id,
            repetitions=repetitions,
        )
        for task in task_tuple
    )
    return ControlledAgentSuiteReceipt(receipts=receipts)


def _replay_controlled_agent_task(
    repository: Path,
    task: ReplayTask,
    verifier_source: Path,
    adapter_script: Path,
    work_root: Path,
    repetitions: int,
) -> ControlledAgentReceipt:
    work_root.mkdir(parents=True)
    candidate = work_root / "candidate"
    base_snapshot_sha256 = snapshot_commit(repository, task.base_commit, candidate)
    request = capture_request(candidate, task.task_id, task.statement)
    serialized_request = request.to_json()
    invocation: AgentInvocation = run_controlled_adapter(
        request=request,
        adapter_script=adapter_script,
        scratch_directory=work_root / "agent-scratch",
    )
    changed_paths = apply_patch_artifact(
        request,
        invocation.artifact,
        candidate,
        allowed_paths=("toycalc.py",),
    )

    trusted_directory = work_root / "trusted-verifier"
    verifier = _stage_verifier(verifier_source, trusted_directory)
    verifier_sha256 = file_sha256(verifier)
    verifier_runs = tuple(
        _run_verifier_once(verifier, candidate, task.task_id)
        for _ in range(repetitions)
    )
    candidate_names = {path.name for path in candidate.rglob("*")}
    source_only_snapshot = (
        ".git" not in candidate_names and "trusted_verifier.py" not in candidate_names
    )
    request_contains_no_host_paths = all(
        host_path not in serialized_request
        for host_path in (str(work_root.resolve()), str(candidate.resolve()))
    )
    verifier_outside_workspace = not _is_relative_to(verifier, candidate)
    verifier_read_only = stat.S_IMODE(verifier.stat().st_mode) & 0o222 == 0
    verifier_unchanged = file_sha256(verifier) == verifier_sha256

    return ControlledAgentReceipt(
        task=task,
        base_snapshot_sha256=base_snapshot_sha256,
        patched_snapshot_sha256=tree_sha256(candidate),
        request_sha256=invocation.request_sha256,
        artifact_sha256=invocation.artifact.artifact_sha256,
        adapter_id=invocation.artifact.adapter_id,
        adapter_sha256=invocation.adapter_sha256,
        agent_stdout_sha256=invocation.stdout_sha256,
        agent_stderr_sha256=invocation.stderr_sha256,
        agent_environment_keys=invocation.environment_keys,
        agent_timeout_seconds=invocation.timeout_seconds,
        changed_paths=changed_paths,
        verifier_sha256=verifier_sha256,
        verifier_runs=verifier_runs,
        source_only_snapshot=source_only_snapshot,
        request_contains_no_host_paths=request_contains_no_host_paths,
        parent_environment_replaced=invocation.environment_keys
        == ("HOME", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "TMPDIR", "TZ"),
        task_verifier_copy_staged_after_adapter=True,
        verifier_outside_workspace=verifier_outside_workspace,
        verifier_read_only=verifier_read_only,
        verifier_unchanged=verifier_unchanged,
        unmeasured_checks=UNMEASURED_M2A_CHECKS,
        unimplemented_controls=UNIMPLEMENTED_M2A_CONTROLS,
    )


def _json_digest(payload: dict[str, Any]) -> str:
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
