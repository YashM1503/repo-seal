"""User-facing validation for recorded benchmark-task evidence."""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

from .falsification import CHECKS, FalsificationEvidence, Finding, falsify
from .version import __version__

MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_BATCH_FILES = 1000


@dataclass(frozen=True)
class TaskEvidenceReport:
    """A deterministic decision derived from one evidence document."""

    task_id: str
    evidence_sha256: str
    findings: tuple[Finding, ...]
    evidence_schema_version: str = "0.1"
    report_schema_version: str = "0.2"

    @property
    def eligible(self) -> bool:
        return not self.findings

    @property
    def decision(self) -> str:
        return "ELIGIBLE" if self.eligible else "HOLD"

    @property
    def checks_evaluated(self) -> int:
        return len(CHECKS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_schema_version": self.report_schema_version,
            "report_kind": "task",
            "tool": "benchseal",
            "tool_version": __version__,
            "task_id": self.task_id,
            "decision": self.decision,
            "eligible": self.eligible,
            "checks_evaluated": self.checks_evaluated,
            "evidence_schema_version": self.evidence_schema_version,
            "evidence_sha256": self.evidence_sha256,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_text(self) -> str:
        lines = [
            "BenchSeal task evidence report",
            f"Task: {_display_text(self.task_id)}",
            f"Decision: {self.decision}",
            f"Evidence: {self.evidence_sha256}",
            f"Checks evaluated: {self.checks_evaluated}",
        ]
        if not self.findings:
            lines.extend(("", "No blocking findings were recorded."))
            return "\n".join(lines)

        lines.extend(("", f"Blocking findings ({len(self.findings)}):"))
        for finding in self.findings:
            lines.append(f"- {finding.code.value}: {finding.message}")
            for detail in finding.evidence:
                lines.append(f"  Evidence: {_display_text(detail)}")
        lines.extend(
            (
                "",
                (
                    "This task is on hold. Correct the evidence collection or task "
                    "design, then validate a new evidence document."
                ),
            )
        )
        return "\n".join(lines)


@dataclass(frozen=True)
class TaskSetEvidenceReport:
    """A deterministic summary for a directory of evidence documents."""

    tasks: tuple[TaskEvidenceReport, ...]
    report_schema_version: str = "0.2"

    def __post_init__(self) -> None:
        if not isinstance(self.tasks, tuple) or any(
            not isinstance(task, TaskEvidenceReport) for task in self.tasks
        ):
            raise TypeError("tasks must be a tuple of task evidence reports")
        if not self.tasks:
            raise ValueError("task set must contain at least one report")
        duplicates = _duplicate_task_ids(self.tasks)
        if duplicates:
            raise ValueError(f"duplicate task_id values: {', '.join(duplicates)}")
        ordered = tuple(
            sorted(
                self.tasks,
                key=lambda task: (task.task_id, task.evidence_sha256),
            )
        )
        object.__setattr__(self, "tasks", ordered)

    @property
    def eligible(self) -> bool:
        return all(task.eligible for task in self.tasks)

    @property
    def decision(self) -> str:
        return "ELIGIBLE" if self.eligible else "HOLD"

    @property
    def eligible_count(self) -> int:
        return sum(task.eligible for task in self.tasks)

    @property
    def held_count(self) -> int:
        return len(self.tasks) - self.eligible_count

    @property
    def task_set_sha256(self) -> str:
        payload = {
            "tasks": [
                {
                    "task_id": task.task_id,
                    "evidence_sha256": task.evidence_sha256,
                }
                for task in self.tasks
            ]
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_schema_version": self.report_schema_version,
            "report_kind": "task_set",
            "tool": "benchseal",
            "tool_version": __version__,
            "decision": self.decision,
            "eligible": self.eligible,
            "task_count": len(self.tasks),
            "eligible_count": self.eligible_count,
            "held_count": self.held_count,
            "task_set_sha256": self.task_set_sha256,
            "tasks": [task.to_dict() for task in self.tasks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_text(self) -> str:
        lines = [
            "BenchSeal task set report",
            f"Decision: {self.decision}",
            f"Tasks: {len(self.tasks)}",
            f"Eligible: {self.eligible_count}",
            f"Hold: {self.held_count}",
            f"Task set: {self.task_set_sha256}",
            "",
        ]
        for task in self.tasks:
            codes = ", ".join(finding.code.value for finding in task.findings)
            detail = codes if codes else "no blocking findings"
            lines.append(
                f"- {_display_text(task.task_id)}: {task.decision} ({detail})"
            )
        return "\n".join(lines)


EvidenceReport = Union[TaskEvidenceReport, TaskSetEvidenceReport]


def write_evidence_draft(path: Path, task_id: str) -> None:
    """Write a deliberately incomplete evidence document without overwriting."""

    if not isinstance(task_id, str) or not task_id.strip():
        raise ValueError("task_id must be a non-blank string")
    if path.exists() or path.is_symlink():
        raise ValueError("output file must not already exist")
    payload = {
        "schema_version": "0.1",
        "task_id": task_id,
        "base_fails": None,
        "gold_passes": None,
        "flake_rate": None,
        "oracle_artifacts": None,
        "future_history_accessible": None,
        "verifier_writable": None,
        "network_egress_observed": None,
        "grader_tamper_vectors": None,
        "declared_requirements": None,
        "verified_requirements": None,
        "rejected_valid_alternatives": None,
        "broken_patch_passes": None,
        "broken_patch_trials": None,
        "cache_leaks": None,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2) + "\n")


def validate_evidence_path(path: Path) -> EvidenceReport:
    """Validate one evidence file or every JSON file in one directory."""

    if path.is_symlink():
        raise ValueError("evidence path must not be a symlink")
    if path.is_file():
        return validate_evidence_file(path)
    if not path.is_dir():
        raise ValueError("evidence path must be a JSON file or directory")

    candidates = tuple(
        sorted(
            (
                candidate
                for candidate in path.iterdir()
                if candidate.suffix == ".json"
                and (candidate.is_file() or candidate.is_symlink())
            ),
            key=lambda candidate: candidate.name,
        )
    )
    if not candidates:
        raise ValueError("evidence directory contains no JSON files")
    if len(candidates) > MAX_BATCH_FILES:
        raise ValueError(f"evidence directory exceeds {MAX_BATCH_FILES} JSON files")

    reports = []
    for candidate in candidates:
        try:
            reports.append(validate_evidence_file(candidate))
        except (OSError, TypeError, ValueError) as error:
            raise ValueError(f"invalid evidence file {candidate.name}: {error}") from error
    duplicates = _duplicate_task_ids(tuple(reports))
    if duplicates:
        raise ValueError(f"duplicate task_id values: {', '.join(duplicates)}")
    return TaskSetEvidenceReport(tasks=tuple(reports))


def _duplicate_task_ids(
    reports: tuple[TaskEvidenceReport, ...],
) -> tuple[str, ...]:
    counts: dict[str, int] = {}
    for report in reports:
        counts[report.task_id] = counts.get(report.task_id, 0) + 1
    return tuple(sorted(task_id for task_id, count in counts.items() if count > 1))


def validate_evidence_file(path: Path) -> TaskEvidenceReport:
    """Parse and validate one standalone evidence JSON file."""

    if path.is_symlink():
        raise ValueError("evidence path must not be a symlink")
    try:
        metadata = path.stat()
    except OSError as error:
        raise ValueError("evidence file is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("evidence path must be a regular file")
    if metadata.st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence file exceeds 1 MiB")

    try:
        with path.open("rb") as handle:
            content = handle.read(MAX_EVIDENCE_BYTES + 1)
        if len(content) > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence file exceeds 1 MiB")
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except UnicodeDecodeError as error:
        raise ValueError("evidence file must be UTF-8 JSON") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"evidence file contains invalid JSON: {error.msg}") from error
    if not isinstance(payload, dict):
        raise TypeError("evidence document must be a JSON object")

    evidence = FalsificationEvidence.from_dict(payload)
    result = falsify(evidence)
    return TaskEvidenceReport(
        task_id=evidence.task_id,
        evidence_schema_version=evidence.schema_version,
        evidence_sha256="sha256:" + hashlib.sha256(content).hexdigest(),
        findings=result.findings,
    )


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _display_text(value: str) -> str:
    """Escape control characters before rendering untrusted evidence."""

    return json.dumps(value, ensure_ascii=True)[1:-1]
