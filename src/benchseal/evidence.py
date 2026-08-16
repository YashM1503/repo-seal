"""User-facing validation for recorded benchmark-task evidence."""

from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .falsification import CHECKS, FalsificationEvidence, Finding, falsify
from .version import __version__

MAX_EVIDENCE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class TaskEvidenceReport:
    """A deterministic decision derived from one evidence document."""

    task_id: str
    evidence_sha256: str
    findings: tuple[Finding, ...]
    evidence_schema_version: str = "0.1"
    report_schema_version: str = "0.1"

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
