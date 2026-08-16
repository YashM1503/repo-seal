"""Small, dependency-free contracts for evaluation artifacts.

These types deliberately describe evidence. They do not run agents, execute
repository code, or claim that a task is semantically valid.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ValidationCode(str, Enum):
    """Machine-readable reasons an evaluation task must be held or rejected."""

    BASE_NOT_FAILING = "BASE_NOT_FAILING"
    GOLD_NOT_PASSING = "GOLD_NOT_PASSING"
    FLAKY_VERIFIER = "FLAKY_VERIFIER"
    ORACLE_EXPOSED = "ORACLE_EXPOSED"
    HISTORY_LEAK = "HISTORY_LEAK"
    VERIFIER_MUTABLE = "VERIFIER_MUTABLE"
    NETWORK_POLICY_FAILURE = "NETWORK_POLICY_FAILURE"
    GRADER_TAMPER_SURFACE = "GRADER_TAMPER_SURFACE"
    SPEC_TEST_MISMATCH = "SPEC_TEST_MISMATCH"
    OVERCONSTRAINED_TEST = "OVERCONSTRAINED_TEST"
    UNDERPOWERED_TEST = "UNDERPOWERED_TEST"
    CACHE_LEAK = "CACHE_LEAK"


@dataclass(frozen=True)
class EnvironmentPolicy:
    image_digest: str
    network: str = "deny"
    wall_seconds: int = 900

    def __post_init__(self) -> None:
        _require_sha256(self.image_digest, "image_digest")
        if self.network not in {"deny", "allowlist"}:
            raise ValueError("network must be 'deny' or 'allowlist'")
        if self.wall_seconds <= 0:
            raise ValueError("wall_seconds must be positive")


@dataclass(frozen=True)
class TaskManifest:
    task_id: str
    base_commit: str
    snapshot_sha256: str
    statement: str
    environment: EnvironmentPolicy
    verifier_sha256: str
    schema_version: str = "0.1"

    def __post_init__(self) -> None:
        if not self.task_id.strip():
            raise ValueError("task_id must not be blank")
        if not self.base_commit.strip():
            raise ValueError("base_commit must not be blank")
        if not self.statement.strip():
            raise ValueError("statement must not be blank")
        _require_sha256(self.snapshot_sha256, "snapshot_sha256")
        _require_sha256(self.verifier_sha256, "verifier_sha256")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass(frozen=True)
class AgentConfiguration:
    configuration_id: str
    model: str
    harness: str
    instruction_sha256: str
    reasoning: str
    network: str = "deny"

    def __post_init__(self) -> None:
        for name in ("configuration_id", "model", "harness", "reasoning"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be blank")
        _require_sha256(self.instruction_sha256, "instruction_sha256")
        if self.network not in {"deny", "allowlist"}:
            raise ValueError("network must be 'deny' or 'allowlist'")


@dataclass(frozen=True)
class TaskQualityRecord:
    task_id: str
    reproducible: bool
    base_fail: bool
    gold_pass: bool
    flake_rate: float
    prompt_sufficiency: str
    leakage_scan: str
    environment_completeness: str
    confidence: float
    failures: tuple[ValidationCode, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not 0.0 <= self.flake_rate <= 1.0:
            raise ValueError("flake_rate must be between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    @property
    def eligible(self) -> bool:
        return (
            self.reproducible
            and self.base_fail
            and self.gold_pass
            and self.flake_rate == 0.0
            and not self.failures
        )


@dataclass(frozen=True)
class DecisionReceipt:
    baseline: str
    candidate: str
    task_set_sha256: str
    verifier_sha256: str
    primary_metric: str
    baseline_score: float
    candidate_score: float
    paired_effect: float
    confidence_interval: tuple[float, float]
    regressions: int
    holdout_status: str
    verdict: str

    def __post_init__(self) -> None:
        _require_sha256(self.task_set_sha256, "task_set_sha256")
        _require_sha256(self.verifier_sha256, "verifier_sha256")
        if self.confidence_interval[0] > self.confidence_interval[1]:
            raise ValueError("confidence_interval must be ordered")
        if self.regressions < 0:
            raise ValueError("regressions must not be negative")
        if self.holdout_status not in {"pass", "hold", "fail", "not_run"}:
            raise ValueError("invalid holdout_status")
        if self.verdict not in {"PROMOTE", "HOLD", "ROLLBACK"}:
            raise ValueError("invalid verdict")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def _require_sha256(value: str, field_name: str) -> None:
    if not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{field_name} must use the form sha256:<64 hex characters>")
    digest = value.removeprefix("sha256:")
    if any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field_name} must contain lowercase hexadecimal")
