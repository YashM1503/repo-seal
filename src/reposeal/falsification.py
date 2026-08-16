"""Deterministic falsification checks for evaluation-task evidence.

The harness evaluates recorded observations. It intentionally does not execute
repository code, inspect live credentials, or claim to provide a sandbox.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .schemas import ValidationCode


@dataclass(frozen=True)
class FalsificationEvidence:
    """Observations collected by a trusted task-validation process."""

    task_id: str
    base_fails: bool
    gold_passes: bool
    flake_rate: float
    oracle_artifacts: tuple[str, ...]
    future_history_accessible: bool
    verifier_writable: bool
    network_egress_observed: bool
    grader_tamper_vectors: tuple[str, ...]
    declared_requirements: frozenset[str]
    verified_requirements: frozenset[str]
    rejected_valid_alternatives: int
    broken_patch_passes: int
    broken_patch_trials: int
    cache_leaks: tuple[str, ...]
    schema_version: str = "0.1"

    def __post_init__(self) -> None:
        if not self.task_id.strip():
            raise ValueError("task_id must not be blank")
        if self.schema_version != "0.1":
            raise ValueError(f"unsupported evidence schema_version: {self.schema_version}")
        for name in (
            "base_fails",
            "gold_passes",
            "future_history_accessible",
            "verifier_writable",
            "network_egress_observed",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if isinstance(self.flake_rate, bool) or not isinstance(
            self.flake_rate, (int, float)
        ):
            raise ValueError("flake_rate must be a number")  # noqa: TRY004
        if not 0.0 <= self.flake_rate <= 1.0:
            raise ValueError("flake_rate must be between 0 and 1")
        for name in ("oracle_artifacts", "grader_tamper_vectors", "cache_leaks"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise ValueError(f"{name} must be a tuple of non-blank strings")
        for name in ("declared_requirements", "verified_requirements"):
            value = getattr(self, name)
            if not isinstance(value, frozenset) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise ValueError(f"{name} must be a frozenset of non-blank strings")
        for name in (
            "rejected_valid_alternatives",
            "broken_patch_passes",
            "broken_patch_trials",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")  # noqa: TRY004
            if value < 0:
                raise ValueError(f"{name} must not be negative")
        if self.broken_patch_passes > self.broken_patch_trials:
            raise ValueError("broken_patch_passes cannot exceed broken_patch_trials")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FalsificationEvidence:
        allowed = {
            "schema_version",
            "task_id",
            "base_fails",
            "gold_passes",
            "flake_rate",
            "oracle_artifacts",
            "future_history_accessible",
            "verifier_writable",
            "network_egress_observed",
            "grader_tamper_vectors",
            "declared_requirements",
            "verified_requirements",
            "rejected_valid_alternatives",
            "broken_patch_passes",
            "broken_patch_trials",
            "cache_leaks",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise ValueError(f"unknown evidence fields: {', '.join(unknown)}")

        return cls(
            schema_version=_optional_string(payload, "schema_version", "0.1"),
            task_id=_required_string(payload, "task_id"),
            base_fails=_required_bool(payload, "base_fails"),
            gold_passes=_required_bool(payload, "gold_passes"),
            flake_rate=_required_number(payload, "flake_rate"),
            oracle_artifacts=_required_strings(payload, "oracle_artifacts"),
            future_history_accessible=_required_bool(
                payload, "future_history_accessible"
            ),
            verifier_writable=_required_bool(payload, "verifier_writable"),
            network_egress_observed=_required_bool(
                payload, "network_egress_observed"
            ),
            grader_tamper_vectors=_required_strings(payload, "grader_tamper_vectors"),
            declared_requirements=frozenset(
                _required_strings(payload, "declared_requirements")
            ),
            verified_requirements=frozenset(
                _required_strings(payload, "verified_requirements")
            ),
            rejected_valid_alternatives=_required_int(
                payload, "rejected_valid_alternatives"
            ),
            broken_patch_passes=_required_int(payload, "broken_patch_passes"),
            broken_patch_trials=_required_int(payload, "broken_patch_trials"),
            cache_leaks=_required_strings(payload, "cache_leaks"),
        )


@dataclass(frozen=True)
class Finding:
    code: ValidationCode
    message: str
    evidence: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class FalsificationResult:
    task_id: str
    findings: tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings

    @property
    def codes(self) -> tuple[ValidationCode, ...]:
        return tuple(finding.code for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


@dataclass(frozen=True)
class FalsificationFixture:
    name: str
    expected_failures: tuple[ValidationCode, ...]
    evidence: FalsificationEvidence
    fixture_version: str = "0.1"

    def __post_init__(self) -> None:
        if self.fixture_version != "0.1":
            raise ValueError(f"unsupported fixture_version: {self.fixture_version}")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FalsificationFixture:
        allowed = {"fixture_version", "name", "expected_failures", "evidence"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise ValueError(f"unknown fixture fields: {', '.join(unknown)}")

        expected_raw = payload.get("expected_failures")
        if not isinstance(expected_raw, list) or any(
            not isinstance(value, str) for value in expected_raw
        ):
            raise ValueError("expected_failures must be an array of strings")
        expected = tuple(ValidationCode(value) for value in expected_raw)
        if len(expected) != len(set(expected)):
            raise ValueError("expected_failures must not contain duplicates")

        evidence_raw = payload.get("evidence")
        if not isinstance(evidence_raw, dict):
            raise ValueError("evidence must be an object")  # noqa: TRY004

        return cls(
            fixture_version=_optional_string(payload, "fixture_version", "0.1"),
            name=_required_string(payload, "name"),
            expected_failures=expected,
            evidence=FalsificationEvidence.from_dict(evidence_raw),
        )


Check = Callable[[FalsificationEvidence], Optional[Finding]]


def falsify(evidence: FalsificationEvidence) -> FalsificationResult:
    """Apply every falsification check in stable, declared order."""

    findings = tuple(
        finding
        for finding in (check(evidence) for check in CHECKS)
        if finding is not None
    )
    return FalsificationResult(task_id=evidence.task_id, findings=findings)


def load_fixture(path: Path) -> FalsificationFixture:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("fixture root must be an object")  # noqa: TRY004
    return FalsificationFixture.from_dict(payload)


def check_fixture(path: Path) -> tuple[FalsificationFixture, FalsificationResult]:
    fixture = load_fixture(path)
    return fixture, falsify(fixture.evidence)


def iter_fixture_paths(directory: Path) -> Iterable[Path]:
    return sorted(path for path in directory.glob("*.json") if path.is_file())


def _base_failure(evidence: FalsificationEvidence) -> Optional[Finding]:
    if evidence.base_fails:
        return None
    return Finding(
        ValidationCode.BASE_NOT_FAILING,
        "The verifier is already green at the base snapshot.",
    )


def _gold_pass(evidence: FalsificationEvidence) -> Optional[Finding]:
    if evidence.gold_passes:
        return None
    return Finding(
        ValidationCode.GOLD_NOT_PASSING,
        "The accepted patch does not pass the verifier.",
    )


def _flake_rate(evidence: FalsificationEvidence) -> Optional[Finding]:
    if evidence.flake_rate == 0.0:
        return None
    return Finding(
        ValidationCode.FLAKY_VERIFIER,
        "Repeated clean runs produced inconsistent verifier outcomes.",
        (f"flake_rate={evidence.flake_rate:.6f}",),
    )


def _oracle_exposure(evidence: FalsificationEvidence) -> Optional[Finding]:
    if not evidence.oracle_artifacts:
        return None
    return Finding(
        ValidationCode.ORACLE_EXPOSED,
        "Oracle or hidden-verifier artifacts are visible to the solver.",
        evidence.oracle_artifacts,
    )


def _history_leak(evidence: FalsificationEvidence) -> Optional[Finding]:
    if not evidence.future_history_accessible:
        return None
    return Finding(
        ValidationCode.HISTORY_LEAK,
        "Future Git history is accessible from the solver snapshot.",
    )


def _verifier_mutability(evidence: FalsificationEvidence) -> Optional[Finding]:
    if not evidence.verifier_writable:
        return None
    return Finding(
        ValidationCode.VERIFIER_MUTABLE,
        "The solver can modify trusted verifier state.",
    )


def _network_policy(evidence: FalsificationEvidence) -> Optional[Finding]:
    if not evidence.network_egress_observed:
        return None
    return Finding(
        ValidationCode.NETWORK_POLICY_FAILURE,
        "Outbound network access succeeded under a deny policy.",
    )


def _grader_tamper_surface(evidence: FalsificationEvidence) -> Optional[Finding]:
    if not evidence.grader_tamper_vectors:
        return None
    return Finding(
        ValidationCode.GRADER_TAMPER_SURFACE,
        "The solver can influence the trusted grading path.",
        evidence.grader_tamper_vectors,
    )


def _spec_test_alignment(evidence: FalsificationEvidence) -> Optional[Finding]:
    hidden_requirements = sorted(
        evidence.verified_requirements - evidence.declared_requirements
    )
    if not hidden_requirements:
        return None
    return Finding(
        ValidationCode.SPEC_TEST_MISMATCH,
        "The verifier enforces requirements absent from the disclosed specification.",
        tuple(hidden_requirements),
    )


def _implementation_independence(
    evidence: FalsificationEvidence,
) -> Optional[Finding]:
    if evidence.rejected_valid_alternatives == 0:
        return None
    return Finding(
        ValidationCode.OVERCONSTRAINED_TEST,
        "A reviewed valid alternative implementation was rejected.",
        (f"rejected_valid_alternatives={evidence.rejected_valid_alternatives}",),
    )


def _test_strength(evidence: FalsificationEvidence) -> Optional[Finding]:
    if evidence.broken_patch_passes == 0:
        return None
    return Finding(
        ValidationCode.UNDERPOWERED_TEST,
        "At least one known-broken patch passed the verifier.",
        (
            f"broken_patch_passes={evidence.broken_patch_passes}",
            f"broken_patch_trials={evidence.broken_patch_trials}",
        ),
    )


def _cache_isolation(evidence: FalsificationEvidence) -> Optional[Finding]:
    if not evidence.cache_leaks:
        return None
    return Finding(
        ValidationCode.CACHE_LEAK,
        "A shared cache exposes cross-run solution or oracle state.",
        evidence.cache_leaks,
    )


CHECKS: tuple[Check, ...] = (
    _base_failure,
    _gold_pass,
    _flake_rate,
    _oracle_exposure,
    _history_leak,
    _verifier_mutability,
    _network_policy,
    _grader_tamper_surface,
    _spec_test_alignment,
    _implementation_independence,
    _test_strength,
    _cache_isolation,
)


def _required_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-blank string")
    return value


def _optional_string(payload: Mapping[str, Any], key: str, default: str) -> str:
    if key not in payload:
        return default
    value = payload[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-blank string")
    return value


def _required_bool(payload: Mapping[str, Any], key: str) -> bool:
    if key not in payload:
        raise ValueError(f"missing required evidence field: {key}")
    value = payload[key]
    if type(value) is not bool:
        raise ValueError(f"{key} must be a boolean")
    return value


def _required_number(payload: Mapping[str, Any], key: str) -> float:
    if key not in payload:
        raise ValueError(f"missing required evidence field: {key}")
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number")  # noqa: TRY004
    return float(value)


def _required_int(payload: Mapping[str, Any], key: str) -> int:
    if key not in payload:
        raise ValueError(f"missing required evidence field: {key}")
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")  # noqa: TRY004
    return value


def _required_strings(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    if key not in payload:
        raise ValueError(f"missing required evidence field: {key}")
    value = payload[key]
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{key} must be an array of non-blank strings")
    return tuple(value)
