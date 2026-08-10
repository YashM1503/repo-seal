"""Reference primitives for repository-derived coding-agent evaluations."""

from .schemas import (
    AgentConfiguration,
    DecisionReceipt,
    EnvironmentPolicy,
    TaskManifest,
    TaskQualityRecord,
    ValidationCode,
)
from .falsification import (
    FalsificationEvidence,
    FalsificationFixture,
    FalsificationResult,
    Finding,
    check_fixture,
    falsify,
    load_fixture,
)

__all__ = [
    "AgentConfiguration",
    "DecisionReceipt",
    "EnvironmentPolicy",
    "FalsificationEvidence",
    "FalsificationFixture",
    "FalsificationResult",
    "Finding",
    "TaskManifest",
    "TaskQualityRecord",
    "ValidationCode",
    "check_fixture",
    "falsify",
    "load_fixture",
]

__version__ = "0.1.0"
