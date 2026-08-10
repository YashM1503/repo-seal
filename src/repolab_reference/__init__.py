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
from .controlled import (
    ControlledRepository,
    ControlledTaskDefinition,
    TASK_DEFINITIONS,
    build_controlled_repository,
    write_trusted_verifier,
)
from .replay import (
    ReplayError,
    ReplayReceipt,
    ReplaySuiteReceipt,
    ReplayTask,
    SnapshotSecurityError,
    VerificationRun,
    replay_suite,
    replay_task,
    snapshot_commit,
    tree_sha256,
)

__all__ = [
    "AgentConfiguration",
    "ControlledRepository",
    "ControlledTaskDefinition",
    "DecisionReceipt",
    "EnvironmentPolicy",
    "FalsificationEvidence",
    "FalsificationFixture",
    "FalsificationResult",
    "Finding",
    "ReplayError",
    "ReplayReceipt",
    "ReplaySuiteReceipt",
    "ReplayTask",
    "SnapshotSecurityError",
    "TASK_DEFINITIONS",
    "TaskManifest",
    "TaskQualityRecord",
    "ValidationCode",
    "VerificationRun",
    "build_controlled_repository",
    "check_fixture",
    "falsify",
    "load_fixture",
    "replay_suite",
    "replay_task",
    "snapshot_commit",
    "tree_sha256",
    "write_trusted_verifier",
]

__version__ = "0.2.0"
