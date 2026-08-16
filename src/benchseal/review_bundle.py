"""Deterministic handoff bundle for an independent M2b security review."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .docker_backend import DockerIsolationPolicy, docker_isolation_plan
from .replay import file_sha256

REVIEW_SCOPE_PATHS: tuple[str, ...] = (
    ".github/workflows/ci.yml",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
    "docs/adr/0002-benchseal-mvp.md",
    "docs/m2b-docker-backend.md",
    "docs/m2b-isolation-preflight.md",
    "docs/security/m2b-internal-review-2026-08-10.md",
    "examples/evidence.json",
    "pyproject.toml",
    "src/benchseal/__init__.py",
    "src/benchseal/__main__.py",
    "src/benchseal/agent_boundary.py",
    "src/benchseal/controlled.py",
    "src/benchseal/controlled_agent.py",
    "src/benchseal/docker_backend.py",
    "src/benchseal/evidence.py",
    "src/benchseal/falsification.py",
    "src/benchseal/isolation.py",
    "src/benchseal/isolation_probe.py",
    "src/benchseal/mock_agent.py",
    "src/benchseal/replay.py",
    "src/benchseal/review_bundle.py",
    "src/benchseal/schemas.py",
    "src/benchseal/version.py",
    "tests/test_agent_boundary.py",
    "tests/test_docker_backend.py",
    "tests/test_evidence.py",
    "tests/test_falsification.py",
    "tests/test_isolation.py",
    "tests/test_replay.py",
    "tests/test_review_bundle.py",
    "tests/test_schemas.py",
)

REVIEW_CHECKLIST = """# Independent M2b security review checklist

This checklist is a handoff aid, not a review result.

- Confirm `git_commit_oid` is the candidate commit and the reviewed checkout is clean at that commit.
- Confirm every file digest in `manifest.json` against the reviewed checkout.
- Reproduce the policy and normalized command-template digests.
- Assess Docker daemon, local Unix socket, CLI binary, kernel, and image trust.
- Inspect every namespace, capability, seccomp, identity, resource, mount, and environment control.
- Confirm the probe measures runtime state rather than trusting command flags alone.
- Exercise timeout, streaming-output, cleanup, export, symlink, hard-link, and path-race failures.
- Verify that no Git history, verifier, credential broker, host socket, or foreign cache is mounted.
- Review image provenance, declared volumes, package inventory, and known vulnerabilities.
- Review CI evidence on each supported architecture and engine version.
- Record reviewer identity, organization, date, commit, scope digest, findings, and residual risks outside this bundle.
- Do not change `INDEPENDENT_REVIEW`, `security_gate_passed`, or `safe_for_real_agents` without a separately authenticated review decision.
"""


@dataclass(frozen=True)
class ReviewedFile:
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
class SecurityReviewBundleReceipt:
    files: tuple[ReviewedFile, ...]
    git_commit_oid: str
    git_object_format: str
    policy_sha256: str
    command_template_sha256: str
    checklist_sha256: str
    bundle_version: str = "0.2"

    @property
    def scope_sha256(self) -> str:
        return _json_digest({"files": [item.to_dict() for item in self.files]})

    @property
    def receipt_sha256(self) -> str:
        return _json_digest(self._core_dict())

    @property
    def independent_review_status(self) -> str:
        return "NOT_PERFORMED"

    @property
    def security_gate_passed(self) -> bool:
        return False

    @property
    def safe_for_real_agents(self) -> bool:
        return False

    def _core_dict(self) -> dict[str, Any]:
        return {
            "bundle_version": self.bundle_version,
            "review_scope": "m2b-docker-controlled-probe/0.2",
            "git_commit_oid": self.git_commit_oid,
            "git_object_format": self.git_object_format,
            "git_worktree_clean": True,
            "files": [item.to_dict() for item in self.files],
            "scope_sha256": self.scope_sha256,
            "policy_sha256": self.policy_sha256,
            "command_template_sha256": self.command_template_sha256,
            "checklist_sha256": self.checklist_sha256,
            "independent_review_status": self.independent_review_status,
            "security_gate_passed": self.security_gate_passed,
            "safe_for_real_agents": self.safe_for_real_agents,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._core_dict()
        payload["receipt_sha256"] = self.receipt_sha256
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def create_security_review_bundle(
    repository_root: Path,
    output_directory: Path,
) -> SecurityReviewBundleReceipt:
    root = repository_root.resolve()
    output = output_directory.resolve()
    if not root.is_dir():
        raise ValueError("repository_root must be a directory")
    if output_directory.exists():
        raise ValueError("output_directory must not already exist")
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("output_directory must be outside repository_root")

    git_commit_oid, git_object_format = _clean_git_source_state(root)
    reviewed_files = tuple(
        _reviewed_file(root, relative) for relative in REVIEW_SCOPE_PATHS
    )
    if _clean_git_source_state(root) != (git_commit_oid, git_object_format):
        raise ValueError("repository changed while generating the review bundle")
    policy = DockerIsolationPolicy()
    plan = docker_isolation_plan(policy)
    checklist_sha256 = _bytes_sha256(REVIEW_CHECKLIST.encode("utf-8"))
    receipt = SecurityReviewBundleReceipt(
        files=reviewed_files,
        git_commit_oid=git_commit_oid,
        git_object_format=git_object_format,
        policy_sha256=policy.policy_sha256,
        command_template_sha256=plan.command_template_sha256,
        checklist_sha256=checklist_sha256,
    )

    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    manifest = output / "manifest.json"
    checklist = output / "review-checklist.md"
    manifest.write_text(receipt.to_json() + "\n", encoding="utf-8")
    checklist.write_text(REVIEW_CHECKLIST, encoding="utf-8")
    manifest.chmod(0o600)
    checklist.chmod(0o600)
    return receipt


def _clean_git_source_state(root: Path) -> tuple[str, str]:
    candidate = shutil.which("git")
    if candidate is None:
        raise ValueError("git executable is unavailable")
    try:
        git = Path(candidate).resolve(strict=True)
        metadata = git.stat()
    except OSError as error:
        raise ValueError("git executable is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("git executable must be a regular file")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("git executable must not be group- or world-writable")

    top_level = Path(
        _run_git(git, root, "rev-parse", "--show-toplevel").strip()
    ).resolve()
    if top_level != root:
        raise ValueError("repository_root must be the Git worktree root")

    commit_oid = _run_git(
        git, root, "rev-parse", "--verify", "HEAD^{commit}"
    ).strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit_oid):
        object_format = "sha1"
    elif re.fullmatch(r"[0-9a-f]{64}", commit_oid):
        object_format = "sha256"
    else:
        raise ValueError("Git returned an invalid commit object ID")

    status_output = _run_git(
        git,
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status_output:
        raise ValueError(
            "repository worktree must be clean before generating a review bundle"
        )
    return commit_oid, object_format


def _run_git(git: Path, root: Path, *arguments: str) -> str:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    completed = subprocess.run(
        [
            str(git),
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.hooksPath=/dev/null",
            *arguments,
        ],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip()
        raise ValueError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout


def _reviewed_file(root: Path, relative: str) -> ReviewedFile:
    path = root / relative
    if path.is_symlink():
        raise ValueError(f"review scope path must not be a symlink: {relative}")
    try:
        metadata = path.stat()
    except OSError as error:
        raise ValueError(f"review scope path is unavailable: {relative}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"review scope path must be a regular file: {relative}")
    if metadata.st_size > 1024 * 1024:
        raise ValueError(f"review scope path exceeds 1 MiB: {relative}")
    return ReviewedFile(
        path=relative,
        sha256=file_sha256(path),
        size_bytes=metadata.st_size,
    )


def _bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return _bytes_sha256(encoded)
