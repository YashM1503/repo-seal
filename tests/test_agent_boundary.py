import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from benchseal.agent_boundary import (
    AgentBoundaryError,
    PatchValidationError,
    apply_patch_artifact,
    capture_request,
    parse_patch_artifact,
    validate_patch_artifact,
)
from benchseal.controlled import (
    build_controlled_repository,
    write_trusted_verifier,
)
from benchseal.controlled_agent import (
    UNIMPLEMENTED_M2A_CONTROLS,
    UNMEASURED_M2A_CHECKS,
    replay_controlled_agent_suite,
)
from benchseal.replay import SnapshotSecurityError

EXPECTED_M2A_SUITE_SHA256 = (
    "sha256:6a572de985a009a83257cd91c6f02ae363b3f35e36c2ffe9e2c5224c120367b5"
)


class ControlledAgentReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="benchseal-agent-")
        cls.root = Path(cls.temporary.name)
        cls.controlled = build_controlled_repository(cls.root / "repository")
        cls.verifier = write_trusted_verifier(cls.root / "source" / "verifier.py")
        cls.first = replay_controlled_agent_suite(
            cls.controlled.path,
            cls.controlled.tasks,
            cls.verifier,
            cls.root / "run-a",
        )
        cls.second = replay_controlled_agent_suite(
            cls.controlled.path,
            cls.controlled.tasks,
            cls.verifier,
            cls.root / "run-b",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_ten_mock_agent_tasks_pass_only_the_contract_gate(self) -> None:
        self.assertEqual(len(self.first.receipts), 10)
        self.assertTrue(self.first.contract_gate_passed)
        self.assertFalse(self.first.security_gate_passed)
        for receipt in self.first.receipts:
            with self.subTest(task=receipt.task.task_id):
                self.assertTrue(receipt.verifier_passes)
                self.assertTrue(receipt.stable)
                self.assertTrue(receipt.contract_gate_passed)
                self.assertFalse(receipt.security_gate_passed)
                self.assertEqual(receipt.changed_paths, ("toycalc.py",))

    def test_two_fresh_agent_replays_have_identical_receipts(self) -> None:
        self.assertEqual(self.first.to_dict(), self.second.to_dict())
        self.assertEqual(self.first.suite_sha256, self.second.suite_sha256)
        self.assertEqual(self.first.suite_sha256, EXPECTED_M2A_SUITE_SHA256)

    def test_receipts_disclose_unimplemented_security_controls(self) -> None:
        for receipt in self.first.receipts:
            with self.subTest(task=receipt.task.task_id):
                self.assertEqual(receipt.unmeasured_checks, UNMEASURED_M2A_CHECKS)
                self.assertEqual(
                    receipt.unimplemented_controls, UNIMPLEMENTED_M2A_CONTROLS
                )
                self.assertTrue(receipt.parent_environment_replaced)
                self.assertTrue(receipt.task_verifier_copy_staged_after_adapter)

    def test_candidate_contains_no_history_verifier_or_adapter(self) -> None:
        for receipt in self.first.receipts:
            candidate = self.root / "run-a" / receipt.task.task_id / "candidate"
            names = {path.name for path in candidate.rglob("*")}
            self.assertEqual(names, {"toycalc.py"})

    def test_receipt_contains_no_temporary_paths_or_patch_contents(self) -> None:
        rendered = self.first.to_json()

        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("return left + right", rendered)
        self.assertFalse(json.loads(rendered)["safe_for_real_agents"])


class PatchArtifactSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchseal-patch-")
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "toycalc.py").write_text(
            "def add(left, right):\n    return left - right\n", encoding="utf-8"
        )
        self.request = capture_request(
            self.workspace,
            "toy-01-add",
            "Make add return the arithmetic sum of both arguments.",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact_payload(self, **overrides):
        source = self.request.files[0]
        payload = {
            "artifact_version": "0.1",
            "adapter_id": "test-adapter/0.1",
            "task_id": self.request.task_id,
            "base_snapshot_sha256": self.request.base_snapshot_sha256,
            "replacements": [
                {
                    "path": source.path,
                    "expected_sha256": source.sha256,
                    "content_utf8": "def add(left, right):\n    return left + right\n",
                }
            ],
        }
        payload.update(overrides)
        return payload

    def parse(self, payload=None, **limits):
        selected = payload if payload is not None else self.artifact_payload()
        return parse_patch_artifact(
            json.dumps(selected, sort_keys=True).encode("utf-8"), **limits
        )

    def test_valid_replacement_is_applied(self) -> None:
        changed = apply_patch_artifact(
            self.request,
            self.parse(),
            self.workspace,
            allowed_paths=("toycalc.py",),
        )

        self.assertEqual(changed, ("toycalc.py",))
        self.assertIn(
            "return left + right", (self.workspace / "toycalc.py").read_text()
        )

    def test_path_traversal_and_git_paths_are_rejected(self) -> None:
        for unsafe_path in ("../escape.py", ".git/config", "nested/../../escape"):
            payload = self.artifact_payload()
            payload["replacements"][0]["path"] = unsafe_path
            with (
                self.subTest(path=unsafe_path),
                self.assertRaisesRegex(PatchValidationError, "unsafe artifact path"),
            ):
                self.parse(payload)

    def test_unknown_schema_fields_are_rejected(self) -> None:
        payload = self.artifact_payload(unrequested_capability="network")

        with self.assertRaisesRegex(PatchValidationError, "unexpected"):
            self.parse(payload)

    def test_duplicate_json_fields_are_rejected(self) -> None:
        raw = json.dumps(self.artifact_payload(), sort_keys=True).encode("utf-8")
        duplicate = raw[:-1] + b',"task_id":"toy-02-clamp"}'

        with self.assertRaisesRegex(PatchValidationError, "duplicate JSON field"):
            parse_patch_artifact(duplicate)

    def test_wrong_task_snapshot_and_digest_are_rejected(self) -> None:
        wrong_task = self.parse(self.artifact_payload(task_id="toy-02-clamp"))
        with self.assertRaisesRegex(PatchValidationError, "task_id"):
            validate_patch_artifact(
                self.request,
                wrong_task,
                self.workspace,
                allowed_paths=("toycalc.py",),
            )

        wrong_snapshot = self.parse(
            self.artifact_payload(base_snapshot_sha256="sha256:" + "0" * 64)
        )
        with self.assertRaisesRegex(PatchValidationError, "base snapshot"):
            validate_patch_artifact(
                self.request,
                wrong_snapshot,
                self.workspace,
                allowed_paths=("toycalc.py",),
            )

        payload = self.artifact_payload()
        payload["replacements"][0]["expected_sha256"] = "sha256:" + "0" * 64
        wrong_digest = self.parse(payload)
        with self.assertRaisesRegex(PatchValidationError, "digest"):
            validate_patch_artifact(
                self.request,
                wrong_digest,
                self.workspace,
                allowed_paths=("toycalc.py",),
            )

    def test_workspace_mutation_and_symlink_swap_are_rejected(self) -> None:
        (self.workspace / "toycalc.py").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(PatchValidationError, "workspace changed"):
            validate_patch_artifact(
                self.request,
                self.parse(),
                self.workspace,
                allowed_paths=("toycalc.py",),
            )

        (self.workspace / "toycalc.py").unlink()
        outside = self.root / "outside.py"
        outside.write_text("secret\n", encoding="utf-8")
        os.symlink(outside, self.workspace / "toycalc.py")
        with self.assertRaises(SnapshotSecurityError):
            validate_patch_artifact(
                self.request,
                self.parse(),
                self.workspace,
                allowed_paths=("toycalc.py",),
            )

    def test_no_op_and_disallowed_paths_are_rejected(self) -> None:
        payload = self.artifact_payload()
        payload["replacements"][0]["content_utf8"] = self.request.files[0].content_utf8
        with self.assertRaisesRegex(PatchValidationError, "no-op"):
            validate_patch_artifact(
                self.request,
                self.parse(payload),
                self.workspace,
                allowed_paths=("toycalc.py",),
            )

        with self.assertRaisesRegex(PatchValidationError, "not allowed"):
            validate_patch_artifact(
                self.request,
                self.parse(),
                self.workspace,
                allowed_paths=("other.py",),
            )

    def test_oversized_artifacts_are_rejected_before_json_parsing(self) -> None:
        raw = json.dumps(self.artifact_payload()).encode("utf-8")

        with self.assertRaisesRegex(PatchValidationError, "byte limit"):
            parse_patch_artifact(raw, max_artifact_bytes=len(raw) - 1)

    def test_request_size_and_file_count_are_bounded(self) -> None:
        with self.assertRaisesRegex(AgentBoundaryError, "request.*byte limit"):
            capture_request(
                self.workspace,
                self.request.task_id,
                self.request.statement,
                max_request_bytes=16,
            )

        (self.workspace / "second.py").write_text("value = 1\n", encoding="utf-8")
        with self.assertRaisesRegex(AgentBoundaryError, "file count"):
            capture_request(
                self.workspace,
                self.request.task_id,
                self.request.statement,
                max_source_files=1,
            )


if __name__ == "__main__":
    unittest.main()
