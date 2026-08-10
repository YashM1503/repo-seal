import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from repolab_reference import (  # noqa: E402
    ReplayTask,
    SnapshotSecurityError,
    build_controlled_repository,
    replay_suite,
    tree_sha256,
    write_trusted_verifier,
)
from repolab_reference.replay import UNMEASURED_M1_CHECKS  # noqa: E402


EXPECTED_SUITE_SHA256 = (
    "sha256:b5b4095dc4c632fff2ea39322940056b61e3adab8f6c088d19e34c695a9b3401"
)


class ControlledReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="repolab-replay-")
        cls.root = Path(cls.temporary.name)
        cls.controlled = build_controlled_repository(cls.root / "repository")
        cls.verifier = write_trusted_verifier(
            cls.root / "trusted-source" / "trusted_verifier.py"
        )
        cls.first = replay_suite(
            cls.controlled.path,
            cls.controlled.tasks,
            cls.verifier,
            cls.root / "run-a",
        )
        cls.second = replay_suite(
            cls.controlled.path,
            cls.controlled.tasks,
            cls.verifier,
            cls.root / "run-b",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_ten_tasks_pass_the_replay_gate(self) -> None:
        self.assertEqual(len(self.first.receipts), 10)
        self.assertTrue(self.first.gate_passed)
        for receipt in self.first.receipts:
            with self.subTest(task=receipt.task.task_id):
                self.assertTrue(receipt.base_fails)
                self.assertTrue(receipt.gold_passes)
                self.assertTrue(receipt.stable)
                self.assertTrue(receipt.gate_passed)

    def test_two_fresh_replays_have_identical_receipts(self) -> None:
        self.assertEqual(self.first.to_dict(), self.second.to_dict())
        self.assertEqual(self.first.suite_sha256, self.second.suite_sha256)
        self.assertEqual(self.first.suite_sha256, EXPECTED_SUITE_SHA256)

    def test_snapshot_chain_matches_the_commit_chain(self) -> None:
        receipts = self.first.receipts
        for current, following in zip(receipts, receipts[1:]):
            with self.subTest(task=current.task.task_id):
                self.assertEqual(
                    current.gold_snapshot_sha256,
                    following.base_snapshot_sha256,
                )

    def test_candidate_workspaces_contain_no_git_or_verifier_material(self) -> None:
        for receipt in self.first.receipts:
            task_root = self.root / "run-a" / receipt.task.task_id
            for workspace_name in ("candidate-base", "candidate-gold"):
                workspace = task_root / workspace_name
                names = {path.name for path in workspace.rglob("*")}
                self.assertNotIn(".git", names)
                self.assertNotIn("trusted_verifier.py", names)
                self.assertEqual(names, {"toycalc.py"})

    def test_unmeasured_checks_are_explicit(self) -> None:
        for receipt in self.first.receipts:
            self.assertEqual(receipt.unmeasured_checks, UNMEASURED_M1_CHECKS)

    def test_receipt_contains_no_temporary_paths(self) -> None:
        rendered = self.first.to_json()

        self.assertNotIn(str(self.root), rendered)
        self.assertEqual(json.loads(rendered)["task_count"], 10)

    def test_controlled_history_has_initial_commit_plus_ten_fixes(self) -> None:
        completed = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=self.controlled.path,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(completed.stdout.strip(), "11")


class SnapshotSafetyTests(unittest.TestCase):
    def test_replay_task_rejects_path_traversal_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "path component"):
            ReplayTask(
                task_id="../escape",
                statement="Unsafe task ID.",
                base_commit="a" * 40,
                gold_commit="b" * 40,
            )

    def test_replay_task_requires_full_object_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "object ID"):
            ReplayTask(
                task_id="safe-id",
                statement="Reject option-like revisions.",
                base_commit="--help",
                gold_commit="b" * 40,
            )

    def test_tree_digest_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="repolab-symlink-") as directory:
            root = Path(directory)
            outside = root / "outside.txt"
            outside.write_text("oracle", encoding="utf-8")
            snapshot = root / "snapshot"
            snapshot.mkdir()
            os.symlink(outside, snapshot / "leak.txt")

            with self.assertRaisesRegex(SnapshotSecurityError, "symlink"):
                tree_sha256(snapshot)


if __name__ == "__main__":
    unittest.main()
