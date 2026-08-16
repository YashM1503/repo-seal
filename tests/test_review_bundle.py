import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from benchseal.review_bundle import (
    REVIEW_SCOPE_PATHS,
    create_security_review_bundle,
)


class SecurityReviewBundleTests(unittest.TestCase):
    def _committed_repository(self, destination: Path) -> tuple[Path, str]:
        source = Path(__file__).parents[1]
        repository = destination / "repository"
        for relative in REVIEW_SCOPE_PATHS:
            target = repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, target)

        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_AUTHOR_NAME": "BenchSeal Fixture",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "BenchSeal Fixture",
            }
        )
        subprocess.run(
            ["git", "init", "--quiet"], cwd=repository, check=True, env=environment
        )
        subprocess.run(
            ["git", "add", "--all"], cwd=repository, check=True, env=environment
        )
        subprocess.run(
            [
                "git",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "review fixture",
            ],
            cwd=repository,
            check=True,
            env=environment,
        )
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        return repository, completed.stdout.strip()

    def test_two_handoffs_are_deterministic_and_keep_the_gate_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-review-") as directory:
            root = Path(directory)
            repository, commit_oid = self._committed_repository(root)
            first = create_security_review_bundle(repository, root / "first")
            second = create_security_review_bundle(repository, root / "second")
            manifest = json.loads((root / "first" / "manifest.json").read_text())

        self.assertEqual(first, second)
        self.assertEqual(first.receipt_sha256, second.receipt_sha256)
        self.assertEqual(tuple(item.path for item in first.files), REVIEW_SCOPE_PATHS)
        self.assertEqual(manifest["bundle_version"], "0.2")
        self.assertEqual(manifest["git_commit_oid"], commit_oid)
        expected_format = "sha1" if len(commit_oid) == 40 else "sha256"
        self.assertEqual(manifest["git_object_format"], expected_format)
        self.assertTrue(manifest["git_worktree_clean"])
        self.assertEqual(manifest["independent_review_status"], "NOT_PERFORMED")
        self.assertFalse(manifest["security_gate_passed"])
        self.assertFalse(manifest["safe_for_real_agents"])
        self.assertNotIn(str(root), first.to_json())

    def test_receipt_changes_for_a_new_commit_with_the_same_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-review-") as directory:
            root = Path(directory)
            repository, first_commit = self._committed_repository(root)
            first = create_security_review_bundle(repository, root / "first")
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_AUTHOR_DATE": "2000-01-01T00:00:01+0000",
                    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_AUTHOR_NAME": "BenchSeal Fixture",
                    "GIT_COMMITTER_DATE": "2000-01-01T00:00:01+0000",
                    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "BenchSeal Fixture",
                }
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "--quiet",
                    "--no-gpg-sign",
                    "--allow-empty",
                    "-m",
                    "new review commit",
                ],
                cwd=repository,
                check=True,
                env=environment,
            )
            second = create_security_review_bundle(repository, root / "second")

        self.assertNotEqual(first.git_commit_oid, second.git_commit_oid)
        self.assertEqual(first.git_commit_oid, first_commit)
        self.assertEqual(first.scope_sha256, second.scope_sha256)
        self.assertNotEqual(first.receipt_sha256, second.receipt_sha256)

    def test_dirty_repository_is_rejected_without_writing_output(self) -> None:
        for scenario in ("tracked", "untracked"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="benchseal-review-"
            ) as directory:
                root = Path(directory)
                repository, _ = self._committed_repository(root)
                if scenario == "tracked":
                    readme = repository / "README.md"
                    readme.write_text(
                        readme.read_text() + "\nchanged\n", encoding="utf-8"
                    )
                else:
                    (repository / "unexpected.txt").write_text(
                        "untracked\n", encoding="utf-8"
                    )
                output = root / "bundle"

                with self.assertRaisesRegex(ValueError, "worktree must be clean"):
                    create_security_review_bundle(repository, output)

                self.assertFalse(output.exists())

    def test_repository_root_must_be_the_worktree_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-review-") as directory:
            root = Path(directory)
            repository, _ = self._committed_repository(root)
            with self.assertRaisesRegex(ValueError, "worktree root"):
                create_security_review_bundle(repository / "docs", root / "bundle")

    def test_existing_or_in_repository_output_is_rejected(self) -> None:
        repository = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory(prefix="benchseal-review-") as directory:
            existing = Path(directory)
            with self.assertRaisesRegex(ValueError, "must not already exist"):
                create_security_review_bundle(repository, existing)

        with self.assertRaisesRegex(ValueError, "outside repository_root"):
            create_security_review_bundle(
                repository,
                repository / "untracked-review-output",
            )


if __name__ == "__main__":
    unittest.main()
