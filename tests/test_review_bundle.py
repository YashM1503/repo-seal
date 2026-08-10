import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from repolab_reference.review_bundle import (
    REVIEW_SCOPE_PATHS,
    create_security_review_bundle,
)


class SecurityReviewBundleTests(unittest.TestCase):
    def test_two_handoffs_are_deterministic_and_keep_the_gate_closed(self) -> None:
        repository = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory(prefix="repolab-review-") as directory:
            root = Path(directory)
            first = create_security_review_bundle(repository, root / "first")
            second = create_security_review_bundle(repository, root / "second")
            manifest = json.loads((root / "first" / "manifest.json").read_text())

        self.assertEqual(first, second)
        self.assertEqual(first.receipt_sha256, second.receipt_sha256)
        self.assertEqual(tuple(item.path for item in first.files), REVIEW_SCOPE_PATHS)
        self.assertEqual(manifest["independent_review_status"], "NOT_PERFORMED")
        self.assertFalse(manifest["security_gate_passed"])
        self.assertFalse(manifest["safe_for_real_agents"])
        self.assertNotIn(str(root), first.to_json())

    def test_existing_or_in_repository_output_is_rejected(self) -> None:
        repository = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory(prefix="repolab-review-") as directory:
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
