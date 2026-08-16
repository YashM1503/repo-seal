import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from reposeal import (
    DecisionReceipt,
    EnvironmentPolicy,
    TaskManifest,
    TaskQualityRecord,
    ValidationCode,
)

DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


class TaskManifestTests(unittest.TestCase):
    def test_serializes_a_valid_manifest(self) -> None:
        task = TaskManifest(
            task_id="example-001",
            base_commit="abc123",
            snapshot_sha256=DIGEST_A,
            statement="Fix the deterministic example.",
            environment=EnvironmentPolicy(image_digest=DIGEST_B),
            verifier_sha256=DIGEST_A,
        )

        payload = json.loads(task.to_json())

        self.assertEqual(payload["task_id"], "example-001")
        self.assertEqual(payload["environment"]["network"], "deny")

    def test_rejects_an_unpinned_environment(self) -> None:
        with self.assertRaisesRegex(ValueError, "image_digest"):
            EnvironmentPolicy(image_digest="latest")


class QualityRecordTests(unittest.TestCase):
    def test_eligible_requires_every_hard_gate(self) -> None:
        quality = TaskQualityRecord(
            task_id="example-001",
            reproducible=True,
            base_fail=True,
            gold_pass=True,
            flake_rate=0.0,
            prompt_sufficiency="reviewed",
            leakage_scan="pass",
            environment_completeness="pass",
            confidence=0.86,
        )

        self.assertTrue(quality.eligible)

    def test_failure_code_holds_the_task(self) -> None:
        quality = TaskQualityRecord(
            task_id="example-001",
            reproducible=True,
            base_fail=True,
            gold_pass=True,
            flake_rate=0.0,
            prompt_sufficiency="reviewed",
            leakage_scan="fail",
            environment_completeness="pass",
            confidence=0.99,
            failures=(ValidationCode.HISTORY_LEAK,),
        )

        self.assertFalse(quality.eligible)


class DecisionReceiptTests(unittest.TestCase):
    def test_rejects_an_inverted_interval(self) -> None:
        with self.assertRaisesRegex(ValueError, "ordered"):
            DecisionReceipt(
                baseline="A",
                candidate="B",
                task_set_sha256=DIGEST_A,
                verifier_sha256=DIGEST_B,
                primary_metric="verified_success",
                baseline_score=0.72,
                candidate_score=0.79,
                paired_effect=0.07,
                confidence_interval=(0.10, 0.01),
                regressions=0,
                holdout_status="pass",
                verdict="PROMOTE",
            )


if __name__ == "__main__":
    unittest.main()
