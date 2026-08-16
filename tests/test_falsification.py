import io
import sys
import unittest
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from reposeal import (
    FalsificationEvidence,
    ValidationCode,
    check_fixture,
)
from reposeal.__main__ import main
from reposeal.falsification import iter_fixture_paths

FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "falsification"


def make_valid_evidence(**overrides: object) -> FalsificationEvidence:
    values = {
        "task_id": "example",
        "base_fails": True,
        "gold_passes": True,
        "flake_rate": 0.0,
        "oracle_artifacts": (),
        "future_history_accessible": False,
        "verifier_writable": False,
        "network_egress_observed": False,
        "grader_tamper_vectors": (),
        "declared_requirements": frozenset(),
        "verified_requirements": frozenset(),
        "rejected_valid_alternatives": 0,
        "broken_patch_passes": 0,
        "broken_patch_trials": 0,
        "cache_leaks": (),
    }
    values.update(overrides)
    return FalsificationEvidence(**values)


class FalsificationFixtureTests(unittest.TestCase):
    def test_every_fixture_produces_exactly_the_expected_failures(self) -> None:
        paths = tuple(iter_fixture_paths(FIXTURE_DIRECTORY))

        self.assertEqual(len(paths), 13)
        for path in paths:
            with self.subTest(fixture=path.name):
                fixture, result = check_fixture(path)
                self.assertEqual(result.codes, fixture.expected_failures)

    def test_fixture_suite_covers_every_validation_code_once(self) -> None:
        expected_codes = Counter()
        for path in iter_fixture_paths(FIXTURE_DIRECTORY):
            fixture, _ = check_fixture(path)
            expected_codes.update(fixture.expected_failures)

        self.assertEqual(set(expected_codes), set(ValidationCode))
        self.assertTrue(all(count == 1 for count in expected_codes.values()))

    def test_valid_control_passes_without_findings(self) -> None:
        _, result = check_fixture(FIXTURE_DIRECTORY / "00-valid-control.json")

        self.assertTrue(result.passed)
        self.assertEqual(result.findings, ())

    def test_cli_confirms_the_complete_fixture_directory(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = main(["check-fixtures", str(FIXTURE_DIRECTORY)])

        self.assertEqual(exit_code, 0)
        self.assertIn('"fixture_count": 13', output.getvalue())
        self.assertIn('"passed": true', output.getvalue())


class EvidenceParsingTests(unittest.TestCase):
    def test_unknown_fields_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown evidence fields"):
            FalsificationEvidence.from_dict(
                {"task_id": "example", "unreviewed_claim": True}
            )

    def test_boolean_strings_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "base_fails must be a boolean"):
            FalsificationEvidence.from_dict(
                {"task_id": "example", "base_fails": "false"}
            )

    def test_missing_observations_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing required evidence field"):
            FalsificationEvidence.from_dict({"task_id": "example"})

    def test_broken_passes_cannot_exceed_trials(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            make_valid_evidence(
                broken_patch_passes=2,
                broken_patch_trials=1,
            )


if __name__ == "__main__":
    unittest.main()
