import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from benchseal.__main__ import main
from benchseal.evidence import MAX_EVIDENCE_BYTES, validate_evidence_file

EXAMPLE_EVIDENCE = Path(__file__).parents[1] / "examples" / "evidence.json"


class TaskEvidenceReportTests(unittest.TestCase):
    def test_valid_example_is_eligible_and_deterministic(self) -> None:
        first = validate_evidence_file(EXAMPLE_EVIDENCE)
        second = validate_evidence_file(EXAMPLE_EVIDENCE)

        self.assertEqual(first, second)
        self.assertEqual(first.decision, "ELIGIBLE")
        self.assertEqual(first.checks_evaluated, 12)
        self.assertEqual(first.findings, ())
        self.assertEqual(first.to_dict()["tool_version"], "0.8.0")
        self.assertIn("No blocking findings", first.to_text())

    def test_failing_evidence_is_held_with_a_clear_reason(self) -> None:
        payload = json.loads(EXAMPLE_EVIDENCE.read_text(encoding="utf-8"))
        payload["base_fails"] = False
        with tempfile.TemporaryDirectory(prefix="benchseal-evidence-") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            report = validate_evidence_file(path)

        self.assertEqual(report.decision, "HOLD")
        self.assertEqual(
            [finding.code.value for finding in report.findings],
            ["BASE_NOT_FAILING"],
        )
        self.assertIn("verifier is already green", report.to_text())

    def test_duplicate_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-evidence-") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text('{"task_id":"first","task_id":"second"}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON field: task_id"):
                validate_evidence_file(path)

    def test_oversized_evidence_is_rejected_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-evidence-") as directory:
            path = Path(directory) / "evidence.json"
            path.write_bytes(b" " * (MAX_EVIDENCE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "exceeds 1 MiB"):
                validate_evidence_file(path)

    def test_symlink_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-evidence-") as directory:
            link = Path(directory) / "evidence-link.json"
            try:
                link.symlink_to(EXAMPLE_EVIDENCE)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                validate_evidence_file(link)

    def test_human_report_escapes_untrusted_control_characters(self) -> None:
        payload = json.loads(EXAMPLE_EVIDENCE.read_text(encoding="utf-8"))
        payload["task_id"] = "example\nforged-line"
        payload["oracle_artifacts"] = ["\u001b[31mhidden-answer"]
        with tempfile.TemporaryDirectory(prefix="benchseal-evidence-") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            rendered = validate_evidence_file(path).to_text()

        self.assertNotIn("example\nforged-line", rendered)
        self.assertNotIn("\u001b", rendered)
        self.assertIn(r"example\nforged-line", rendered)
        self.assertIn(r"\u001b[31mhidden-answer", rendered)


class ValidateCommandTests(unittest.TestCase):
    def test_human_output_is_the_default(self) -> None:
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(["validate", str(EXAMPLE_EVIDENCE)])

        self.assertEqual(exit_code, 0)
        self.assertIn("BenchSeal task evidence report", output.getvalue())
        self.assertIn("Decision: ELIGIBLE", output.getvalue())

    def test_json_output_can_be_saved_as_a_receipt(self) -> None:
        output = StringIO()
        with tempfile.TemporaryDirectory(prefix="benchseal-cli-") as directory:
            receipt = Path(directory) / "receipt.json"
            with redirect_stdout(output):
                exit_code = main(
                    [
                        "validate",
                        str(EXAMPLE_EVIDENCE),
                        "--json",
                        "--output",
                        str(receipt),
                    ]
                )
            saved = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue()), saved)
        self.assertEqual(saved["decision"], "ELIGIBLE")

    def test_invalid_input_uses_exit_code_two(self) -> None:
        errors = StringIO()
        with tempfile.TemporaryDirectory(prefix="benchseal-cli-") as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("[]", encoding="utf-8")
            with redirect_stderr(errors):
                exit_code = main(["validate", str(path)])

        self.assertEqual(exit_code, 2)
        self.assertIn("must be a JSON object", errors.getvalue())

    def test_blocking_finding_uses_exit_code_one(self) -> None:
        payload = json.loads(EXAMPLE_EVIDENCE.read_text(encoding="utf-8"))
        payload["gold_passes"] = False
        output = StringIO()
        with tempfile.TemporaryDirectory(prefix="benchseal-cli-") as directory:
            path = Path(directory) / "held.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with redirect_stdout(output):
                exit_code = main(["validate", str(path)])

        self.assertEqual(exit_code, 1)
        self.assertIn("Decision: HOLD", output.getvalue())
        self.assertIn("GOLD_NOT_PASSING", output.getvalue())


if __name__ == "__main__":
    unittest.main()
