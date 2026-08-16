import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from benchseal.__main__ import main
from benchseal.evidence import (
    MAX_EVIDENCE_BYTES,
    TaskSetEvidenceReport,
    validate_evidence_file,
    validate_evidence_path,
    write_evidence_draft,
)

EXAMPLE_EVIDENCE = Path(__file__).parents[1] / "examples" / "evidence.json"


class TaskEvidenceReportTests(unittest.TestCase):
    def test_valid_example_is_eligible_and_deterministic(self) -> None:
        first = validate_evidence_file(EXAMPLE_EVIDENCE)
        second = validate_evidence_file(EXAMPLE_EVIDENCE)

        self.assertEqual(first, second)
        self.assertEqual(first.decision, "ELIGIBLE")
        self.assertEqual(first.checks_evaluated, 12)
        self.assertEqual(first.findings, ())
        self.assertEqual(first.to_dict()["tool_version"], "1.0.0")
        self.assertEqual(first.to_dict()["report_kind"], "task")
        self.assertEqual(first.to_dict()["report_schema_version"], "0.2")
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


class EvidenceDraftTests(unittest.TestCase):
    def test_draft_is_complete_in_shape_but_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-draft-") as directory:
            path = Path(directory) / "nested" / "evidence.json"
            write_evidence_draft(path, "issue-123")
            payload = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(payload["schema_version"], "0.1")
            self.assertEqual(payload["task_id"], "issue-123")
            self.assertEqual(len(payload), 16)
            self.assertTrue(
                all(
                    value is None
                    for key, value in payload.items()
                    if key not in {"schema_version", "task_id"}
                )
            )
            with self.assertRaisesRegex(ValueError, "base_fails must be a boolean"):
                validate_evidence_file(path)

    def test_draft_never_overwrites_an_existing_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="benchseal-draft-") as directory:
            path = Path(directory) / "evidence.json"
            path.write_text("keep me\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must not already exist"):
                write_evidence_draft(path, "issue-123")

            self.assertEqual(path.read_text(encoding="utf-8"), "keep me\n")


class TaskSetEvidenceReportTests(unittest.TestCase):
    def test_directory_report_is_sorted_and_held_if_any_task_is_held(self) -> None:
        valid = json.loads(EXAMPLE_EVIDENCE.read_text(encoding="utf-8"))
        valid["task_id"] = "zeta"
        held = dict(valid)
        held["task_id"] = "alpha"
        held["gold_passes"] = False
        with tempfile.TemporaryDirectory(prefix="benchseal-batch-") as directory:
            root = Path(directory)
            (root / "a-valid.json").write_text(json.dumps(valid), encoding="utf-8")
            (root / "z-held.json").write_text(json.dumps(held), encoding="utf-8")
            report = validate_evidence_path(root)
            renamed = root / "renamed"
            renamed.mkdir()
            (renamed / "first.json").write_text(json.dumps(held), encoding="utf-8")
            (renamed / "second.json").write_text(json.dumps(valid), encoding="utf-8")
            renamed_report = validate_evidence_path(renamed)

        self.assertIsInstance(report, TaskSetEvidenceReport)
        self.assertEqual([task.task_id for task in report.tasks], ["alpha", "zeta"])
        self.assertEqual(report.decision, "HOLD")
        self.assertEqual(report.eligible_count, 1)
        self.assertEqual(report.held_count, 1)
        self.assertEqual(report.to_json(), renamed_report.to_json())
        self.assertTrue(report.task_set_sha256.startswith("sha256:"))
        self.assertIn("alpha: HOLD (GOLD_NOT_PASSING)", report.to_text())

    def test_directory_rejects_duplicate_task_ids(self) -> None:
        payload = EXAMPLE_EVIDENCE.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="benchseal-batch-") as directory:
            root = Path(directory)
            (root / "first.json").write_text(payload, encoding="utf-8")
            (root / "second.json").write_text(payload, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate task_id values"):
                validate_evidence_path(root)

    def test_empty_directory_is_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="benchseal-batch-") as directory,
            self.assertRaisesRegex(ValueError, "contains no JSON files"),
        ):
            validate_evidence_path(Path(directory))


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

    def test_receipt_output_never_overwrites_an_existing_path(self) -> None:
        errors = StringIO()
        with tempfile.TemporaryDirectory(prefix="benchseal-cli-") as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text("keep me\n", encoding="utf-8")
            with redirect_stderr(errors):
                exit_code = main(
                    ["validate", str(EXAMPLE_EVIDENCE), "--output", str(receipt)]
                )

            self.assertEqual(receipt.read_text(encoding="utf-8"), "keep me\n")

        self.assertEqual(exit_code, 2)
        self.assertIn("output file must not already exist", errors.getvalue())

    def test_receipt_output_never_follows_a_symbolic_link(self) -> None:
        errors = StringIO()
        with tempfile.TemporaryDirectory(prefix="benchseal-cli-") as directory:
            root = Path(directory)
            target = root / "target.json"
            receipt = root / "receipt.json"
            try:
                receipt.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")

            with redirect_stderr(errors):
                exit_code = main(
                    ["validate", str(EXAMPLE_EVIDENCE), "--output", str(receipt)]
                )

            self.assertTrue(receipt.is_symlink())
            self.assertFalse(target.exists())

        self.assertEqual(exit_code, 2)
        self.assertIn("output file must not already exist", errors.getvalue())

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

    def test_new_evidence_command_creates_a_draft(self) -> None:
        output = StringIO()
        with tempfile.TemporaryDirectory(prefix="benchseal-cli-") as directory:
            path = Path(directory) / "evidence.json"
            with redirect_stdout(output):
                exit_code = main(
                    ["new-evidence", str(path), "--task-id", "issue-123"]
                )
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["task_id"], "issue-123")
        self.assertIn("Replace every null", output.getvalue())

    def test_directory_command_returns_an_aggregate_json_receipt(self) -> None:
        output = StringIO()
        with tempfile.TemporaryDirectory(prefix="benchseal-cli-") as directory:
            root = Path(directory)
            payload = EXAMPLE_EVIDENCE.read_text(encoding="utf-8")
            (root / "evidence.json").write_text(payload, encoding="utf-8")
            with redirect_stdout(output):
                exit_code = main(["validate", str(root), "--json"])
            report = json.loads(output.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["decision"], "ELIGIBLE")
        self.assertEqual(report["report_kind"], "task_set")
        self.assertEqual(report["task_count"], 1)


if __name__ == "__main__":
    unittest.main()
