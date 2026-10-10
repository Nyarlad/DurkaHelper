"""Bounded analysis and report regressions for inert adversarial source text."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("resource_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)
ENV = "NODE_TLS_REJECT_UNAUTHORIZED=0"


class ResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def test_oversized_line_never_creates_an_artificial_scalar_end(self):
        source = " " * (8192 - len(ENV)) + ENV + "x"
        hits, issues = scanner.scan_text(source, "shell", self.rules)
        self.assertNotIn("JS-TLS", {rid for rid, _ in hits})
        self.assertIn("regex_line_limit", issues)

    def test_exact_8192_character_eof_preserves_real_zero_and_rejects_zero_x(self):
        for value, expected in ((ENV, True), (ENV + "x", False)):
            source = " " * (8192 - len(value)) + value
            hits, issues = scanner.scan_text(source, "shell", self.rules)
            self.assertEqual(issues, [])
            self.assertEqual(("JS-TLS", 1) in hits, expected)

    def test_oversized_line_keeps_findings_on_following_lines_two_and_six(self):
        source = "#" + "x" * 8193 + "\n" + ENV + "\n\n\n\n" + ENV + "\n"
        hits, issues = scanner.scan_text(source, "shell", self.rules)
        self.assertEqual([hit for hit in hits if hit[0] == "JS-TLS"], [("JS-TLS", 2), ("JS-TLS", 6)])
        self.assertIn("regex_line_limit", issues)

    def test_budget_split_keeps_complete_short_lines_and_cannot_truncate_values(self):
        for suffix, expected in (("", True), ("x", False)):
            source = "#" + "a" * 6000 + "\n" + " " * 3000 + ENV + suffix + "\n"
            hits, issues = scanner.scan_text(source, "shell", self.rules)
            self.assertEqual(("JS-TLS", 2) in hits, expected)
            self.assertEqual(issues, [])
        # Both lines fit individually; their combined window formerly ended
        # in the middle of the second scalar, turning 0x into 0.
        first = "#" + "a" * 6000 + "\n"
        source = first + " " * (8192 - len(first) - len(ENV)) + ENV + "x\n"
        hits, issues = scanner.scan_text(source, "shell", self.rules)
        self.assertNotIn("JS-TLS", {rid for rid, _ in hits})
        self.assertEqual(issues, [])

    def test_crlf_and_unicode_separators_use_physical_lf_line_numbers(self):
        hits, issues = scanner.scan_text("# note\r\n" + ENV + "\r\n", "shell", self.rules)
        self.assertEqual(hits, [("JS-TLS", 2)])
        self.assertEqual(issues, [])
        for separator in ("\v", "\f", "\u0085", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                hits, issues = scanner.scan_text(separator * 6 + ENV, "shell", self.rules)
                self.assertEqual(hits, [("JS-TLS", 1)])
                self.assertEqual(issues, [])

    def test_other_analysis_continues_after_regex_line_limit(self):
        python_source = "#" + "x" * 9000 + "\neval(payload)\n"
        hits, issues = scanner.scan_text(python_source, "python", self.rules)
        self.assertIn(("PY-EVAL", 2), hits)
        self.assertIn("regex_line_limit", issues)
        js_source = "import {exec as launch} from 'child_process'; //" + "x" * 9000 + "\nlaunch(command);\n"
        hits, issues = scanner.scan_text(js_source, "javascript", self.rules)
        self.assertIn(("JS-SHELL", 2), hits)
        self.assertIn("regex_line_limit", issues)

    def test_cli_partial_keeps_neighbor_metadata_without_source_or_secrets(self):
        source = "# DO_NOT_REPORT_SOURCE " + "x" * 9000 + "\n" + ENV + "\n"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "run.sh"
            path.write_text(source, encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = scanner.main([str(path), "--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertTrue(report["partial"])
        self.assertEqual(report["issues"], [{"path": "run.sh", "reason": "regex_line_limit"}])
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual((finding["rule"], finding["path"], finding["line"]), ("JS-TLS", "run.sh", 2))
        self.assertEqual(finding["doc"], "docs/vulnerabilities/javascript.md#js-tls")
        self.assertNotIn("DO_NOT_REPORT_SOURCE", output.getvalue())

    def test_python_ast_node_limit_retains_other_engine_without_source_leak(self):
        source = "JWT_SECRET='RESOURCE_SECRET'\n" + "x=0\n" * 50001
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertIn("python_parse_failed:ValueError", issues)
        self.assertIn(("CFG-SECRET", 1), hits)
        self.assertNotIn("RESOURCE_SECRET", json.dumps((hits, issues)))

    def test_python_ast_depth_limit_is_reported_and_retains_regex_engine(self):
        source = "value=" + "+".join("x" for _ in range(2000)) + "\nJWT_SECRET='RESOURCE_SECRET'\n"
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertIn("python_parse_failed:RecursionError", issues)
        self.assertIn(("CFG-SECRET", 2), hits)
        self.assertNotIn("RESOURCE_SECRET", json.dumps((hits, issues)))


if __name__ == "__main__":
    unittest.main()
