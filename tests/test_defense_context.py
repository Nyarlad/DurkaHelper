"""Independent malformed scanner-scope boundary regressions."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("context_boundary_diff", ROOT / "scripts/defense_diff.py")
diff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diff)


def scope(schema):
    body = {"schema": schema, "root": "sha256:" + "a" * 64,
            "rules_sha256": "b" * 64, "exclude": [],
            "limits": {"max_bytes": 1024, "max_files": 10, "max_findings": 10},
            "path_semantics": "root-relative-posix.v1"}
    body["sha256"] = hashlib.sha256(json.dumps(body, ensure_ascii=True, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()
    return body


class ScopeBoundaryTests(unittest.TestCase):
    def test_nonstring_schema_rejected_as_validation_error(self):
        for value in ([], {}, ["CANARY_SCOPE"], {"secret": "CANARY_SCOPE"}, None, True, 17):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(ValueError) as raised:
                    diff.validate_scope(scope(value))
                self.assertNotIn("CANARY_SCOPE", str(raised.exception))

    def test_cli_malformed_scope_returns_two_without_traceback_or_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report = {"tool": "DurkaHelper defense_scan", "version": "1.7.0", "offline": True,
                      "created_at": "2026-10-09T00:00:00Z", "findings": [], "issues": [],
                      "partial": False, "exit_code": 0}
            for value in ([], {"secret": "CANARY_SCOPE"}):
                report_path.write_text(json.dumps({**report, "scope": scope(value)}), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()) as output, \
                     contextlib.redirect_stderr(io.StringIO()) as errors:
                    code = diff.main([str(report_path), str(report_path), "--json"])
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output.getvalue())["error"], "invalid_or_unreadable_report")
                self.assertNotIn("CANARY_SCOPE", output.getvalue() + errors.getvalue())
                self.assertNotIn("Traceback", output.getvalue() + errors.getvalue())


if __name__ == "__main__":
    unittest.main()
