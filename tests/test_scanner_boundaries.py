"""Independent, inert boundary regressions: no dependencies or target execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location("boundary_" + name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner, diff, ops = load("defense_scan"), load("defense_diff"), load("defense_ops")
RULES = scanner.load_rules()
CASES = json.loads((ROOT / "tests/fixtures/defense_boundaries.json").read_text(encoding="utf-8"))["cases"]


class IndependentBoundaryTests(unittest.TestCase):
    pass


def fixture_test(case):
    def run(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            hits, issues = scanner.scan_text(case["source"], case["language"], RULES)
            self.assertEqual(issues, [])
            ids = {rid for rid, _ in hits}
            self.assertFalse(set(case["expected"]) - ids)
            self.assertFalse(set(case["forbidden"]) & ids)
            self.assertEqual((hits, issues), scanner.scan_text(case["source"], case["language"], RULES))
    return run


for case in CASES:
    setattr(IndependentBoundaryTests, "test_" + case["id"].replace("-", "_"), fixture_test(case))


class ScannerBoundaryContractTests(unittest.TestCase):
    def test_new_findings_redact_source_and_do_not_write_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {"app.py": "from flask import Flask\napp=Flask('x')\npassword='SOURCE_CANARY'\napp.logger.error(password)",
                     "app.js": "const password='SOURCE_CANARY'; console.error(password);",
                     "roles.sql": "GRANT pg_execute_server_program TO app;"}
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            before = {name: (root / name).read_bytes() for name in files}
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(scanner.main([str(root), "--json", "--patches"]), 1)
            self.assertNotIn("SOURCE_CANARY", output.getvalue())
            self.assertTrue({"PY-LOG-CREDENTIALS", "JS-LOG-CREDENTIALS", "SQL-SERVER-ROLE"} <=
                            {item["rule"] for item in json.loads(output.getvalue())["findings"]})
            self.assertEqual(before, {name: (root / name).read_bytes() for name in files})

    def test_old_semantics_are_readable_but_incomparable(self):
        scope = scanner.scan_scope(Path("example"), RULES, [], 1024, 50, 50)
        old = {**scope, "semantic_revision": "bounded-source-signals.v2"}
        old.pop("sha256")
        old["sha256"] = hashlib.sha256(scanner._canonical_json(old)).hexdigest()
        self.assertEqual(diff.validate_scope(old), old)
        self.assertEqual(ops._validate_scanner_scope(old), old)
        self.assertEqual(ops._validate_scanner_scope(scope), scope)
        common = {"tool": "DurkaHelper defense_scan", "version": scanner.VERSION, "offline": True,
                  "created_at": "2026-10-09T00:00:00Z", "findings": [], "issues": [], "partial": False, "exit_code": 0}
        first, second = {**common, "scope": old}, {**common, "scope": scope}
        self.assertEqual(diff.compare_reports(diff.validate_report(first), diff.validate_report(second))["exit_code"], 2)
        self.assertEqual(ops._sanitize_scanner_report(second)["scope"], scope)
        self.assertEqual(ops._sanitize_scanner_report(first)["scope"], old)

    def test_unknown_semantics_rejected_by_both_consumers(self):
        scope = scanner.scan_scope(Path("example"), RULES, [], 1024, 50, 50)
        scope["semantic_revision"] = "unknown"
        with self.assertRaises(ValueError):
            diff.validate_scope(scope)
        with self.assertRaises(ops.DefenseError):
            ops._validate_scanner_scope(scope)

    def test_javascript_limits_are_partial_not_clean(self):
        for text, issue in [("x;" * 50001, "javascript_token_limit"),
                            ("(" * 129 + ")" * 129, "javascript_nesting_limit"),
                            ("const x='unfinished", "lexical_unterminated")]:
            with self.subTest(issue=issue):
                self.assertIn(issue, scanner.scan_text(text, "javascript", RULES)[1])

    def test_expression_limits_report_partial_instead_of_false_clean(self):
        source = "console.log(" + ",".join(["approved"] * 1100) + ");"
        self.assertIn("javascript_expression_limit", scanner.scan_text(source, "javascript", RULES)[1])
        expression = "sql.Identifier('fixed')"
        for _ in range(34):
            expression = "sql.SQL('SELECT {}').format(" + expression + ")"
        source = "from psycopg import sql\ncur.execute(" + expression + ")"
        self.assertIn("python_composition_limit", scanner.scan_text(source, "python", RULES)[1])

    def test_common_regex_literals_and_escaped_strings_do_not_log(self):
        for text in ["const pattern=/['\"]console.error(password)[/]/;", "const sample=`console.error(password)`;",
                     r'''const sample="quote\" console.log(password)";''']:
            hits, issues = scanner.scan_text(text, "javascript", RULES)
            self.assertNotIn("JS-LOG-CREDENTIALS", {rid for rid, _ in hits})
            self.assertEqual(issues, [])

    def test_custom_require_and_method_parameters_are_not_known_apis(self):
        for text in ["function require(name){return custom;} const c=require('cors'); c({origin:true,credentials:true});",
                     "class Report { write(console) { console.error(password); } }",
                     "const {console: logger}=custom; logger.error(password);",
                     "import {console} from 'custom'; console.log(password);"]:
            hits, issues = scanner.scan_text(text, "javascript", RULES)
            self.assertEqual(issues, [])
            self.assertFalse({"CFG-CORS", "JS-LOG-CREDENTIALS"} & {rid for rid, _ in hits})

    def test_unknown_python_composition_stays_reviewable(self):
        for part in ("unknown", "sql.SQL(user_input)", "sql.SQL('x').format(**other)"):
            text = "from psycopg import sql\ncur.execute(sql.SQL('SELECT {}').format(" + part + "))"
            self.assertIn("PY-SQL", {rid for rid, _ in scanner.scan_text(text, "python", RULES)[0]})

    def test_python_replaced_quoting_api_never_suppresses_review(self):
        text = "from psycopg import sql\nsql.Identifier=custom\ncur.execute(sql.SQL('SELECT {}').format(sql.Identifier(value)))"
        self.assertIn("PY-SQL", {rid for rid, _ in scanner.scan_text(text, "python", RULES)[0]})

    def test_python_as_string_preserves_raw_composition_signal(self):
        for argument, expected in [("sql.SQL(text)", True), ("sql.Identifier(column)", False)]:
            text = "from psycopg import sql\ncur.execute(sql.SQL('SELECT {}').format(" + argument + ").as_string(cur))"
            self.assertEqual("PY-SQL" in {rid for rid, _ in scanner.scan_text(text, "python", RULES)[0]}, expected)

    def test_known_python_config_last_write_and_unknown_spreads(self):
        for expr in ("update({'DEBUG':True, 'DEBUG':False})", "from_mapping({'DEBUG':True, **unknown})",
                     "update({'DEBUG':True}, **unknown)"):
            text = "from flask import Flask\napp=Flask('x')\napp.config." + expr
            self.assertNotIn("PY-DEBUG", {rid for rid, _ in scanner.scan_text(text, "python", RULES)[0]})

    def test_sql_comments_strings_and_statement_boundaries(self):
        text = "GRANT SELECT ON notes TO app; -- TO PUBLIC\nSELECT 'SUPERUSER';\nCREATE USER app PASSWORD 'SUPERUSER';"
        hits, issues = scanner.scan_text(text, "sql", RULES)
        self.assertEqual(issues, [])
        self.assertFalse({"SQL-BYPASSRLS", "SQL-PUBLIC-GRANT", "SQL-SERVER-ROLE"} & {rid for rid, _ in hits})


if __name__ == "__main__":
    unittest.main()
