"""Infrastructure context, English metadata and independent expansion regressions.

All fixture source is inert text. No target source, dependency or command is
imported/executed; sockets/process launch are forbidden during detector tests.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = load_script("defense_scan")
diff = load_script("defense_diff")
with patch.dict(sys.modules, {"defense_scan": scanner}):
    coverage = load_script("scanner_coverage")


class ScannerContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()
        cls.cases = json.loads((ROOT / "tests/fixtures/defense_expansion.json").read_text(encoding="utf-8"))["cases"]
        cls.context = {"schema": scanner.CONTEXT_SCHEMA,
                       "infrastructure": ["vulnbox", "compose", "team-lan"], "role": "both"}

    def test_context_is_strict_nonsecret_and_canonical(self):
        self.assertEqual(scanner.validate_context(self.context)["infrastructure"], ["compose", "team-lan", "vulnbox"])
        invalid = [False, [], {}, {**self.context, "secret": "CANARY"},
                   {**self.context, "infrastructure": ["CANARY"]},
                   {**self.context, "infrastructure": ["compose", "compose"]},
                   {**self.context, "infrastructure": [False]},
                   {**self.context, "infrastructure": "compose"},
                   {**self.context, "role": "CANARY"},
                   {**self.context, "schema": "unsupported"}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError) as exc:
                scanner.validate_context(value)
            self.assertNotIn("CANARY", str(exc.exception))

    def test_context_changes_priority_not_detector_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compose.yaml").write_text("privileged: true\n", encoding="utf-8")
            before = scanner.scan(root, self.rules)
            after = scanner.scan(root, self.rules, context=self.context)
            self.assertEqual([(r["rule"], r["line"], r["path"]) for r in before["findings"]],
                             [(r["rule"], r["line"], r["path"]) for r in after["findings"]])
            self.assertEqual(before["findings"][0]["review_priority"], "normal")
            self.assertEqual(after["findings"][0]["review_priority"], "high")
            self.assertTrue(after["findings"][0]["context_notes"])
            result = diff.compare_reports(diff.validate_report(before), diff.validate_report(after))
            self.assertEqual(result["exit_code"], 2)
            self.assertIn("scope_changed", result["warnings"])

    def test_scope_v2_canonical_context_and_role(self):
        args = (Path("example"), self.rules, [], 1024, 50, 50)
        first = scanner.scan_scope(*args, context=self.context)
        reordered = {**self.context, "infrastructure": list(reversed(self.context["infrastructure"]))}
        self.assertEqual(first, scanner.scan_scope(*args, context=reordered))
        self.assertNotEqual(first, scanner.scan_scope(*args, context={**self.context, "role": "administrator"}))
        self.assertEqual(diff.validate_scope(first), first)
        for key in ("context_sha256", "semantic_revision", "sha256"):
            changed = {**first, key: "x"}
            with self.assertRaises(ValueError):
                diff.validate_scope(changed)
        with self.assertRaises(ValueError):
            diff.validate_scope({**first, "untrusted": "secret"})

    def test_legacy_v1_is_readable_but_not_comparable_to_v2(self):
        current = scanner.scan_scope(Path("example"), self.rules, [], 1024, 50, 50)
        legacy = {k: v for k, v in current.items() if k not in {"context_sha256", "semantic_revision", "sha256"}}
        legacy["schema"] = "durkahelper.scanner-scope.v1"
        legacy["sha256"] = hashlib.sha256(scanner._canonical_json(legacy)).hexdigest()
        self.assertEqual(diff.validate_scope(legacy), legacy)
        common = {"tool": "DurkaHelper defense_scan", "version": scanner.VERSION,
                  "offline": True, "created_at": "2026-10-09T00:00:00Z", "findings": [],
                  "issues": [], "partial": False, "exit_code": 0}
        result = diff.compare_reports(diff.validate_report({**common, "scope": legacy}),
                                      diff.validate_report({**common, "scope": current}))
        self.assertEqual(result["exit_code"], 2)
        self.assertFalse(result["scope_verified"])

    def test_context_file_limits_duplicates_and_cli_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "app.py"
            source.write_text("import logging\npassword = 'SOURCE_CANARY'\nlogging.error(password)\n", encoding="utf-8")
            profile = Path(tmp) / "context.json"
            for data in ('{"schema":"x","schema":"x"}', "[" * 1500 + "]" * 1500,
                         json.dumps({**self.context, "secret": "CONTEXT_CANARY"}), "x" * 16385):
                profile.write_text(data, encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    status = scanner.main([str(source), "--context", str(profile), "--json"])
                self.assertEqual(status, 2)
                self.assertNotIn("CONTEXT_CANARY", output.getvalue())
                self.assertNotIn("SOURCE_CANARY", output.getvalue())
            profile.write_text(json.dumps(self.context), encoding="utf-8")
            before = source.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(scanner.main([str(source), "--context", str(profile), "--json"]), 1)
            self.assertNotIn("SOURCE_CANARY", output.getvalue())
            self.assertEqual(before, source.read_bytes())

    def test_private_key_directories_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("value=1", encoding="utf-8")
            for directory in (".ssh", ".aws"):
                (root / directory).mkdir()
                (root / directory / "private.json").write_text('{"secret_key":"PRIVATE_CANARY"}', encoding="utf-8")
            report = scanner.scan(root, self.rules)
            self.assertEqual(report["files_scanned"], 1)
            self.assertEqual(report["skipped"]["excluded_directory"], 2)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(report))

    def test_expansion_fixtures_offline_without_target_execution(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
            for case in self.cases:
                with self.subTest(case=case["id"]):
                    hits, issues = scanner.scan_text(case["source"], case["language"], self.rules)
                    ids = {rid for rid, _ in hits}
                    self.assertEqual(issues, [])
                    self.assertFalse(set(case["expected"]) - ids)
                    self.assertFalse(set(case["forbidden"]) & ids)
                    self.assertEqual((hits, issues), scanner.scan_text(case["source"], case["language"], self.rules))

    def test_coverage_target_uses_independent_sources_per_language(self):
        ledger = coverage.build_ledger(self.rules, run_checks=True)
        self.assertEqual(ledger["failing_case_ids"], [])
        self.assertEqual(ledger["unmet_release_pairs"], [])
        self.assertFalse(ledger["authored_examples_counted"])
        self.assertEqual(ledger["exit_code"], 0)
        required = [row for row in ledger["rows"] if row["required_for_release"]]
        self.assertEqual(len(required), 28)
        self.assertEqual({row["language"] for row in required}, set(scanner.EXTENSIONS.values()) | {"docker"})
        self.assertTrue(any(not row["meets_independent_target"] for row in ledger["rows"]))
        self.assertEqual(ledger, coverage.build_ledger(self.rules, run_checks=True))

    def test_coverage_rejects_duplicate_ids_and_ignores_duplicate_source(self):
        case = self.cases[0]
        with self.assertRaises(ValueError):
            coverage.build_ledger(self.rules, [case, case])
        first = coverage.build_ledger(self.rules, [case])
        duplicate = coverage.build_ledger(self.rules, [case, {**case, "id": "another-name"}])
        self.assertEqual(first["rows"], duplicate["rows"])
        rule = next(rule for rule in self.rules if rule["id"] == case["expected"][0])
        authored = coverage.build_ledger(self.rules, [{**case, "source": rule["before"]}])
        row = next(row for row in authored["rows"] if row["rule"] == rule["id"])
        self.assertEqual(row["independent_positive"], 0)

    def test_coverage_cli_runs_in_isolated_python_mode(self):
        completed = subprocess.run([sys.executable, "-I", "-S", str(ROOT / "scripts/scanner_coverage.py"), "--check", "--json"],
                                   capture_output=True, timeout=20, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
        ledger = json.loads(completed.stdout)
        self.assertTrue(ledger["checks_executed"])
        self.assertEqual(ledger["unmet_release_pairs"], [])

    def test_rule_metadata_is_english_and_bounded_review_not_verdict(self):
        for rule in self.rules:
            with self.subTest(rule=rule["id"]):
                for key in ("title", "reason", "fix", "check", "limitations"):
                    self.assertIsInstance(rule[key], str)
                    self.assertNotRegex(rule[key], r"[\u0400-\u04ff]")
                self.assertIn(rule["review_priority"], {"normal", "high"})
                self.assertIn(rule["signal_kind"], {"syntactic-review", "configuration-review"})
                self.assertTrue(all(re.fullmatch(r"CWE-[1-9][0-9]*", value) for value in rule["cwe"]))
        bidi = next(rule for rule in self.rules if rule["id"] == "SRC-MIXED-IDENTIFIER")
        self.assertRegex(bidi["before"], r"[\u0400-\u04ff]")

    def test_new_lexical_exclusion_preserves_physical_lines_and_limits(self):
        source = "/* res.redirect(req.query.next); */\r\nres.redirect(req.body.next);\r\n"
        hits, issues = scanner.scan_text(source, "javascript", self.rules)
        self.assertEqual([item for item in hits if item[0] == "JS-REDIRECT-INPUT"], [("JS-REDIRECT-INPUT", 2)])
        self.assertEqual(issues, [])
        source = "#" + "x" * 8193 + "\nSESSION_COOKIE_SECURE = False\n"
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertIn(("CFG-COOKIE-FLAGS", 2), hits)
        self.assertIn("regex_line_limit", issues)

    def test_language_specific_lexical_boundaries_and_uncertain_exclusions(self):
        examples = [
            ("rust", "fn read<'a>(reader: &'a mut Socket) { reader.read_to_end(&mut bytes); }", "RUST-UNBOUNDED-READ", True),
            ("php", "# ldap_search($ld, $dn, '(uid=' . $uid);", "PHP-LDAP-FILTER", False),
            ("ruby", "=begin\nredirect_to params[:next]\n=end\n", "RUBY-REDIRECT-INPUT", False),
            ("sql", "SELECT $example$USING (true)$example$;", "SQL-RLS-ALLOW-ALL", False),
        ]
        for language, source, rid, expected in examples:
            with self.subTest(language=language):
                hits, issues = scanner.scan_text(source, language, self.rules)
                self.assertEqual(rid in {item[0] for item in hits}, expected)
                self.assertEqual(issues, [])
        hits, issues = scanner.scan_text("const text = 'res.redirect(req.query.next);", "javascript", self.rules)
        self.assertNotIn("JS-REDIRECT-INPUT", {rid for rid, _ in hits})
        self.assertIn("lexical_unterminated", issues)

    def test_new_python_detectors_require_explicit_import_or_instance_facts(self):
        for source, rid in [
            ("logging.error(password)", "PY-LOG-CREDENTIALS"),
            ("logger=logging.getLogger('unknown')\nlogger.error(token)", "PY-LOG-CREDENTIALS"),
            ("app=flask.Flask('unknown')\n@flask_login.login_required\n@app.route('/x')\ndef view():\n    pass", "PY-AUTH-DECORATOR"),
        ]:
            with self.subTest(rule=rid):
                hits, issues = scanner.scan_text(source, "python", self.rules)
                self.assertEqual(issues, [])
                self.assertNotIn(rid, {item[0] for item in hits})


if __name__ == "__main__":
    unittest.main()
