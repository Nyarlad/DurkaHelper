"""TLS configuration signals: exact environment values and Go assignments."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tls_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class TlsConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def ids(self, source, language):
        hits, issues = scanner.scan_text(source, language, self.rules)
        self.assertEqual(issues, [])
        return {rid for rid, _ in hits}

    def test_go_assignment_and_callback_remain_review_signals(self):
        for source in [
            "cfg.InsecureSkipVerify = true",
            "transport.TLSClientConfig.InsecureSkipVerify =\n true",
            "cfg := tls.Config{InsecureSkipVerify: true, VerifyConnection: verifyPeer}",
        ]:
            with self.subTest(source=source):
                self.assertIn("GO-TLS", self.ids(source, "go"))
        for source in [
            "cfg.InsecureSkipVerify = false",
            "if cfg.InsecureSkipVerify == true {}",
            "if cfg.InsecureSkipVerify != true {}",
            "cfg := tls.Config{InsecureSkipVerify: false}",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("GO-TLS", self.ids(source, "go"))

    def test_node_exact_zero_in_javascript_and_config(self):
        for source, language in [
            ('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";', "javascript"),
            ("process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';", "javascript"),
            ('{"NODE_TLS_REJECT_UNAUTHORIZED": "0"}', "config"),
            ("NODE_TLS_REJECT_UNAUTHORIZED: '0' # review environment", "config"),
            ("NODE_TLS_REJECT_UNAUTHORIZED=0", "config"),
        ]:
            with self.subTest(source=source):
                self.assertIn("JS-TLS", self.ids(source, language))
        for value in ("0.1", "0-disabled", "0 ", "00", "0abc"):
            for quote in ("'", '"'):
                source = f"process.env.NODE_TLS_REJECT_UNAUTHORIZED = {quote}{value}{quote};"
                with self.subTest(source=source):
                    self.assertNotIn("JS-TLS", self.ids(source, "javascript"))
        for source in [
            "NODE_TLS_REJECT_UNAUTHORIZED: 0.1",
            "NODE_TLS_REJECT_UNAUTHORIZED: 0-disabled",
            "NODE_TLS_REJECT_UNAUTHORIZED: 00",
            "NODE_TLS_REJECT_UNAUTHORIZED: 0 words",
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' + suffix;",
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0\";",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("JS-TLS", self.ids(source, "config"))

    def test_node_shell_assignments_use_whole_tokens(self):
        for source in [
            "export NODE_TLS_REJECT_UNAUTHORIZED=0",
            "NODE_TLS_REJECT_UNAUTHORIZED='0' node app.js",
            'NODE_TLS_REJECT_UNAUTHORIZED="0"; node app.js',
        ]:
            with self.subTest(source=source):
                self.assertIn("JS-TLS", self.ids(source, "shell"))
        for source in [
            "NODE_TLS_REJECT_UNAUTHORIZED='0'suffix node app.js",
            "NODE_TLS_REJECT_UNAUTHORIZED='0'\"suffix\" node app.js",
            "NODE_TLS_REJECT_UNAUTHORIZED=0-disabled",
            "NODE_TLS_REJECT_UNAUTHORIZED='0 '",
            "rejectUnauthorized: false",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("JS-TLS", self.ids(source, "shell"))

    def test_node_docker_env_modern_and_legacy_values(self):
        for source in [
            "ENV NODE_TLS_REJECT_UNAUTHORIZED=0",
            'ENV NODE_TLS_REJECT_UNAUTHORIZED="0" OTHER=1',
            "ENV NODE_TLS_REJECT_UNAUTHORIZED 0",
            'ENV NODE_TLS_REJECT_UNAUTHORIZED "0"',
            "ENV NODE_TLS_REJECT_UNAUTHORIZED '0'",
        ]:
            with self.subTest(source=source):
                self.assertIn("JS-TLS", self.ids(source, "docker"))
        for source in [
            "ENV NODE_TLS_REJECT_UNAUTHORIZED 0 # this is part of the value",
            "ENV NODE_TLS_REJECT_UNAUTHORIZED 0 other",
            "ENV NODE_TLS_REJECT_UNAUTHORIZED=0.1",
            "ENV NODE_TLS_REJECT_UNAUTHORIZED=0#suffix",
            "ENV NODE_TLS_REJECT_UNAUTHORIZED=0//suffix",
            "ENV NODE_TLS_REJECT_UNAUTHORIZED=0;",
            'ENV NODE_TLS_REJECT_UNAUTHORIZED="0 "',
            "rejectUnauthorized: false",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("JS-TLS", self.ids(source, "docker"))

    def test_shell_hash_and_slash_suffixes_are_value_text(self):
        for source in [
            "NODE_TLS_REJECT_UNAUTHORIZED=0#suffix node app.js",
            "NODE_TLS_REJECT_UNAUTHORIZED=0//suffix node app.js",
            "NODE_TLS_REJECT_UNAUTHORIZED='0'#suffix node app.js",
            "NODE_TLS_REJECT_UNAUTHORIZED = 0",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("JS-TLS", self.ids(source, "shell"))
        self.assertIn("JS-TLS", self.ids("NODE_TLS_REJECT_UNAUTHORIZED=0; node app.js", "shell"))

    def test_docker_unmodelled_instruction_forms_remain_manual(self):
        for source in [
            "RUN NODE_TLS_REJECT_UNAUTHORIZED=0 node app.js",
            "ENV OTHER=1 NODE_TLS_REJECT_UNAUTHORIZED=0",
            "NODE_TLS_REJECT_UNAUTHORIZED: 0",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("JS-TLS", self.ids(source, "docker"))

    def test_explain_excludes_compiled_language_patterns(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(scanner.main(["--explain", "JS-TLS"]), 0)
        explanation = json.loads(output.getvalue())
        self.assertEqual(explanation["id"], "JS-TLS")
        self.assertEqual(explanation["languages"], ["javascript", "config", "docker", "shell"])
        self.assertFalse({"compiled", "compiled_languages", "pattern", "language_patterns"} & explanation.keys())

    def test_language_pattern_schema_rejects_unknown_languages_and_non_strings(self):
        data = json.loads((ROOT / "rules/defense.json").read_text(encoding="utf-8"))
        rule = next(rule for rule in data["rules"] if rule["id"] == "JS-TLS")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rules.json"
            for invalid in ([], {"ruby": "x"}, {"shell": None}):
                rule["language_patterns"] = invalid
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.subTest(invalid=invalid), patch.object(scanner, "RULE_PATH", path):
                    with self.assertRaises(ValueError):
                        scanner.load_rules()

    def test_value_endings_and_comment_limit_after_implementation(self):
        for language in ("javascript", "config", "shell", "docker"):
            for source in (
                'NODE_TLS_REJECT_UNAUTHORIZED="0.1"',
                "NODE_TLS_REJECT_UNAUTHORIZED='0-disabled'",
                'NODE_TLS_REJECT_UNAUTHORIZED="0 "',
                'NODE_TLS_REJECT_UNAUTHORIZED="0"suffix',
            ):
                with self.subTest(language=language, source=source):
                    self.assertNotIn("JS-TLS", self.ids(source, language))
        self.assertIn("JS-TLS", self.ids("(process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0')", "javascript"))
        # This is text matching, not a parser: commented configuration remains
        # a documented review signal, not a claim about the effective value.
        self.assertIn("JS-TLS", self.ids("# NODE_TLS_REJECT_UNAUTHORIZED=0", "shell"))

    def test_file_types_locations_and_documentation(self):
        sources = {
            "Dockerfile": "FROM node:22\nENV NODE_TLS_REJECT_UNAUTHORIZED 0\n",
            "run.sh": "#!/bin/sh\nexport NODE_TLS_REJECT_UNAUTHORIZED=0\n",
            "main.go": "package main\nfunc f(){ cfg.InsecureSkipVerify = true }\n",
        }
        with tempfile.TemporaryDirectory() as temp:
            for filename, source in sources.items():
                (Path(temp) / filename).write_text(source, encoding="utf-8")
            report = scanner.scan(temp, self.rules)
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["files_scanned"], 3)
        findings = {finding["path"]: finding for finding in report["findings"]}
        self.assertEqual(set(findings), set(sources))
        for filename, finding in findings.items():
            self.assertEqual(finding["line"], 2)
            self.assertEqual(finding["rule"], "GO-TLS" if filename == "main.go" else "JS-TLS")
            self.assertEqual(finding["doc"], "docs/vulnerabilities/go.md#go-tls" if filename == "main.go"
                             else "docs/vulnerabilities/javascript.md#js-tls")
            self.assertTrue(finding["reason"] and finding["detection"])


if __name__ == "__main__":
    unittest.main()
