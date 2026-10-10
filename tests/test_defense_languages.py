"""Independent Go/PHP detector variants. Snippets are inert source text."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("language_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class LanguageVariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def ids(self, source, language):
        hits, issues = scanner.scan_text(source, language, self.rules)
        self.assertEqual(issues, [])
        return {rid for rid, _ in hits}

    def test_go_minimum_tls_version_assignment_variants(self):
        for version in ("SSL30", "TLS10", "TLS11"):
            for source in [
                f"cfg.MinVersion = tls.Version{version}",
                f"transport.TLSClientConfig.MinVersion =\n tls.Version{version}",
                f"cfg := tls.Config{{MinVersion: tls.Version{version}}}",
            ]:
                with self.subTest(source=source):
                    self.assertIn("GO-TLS-MIN", self.ids(source, "go"))
        for source in [
            "cfg.MinVersion = tls.VersionTLS12",
            "cfg.MinVersion = tls.VersionTLS13",
            "cfg.MinVersion = 0",
            "if cfg.MinVersion == tls.VersionTLS10 {}",
            "if cfg.MinVersion != tls.VersionTLS11 {}",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("GO-TLS-MIN", self.ids(source, "go"))

    def test_php_named_first_command_array_is_not_a_shell_by_itself(self):
        for source in [
            "proc_open(command: ['/usr/bin/file', '--', $filename], descriptor_spec: $spec, pipes: $pipes);",
            "proc_open(\n command: array('/usr/bin/file', '--', $filename),\n descriptor_spec: $spec, pipes: $pipes);",
            "proc_open(['/usr/bin/file', '--', $filename], $spec, $pipes);",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("PHP-SHELL", self.ids(source, "php"))
        for source in [
            "proc_open(command: $command, descriptor_spec: $spec, pipes: $pipes);",
            "proc_open(command: ['/bin/sh', '-c', $command], descriptor_spec: $spec, pipes: $pipes);",
            "proc_open(command: array('/bin/bash', '-c', $command), descriptor_spec: $spec, pipes: $pipes);",
            "proc_open(descriptor_spec: $spec, command: ['/usr/bin/file', '--', $filename], pipes: $pipes);",
            "system(command: ['/usr/bin/file', '--', $filename]);",
            "exec(command: ['/usr/bin/file', '--', $filename]);",
        ]:
            with self.subTest(source=source):
                self.assertIn("PHP-SHELL", self.ids(source, "php"))

    def test_post_implementation_go_selector_layout_and_similar_names(self):
        self.assertIn("GO-TLS-MIN", self.ids("cfg.\nMinVersion =\n tls.VersionTLS11", "go"))
        for source in (
            "cfg.MinimumVersion = tls.VersionTLS10",
            "cfg.MinVersion = tls.VersionTLS110",
            "cfg.MinVersion = configuredMinimum",
        ):
            with self.subTest(source=source):
                self.assertNotIn("GO-TLS-MIN", self.ids(source, "go"))

    def test_post_implementation_php_array_boundary_and_explicit_shell(self):
        self.assertNotIn("PHP-SHELL", self.ids(
            "\\proc_open( command : [ $executable, $argument ], descriptor_spec: $spec, pipes: $pipes);", "php"))
        # An argv array avoids an implicit shell but does not establish an
        # executable allowlist or safe utility options; that review stays manual.
        self.assertIn("PHP-SHELL", self.ids(
            "proc_open(command: ['cmd.exe', '/c', $command], descriptor_spec: $spec, pipes: $pipes);", "php"))
        self.assertIn("PHP-SHELL", self.ids(
            "proc_open(command: array_merge($prefix, $arguments), descriptor_spec: $spec, pipes: $pipes);", "php"))
        self.assertNotIn("PHP-SHELL", self.ids(
            "my_proc_open(command: $command, descriptor_spec: $spec, pipes: $pipes);", "php"))

    def test_language_findings_keep_file_line_and_documentation(self):
        sources = {
            "main.go": "package app\ncfg.MinVersion = tls.VersionTLS11\n",
            "worker.php": "<?php\nproc_open(command: ['/bin/sh', '-c', $command], descriptor_spec: $spec, pipes: $pipes);\n",
            "safe.php": "<?php\nproc_open(command: ['/usr/bin/file', '--', $checkedName], descriptor_spec: $spec, pipes: $pipes);\n",
        }
        with tempfile.TemporaryDirectory() as temp:
            for filename, source in sources.items():
                (Path(temp) / filename).write_text(source, encoding="utf-8")
            report = scanner.scan(temp, self.rules)
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["files_scanned"], 3)
        self.assertEqual(len(report["findings"]), 2)
        findings = {finding["rule"]: finding for finding in report["findings"]}
        for rid, filename, language in (("GO-TLS-MIN", "main.go", "go"), ("PHP-SHELL", "worker.php", "php")):
            finding = findings[rid]
            self.assertEqual((finding["path"], finding["line"]), (filename, 2))
            self.assertEqual(finding["doc"], f"docs/vulnerabilities/{language}.md#{rid.lower()}")
            self.assertTrue(finding["reason"] and finding["detection"])


if __name__ == "__main__":
    unittest.main()
