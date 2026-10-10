"""Independent detector regressions. Fixture code is data and never executed."""
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("variant_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class VariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()
        cls.cases = json.loads((ROOT / "tests/fixtures/defense_variants.json").read_text(encoding="utf-8"))["cases"]

    def test_fixture_contract(self):
        self.assertEqual(len(self.cases), len({c["id"] for c in self.cases}))
        rule_ids = {r["id"] for r in self.rules}
        for c in self.cases:
            with self.subTest(case=c["id"]):
                self.assertTrue(c["note"] and c["source"])
                self.assertTrue(c["expected"] or c["forbidden"])
                self.assertTrue(set(c["expected"] + c["forbidden"]) <= rule_ids)
                self.assertFalse(set(c["expected"]) & set(c["forbidden"]))

    def test_independent_variants_offline(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
             patch.object(urllib.request, "urlopen", side_effect=AssertionError("HTTP")):
            for c in self.cases:
                with self.subTest(case=c["id"]):
                    hits, issues = scanner.scan_text(c["source"], c["language"], self.rules)
                    ids = {rid for rid, _ in hits}
                    self.assertEqual(issues, [])
                    self.assertFalse(set(c["expected"]) - ids, (c["id"], "missing", ids))
                    self.assertFalse(set(c["forbidden"]) & ids, (c["id"], "false signal", ids))

    def test_unknown_dict_spread_invalidates_previous_fact(self):
        source = "import jwt\njwt.decode(token, options={'verify_signature': False, **external})"
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertEqual(issues, [])
        self.assertNotIn("PY-JWT", {rid for rid, _ in hits})
        source = "import jwt\njwt.decode(token, options={**external, 'verify_signature': False})"
        hits, _ = scanner.scan_text(source, "python", self.rules)
        self.assertIn("PY-JWT", {rid for rid, _ in hits})

    def test_alias_limit_marks_partial_and_keeps_other_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "many.js"
            path.write_text("\n".join(f"import * as p{i} from 'child_process';" for i in range(30)) + "\neval(input);")
            report = scanner.scan(path, self.rules)
            self.assertTrue(report["partial"])
            self.assertEqual(report["exit_code"], 2)
            self.assertIn("javascript_alias_limit", {i["reason"] for i in report["issues"]})
            self.assertIn("JS-EVAL", {f["rule"] for f in report["findings"]})

    def test_alias_lines_and_regex_deduplicate(self):
        source = "import cp from 'child_process';\ncp.exec(command);\ncp['exec'](command);"
        hits, issues = scanner.scan_text(source, "javascript", self.rules)
        self.assertEqual(issues, [])
        self.assertEqual([h for h in hits if h[0] == "JS-SHELL"], [("JS-SHELL", 2), ("JS-SHELL", 3)])


if __name__ == "__main__":
    unittest.main()
