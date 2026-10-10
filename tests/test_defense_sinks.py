"""Keyword sink forms and literal-only SQL/XPath expression regressions."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sink_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class KeywordSinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def ids(self, source):
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertEqual(issues, [])
        return {rid for rid, _ in hits}

    def test_template_and_file_keywords(self):
        for source, rid in [
            ("from flask import render_template_string as render\nrender(source=user_template)", "PY-TEMPLATE"),
            ("env.from_string(\n    source=user_template,\n)", "PY-TEMPLATE"),
            ("from flask import render_template_string\nrender_template_string(**{'source': user_template})", "PY-TEMPLATE"),
            ("from flask import send_file as send\nsend(path_or_file=user_path)", "PY-FILE"),
            ("from flask import send_file\nsend_file(\n    **{'path_or_file': user_path},\n)", "PY-FILE"),
        ]:
            with self.subTest(source=source):
                self.assertIn(rid, self.ids(source))

    def test_redirect_framework_specific_keywords(self):
        for source in [
            "from flask import redirect as move\nmove(location=user_url)",
            "from werkzeug.utils import redirect as move\nmove(**{'location': user_url})",
            "from django.shortcuts import redirect as move\nmove(to=user_url)",
            "import django.shortcuts as shortcuts\nshortcuts.redirect(\n    **{'to': user_url},\n)",
        ]:
            with self.subTest(source=source):
                self.assertIn("PY-REDIRECT", self.ids(source))
        for source in [
            "from flask import redirect\nredirect(to=user_url)",
            "from django.shortcuts import redirect\nredirect(location=user_url)",
            "custom.redirect(location=user_url)",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("PY-REDIRECT", self.ids(source))

    def test_constant_unknown_and_similar_keyword_forms(self):
        for source, rid in [
            ("render_template_string(source='message.html')", "PY-TEMPLATE"),
            ("env.from_string(source='Hello {{ name }}')", "PY-TEMPLATE"),
            ("send_file(path_or_file='/srv/public/logo.png')", "PY-FILE"),
            ("from flask import redirect\nredirect(location='/home')", "PY-REDIRECT"),
            ("from django.shortcuts import redirect\nredirect(to='home')", "PY-REDIRECT"),
            ("render_template_string(**options)", "PY-TEMPLATE"),
            ("send_file(**options)", "PY-FILE"),
            ("from flask import redirect\nredirect(**options)", "PY-REDIRECT"),
            ("custom.parse_from_string(source=user_template)", "PY-TEMPLATE"),
            ("custom.send_file_metadata(path_or_file=user_path)", "PY-FILE"),
        ]:
            with self.subTest(source=source):
                self.assertNotIn(rid, self.ids(source))
        # The established tail-name heuristics also warn for custom methods.
        self.assertIn("PY-TEMPLATE", self.ids("custom.from_string(source=unknown)"))
        self.assertIn("PY-FILE", self.ids("custom.send_file(path_or_file=unknown)"))

    def test_literal_only_string_expressions_are_not_dynamic_sql_or_xpath(self):
        for source, rid in [
            ("db.execute('SELECT ' + '1')", "PY-SQL"),
            ("query=('SELECT ' + '1') + ' AS count'\ndb.execute(query)", "PY-SQL"),
            ("db.execute(f'SELECT 1')", "PY-SQL"),
            ("tree.xpath('/root/' + 'item')", "PY-XPATH"),
            ("tree.xpath(f'/root/item')", "PY-XPATH"),
            ("tree.xpath('/root/' + (f'item' + '/name'))", "PY-XPATH"),
        ]:
            with self.subTest(source=source):
                self.assertNotIn(rid, self.ids(source))

    def test_dynamic_and_unfolded_expressions_keep_signals(self):
        for source, rid in [
            ("db.execute('SELECT ' + user_column)", "PY-SQL"),
            ("db.execute(f'SELECT {user_column}')", "PY-SQL"),
            ("db.execute('SELECT %s' % '1')", "PY-SQL"),
            ("db.execute('SELECT {}'.format('1'))", "PY-SQL"),
            ("tree.xpath('/root/' + user_element)", "PY-XPATH"),
            ("tree.xpath(f'/root/{user_element}')", "PY-XPATH"),
            ("tree.xpath('/root/%s' % 'item')", "PY-XPATH"),
        ]:
            with self.subTest(source=source):
                self.assertIn(rid, self.ids(source))

    def test_post_implementation_kwargs_order_and_safe_context_limits(self):
        self.assertNotIn("PY-FILE", self.ids("send_file(**{'path_or_file': user_path, **options})"))
        self.assertIn("PY-FILE", self.ids("send_file(**{**options, 'path_or_file': user_path})"))
        self.assertNotIn("PY-TEMPLATE", self.ids(
            "from flask import render_template_string as render\nrender=custom_parser\nrender(source=user_template)"))
        # Access control and redirect policies are not proved by syntax. These
        # corrected shapes deliberately retain a review signal.
        self.assertIn("PY-FILE", self.ids(
            "record=load_owned_record(file_id, current_user.id)\nsend_file(path_or_file=record.storage_path)"))
        self.assertIn("PY-REDIRECT", self.ids(
            "from flask import redirect\nredirect(location=validated_relative_path)"))

    def test_post_implementation_constant_strings_do_not_expand_name_cycles(self):
        self.assertNotIn("PY-SQL", self.ids("db.execute(f'SELECT {{literal}}')"))
        self.assertNotIn("PY-XPATH", self.ids("tree.xpath(f'')"))
        self.assertIn("PY-SQL", self.ids("query=query+' suffix'\ndb.execute(query)"))
        # A FormattedValue remains dynamic even when its own value is literal;
        # this intentionally avoids general Python constant evaluation.
        self.assertIn("PY-SQL", self.ids('db.execute(f"SELECT {1}")'))

    def test_keyword_findings_have_locations_and_documentation(self):
        source = ("from flask import render_template_string as render, send_file as send, redirect as move\n"
                  "render(source=user_template)\nsend(path_or_file=user_path)\nmove(location=user_url)\n"
                  "db.execute('SELECT ' + '1')\n")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "views.py"
            path.write_text(source, encoding="utf-8")
            report = scanner.scan(path, self.rules)
        self.assertEqual(report["issues"], [])
        findings = {finding["rule"]: finding for finding in report["findings"]}
        self.assertEqual(set(findings), {"PY-TEMPLATE", "PY-FILE", "PY-REDIRECT"})
        for rid, line in (("PY-TEMPLATE", 2), ("PY-FILE", 3), ("PY-REDIRECT", 4)):
            finding = findings[rid]
            self.assertEqual((finding["path"], finding["line"]), ("views.py", line))
            self.assertEqual(finding["doc"], "docs/vulnerabilities/python.md#" + rid.lower())
            self.assertTrue(finding["reason"] and finding["detection"])


if __name__ == "__main__":
    unittest.main()
