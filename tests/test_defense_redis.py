"""Redis ACL token-order checks on inert config text; Redis is never run."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("redis_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class RedisAclTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def signal(self, source):
        hits, issues = scanner.scan_text(source, "config", self.rules)
        self.assertEqual(issues, [])
        return {line for rid, line in hits if rid == "CFG-REDIS-ACL"}

    def test_ordered_enabled_passwordless_state(self):
        for source in [
            "user default on nopass ~* &* +@all",
            "user service off resetpass on nopass +get ~app:*",
            "user service >secret on nopass",
            "user service #" + "a" * 64 + " on nopass",
            "user service ON NOPASS",
            "user service on  nopass   ~*",
        ]:
            with self.subTest(source=source):
                self.assertTrue(self.signal(source))
        for source in [
            "user service on nopass off",
            "user service on nopass resetpass",
            "user service on nopass reset on",
            "user service on nopass >secret",
            "user service on nopass >",
            "user service on nopass #" + "a" * 64,
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.signal(source))

    def test_password_username_and_access_patterns_are_not_flags(self):
        for source in [
            "user nopass on >secret",
            "user on nopass",
            "user service on >nopass",
            "user service >on >nopass",
            "user service on ~nopass +get",
            "user service on &nopass +subscribe",
            "user service on >on >nopass ~* &* +@all",
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.signal(source))

    def test_unsupported_or_invalid_token_forms_remain_manual(self):
        for source in [
            'user "service" on nopass',
            "user service on\tnopass",
            "user service on nopass \\escaped",
            "user service on nopass (+get ~*)",
            "user service on nopass unknownflag",
            "user service on nopass #not-a-valid-hash",
            "user service on nopass #" + "A" * 64,
            "user  service on nopass",
            "USER service on nopass",
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.signal(source))

    def test_modifiers_after_600_characters_are_not_discarded(self):
        padding = "+get " * 140
        self.assertFalse(self.signal("user service on nopass " + padding + "off"))
        self.assertFalse(self.signal("user service on nopass " + padding + ">secret"))
        self.assertTrue(self.signal("user service off resetpass " + padding + "on nopass"))

    def test_oversized_physical_line_is_partial_without_prefix_signal(self):
        source = "user service on nopass " + "+get " * 1700 + "off"
        hits, issues = scanner.scan_text(source, "config", self.rules)
        self.assertNotIn("CFG-REDIS-ACL", {rid for rid, _ in hits})
        self.assertIn("regex_line_limit", issues)

    def test_post_implementation_removals_patterns_and_unknown_initial_state(self):
        self.assertTrue(self.signal("user service on nopass <old-password !" + "b" * 64))
        self.assertTrue(self.signal("user service on nopass ~>password &>channel"))
        self.assertFalse(self.signal("user service off nopass ~on"))
        self.assertFalse(self.signal("user service nopass"))
        # The scanner intentionally does not merge multiple declarations into
        # an effective ACL, even when they name the same user.
        self.assertFalse(self.signal("user service on\nuser service nopass"))

    def test_non_ascii_or_vertical_whitespace_is_not_trimmed_into_a_flag(self):
        for suffix in ("\u00a0", "\v"):
            with self.subTest(suffix=repr(suffix)):
                self.assertFalse(self.signal("user service on nopass" + suffix))
        self.assertTrue(self.signal(" \tuser service on nopass\t\r\n"))

    def test_report_metadata_never_contains_acl_password_tokens(self):
        source = "# inert fixture\nuser service on >DO_NOT_REPORT_THIS_PASSWORD nopass ~app:* +get\n"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "users.acl"
            path.write_text(source, encoding="utf-8")
            report = scanner.scan(path, self.rules)
        self.assertEqual(report["issues"], [])
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual((finding["rule"], finding["path"], finding["line"]),
                         ("CFG-REDIS-ACL", "users.acl", 2))
        self.assertEqual(finding["doc"], "docs/vulnerabilities/configuration.md#cfg-redis-acl")
        self.assertTrue(finding["reason"] and finding["detection"])
        self.assertNotIn("DO_NOT_REPORT_THIS_PASSWORD", json.dumps(report))

    def test_oversized_acl_file_has_partial_exit_and_no_source_leak(self):
        source = "user service on nopass " + "+get " * 1700 + ">DO_NOT_REPORT_THIS_PASSWORD"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "users.acl"
            path.write_text(source, encoding="utf-8")
            report = scanner.scan(path, self.rules)
        self.assertEqual(report["exit_code"], 2)
        self.assertTrue(report["partial"])
        self.assertEqual(report["findings"], [])
        self.assertIn("regex_line_limit", {issue["reason"] for issue in report["issues"]})
        self.assertNotIn("DO_NOT_REPORT_THIS_PASSWORD", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
