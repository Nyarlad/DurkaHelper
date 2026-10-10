"""JWT API binding regressions; token decoders and fixture code are not run."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jwt_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class JwtBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def ids(self, source):
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertEqual(issues, [])
        return {rid for rid, _ in hits}

    def test_known_positional_algorithms_and_options(self):
        for source, expected in [
            ("from jose import jwt\njwt.decode(token, key, algorithm_from_token)", "PY-JWT-ALGORITHMS"),
            ("from jose.jwt import decode as read\nread(token, key, ['HS256'], {'verify_signature': False})", "PY-JWT"),
            ("import jwt\njwt.decode_complete(token, key, ['HS256'], {'verify_exp': False})", "PY-JWT-CLAIMS"),
            ("from jwt import decode_complete as read\nread(\n token, key, dynamic_algorithms,\n)", "PY-JWT-ALGORITHMS"),
        ]:
            with self.subTest(source=source):
                self.assertIn(expected, self.ids(source))

    def test_jose_literal_algorithm_string_and_explicit_none(self):
        for source in [
            "from jose import jwt\njwt.decode(token, key, algorithms='HS256')",
            "from jose import jwt\njwt.decode(token, key, 'HS256')",
            "from jose import jwt\nalgorithm='HS256'\njwt.decode(token, key, algorithms=algorithm)",
            "from jose import jwt\njwt.decode(token, key, ['HS256'])",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("PY-JWT-ALGORITHMS", self.ids(source))
        for source in [
            "from jose import jwt\njwt.decode(token, key, None)",
            "import jwt\njwt.decode_complete(token, key, None)",
            "from jose import jwt\njwt.decode(token, key, algorithms=None)",
        ]:
            with self.subTest(source=source):
                self.assertIn("PY-JWT-ALGORITHMS", self.ids(source))

    def test_jose_required_claim_overrides_only_the_matching_verifier(self):
        for claim in ("exp", "nbf", "aud", "iss"):
            source = ("from jose import jwt\nrequired=True\n"
                      f"jwt.decode(token, key, options={{'verify_{claim}': False, 'require_{claim}': required}})")
            with self.subTest(claim=claim):
                self.assertNotIn("PY-JWT-CLAIMS", self.ids(source))
        self.assertIn("PY-JWT-CLAIMS", self.ids(
            "from jose import jwt\njwt.decode(token, key, options={'verify_aud': False, 'require_exp': True})"))
        self.assertIn("PY-JWT", self.ids(
            "from jose import jwt\njwt.decode(token, key, options={'verify_signature': False, 'require_exp': True})"))
        self.assertIn("PY-JWT-CLAIMS", self.ids(
            "import jwt\njwt.decode_complete(token, key, options={'verify_exp': False, 'require_exp': True})"))

    def test_legacy_verify_flag_is_not_assigned_to_known_modern_apis(self):
        self.assertIn("PY-JWT", self.ids("import jwt\njwt.decode(token, key, verify=False)"))
        for source in [
            "import jwt\njwt.decode_complete(token, key, verify=False)",
            "from jose import jwt\njwt.decode(token, key, verify=False)",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("PY-JWT", self.ids(source))
        self.assertIn("PY-JWT", self.ids(
            "import jwt\njwt.decode_complete(token, key, verify=False, options={'verify_signature': False})"))

    def test_unknown_positional_binding_and_explicit_duplicates_are_not_guessed(self):
        for source in [
            "import jwt\njwt.decode(token, key, user_algorithms, {'verify_signature': False})",
            "from jose import jwt\njwt.decode(token, *args, dynamic_algorithms, {'verify_signature': False})",
            "from jose import jwt\njwt.decode(token, key, dynamic_algorithms, algorithms=['HS256'])",
            "import jwt\njwt.decode_complete(token, key, ['HS256'], {'verify_signature': False}, options={'verify_signature': True})",
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.ids(source) & {"PY-JWT", "PY-JWT-CLAIMS", "PY-JWT-ALGORITHMS"})
        self.assertIn("PY-JWT", self.ids(
            "from jose import jwt\njwt.decode(token, *args, options={'verify_signature': False})"))

    def test_post_implementation_spreads_scalar_flags_and_rebinding(self):
        self.assertNotIn("PY-JWT-CLAIMS", self.ids(
            "from jose import jwt\njwt.decode(token, key, options={'verify_exp': False, **{'require_exp': True}})"))
        self.assertIn("PY-JWT-CLAIMS", self.ids(
            "from jose import jwt\njwt.decode(token, key, options={'verify_exp': False, 'require_exp': True, **{'require_exp': False}})"))
        self.assertIn("PY-JWT-CLAIMS", self.ids(
            "from jose import jwt\njwt.decode(token, key, options={'require_exp': True, **external, 'verify_exp': False})"))
        self.assertNotIn("PY-JWT", self.ids(
            "from jose import jwt\njwt.decode(token, key, options={'verify_signature': False, **external})"))
        self.assertIn("PY-JWT", self.ids(
            "from jose.jwt import decode as read\nflag=False\nread(token, key, **{'options': {'verify_signature': flag, 'require_signature': True}})"))
        self.assertNotIn("PY-JWT", self.ids(
            "from jose.jwt import decode as read\nread=custom_decoder\nread(token, key, options={'verify_signature': False})"))

    def test_invalid_jwt_binding_still_scans_argument_calls(self):
        source = "from jose.jwt import decode\ndecode(token, key, dynamic_algorithms, algorithms=eval(text))"
        ids = self.ids(source)
        self.assertIn("PY-EVAL", ids)
        self.assertFalse(ids & {"PY-JWT", "PY-JWT-CLAIMS", "PY-JWT-ALGORITHMS"})

    def test_positional_jwt_findings_have_report_locations(self):
        source = ("from jose import jwt as tokens\n"
                  "tokens.decode(token, key, user_algorithms, {'verify_signature': False, 'verify_exp': False})\n")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "auth.py"
            path.write_text(source, encoding="utf-8")
            report = scanner.scan(path, self.rules)
        self.assertEqual(report["issues"], [])
        findings = {finding["rule"]: finding for finding in report["findings"]}
        self.assertEqual(set(findings), {"PY-JWT", "PY-JWT-CLAIMS", "PY-JWT-ALGORITHMS"})
        for rid, finding in findings.items():
            self.assertEqual((finding["path"], finding["line"]), ("auth.py", 2))
            self.assertEqual(finding["doc"], "docs/vulnerabilities/python.md#" + rid.lower())
            self.assertTrue(finding["reason"] and finding["detection"])


if __name__ == "__main__":
    unittest.main()
