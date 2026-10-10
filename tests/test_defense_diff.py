"""Report comparison is inert, bounded and explicit about incomplete evidence."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("defense_diff", ROOT / "scripts/defense_diff.py")
diff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diff)
SCAN_SPEC = importlib.util.spec_from_file_location("diff_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SCAN_SPEC)
SCAN_SPEC.loader.exec_module(scanner)


def scan_scope(**changes):
    value = {"schema": "durkahelper.scanner-scope.v1",
             "root": "sha256:" + "a" * 64,
             "rules_sha256": "b" * 64,
             "exclude": [],
             "limits": {"max_bytes": 1048576, "max_files": 20000,
                        "max_findings": 10000},
             "path_semantics": "root-relative-posix.v1"}
    value.update(changes)
    if "sha256" not in changes:
        value["sha256"] = hashlib.sha256(json.dumps(
            value, ensure_ascii=True, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
    return value


def report(findings=(), **changes):
    value = {"tool": "DurkaHelper defense_scan", "version": "1.6.0", "offline": True,
             "created_at": "2026-10-09T00:00:00.000Z", "scope": scan_scope(),
             "findings": list(findings), "issues": [], "partial": False,
             "exit_code": 1 if findings else 0}
    value.update(changes)
    return value


def finding(path="service.py", line=3, rule="PY-EVAL", **extra):
    return {"path": path, "line": line, "rule": rule, **extra}


def compare(before, after):
    return diff.compare_reports(diff.validate_report(before), diff.validate_report(after))


class ReportDiffTests(unittest.TestCase):
    def test_partitions_are_sorted_and_descriptions_do_not_define_identity(self):
        old = report([finding("z.py"), finding("same.py", reason="old explanation")])
        new = report([finding("b.py"), finding("same.py", reason="new explanation"), finding("a.py")])
        result = compare(old, new)
        self.assertEqual(result["new"], [finding("a.py"), finding("b.py")])
        self.assertEqual(result["existing"], [finding("same.py")])
        self.assertEqual(result["not_observed"], [finding("z.py")])
        self.assertEqual(result["counts"], {"new": 2, "existing": 1, "not_observed": 1})
        self.assertEqual(result["exit_code"], 1)
        self.assertNotIn("fixed", result)
        self.assertTrue(result["scope_verified"])

    def test_shifted_lines_and_renamed_files_are_not_silently_matched(self):
        for current in (finding(line=4), finding(path="renamed.py"), finding(rule="PY-SQL")):
            with self.subTest(current=current):
                result = compare(report([finding()]), report([current]))
                self.assertEqual(result["counts"], {"new": 1, "existing": 0, "not_observed": 1})

    def test_identical_and_absent_findings_exit_zero_without_security_verdict(self):
        for after in (report([finding()]), report()):
            result = compare(report([finding()]), after)
            self.assertEqual(result["exit_code"], 0)
            self.assertIn("does not prove a fix", result["note"])
        self.assertEqual(compare(report(), report())["counts"], {"new": 0, "existing": 0, "not_observed": 0})

    def test_partial_and_changed_versions_keep_findings_and_exit_two(self):
        cases = [(report(partial=True, exit_code=2), report([finding()]), "before_partial"),
                 (report([finding()]), report(partial=True, exit_code=2), "after_partial"),
                 (report(), report([finding()], version="1.6.1"), "scanner_version_changed"),
                 (report(), report(issues=[{"reason": "file_limit_reached"}]), "after_partial"),
                 (report(), report(exit_code=2), "after_partial")]
        for before, after, warning in cases:
            with self.subTest(warning=warning):
                result = compare(before, after)
                self.assertEqual(result["exit_code"], 2)
                self.assertTrue(result["partial"])
                self.assertIn(warning, result["warnings"])
                self.assertEqual(len(result["new"]), len(after["findings"]))

    def test_missing_or_changed_scope_refuses_clean_verdict(self):
        missing = report()
        missing.pop("scope")
        missing.pop("created_at")
        result = compare(missing, report())
        self.assertEqual(result["exit_code"], 2)
        self.assertFalse(result["scope_verified"])
        self.assertIn("scope_unverified", result["warnings"])
        self.assertIsNone(result["before"]["scope_sha256"])

        variants = [
            scan_scope(root="sha256:" + "c" * 64),
            scan_scope(rules_sha256="d" * 64),
            scan_scope(exclude=["generated/**"]),
            scan_scope(limits={"max_bytes": 2048, "max_files": 20000,
                               "max_findings": 10000}),
        ]
        for changed in variants:
            with self.subTest(scope=changed):
                result = compare(report(), report(scope=changed))
                self.assertEqual(result["exit_code"], 2)
                self.assertFalse(result["scope_verified"])
                self.assertIn("scope_changed", result["warnings"])

    def test_only_location_and_rule_are_copied_from_untrusted_findings(self):
        secret = "DO_NOT_ECHO_SENSITIVE_REPORT_FIELD"
        payload = finding(source=secret, reason=secret, title=secret, doc=secret,
                          patch_example={"before": secret}, arbitrary=secret)
        before = report([payload], issues=[{"path": secret, "reason": secret}])
        result = compare(before, report([payload]))
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["existing"], [finding()])
        self.assertEqual(result["before"]["issue_count"], 1)

    def test_invalid_report_shapes_and_findings_are_rejected(self):
        bad = [None, [], {}, {"error": "invalid"}, report(tool="another tool"),
               report(offline=False), report(partial=0), report(version="secret value"),
               report(exit_code=True), report(exit_code=3), report(issues={}), {**report(), "findings": {}},
               report([None]), report([finding(line=True)]), report([finding(line=0)]),
               report([finding(line="1")]), report([finding(rule="arbitrary text")]),
               report([finding(path="")]), report([finding(path="nul\x00path")]),
               report([finding(), finding()])]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    diff.validate_report(value)
        with patch.object(diff, "MAX_FINDINGS", 1):
            with self.assertRaises(ValueError):
                diff.validate_report(report([finding(), finding(line=4)]))

    def test_invalid_timestamps_and_scopes_are_rejected(self):
        malformed_scopes = [
            {},
            scan_scope(root="/secret/source"),
            scan_scope(rules_sha256="b" * 63),
            scan_scope(exclude=["z", "a"]),
            scan_scope(exclude=["a", "a"]),
            scan_scope(limits={"max_bytes": True, "max_files": 1, "max_findings": 1}),
            scan_scope(sha256="0" * 64),
        ]
        for value in malformed_scopes:
            with self.subTest(scope=value), self.assertRaises(ValueError):
                diff.validate_report(report(scope=value))
        for timestamp in (None, "", "2026-10-09", "2026-10-09T00:00:00+03:00"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                diff.validate_report(report(created_at=timestamp))

    def test_bounded_utf8_bom_reader_and_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            content = json.dumps(report([finding(path="путь.py")])).encode("utf-8-sig")
            path.write_bytes(content)
            self.assertEqual(len(diff.load_report(path, len(content))["findings"]), 1)
            with self.assertRaises(ValueError):
                diff.load_report(path, len(content) - 1)
            path.write_text('{"tool":"one", "tool":"two"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                diff.load_report(path)

    def test_report_change_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(report()), encoding="utf-8")
            before = path.stat()
            after = type("ChangedMetadata", (), {
                "st_dev": before.st_dev,
                "st_ino": before.st_ino,
                "st_mode": before.st_mode,
                "st_size": before.st_size,
                "st_mtime_ns": before.st_mtime_ns + 1,
                "st_ctime_ns": getattr(before, "st_ctime_ns", 0),
            })()
            with patch.object(diff.os, "fstat", side_effect=[before, after]):
                with self.assertRaisesRegex(ValueError, "changed while reading"):
                    diff.load_report(path)

    def test_symlinks_and_non_regular_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text(json.dumps(report()), encoding="utf-8")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError):
                pass
            else:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    diff.load_report(link)
            with self.assertRaises((ValueError, OSError)):
                diff.load_report(temp)

    def test_leaf_swap_to_symlink_during_canonicalization_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(report()), encoding="utf-8")
            regular = path.lstat()
            symlink = type("SymlinkMetadata", (), {
                "st_dev": regular.st_dev,
                "st_ino": regular.st_ino,
                "st_mode": stat.S_IFLNK | 0o777,
            })()
            with patch.object(Path, "lstat", side_effect=[regular, symlink]), \
                 patch.object(diff.os, "open") as opened:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    diff.load_report(path)
            opened.assert_not_called()

    def test_cli_excessive_byte_limit_returns_a_sanitized_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(report()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = diff.main([str(path), str(path), "--max-bytes", str(2**100), "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {
            "error": "invalid_or_unreadable_report", "type": "OverflowError", "exit_code": 2})

    def test_cli_errors_do_not_echo_malformed_input_or_exception_details(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            for raw in (b'{"secret":"DO_NOT_ECHO"', b'\xffDO_NOT_ECHO', b"[" * 2000):
                path.write_bytes(raw)
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    code = diff.main([str(path), str(path), "--json"])
                self.assertEqual(code, 2)
                self.assertNotIn("DO_NOT_ECHO", output.getvalue())
                self.assertEqual(json.loads(output.getvalue())["error"], "invalid_or_unreadable_report")

    def test_text_output_escapes_control_characters_and_existing_is_optional(self):
        with tempfile.TemporaryDirectory() as temp:
            before, after = Path(temp) / "before.json", Path(temp) / "after.json"
            before.write_text(json.dumps(report([finding()])), encoding="utf-8")
            after.write_text(json.dumps(report([finding(), finding(path="evil\n\x1b[31m.py")])), encoding="utf-8")
            for option, visible in (([], False), (["--show-existing"], True)):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    code = diff.main([str(before), str(after), *option])
                text = output.getvalue()
                self.assertEqual(code, 1)
                self.assertNotIn("evil\n", text)
                self.assertNotIn("\x1b", text)
                self.assertEqual("EXISTING:" in text, visible)

    def test_real_scans_can_be_compared_without_network_execution_or_input_writes(self):
        rules = scanner.load_rules()
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "input.py"
            source.write_text("eval(user_input)\n", encoding="utf-8")
            old = scanner.scan(source, rules)
            source.write_text("print(user_input)\n", encoding="utf-8")
            new = scanner.scan(source, rules)
            before, after = Path(temp) / "before.json", Path(temp) / "after.json"
            before.write_text(json.dumps(old), encoding="utf-8")
            after.write_text(json.dumps(new), encoding="utf-8")
            snapshots = {path: path.read_bytes() for path in (before, after, source)}
            with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                 patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
                 patch("subprocess.Popen", side_effect=AssertionError("execution forbidden")), \
                 patch("os.system", side_effect=AssertionError("execution forbidden")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                code = diff.main([str(before), str(after), "--json"])
            result = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(result["not_observed"], [finding("input.py", 1)])
            for path, content in snapshots.items():
                self.assertEqual(path.read_bytes(), content)

    def test_isolated_cli_works_outside_repository(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.json"
            path.write_text(json.dumps(report([finding(path="never-open-this.py")])), encoding="utf-8")
            completed = subprocess.run([sys.executable, "-I", "-S", str(ROOT / "scripts/defense_diff.py"),
                                        str(path), str(path), "--json"], cwd=temp, capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
            self.assertEqual(json.loads(completed.stdout)["counts"]["existing"], 1)


if __name__ == "__main__":
    unittest.main()
