"""Publication checks are bounded and never print the matched value."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publication", ROOT / "scripts/publication_check.py")
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)


class PublicationChecks(unittest.TestCase):
    def test_keys_tokens_homes_and_private_terms_are_locations_only(self):
        samples = [(b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----", "private-key"),
                   (b"ghp_" + b"A" * 36, "access-token"),
                   (b"/home/" + b"operator-canary", "personal-home"),
                   (b"ssh-ed25519 " + b"A" * 48, "ssh-identity"),
                   (b"https://" + b"somebody:canary-value@example.invalid", "url-credentials")]
        for source, category in samples:
            with self.subTest(category=category):
                rows = publication.scan_bytes("example.txt", source)
                self.assertEqual(rows[0]["category"], category)
                self.assertNotIn(source.decode(), str(rows))
        rows = publication.scan_bytes("example.txt", b"private-label-canary", private_terms=(b"private-label-canary",))
        self.assertEqual(rows[0]["category"], "private-environment-reference")
        self.assertNotIn("private-label-canary", str(rows))

    def test_explicit_neutral_home_placeholders_are_not_personal(self):
        for source in (b"/home/USER", b"/Users/example", b"C:/Users/USERNAME"):
            self.assertEqual(publication.scan_bytes("doc.md", source), [])

    def test_runtime_files_and_assets_need_review(self):
        for path in (".ssh/identity", "local/data.json", "traffic.pcap", ".env", ".codex-remote-attachments/screenshot.png"):
            self.assertEqual(publication.scan_bytes(path, b"")[0]["category"], "private-or-runtime-file")
        self.assertEqual(publication.scan_bytes("screen.png", b"png")[0]["category"], "manual-asset-review")

    def test_path_traversal_and_ref_injection_are_rejected(self):
        for path in ("../somewhere", "/absolute", "a/./b", "a\\b", "C:/data", "a\nb"):
            with self.assertRaises(publication.CheckError):
                publication.safe_path(path)

    def make_repo(self, root):
        def run(*args):
            result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
            if result.returncode:
                self.fail("temporary Git repository operation failed")
        run("init", "--quiet")
        run("config", "user.name", "Synthetic Fixture")
        run("config", "user.email", "fixture@example.invalid")
        return run

    def test_selected_history_catches_removed_data_without_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_repo(root)
            source = b"ghp_" + b"B" * 36
            (root / "example.txt").write_bytes(source)
            run("add", "example.txt")
            run("commit", "--quiet", "-m", "synthetic first")
            (root / "example.txt").write_text("clean\n")
            run("add", "example.txt")
            run("commit", "--quiet", "-m", "synthetic replacement")
            self.assertEqual(publication.audit(root)["exit_code"], 0)
            result = publication.audit(root, history=True)
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(result["scope"]["commits"], 2)
            self.assertNotIn(source.decode(), str(result))
            self.assertEqual(publication.audit(root, history=True, max_commits=1)["exit_code"], 2)

    def test_allowlist_is_exact_line_digest_not_blanket_test_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_repo(root)
            source = b"ghp_" + b"C" * 36
            (root / "fixture.txt").write_bytes(source)
            exception = {"path": "fixture.txt", "category": "access-token",
                         "fingerprint": hashlib.sha256(source).hexdigest(), "reason": "Synthetic negative-test canary, not an access credential."}
            self.assertEqual(publication.audit(root, allowlist=[exception])["exit_code"], 0)
            (root / "fixture.txt").write_bytes(source + b" modified")
            self.assertEqual(publication.audit(root, allowlist=[exception])["exit_code"], 1)
            with self.assertRaises(publication.CheckError):
                publication.audit(root, allowlist=[{"path": "*", "category": "*"}])


if __name__ == "__main__":
    unittest.main()
