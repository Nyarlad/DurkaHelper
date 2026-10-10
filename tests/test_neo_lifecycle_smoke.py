"""Harmless lifecycle contract tests; Docker execution remains separately gated."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("life_test", ROOT / "integration/neo_lifecycle_smoke.py")
life = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(life)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.state = {"id": "dh-life-" + "a" * 12, "flag": "A" * 31 + "="}

    def test_payload_has_no_network_or_parameter_expansion(self):
        script = life.payload(self.state["flag"])
        self.assertTrue(script.startswith(b"#!/bin/sh\n"))
        for word in (b"curl", b"wget", b"socket", b"$", b"exec", b"/dev", b"cat"):
            self.assertNotIn(word, script)
        self.assertEqual(script.count(self.state["flag"].encode()), 1)

    def test_payload_rejects_injection(self):
        for value in ("A" * 31 + "='", "A" * 30 + "\n=", "x" * 31 + "="):
            with self.assertRaises(life.Error):
                life.payload(value)

    def test_client_args_fixed_allowlist_and_safe_container(self):
        argv = life.arguments(Path("/fixture"), self.state, Path("/release/neo"), "alpine@sha256:" + "a" * 64,
                              "lab_fixture", "generated-worker", "worker")
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("65534:65534", argv)
        self.assertIn("--log-driver=none", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--network=host", argv)
        self.assertEqual(argv[-5:], ["run", "--jobs", "1", "--endless-jobs", "0"])
        with self.assertRaises(life.Error):
            life.arguments(Path("/fixture"), self.state, Path("/release/neo"), "image", "network", "name", "broadcast")

    def test_add_is_disabled_and_bounded(self):
        argv = life.arguments(Path("/fixture"), self.state, Path("/release/neo"), "image", "network", "name", "add")
        self.assertIn("--disabled", argv)
        self.assertIn("3s", argv)
        self.assertIn("1h", argv)
        self.assertNotIn("--endless", argv)

    def test_cleanup_rejects_wrong_owner(self):
        with mock.patch.object(life.shared, "checked", return_value=b"different") as checked:
            with self.assertRaises(life.Error):
                life.cleanup("name", self.state["id"])
            self.assertEqual(checked.call_count, 1)

    def test_failing_client_is_cleaned_and_output_suppressed(self):
        with mock.patch.object(life.shared, "checked"), mock.patch.object(life.release, "capture", return_value=(1, b"secret-canary")), mock.patch.object(life, "cleanup") as cleanup:
            with self.assertRaises(life.Error) as error:
                life.run_client(Path("/fixture"), self.state, Path("/release/neo"), "image", "network", "info")
            self.assertNotIn("secret-canary", str(error.exception))
            cleanup.assert_called_once()

    def test_acceptance_requires_correct_neo_origin(self):
        row = {"flag": self.state["flag"], "status": "ACCEPTED", "sploit": "[neo] " + self.state["id"]}
        with mock.patch.object(life.shared, "request", return_value=(200, json.dumps({"flags": [row]}).encode())):
            self.assertTrue(life.accepted(8080, self.state["flag"], self.state["id"], timeout=1))

    def test_prepare_preview_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new"
            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(life.shared, "checked", side_effect=AssertionError("executed")):
                self.assertEqual(life.main(["prepare", "--workspace", str(path)]), 0)
            self.assertFalse(path.exists())

    def test_apply_requires_approval(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(life.main(["prepare", "--workspace", "unused", "--apply"]), 2)


if __name__ == "__main__":
    unittest.main()
