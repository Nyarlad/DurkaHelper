import argparse
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("logger_test", ROOT / "integration/packmate_logger_smoke.py")
logger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(logger)


class LoggerTests(unittest.TestCase):
    def test_override_is_configuration_only_and_bounded(self):
        control = logger.overlay(False)["services"]["packmate"]
        treatment = logger.overlay(True)["services"]["packmate"]
        self.assertEqual(control["logging"], treatment["logging"])
        self.assertEqual(control["logging"]["options"], {"max-size": "1m", "max-file": "1"})
        self.assertEqual(treatment["volumes"], ["./logger.properties:/fixture/application.properties:ro"])
        self.assertNotIn("build", treatment)
        self.assertNotIn("privileged", treatment)
        self.assertNotIn("command", treatment)

    def test_preview_never_starts_docker(self):
        with tempfile.TemporaryDirectory() as folder:
            args = argparse.Namespace(workspace=str(Path(folder) / "new"), apply=False,
                postgres_image="postgres:15.2@sha256:" + "a" * 64, source=None)
            with patch.object(logger.pack.shared, "checked", side_effect=AssertionError("execution")):
                self.assertEqual(logger.prepare(args)["status"], "NOT_RUN")
            self.assertFalse(Path(args.workspace).exists())

    def test_mutation_needs_approval(self):
        with redirect_stdout(io.StringIO()), patch.object(logger, "prepare", side_effect=AssertionError("mutation")):
            self.assertEqual(logger.main(["prepare", "--workspace", "new", "--apply"]), 2)

    def test_bounded_logs_never_return_failed_command_output(self):
        with patch.object(logger.safe, "capture", return_value=(1, b"CANARY_SECRET")):
            with self.assertRaisesRegex(logger.Error, "^bounded synthetic log read failed$"):
                logger.logs("a" * 64)

    def test_container_identity_is_exactly_one_owned_id(self):
        with patch.object(logger.pack.shared, "checked", return_value=b""):
            with self.assertRaises(logger.Error):
                logger.app_identity(["docker"], {"project": "synthetic"})
        with patch.object(logger.pack.shared, "checked", side_effect=[b"a" * 64, b"other"]):
            with self.assertRaisesRegex(logger.Error, "ownership"):
                logger.app_identity(["docker"], {"project": "synthetic"})


if __name__ == "__main__":
    unittest.main()
