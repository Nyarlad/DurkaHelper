"""Cross-module failures must retain redaction and scoped cleanup."""
import argparse
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tested_host_smoke", ROOT / "integration/packmate_host_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class HostSmokeErrors(unittest.TestCase):
    def test_distinct_synthetic_errors_are_redacted_by_cli(self):
        self.assertIsNot(smoke.Error, smoke.synthetic.Error)
        output = io.StringIO()
        with patch.object(smoke.synthetic, "fixture", side_effect=smoke.synthetic.Error("SECRET-CANARY")), redirect_stdout(output):
            code = smoke.main(["run", "--workspace", "unused"])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET-CANARY", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")

    def test_synthetic_traffic_and_cleanup_errors_do_not_skip_remaining_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {"project": "dh-live-test-" + "a" * 12, "daemon_id": "synthetic-engine",
                     "marker": "b" * 24, "python_image": "synthetic-pinned-image"}
            network, server = "c" * 64, "d" * 64
            args = argparse.Namespace(workspace=root, apply=True, capture_approved=True, approval_id="test")
            metadata = {"internal": True, "containers": {server: {"IPv4Address": "192.0.2.2/24"}}}
            link = [{"ifindex": 9, "address": "02:00:00:00:00:01"}]
            replies = [("sha256:" + "e" * 64 + ";linux;amd64").encode(), b"", json.dumps(metadata).encode(), json.dumps(link).encode()]
            with patch.object(smoke.synthetic, "fixture", return_value=(root, state)), \
                 patch.object(smoke.sys, "platform", "linux"), patch.object(smoke.host.live, "daemon"), \
                 patch.object(smoke.shared, "checked", side_effect=replies), patch.object(smoke.shared, "write"), \
                 patch.object(smoke.synthetic, "identifier", side_effect=[network, server]), \
                 patch.object(smoke.synthetic, "private_command", return_value=["synthetic"]), \
                 patch.object(smoke, "free_port", side_effect=[65000, 55432]), \
                 patch.object(smoke.host, "prepare"), patch.object(smoke.host, "execute") as execute, \
                 patch.object(smoke.host.live, "request", return_value=True), \
                 patch.object(smoke.synthetic, "configure", side_effect=smoke.synthetic.Error("SECRET-CANARY")), \
                 patch.object(smoke.synthetic, "reconcile_resource", side_effect=[smoke.synthetic.Error("PRIVATE-CLEANUP"), None]) as cleanup:
                report = smoke.run(args)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["phase"], "traffic-first")
            self.assertFalse(report["cleanup"]["source"])
            self.assertTrue(report["cleanup"]["network"])
            self.assertEqual(cleanup.call_count, 2)
            self.assertEqual(cleanup.call_args.args, ("network", state["project"], state["project"]))
            self.assertEqual(execute.call_args.args[0].action, "down")
            self.assertNotIn("SECRET-CANARY", json.dumps(report))
            self.assertNotIn("PRIVATE-CLEANUP", json.dumps(report))


    def test_bootstrap_is_only_forwarded_to_first_up_and_hash_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {"project": "dh-live-test-" + "a" * 12, "daemon_id": "synthetic-engine",
                     "marker": "b" * 24, "python_image": "synthetic-pinned-image"}
            network, server = "c" * 64, "d" * 64
            args = argparse.Namespace(workspace=root, apply=True, capture_approved=True, approval_id="test",
                                      bootstrap_images="private-approved-images.json", expected_images_sha256="a" * 64)
            metadata = {"internal": True, "containers": {server: {"IPv4Address": "192.0.2.2/24"}}}
            link = [{"ifindex": 9, "address": "02:00:00:00:00:01"}]
            calls = []
            def execute(params):
                calls.append(copy.copy(params))
                return {"images_sha256": args.expected_images_sha256}
            def checked(argv, **kwargs):
                if argv[:3] == ["docker", "image", "inspect"]:
                    return ("sha256:" + "e" * 64 + ";linux;amd64").encode()
                if argv[:3] == ["docker", "network", "inspect"]:
                    return json.dumps(metadata).encode()
                if argv[0] == "ip":
                    return json.dumps(link).encode()
                return b""
            with patch.object(smoke.synthetic, "fixture", return_value=(root, state)), \
                 patch.object(smoke.sys, "platform", "linux"), patch.object(smoke.host.live, "daemon"), \
                 patch.object(smoke.shared, "checked", side_effect=checked), patch.object(smoke.shared, "write"), \
                 patch.object(smoke.synthetic, "identifier", side_effect=[network, server, "f" * 64, "a" * 64]), \
                 patch.object(smoke.synthetic, "private_command", return_value=["synthetic"]), \
                 patch.object(smoke, "free_port", side_effect=[65000, 55432]), \
                 patch.object(smoke.host, "prepare"), patch.object(smoke.host, "execute", side_effect=execute), \
                 patch.object(smoke.host, "workspace", return_value=(root / "deployment", {"project": state["project"]})), \
                 patch.object(smoke.host, "owned"), patch.object(smoke.host.live, "request", return_value=True), \
                 patch.object(smoke.synthetic, "configure", return_value=["pattern"]), \
                 patch.object(smoke.synthetic, "collect", return_value={"request_response": True}), \
                 patch.object(smoke.synthetic, "reconcile_resource"):
                report = smoke.run(args)
            self.assertEqual(report["status"], "PASS")
            self.assertTrue(report["checks"]["fresh_offline_image_bootstrap"])
            self.assertTrue(report["checks"]["restart_preserved_streams"])
            self.assertEqual([item.action for item in calls], ["up", "up", "down"])
            self.assertEqual(calls[0].bootstrap_images, args.bootstrap_images)
            self.assertIsNone(calls[1].bootstrap_images)
            self.assertEqual(calls[1].expected_images_sha256, args.expected_images_sha256)


if __name__ == "__main__":
    unittest.main()
