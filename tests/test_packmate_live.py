import argparse
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_live", ROOT / "deployment/packmate_live.py")
live = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live)


def config():
    return {"schema": live.SCHEMA, "daemon_id": "test-daemon-01", "capture_container": "a" * 64,
            "network_id": "b" * 64, "capture_scope": "synthetic-scope", "interface": "eth0",
            "local_ip": "172.29.0.2", "bind_address": "127.0.0.1", "ui_port": 45000,
            "tcp_timeout_seconds": 4, "udp_timeout_seconds": 3, "timeout_check_seconds": 1,
            "retention_minutes": 60, "cleanup_interval_minutes": 1}


SECRET = {"username": "synthetic-user", "password": "a" * 30, "db_password": "b" * 30}
PROJECT = "dh-live-012345abcdef"


def scope_metadata():
    return {"id": "a" * 64, "running": True, "mode": "b" * 64,
            "networks": {"synthetic": {"NetworkID": "b" * 64, "IPAddress": "172.29.0.2"}},
            "ports": {"65000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "45000"}]}, "owner": "synthetic-scope"}


class LiveTests(unittest.TestCase):
    def test_profile_requires_exact_scoped_namespace(self):
        self.assertEqual(live.profile(config()), config())
        cases = {"schema": "host-mode", "capture_container": "target-name", "network_id": "bridge", "capture_scope": "x\nsecret",
                 "interface": "any", "local_ip": "127.0.0.1", "bind_address": "0.0.0.0", "ui_port": True,
                 "tcp_timeout_seconds": 0, "retention_minutes": 1441}
        for key, value in cases.items():
            with self.subTest(key=key), self.assertRaises((live.Error, ValueError)):
                live.profile(dict(config(), **{key: value}))
        with self.assertRaises(live.Error):
            live.profile(dict(config(), network_mode="host"))

    def test_credentials_reject_properties_injection(self):
        live.credentials(SECRET)
        for value in ("short", "REPLACE_long_password_not_real", "a" * 20 + "\nlogging.level=ALL"):
            with self.assertRaises(live.Error):
                live.credentials(dict(SECRET, password=value))

    def test_properties_real_live_timeout_cleanup_and_secret_logger(self):
        data = live.properties(config(), SECRET, PROJECT).decode()
        self.assertIn("packmate.capture-mode=LIVE\n", data)
        self.assertNotIn("pcap-file", data)
        self.assertIn("packmate.timeout.tcp-stream-timeout=4\n", data)
        self.assertIn("packmate.cleanup.enabled=true\n", data)
        self.assertIn("logging.level." + live.kit.LOGGER + "=OFF\n", data)
        self.assertIn("server.address=172.29.0.2\n", data)

    def test_compose_no_privileged_or_host_networking_database_unpublished(self):
        value = live.compose_spec(config(), SECRET, PROJECT)
        app, database = value["services"]["packmate"], value["services"]["db"]
        self.assertNotIn("privileged", app)
        self.assertEqual(app["cap_drop"], ["ALL"])
        self.assertEqual(app["cap_add"], ["NET_RAW"])
        self.assertEqual(app["network_mode"], "container:" + "a" * 64)
        self.assertNotIn("ports", app)
        self.assertNotIn("ports", database)
        self.assertEqual(value["networks"]["capture"], {"external": True, "name": "b" * 64})
        self.assertEqual(app["image"], live.kit.PACKMATE)
        self.assertEqual(app["logging"], {"driver": "none"})
        self.assertEqual(app["labels"], {live.LABEL: PROJECT})
        self.assertEqual(app["restart"], "no")

    def test_scope_checks_exact_target_network_binding_and_labels(self):
        network = {"id": "b" * 64, "driver": "bridge", "owner": "synthetic-scope"}
        with mock.patch.object(live.shared, "checked", side_effect=[json.dumps(scope_metadata()).encode(), json.dumps(network).encode()]) as calls:
            live.capture_scope(config())
        self.assertEqual(len(calls.call_args_list), 2)
        for call in calls.call_args_list:
            self.assertIn("inspect", call.args[0])
            self.assertNotIn(".Config.Env", " ".join(call.args[0]))

    def test_scope_rejects_unapproved_network_container_or_publication(self):
        for key, value in (("id", "c" * 64), ("running", False), ("mode", "host"), ("mode", "container:other"),
                           ("owner", "other"), ("networks", {}), ("ports", {"65000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "45000"}]})):
            data = dict(scope_metadata(), **{key: value})
            with self.subTest(key=key, value=value), mock.patch.object(live.shared, "checked", return_value=json.dumps(data).encode()), self.assertRaises(live.Error):
                live.capture_scope(config())

    def test_scope_rejects_changed_ip_and_foreign_bridge(self):
        data = scope_metadata()
        data["networks"]["synthetic"]["IPAddress"] = "172.29.0.3"
        with mock.patch.object(live.shared, "checked", return_value=json.dumps(data).encode()), self.assertRaises(live.Error):
            live.capture_scope(config())
        for network in ({"id": "b" * 64, "driver": "host", "owner": "synthetic-scope"},
                        {"id": "b" * 64, "driver": "bridge", "owner": "someone-else"}):
            with mock.patch.object(live.shared, "checked", side_effect=[json.dumps(scope_metadata()).encode(), json.dumps(network).encode()]), self.assertRaises(live.Error):
                live.capture_scope(config())

    def test_daemon_rejects_other_identity_desktop_and_architecture(self):
        for value in (b"other-daemon;linux;amd64;Ubuntu", b"test-daemon-01;linux;aarch64;Ubuntu",
                      b"test-daemon-01;linux;x86_64;Docker Desktop"):
            with mock.patch.object(live.shared, "checked", return_value=value), self.assertRaises(live.Error):
                live.daemon(config())
        with mock.patch.object(live.shared, "checked", return_value=b"test-daemon-01;linux;x86_64;Ubuntu"):
            live.daemon(config())

    def test_prepare_preview_does_not_contact_daemon_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(profile="private-profile", credentials="private-credentials", workspace=Path(directory) / "new", apply=False)
            with mock.patch.object(live.kit, "load", side_effect=[config(), SECRET]), mock.patch.object(live.shared, "checked") as command:
                result = live.prepare(args)
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertFalse(args.workspace.exists())
            command.assert_not_called()

    def test_apply_gate_precedes_io_and_output_excludes_secret(self):
        output = io.StringIO()
        with redirect_stdout(output), mock.patch.object(live.kit, "load") as read:
            code = live.main(["prepare", "--workspace", "missing", "--apply"])
        self.assertEqual(code, 2)
        read.assert_not_called()
        self.assertNotIn(SECRET["password"], output.getvalue())

    def test_capture_approval_required_before_any_daemon_operation(self):
        state = {"project": PROJECT, "profile": config(), "credentials": SECRET}
        args = argparse.Namespace(workspace="any", action="up", apply=True, capture_approval="wrong")
        with mock.patch.object(live, "workspace", return_value=(Path("fixture"), state)), mock.patch.object(live.sys, "platform", "linux"), mock.patch.object(live.shared, "checked") as command, self.assertRaises(live.Error):
            live.execute(args)
        command.assert_not_called()

    def test_down_requires_no_capture_reapproval_and_never_removes_owner(self):
        state = {"project": PROJECT, "profile": config(), "credentials": SECRET}
        args = argparse.Namespace(workspace="any", action="down", apply=True, capture_approval=None)
        with mock.patch.object(live, "workspace", return_value=(Path("fixture"), state)), mock.patch.object(live.sys, "platform", "linux"), mock.patch.object(live, "daemon"), mock.patch.object(live, "owned"), mock.patch.object(live.shared, "checked") as command:
            result = live.execute(args)
        self.assertTrue(result["capture_owner_unchanged"])
        argv = command.call_args.args[0]
        self.assertIn("down", argv)
        self.assertNotIn("--volumes", argv)
        self.assertNotIn("a" * 64, argv)
        self.assertNotIn("prune", argv)

    def test_owned_foreign_container_blocks_mutation(self):
        with mock.patch.object(live.shared, "checked", side_effect=[b"a" * 64, b"other-project"]), self.assertRaises(live.Error):
            live.owned({"project": PROJECT})

    def test_readiness_requires_authenticated_capture_not_ui_only(self):
        with mock.patch.object(live, "request", side_effect=[[], True]):
            live.ready(config(), SECRET, timeout=1)
        with mock.patch.object(live, "request", side_effect=[[], False]), mock.patch.object(live.time, "monotonic", side_effect=[0, 0, 2]), mock.patch.object(live.time, "sleep"), self.assertRaises(live.Error):
            live.ready(config(), SECRET, timeout=1)

    def test_api_rejects_arbitrary_routes_before_network(self):
        for path in ("https://external.invalid", "/api/../admin", "/api/service/?secret=a", "//other/path"):
            with mock.patch.object(live.urllib.request, "build_opener") as opener, self.assertRaises(live.Error):
                live.request(config(), SECRET, path)
            opener.assert_not_called()

    def test_state_rejects_extra_and_changed_ownership(self):
        state = {"schema": live.SCHEMA, "project": PROJECT, "profile": config(), "credentials": SECRET}
        self.assertEqual(live.validate_state(state), state)
        for value in (dict(state, project="default"), dict(state, command="docker prune")):
            with self.assertRaises(live.Error):
                live.validate_state(value)


if __name__ == "__main__":
    unittest.main()
