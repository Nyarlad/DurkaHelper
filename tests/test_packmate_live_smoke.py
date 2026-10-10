import argparse
import base64
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_live_smoke", ROOT / "integration/packmate_live_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class LiveSmokeTests(unittest.TestCase):
    def test_programs_compile_and_have_no_raw_capture_or_external_targets(self):
        compile(smoke.SERVER, "server.py", "exec")
        compile(smoke.CLIENT, "client.py", "exec")
        for source in (smoke.SERVER, smoke.CLIENT):
            self.assertNotIn(b"subprocess", source)
            self.assertNotIn(b"AF_PACKET", source)
            self.assertNotIn(b"http://", source)
        self.assertIn(b"time.sleep(90)", smoke.CLIENT)

    def test_create_peer_is_nonprivileged_exact_private_program(self):
        args = smoke.private_command(Path("fixture"), {"project": "test-owned"}, "sha256:" + "a" * 64, "test-source", "b" * 64, "server.py")
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("65534:65534", args)
        self.assertIn("--read-only", args)
        self.assertIn("--pull=never", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("host", args)

    def test_cleanup_refuses_foreign_container(self):
        with mock.patch.object(smoke.shared, "checked", return_value=b"foreign") as run, self.assertRaises(smoke.Error):
            smoke.cleanup_container("a" * 64, "expected")
        self.assertEqual(run.call_count, 1)

    def test_cleanup_refuses_foreign_network(self):
        with mock.patch.object(smoke.shared, "checked", return_value=b"foreign") as run, self.assertRaises(smoke.Error):
            smoke.cleanup_network("a" * 64, "expected")
        self.assertEqual(run.call_count, 1)

    def test_cleanup_targets_exact_ids_not_global(self):
        with mock.patch.object(smoke.shared, "checked", side_effect=[b"expected", b""]) as run:
            smoke.cleanup_container("a" * 64, "expected")
        self.assertEqual(run.call_args.args[0], ["docker", "rm", "--force", "a" * 64])

    def test_capture_gate_before_runtime_or_resources(self):
        args = argparse.Namespace(workspace="any", apply=True, capture_approved=False)
        with mock.patch.object(smoke, "fixture", return_value=(Path("any"), {})), mock.patch.object(smoke.sys, "platform", "linux"), mock.patch.object(smoke.shared, "checked") as run, self.assertRaises(smoke.Error):
            smoke.run(args)
        run.assert_not_called()

    def test_run_preview_has_no_docker_or_writes(self):
        args = argparse.Namespace(workspace="any", apply=False)
        with mock.patch.object(smoke, "fixture", return_value=(Path("any"), {})), mock.patch.object(smoke.shared, "checked") as run:
            result = smoke.run(args)
        self.assertEqual(result["status"], "NOT_RUN")
        run.assert_not_called()

    def test_prepare_preview_has_no_docker_or_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(workspace=Path(directory) / "new", daemon_id="test-daemon", apply=False)
            with mock.patch.object(smoke.shared, "checked") as run:
                result = smoke.prepare(args)
            self.assertEqual(result["status"], "NOT_RUN")
            self.assertFalse(args.workspace.exists())
            run.assert_not_called()

    def test_approval_gate_precedes_input_reads(self):
        with redirect_stdout(io.StringIO()), mock.patch.object(smoke, "fixture") as fixture:
            self.assertEqual(smoke.main(["run", "--workspace", "missing", "--apply", "--capture-approved"]), 2)
        fixture.assert_not_called()

    def test_collect_requires_exact_protocol_directions_and_payload(self):
        replies = []
        for kind in smoke.PORTS:
            raw = ("request:marker:" + kind + "\n").encode()
            replies.extend([[{"id": 1, "protocol": "UDP" if kind == "udp" else "TCP"}],
                            [{"id": 1, "incoming": True, "content": base64.b64encode(raw).decode()},
                             {"id": 2, "incoming": False, "content": base64.b64encode(b"response:" + raw).decode()}]])
        with mock.patch.object(smoke.live, "request", side_effect=replies):
            result = smoke.collect({}, {}, dict.fromkeys(smoke.PORTS, 1), "marker")
        self.assertTrue(all(result.values()))
        self.assertEqual(len(result), 12)

    def test_collect_empty_and_wrong_direction_cannot_pass(self):
        with mock.patch.object(smoke.live, "request", return_value=[]):
            result = smoke.collect({}, {}, dict.fromkeys(smoke.PORTS, 1), "marker")
        self.assertFalse(any(result.values()))
        replies = []
        for kind in smoke.PORTS:
            raw = ("request:marker:" + kind + "\n").encode()
            replies.extend([[{"id": 1, "protocol": "WRONG"}], [{"id": 1, "incoming": False, "content": base64.b64encode(raw).decode()}]])
        with mock.patch.object(smoke.live, "request", side_effect=replies):
            result = smoke.collect({}, {}, dict.fromkeys(smoke.PORTS, 1), "marker")
        self.assertFalse(result["tcp_request_incoming"])
        self.assertFalse(result["udp_protocol"])

    def test_collect_rejects_invalid_stream_id(self):
        with mock.patch.object(smoke.live, "request", return_value=[{"id": "arbitrary-path", "protocol": "TCP"}]), self.assertRaises(smoke.Error):
            smoke.collect({}, {}, dict.fromkeys(smoke.PORTS, 1), "marker")

    def test_identifier_requires_exact_resource_id(self):
        for value in (b"name", b"a" * 12, b"a" * 64 + b"\nforeign"):
            with mock.patch.object(smoke.shared, "checked", return_value=value), self.assertRaises(smoke.Error):
                smoke.identifier(["docker", "create"])

    def test_bounded_line_framing_accepts_split_reads(self):
        namespace = {"time": mock.Mock()}
        namespace["time"].monotonic.return_value = 0
        exec(compile(smoke.FRAMING, "framing.py", "exec"), namespace)
        connection = mock.Mock()
        connection.recv.side_effect = [b"req", b"uest:", b"marker", b"\n"]
        self.assertEqual(namespace["read_line"](connection), b"request:marker\n")
        self.assertEqual(connection.recv.call_count, 4)
        self.assertTrue(all(call.args[0] <= 1025 for call in connection.recv.call_args_list))

    def test_bounded_line_framing_rejects_truncation_size_and_extra_frames(self):
        namespace = {"time": mock.Mock()}
        namespace["time"].monotonic.return_value = 0
        exec(compile(smoke.FRAMING, "framing.py", "exec"), namespace)
        for replies in ([b"partial", b""], [b"x" * 1025], [b"one\ntwo\n"]):
            connection = mock.Mock()
            connection.recv.side_effect = replies
            with self.subTest(replies=len(replies)), self.assertRaises(ValueError):
                namespace["read_line"](connection)

    def test_bounded_line_framing_total_deadline_not_per_read(self):
        namespace = {"time": mock.Mock()}
        namespace["time"].monotonic.side_effect = [0, 0, 6]
        exec(compile(smoke.FRAMING, "framing.py", "exec"), namespace)
        connection = mock.Mock()
        connection.recv.return_value = b"partial"
        with self.assertRaises(TimeoutError):
            namespace["read_line"](connection)
        self.assertEqual(connection.recv.call_count, 1)

    def test_collect_reassembles_fragmented_tcp_without_packet_local_pattern_filter(self):
        replies = []
        for kind in smoke.PORTS:
            raw = ("request:marker:" + kind + "\n").encode()
            packets = [{"id": 1, "incoming": True, "content": base64.b64encode(raw[:7]).decode()},
                       {"id": 2, "incoming": True, "content": base64.b64encode(raw[7:]).decode()},
                       {"id": 3, "incoming": False, "content": base64.b64encode(b"response:").decode()},
                       {"id": 4, "incoming": False, "content": base64.b64encode(raw).decode()}]
            if kind == "udp":
                packets = [{"id": 1, "incoming": True, "content": base64.b64encode(raw).decode()},
                           {"id": 2, "incoming": False, "content": base64.b64encode(b"response:" + raw).decode()}]
            replies.extend([[{"id": 1, "protocol": "UDP" if kind == "udp" else "TCP"}], packets])
        with mock.patch.object(smoke.live, "request", side_effect=replies) as request:
            result = smoke.collect({}, {}, dict.fromkeys(smoke.PORTS, 1), "marker")
        self.assertTrue(all(result.values()))
        for call in request.call_args_list:
            if "/api/stream/" in call.args[2]:
                self.assertIsNone(call.args[4]["pattern"])

    def test_collect_does_not_treat_split_udp_datagrams_as_tcp_segments(self):
        replies = [[]]
        raw = b"request:marker:udp\n"
        packets = [{"id": 1, "incoming": True, "content": base64.b64encode(raw[:7]).decode()},
                   {"id": 2, "incoming": True, "content": base64.b64encode(raw[7:]).decode()}]
        replies.extend([[{"id": 1, "protocol": "UDP"}], packets, []])
        with mock.patch.object(smoke.live, "request", side_effect=replies):
            result = smoke.collect({}, {}, dict.fromkeys(smoke.PORTS, 1), "marker")
        self.assertFalse(result["udp_request_incoming"])

    def test_collect_packet_order_duplicates_and_oversize_rejected(self):
        for packets in ([{"id": 2, "incoming": True, "content": ""}, {"id": 1, "incoming": True, "content": ""}],
                        [{"id": 1, "incoming": True, "content": ""}, {"id": 1, "incoming": True, "content": ""}],
                        [{"id": 1, "incoming": 1, "content": ""}],
                        [{"id": 1, "incoming": True, "content": base64.b64encode(b"x" * 2049).decode()}]):
            with mock.patch.object(smoke.live, "request", side_effect=[[{"id": 1, "protocol": "TCP"}], packets]), self.assertRaises(smoke.Error):
                smoke.collect({}, {}, dict.fromkeys(smoke.PORTS, 1), "marker")

    def test_reconcile_uncertain_named_container_removes_only_owned_id(self):
        project = "dh-live-test-012345abcdef"
        name, identity = project + "-source", "a" * 64
        metadata = {"id": identity, "name": "/" + name, "owner": project}
        with mock.patch.object(smoke.shared, "checked", side_effect=[identity.encode(), json.dumps(metadata).encode(), project.encode(), b""]) as command:
            smoke.reconcile_resource("container", name, project)
        self.assertEqual(command.call_args.args[0], ["docker", "rm", "--force", identity])
        self.assertIn("name=^/" + name + "$", command.call_args_list[0].args[0])

    def test_reconcile_refuses_name_collision_or_wrong_label(self):
        project = "dh-live-test-012345abcdef"
        base = {"id": "a" * 64, "name": "/" + project + "-source", "owner": project}
        for key, value in (("id", "b" * 64), ("name", "/foreign"), ("owner", "foreign")):
            with mock.patch.object(smoke.shared, "checked", side_effect=[b"a" * 64, json.dumps(dict(base, **{key: value})).encode()]) as command, self.assertRaises(smoke.Error):
                smoke.reconcile_resource("container", project + "-source", project)
            self.assertFalse(any("rm" in call.args[0] for call in command.call_args_list))

    def test_reconcile_network_and_absence_scoped_by_exact_name(self):
        project = "dh-live-test-012345abcdef"
        with mock.patch.object(smoke.shared, "checked", return_value=b"") as command:
            smoke.reconcile_resource("network", project, project)
        self.assertIn("name=^" + project + "$", command.call_args.args[0])
        self.assertEqual(command.call_count, 1)

    def test_uncertain_source_create_is_reconciled_even_without_returned_id(self):
        project = "dh-live-test-012345abcdef"
        state = {"project": project, "daemon_id": "test-daemon", "python_image": "pinned", "marker": "a" * 24}
        for failure in (smoke.Error("create timed out"), KeyboardInterrupt()):
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(smoke, "fixture", return_value=(Path(directory), state)), mock.patch.object(smoke.sys, "platform", "linux"), mock.patch.object(smoke.live, "daemon"), mock.patch.object(smoke.shared, "checked", return_value=("sha256:" + "c" * 64 + ";linux;amd64").encode()), mock.patch.object(smoke, "identifier", side_effect=["b" * 64, failure]), mock.patch.object(smoke, "reconcile_resource") as cleanup, mock.patch.object(smoke.shared, "write"):
                result = smoke.run(argparse.Namespace(workspace=directory, apply=True, capture_approved=True, approval_id="test-run"))
            self.assertEqual(result["status"], "BLOCKED")
            cleanup.assert_any_call("container", project + "-source", project)
            cleanup.assert_any_call("network", project, project)

    def test_uncertain_network_create_is_reconciled_without_returned_id(self):
        project = "dh-live-test-012345abcdef"
        state = {"project": project, "daemon_id": "test-daemon", "python_image": "pinned", "marker": "a" * 24}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(smoke, "fixture", return_value=(Path(directory), state)), mock.patch.object(smoke.sys, "platform", "linux"), mock.patch.object(smoke.live, "daemon"), mock.patch.object(smoke.shared, "checked", return_value=("sha256:" + "c" * 64 + ";linux;amd64").encode()), mock.patch.object(smoke, "identifier", side_effect=smoke.Error("create timed out")), mock.patch.object(smoke, "reconcile_resource") as cleanup, mock.patch.object(smoke.shared, "write"):
            result = smoke.run(argparse.Namespace(workspace=directory, apply=True, capture_approved=True, approval_id="test-run"))
        self.assertEqual(result["status"], "BLOCKED")
        cleanup.assert_called_once_with("network", project, project)


if __name__ == "__main__":
    unittest.main()
