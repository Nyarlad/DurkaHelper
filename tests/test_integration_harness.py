"""Offline safety/contract tests for the opt-in external integration fixture."""
import argparse
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stack = load("stack_smoke_test", ROOT / "integration/stack_smoke.py")
receiver = load("fixture_receiver_test", ROOT / "integration/synthetic_receiver.py")


def images():
    return {name: name + "@sha256:" + "a" * 64 for name in stack.IMAGE_KEYS}


def archive(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as output:
        for name, content, kind in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                member.linkname = "/unrelated"
            output.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


class IntegrationHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS tempfile may use /var -> /private/var. The harness deliberately
        # requires canonical owned workspaces, so canonicalize the test fixture.
        self.root = Path(self.temp.name).resolve()

    def test_only_root_owned_stock_macos_ancestor_aliases_are_trusted(self):
        info = SimpleNamespace(st_uid=0)
        with patch.object(stack.sys, "platform", "darwin"), patch.object(stack.os, "readlink", return_value="private/var"):
            self.assertEqual(stack.macos_ancestor_alias(PurePosixPath("/var/test/file"), PurePosixPath("/var"), info),
                             PurePosixPath("/private/var/test/file"))
            self.assertIsNone(stack.macos_ancestor_alias(PurePosixPath("/var"), PurePosixPath("/var"), info))
            self.assertIsNone(stack.macos_ancestor_alias(PurePosixPath("/var/test/file"), PurePosixPath("/var"), SimpleNamespace(st_uid=501)))
            self.assertIsNone(stack.macos_ancestor_alias(PurePosixPath("/opt/alias/file"), PurePosixPath("/opt/alias"), info))
        with patch.object(stack.sys, "platform", "darwin"), patch.object(stack.os, "readlink", return_value="/untrusted"):
            self.assertIsNone(stack.macos_ancestor_alias(PurePosixPath("/var/test/file"), PurePosixPath("/var"), info))
        with patch.object(stack.sys, "platform", "linux"):
            self.assertIsNone(stack.macos_ancestor_alias(PurePosixPath("/var/test/file"), PurePosixPath("/var"), info))

    def test_temp_path_is_canonicalized_without_rejecting_stock_alias(self):
        result = stack.no_links(Path(self.temp.name) / "new")
        self.assertEqual(result.resolve(), self.root / "new")
        if sys.platform == "darwin":
            self.assertEqual(result, self.root / "new")

    @unittest.skipIf(os.name == "nt", "POSIX symlink test")
    def test_leaf_and_user_ancestor_symlinks_still_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        for path in (link, link / "child"):
            with self.subTest(path=path), self.assertRaises(stack.FixtureError):
                stack.no_links(path)

    def args(self, apply=False):
        path = self.root / "images.json"
        path.write_text(json.dumps(images()), encoding="utf-8")
        return argparse.Namespace(images=str(path), workspace=str(self.root / "run"),
            s4dfarm_source="unused", neo_source="unused", apply=apply, approval_id="qa-approved")

    def fake_export(self, source, target, component):
        if component == "s4dfarm":
            for role in ("server", "celery", "front"):
                content = "FROM python:3.9-slim\n" if role != "front" else (
                    "FROM node:20-slim AS front-base\nENV PNPM_HOME=\"/pnpm\"\nRUN corepack enable\n"
                    "FROM front-base AS front-build\nRUN pnpm install --frozen-lockfile\nFROM nginx:1.21.0-alpine\n"
                    "COPY --from=front-build /app/dist /front\n")
                stack.write(target / "server/docker" / role / "Dockerfile", content)
            stack.write(target / "server/app/config.py", "CONFIG = {}\n")
        else:
            stack.write(target / "Dockerfile", "FROM golang:1.21-alpine AS build\nFROM alpine\n"
                        "COPY --from=build /app/neo_server /neo_server\nCMD [\"/neo_server\"]\n")

    def prepare(self):
        args = self.args(True)
        with patch.object(stack, "export_source", side_effect=self.fake_export):
            result = stack.prepare(args)
        return args, result

    def test_prepare_default_has_no_files_or_subprocess(self):
        args = self.args()
        with patch.object(stack, "checked", side_effect=AssertionError("must not execute")):
            self.assertEqual(stack.prepare(args)["status"], "NOT_RUN")
        self.assertFalse(Path(args.workspace).exists())

    def test_apply_requires_approval_before_any_action(self):
        with redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(stack.main(["down", "--workspace", "not-used", "--apply"]), 2)
        self.assertIn("approval", stdout.getvalue())

    def test_image_map_rejects_floating_tag(self):
        path = self.root / "images.json"
        values = images()
        values["alpine"] = "alpine:latest"
        path.write_text(json.dumps(values), encoding="utf-8")
        with self.assertRaises(stack.FixtureError):
            stack.image_map(path)

    def test_image_map_rejects_missing_or_extra_roles(self):
        path = self.root / "images.json"
        for values in ({}, dict(images(), surprise="image@sha256:" + "a" * 64)):
            path.write_text(json.dumps(values), encoding="utf-8")
            with self.assertRaises(stack.FixtureError):
                stack.image_map(path)

    def test_prepare_existing_directory_rejected_without_overwrite(self):
        args = self.args(True)
        Path(args.workspace).mkdir()
        marker = Path(args.workspace) / "important"
        marker.write_text("preserve", encoding="utf-8")
        with self.assertRaises(stack.FixtureError):
            stack.prepare(args)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_archive_rejects_traversal_links_and_metadata_directory(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("safe", tarfile.SYMTYPE), (".ssh/key", tarfile.REGTYPE),
                           ("a\\b", tarfile.REGTYPE), ("C:/file", tarfile.REGTYPE)):
            with self.subTest(name=name):
                target = self.root / "out"
                with self.assertRaises(stack.FixtureError):
                    stack.extract_source(archive([(name, b"value", kind)]), target)
                self.assertFalse(target.exists())

    def test_archive_rejects_duplicate_before_writing(self):
        with self.assertRaises(stack.FixtureError):
            stack.extract_source(archive([("file", b"one", tarfile.REGTYPE),
                                          ("file", b"two", tarfile.REGTYPE)]), self.root / "out")
        self.assertFalse((self.root / "out").exists())

    def test_archive_extracts_regular_files(self):
        stack.extract_source(archive([("app/main.py", b"pass\n", tarfile.REGTYPE)]), self.root / "out")
        self.assertEqual((self.root / "out/app/main.py").read_bytes(), b"pass\n")

    def test_wrong_source_commit_rejected(self):
        with patch.object(stack, "checked", return_value=b"0" * 40):
            with self.assertRaises(stack.FixtureError):
                stack.export_source(self.root, self.root / "out", "neo")

    def test_dirty_source_rejected(self):
        with patch.object(stack, "checked", side_effect=[stack.PINS["neo"].encode(), b" M file"]):
            with self.assertRaises(stack.FixtureError):
                stack.export_source(self.root, self.root / "out", "neo")

    def test_git_read_disables_replace_and_fsmonitor_and_ambient_config(self):
        with patch.dict(stack.os.environ, {"GIT_DIR": "unrelated", "GIT_CONFIG_COUNT": "1"}):
            with patch.object(stack, "checked", return_value=b"") as command:
                stack.git_read(self.root, ["rev-parse", "HEAD"])
        args = command.call_args
        self.assertIn("core.fsmonitor=false", args.args[0])
        env = args.kwargs["environment"]
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_dockerfile_pin_preserves_stage_and_rejects_unknown_base(self):
        text = "FROM python:3.9-slim AS build\nRUN true\n"
        actual = stack.pin_dockerfile(text, {"python:3.9-slim": images()["python"]})
        self.assertIn(images()["python"] + " AS build", actual)
        with self.assertRaises(stack.FixtureError):
            stack.pin_dockerfile("FROM arbitrary\n", {})

    def test_compose_all_runtime_services_are_isolated(self):
        spec = stack.compose_spec("dh-smoke-123456789abc", images())
        self.assertTrue(spec["networks"]["fixture"]["internal"])
        for name, service in spec["services"].items():
            with self.subTest(name=name):
                self.assertNotIn("privileged", service)
                self.assertNotIn("network_mode", service)
                self.assertNotIn("container_name", service)
                self.assertEqual(service["logging"]["driver"], "none")
                self.assertEqual(service["restart"], "no")
                self.assertLessEqual(service["cpus"], 1)
                self.assertEqual(service["networks"], ["fixture", "edge"] if name in {"front", "neo-server"} else ["fixture"])
                self.assertIn("mem_limit", service)
                for port in service.get("ports", []):
                    self.assertIn(name, {"front", "neo-server"})
                    self.assertEqual(port["host_ip"], "127.0.0.1")
                    self.assertEqual(port["published"], "0")
                for volume in service.get("volumes", []):
                    self.assertTrue(volume.startswith("./"))
                    self.assertNotIn("docker.sock", volume)
        self.assertEqual(spec["networks"]["edge"], {})

    def test_prepare_emits_complete_verifiable_fixture(self):
        args, result = self.prepare()
        self.assertEqual(result["status"], "PASS")
        workspace, state = stack.fixture(args.workspace)
        self.assertEqual(state["source_pins"], stack.PINS)
        compose = stack.read_json(workspace / "compose.json")
        self.assertEqual(compose, stack.compose_spec(state["project"], images()))
        neo_dockerfile = (workspace / "sources/neo/Dockerfile.fixture").read_text(encoding="utf-8")
        self.assertIn("RUN go build -o neo_client cmd/client/main.go", neo_dockerfile)
        self.assertNotIn("FROM alpine\n", neo_dockerfile)

    def test_changed_config_is_rejected(self):
        args, _ = self.prepare()
        (Path(args.workspace) / "config/farm.py").write_text("modified", encoding="utf-8")
        with self.assertRaises(stack.FixtureError):
            stack.fixture(args.workspace)

    def test_static_output_is_readable_by_nginx_worker(self):
        args, _ = self.prepare()
        text = (Path(args.workspace) / "sources/s4dfarm/server/Dockerfile.fixture.front").read_text(encoding="utf-8")
        self.assertIn("COPY --from=front-build /app/dist /front\nRUN chmod -R a+rX /front", text)

    def test_neo_info_uses_synthetic_client_id_not_host_machine_identity(self):
        args, _ = self.prepare()
        for name in ("neo-client.yml", "neo-denied.yml"):
            text = (Path(args.workspace) / "config" / name).read_text(encoding="utf-8")
            self.assertIn('client_id: "synthetic-info-client"', text)

    def test_restricted_neo_client_can_read_only_generated_synthetic_configs(self):
        chmod = Path.chmod
        with patch.object(Path, "chmod", autospec=True, side_effect=chmod) as mode:
            args, _ = self.prepare()
        for name in ("neo-client.yml", "neo-denied.yml"):
            self.assertTrue(any(call.args == (Path(args.workspace) / "config" / name, 0o644)
                                for call in mode.call_args_list))

    def test_pinned_frontend_tool_does_not_float_or_rewrite_dependency_lock(self):
        args, _ = self.prepare()
        path = Path(args.workspace) / "sources/s4dfarm/server/Dockerfile.fixture.front"
        text = path.read_text(encoding="utf-8")
        self.assertIn("corepack prepare pnpm@8.15.9+sha512.", text)
        self.assertIn("COREPACK_DEFAULT_TO_LATEST=0", text)
        self.assertIn("COREPACK_ENABLE_AUTO_PIN=0", text)
        self.assertIn("pnpm install --frozen-lockfile", text)
        self.assertNotIn("--no-frozen-lockfile", text)
        self.assertNotIn("corepack use", text)

    def test_tampered_compose_is_rejected_even_with_updated_hash(self):
        args, _ = self.prepare()
        workspace = Path(args.workspace)
        path = workspace / "compose.json"
        compose = stack.read_json(path)
        compose["services"]["farm"]["privileged"] = True
        path.write_bytes(stack.canonical(compose))
        state_path = workspace / "fixture.json"
        state = stack.read_json(state_path)
        state["files"]["compose.json"] = stack.digest(path)
        state_path.write_bytes(stack.canonical(state))
        with self.assertRaises(stack.FixtureError):
            stack.fixture(workspace)

    def test_down_is_preview_without_apply(self):
        args, _ = self.prepare()
        args.action = "down"
        args.apply = False
        with patch.object(stack, "checked", side_effect=AssertionError("must not execute")):
            self.assertEqual(stack.execute(args)["status"], "NOT_RUN")

    def test_down_only_targets_generated_project_and_retains_data(self):
        args, _ = self.prepare()
        args.action = "down"
        # Source/config drift must not prevent stopping the exact isolated project.
        (Path(args.workspace) / "config/farm.py").write_text("modified", encoding="utf-8")
        with patch.object(stack, "checked", return_value=b"") as check:
            self.assertEqual(stack.execute(args)["status"], "PASS")
        command = check.call_args_list[-1].args[0]
        self.assertIn("--project-name", command)
        self.assertEqual(command[-3:], ["down", "--timeout", "10"])
        self.assertNotIn("--volumes", command)
        self.assertNotIn("--rmi", command)
        self.assertNotIn("--remove-orphans", command)

    def test_legacy_internal_only_fixture_can_still_be_stopped(self):
        args, _ = self.prepare()
        root = Path(args.workspace)
        state_path = root / "fixture.json"
        state = stack.read_json(state_path)
        state.pop("network_layout")
        state_path.write_bytes(stack.canonical(state))
        (root / "compose.json").write_bytes(stack.canonical(stack.compose_spec(state["project"], state["images"], edge=False)))
        args.action = "down"
        with patch.object(stack, "checked", return_value=b""):
            self.assertEqual(stack.execute(args)["status"], "PASS")

    def test_build_is_serial_and_resource_capped(self):
        args, _ = self.prepare()
        args.action = "build"
        with patch.object(stack, "checked", return_value=("sha256:" + "b" * 64).encode()) as check:
            result = stack.execute(args)
        builds = [call for call in check.call_args_list if call.args[0][:2] == ["docker", "build"]]
        self.assertEqual(len(builds), 4)
        self.assertEqual(len(result["image_ids"]), 4)
        for call in builds:
            self.assertIn("--memory=2g", call.args[0])
            self.assertIn("--cpu-quota=100000", call.args[0])
            self.assertEqual(call.kwargs["environment"]["DOCKER_BUILDKIT"], "0")

    def test_up_interrupt_stops_exact_project_and_returns_sanitized_blocked(self):
        args, result = self.prepare()
        calls = []

        def checked(argv, **kwargs):
            calls.append(argv)
            if "up" in argv:
                raise KeyboardInterrupt("sensitive-interrupt-payload")
            return b""

        with patch.object(stack, "checked", side_effect=checked), redirect_stdout(io.StringIO()) as output:
            try:
                code = stack.main(["up", "--workspace", args.workspace, "--apply", "--approval-id", "qa-approved"])
            except KeyboardInterrupt:
                code = None
        self.assertEqual(code, 2, "Ctrl-C must produce a sanitized blocked result")
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIn("stopped", report["rollback_status"])
        self.assertNotIn("sensitive", output.getvalue())
        downs = [argv for argv in calls if "down" in argv]
        self.assertEqual(len(downs), 1)
        self.assertIn(result["project"], downs[0])
        self.assertNotIn("--volumes", downs[0])
        self.assertNotIn("prune", downs[0])

    def test_build_interrupt_does_not_claim_daemon_build_cancellation(self):
        args, _ = self.prepare()
        calls = []

        def checked(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["docker", "build"]:
                raise KeyboardInterrupt("sensitive-build-output")
            return b""

        with patch.object(stack, "checked", side_effect=checked), redirect_stdout(io.StringIO()) as output:
            try:
                code = stack.main(["build", "--workspace", args.workspace, "--apply", "--approval-id", "qa-approved"])
            except KeyboardInterrupt:
                code = None
        self.assertEqual(code, 2)
        report = json.loads(output.getvalue())
        self.assertIn("not confirmed", report["rollback_status"])
        self.assertIn("does not cancel", report["rollback"])
        self.assertNotIn("sensitive", output.getvalue())
        self.assertTrue(all("down" not in argv and "prune" not in argv for argv in calls))

    def test_readiness_interrupt_with_cleanup_failure_does_not_claim_stop(self):
        args, _ = self.prepare()
        calls = []

        def checked(argv, **kwargs):
            calls.append(argv)
            if "down" in argv:
                raise stack.FixtureError("synthetic cleanup failure")
            return b""

        with patch.object(stack, "checked", side_effect=checked), patch.object(stack, "farm_port", return_value=1234), \
             patch.object(stack, "wait_ready", side_effect=KeyboardInterrupt("sensitive-payload")), \
             redirect_stdout(io.StringIO()) as output:
            code = stack.main(["up", "--workspace", args.workspace, "--apply", "--approval-id", "qa-approved"])
        self.assertEqual(code, 2)
        self.assertIn("automatic stop failed", json.loads(output.getvalue())["rollback_status"])
        self.assertNotIn("sensitive", output.getvalue())
        self.assertEqual(len([argv for argv in calls if "down" in argv]), 1)

    def test_port_rejects_non_loopback_and_multiple_bindings(self):
        for value in (b"0.0.0.0:1234", b"127.0.0.1:0", b"127.0.0.1:1234\n[::]:1234", b"bad"):
            with patch.object(stack, "checked", return_value=value):
                with self.assertRaises(stack.FixtureError):
                    stack.farm_port(["docker", "compose"])

    def test_checked_sanitizes_application_output(self):
        result = subprocess.CompletedProcess([], 1, b"secret-output", b"secret-error")
        with patch.object(stack.subprocess, "run", return_value=result):
            with self.assertRaises(stack.FixtureError) as error:
                stack.checked(["docker"])
        self.assertNotIn("secret", str(error.exception))

    def test_probe_cleanup_requires_ownership(self):
        with patch.object(stack, "checked", return_value=b"another-project;neo-client") as check:
            with self.assertRaises(stack.FixtureError):
                stack.stop_probe("owned-candidate", "dh-smoke-123456789abc", "neo-client")
        self.assertEqual(check.call_count, 1)

    def test_probe_timeout_stops_only_named_owned_container(self):
        command = ["docker", "compose", "--project-name", "dh-smoke-123456789abc"]
        with patch.object(stack, "capture_probe", side_effect=stack.FixtureError("Neo probe timed out")):
            with patch.object(stack, "stop_probe") as stop:
                with self.assertRaises(stack.FixtureError):
                    stack.neo_probe(command, "neo-client")
        self.assertEqual(stop.call_args.args[1:], ("dh-smoke-123456789abc", "neo-client"))
        self.assertTrue(stop.call_args.args[0].startswith("dh-smoke-123456789abc-probe-"))

    def test_probe_interrupt_stops_only_named_owned_container_and_sanitizes_error(self):
        command = ["docker", "compose", "--project-name", "dh-smoke-123456789abc"]
        caught = None
        with patch.object(stack, "capture_probe", side_effect=KeyboardInterrupt("sensitive-payload")), \
             patch.object(stack, "stop_probe") as stop:
            try:
                stack.neo_probe(command, "neo-client")
            except BaseException as error:
                caught = error
        self.assertIsInstance(caught, stack.FixtureError)
        self.assertIn("interrupted", str(caught))
        self.assertNotIn("sensitive", str(caught))
        self.assertEqual(stop.call_args.args[1:], ("dh-smoke-123456789abc", "neo-client"))
        self.assertTrue(stop.call_args.args[0].startswith("dh-smoke-123456789abc-probe-"))

    def test_probe_interrupt_cleanup_failure_preserves_exact_name_in_diagnostic(self):
        command = ["docker", "compose", "--project-name", "dh-smoke-123456789abc"]
        with patch.object(stack, "capture_probe", side_effect=KeyboardInterrupt("sensitive-payload")), \
             patch.object(stack, "stop_probe", side_effect=stack.FixtureError("ownership mismatch")) as stop:
            with self.assertRaises(stack.FixtureError) as caught:
                stack.neo_probe(command, "neo-client")
        self.assertIn(stop.call_args.args[0], str(caught.exception))
        self.assertIn("cleanup required", str(caught.exception))
        self.assertNotIn("sensitive", str(caught.exception))

    def test_probe_output_overflow_stops_only_named_owned_container(self):
        command = ["docker", "compose", "--project-name", "dh-smoke-123456789abc"]
        with patch.object(stack, "capture_probe", side_effect=stack.FixtureError("Neo probe output exceeded limit")), \
             patch.object(stack, "stop_probe") as stop:
            with self.assertRaisesRegex(stack.FixtureError, "exceeded limit"):
                stack.neo_probe(command, "neo-client")
        self.assertEqual(stop.call_args.args[1:], ("dh-smoke-123456789abc", "neo-client"))
        self.assertTrue(stop.call_args.args[0].startswith("dh-smoke-123456789abc-probe-"))

    def test_probe_capture_combined_output_limit_timeout_and_success(self):
        with self.assertRaisesRegex(stack.FixtureError, "exceeded limit"):
            stack.capture_probe([sys.executable, "-I", "-S", "-c",
                "import sys; print('x'*40000); print('y'*40000,file=sys.stderr)"])
        with self.assertRaisesRegex(stack.FixtureError, "timed out"):
            stack.capture_probe([sys.executable, "-I", "-S", "-c", "import time;time.sleep(5)"], timeout=0.05)
        self.assertEqual(stack.capture_probe([sys.executable, "-I", "-S", "-c", "print('fixture')"]),
                         (0, b"fixture\r\n" if os.name == "nt" else b"fixture\n"))

    def test_probe_capture_interrupt_kills_cli_before_scoped_container_cleanup(self):
        with patch.object(stack.subprocess, "Popen") as popen:
            process = popen.return_value
            process.stdout = io.BytesIO(b"")
            process.poll.return_value = None
            process.wait.side_effect = [KeyboardInterrupt(), 0]
            with self.assertRaises(KeyboardInterrupt):
                stack.capture_probe(["docker"])
            process.kill.assert_called_once()


class SyntheticReceiverTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), receiver.Receiver)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def send(self, value, token="fixture-only", path="/flags"):
        request = urllib.request.Request("http://127.0.0.1:" + str(self.server.server_port) + path,
            data=json.dumps(value).encode(), headers={"X-Team-Token": token}, method="PUT")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read(100000)

    def test_protocol_accepts_only_synthetic_flag_shape(self):
        flag = "A" * 31 + "="
        code, body = self.send([flag])
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), [{"flag": flag, "msg": "accepted synthetic fixture"}])
        self.assertEqual(self.send(["not-a-flag"])[0], 400)

    def test_protocol_rejects_unauthorized_wrong_path_and_wrong_shape(self):
        flag = "A" * 31 + "="
        self.assertEqual(self.send([flag], token="incorrect")[0], 403)
        self.assertEqual(self.send([flag], path="/other")[0], 403)
        self.assertEqual(self.send({"flag": flag})[0], 400)
        self.assertEqual(self.send([flag] * 101)[0], 400)


if __name__ == "__main__":
    unittest.main()
