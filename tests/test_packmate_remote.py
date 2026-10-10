"""Remote LIVE safety and offline orchestration; never contacts an actual host."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_remote", ROOT / "deployment/packmate_remote.py")
remote = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote)


def value():
    return {"schema": remote.SCHEMA, "ssh": {"target": "example@fixture.example", "port": 22, "key": None, "known_hosts": None, "docker": "docker"},
            "workspace": "/home/example/private/live", "project": "dh-host-" + "a" * 12,
            "profile": {"schema": remote.host.SCHEMA, "daemon_id": "fixture-engine", "interface": "br-fixture", "ifindex": 9,
                        "interface_mac": "02:00:00:00:00:01", "local_ip": "192.0.2.10", "bind_address": "192.0.2.20",
                        "ui_port": 65000, "db_port": 55432, "tcp_timeout_seconds": 30, "udp_timeout_seconds": 10,
                        "timeout_check_seconds": 5, "retention_minutes": 60, "cleanup_interval_minutes": 1},
            "credentials": {"username": "operator", "password": "synthetic-not-real-0123456789", "db_password": "synthetic-db-0123456789"},
            "images": {"packmate": "sha256:" + "b" * 64, "db": "sha256:" + "c" * 64}}


class RemoteTests(unittest.TestCase):
    def args(self, *argv):
        with mock.patch.object(remote, "run", return_value={"status": "PASS"}) as run, contextlib.redirect_stdout(io.StringIO()):
            remote.main(list(argv))
        return run.call_args.args[0]

    def test_settings_and_ssh_injection_rejected(self):
        self.assertEqual(remote.settings(value()), value())
        for name, bad in (("target", "-oProxyCommand=evil"), ("target", "tester@host;id"),
                          ("docker", "sudo docker"), ("docker", "/tmp/tool;id"), ("port", True), ("key", "relative")):
            altered = value()
            altered["ssh"][name] = bad
            with self.subTest(field=name), self.assertRaises(remote.Error):
                remote.settings(altered)

    def test_broad_and_traversal_directories_rejected(self):
        for path in ("/", "/home/example", "/etc/tool", "/home/example/../other", "/root/.", "/home/example/a//b"):
            with self.subTest(path=path), self.assertRaises(remote.Error):
                remote.remote_path(path)

    def test_strict_host_trust_and_batch_identity(self):
        ssh = value()["ssh"]
        ssh["key"] = str((ROOT / "local/identity").absolute())
        ssh["known_hosts"] = str((ROOT / "local/known_hosts").absolute())
        argv = remote.SSH(ssh).argv()
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertNotIn("StrictHostKeyChecking=no", argv)

    def test_ssh_failure_never_leaks_output(self):
        client = remote.SSH(value()["ssh"])
        result = mock.Mock(returncode=1, stdout=b"synthetic-secret", stderr=b"synthetic-secret")
        with mock.patch.object(remote.subprocess, "run", return_value=result), self.assertRaises(remote.Error) as caught:
            client.shell("true")
        self.assertNotIn("synthetic-secret", str(caught.exception))

    def test_remote_allowlist_and_environment_guard(self):
        client = remote.SSH(value()["ssh"])
        with mock.patch.object(client, "shell", return_value=b"ok") as shell:
            self.assertEqual(client.checked(["docker", "info"], capture=True), b"ok")
        self.assertIn("DOCKER_HOST", shell.call_args.args[0])
        with self.assertRaises(remote.Error):
            client.checked(["rm", "-rf", "/"])

    def test_target_engine_rejects_desktop_rootless_and_remote_context(self):
        client = remote.SSH(value()["ssh"])
        info = {"ID": "fixture-engine", "OSType": "linux", "Architecture": "x86_64", "OperatingSystem": "Ubuntu", "KernelVersion": "fixture-kernel", "SecurityOptions": []}
        for altered, endpoint in ((dict(info, OperatingSystem="Docker Desktop"), "unix:///var/run/docker.sock"),
                                  (dict(info, SecurityOptions=["rootless"]), "unix:///var/run/docker.sock"),
                                  (info, "tcp://other:2375"), (dict(info, Architecture="arm64"), "unix:///var/run/docker.sock")):
            with mock.patch.object(client, "shell", return_value=b"0\nLinux\nx86_64\nfixture-kernel\n"), \
                    mock.patch.object(client, "checked", side_effect=[json.dumps({"Host": endpoint}).encode(), json.dumps(altered).encode()]), \
                    self.assertRaises(remote.Error):
                client.engine()

    def test_bundle_roundtrip_tamper_and_no_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "images.tar").write_bytes(b"synthetic image archive")
            _, checksum = remote.digest_file(root / "images.tar")
            remote.shared.write(root / "manifest.json", remote.shared.canonical({"schema": "durkahelper.packmate-images.v1", "refs": remote.REFS, "images": value()["images"], "sha256": checksum}))
            self.assertEqual(remote.bundle(root)[1], value()["images"])
            (root / "images.tar").write_bytes(b"tampered")
            with self.assertRaises(remote.Error):
                remote.bundle(root)

    def test_bundle_symlink_rejected(self):
        if os.name == "nt":
            self.skipTest("symlink creation requires Windows elevation")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "real").write_bytes(b"x")
            (root / "images.tar").symlink_to(root / "real")
            with self.assertRaises(remote.Error):
                remote.digest_file(root / "images.tar")

    def test_bundle_preview_has_no_docker_or_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "new"
            args = self.args("bundle", "--output", str(output), "--download")
            with mock.patch.object(remote.shared, "checked") as checked:
                self.assertEqual(remote.make_bundle(args)["status"], "NOT_RUN")
            checked.assert_not_called()
            self.assertFalse(output.exists())

    def test_bundle_selects_and_exports_amd64_from_mixed_platform_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "bundle"
            args = self.args("bundle", "--output", str(output), "--download", "--apply")

            def checked(argv, **kwargs):
                if argv[:3] == ["docker", "image", "inspect"]:
                    name = next(name for name, ref in remote.REFS.items() if ref == argv[-1])
                    # On an ARM Mac, an unqualified inspection selects the cached
                    # ARM64 PostgreSQL even after pulling its AMD64 variant.
                    selected = "--platform" in argv and argv[argv.index("--platform") + 1] == "linux/amd64"
                    architecture = "amd64" if selected or name == "packmate" else "arm64"
                    return (value()["images"][name] + ";linux;" + architecture).encode()
                if argv[:3] == ["docker", "image", "save"]:
                    self.assertIn("--platform", argv)
                    self.assertEqual(argv[argv.index("--platform") + 1], "linux/amd64")
                    # A selected platform's child ID may not be addressable in
                    # containerd. Export through the exact pinned names instead.
                    self.assertEqual(argv[-2:], list(remote.REFS.values()))
                    Path(argv[argv.index("--output") + 1]).write_bytes(b"synthetic amd64 archive")
                return b""

            with mock.patch.object(remote.shared, "checked", side_effect=checked) as runner:
                self.assertEqual(remote.make_bundle(args)["status"], "PASS")
            self.assertEqual(remote.bundle(output)[1], value()["images"])
            pulls = [call.args[0] for call in runner.call_args_list if call.args[0][:2] == ["docker", "pull"]]
            self.assertEqual(pulls, [["docker", "pull", "--platform", "linux/amd64", ref] for ref in remote.REFS.values()])

    def test_explicit_platform_does_not_accept_arm64_metadata(self):
        checked = mock.Mock(return_value=("sha256:" + "b" * 64 + ";linux;arm64").encode())
        with self.assertRaises(remote.Error):
            remote.inspect_images(checked, remote.REFS, platform="linux/amd64")
        self.assertIn("--platform", checked.call_args.args[0])

    def test_native_target_inspection_does_not_require_new_platform_api(self):
        checked = mock.Mock(return_value=("sha256:" + "b" * 64 + ";linux;amd64").encode())
        remote.inspect_images(checked, remote.REFS)
        for call in checked.call_args_list:
            self.assertNotIn("--platform", call.args[0])

    def test_generated_payload_reuses_host_limits_and_no_python(self):
        payload = remote.files(value())
        spec = json.loads(payload["runtime-compose.json"])
        self.assertEqual(spec, remote.host.compose_spec(value()["profile"], value()["credentials"], value()["project"], value()["images"]))
        self.assertEqual(spec["services"]["packmate"]["cap_add"], ["NET_RAW"])
        self.assertNotIn("python", payload["runtime-compose.json"].decode())
        client = remote.SSH(value()["ssh"])
        with mock.patch.object(client, "shell", return_value=b"" ) as shell, mock.patch.object(remote, "verify_workspace", return_value=True):
            remote.upload(client, value())
        self.assertNotIn("python", shell.call_args.args[0])
        self.assertNotIn("rm ", shell.call_args.args[0])
        self.assertIn("test ! -e", shell.call_args.args[0])

    def test_up_preview_and_capture_approval_before_ssh(self):
        args = self.args("up")
        with mock.patch.object(remote, "private_config", return_value=(Path("unused"), value())), mock.patch.object(remote, "SSH") as ssh:
            self.assertEqual(remote.run(args)["status"], "NOT_RUN")
            args.apply = True
            with self.assertRaises(remote.Error):
                remote.run(args)
        ssh.assert_not_called()

    def test_route_restores_shared_runner_even_on_error(self):
        original = remote.shared.checked
        with self.assertRaises(ValueError), remote.SSH(value()["ssh"]).route():
            raise ValueError("fixture")
        self.assertIs(remote.shared.checked, original)

    def test_doctor_discovery_never_writes_or_starts_and_requires_no_config(self):
        args = self.args("doctor", "--host", "tester@fixture.example")
        client = mock.Mock()
        client.engine.return_value = {"ID": "fixture-engine"}
        client.checked.return_value = json.dumps([{"ifname": "eth0", "ifindex": 2, "address": "02:00:00:00:00:01", "flags": ["UP"], "addr_info": [{"family": "inet", "local": "192.0.2.10"}]}]).encode()
        client.shell.side_effect = [b"8388608\n20971520\n", b""]
        with mock.patch.object(remote, "SSH", return_value=client), mock.patch.object(remote, "inspect_images", return_value=value()["images"]), \
                mock.patch.object(remote, "private_config") as config, mock.patch.object(remote, "write_config") as write:
            report = remote.run(args)
        config.assert_not_called()
        write.assert_not_called()
        self.assertTrue(report["read_only"])
        self.assertEqual(report["status"], "PASS")
        scripts = " ".join(call.args[0] for call in client.shell.call_args_list)
        self.assertNotIn("mkdir", scripts)
        self.assertNotIn("load", scripts)
        self.assertEqual(report["capture_permission"], "NOT_VERIFIED")

    def test_doctor_discovery_conflicting_ports_block(self):
        args = self.args("doctor", "--host", "tester@fixture.example")
        client = mock.Mock()
        client.engine.return_value = {"ID": "fixture-engine"}
        client.checked.return_value = b"[]"
        client.shell.side_effect = [b"8388608\n20971520\n", b"LISTEN 0 128 192.0.2.20:65000"]
        with mock.patch.object(remote, "SSH", return_value=client), mock.patch.object(remote, "inspect_images", side_effect=remote.Error("missing")):
            self.assertEqual(remote.run(args)["status"], "BLOCKED")

    def test_config_bound_doctor_runs_no_mutations(self):
        args = self.args("doctor")
        with mock.patch.object(remote, "private_config", return_value=(Path("unused"), value())), \
                mock.patch.object(remote, "doctor", return_value={"status": "PASS"}), \
                mock.patch.object(remote, "inspect_images", return_value=value()["images"]), \
                mock.patch.object(remote, "write_config") as write, mock.patch.object(remote, "upload") as upload:
            self.assertEqual(remote.run(args)["images"], "CACHED_AMD64_VERIFIED")
        write.assert_not_called()
        upload.assert_not_called()

    def test_offline_up_uses_load_and_never_pull_build_install(self):
        args = self.args("up", "--bundle", "private-bundle", "--apply", "--host-network-approved", "--interface-scope-approved")
        client = mock.Mock()
        client.route.return_value = contextlib.nullcontext()
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "images.tar"
            archive.write_bytes(b"fixture")
            with mock.patch.object(remote, "private_config", return_value=(Path("unused"), value())), mock.patch.object(remote, "SSH", return_value=client), \
                    mock.patch.object(remote, "doctor", return_value={"status": "PASS"}), mock.patch.object(remote, "bundle", return_value=(archive, value()["images"])), \
                    mock.patch.object(remote, "inspect_images", side_effect=[remote.Error("missing"), value()["images"]]), \
                    mock.patch.object(remote, "write_config"), mock.patch.object(remote, "verify_workspace", return_value=False), mock.patch.object(remote, "upload") as upload, \
                    mock.patch.object(remote.host, "owned", return_value={"packmate": {"running": True}, "db": {"running": True}}), \
                    mock.patch.object(remote.host, "interface"), mock.patch.object(remote, "tunnel", return_value=contextlib.nullcontext({})), mock.patch.object(remote.host.live, "ready"):
                self.assertTrue(remote.run(args)["authenticated_capture_started"])
        upload.assert_called_once()
        self.assertIn("image load", client.shell.call_args.args[0])
        commands = [call.args[0] for call in client.checked.call_args_list]
        self.assertEqual(commands[-1][-5:], ["up", "--detach", "--no-build", "--pull", "never"])

    def test_down_checks_ownership_and_never_removes_data(self):
        args = self.args("down", "--apply")
        client = mock.Mock()
        client.route.return_value = contextlib.nullcontext()
        client.engine.return_value = {"ID": "fixture-engine"}
        with mock.patch.object(remote, "private_config", return_value=(Path("unused"), value())), mock.patch.object(remote, "SSH", return_value=client), \
                mock.patch.object(remote, "verify_workspace", return_value=True), mock.patch.object(remote.host, "owned") as owned, mock.patch.object(remote.host, "interface") as interface:
            self.assertTrue(remote.run(args)["data_retained"])
        owned.assert_called_once()
        interface.assert_not_called()
        self.assertEqual(client.checked.call_args.args[0][-3:], ["down", "--timeout", "10"])
        self.assertNotIn("--volumes", client.checked.call_args.args[0])

    def test_down_rejects_foreign_resources_before_compose(self):
        args = self.args("down", "--apply")
        client = mock.Mock()
        client.route.return_value = contextlib.nullcontext()
        client.engine.return_value = {"ID": "fixture-engine"}
        with mock.patch.object(remote, "private_config", return_value=(Path("unused"), value())), mock.patch.object(remote, "SSH", return_value=client), \
                mock.patch.object(remote, "verify_workspace", return_value=True), mock.patch.object(remote.host, "owned", side_effect=remote.Error("foreign")), \
                self.assertRaises(remote.Error):
            remote.run(args)
        client.checked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
