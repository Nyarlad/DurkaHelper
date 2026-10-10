"""Host capture is an explicit boundary, never inferred from LAN membership."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_host_capture", ROOT / "deployment/packmate_host.py")
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


def config():
    return {"schema": host.SCHEMA, "daemon_id": "synthetic-engine", "interface": "br-synthetic",
            "ifindex": 9, "interface_mac": "02:00:00:00:00:01", "local_ip": "192.0.2.2",
            "bind_address": "127.0.0.1", "ui_port": 65000, "db_port": 55432,
            "tcp_timeout_seconds": 10, "udp_timeout_seconds": 10, "timeout_check_seconds": 2,
            "retention_minutes": 30, "cleanup_interval_minutes": 1}


def secret():
    return {"username": "synthetic", "password": "synthetic-password-not-real-01", "db_password": "synthetic-db-not-real-02"}


class HostPolicyTests(unittest.TestCase):
    def test_profile_roundtrip_and_invalid_fields(self):
        self.assertEqual(host.profile(config()), config())
        for name, value in [("interface", "any"), ("interface", "eth0;id"), ("ifindex", True),
                            ("interface_mac", "not-a-mac"), ("bind_address", "0.0.0.0"),
                            ("bind_address", "::"), ("local_ip", "224.0.0.1"), ("ui_port", 80),
                            ("db_port", 65000), ("retention_minutes", 0), ("extra", "bad")]:
            with self.subTest(field=name):
                bad = config()
                bad[name] = value
                with self.assertRaises((host.Error, ValueError)):
                    host.profile(bad)

    def test_compose_bounds_and_loopback_database(self):
        spec = host.compose_spec(config(), secret(), "dh-host-" + "a" * 12)
        app, db = spec["services"]["packmate"], spec["services"]["db"]
        self.assertEqual(app["network_mode"], "host")
        self.assertEqual(app["cap_add"], ["NET_RAW"])
        self.assertEqual(app["cap_drop"], ["ALL"])
        self.assertTrue(app["read_only"])
        self.assertNotIn("privileged", app)
        self.assertNotIn("ports", app)
        self.assertEqual(db["ports"], [{"target": 5432, "published": "55432", "host_ip": "127.0.0.1", "protocol": "tcp"}])
        self.assertTrue(all("docker.sock" not in mount for mount in app["volumes"]))
        for svc in spec["services"].values():
            self.assertIn("cpus", svc)
            self.assertIn("mem_limit", svc)
            self.assertEqual(svc["logging"], {"driver": "none"})

    def test_pinned_properties_and_logger(self):
        result = host.properties(config(), secret()).decode()
        self.assertIn("packmate.capture-mode=LIVE\n", result)
        self.assertIn("packmate.interface-name=br-synthetic\n", result)
        self.assertIn("server.address=127.0.0.1\n", result)
        self.assertIn("jdbc:postgresql://127.0.0.1:55432/packmate", result)
        self.assertIn("logging.level." + host.kit.LOGGER + "=OFF", result)

    def test_interface_identity_and_state_are_verified(self):
        item = {"ifname": "br-synthetic", "ifindex": 9, "address": "02:00:00:00:00:01", "flags": ["UP"]}
        with patch.object(host.shared, "checked", return_value=json.dumps([item]).encode()) as check:
            host.interface(config())
            check.assert_called_once_with(["ip", "-json", "link", "show", "dev", "br-synthetic"], capture=True)
        for name, value in [("ifindex", 10), ("ifname", "eth0"), ("address", "02:00:00:00:00:02"), ("flags", [])]:
            bad = dict(item, **{name: value})
            with patch.object(host.shared, "checked", return_value=json.dumps([bad]).encode()), self.assertRaises(host.Error):
                host.interface(config())

    def test_preview_never_contacts_daemon(self):
        state = {"profile": config()}
        args = argparse.Namespace(workspace="unused", apply=False, action="up")
        with patch.object(host, "workspace", return_value=(Path("unused"), state)), patch.object(host.shared, "checked") as command:
            self.assertEqual(host.execute(args)["status"], "NOT_RUN")
            command.assert_not_called()

    def test_each_explicit_capture_approval_is_mandatory(self):
        state = {"profile": config()}
        args = argparse.Namespace(workspace="unused", apply=True, action="up", host_network_approved=True,
                                  interface_scope_approved=True, capture_approval="br-synthetic:9:02:00:00:00:00:01")
        for name, value in [("host_network_approved", False), ("interface_scope_approved", False), ("capture_approval", "eth0")]:
            bad = copy.copy(args)
            setattr(bad, name, value)
            with patch.object(host, "workspace", return_value=(Path("unused"), state)), patch.object(host.sys, "platform", "linux"), patch.object(host.live, "daemon") as daemon:
                with self.assertRaises(host.Error):
                    host.execute(bad)
                daemon.assert_not_called()

    def test_desktop_platform_refuses_before_daemon(self):
        args = argparse.Namespace(workspace="unused", apply=True, action="up")
        with patch.object(host, "workspace", return_value=(Path("unused"), {"profile": config()})), patch.object(host.sys, "platform", "darwin"), patch.object(host.live, "daemon") as daemon:
            with self.assertRaises(host.Error):
                host.execute(args)
            daemon.assert_not_called()

    def test_foreign_resource_blocks(self):
        with patch.object(host.shared, "checked", side_effect=[b"a" * 64, b'{}']), \
             patch.object(host, "receipt_images", return_value={"db": "sha256:" + "b" * 64, "packmate": "sha256:" + "c" * 64}), \
             self.assertRaises(host.Error):
            host.owned(Path("unused"), {"project": "dh-host-" + "a" * 12})

    def test_cleanup_does_not_require_live_interface(self):
        args = argparse.Namespace(workspace="unused", apply=True, action="down")
        state = {"profile": config(), "project": "dh-host-" + "a" * 12}
        with patch.object(host, "workspace", return_value=(Path("unused"), state)), patch.object(host.sys, "platform", "linux"), patch.object(host, "local_engine"), patch.object(host.live, "daemon"), patch.object(host, "owned"), patch.object(host, "interface") as interface, patch.object(host.shared, "checked", return_value=b"") as command:
            self.assertTrue(host.execute(args)["data_retained"])
            interface.assert_not_called()
            self.assertEqual(command.call_args.args[0][-3:], ["down", "--timeout", "10"])

    def test_prepare_preview_does_not_write_or_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "profile.json").write_text(json.dumps(config()))
            (root / "credentials.json").write_text(json.dumps(secret()))
            args = argparse.Namespace(profile=root / "profile.json", credentials=root / "credentials.json", workspace=root / "new", apply=False)
            with patch.object(host.shared, "checked") as command:
                self.assertEqual(host.prepare(args)["status"], "NOT_RUN")
                self.assertFalse((root / "new").exists())
                command.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "private host deployment writes require POSIX")
    def test_prepare_and_immutable_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            (root / "profile.json").write_text(json.dumps(config()))
            (root / "credentials.json").write_text(json.dumps(secret()))
            args = argparse.Namespace(profile=root / "profile.json", credentials=root / "credentials.json", workspace=root / "new", apply=True)
            self.assertEqual(host.prepare(args)["status"], "PASS")
            self.assertEqual(host.workspace(args.workspace)[1]["profile"], config())
            self.assertEqual((args.workspace / "application.properties").stat().st_mode & 0o777, 0o644)
            self.assertEqual((args.workspace / "state.json").stat().st_mode & 0o777, 0o600)
            (args.workspace / "application.properties").write_text("changed")
            with self.assertRaises(host.Error):
                host.workspace(args.workspace)

    def test_remote_engine_and_override_variables_are_rejected_before_capture(self):
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"):
            with patch.dict(os.environ, {name: "unapproved"}, clear=True), patch.object(host.shared, "checked") as run:
                with self.assertRaises(host.Error):
                    host.local_engine()
                run.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), patch.object(host.shared, "checked", return_value=b'{"Host":"ssh://other-host"}'):
            with self.assertRaisesRegex(host.Error, "remote context"):
                host.local_engine()

    def test_rootful_local_socket_and_same_kernel_required(self):
        socket = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
        expected = {"security": ["name=seccomp,profile=builtin"], "kernel": "synthetic-kernel"}
        replies = [b'{"Host":"unix:///var/run/docker.sock"}', json.dumps(expected).encode()]
        with patch.dict(os.environ, {}, clear=True), patch.object(host.shared, "checked", side_effect=replies), \
             patch.object(Path, "lstat", return_value=socket), \
             patch.object(host.os, "uname", return_value=SimpleNamespace(release="synthetic-kernel"), create=True):
            host.local_engine()
        for change in ({"security": ["name=rootless"]}, {"kernel": "different-kernel"}):
            changed = dict(expected, **change)
            with patch.dict(os.environ, {}, clear=True), patch.object(host.shared, "checked", side_effect=[replies[0], json.dumps(changed).encode()]), \
                 patch.object(Path, "lstat", return_value=socket), \
                 patch.object(host.os, "uname", return_value=SimpleNamespace(release="synthetic-kernel"), create=True), \
                 self.assertRaises(host.Error):
                host.local_engine()

    def owned_fixture(self):
        root = Path("/private/synthetic")
        project = "dh-host-" + "a" * 12
        images = {"db": "sha256:" + "b" * 64, "packmate": "sha256:" + "c" * 64}
        ids = {"db": "d" * 64, "packmate": "e" * 64, "network": "f" * 64}
        physical = project + "_database"
        database = {"id": ids["db"], "labels": {host.LABEL: project, "com.docker.compose.project": project, "com.docker.compose.service": "db"},
                    "image": images["db"], "privileged": False, "running": True,
                    "mounts": [{"Type": "bind", "Destination": "/var/lib/postgresql/data", "Source": str(root / "data/postgres"), "RW": True}],
                    "mode": physical, "networks": {physical: {"NetworkID": ids["network"]}},
                    "ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "55432"}]}}
        app = {"id": ids["packmate"], "labels": {host.LABEL: project, "com.docker.compose.project": project, "com.docker.compose.service": "packmate"},
               "image": images["packmate"], "privileged": False, "running": True,
               "mounts": [{"Type": "bind", "Destination": "/configuration/application.properties", "Source": str(root / "application.properties"), "RW": False}],
               "mode": "host", "networks": {"host": {}}, "ports": {}, "readonly": True, "caps": ["NET_RAW"], "drop": ["ALL"]}
        network = {"id": ids["network"], "name": physical, "labels": {host.LABEL: project, "com.docker.compose.project": project},
                   "internal": False, "containers": {ids["db"]: {}}}
        return root, {"project": project, "profile": config()}, images, ids, database, app, network

    def test_owned_runtime_checks_images_mounts_caps_publication_and_foreign_network_members(self):
        root, state, images, ids, database, app, network = self.owned_fixture()
        def responses(db, application, net):
            return [(ids["db"] + " " + ids["packmate"]).encode(), json.dumps(db).encode(), json.dumps(application).encode(),
                    ids["network"].encode(), ids["network"].encode(), json.dumps(net).encode()]
        with patch.object(host, "receipt_images", return_value=images), patch.object(host.shared, "checked", side_effect=responses(database, app, network)):
            self.assertEqual(set(host.owned(root, state)), {"db", "packmate"})
        with patch.object(host, "receipt_images", return_value=images), patch.object(host.shared, "checked", side_effect=responses(database, dict(app, caps=["CAP_NET_RAW"]), network)):
            self.assertEqual(set(host.owned(root, state)), {"db", "packmate"})
        variants = []
        for field, value in (("image", "sha256:" + "0" * 64), ("mode", "bridge"), ("privileged", True), ("caps", ["NET_ADMIN", "NET_RAW"])):
            variants.append((database, dict(app, **{field: value}), network))
        foreign = copy.deepcopy(database)
        foreign["mounts"][0]["Source"] = "/unrelated/database"
        variants.append((foreign, app, network))
        foreign = copy.deepcopy(network)
        foreign["containers"]["0" * 64] = {}
        variants.append((database, app, foreign))
        for db, application, net in variants:
            with patch.object(host, "receipt_images", return_value=images), \
                 patch.object(host.shared, "checked", side_effect=responses(db, application, net)), self.assertRaises(host.Error):
                host.owned(root, state)

    def test_unlabelled_exact_network_name_collision_is_rejected(self):
        with patch.object(host.shared, "checked", side_effect=[b"", b"", b"f" * 64]), self.assertRaises(host.Error):
            host.owned(Path("/private/synthetic"), {"project": "dh-host-" + "a" * 12})

    def test_offline_receipt_requires_independent_checksum_or_live_pin_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {"profile": config(), "credentials": secret(), "project": "dh-host-" + "a" * 12}
            images = {"db": "sha256:" + "b" * 64, "packmate": "sha256:" + "c" * 64}
            (root / "images.json").write_bytes(host.shared.canonical(images))
            (root / "runtime-compose.json").write_bytes(host.shared.canonical(host.compose_spec(config(), secret(), state["project"], images)))
            checksum = hashlib.sha256(host.shared.canonical(images)).hexdigest()
            def inspect(argv, **kw):
                self.assertTrue(argv[-1].startswith("sha256:"))
                return (argv[-1] + ";linux;amd64").encode()
            with patch.object(host.shared, "checked", side_effect=inspect):
                self.assertEqual(host.runtime(root, state, checksum), checksum)
            with patch.object(host.shared, "checked") as run, self.assertRaises(host.Error):
                host.runtime(root, state, "0" * 64)
            run.assert_not_called()
            with patch.object(host.shared, "checked", return_value=b"sha256:" + b"0" * 64), self.assertRaisesRegex(host.Error, "pinned upstream"):
                host.runtime(root, state)


class HostBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.root = self.parent / "fresh"
        self.root.mkdir(mode=0o700)
        self.source = self.parent / "approved-images.json"
        self.images = {"db": "sha256:" + "b" * 64, "packmate": "sha256:" + "c" * 64}
        self.source.write_bytes(host.shared.canonical(self.images))
        self.source.chmod(0o600)
        self.checksum = hashlib.sha256(host.shared.canonical(self.images)).hexdigest()
        self.state = {"profile": config(), "credentials": secret(), "project": "dh-host-" + "a" * 12}

    def inspect(self, argv, **kwargs):
        self.assertEqual(argv[:-1], ["docker", "image", "inspect", "--format", "{{.Id}};{{.Os}};{{.Architecture}}"])
        self.assertIn(argv[-1], self.images.values())
        return (argv[-1] + ";linux;amd64").encode()

    def test_fresh_bootstrap_uses_only_approved_local_ids_then_restarts(self):
        original = self.source.read_bytes()
        with patch.object(host.shared, "checked", side_effect=self.inspect) as inspect:
            self.assertEqual(host.runtime(self.root, self.state, self.checksum, self.source), self.checksum)
            self.assertEqual(inspect.call_count, 2)
            self.assertEqual(host.runtime(self.root, self.state, self.checksum), self.checksum)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(host.receipt_images(self.root), self.images)
        spec = json.loads((self.root / "runtime-compose.json").read_bytes())
        self.assertEqual({name: data["image"] for name, data in spec["services"].items()}, self.images)
        if os.name == "posix":
            self.assertEqual((self.root / "images.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.root / "runtime-compose.json").stat().st_mode & 0o777, 0o600)

    def test_bootstrap_preview_validates_input_without_daemon_or_writes(self):
        args = argparse.Namespace(workspace=self.root, apply=False, action="up", bootstrap_images=self.source,
                                  expected_images_sha256=self.checksum)
        with patch.object(host, "workspace", return_value=(self.root, self.state)), patch.object(host.shared, "checked") as command:
            self.assertEqual(host.execute(args)["status"], "NOT_RUN")
            command.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])
        args.expected_images_sha256 = None
        with patch.object(host, "workspace", return_value=(self.root, self.state)), self.assertRaises(host.Error):
            host.execute(args)

    def test_malformed_or_missing_hash_and_receipt_fail_before_docker(self):
        for checksum in (None, "", "0" * 64, "A" * 64, "../hash"):
            with self.subTest(checksum=checksum), patch.object(host.shared, "checked") as run, self.assertRaises(host.Error):
                host.runtime(self.root, self.state, checksum, self.source)
            run.assert_not_called()
        cases = [b"[]", b"null", b"{}", b"x" * 4097, b'{"db":null,"packmate":2}',
                 json.dumps(dict(self.images, extra="forbidden")).encode(),
                 json.dumps(dict(self.images, db="registry/forbidden:latest")).encode(),
                 json.dumps(dict(self.images, db=self.images["packmate"])).encode(),
                 ('{"db":"' + self.images["db"] + '","db":"' + self.images["db"] + '","packmate":"' + self.images["packmate"] + '"}').encode()]
        for content in cases:
            self.source.write_bytes(content)
            with self.subTest(content=content[:30]), patch.object(host.shared, "checked") as run, self.assertRaises((host.Error, ValueError)):
                host.runtime(self.root, self.state, self.checksum, self.source)
            run.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_detached_hash_is_of_canonical_object_not_whitespace(self):
        self.source.write_text(json.dumps(self.images, separators=(",", ":")))
        with patch.object(host.shared, "checked", side_effect=self.inspect):
            self.assertEqual(host.runtime(self.root, self.state, self.checksum, self.source), self.checksum)

    def test_wrong_architecture_or_observed_id_never_publishes(self):
        for reply in ("sha256:" + "b" * 64 + ";linux;arm64", "sha256:" + "b" * 64 + ";windows;amd64",
                      "sha256:" + "0" * 64 + ";linux;amd64", "unknown"):
            with self.subTest(reply=reply), patch.object(host.shared, "checked", return_value=reply.encode()), self.assertRaises(host.Error):
                host.runtime(self.root, self.state, self.checksum, self.source)
            self.assertEqual(list(self.root.iterdir()), [])

    def test_any_existing_or_partial_runtime_refuses_bootstrap(self):
        for name in ("images.json", "runtime-compose.json"):
            path = self.root / name
            path.write_bytes(b"existing-owned-data")
            with patch.object(host.shared, "checked") as run, self.assertRaisesRegex(host.Error, "fresh workspace"):
                host.runtime(self.root, self.state, self.checksum, self.source)
            run.assert_not_called()
            self.assertEqual(path.read_bytes(), b"existing-owned-data")
            path.unlink()

    def test_source_content_change_during_inspection_refuses_publication(self):
        def inspect(argv, **kwargs):
            result = self.inspect(argv, **kwargs)
            self.source.write_bytes(host.shared.canonical(dict(self.images, db="sha256:" + "a" * 64)))
            return result
        with patch.object(host.shared, "checked", side_effect=inspect), self.assertRaisesRegex(host.Error, "checksum"):
            host.runtime(self.root, self.state, self.checksum, self.source)
        self.assertEqual(list(self.root.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX file replacement semantics")
    def test_source_replacement_during_inspection_refuses_even_identical_bytes(self):
        def inspect(argv, **kwargs):
            result = self.inspect(argv, **kwargs)
            replacement = self.parent / "replacement.json"
            replacement.write_bytes(self.source.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(self.source)
            return result
        with patch.object(host.shared, "checked", side_effect=inspect), self.assertRaisesRegex(host.Error, "changed during"):
            host.runtime(self.root, self.state, self.checksum, self.source)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_destination_created_during_inspection_is_retained_not_overwritten(self):
        def inspect(argv, **kwargs):
            result = self.inspect(argv, **kwargs)
            (self.root / "runtime-compose.json").write_bytes(b"collision")
            return result
        with patch.object(host.shared, "checked", side_effect=inspect), self.assertRaisesRegex(host.Error, "fresh workspace"):
            host.runtime(self.root, self.state, self.checksum, self.source)
        self.assertEqual((self.root / "runtime-compose.json").read_bytes(), b"collision")
        self.assertFalse((self.root / "images.json").exists())

    def test_partial_publication_collision_fails_closed_and_retains_files(self):
        original_open = os.open
        def raced_open(path, flags, *args, **kwargs):
            if Path(path) == self.root / "images.json" and flags & os.O_CREAT:
                (self.root / "images.json").write_bytes(b"collision")
            return original_open(path, flags, *args, **kwargs)
        with patch.object(host.shared, "checked", side_effect=self.inspect), patch.object(host.os, "open", side_effect=raced_open), self.assertRaises(FileExistsError):
            host.runtime(self.root, self.state, self.checksum, self.source)
        self.assertEqual((self.root / "images.json").read_bytes(), b"collision")
        self.assertTrue((self.root / "runtime-compose.json").is_file())
        with patch.object(host.shared, "checked") as run, self.assertRaises(host.Error):
            host.runtime(self.root, self.state, self.checksum, self.source)
        run.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX receipt modes and special files")
    def test_private_owner_regular_unlinked_receipt_required(self):
        self.source.chmod(0o644)
        with self.assertRaisesRegex(host.Error, "private owned"):
            host.bootstrap_receipt(self.root, self.source, self.checksum)
        self.source.chmod(0o600)
        linked = self.parent / "linked.json"
        linked.symlink_to(self.source)
        with self.assertRaises(host.Error):
            host.bootstrap_receipt(self.root, linked, self.checksum)
        hardlink = self.parent / "hardlink.json"
        os.link(self.source, hardlink)
        with self.assertRaises(host.Error):
            host.bootstrap_receipt(self.root, self.source, self.checksum)
        hardlink.unlink()
        fifo = self.parent / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(host.Error):
            host.bootstrap_receipt(self.root, fifo, self.checksum)
        (self.root / "images.json").symlink_to(self.parent / "missing")
        with self.assertRaisesRegex(host.Error, "fresh workspace"):
            host.bootstrap_receipt(self.root, self.source, self.checksum)

    @unittest.skipUnless(os.name == "posix", "POSIX replacement of an open publication inode")
    def test_publication_inode_replacement_with_identical_bytes_is_rejected(self):
        original_open = os.open
        def raced_open(path, flags, *args, **kwargs):
            if Path(path) == self.root / "images.json" and flags & os.O_CREAT:
                current = self.root / "runtime-compose.json"
                replacement = self.parent / "replaced-runtime.json"
                replacement.write_bytes(current.read_bytes())
                replacement.replace(current)
            return original_open(path, flags, *args, **kwargs)
        with patch.object(host.shared, "checked", side_effect=self.inspect), patch.object(host.os, "open", side_effect=raced_open), self.assertRaisesRegex(host.Error, "publication changed"):
            host.runtime(self.root, self.state, self.checksum, self.source)


if __name__ == "__main__":
    unittest.main()
