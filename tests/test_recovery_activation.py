"""Recovery safety contracts. Mocked checks are not Docker/app acceptance."""
import argparse
import copy
from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tested_recovery_activation", ROOT / "deployment/recovery_activation.py")
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "candidate"
        self.root.mkdir(mode=0o700)
        self.state = {"schema": app.SCHEMA, "project": "dh-deploy-" + "a" * 12,
                      "source_project": "dh-deploy-" + "b" * 12, "stage_project": "dh-recovery-" + "c" * 12,
                      "daemon_id": "approved-daemon", "backup_sha256": "d" * 64,
                      "stage_verification_sha256": "e" * 64, "pending_sha256": "f" * 64,
                      "owner": {"uid": self.root.stat().st_uid, "gid": self.root.stat().st_gid},
                      "redis_policy": "DISCARD_CANDIDATE_ALL_STATE_BACKUP_RETAINED",
                      "neo_runtime_owner": "0:0", "pcap_policy": "EMPTY_CLOSED_FILE_NO_AUTO_IMPORT"}
        self.profile = json.loads((ROOT / "deployment/profile.example.json").read_text())
        credentials = {key: "synthetic-private-canary-123456" for key in ("database_password", "farm_password", "neo_key", "packmate_password")}
        credentials["packmate_user"] = "operator"
        self.spec = app.kit.compose_spec(self.profile, credentials, self.state["project"],
                                        app.kit.shared.image_map(ROOT / "config/integration-images.lock.json"))
        self.images = {name: "sha256:" + "1" * 64 for name in self.spec["services"]}
        self.runtime = app.kit.runtime_spec(self.spec, self.images)
        self.pending = {"schema": app.kit.SCHEMA, "project": self.state["project"], "files": {},
                        "source_pins": app.kit.shared.PINS, "approval_id": "test"}
        self.epoch = {name: {"id": ("%064x" % (index + 1)), "running": False,
                            "started": "2026-01-01T00:00:01Z", "finished": "2026-01-01T00:00:02Z", "restarts": 0}
                      for index, name in enumerate(app.ACTIVE)}
        self.record = {"schema": app.ACCEPTANCE, "project": self.state["project"],
                       "recovery_sha256": app.rec.sha(app.ops._canonical(self.state)),
                       "checks": {name: True for name in app.CHECKS},
                       "runtime_owners": {name: "999:1000" for name in app.rec.BACKENDS},
                       "stopped_containers": self.epoch, "redis_policy": self.state["redis_policy"],
                       "candidate_stopped": True, "submission_enabled": False, "worker_enabled": False,
                       "capture_enabled": False, "seconds": 1.2}
        self.record["runtime_owners"].update({"neo-server": "0:0", "packmate": "65534:65534"})

    def tearDown(self):
        self.temp.cleanup()

    def args(self, **changes):
        values = dict(output=str(self.root), workspace=str(self.base / "source"), backup=str(self.base / "backup"),
                      stage=str(self.base / "stage"), stage_project=self.state["stage_project"],
                      daemon_id=self.state["daemon_id"], approval_id="test", apply=True,
                      snapshot_confirmed=True, maintenance_confirmed=True, queue_reviewed=True, ttl_reviewed=True,
                      discard_candidate_redis_state=True, activation_confirmed=True,
                      acceptance_sha256=app.rec.sha(app.ops._canonical(self.record)),
                      target_uid=self.root.stat().st_uid, target_gid=self.root.stat().st_gid)
        values.update(changes)
        return argparse.Namespace(**values)

    def data(self):
        stage = (self.base / "stage", {"project": self.state["stage_project"]}, {},
                 {"verification_sha256": self.state["stage_verification_sha256"]}, self.runtime, self.profile)
        manifest = {"files": {}, "databases": {"postgres": {}, "packmate-db": {}}}
        data = (self.base / "backup", manifest, {}, self.spec, self.runtime, self.profile, stage)
        source = (self.base / "source", self.state["source_project"], self.runtime,
                  self.state["daemon_id"], app.kit.LABEL)
        return data, source

    def test_selection_excludes_worker_and_submission_but_preserves_exact_mounts(self):
        value = app.selected(self.runtime)
        self.assertEqual(set(value["services"]), set(app.ACTIVE))
        self.assertNotIn("celery", value["services"])
        self.assertNotIn("neo-worker", value["services"])
        self.assertEqual(value["services"]["neo-server"], self.runtime["services"]["neo-server"])
        value["services"]["neo-server"]["image"] = "changed"
        self.assertNotEqual(value, app.selected(self.runtime))

    def test_queue_discard_requires_explicit_separate_gate(self):
        with patch.object(app.rec, "require_promotion_apply") as gate:
            with self.assertRaisesRegex(app.Error, "discard-candidate-redis-state"):
                app.require_gates(self.args(discard_candidate_redis_state=False))
            app.require_gates(self.args())
        self.assertEqual(gate.call_count, 2)

    def test_preview_has_no_docker_no_mutation_and_describes_redis_loss(self):
        target = self.base / "unused"
        with patch.object(app, "inputs", return_value=self.data()), \
             patch.object(app.rec, "run", side_effect=AssertionError("Docker contacted")):
            result = app.recover(self.args(output=str(target), apply=False))
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertIn("ALL_STATE", result["redis_policy"])
        self.assertFalse(result["source_auto_resume"])
        self.assertFalse(target.exists())

    def test_existing_target_rejected_before_private_inputs_read(self):
        with patch.object(app, "inputs", side_effect=AssertionError("private inputs read")):
            with self.assertRaises(app.Error):
                app.recover(self.args())

    def test_running_source_is_not_automatically_stopped(self):
        with patch.object(app.rec, "owned", return_value={"postgres": {"running": True}}), \
             patch.object(app.rec, "stop", side_effect=AssertionError("source stopped")):
            with self.assertRaisesRegex(app.Error, "running"):
                app.stopped(self.data()[1])

    def test_acceptance_requires_all_true_checks_and_no_enabled_capture(self):
        path = self.root / "recovery-acceptance.json"
        path.write_bytes(app.ops._canonical(self.record))
        self.assertEqual(app.acceptance(self.root, self.state), self.record)
        mutations = []
        for field in ("capture_enabled", "submission_enabled", "worker_enabled"):
            value = copy.deepcopy(self.record)
            value[field] = True
            mutations.append(value)
        value = copy.deepcopy(self.record)
        value["checks"]["restart_reconnect"] = "PASS"
        mutations.append(value)
        value = copy.deepcopy(self.record)
        del value["checks"]["postgres"]
        mutations.append(value)
        value = copy.deepcopy(self.record)
        value["recovery_sha256"] = "0" * 64
        mutations.append(value)
        value = copy.deepcopy(self.record)
        value["runtime_owners"]["neo-server"] = "not an owner"
        mutations.append(value)
        for value in mutations:
            path.write_bytes(app.ops._canonical(value))
            with self.subTest(value=value), self.assertRaises(app.Error):
                app.acceptance(self.root, self.state)

    def test_native_ownership_accepts_operator_group_only_with_private_owner_mode(self):
        current = {name: {"id": name} for name in app.rec.BACKENDS}
        def invoke(argv, **kw):
            if "id" in argv:
                return b"999\n"
            return b"999:1000:700\n"
        with patch.object(app.rec, "run", side_effect=invoke):
            self.assertEqual(app.runtime_ownership(current)["redis"], "999:1000")
        for value in (b"999:1000:777", b"1000:1000:700", b"999:group:700"):
            with patch.object(app.rec, "run", side_effect=lambda argv, **kw: b"999" if "id" in argv else value):
                with self.assertRaises(app.Error):
                    app.runtime_ownership(current)

    def test_stopped_epochs_bind_service_ids_timestamps_and_restart_counts(self):
        current = {name: {"id": item["id"], "running": False} for name, item in self.epoch.items()}
        by_id = {item["id"]: item for item in self.epoch.values()}
        with patch.object(app, "stopped", return_value=current), \
             patch.object(app.rec, "run", side_effect=lambda argv: json.dumps(by_id[argv[-1]]).encode()):
            self.assertEqual(app.stopped_epochs(self.data()[1]), self.epoch)
        invalid = copy.deepcopy(next(iter(by_id.values())))
        invalid["running"] = True
        with patch.object(app, "stopped", return_value={"postgres": current["postgres"]}), \
             patch.object(app.rec, "run", return_value=json.dumps(invalid).encode()):
            with self.assertRaises(app.Error):
                app.stopped_epochs(self.data()[1])

    def test_application_start_is_bounded_to_safe_services_and_independent_checks(self):
        with patch.object(app.rec, "owned"), patch.object(app.rec, "run") as run, \
             patch.object(app.kit, "wait_farm") as farm, patch.object(app.kit, "wait_neo") as neo, \
             patch.object(app, "packmate_ready") as pm, patch.object(app.rec, "wait_strict_owned", return_value={
                 name: {"running": True} for name in app.ACTIVE}):
            app.start_and_check(self.root, self.state, self.runtime, self.profile)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0][-3:], ["farm", "front", "packmate"])
        self.assertEqual(run.call_args_list[1].args[0][-1], "neo-server")
        for call in run.call_args_list:
            self.assertNotIn("celery", call.args[0])
            self.assertNotIn("neo-worker", call.args[0])
            self.assertIn("never", call.args[0])
        farm.assert_called_once()
        neo.assert_called_once()
        pm.assert_called_once()

    def recovery_mocks(self, target):
        stack = ExitStack()
        data = self.data()
        stack.enter_context(patch.object(app, "inputs", return_value=data))
        stack.enter_context(patch.object(app, "require_gates"))
        stack.enter_context(patch.object(app, "stopped", return_value={}))
        stack.enter_context(patch.object(app, "stopped_epochs", return_value=self.epoch))
        stack.enter_context(patch.object(app, "prepare_files", return_value=(target, self.state, self.pending, self.runtime, self.profile)))
        stack.enter_context(patch.object(app, "workspace", return_value=(target, self.state, self.pending, self.runtime, self.profile)))
        stack.enter_context(patch.object(app.rec, "owned", return_value={name: {"id": name} for name in app.rec.BACKENDS}))
        stack.enter_context(patch.object(app.rec, "run", return_value=b"0"))
        stack.enter_context(patch.object(app.rec, "verify_backup", return_value=data[0][:2]))
        stack.enter_context(patch.object(app, "ready"))
        stack.enter_context(patch.object(app, "restore_pg"))
        stack.enter_context(patch.object(app, "runtime_ownership", return_value=self.record["runtime_owners"]))
        stack.enter_context(patch.object(app.kit, "cleanup_readiness_probes"))
        stack.enter_context(patch.object(app.ops, "_atomic_write_new"))
        return stack

    def test_recovery_failure_stops_only_candidate_and_never_publishes_acceptance(self):
        target = self.base / "failed"
        with self.recovery_mocks(target), \
             patch.object(app, "start_and_check", side_effect=app.Error("synthetic acceptance failure")), \
             patch.object(app.rec, "stop") as stop, patch.object(app.ops, "_atomic_write_new") as publish:
            with self.assertRaisesRegex(app.Error, "synthetic acceptance"):
                app.recover(self.args(output=str(target)))
        stop.assert_called_once()
        self.assertEqual(stop.call_args.args[0][0], target)
        self.assertEqual(stop.call_args.args[1], app.ACTIVE)
        publish.assert_not_called()

    def test_recovery_success_restarts_apps_then_stops_before_acceptance(self):
        target = self.base / "success"
        with self.recovery_mocks(target), patch.object(app, "start_and_check") as checks, \
             patch.object(app.rec, "stop") as stop, patch.object(app.ops, "_atomic_write_new") as publish:
            result = app.recover(self.args(output=str(target)))
        self.assertEqual(checks.call_count, 2)
        self.assertEqual(stop.call_args_list[0].args[1], app.APPS)
        self.assertEqual(stop.call_args_list[1].args[1], app.ACTIVE)
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["toolkit_runnable"])
        self.assertEqual(set(result["checks"]), app.CHECKS)
        self.assertEqual(publish.call_args.args[0].name, "recovery-acceptance.json")

    def test_nonempty_candidate_redis_blocks_apps_and_leaves_no_acceptance(self):
        target = self.base / "queues"
        with self.recovery_mocks(target), patch.object(app.rec, "run", return_value=b"12"), \
             patch.object(app, "start_and_check") as apps, patch.object(app.rec, "stop"), \
             patch.object(app.ops, "_atomic_write_new") as publish:
            with self.assertRaisesRegex(app.Error, "queue replay"):
                app.recover(self.args(output=str(target)))
        apps.assert_not_called()
        publish.assert_not_called()

    def test_partial_stop_failure_cannot_publish_a_success_record(self):
        target = self.base / "uncertain"
        with self.recovery_mocks(target), patch.object(app, "start_and_check"), \
             patch.object(app.rec, "stop", side_effect=app.Error("stop uncertain")), \
             patch.object(app.ops, "_atomic_write_new") as publish:
            with self.assertRaisesRegex(app.Error, "uncertain"):
                app.recover(self.args(output=str(target)))
        publish.assert_not_called()

    def test_probe_cleanup_failure_still_attempts_scoped_candidate_stop(self):
        target = self.base / "probe-failed"
        with self.recovery_mocks(target), patch.object(app, "start_and_check"), \
             patch.object(app.kit, "cleanup_readiness_probes", side_effect=app.Error("probe cleanup uncertain")), \
             patch.object(app.rec, "stop") as stop, patch.object(app.ops, "_atomic_write_new") as publish:
            with self.assertRaisesRegex(app.Error, "probe cleanup uncertain"):
                app.recover(self.args(output=str(target)))
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(stop.call_args.args[0][0], target)
        self.assertEqual(stop.call_args.args[1], app.ACTIVE)
        publish.assert_not_called()

    def test_operator_stop_attempts_stack_stop_after_probe_cleanup_failure(self):
        output = io.StringIO()
        with patch.object(app, "workspace", return_value=(self.root, self.state, self.pending, self.runtime, self.profile)), \
             patch.object(app.rec, "require_apply"), \
             patch.object(app.kit, "cleanup_readiness_probes", side_effect=app.Error("probe cleanup uncertain")), \
             patch.object(app.rec, "stop") as stop, redirect_stdout(output):
            code = app.main(["stop", "--output", str(self.root), "--apply", "--daemon-id", self.state["daemon_id"]])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")
        stop.assert_called_once()
        self.assertEqual(stop.call_args.args[1], app.ACTIVE)

    def test_native_restore_refuses_existing_tables_before_reading_dump(self):
        with patch.object(app.rec, "run", return_value=b"1"), \
             patch.object(app.ops, "_open_anchored_regular", side_effect=AssertionError("dump opened")):
            with self.assertRaisesRegex(app.Error, "not empty"):
                app.restore_pg(self.base, {}, "id", "postgres", "farm")

    def test_native_restore_rejects_tampering_without_executing_pg_restore(self):
        dumps = self.base / "dumps"
        dumps.mkdir()
        (dumps / "postgres.dump").write_bytes(b"PGDMPsynthetic")
        manifest = {"files": {"dumps/postgres.dump": {"bytes": 13, "sha256": "0" * 64}}}
        with patch.object(app.rec, "run", return_value=b"0") as run:
            with self.assertRaisesRegex(app.Error, "changed before"):
                app.restore_pg(self.base, manifest, "id", "postgres", "farm")
        self.assertEqual(run.call_count, 1)

    @unittest.skipIf(os.name == "nt", "private application candidate publication requires POSIX descriptors")
    def test_real_candidate_files_restore_neo_but_never_copy_redis_or_publish_deployment(self):
        backup = self.base / "backup"
        backup.mkdir(mode=0o700)
        credentials = {key: "synthetic-private-canary-123456" for key in
                       ("database_password", "farm_password", "neo_key", "packmate_password")}
        credentials["packmate_user"] = "operator"
        files = {"private/config/neo-client.yml": ('grpc_auth_key: "' + credentials["neo_key"] + '"\n').encode(),
                 "private/config/packmate.properties": app.kit.properties(self.profile, credentials).encode(),
                 "private/config/neo-server.yml": b"inert synthetic server config\n",
                 "private/sources/inert": b"source is never executed by recovery\n"}
        cold = b"\0" * 16 + struct.pack("<II", 0xED0CDAED, 2) + b"\0" * 8
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:") as archive:
            item = tarfile.TarInfo("./db.db")
            item.size = len(cold)
            archive.addfile(item, io.BytesIO(cold))
        files["cold/neo.tar"] = buffer.getvalue()
        for name, payload in files.items():
            path = backup / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        manifest = {"files": {name: {"bytes": len(payload), "sha256": app.rec.sha(payload)} for name, payload in files.items()},
                    "cold": {"neo": {"db.db": {"bytes": len(cold), "sha256": app.rec.sha(cold)}}}}
        data, _ = self.data()
        data = (backup, manifest, {"project": self.state["source_project"]}, self.spec, self.runtime, self.profile, data[6])
        target = self.base / "real-candidate"
        with patch.object(app.kit, "image_preflight", return_value=self.images), \
             patch.object(app.kit, "check_build_receipt", wraps=app.kit.check_build_receipt) as receipt, \
             patch.object(app.rec, "owned", return_value={}), \
             patch.object(app.rec, "run", return_value=b'""'), \
             patch.object(app.rec, "verify_backup", return_value=(backup, manifest)):
            original_receipt = app.kit.check_build_receipt
            receipt.side_effect = lambda root, *args, **kw: self.runtime if root == backup / "private" else receipt._mock_wraps(root, *args, **kw)
            root, state, pending, runtime, profile = app.prepare_files(self.args(output=str(target)), target, data)
        self.assertFalse((root / "deployment.json").exists())
        self.assertEqual((root / "data/neo/db.db").read_bytes(), cold)
        self.assertEqual(list((root / "data/redis").iterdir()), [])
        self.assertEqual(list((root / "data/neo-redis").iterdir()), [])
        self.assertEqual((root / "pcaps" / profile["packmate"]["pcap_file"]).read_bytes(), app.EMPTY_PCAP)
        self.assertEqual((root / "pcaps").stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / "config/neo-client.yml").stat().st_mode & 0o777, 0o644)
        self.assertEqual((root / "config/neo-server.yml").stat().st_mode & 0o777, 0o600)
        with self.assertRaises((OSError, app.Error)):
            app.kit.workspace(root)
        # A changed immutable mount is rejected, not silently rehashed.
        (root / "config/neo-client.yml").write_bytes(b"modified")
        with self.assertRaisesRegex(app.Error, "immutable input changed"):
            app.workspace(root)

    def test_cli_suppresses_exception_payload_and_does_not_claim_success(self):
        output = io.StringIO()
        with patch.object(app, "workspace", side_effect=ValueError("SECRET-CANARY")), redirect_stdout(output):
            code = app.main(["verify", "--output", str(self.root)])
        self.assertEqual(code, 2)
        self.assertNotIn("SECRET-CANARY", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "BLOCKED")

    def activation_mocks(self):
        stack = ExitStack()
        data, source = self.data()
        self.state["backup_sha256"] = app.rec.sha(app.ops._canonical(data[1]))
        stack.enter_context(patch.object(app, "workspace", return_value=(self.root, self.state, self.pending, self.runtime, self.profile)))
        stack.enter_context(patch.object(app, "inputs", return_value=(data, source)))
        stack.enter_context(patch.object(app, "acceptance", return_value=self.record))
        stack.enter_context(patch.object(app, "require_gates"))
        stack.enter_context(patch.object(app, "stopped", return_value={}))
        stack.enter_context(patch.object(app, "stopped_epochs", return_value=self.epoch))
        stack.enter_context(patch.object(app.kit, "image_preflight", return_value=self.images))
        stack.enter_context(patch.object(app.kit, "check_build_receipt"))
        stack.enter_context(patch.object(app.kit, "load", return_value=self.spec))
        return stack

    def test_activation_preview_never_contacts_docker_or_publishes_manifest(self):
        with self.activation_mocks(), patch.object(app.rec, "run", side_effect=AssertionError("Docker")):
            result = app.activate(self.args(apply=False))
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertFalse((self.root / "deployment.json").exists())

    def test_activation_requires_exact_reviewed_receipt_checksum(self):
        for fields in ({"activation_confirmed": False}, {"acceptance_sha256": "0" * 64}):
            with self.activation_mocks(), self.assertRaisesRegex(app.Error, "reviewed"):
                app.activate(self.args(**fields))

    def test_activation_rejects_candidate_restarted_since_acceptance(self):
        with self.activation_mocks(), patch.object(app, "stopped_epochs", return_value={}), \
             self.assertRaisesRegex(app.Error, "restarted or changed"):
            app.activate(self.args())
        self.assertFalse((self.root / "deployment.json").exists())

    @unittest.skipIf(os.name == "nt", "activation commit requires POSIX directory descriptors")
    def test_atomic_activation_publishes_only_exact_pending_inode_and_starts_nothing(self):
        raw = app.ops._canonical(self.pending)
        (self.root / "deployment.pending.json").write_bytes(raw)
        self.state["pending_sha256"] = app.rec.sha(raw)
        with self.activation_mocks(), patch.object(app.rec, "run", side_effect=AssertionError("services started")):
            result = app.activate(self.args())
        self.assertTrue(result["toolkit_runnable"])
        self.assertFalse(result["services_started"])
        self.assertEqual((self.root / "deployment.pending.json").stat().st_ino, (self.root / "deployment.json").stat().st_ino)
        with self.activation_mocks(), self.assertRaisesRegex(app.Error, "already activated"):
            app.activate(self.args())

    @unittest.skipIf(os.name == "nt", "activation commit requires POSIX directory descriptors")
    def test_activation_rejects_raced_pending_manifest(self):
        (self.root / "deployment.pending.json").write_bytes(b"tampered")
        with self.activation_mocks(), self.assertRaisesRegex(app.Error, "identity changed"):
            app.activate(self.args())
        self.assertFalse((self.root / "deployment.json").exists())

    @unittest.skipIf(os.name == "nt", "activation commit requires POSIX directory descriptors")
    def test_successful_link_of_replaced_source_is_rejected_and_exact_destination_removed(self):
        raw = app.ops._canonical(self.pending)
        (self.root / "deployment.pending.json").write_bytes(raw)
        self.state["pending_sha256"] = app.rec.sha(raw)
        replacement = self.root / "replaced.json"
        replacement.write_bytes(b'{"raced":"manifest"}\n')
        original_link = os.link
        def raced_link(source, destination, **kwargs):
            os.replace(replacement, self.root / "deployment.pending.json")
            return original_link(source, destination, **kwargs)
        with self.activation_mocks(), patch.object(app.os, "link", side_effect=raced_link), \
             self.assertRaisesRegex(app.Error, "changed at commit"):
            app.activate(self.args())
        self.assertFalse((self.root / "deployment.json").exists())
        self.assertEqual((self.root / "deployment.pending.json").read_bytes(), b'{"raced":"manifest"}\n')

    @unittest.skipIf(os.name == "nt", "activation commit requires POSIX directory descriptors")
    def test_lost_link_response_is_reconciled_by_held_inode(self):
        raw = app.ops._canonical(self.pending)
        (self.root / "deployment.pending.json").write_bytes(raw)
        self.state["pending_sha256"] = app.rec.sha(raw)
        original_link = os.link
        def uncertain_link(*args, **kwargs):
            original_link(*args, **kwargs)
            raise InterruptedError("synthetic lost completion")
        with self.activation_mocks(), patch.object(app.os, "link", side_effect=uncertain_link):
            result = app.activate(self.args())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual((self.root / "deployment.json").read_bytes(), raw)

    @unittest.skipIf(os.name == "nt", "activation commit requires POSIX directory descriptors")
    def test_failed_link_never_deletes_a_concurrent_foreign_destination(self):
        raw = app.ops._canonical(self.pending)
        (self.root / "deployment.pending.json").write_bytes(raw)
        self.state["pending_sha256"] = app.rec.sha(raw)
        def collided_link(*args, **kwargs):
            (self.root / "deployment.json").write_bytes(b"foreign concurrent file")
            raise FileExistsError("synthetic collision")
        with self.activation_mocks(), patch.object(app.os, "link", side_effect=collided_link), self.assertRaises(FileExistsError):
            app.activate(self.args())
        self.assertEqual((self.root / "deployment.json").read_bytes(), b"foreign concurrent file")


if __name__ == "__main__":
    unittest.main()
