"""Private recovery contract tests. Mocked Docker is not runtime acceptance."""
import argparse
import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tested_deployment_recovery", ROOT / "deployment/recovery.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
kit = recovery.kit


def archive_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo("./" + name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # Public source_workspace() canonicalizes system ancestors before
        # passing paths to internal helpers. Model that same contract here:
        # macOS tempfile can spell /private/var as the stock /var alias.
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir(mode=0o700)
        self.profile = json.loads((ROOT / "deployment/profile.example.json").read_text())
        self.credentials = {name: "private-canary-never-print-12345" for name in ("farm_password", "database_password", "neo_key", "packmate_password")}
        self.credentials["packmate_user"] = "operator"
        self.project = "dh-deploy-" + "a" * 12
        self.spec = kit.compose_spec(self.profile, self.credentials, self.project, kit.shared.image_map(ROOT / "config/integration-images.lock.json"))
        self.identities = {name: "sha256:" + "b" * 64 for name in self.spec["services"]}
        self.runtime = kit.runtime_spec(self.spec, self.identities)
        self.files = {
            "compose.json": kit.shared.canonical(self.spec), "profile.json": kit.shared.canonical(self.profile),
            "config/neo-client.yml": ('host: "neo-server:5005"\ngrpc_auth_key: "' + self.credentials["neo_key"] + '"\n').encode(),
            "config/packmate.properties": kit.properties(self.profile, self.credentials).encode(),
            "sources/inert.txt": b"inert source, never executed\n"}
        for name, data in self.files.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        self.state = {"schema": kit.SCHEMA, "project": self.project, "source_pins": kit.shared.PINS,
                      "approval_id": "test", "files": {name: recovery.sha(data) for name, data in self.files.items()}}
        (self.root / "deployment.json").write_bytes(kit.shared.canonical(self.state))
        (self.root / "runtime-compose.json").write_bytes(kit.shared.canonical(self.runtime))
        self.receipt = {"schema": "durkahelper.deployment-build.v2", "images": self.identities,
                       "compose_sha256": recovery.sha(kit.shared.canonical(self.spec)), "runtime_sha256": recovery.sha(kit.shared.canonical(self.runtime))}
        (self.root / "build-receipt.json").write_bytes(kit.shared.canonical(self.receipt))
        for name in (*recovery.BACKENDS, "neo"):
            (self.root / "data" / name).mkdir(parents=True, mode=0o700)
        (self.root / "pcaps").mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def args(self, **kwargs):
        values = dict(workspace=str(self.root), output=str(self.base / "backup"), apply=False,
                      approval_id="test", daemon_id="approved-daemon", snapshot_confirmed=True, maintenance_confirmed=True,
                      stage=str(self.base / "stage"), stage_project="dh-recovery-" + "c" * 12,
                      queue_reviewed=True, ttl_reviewed=True, target_uid=1001, target_gid=1001,
                      acceptance=None)
        values.update(kwargs)
        return argparse.Namespace(**values)

    def test_preview_validates_maintained_source_without_docker_or_writes(self):
        with patch.object(recovery, "run", side_effect=AssertionError("Docker contacted")):
            result = recovery.backup(self.args())
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertFalse(result["source_auto_resume"])
        self.assertFalse((self.base / "backup").exists())
        self.assertNotIn(self.credentials["neo_key"], json.dumps(result))

    def test_facade_paths_binding_is_preserved_as_private_backup_metadata(self):
        data = kit.shared.canonical({"schema": "durkahelper.operator-paths.v1",
                                    "paths": {"workspace": str(self.root), "sources": str(self.base / "sources")}})
        (self.root / "operator-paths.json").write_bytes(data)
        self.state["files"]["operator-paths.json"] = recovery.sha(data)
        (self.root / "deployment.json").write_bytes(kit.shared.canonical(self.state))
        self.assertIn("operator-paths.json", recovery.source_workspace(self.root)[4])

    def test_unknown_inventory_member_remains_rejected(self):
        (self.root / "extra.json").write_bytes(b"{}")
        self.state["files"]["extra.json"] = recovery.sha(b"{}")
        (self.root / "deployment.json").write_bytes(kit.shared.canonical(self.state))
        with self.assertRaisesRegex(recovery.Error, "unexpected private deployment"):
            recovery.source_workspace(self.root)

    def test_mutation_requires_all_explicit_gates(self):
        for fields in ({"approval_id": None}, {"approval_id": "secret\nvalue"},
                       {"snapshot_confirmed": False}, {"maintenance_confirmed": False}):
            with self.subTest(fields=fields), patch.object(recovery, "daemon", side_effect=AssertionError("daemon contacted")):
                with self.assertRaises(recovery.Error):
                    recovery.require_apply(self.args(**fields))

    def test_promotion_requires_queue_ttl_stage_identity_and_explicit_owner(self):
        cases = ({"queue_reviewed": False}, {"ttl_reviewed": False}, {"stage_project": None},
                 {"stage_project": "dh-recovery-not-an-id"}, {"target_uid": None},
                 {"target_gid": -1})
        for fields in cases:
            with self.subTest(fields=fields), patch.object(recovery, "require_apply"):
                with self.assertRaises(recovery.Error):
                    recovery.require_promotion_apply(self.args(apply=True, **fields))

    def test_promotion_preview_is_read_only_and_reports_unclosed_gates(self):
        stage_state = {"project": self.args().stage_project, "daemon_id": "approved-daemon"}
        verified = (self.base / "stage", stage_state, {}, {}, self.runtime, self.profile)
        manifest = {"daemon_id": "approved-daemon", "source_project": self.project}
        inputs = (self.base / "backup", manifest, self.state, self.spec, self.runtime, self.profile, verified)
        with patch.object(recovery, "_promotion_inputs", return_value=inputs), \
             patch.object(recovery, "run", side_effect=AssertionError("Docker contacted")):
            result = recovery.prepare_promotion(self.args(backup=str(self.base / "backup"), apply=False))
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse(result["candidate_created"])
        self.assertFalse(result["writers_enabled"])
        self.assertFalse(result["capture_enabled"])
        self.assertIn("application_acceptance", result["blocked_on"])
        self.assertFalse((self.base / "backup").exists())

    def test_promotion_rejects_overwrite_and_project_collision(self):
        output = self.base / "candidate"
        output.mkdir()
        with patch.object(recovery, "verify_backup", side_effect=AssertionError("backup should not be read")):
            with self.assertRaises(recovery.Error):
                recovery.prepare_promotion(self.args(output=str(output), backup=str(self.base / "backup")))
        output.rmdir()
        stage_state = {"project": self.args().stage_project, "daemon_id": "approved-daemon"}
        verified = (self.base / "stage", stage_state, {}, {}, self.runtime, self.profile)
        manifest = {"daemon_id": "approved-daemon", "source_project": self.project}
        inputs = (self.base / "backup", manifest, self.state, self.spec, self.runtime, self.profile, verified)
        with patch.object(recovery, "require_promotion_apply"), \
             patch.object(recovery, "_promotion_inputs", return_value=inputs), \
             patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(kit, "check_build_receipt"), \
             patch.object(recovery, "owned", side_effect=[{name: self.container(name, running=False) for name in recovery.BACKENDS},
                                                            {"postgres": self.container(running=False)}]), \
             patch.object(recovery.secrets, "token_hex", return_value="e" * 12), \
             patch.object(recovery, "stop") as stopped:
            with self.assertRaisesRegex(recovery.Error, "project.*already"):
                recovery.prepare_promotion(self.args(output=str(output), backup=str(self.base / "backup"), apply=True))
        stopped.assert_not_called()

    def test_verify_stage_rejects_stale_or_tampered_attestation(self):
        stage = self.base / "stage-contract"
        stage.mkdir(mode=0o700)
        project = "dh-recovery-" + "c" * 12
        spec = recovery.stage_spec(self.runtime, project)
        manifest = {"daemon_id": "approved-daemon", "source_project": self.project,
                    "files": {}, "cold": {}, "databases": {}, "source_quiesced": True}
        state = {"schema": recovery.STAGE_SCHEMA, "project": project, "daemon_id": "approved-daemon",
                 "compose_sha256": recovery.sha(recovery.ops._canonical(spec)),
                 "backup_sha256": recovery.sha(recovery.ops._canonical(manifest))}
        attestation = {"schema": recovery.STAGE_VERIFY_SCHEMA, "project": project,
                       "daemon_id": "approved-daemon", "backup_sha256": state["backup_sha256"],
                       "compose_sha256": state["compose_sha256"], "stage_stopped": True,
                       "writers_enabled": False, "checks": {name: True for name in recovery.BACKENDS}}
        attestation["verification_sha256"] = recovery.sha(recovery.ops._canonical(attestation))
        (stage / "private").mkdir()
        for name in (*recovery.BACKENDS, "neo"):
            (stage / "data" / name).mkdir(parents=True)
        (stage / "recovery-compose.json").write_bytes(recovery.ops._canonical(spec))
        (stage / "recovery-stage.json").write_bytes(recovery.ops._canonical(state))
        (stage / "recovery-verification.json").write_bytes(recovery.ops._canonical(attestation))
        original_walk = os.walk

        def guarded_walk(*args, **kwargs):
            for item in original_walk(*args, **kwargs):
                if Path(item[0]).is_relative_to(stage / "data"):
                    raise AssertionError("component-owned data bytes were traversed")
                yield item

        with patch.object(recovery, "private_root", return_value=stage), \
             patch.object(recovery.os, "walk", new=guarded_walk):
            recovered = recovery.verify_stage(stage, manifest, self.runtime, self.profile, project)
        self.assertEqual(recovered[1]["project"], project)
        (stage / "data/unexpected").mkdir()
        with patch.object(recovery, "private_root", return_value=stage), self.assertRaisesRegex(
                recovery.Error, "data-root contract"):
            recovery.verify_stage(stage, manifest, self.runtime, self.profile, project)
        (stage / "data/unexpected").rmdir()
        attestation["backup_sha256"] = "0" * 64
        (stage / "recovery-verification.json").write_bytes(recovery.ops._canonical(attestation))
        with patch.object(recovery, "private_root", return_value=stage), self.assertRaises(recovery.Error):
            recovery.verify_stage(stage, manifest, self.runtime, self.profile, project)

    @unittest.skipIf(os.name == "nt", "atomic verification publication requires POSIX descriptors")
    def test_stage_verification_precommit_failure_leaves_no_acceptable_final_file(self):
        stage = self.base / "atomic-stage"
        stage.mkdir(mode=0o700)
        stage.chmod(0o700)
        state = {"project": self.args().stage_project, "daemon_id": "approved-daemon",
                 "backup_sha256": "a" * 64, "compose_sha256": "b" * 64}
        checks = {name: True for name in recovery.BACKENDS}
        original_write = recovery.ops._write_all

        def fail_after_complete_write(descriptor, payload):
            original_write(descriptor, payload)
            raise OSError("synthetic precommit failure")

        with patch.object(recovery.ops, "_write_all", side_effect=fail_after_complete_write), \
             self.assertRaises(OSError):
            recovery.write_stage_verification(stage, state, checks)
        self.assertFalse((stage / "recovery-verification.json").exists())
        self.assertEqual(list(stage.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "atomic verification publication requires POSIX descriptors")
    def test_stage_verification_is_no_replace_and_reconciles_committed_link(self):
        state = {"project": self.args().stage_project, "daemon_id": "approved-daemon",
                 "backup_sha256": "a" * 64, "compose_sha256": "b" * 64}
        checks = {name: True for name in recovery.BACKENDS}
        occupied = self.base / "occupied-stage"
        occupied.mkdir(mode=0o700)
        occupied.chmod(0o700)
        final = occupied / "recovery-verification.json"
        final.write_bytes(b"pre-existing")
        with self.assertRaises(OSError):
            recovery.write_stage_verification(occupied, state, checks)
        self.assertEqual(final.read_bytes(), b"pre-existing")
        self.assertEqual({item.name for item in occupied.iterdir()}, {final.name})

        reconciled = self.base / "reconciled-stage"
        reconciled.mkdir(mode=0o700)
        reconciled.chmod(0o700)
        original_link = os.link

        def commit_then_interrupt(*args, **kwargs):
            original_link(*args, **kwargs)
            raise OSError("synthetic interrupted link")

        with patch.object(recovery.os, "link", side_effect=commit_then_interrupt):
            recovery.write_stage_verification(reconciled, state, checks)
        value = json.loads((reconciled / "recovery-verification.json").read_text())
        self.assertEqual(value, recovery._stage_verification_payload(state, checks))
        self.assertEqual({item.name for item in reconciled.iterdir()}, {"recovery-verification.json"})

    def test_promotion_foreign_stage_resources_fail_closed(self):
        output = self.base / "foreign-candidate"
        stage_state = {"project": self.args().stage_project, "daemon_id": "approved-daemon"}
        verified = (self.base / "stage", stage_state, {}, {}, self.runtime, self.profile)
        manifest = {"daemon_id": "approved-daemon", "source_project": self.project, "files": {}}
        inputs = (self.base / "backup", manifest, self.state, self.spec, self.runtime, self.profile, verified)
        with patch.object(recovery, "require_promotion_apply"), \
             patch.object(recovery, "_promotion_inputs", return_value=inputs), \
             patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(kit, "check_build_receipt"), \
             patch.object(recovery, "owned", side_effect=recovery.Error("foreign resource")):
            with self.assertRaises(recovery.Error):
                recovery.prepare_promotion(self.args(output=str(output), backup=str(self.base / "backup"), apply=True))
        self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "secure promotion candidate publication requires POSIX descriptors")
    def test_promotion_candidate_happy_path_is_partial_nonrunnable_and_verifiable(self):
        backup = self.base / "promotion-backup"
        private = backup / "private"
        private.mkdir(parents=True, mode=0o700)
        payloads = dict(self.files)
        payloads.update({"deployment.json": kit.shared.canonical(self.state),
                         "runtime-compose.json": kit.shared.canonical(self.runtime),
                         "build-receipt.json": kit.shared.canonical(self.receipt)})
        files = {}
        for name, data in payloads.items():
            destination = private / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            files["private/" + name] = {"bytes": len(data), "sha256": recovery.sha(data)}
        manifest = {"daemon_id": "approved-daemon", "source_project": self.project, "files": files}
        stage_state = {"project": self.args().stage_project, "daemon_id": "approved-daemon"}
        verification = {"verification_sha256": "f" * 64}
        verified = (self.base / "stage", stage_state, {}, verification, self.runtime, self.profile)
        inputs = (backup, manifest, self.state, self.spec, self.runtime, self.profile, verified)
        stopped = {name: self.container(name, running=False) for name in recovery.BACKENDS}
        output = self.base / "candidate"
        args = self.args(output=str(output), backup=str(backup), apply=True,
                         target_uid=os.geteuid(), target_gid=os.getegid())
        with patch.object(recovery, "require_promotion_apply"), \
             patch.object(recovery, "_promotion_inputs", return_value=inputs), \
             patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(kit, "check_build_receipt"), \
             patch.object(recovery, "owned", side_effect=[stopped, {}]), \
             patch.object(recovery, "verify_backup", return_value=(backup, manifest)), \
             patch.object(recovery, "verify_stage", return_value=verified), \
             patch.object(recovery, "stop") as stopped_again:
            result = recovery.prepare_promotion(args)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertTrue(result["candidate_created"])
        self.assertFalse(result["compose_runnable"])
        self.assertFalse(result["runnable_artifacts_present"])
        self.assertFalse((output / "workspace/deployment.json").exists())
        self.assertTrue((output / "workspace/deployment.pending.json").is_file())
        self.assertTrue((output / "promotion-plan.json").is_file())
        for name in ("compose.json", "runtime-compose.json", "build-receipt.json",
                     "compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"):
            self.assertFalse((output / "workspace" / name).exists())
        for metadata in (output / "workspace").glob("*.json"):
            value = json.loads(metadata.read_text())
            self.assertFalse(isinstance(value.get("services"), dict), metadata.name)
        plan = json.loads((output / "promotion-plan.json").read_text())
        self.assertEqual(plan["candidate_contract"], {
            "compose_spec": "ABSENT", "runtime_spec": "ABSENT", "build_receipt": "ABSENT",
            "deployment_state": "PENDING_ONLY"})
        stopped_again.assert_called_once()
        with patch.object(recovery, "_promotion_inputs", return_value=inputs):
            verified_result = recovery.verify_promotion(self.args(output=str(output), backup=str(backup)))
        self.assertEqual(verified_result["candidate_integrity"], "PASS")
        self.assertEqual(verified_result["status"], "PARTIAL")
        self.assertFalse(verified_result["toolkit_runnable"])
        self.assertFalse(verified_result["compose_runnable"])
        self.assertFalse(verified_result["runnable_artifacts_present"])
        original_plan = (output / "promotion-plan.json").read_bytes()

        for field, replacement in (
                ("expected_application_acceptance", {
                    **plan["expected_application_acceptance"],
                    "submission_enabled": True,
                }),
                ("rollback", "activate the candidate without preserving the stopped stage")):
            tampered = copy.deepcopy(plan)
            tampered[field] = replacement
            tampered_body = {name: value for name, value in tampered.items() if name != "plan_sha256"}
            tampered["plan_sha256"] = recovery.sha(recovery.ops._canonical(tampered_body))
            (output / "promotion-plan.json").write_bytes(recovery.ops._canonical(tampered))
            (output / "promotion-plan.json").chmod(0o600)
            with self.subTest(field=field), patch.object(recovery, "_promotion_inputs", return_value=inputs), \
                    self.assertRaisesRegex(recovery.Error, "binding or checksum"):
                recovery.verify_promotion(self.args(output=str(output), backup=str(backup)))
        (output / "promotion-plan.json").write_bytes(original_plan)
        (output / "promotion-plan.json").chmod(0o600)

        runnable = output / "workspace/compose.json"
        runnable.write_bytes(kit.shared.canonical(recovery.reproject_spec(self.spec, plan["project"])))
        runnable.chmod(0o600)
        plan["candidate_files"]["workspace/compose.json"] = {
            "bytes": runnable.stat().st_size, "sha256": recovery.sha(runnable.read_bytes())}
        plan_body = {name: value for name, value in plan.items() if name != "plan_sha256"}
        plan["plan_sha256"] = recovery.sha(recovery.ops._canonical(plan_body))
        (output / "promotion-plan.json").write_bytes(recovery.ops._canonical(plan))
        (output / "promotion-plan.json").chmod(0o600)
        with patch.object(recovery, "_promotion_inputs", return_value=inputs), \
             self.assertRaisesRegex(recovery.Error, "runnable-state|runnable or unexpected"):
            recovery.verify_promotion(self.args(output=str(output), backup=str(backup)))
        runnable.unlink()
        (output / "promotion-plan.json").write_bytes(original_plan)
        (output / "promotion-plan.json").chmod(0o600)
        protected = output / "workspace/config/neo-client.yml"
        protected.chmod(0o600)
        with patch.object(recovery, "_promotion_inputs", return_value=inputs), self.assertRaises(recovery.Error):
            recovery.verify_promotion(self.args(output=str(output), backup=str(backup)))

    def test_promotion_acceptance_record_is_exact_and_candidate_bound(self):
        plan = {"project": "dh-deploy-0123456789ab", "plan_sha256": "a" * 64}
        record = {
            "schema": recovery.ACCEPTANCE_SCHEMA,
            "project": plan["project"],
            "plan_sha256": plan["plan_sha256"],
            "checks": {
                "component_native_data_restore": "PASS",
                "filesystem_ownership": "PASS",
                "farm_authenticated": "PASS",
                "neo_authenticated": "PASS",
                "packmate_file": "PASS",
                "restart_reconnect": "PASS",
            },
            "submission_enabled": False,
            "worker_enabled": False,
            "capture_enabled": False,
            "rollback_confirmed": True,
        }
        path = self.base / "promotion-acceptance.json"
        path.write_bytes(recovery.ops._canonical(record))
        self.assertEqual(recovery._verify_acceptance(path, plan), record)

        mutations = []
        failed = copy.deepcopy(record)
        failed["checks"]["restart_reconnect"] = "FAIL"
        mutations.append(failed)
        enabled = copy.deepcopy(record)
        enabled["submission_enabled"] = True
        mutations.append(enabled)
        unbound = copy.deepcopy(record)
        unbound["plan_sha256"] = "b" * 64
        mutations.append(unbound)
        for mutation in mutations:
            path.write_bytes(recovery.ops._canonical(mutation))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(recovery.Error, "incomplete or not bound"):
                recovery._verify_acceptance(path, plan)

    @unittest.skipIf(os.name == "nt", "secure promotion candidate publication requires POSIX descriptors")
    def test_promotion_partial_creation_is_removed_and_stage_is_left_stopped(self):
        output = self.base / "failed-candidate"
        backup = self.base / "failed-backup"
        (backup / "private/config").mkdir(parents=True, mode=0o700)
        data = b"inert"
        (backup / "private/config/inert").write_bytes(data)
        manifest = {"daemon_id": "approved-daemon", "source_project": self.project,
                    "files": {"private/config/inert": {"bytes": len(data), "sha256": recovery.sha(data)}}}
        stage_state = {"project": self.args().stage_project, "daemon_id": "approved-daemon"}
        verified = (self.base / "stage", stage_state, {}, {"verification_sha256": "f" * 64},
                    self.runtime, self.profile)
        inputs = (backup, manifest, self.state, self.spec, self.runtime, self.profile, verified)
        stopped = {name: self.container(name, running=False) for name in recovery.BACKENDS}
        args = self.args(output=str(output), backup=str(backup), apply=True,
                         target_uid=os.geteuid(), target_gid=os.getegid())
        with patch.object(recovery, "require_promotion_apply"), \
             patch.object(recovery, "_promotion_inputs", return_value=inputs), \
             patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(kit, "check_build_receipt"), \
             patch.object(recovery, "owned", side_effect=[stopped, {}]), \
             patch.object(recovery.ops, "_copy_stable", side_effect=recovery.Error("synthetic copy failure")), \
             patch.object(recovery, "stop") as stopped_again, self.assertRaises(recovery.Error):
            recovery.prepare_promotion(args)
        self.assertFalse(output.exists())
        self.assertTrue(backup.is_dir())
        stopped_again.assert_not_called()

    @unittest.skipIf(os.name == "nt", "secure promotion candidate publication requires POSIX descriptors")
    def test_promotion_performs_no_docker_operation_after_publication(self):
        output = self.base / "ordered-candidate"
        backup = self.base / "ordered-backup"
        (backup / "private/config").mkdir(parents=True, mode=0o700)
        data = b"inert"
        (backup / "private/config/inert").write_bytes(data)
        manifest = {"daemon_id": "approved-daemon", "source_project": self.project,
                    "files": {"private/config/inert": {"bytes": len(data), "sha256": recovery.sha(data)}}}
        stage_state = {"project": self.args().stage_project, "daemon_id": "approved-daemon"}
        verified = (self.base / "stage", stage_state, {}, {"verification_sha256": "f" * 64},
                    self.runtime, self.profile)
        inputs = (backup, manifest, self.state, self.spec, self.runtime, self.profile, verified)
        stopped = {name: self.container(name, running=False) for name in recovery.BACKENDS}
        args = self.args(output=str(output), backup=str(backup), apply=True,
                         target_uid=os.geteuid(), target_gid=os.getegid())
        publication = {"committed": False, "owned_calls": 0}
        original_publish = recovery.ops._publish_directory

        def inspect_owned(*_args, **_kwargs):
            self.assertFalse(publication["committed"], "Docker inspection occurred after publication")
            publication["owned_calls"] += 1
            return stopped if publication["owned_calls"] == 1 else {}

        def stop_before_publish(*_args, **_kwargs):
            self.assertFalse(publication["committed"], "Docker stop occurred after publication")

        def publish(staging, target):
            result = original_publish(staging, target)
            publication["committed"] = True
            return result

        with patch.object(recovery, "require_promotion_apply"), \
             patch.object(recovery, "_promotion_inputs", return_value=inputs), \
             patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(kit, "check_build_receipt"), \
             patch.object(recovery, "owned", side_effect=inspect_owned), \
             patch.object(recovery, "verify_backup", return_value=(backup, manifest)), \
             patch.object(recovery, "verify_stage", return_value=verified), \
             patch.object(recovery, "stop", side_effect=stop_before_publish) as stopped_once, \
             patch.object(recovery.ops, "_publish_directory", side_effect=publish):
            result = recovery.prepare_promotion(args)
        self.assertTrue(publication["committed"])
        self.assertTrue(result["candidate_created"])
        self.assertFalse(result["runnable_artifacts_present"])
        stopped_once.assert_called_once()

    def test_daemon_mismatch_and_malformed_identity_are_blocked(self):
        with patch.object(recovery, "run", return_value=b"another-daemon"):
            with self.assertRaises(recovery.Error):
                recovery.daemon("approved-daemon")
        with patch.object(recovery, "run", side_effect=AssertionError("run")):
            for value in (None, "bad", "shell;command"):
                with self.assertRaises(recovery.Error):
                    recovery.daemon(value)

    def test_existing_nested_and_repository_outputs_are_rejected(self):
        for target in (self.root, self.root / "backup", ROOT / "local/new-recovery"):
            with self.subTest(target=target), self.assertRaises((recovery.Error, OSError)):
                recovery.new_target(target, self.root)

    def test_changed_source_config_is_rejected(self):
        (self.root / "config/neo-client.yml").write_text("changed")
        with self.assertRaises(Exception):
            recovery.source_workspace(self.root)

    def test_rehashed_custom_compose_command_or_mount_is_rejected(self):
        bad = copy.deepcopy(self.spec)
        bad["services"]["postgres"]["entrypoint"] = ["arbitrary-command"]
        with patch.object(kit, "check_build_receipt", return_value=kit.runtime_spec(bad, self.identities)):
            with self.assertRaisesRegex(recovery.Error, "maintained Compose"):
                recovery.maintained_runtime(self.root, self.state, bad, self.profile)

    def test_quarantine_spec_has_no_apps_ports_external_network_or_aof_replay(self):
        value = recovery.stage_spec(self.runtime, "dh-recovery-" + "c" * 12)
        self.assertEqual(set(value["services"]), set(recovery.BACKENDS))
        self.assertTrue(value["networks"]["quarantine"]["internal"])
        for name, service in value["services"].items():
            self.assertNotIn("ports", service)
            self.assertNotIn("build", service)
            self.assertEqual(service["restart"], "no")
            self.assertEqual(service["networks"], ["quarantine"])
            if "redis" in name:
                self.assertEqual(service["command"], ["redis-server", "--appendonly", "no", "--save", ""])

    def test_database_summary_accepts_uninitialized_empty_public_schema(self):
        with patch.object(recovery, "run", return_value=b"") as command:
            self.assertEqual(recovery.pg_summary("d" * 64, "farm"), {})
        command.assert_called_once()
        self.assertIn("information_schema.tables", command.call_args.args[0][-1])

    def test_database_summary_rejects_malformed_or_excessive_table_inventory(self):
        for names in (b"flags;DROP_TABLE", b'bad"identifier', b"schema.table", b"flags\n" * 257):
            with self.subTest(names=names[:20]), patch.object(recovery, "run", return_value=names) as command:
                with self.assertRaises(recovery.Error):
                    recovery.pg_summary("d" * 64, "farm")
                command.assert_called_once()

    def container(self, name="postgres", **changes):
        spec = self.runtime["services"][name]
        mounts = []
        for volume in spec.get("volumes", []):
            source, destination, *flags = volume.split(":")
            mounts.append({"Type": "bind", "Source": str(self.root / source[2:]), "Destination": destination, "RW": "ro" not in flags})
        result = {"id": "d" * 64, "image": spec["image"], "running": True, "mounts": mounts,
                  "labels": {kit.LABEL: self.project, "com.docker.compose.project": self.project, "com.docker.compose.service": name}}
        result.update(changes)
        return result

    def docker_listing(self, value):
        def fake(argv, **kwargs):
            if argv[1] == "ps":
                return ("d" * 64).encode()
            if argv[1:3] == ["container", "inspect"]:
                return json.dumps(value).encode()
            if argv[1:3] == ["network", "ls"]:
                return b""
            if argv[1:3] == ["image", "inspect"]:
                return value["image"].encode()
            raise AssertionError("unexpected command")
        return fake

    def test_exact_owned_resources_are_accepted(self):
        with patch.object(recovery, "daemon"), patch.object(recovery, "run", side_effect=self.docker_listing(self.container())):
            result = recovery.owned(self.root, self.project, self.runtime, "approved-daemon")
        self.assertEqual(set(result), {"postgres"})

    def test_quarantine_network_preflight_and_post_up_contract_are_exact(self):
        project = "dh-recovery-" + "c" * 12
        stage = self.base / "network-stage"
        runtime = recovery.stage_spec(self.runtime, project)
        physical = project + "_quarantine"
        network_id = "e" * 64
        service_ids = {name: format(index, "x") * 64
                       for index, name in enumerate(sorted(recovery.BACKENDS), 1)}
        containers = {}
        for name, identity in service_ids.items():
            mounts = []
            for volume in runtime["services"][name].get("volumes", []):
                source, destination, *flags = volume.split(":")
                mounts.append({"Type": "bind", "Source": str(stage / source[2:]),
                               "Destination": destination, "RW": "ro" not in flags})
            containers[identity] = {
                "id": identity, "image": runtime["services"][name]["image"], "running": True,
                "mounts": mounts,
                "labels": {recovery.LABEL: project, "com.docker.compose.project": project,
                           "com.docker.compose.service": name},
                "networks": {physical: {"NetworkID": network_id}},
            }
        network = {"id": network_id, "name": physical, "internal": True,
                   "labels": {recovery.LABEL: project, "com.docker.compose.project": project},
                   "containers": {identity: {} for identity in service_ids.values()}}

        def command(container_values, network_values, calls):
            def fake(argv, **_kwargs):
                calls.append(argv)
                if argv[1] == "ps":
                    self.assertIn("label=com.docker.compose.project=" + project, argv)
                    return "\n".join(container_values).encode()
                if argv[1:3] == ["container", "inspect"]:
                    return json.dumps(container_values[argv[-1]]).encode()
                if argv[1:3] == ["network", "ls"]:
                    selected = []
                    query = argv[argv.index("--filter") + 1]
                    for identity, value in network_values.items():
                        if (query == "label=com.docker.compose.project=" + project and
                                value.get("labels", {}).get("com.docker.compose.project") == project):
                            selected.append(identity)
                        elif query == "name=" + physical:
                            selected.append(identity + " " + value["name"])
                    return "\n".join(selected).encode()
                if argv[1:3] == ["network", "inspect"]:
                    return json.dumps(network_values[argv[-1]]).encode()
                raise AssertionError("unexpected Docker command")
            return fake

        calls = []
        with patch.object(recovery, "daemon"), \
             patch.object(recovery, "run", side_effect=command(containers, {network_id: network}, calls)):
            result = recovery.owned(stage, project, runtime, "approved-daemon", recovery.LABEL,
                                    exclusive=False, strict_networks=True)
        self.assertEqual(set(result), set(recovery.BACKENDS))
        inspected = {call[-1] for call in calls if call[1:3] == ["container", "inspect"]}
        self.assertEqual(inspected, set(service_ids.values()))

        # Docker removes stopped endpoints from network inspect .Containers,
        # while container inspect retains the configured NetworkID with an
        # empty endpoint.  Final restore attestation must accept that exact
        # stopped state without weakening attachment/ownership checks.
        stopped_containers = copy.deepcopy(containers)
        for value in stopped_containers.values():
            value["running"] = False
        stopped_network = copy.deepcopy(network)
        stopped_network["containers"] = {}
        with patch.object(recovery, "daemon"), \
             patch.object(recovery, "run", side_effect=command(
                 stopped_containers, {network_id: stopped_network}, [])):
            stopped = recovery.owned(stage, project, runtime, "approved-daemon", recovery.LABEL,
                                     exclusive=False, strict_networks=True)
        self.assertEqual(set(stopped), set(recovery.BACKENDS))

        cases = []
        not_internal = copy.deepcopy(network)
        not_internal["internal"] = False
        cases.append((containers, {network_id: not_internal}))
        foreign_member = copy.deepcopy(network)
        foreign_member["containers"]["f" * 64] = {}
        cases.append((containers, {network_id: foreign_member}))
        wrong_attachment = copy.deepcopy(containers)
        wrong_attachment[next(iter(wrong_attachment))]["networks"]["unexpected"] = {
            "NetworkID": "f" * 64}
        cases.append((wrong_attachment, {network_id: network}))
        extra_id = "f" * 64
        extra = {"id": extra_id, "name": project + "_extra", "internal": True,
                 "labels": {recovery.LABEL: project, "com.docker.compose.project": project},
                 "containers": {}}
        cases.append((containers, {network_id: network, extra_id: extra}))
        for container_values, network_values in cases:
            with self.subTest(networks=list(network_values)), patch.object(recovery, "daemon"), \
                 patch.object(recovery, "run", side_effect=command(container_values, network_values, [])), \
                 self.assertRaises(recovery.Error):
                recovery.owned(stage, project, runtime, "approved-daemon", recovery.LABEL,
                               exclusive=False, strict_networks=True)

        foreign_exact = copy.deepcopy(network)
        foreign_exact["labels"] = {}
        with patch.object(recovery, "daemon"), \
             patch.object(recovery, "run", side_effect=command({}, {network_id: foreign_exact}, [])), \
             self.assertRaises(recovery.Error):
            recovery.owned(stage, project, runtime, "approved-daemon", recovery.LABEL,
                           exclusive=False, require_no_networks=True)

    def test_post_up_network_contract_wait_is_bounded_and_fail_closed(self):
        context = (self.root, self.project, self.runtime, "approved-daemon", recovery.LABEL)
        expected = {"postgres": self.container()}
        with patch.object(recovery, "owned", side_effect=[recovery.Error("transient"), expected]) as ownership, \
             patch.object(recovery.time, "monotonic", side_effect=[0.0, 0.1]), \
             patch.object(recovery.time, "sleep") as pause:
            self.assertEqual(recovery.wait_strict_owned(context, timeout=1.0), expected)
        self.assertEqual(ownership.call_count, 2)
        pause.assert_called_once_with(0.1)
        for call in ownership.call_args_list:
            self.assertFalse(call.kwargs["exclusive"])
            self.assertTrue(call.kwargs["strict_networks"])

        with patch.object(recovery, "owned", side_effect=recovery.Error("persistent")) as ownership, \
             patch.object(recovery.time, "monotonic", side_effect=[0.0, 1.0]), \
             patch.object(recovery.time, "sleep") as pause, \
             self.assertRaisesRegex(recovery.Error, "did not converge"):
            recovery.wait_strict_owned(context, timeout=1.0)
        ownership.assert_called_once()
        pause.assert_not_called()

    def test_foreign_owner_image_and_external_mount_are_rejected(self):
        bad_mount = [{"Type": "bind", "Source": str(self.base / "foreign"), "Destination": "/var/lib/postgresql/data", "RW": True}]
        cases = [self.container(labels={"com.docker.compose.project": self.project}),
                 self.container(image="sha256:" + "e" * 64), self.container(mounts=bad_mount),
                 self.container(labels={"unrelated": "never printed"})]
        for value in cases:
            with self.subTest(value=list(value)), patch.object(recovery, "daemon"), patch.object(recovery, "run", side_effect=self.docker_listing(value)):
                with self.assertRaises(recovery.Error):
                    recovery.owned(self.root, self.project, self.runtime, "approved-daemon")

    def test_stop_targets_only_validated_exact_running_ids(self):
        before = {"postgres": self.container(), "celery": self.container("celery")}
        after = copy.deepcopy(before)
        after["celery"]["running"] = False
        with patch.object(recovery, "owned", side_effect=[before, after]), patch.object(recovery, "run") as command:
            recovery.stop((self.root, self.project, self.runtime, "approved-daemon", kit.LABEL), recovery.WRITERS)
        self.assertEqual(command.call_args.args[0], ["docker", "stop", "--time", "20", "d" * 64])

    def test_uncertain_helper_create_is_reconciled_after_error_and_interrupt(self):
        for failure in (subprocess.TimeoutExpired("docker", 10), KeyboardInterrupt(), None):
            with self.subTest(failure=type(failure).__name__), patch.object(recovery, "daemon"), \
                 patch.object(recovery, "run", side_effect=failure if failure is not None else None, return_value=b"truncated-id"), \
                 patch.object(recovery, "cleanup_helpers") as cleanup:
                with self.assertRaises((subprocess.TimeoutExpired, KeyboardInterrupt, recovery.Error)):
                    recovery.helper(self.root, self.project, self.identities["redis"], "redis", "approved-daemon", check=True)
                cleanup.assert_called_once()
                self.assertRegex(cleanup.call_args.args[2], r"^dh-cold-[a-f0-9]{24}$")

    def test_helper_cleanup_requires_exact_name_owner_purpose_and_full_id(self):
        identity, name = "e" * 64, "dh-cold-" + "f" * 24
        good = {"id": identity, "name": "/" + name, "owner": self.project, "purpose": "cold-read"}
        for field in (None, "id", "name", "owner", "purpose"):
            observed = dict(good)
            if field:
                observed[field] = "unrelated"
            def command(argv, **kwargs):
                if argv[1] == "ps":
                    return identity.encode()
                if argv[1] == "inspect":
                    return json.dumps(observed).encode()
                return b""
            with self.subTest(field=field), patch.object(recovery, "daemon"), patch.object(recovery, "run", side_effect=command) as execute:
                if field:
                    with self.assertRaises(recovery.Error):
                        recovery.cleanup_helpers(self.project, "approved-daemon", name)
                    self.assertFalse(any(call.args[0][1] == "rm" for call in execute.call_args_list))
                else:
                    recovery.cleanup_helpers(self.project, "approved-daemon", name)
                    self.assertEqual(execute.call_args.args[0], ["docker", "rm", "--force", identity])

    def test_cold_archives_validate_native_signatures_and_hashes(self):
        path = self.base / "cold.tar"
        blob = b"REDIS0010" + b"x" * 50
        path.write_bytes(archive_bytes({"dump.rdb": blob, "appendonlydir/appendonly.aof": b"other snapshot"}))
        result = recovery.cold_members(path, directory="redis")
        self.assertEqual(result["dump.rdb"], {"bytes": len(blob), "sha256": recovery.sha(blob)})
        bolt = b"\0" * 16 + struct.pack("<II", 0xED0CDAED, 2) + b"\0" * 4096
        path.write_bytes(archive_bytes({"db.db": bolt, "exploits/inert": b"not executed"}))
        self.assertIn("db.db", recovery.cold_members(path, directory="neo"))

    def test_cold_archive_rejects_traversal_missing_or_bad_database_headers(self):
        path = self.base / "cold.tar"
        cases = [({"../outside": b"x", "dump.rdb": b"REDIS0010"}, "redis"),
                 ({"dump.rdb": b"not redis"}, "redis"), ({"other": b"REDIS0010"}, "redis"),
                 ({"db.db": b"not bbolt"}, "neo")]
        for entries, directory in cases:
            path.write_bytes(archive_bytes(entries))
            with self.subTest(directory=directory), self.assertRaises(recovery.Error):
                recovery.cold_members(path, directory=directory)

    def test_cli_errors_never_expose_arbitrary_exception_or_credentials(self):
        output = io.StringIO()
        with patch.object(recovery, "backup", side_effect=RuntimeError(self.credentials["neo_key"])), redirect_stdout(output):
            code = recovery.main(["backup", "--workspace", "private", "--output", "new"])
        self.assertEqual(code, 2)
        self.assertNotIn(self.credentials["neo_key"], output.getvalue())
        self.assertFalse(json.loads(output.getvalue())["source_auto_resume"])

    def test_cli_partial_promotion_uses_exit_two_without_secrets(self):
        output = io.StringIO()
        result = {"status": "PARTIAL", "action": "prepare-promotion", "candidate_created": False}
        argv = ["prepare-promotion", "--backup", "private", "--stage", "stage", "--output", "new",
                "--stage-project", "dh-recovery-" + "c" * 12]
        with patch.object(recovery, "prepare_promotion", return_value=result), redirect_stdout(output):
            code = recovery.main(argv)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), result)

    def test_bounded_process_output_is_rejected_without_echo(self):
        class Process:
            def __init__(self):
                self.stdout = io.BytesIO(b"private-canary" * 100)
                self.killed = False
            def wait(self, timeout=None):
                return 0
            def poll(self):
                return 0
            def kill(self):
                self.killed = True
        process = Process()
        with patch.object(recovery.subprocess, "Popen", return_value=process), self.assertRaises(recovery.Error):
            recovery.run(["inert"], limit=16)
        self.assertTrue(process.killed)

    def test_cold_copy_rejects_changed_expected_hash_and_symlink(self):
        path = self.base / "cold.tar"
        path.write_bytes(archive_bytes({"dump.rdb": b"REDIS0010"}))
        with self.assertRaisesRegex(recovery.Error, "changed before use"):
            recovery.cold_members(path, directory="redis", expected={"bytes": path.stat().st_size, "sha256": "0" * 64})

    def test_tar_link_member_is_never_extracted(self):
        path = self.base / "linked.tar"
        with tarfile.open(path, "w:") as archive:
            member = tarfile.TarInfo("dump.rdb")
            member.type = tarfile.SYMTYPE
            member.linkname = "outside"
            archive.addfile(member)
        with self.assertRaises(recovery.Error):
            recovery.cold_members(path, directory="redis")

    @unittest.skipIf(os.name == "nt", "native recovery staging requires descriptor-anchored POSIX writes")
    def test_mocked_native_backup_roundtrip_preserves_secrets_only_privately(self):
        current = {name: self.container(name) for name in self.runtime["services"]}
        def stop(_source, names):
            for name in names:
                current[name]["running"] = False
        def dump(staging, name, argv):
            data = b"PGDMP synthetic native dump"
            staging.write_new_bytes(name, data)
            return {"prefix": data[:32], "bytes": len(data), "sha256": recovery.sha(data)}
        def cold(root, project, image, directory, daemon_id, *, staging=None, check=False):
            if check:
                return
            data = b"REDIS0010" + b"x" * 50 if directory != "neo" else b"\0" * 16 + struct.pack("<II", 0xED0CDAED, 2) + b"\0" * 4096
            staging.write_new_bytes("cold/" + directory + ".tar", archive_bytes({"dump.rdb" if directory != "neo" else "db.db": data}))
        with patch.object(recovery, "require_apply"), patch.object(recovery, "cleanup_helpers"), patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(recovery, "owned", side_effect=lambda *a: copy.deepcopy(current)), \
             patch.object(recovery, "stop", side_effect=stop), patch.object(recovery, "stream_file", side_effect=dump), \
             patch.object(recovery, "helper", side_effect=cold), patch.object(recovery, "pg_summary", return_value={"inert": {"bytes": 1, "sha256": "f" * 64}}), \
             patch.object(recovery, "run", return_value=b"OK"):
            result = recovery.backup(self.args(apply=True))
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["source_left_quiesced"])
        self.assertNotIn(self.credentials["neo_key"], json.dumps(result))
        backup_root, value = recovery.verify_backup(self.base / "backup")
        self.assertIn(self.credentials["neo_key"], (backup_root / "private/config/neo-client.yml").read_text())
        self.assertEqual(backup_root.stat().st_mode & 0o777, 0o700)
        with patch.object(recovery, "run", side_effect=AssertionError("Docker")):
            preview = recovery.restore(self.args(backup=str(backup_root), output=str(self.base / "stage")))
        self.assertFalse(preview["writers_enabled"])
        staged = {name: self.container(name) for name in recovery.BACKENDS}
        def restore_run(argv, **kwargs):
            if argv[-1] == "PING":
                return b"PONG"
            if "psql" in argv:
                return b"0"
            return b""
        staged_stopped = copy.deepcopy(staged)
        for container_state in staged_stopped.values():
            container_state["running"] = False
        with patch.object(recovery, "require_apply"), patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(recovery, "owned", side_effect=[{}, staged, staged_stopped]) as ownership, \
             patch.object(recovery, "stop") as stopped, \
             patch.object(recovery, "pg_summary", return_value=value["databases"]["postgres"]), \
             patch.object(recovery, "run", side_effect=restore_run) as execute:
            restored = recovery.restore(self.args(apply=True, backup=str(backup_root), output=str(self.base / "stage")))
        self.assertEqual(restored["status"], "PASS")
        self.assertTrue(restored["stage_left_stopped"])
        self.assertFalse(restored["writers_enabled"])
        stopped.assert_called_once()
        self.assertTrue(ownership.call_args_list[0].kwargs["require_no_networks"])
        self.assertTrue(ownership.call_args_list[1].kwargs["strict_networks"])
        self.assertTrue(ownership.call_args_list[2].kwargs["strict_networks"])
        readiness = [call.args[0] for call in execute.call_args_list if "pg_isready" in call.args[0]]
        self.assertEqual(len(readiness), 2)
        self.assertTrue(all(command[command.index("-h") + 1] == "127.0.0.1" for command in readiness))
        self.assertTrue((self.base / "stage/recovery-verification.json").is_file())
        self.assertFalse((self.base / "stage/deployment.json").exists())
        with self.assertRaises(Exception):
            kit.workspace(self.base / "stage")
        self.assertEqual(set(json.loads((self.base / "stage/recovery-compose.json").read_text())["services"]), set(recovery.BACKENDS))
        # A restore failure retains its new private stage and stops only its DBs.
        def failed_restore(argv, **kwargs):
            if "pg_restore" in argv:
                raise recovery.Error("native restore rejected")
            return restore_run(argv, **kwargs)
        with patch.object(recovery, "require_apply"), patch.object(kit, "image_preflight", return_value=self.identities), \
             patch.object(recovery, "owned", side_effect=[{}, staged]), patch.object(recovery, "stop") as stopped, \
             patch.object(recovery, "run", side_effect=failed_restore), self.assertRaises(recovery.Error):
            recovery.restore(self.args(apply=True, backup=str(backup_root), output=str(self.base / "failed-stage")))
        stopped.assert_called_once()
        self.assertTrue((self.base / "failed-stage/recovery-stage.json").is_file())
        recovery.verify_backup(backup_root)
        (backup_root / "dumps/postgres.dump").write_bytes(b"tampered")
        with self.assertRaises(recovery.Error):
            recovery.verify_backup(backup_root)


if __name__ == "__main__":
    unittest.main()
