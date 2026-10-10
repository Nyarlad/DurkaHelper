"""Offline preparation bridges: trusted inputs, exact role binding and no false readiness."""
import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


inventory = module("inventory_under_test", ROOT / "scripts/toolchain_inventory.py")
fixtures = module("inventory_image_fixtures", ROOT / "tests/test_toolchain_bundle.py")


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "export").mkdir()
        self.full = fixtures.complete_document()
        self.images, self.assets, roles = [], [], {}
        for original in self.full["artifacts"]:
            item = copy.deepcopy(original)
            if item["kind"] == "image":
                item["path"] = item["id"] + ".tar"
                native = item["architecture"].split("/")[1]
                identities = fixtures.image_archive(self.root / "export" / item["path"],
                    architecture=native, count=len(item["image_ids"]), marker=item["id"])
                identities = [identities] if isinstance(identities, str) else identities
                mapping = dict(zip(item["image_ids"], identities))
                for role in self.full["targets"][0]["runtime_roles"]:
                    if role["id"] in item["runtime_roles"]:
                        roles[role["id"]] = mapping[role["image_id"]]
                item.update(image_ids=identities, runtime_roles=[], compatible_with=[])
                item["sha256"] = checksum(self.root / "export" / item["path"])
                item["size"] = (self.root / "export" / item["path"]).stat().st_size
                self.images.append(item)
            else:
                item = {key: value for key, value in item.items() if key not in {"runtime_roles", "compatible_with", "image_ids"}}
                item["source_pins"] = {".": item["version"]} if item["kind"] == "source" else {}
                if item["component"] == "packmate" and item["kind"] == "source":
                    item["source_pins"]["frontend"] = "f" * 40
                path = self.root / item["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = b"synthetic offline source\n" if item["kind"] == "core" else (item["id"] + "\n").encode()
                path.write_bytes(raw)
                item["sha256"], item["size"] = checksum(path), len(raw)
                self.assets.append(item)
        self.receipt = {"schema": "durkahelper.deployment-build.v2", "images": roles,
                        "compose_sha256": "a" * 64, "runtime_sha256": "b" * 64}
        self.export = {"schema": inventory.kit.SCHEMA, "scope": "image-export", "targets": [],
                       "release_commit": "a" * 40, "required_ids": [item["id"] for item in self.images], "artifacts": self.images}
        self.value = {"schema": inventory.SCHEMA, "release_commit": "a" * 40,
                      "target": {"id": "test-macos-arm64", "platform": "darwin/arm64"},
                      "receipt": {"path": "receipt.json", "sha256": "a" * 64},
                      "image_export": {"path": "export/manifest.json", "sha256": "a" * 64},
                      "artifacts": self.assets}
        self.write_references()
        self.lock = {"schema": "durkahelper.toolchain-lock.v1", "components": {}}
        for item in self.assets:
            component = self.lock["components"].setdefault(item["component"], {})
            if item["kind"] == "source":
                component["source"] = {"commit": item["version"]}
                component["submodules"] = {"status": "EXISTING", "items": [{"path": path, "commit": pin}
                    for path, pin in item["source_pins"].items() if path != "."]}
            elif item["kind"] == "client":
                component["version"] = item["version"]
                component["release"] = {"assets": [{"architecture": "arm64", "os": "darwin",
                    "published_sha256": item["sha256"], "size": item["size"]}]}
            elif item["kind"] in {"runtime", "installer"}:
                component.update(version=item["version"], architectures=[{"arch": "arm64", "os": "macos"}],
                                 asset={"sha256": item["sha256"], "size": item["size"]})

    def write_references(self):
        for name, document in (("receipt", self.receipt), ("image_export", self.export)):
            path = self.root / self.value[name]["path"]
            path.write_text(json.dumps(document), encoding="utf-8")
            self.value[name]["sha256"] = checksum(path)

    def run_inventory(self):
        return inventory.inspect(self.root, self.value, self.lock)

    def cli_args(self):
        plan = self.root / "inventory.json"
        plan.write_text(json.dumps(self.value), encoding="utf-8")
        lock = self.root / "lock.json"
        lock.write_text(json.dumps(self.lock), encoding="utf-8")
        return ["--root", str(self.root), "--inventory", str(plan),
                "--expected-inventory-sha256", checksum(plan), "--lock", str(lock)]

    def test_full_inventory_binds_roles_sources_client_and_manifest(self):
        report, manifest = self.run_inventory()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["existing_runtime_inventory"], "PASS")
        self.assertEqual(report["clean_machine_inventory"], "PASS")
        self.assertEqual(report["runtime_roles_bound"], 10)
        self.assertEqual(manifest, inventory.kit.manifest(manifest))
        inventory.kit.check_files(self.root, manifest)
        by_id = {item["id"]: item for item in manifest["artifacts"]}
        self.assertEqual(by_id["neo-client"]["compatible_with"], ["neo-runtime-images", "neo-source"])
        self.assertEqual(by_id["packmate-image"]["compatible_with"], ["packmate-source"])
        self.assertEqual({role["id"]: role["image_id"] for role in manifest["targets"][0]["runtime_roles"]}, self.receipt["images"])
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(inventory.ops._canonical(manifest)).hexdigest())
        self.assertFalse(report["competition_ready"])
        self.assertFalse(report["daemon_checked"])
        self.assertEqual(report["offline_runtime"], "NOT_RUN")
        self.assertEqual(report["installed_prerequisites"], "NOT_CHECKED")

    def test_installer_missing_does_not_destroy_existing_runtime_inventory_but_blocks_complete(self):
        self.value["artifacts"] = [item for item in self.assets if item["component"] not in inventory.NATIVE_COMPONENTS]
        report, manifest = self.run_inventory()
        self.assertEqual(report["existing_runtime_inventory"], "PASS")
        self.assertEqual(report["clean_machine_inventory"], "BLOCKED")
        self.assertFalse(report["complete_target"])
        self.assertIsNone(manifest)
        self.assertEqual(len(report["issues"]), 6)

    def test_unknown_native_pins_do_not_become_trusted_by_hashing_local_assets(self):
        self.lock["components"]["container-runtime"]["version"] = None
        self.lock["components"]["python"]["asset"]["sha256"] = None
        report, manifest = self.run_inventory()
        self.assertIsNone(manifest)
        self.assertEqual(report["existing_runtime_inventory"], "PASS")
        self.assertEqual([entry["issue"] for entry in report["issues"]], ["unresolved-prerequisite-pin"] * 2)

    def test_platform_specific_native_assets_are_supported(self):
        component = self.lock["components"]["python"]
        component["assets"] = [dict(component.pop("asset"), platform="darwin/arm64")]
        self.assertEqual(self.run_inventory()[0]["status"], "PASS")
        component["assets"][0]["platform"] = "linux/arm64"
        self.assertEqual(self.run_inventory()[0]["status"], "BLOCKED")

    def test_target_architecture_cannot_be_relabelled_from_linux_export(self):
        self.value["target"]["platform"] = "linux/amd64"
        self.value["artifacts"] = []
        with self.assertRaisesRegex(inventory.Error, "target roles"):
            self.run_inventory()

    def test_missing_export_image_and_extra_image_fail_receipt_binding(self):
        self.export["artifacts"] = self.images[:-1]
        self.export["required_ids"] = [item["id"] for item in self.images[:-1]]
        self.write_references()
        with self.assertRaisesRegex(inventory.Error, "exactly cover"):
            self.run_inventory()

    def test_receipt_cannot_add_omit_or_relabel_service_roles(self):
        for change in (lambda images: images.pop("front"), lambda images: images.update(unrelated="sha256:" + "f" * 64),
                       lambda images: images.update(redis="redis:latest")):
            original = copy.deepcopy(self.receipt)
            change(self.receipt["images"])
            self.write_references()
            with self.assertRaises(inventory.Error):
                self.run_inventory()
            self.receipt = original

    def test_receipt_digest_is_verified_before_payload_use(self):
        (self.root / "receipt.json").write_text(json.dumps(dict(self.receipt, runtime_sha256="c" * 64)))
        with self.assertRaisesRegex(inventory.Error, "checksum"):
            self.run_inventory()

    def test_export_digest_and_release_are_bound(self):
        self.value["image_export"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(inventory.Error, "checksum"):
            self.run_inventory()
        self.export["release_commit"] = "b" * 40
        self.write_references()
        with self.assertRaisesRegex(inventory.Error, "release commit"):
            self.run_inventory()

    def test_source_root_and_submodule_pins_are_checked(self):
        source = next(item for item in self.assets if item["id"] == "packmate-source")
        source["source_pins"].pop("frontend")
        report, manifest = self.run_inventory()
        self.assertIsNone(manifest)
        self.assertIn({"component": "packmate", "kind": "source", "issue": "source-pin-mismatch"}, report["issues"])

    def test_client_official_checksum_and_size_are_checked(self):
        pinned = self.lock["components"]["neo"]["release"]["assets"][0]
        pinned["size"] += 1
        report, _ = self.run_inventory()
        self.assertIn({"component": "neo", "kind": "client", "issue": "client-pin-mismatch"}, report["issues"])

    def test_native_runtime_pin_mismatch_is_reported_not_executed(self):
        self.lock["components"]["ripgrep"]["version"] = "999.0.0"
        report, _ = self.run_inventory()
        self.assertIn({"component": "ripgrep", "kind": "runtime", "issue": "prerequisite-pin-mismatch"}, report["issues"])

    def test_missing_sources_block_existing_runtime_and_manifest(self):
        self.value["artifacts"] = [item for item in self.assets if item["kind"] != "source"]
        report, manifest = self.run_inventory()
        self.assertEqual(report["existing_runtime_inventory"], "BLOCKED")
        self.assertIsNone(manifest)

    def test_corrupt_artifacts_are_all_reported_without_raw_errors_or_paths(self):
        (self.root / self.assets[0]["path"]).write_bytes(b"PRIVATE-CANARY")
        (self.root / self.assets[1]["path"]).unlink()
        report, manifest = self.run_inventory()
        self.assertIsNone(manifest)
        self.assertEqual(len(report["issues"]), 2)
        self.assertNotIn("PRIVATE-CANARY", json.dumps(report))
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertNotIn(self.assets[0]["path"], json.dumps(report))

    def test_tampered_image_never_becomes_complete(self):
        path = self.root / "export" / self.images[0]["path"]
        with path.open("ab") as stream:
            stream.write(b"changed")
        report, manifest = self.run_inventory()
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIsNone(manifest)

    def test_recipe_rejects_unsafe_ambiguous_floating_and_private_fields(self):
        for fields in ({"path": "../outside"}, {"path": ".ssh/key"}, {"path": "data/private.pcap"},
                       {"path": "manifest.json"}, {"version": "latest"}, {"redistribution": "reviewed"},
                       {"size": True}, {"architecture": "linux/amd64"}, {"command": "docker ps"}):
            value = copy.deepcopy(self.value)
            value["artifacts"][0].update(fields)
            with self.subTest(fields=list(fields)), self.assertRaises(inventory.Error):
                inventory.recipe(value)

    def test_duplicate_artifact_pair_and_cross_image_path_collisions_fail(self):
        value = copy.deepcopy(self.value)
        value["artifacts"].append(dict(value["artifacts"][0], id="other-id", path="other.bin"))
        with self.assertRaises(inventory.Error):
            inventory.recipe(value)
        self.assets[0]["path"] = "export/" + self.images[0]["path"]
        with self.assertRaisesRegex(inventory.Error, "collide"):
            self.run_inventory()

    def test_default_cli_has_no_execution_network_or_writes(self):
        arguments = self.cli_args()
        before = {path.relative_to(self.root): checksum(path) for path in self.root.rglob("*") if path.is_file()}
        output = io.StringIO()
        with redirect_stdout(output), patch.object(inventory.ops, "_atomic_write_new", side_effect=AssertionError("write")), \
                patch.object(inventory.kit.subprocess, "run", side_effect=AssertionError("execute")), \
                patch.object(inventory.kit.subprocess, "Popen", side_effect=AssertionError("execute")):
            self.assertEqual(inventory.main(arguments), 0)
        after = {path.relative_to(self.root): checksum(path) for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(json.loads(output.getvalue())["status"], "PASS")

    def test_manifest_preview_is_read_only_even_with_output(self):
        arguments = self.cli_args() + ["--emit-manifest", str(self.root / "assembly.json")]
        with redirect_stdout(io.StringIO()), patch.object(inventory.ops, "_atomic_write_new", side_effect=AssertionError("write")):
            self.assertEqual(inventory.main(arguments), 0)
        self.assertFalse((self.root / "assembly.json").exists())

    def test_apply_requires_approval_before_any_file_read(self):
        with redirect_stdout(io.StringIO()), patch.object(inventory.ops, "_read_json", side_effect=AssertionError("read")):
            self.assertEqual(inventory.main(["--root", "absent", "--inventory", "absent", "--expected-inventory-sha256", "f" * 64, "--apply"]), 2)

    def test_apply_rejects_short_approval_before_any_file_read(self):
        with redirect_stdout(io.StringIO()), patch.object(inventory.ops, "_read_json", side_effect=AssertionError("read")):
            self.assertEqual(inventory.main(["--root", "absent", "--inventory", "absent",
                "--expected-inventory-sha256", "f" * 64, "--emit-manifest", "new.json",
                "--apply", "--approval-id", "test-1"]), 2)

    def test_recipe_digest_failure_is_sanitized(self):
        arguments = self.cli_args()
        arguments[arguments.index("--expected-inventory-sha256") + 1] = "f" * 64
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(inventory.main(arguments), 2)
        self.assertNotIn(str(self.root), output.getvalue())

    def test_malformed_component_pin_is_a_sanitized_blocker(self):
        for broken in (None, "invalid", {"source": []}):
            self.lock["components"]["s4dfarm"] = broken
            report, manifest = self.run_inventory()
            self.assertIsNone(manifest)
            self.assertIn({"component": "s4dfarm", "kind": "source", "issue": "invalid-component-pin"}, report["issues"])

    def test_inventory_schema_matches_parser_shape(self):
        schema = json.loads((ROOT / "schemas/toolchain-inventory.v1.schema.json").read_text())
        self.assertEqual(set(schema["required"]), set(self.value))
        self.assertEqual(set(schema["$defs"]["artifact"]["required"]), inventory.ASSET_FIELDS)

    def test_native_linux_asset_cannot_authenticate_windows_runtime(self):
        component = self.lock["components"]["python"]
        component["architectures"] = [{"os": "linux", "arch": "amd64"}]
        asset = next(item for item in self.assets if item["component"] == "python" and item["kind"] == "runtime")
        self.assertEqual(inventory._pin_problem(asset, self.lock, "windows/amd64"), "unresolved-prerequisite-pin")

    def test_receipt_json_duplicate_keys_and_malformed_input_are_blocked(self):
        path = self.root / "receipt.json"
        for raw in (b'{"images":{},"images":{}}', b'[' * 2000 + b'0' + b']' * 2000):
            path.write_bytes(raw)
            self.value["receipt"]["sha256"] = checksum(path)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(inventory.main(self.cli_args()), 2)
            self.assertNotIn(str(self.root), output.getvalue())

    def test_incomplete_inventory_cannot_emit_even_with_approval(self):
        self.assets.pop()
        arguments = self.cli_args() + ["--emit-manifest", str(self.root / "assembly.json"), "--apply", "--approval-id", "test-run-01"]
        output = io.StringIO()
        with redirect_stdout(output), patch.object(inventory.ops, "_atomic_write_new", side_effect=AssertionError("write")):
            self.assertEqual(inventory.main(arguments), 2)
        self.assertTrue(json.loads(output.getvalue())["issues"])

    @unittest.skipIf(os.name == "nt", "symlinks require POSIX")
    def test_symlink_inside_cache_is_not_followed(self):
        (self.root / "linked").symlink_to(self.root / "export", target_is_directory=True)
        self.value["image_export"]["path"] = "linked/manifest.json"
        with self.assertRaises(inventory.Error):
            self.run_inventory()

    @unittest.skipIf(os.name == "nt", "secure assembly requires POSIX")
    def test_emit_assemble_verify_roundtrip_no_installer_execution(self):
        output_path = self.root / "assembly.json"
        arguments = self.cli_args() + ["--emit-manifest", str(output_path), "--apply", "--approval-id", "test-run-01"]
        output = io.StringIO()
        with redirect_stdout(output):
            code = inventory.main(arguments)
        self.assertEqual(code, 0, output.getvalue())
        report = json.loads(output.getvalue())
        self.assertTrue(report["manifest_written"])
        self.assertEqual(checksum(output_path), report["manifest_sha256"])
        with tempfile.TemporaryDirectory() as target_parent:
            target = Path(target_parent) / "kit"
            args = fixtures.argparse.Namespace(manifest=str(output_path), root=str(self.root), output=str(target), apply=True,
                expected_manifest_sha256=report["manifest_sha256"], expected_release_commit="a" * 40)
            inventory.kit.assemble(args)
            self.assertEqual(inventory.kit.verify(target, expected_manifest_sha256=report["manifest_sha256"])["scope"], "complete-target")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(inventory.main(arguments), 2)


if __name__ == "__main__":
    unittest.main()
