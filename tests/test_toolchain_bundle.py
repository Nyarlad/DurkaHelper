"""Offline artifact integrity and non-mutating defaults."""
import argparse
from contextlib import redirect_stdout
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("toolchain", ROOT / "scripts/toolchain_bundle.py")
kit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit)


def document(data=b"synthetic offline source\n"):
    return complete_document(data)


def complete_document(core_data=b"synthetic offline source\n"):
    """Synthetic but structurally complete macOS/arm64 competition toolchain."""
    image_id = lambda number: "sha256:" + format(number, "x") * 64
    definitions = (
        ("durkahelper-core", "core", "durkahelper", "all", "a" * 40, [], [], []),
        ("durkahelper-license", "license", "durkahelper", "all", "test-1.0", [], [], []),
        ("postgres-images", "image", "postgres", "linux/arm64", "postgres-15-pins", [],
         ["postgres", "packmate-db"], [image_id(1), image_id(2)]),
        ("postgres-license", "license", "postgres", "all", "test-1.0", [], [], []),
        ("redis-image", "image", "redis", "linux/arm64", "redis-7-pin", [],
         ["redis", "neo-redis"], [image_id(3)]),
        ("redis-license", "license", "redis", "all", "test-1.0", [], [], []),
        ("s4dfarm-images", "image", "s4dfarm", "linux/arm64", "s4dfarm-build-1",
         ["s4dfarm-source"], ["farm", "celery", "front"], [image_id(4), image_id(5), image_id(6)]),
        ("s4dfarm-source", "source", "s4dfarm", "all", "b" * 40, [], [], []),
        ("s4dfarm-license", "license", "s4dfarm", "all", "test-1.0", [], [], []),
        ("neo-runtime-images", "image", "neo", "linux/arm64", "neo-build-1",
         ["neo-source"], ["neo-server", "neo-worker"], [image_id(7), image_id(8)]),
        ("neo-source", "source", "neo", "all", "c" * 40, [], [], []),
        ("neo-client", "client", "neo", "darwin/arm64", "v2.4.2",
         ["neo-runtime-images", "neo-source"], [], []),
        ("neo-license", "license", "neo", "all", "test-1.0", [], [], []),
        ("packmate-image", "image", "packmate", "linux/amd64", "v4.0",
         ["packmate-source"], ["packmate"], [image_id(9)]),
        ("packmate-source", "source", "packmate", "all", "d" * 40, [], [], []),
        ("packmate-license", "license", "packmate", "all", "test-1.0", [], [], []),
        ("container-runtime-installer", "installer", "container-runtime", "darwin/arm64", "4.48.0", [], [], []),
        ("container-runtime-license", "license", "container-runtime", "all", "test-1.0", [], [], []),
        ("python-runtime", "runtime", "python", "darwin/arm64", "3.13.7", [], [], []),
        ("python-license", "license", "python", "all", "test-1.0", [], [], []),
        ("ripgrep-runtime", "runtime", "ripgrep", "darwin/arm64", "14.1.1", [], [], []),
        ("ripgrep-license", "license", "ripgrep", "all", "test-1.0", [], [], []),
    )
    artifacts = []
    for identifier, kind, component, architecture, version, compatible_with, runtime_roles, image_ids in definitions:
        payload = core_data if identifier == "durkahelper-core" else (identifier + "\n").encode()
        artifacts.append({
            "id": identifier,
            "path": "core.txt" if identifier == "durkahelper-core" else
                    "artifacts/" + identifier + (".tar" if kind == "image" else ".bin"),
            "kind": kind,
            "component": component,
            "architecture": architecture,
            "version": version,
            "compatible_with": compatible_with,
            "runtime_roles": runtime_roles,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "license": "TEST-LICENSE",
            "redistribution": "local-only",
            "image_ids": image_ids,
        })
    artifact_ids = [item["id"] for item in artifacts]
    return {
        "schema": kit.SCHEMA,
        "release_commit": "a" * 40,
        "scope": "complete-target",
        "targets": [{
            "id": "competition-macos-arm64",
            "platform": "darwin/arm64",
            "container_platforms": ["linux/arm64", "linux/amd64"],
            "deployment_contract_sha256": kit.DEPLOYMENT_CONTRACT_SHA256,
            "runtime_roles": [
                {"id": "postgres", "component": "s4dfarm", "platform": "linux/arm64", "image_id": image_id(1)},
                {"id": "redis", "component": "s4dfarm", "platform": "linux/arm64", "image_id": image_id(3)},
                {"id": "neo-redis", "component": "neo", "platform": "linux/arm64", "image_id": image_id(3)},
                {"id": "farm", "component": "s4dfarm", "platform": "linux/arm64", "image_id": image_id(4)},
                {"id": "celery", "component": "s4dfarm", "platform": "linux/arm64", "image_id": image_id(5)},
                {"id": "front", "component": "s4dfarm", "platform": "linux/arm64", "image_id": image_id(6)},
                {"id": "neo-server", "component": "neo", "platform": "linux/arm64", "image_id": image_id(7)},
                {"id": "neo-worker", "component": "neo", "platform": "linux/arm64", "image_id": image_id(8)},
                {"id": "packmate-db", "component": "packmate", "platform": "linux/arm64", "image_id": image_id(2)},
                {"id": "packmate", "component": "packmate", "platform": "linux/amd64", "image_id": image_id(9)},
            ],
            "artifact_ids": list(artifact_ids),
        }],
        "required_ids": list(artifact_ids),
        "artifacts": artifacts,
    }


def image_archive(path, *, tag=False, bad_path=False, marker=None, architecture="amd64", count=1):
    entries, body, identities = [], [], []
    for number in range(count):
        config = json.dumps({"architecture": architecture, "os": "linux", "rootfs": {"type": "layers", "diff_ids": []},
                             "synthetic_marker": [marker, number]}, separators=(",", ":")).encode()
        identity = hashlib.sha256(config).hexdigest()
        identities.append("sha256:" + identity)
        entries.append((identity + ".json", config))
        body.append({"Config": identity + ".json", "RepoTags": ["example:latest"] if tag else [], "Layers": []})
    entries.append(("manifest.json", json.dumps(body).encode()))
    with tarfile.open(path, "w:") as archive:
        for name, data in entries:
            member = tarfile.TarInfo("../escape" if bad_path and name == "manifest.json" else name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return identities[0] if count == 1 else identities


def export_document(identity="sha256:" + "a" * 64):
    return {"schema": kit.EXPORT_SCHEMA, "release_commit": "a" * 40,
            "max_archive_bytes": 1024 * 1024, "max_total_bytes": 2 * 1024 * 1024, "timeout_seconds": 10,
            "images": [{"id": "synthetic-runtime", "component": "synthetic", "architecture": "linux/amd64", "image_id": identity,
                        "license": "UNREVIEWED", "redistribution": "local-only", "reviewed_for_secrets": True}]}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def legacy_document():
    items = []
    for source in (next(item for item in complete_document()["artifacts"] if item["kind"] == "image"),
                   next(item for item in complete_document()["artifacts"] if item["kind"] == "source")):
        item = copy.deepcopy(source)
        for field in ("version", "compatible_with", "runtime_roles"):
            item.pop(field)
        items.append(item)
    return {"schema": kit.LEGACY_SCHEMA, "release_commit": "a" * 40,
            "required_ids": [items[0]["id"]], "artifacts": items}


def oci_archive(path, mutation=None, *, attestation=False, attestation_target=None,
                platform="amd64", missing_platform="arm64", compressed=False, bad_diff_id=False,
                missing_attestation=False, missing_attestation_target=None):
    """Docker 29 subset export: one local platform and one absent platform."""
    entries = {}
    def blob(data):
        if not isinstance(data, bytes):
            data = json.dumps(data, separators=(",", ":")).encode()
        digest = hashlib.sha256(data).hexdigest()
        entries["blobs/sha256/" + digest] = data
        return {"digest": "sha256:" + digest, "size": len(data)}
    raw_layer = b"synthetic layer contents"
    diff_id = hashlib.sha256(b"wrong" if bad_diff_id else raw_layer).hexdigest()
    config = blob({"architecture": "amd64", "os": "linux",
                   "rootfs": {"type": "layers", "diff_ids": ["sha256:" + diff_id]}})
    layer = blob(gzip.compress(raw_layer, mtime=0) if compressed else raw_layer)
    leaf = blob({"schemaVersion": 2, "config": config, "layers": [layer]})
    children = [dict(leaf, platform={"os": "linux", "architecture": platform}),
        {"digest": "sha256:" + "0" * 64, "size": 123, "platform": {"os": "linux", "architecture": missing_platform}}]
    if attestation:
        proof = blob({"schemaVersion": 2, "config": blob({"os": "unknown", "architecture": "unknown"}),
            "layers": [dict(blob({"synthetic_provenance": True}), mediaType="application/vnd.in-toto+json")]})
        children.append(dict(proof, platform={"os": "unknown", "architecture": "unknown"},
            annotations={"vnd.docker.reference.type": "attestation-manifest",
                         "vnd.docker.reference.digest": attestation_target or leaf["digest"]}))
    if missing_attestation:
        target = leaf["digest"] if missing_attestation_target == "present" else missing_attestation_target
        children.append({"digest": "sha256:" + "d" * 64, "size": 789,
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                            "vnd.docker.reference.digest": target or children[1]["digest"]}})
    root = blob({"schemaVersion": 2, "manifests": children})
    index = {"schemaVersion": 2, "manifests": [root]}
    rows = [{"Config": "blobs/sha256/" + config["digest"][7:], "RepoTags": None,
             "Layers": ["blobs/sha256/" + layer["digest"][7:]]}]
    if mutation:
        mutation(entries, index, rows)
    entries["index.json"] = json.dumps(index).encode()
    entries["manifest.json"] = json.dumps(rows).encode()
    with tarfile.open(path, "w:") as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return root["digest"], config["digest"]


def legacy_layer_archive(path, *, original=b"original inert layer", stored=None, compressed=False):
    """A config identity must authenticate its uncompressed layer bytes."""
    stored = original if stored is None else stored
    config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {
        "type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(original).hexdigest()]}}).encode()
    rows = [{"Config": "config.json", "Layers": ["layer.tar"], "RepoTags": []}]
    entries = {"config.json": config, "layer.tar": gzip.compress(stored, mtime=0) if compressed else stored,
               "manifest.json": json.dumps(rows).encode()}
    with tarfile.open(path, "w:") as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return "sha256:" + hashlib.sha256(config).hexdigest()


def rewrite_tar(path, *, change=None, pax=None, extra=None, format=tarfile.PAX_FORMAT):
    with tarfile.open(path, "r:") as archive:
        entries = {member.name: archive.extractfile(member).read() for member in archive}
    if change:
        change(entries)
    if extra:
        entries.update(extra)
    with tarfile.open(path, "w:", format=format) as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.pax_headers = pax or {}
            archive.addfile(member, io.BytesIO(data))


class SavedProcess:
    def __init__(self, data, code=0):
        self.stdout = io.BytesIO(data)
        self.code = code
        self.killed = False

    def wait(self, timeout=None):
        return self.code

    def poll(self):
        return self.code

    def kill(self):
        self.killed = True


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cache = self.root / "cache"
        self.cache.mkdir(mode=0o700)
        self.data = b"synthetic offline source\n"
        self.value = document(self.data)
        for item in self.value["artifacts"]:
            path = self.cache / item["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            if item["kind"] == "image":
                original_ids = list(item["image_ids"])
                identities = image_archive(path, marker=item["id"], architecture=item["architecture"].split("/")[1],
                                           count=len(original_ids))
                identities = identities if isinstance(identities, list) else [identities]
                replacements = dict(zip(original_ids, identities))
                for role in self.value["targets"][0]["runtime_roles"]:
                    role["image_id"] = replacements.get(role["image_id"], role["image_id"])
                content = path.read_bytes()
                item["image_ids"] = identities
                item["sha256"] = hashlib.sha256(content).hexdigest()
                item["size"] = len(content)
            else:
                content = self.data if item["id"] == "durkahelper-core" else (item["id"] + "\n").encode()
                path.write_bytes(content)
                item["sha256"] = hashlib.sha256(content).hexdigest()
                item["size"] = len(content)
        self.manifest = self.root / "input.json"
        self.manifest.write_text(json.dumps(self.value))

    def tearDown(self):
        self.temp.cleanup()

    def test_manifest_requires_inventory_and_real_checksums(self):
        self.assertEqual(kit.manifest(self.value), self.value)
        for mutation in ({"required_ids": ["missing"]}, {"release_commit": "main"}, {"extra": "value"}):
            with self.assertRaises(kit.Error):
                kit.manifest({**self.value, **mutation})
        for version in ("latest", "main", "example:latest", "refs/heads/main"):
            value = copy.deepcopy(self.value)
            value["artifacts"][0]["version"] = version
            with self.subTest(version=version), self.assertRaisesRegex(kit.Error, "non-floating pin"):
                kit.manifest(value)

    def test_complete_target_requires_every_artifact_category(self):
        value = complete_document()
        self.assertEqual(kit.manifest(value), value)
        for kind in ("core", "image", "source", "client", "license", "installer", "runtime"):
            incomplete = copy.deepcopy(value)
            removed = {item["id"] for item in incomplete["artifacts"] if item["kind"] == kind}
            incomplete["artifacts"] = [item for item in incomplete["artifacts"] if item["id"] not in removed]
            incomplete["required_ids"] = [item for item in incomplete["required_ids"] if item not in removed]
            incomplete["targets"][0]["artifact_ids"] = [
                item for item in incomplete["targets"][0]["artifact_ids"] if item not in removed]
            for artifact in incomplete["artifacts"]:
                artifact["compatible_with"] = [item for item in artifact["compatible_with"] if item not in removed]
            with self.subTest(kind=kind), self.assertRaises(kit.Error):
                kit.manifest(incomplete)

    def test_complete_target_rejects_duplicate_or_ambiguous_identities(self):
        value = complete_document()
        duplicate = copy.deepcopy(value["artifacts"][-2])
        duplicate.update(id="python-runtime-alias", path="artifacts/python-runtime-alias.bin")
        value["artifacts"].append(duplicate)
        value["required_ids"].append(duplicate["id"])
        value["targets"][0]["artifact_ids"].append(duplicate["id"])
        with self.assertRaisesRegex(kit.Error, "duplicate artifact payload identity"):
            kit.manifest(value)

        value = complete_document()
        image = copy.deepcopy(next(item for item in value["artifacts"] if item["kind"] == "image"))
        image.update(id="neo-runtime-image-alias", path="artifacts/neo-runtime-image-alias.tar",
                     sha256="2" * 64)
        value["artifacts"].append(image)
        value["required_ids"].append(image["id"])
        value["targets"][0]["artifact_ids"].append(image["id"])
        with self.assertRaisesRegex(kit.Error, "duplicate immutable image identity"):
            kit.manifest(value)

    def test_complete_target_enforces_platform_and_client_compatibility(self):
        for artifact_id, architecture in (("neo-runtime-images", "linux/amd64"),
                                          ("neo-client", "windows/amd64"),
                                          ("python-runtime", "linux/arm64")):
            value = complete_document()
            next(item for item in value["artifacts"] if item["id"] == artifact_id)["architecture"] = architecture
            with self.subTest(artifact=artifact_id), self.assertRaisesRegex(
                    kit.Error, "target architecture mismatch|runtime role coverage"):
                kit.manifest(value)

        value = complete_document()
        self.assertNotEqual(
            next(item for item in value["artifacts"] if item["id"] == "neo-source")["version"],
            next(item for item in value["artifacts"] if item["id"] == "neo-client")["version"])
        self.assertEqual(kit.manifest(value), value, "the intentional Neo client/source version difference is explicit")
        client = next(item for item in value["artifacts"] if item["id"] == "neo-client")
        client["compatible_with"] = ["neo-runtime-images", "s4dfarm-source"]
        with self.assertRaisesRegex(kit.Error, "client compatibility mismatch"):
            kit.manifest(value)

        value = complete_document()
        next(item for item in value["artifacts"] if item["id"] == "neo-source")["version"] = "test-source-pin-2"
        with self.assertRaisesRegex(kit.Error, "exact commit pins"):
            kit.manifest(value)

        value = complete_document()
        value["artifacts"][0]["version"] = "b" * 40
        with self.assertRaisesRegex(kit.Error, "core version"):
            kit.manifest(value)

    def test_complete_target_cannot_omit_fixed_competition_components_or_roles(self):
        removals = {
            "durkahelper": "durkahelper-core",
            "postgres": "postgres-images",
            "redis": "redis-image",
            "s4dfarm": "s4dfarm-source",
            "neo": "neo-source",
            "packmate": "packmate-source",
            "container-runtime": "container-runtime-installer",
            "python": "python-runtime",
            "ripgrep": "ripgrep-runtime",
        }
        for component, artifact_id in removals.items():
            value = complete_document()
            value["artifacts"] = [item for item in value["artifacts"] if item["id"] != artifact_id]
            value["required_ids"].remove(artifact_id)
            value["targets"][0]["artifact_ids"].remove(artifact_id)
            for artifact in value["artifacts"]:
                if artifact_id in artifact["compatible_with"]:
                    artifact["compatible_with"].remove(artifact_id)
            with self.subTest(component=component), self.assertRaisesRegex(
                    kit.Error, "missing required artifact kind|target component inventory|provenance|role coverage"):
                kit.manifest(value)

        for role_id in kit.MAINTAINED_ROLES:
            value = complete_document()
            value["targets"][0]["runtime_roles"] = [
                role for role in value["targets"][0]["runtime_roles"] if role["id"] != role_id]
            for artifact in value["artifacts"]:
                if role_id in artifact["runtime_roles"]:
                    artifact["runtime_roles"].remove(role_id)
            with self.subTest(omitted_role=role_id), self.assertRaisesRegex(kit.Error, "role inventory"):
                kit.manifest(value)

        value = complete_document()
        next(item for item in value["artifacts"] if item["id"] == "s4dfarm-images")["runtime_roles"][0] = "packmate"
        with self.assertRaisesRegex(kit.Error, "runtime role coverage"):
            kit.manifest(value)

    def test_complete_target_binds_fixed_contract_role_images_and_provenance(self):
        value = complete_document()
        self.assertEqual(kit.manifest(value), value)
        contract = {
            "schema": "durkahelper.maintained-deployment.v2",
            "roles": [
                {"id": role, "component": component, "image_component": kit.ROLE_IMAGE_COMPONENTS[role]}
                for role, component in kit.MAINTAINED_ROLES.items()
            ],
            "platforms": {
                "derived_from_target": list(kit.TARGET_PLATFORM_ROLES),
                "fixed": kit.FIXED_ROLE_PLATFORMS,
            },
            "shared_image_identity": [list(group) for group in kit.SHARED_IMAGE_IDENTITY_GROUPS],
        }
        self.assertEqual(hashlib.sha256(kit.ops._canonical(contract)).hexdigest(),
                         kit.DEPLOYMENT_CONTRACT_SHA256)
        roles = {item["id"]: item for item in value["targets"][0]["runtime_roles"]}
        self.assertEqual(roles["redis"]["image_id"], roles["neo-redis"]["image_id"])

        bad = copy.deepcopy(value)
        bad["targets"][0]["deployment_contract_sha256"] = "0" * 64
        with self.assertRaisesRegex(kit.Error, "contract digest"):
            kit.manifest(bad)

        bad = copy.deepcopy(value)
        roles = {item["id"]: item for item in bad["targets"][0]["runtime_roles"]}
        roles["neo-redis"]["image_id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(kit.Error, "role coverage|shared runtime roles"):
            kit.manifest(bad)

        for artifact_id in ("s4dfarm-images", "neo-runtime-images", "packmate-image"):
            bad = copy.deepcopy(value)
            next(item for item in bad["artifacts"] if item["id"] == artifact_id)["compatible_with"] = []
            with self.subTest(artifact=artifact_id), self.assertRaisesRegex(kit.Error, "provenance"):
                kit.manifest(bad)

        bad = copy.deepcopy(value)
        bad["targets"][0]["artifact_ids"].remove("neo-source")
        with self.assertRaisesRegex(kit.Error, "target omits"):
            kit.manifest(bad)

    def test_complete_target_rejects_alternate_platform_and_shared_image_topology(self):
        value = complete_document()
        neo_images = next(item for item in value["artifacts"] if item["id"] == "neo-runtime-images")
        neo_images["architecture"] = "linux/amd64"
        for role in value["targets"][0]["runtime_roles"]:
            if role["id"] in {"neo-server", "neo-worker"}:
                role["platform"] = "linux/amd64"
        with self.assertRaisesRegex(kit.Error, "maintained topology"):
            kit.manifest(value)

        value = complete_document()
        redis_images = next(item for item in value["artifacts"] if item["id"] == "redis-image")
        alternate_identity = "sha256:" + "f" * 64
        redis_images["image_ids"].append(alternate_identity)
        roles = {item["id"]: item for item in value["targets"][0]["runtime_roles"]}
        roles["neo-redis"]["image_id"] = alternate_identity
        with self.assertRaisesRegex(kit.Error, "shared runtime roles"):
            kit.manifest(value)

    def test_manifest_malformed_nested_identities_are_bounded_errors(self):
        mutations = []
        value = complete_document()
        value["artifacts"][0]["compatible_with"] = [[]]
        mutations.append(value)
        value = complete_document()
        next(item for item in value["artifacts"] if item["kind"] == "image")["runtime_roles"] = [[]]
        mutations.append(value)
        value = complete_document()
        value["targets"][0]["container_platforms"] = [[]]
        mutations.append(value)
        value = complete_document()
        value["targets"][0]["artifact_ids"] = [[]]
        mutations.append(value)
        value = complete_document()
        value["targets"][0]["runtime_roles"][0]["component"] = []
        mutations.append(value)
        for number, malformed in enumerate(mutations):
            with self.subTest(case=number), self.assertRaises(kit.Error):
                kit.manifest(malformed)

    def test_legacy_v1_mixed_manifest_remains_partial_and_unchanged(self):
        legacy = legacy_document()
        self.assertEqual(kit.manifest(legacy), legacy)
        self.assertEqual(kit._manifest_scope(legacy), "legacy-inventory")
        self.assertEqual(legacy["required_ids"], [legacy["artifacts"][0]["id"]],
                         "v1 retains its historical required subset semantics")
        with self.assertRaisesRegex(kit.Error, "scope is not valid"):
            kit.manifest(legacy, expected_scope="complete-target")
        partial_manifest = self.root / "legacy-mixed.json"
        partial_manifest.write_text(json.dumps(legacy))
        args = argparse.Namespace(root=str(self.cache), manifest=str(partial_manifest),
                                  output=str(self.root / "must-not-exist"), apply=False)
        with self.assertRaisesRegex(kit.Error, "scope is not valid"):
            kit.assemble(args)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(kit.main(["assemble", "--root", str(self.cache), "--manifest", str(partial_manifest),
                                       "--output", str(self.root / "must-not-exist")]), 2)

    def test_v1_v2_schema_and_parser_shape_parity(self):
        v1_schema = json.loads((ROOT / "schemas/toolchain-manifest.v1.schema.json").read_text())
        v2_schema = json.loads((ROOT / "schemas/toolchain-manifest.v2.schema.json").read_text())
        self.assertEqual(v1_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(v2_schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(v1_schema["properties"]["schema"]["const"], kit.LEGACY_SCHEMA)
        self.assertEqual(v2_schema["properties"]["schema"]["const"], kit.SCHEMA)
        self.assertEqual(v1_schema["properties"]["artifacts"]["items"]["properties"]["path"]["maxLength"], 1024)
        self.assertEqual(v2_schema["$defs"]["artifact"]["properties"]["path"]["maxLength"], 1024)
        pairs = ((legacy_document(), v1_schema), (complete_document(), v2_schema))
        for value, _schema in pairs:
            with self.subTest(schema=value["schema"]):
                self.assertEqual(kit.manifest(value), value)

        for mutate in (
                lambda value: value.update(extra="forbidden"),
                lambda value: value["artifacts"][0].pop("sha256")):
            for original, _schema in pairs:
                value = copy.deepcopy(original)
                mutate(value)
                with self.subTest(schema=original["schema"], mutate=mutate), self.assertRaises(kit.Error):
                    kit.manifest(value)

        for original, _schema in pairs:
            value = copy.deepcopy(original)
            value["artifacts"][0]["path"] = "a" * 1025
            with self.subTest(schema=original["schema"], boundary="path"), self.assertRaises(kit.Error):
                kit.manifest(value)

    def test_private_paths_duplicates_and_commands_rejected(self):
        for path in (".ssh/codex", "../outside", ".env", "secrets/a.txt", "packet.pcap"):
            value = copy.deepcopy(self.value)
            value["artifacts"][0]["path"] = path
            with self.assertRaises(kit.Error):
                kit.manifest(value)
        value = copy.deepcopy(self.value)
        value["artifacts"].append(copy.deepcopy(value["artifacts"][0]))
        with self.assertRaises(kit.Error):
            kit.manifest(value)
        value = copy.deepcopy(self.value)
        value["artifacts"][0]["command"] = "not-permitted"
        with self.assertRaises(kit.Error):
            kit.manifest(value)

    def test_preview_reads_without_mutation_or_network(self):
        args = argparse.Namespace(root=str(self.cache), manifest=str(self.manifest),
                                  output=str(self.root / "bundle"), apply=False,
                                  expected_manifest_sha256=digest(self.manifest), expected_release_commit="a" * 40)
        with patch("subprocess.run", side_effect=AssertionError("execution")), \
                patch("socket.socket", side_effect=AssertionError("network")):
            result = kit.assemble(args)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["scope"], "complete-target")
        self.assertTrue(result["complete_target"])
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(kit.ops._canonical(self.value)).hexdigest())
        self.assertFalse((self.root / "bundle").exists())

    def test_complete_verify_and_assemble_require_detached_manifest_digest(self):
        (self.cache / "manifest.json").write_text(json.dumps(self.value))
        expected = digest(self.cache / "manifest.json")
        with self.assertRaisesRegex(kit.Error, "detached expected manifest"):
            kit.verify(self.cache)
        with self.assertRaisesRegex(kit.Error, "detached SHA-256"):
            kit.verify(self.cache, expected_manifest_sha256="0" * 64)
        self.assertEqual(kit.verify(
            self.cache, expected_manifest_sha256=expected,
            expected_release_commit="a" * 40), self.value)
        with self.assertRaisesRegex(kit.Error, "release commit"):
            kit.verify(self.cache, expected_manifest_sha256=expected, expected_release_commit="b" * 40)

        args = argparse.Namespace(root=str(self.cache), manifest=str(self.manifest),
                                  output=str(self.root / "bundle"), apply=False)
        with self.assertRaisesRegex(kit.Error, "detached expected manifest"):
            kit.assemble(args)

    def test_tamper_and_missing_source_rejected(self):
        (self.cache / "core.txt").write_bytes(b"changed")
        with self.assertRaises(kit.Error):
            kit.check_files(self.cache, self.value)

    def test_verify_rejects_unlisted_file(self):
        (self.cache / "manifest.json").write_text(json.dumps(self.value))
        expected = digest(self.cache / "manifest.json")
        self.assertEqual(kit.verify(self.cache, expected_manifest_sha256=expected), self.value)
        (self.cache / "unlisted.txt").write_text("unlisted")
        with self.assertRaises(kit.Error):
            kit.verify(self.cache, expected_manifest_sha256=expected)

    @unittest.skipIf(os.name == "nt", "descriptor anchored toolchain staging requires POSIX")
    def test_atomic_assembly_and_roundtrip_without_overwrite(self):
        target = self.root / "bundle"
        args = argparse.Namespace(root=str(self.cache), manifest=str(self.manifest), output=str(target), apply=True,
                                  expected_manifest_sha256=digest(self.manifest))
        result = kit.assemble(args)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["manifest_sha256"], digest(target / "manifest.json"))
        self.assertEqual(kit.verify(target, expected_manifest_sha256=result["manifest_sha256"]), self.value)
        self.assertEqual((target / "core.txt").read_bytes(), self.data)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(kit.Error):
            kit.assemble(args)

    def test_mutations_require_approval(self):
        with redirect_stdout(io.StringIO()), patch("subprocess.run", side_effect=AssertionError("execution")):
            code = kit.main(["assemble", "--root", str(self.cache), "--manifest", str(self.manifest),
                             "--output", str(self.root / "bundle"), "--apply"])
        self.assertEqual(code, 2)

    def test_tag_free_images_have_exact_config_identities(self):
        path = self.cache / "image.tar"
        identity = image_archive(path)
        kit.inspect_image_archive(path, [identity])
        with self.assertRaises(kit.Error):
            kit.inspect_image_archive(path, ["sha256:" + "0" * 64])
        image_archive(path, tag=True)
        with self.assertRaises(kit.Error):
            kit.inspect_image_archive(path, [identity])
        image_archive(path, bad_path=True)
        with self.assertRaises(kit.Error):
            kit.inspect_image_archive(path, [identity])

    def test_legacy_identity_binds_raw_and_gzip_layer_contents(self):
        path = self.cache / "legacy.tar"
        for compressed in (False, True):
            identity = legacy_layer_archive(path, compressed=compressed)
            kit.inspect_image_archive(path, [identity], architecture="linux/amd64")
            identity = legacy_layer_archive(path, stored=b"different inert bytes", compressed=compressed)
            with self.subTest(compressed=compressed), self.assertRaisesRegex(kit.Error, "layer.*identity"):
                kit.inspect_image_archive(path, [identity], architecture="linux/amd64")

    def test_oci_always_binds_uncompressed_diff_ids(self):
        path = self.cache / "oci.tar"
        for compressed in (False, True):
            identity, config = oci_archive(path, compressed=compressed)
            kit.inspect_image_archive(path, [config], architecture="linux/amd64")
            identity, config = oci_archive(path, compressed=compressed, bad_diff_id=True)
            with self.subTest(compressed=compressed, identity="root"), self.assertRaisesRegex(kit.Error, "layer.*identity"):
                kit.inspect_image_archive(path, [identity], architecture="linux/amd64")
            with self.subTest(compressed=compressed, identity="config"), self.assertRaisesRegex(kit.Error, "layer.*identity"):
                kit.inspect_image_archive(path, [config], architecture="linux/amd64")

    def test_oci_rejects_mislabelled_or_missing_selected_platform(self):
        path = self.cache / "oci.tar"
        for fields in ({"platform": "arm64"}, {"missing_platform": "amd64"},
                       {"platform": "arm64", "missing_platform": "amd64"}):
            identity, _ = oci_archive(path, **fields)
            with self.subTest(fields=fields), self.assertRaisesRegex(kit.Error, "platform"):
                kit.inspect_image_archive(path, [identity], architecture="linux/amd64")

    def test_image_inventory_requires_explicit_linux_architecture(self):
        value = copy.deepcopy(self.value)
        value["artifacts"][0].update(kind="image", image_ids=["sha256:" + "a" * 64])
        for architecture in ("all", "darwin/arm64", "windows/amd64"):
            value["artifacts"][0]["architecture"] = architecture
            with self.subTest(architecture=architecture), self.assertRaises(kit.Error):
                kit.manifest(value)

    def test_oversized_pax_is_rejected_before_tarfile_parses_it(self):
        path = self.cache / "extended.tar"
        identity = image_archive(path)
        with tarfile.open(path, "r:") as archive:
            entries = [(item.name, archive.extractfile(item).read()) for item in archive]
        with tarfile.open(path, "w:", format=tarfile.PAX_FORMAT) as archive:
            for name, data in entries:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.pax_headers = {"comment": "x" * (2 * 1024 * 1024)}
                archive.addfile(member, io.BytesIO(data))
        with patch.object(kit.tarfile, "open", side_effect=AssertionError("unsafe parser reached")):
            with self.assertRaises(kit.Error):
                kit.inspect_image_archive(path, [identity])

    def test_bounded_layer_decompression_and_aggregate_expansion(self):
        path = self.cache / "legacy.tar"
        identity = legacy_layer_archive(path, original=b"x" * 65536, compressed=True)
        with patch.object(kit, "MAX_LAYER_EXPANDED", 1024), self.assertRaisesRegex(kit.Error, "expanded.*bounds"):
            kit.inspect_image_archive(path, [identity])
        # Physical archive fits; expanded data must also obey the total budget.
        with patch.object(kit, "MAX_ARTIFACT", 32768), self.assertRaisesRegex(kit.Error, "expanded.*bounds"):
            kit.inspect_image_archive(path, [identity])
        identity = legacy_layer_archive(path, original=b"x" * 65536)
        with patch.object(kit, "MAX_LAYER_EXPANDED", 1024), self.assertRaisesRegex(kit.Error, "expanded.*bounds"):
            kit.inspect_image_archive(path, [identity])

    def test_gzip_layer_rejects_truncation_corruption_and_concatenation(self):
        path = self.cache / "legacy.tar"
        mutations = [lambda data: data[:-4], lambda data: data + b"trailing",
                     lambda data: data + gzip.compress(b""),
                     lambda data: data[:-8] + b"\xff" * 8]
        for mutation in mutations:
            identity = legacy_layer_archive(path, compressed=True)
            rewrite_tar(path, change=lambda entries: entries.update({"layer.tar": mutation(entries["layer.tar"])}))
            with self.subTest(mutation=mutation), self.assertRaises(kit.Error):
                kit.inspect_image_archive(path, [identity])

    def test_config_identity_rejects_unsupported_layer_compression(self):
        path = self.cache / "legacy.tar"
        for header in (b"\x28\xb5\x2f\xfd", b"\xfd7zX", b"BZh9", b"\x04\x22\x4d\x18", b"\x50\x2a\x4d\x18"):
            identity = legacy_layer_archive(path, original=header + b"not an uncompressed layer")
            with self.subTest(header=header), self.assertRaisesRegex(kit.Error, "unsupported compression"):
                kit.inspect_image_archive(path, [identity])

    def test_config_identity_requires_matching_diff_id_count_and_format(self):
        path = self.cache / "legacy.tar"
        for rootfs in (None, {}, {"type": "layers", "diff_ids": []},
                       {"type": "layers", "diff_ids": ["not-a-digest"]},
                       {"type": "unknown", "diff_ids": ["sha256:" + "a" * 64]}):
            legacy_layer_archive(path)
            ids = []
            def change(entries):
                config = json.loads(entries["config.json"])
                config["rootfs"] = rootfs
                entries["config.json"] = json.dumps(config).encode()
                ids.append("sha256:" + hashlib.sha256(entries["config.json"]).hexdigest())
            rewrite_tar(path, change=change)
            with self.subTest(rootfs=rootfs), self.assertRaisesRegex(kit.Error, "layer identity contract"):
                kit.inspect_image_archive(path, ids)

    def test_tar_framing_is_checked_before_structured_parser(self):
        path = self.cache / "framing.tar"
        identity = image_archive(path)
        original = path.read_bytes()
        with tarfile.open(path, "r:") as archive:
            members = archive.getmembers()
        first, last = members[0], members[-1]
        padding_start = first.offset_data + first.size
        end = last.offset_data + ((last.size + 511) // 512) * 512
        bad_checksum = bytearray(original)
        bad_checksum[0] ^= 1
        bad_padding = bytearray(original)
        bad_padding[padding_start] = ord("x")
        cases = [bytes(bad_checksum), bytes(bad_padding), original[:end],
                 original[:end] + b"\0" * 512, original + b"x" * 512,
                 original + b"\0" * tarfile.RECORDSIZE, original + original]
        for payload in cases:
            with self.subTest(size=len(payload)), patch.object(kit.tarfile, "open", side_effect=AssertionError("unsafe parser reached")):
                with self.assertRaises(kit.Error):
                    kit.inspect_image_archive(None, [identity], fileobj=io.BytesIO(payload))

    def test_normal_pax_and_gnu_long_names_remain_supported(self):
        path = self.cache / "extended.tar"
        identity = image_archive(path)
        rewrite_tar(path, pax={"mtime": "123.125", "comment": "bounded inert metadata"})
        kit.inspect_image_archive(path, [identity])
        identity = image_archive(path)
        rewrite_tar(path, extra={"metadata/" + "a" * 200: b"inert"}, format=tarfile.GNU_FORMAT)
        kit.inspect_image_archive(path, [identity])
        identity = image_archive(path)
        rewrite_tar(path, extra={"metadata/" + "b" * 200: b"inert"})
        kit.inspect_image_archive(path, [identity])
        # Go's archive/tar writer ends at two zero blocks, not a 10 KiB record.
        with tarfile.open(path, "r:") as archive:
            last = archive.getmembers()[-1]
        end = last.offset_data + ((last.size + 511) // 512) * 512
        kit.inspect_image_archive(None, [identity], fileobj=io.BytesIO(path.read_bytes()[:end + 1024]))

    def test_deeply_nested_image_json_is_a_bounded_validation_error(self):
        path = self.cache / "deep.tar"
        identity = image_archive(path)
        rewrite_tar(path, change=lambda entries: entries.update({"manifest.json": b"[" * 2000 + b"0" + b"]" * 2000}))
        with self.assertRaisesRegex(kit.Error, "nested image JSON"):
            kit.inspect_image_archive(path, [identity])

    def test_pax_unsafe_fields_and_aggregate_metadata_are_rejected_before_parser(self):
        path = self.cache / "extended.tar"
        for fields in ({"GNU.sparse.size": "100"}, {"linkpath": "other"}, {"size": "-1"},
                       {"mtime": "1e1000"}, {"path": "a" * 4097}):
            identity = image_archive(path)
            rewrite_tar(path, pax=fields)
            with self.subTest(fields=list(fields)), patch.object(kit.tarfile, "open", side_effect=AssertionError("unsafe parser reached")):
                with self.assertRaises(kit.Error):
                    kit.inspect_image_archive(path, [identity])
        identity = image_archive(path)
        rewrite_tar(path, pax={"comment": "x" * 1024})
        with patch.object(kit, "MAX_TAR_METADATA", 1500), patch.object(kit.tarfile, "open", side_effect=AssertionError("unsafe parser reached")):
            with self.assertRaises(kit.Error):
                kit.inspect_image_archive(path, [identity])

    def test_raw_special_and_chained_extension_records_never_reach_parser(self):
        def record(kind, data=b"", size=None):
            member = tarfile.TarInfo("inert-metadata")
            member.type = kind
            member.size = len(data) if size is None else size
            return member.tobuf(format=tarfile.GNU_FORMAT) + data + b"\0" * ((-len(data)) % 512)
        # Use a valid PAX record for chained-extension handling, not a parse failure.
        payload = b"14 comment=ok\n"
        cases = [record(kind) for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                                          tarfile.GNUTYPE_SPARSE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGLINK)]
        cases += [record(tarfile.GNUTYPE_LONGNAME, size=4097),
                  record(tarfile.XHDTYPE, payload) + record(tarfile.GNUTYPE_LONGNAME, b"name\0"),
                  record(tarfile.DIRTYPE, b"x")]
        for value in cases:
            with self.subTest(kind=value[156:157]), patch.object(kit.tarfile, "open", side_effect=AssertionError("unsafe parser reached")):
                with self.assertRaises(kit.Error):
                    kit.inspect_image_archive(None, ["sha256:" + "a" * 64], fileobj=io.BytesIO(value + b"\0" * 1024))

    def test_import_preview_never_contacts_daemon(self):
        bundle = self.root / "image-bundle"
        bundle.mkdir()
        path = bundle / "image.tar"
        identity = image_archive(path)
        raw = path.read_bytes()
        item = dict(self.value["artifacts"][0], id="test-image", path="image.tar", kind="image",
                    component="synthetic", image_ids=[identity], architecture="linux/amd64", version="test-1.0",
                    compatible_with=[], runtime_roles=[], sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        value = {"schema": kit.SCHEMA, "release_commit": "a" * 40, "scope": "image-export", "targets": [],
                 "required_ids": ["test-image"], "artifacts": [item]}
        (bundle / "manifest.json").write_text(json.dumps(value))
        with patch("subprocess.run", side_effect=AssertionError("execution")):
            with self.assertRaisesRegex(kit.Error, "detached expected manifest"):
                kit.import_images(argparse.Namespace(root=str(bundle), apply=False))
            result = kit.import_images(argparse.Namespace(
                root=str(bundle), apply=False, expected_manifest_sha256=digest(bundle / "manifest.json"),
                expected_release_commit="a" * 40))
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["scope"], "image-export")
        self.assertFalse(result["complete_target"])

    def test_image_verification_inspects_the_anchored_descriptor_not_its_path(self):
        path = self.cache / "image.tar"
        identity = image_archive(path)
        raw = path.read_bytes()
        item = dict(self.value["artifacts"][0], id="test-image", path="image.tar", kind="image",
                    component="synthetic", image_ids=[identity], architecture="linux/amd64", version="test-1.0",
                    compatible_with=[], runtime_roles=[], sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        value = {"schema": kit.SCHEMA, "release_commit": "a" * 40, "scope": "image-export", "targets": [],
                 "required_ids": ["test-image"], "artifacts": [item]}
        original = kit.inspect_image_archive
        def inspect(filename, ids, *, fileobj, architecture):
            self.assertIsNone(filename)
            self.assertEqual(os.fstat(fileobj.fileno()).st_ino, path.stat().st_ino)
            return original(filename, ids, fileobj=fileobj, architecture=architecture)
        with patch.object(kit, "inspect_image_archive", side_effect=inspect):
            kit.check_files(self.cache, value)

    def test_export_profile_requires_ids_local_only_review_and_bounds(self):
        value = export_document()
        self.assertEqual(kit.export_profile(value), value)
        for fields in ({"image_id": "example:latest"}, {"image_id": ["invalid"]}, {"reviewed_for_secrets": False},
                       {"redistribution": "reviewed"}, {"architecture": "darwin/arm64"}, {"id": "../outside"}, {"command": "docker ps"}):
            bad = copy.deepcopy(value)
            bad["images"][0].update(fields)
            with self.subTest(fields=fields), self.assertRaises(kit.Error):
                kit.export_profile(bad)
        for fields in ({"max_archive_bytes": 0}, {"max_total_bytes": 1}, {"timeout_seconds": 1801}, {"release_commit": "main"}):
            with self.assertRaises(kit.Error):
                kit.export_profile(dict(value, **fields))

    def test_export_profile_rejects_duplicate_image_ids(self):
        value = export_document()
        value["images"].append(dict(value["images"][0], id="another-label"))
        with self.assertRaisesRegex(kit.Error, "duplicate image ID"):
            kit.export_profile(value)

    def test_multi_image_profile_uses_distinct_validation_only_payloads(self):
        value = export_document()
        value["images"] = [dict(value["images"][0], id="image-" + str(number),
                                image_id="sha256:" + format(number, "064x")) for number in range(1, 10)]
        before = copy.deepcopy(value)
        with patch.object(kit, "manifest", wraps=kit.manifest) as validate:
            self.assertEqual(kit.export_profile(value), value)
        self.assertEqual(value, before)
        structural = validate.call_args.args[0]
        self.assertEqual(len({(item["sha256"], item["size"]) for item in structural["artifacts"]}), 9)
        # Changing the real inventory to duplicate payloads must still fail.
        structural["artifacts"][1]["sha256"] = structural["artifacts"][0]["sha256"]
        with self.assertRaisesRegex(kit.Error, "duplicate artifact payload"):
            kit.manifest(structural)

    def test_multi_image_profile_still_rejects_duplicate_artifact_labels(self):
        value = export_document()
        value["images"].append(dict(value["images"][0], image_id="sha256:" + "b" * 64))
        with self.assertRaises(kit.Error):
            kit.export_profile(value)

    def test_export_preview_has_no_daemon_contact_or_writes(self):
        profile = self.root / "export.json"
        profile.write_text(json.dumps(export_document()))
        args = argparse.Namespace(export_profile=str(profile), output=str(self.root / "bundle"), apply=False)
        with patch.object(kit, "bounded_docker_metadata", side_effect=AssertionError("daemon")), patch.object(kit.subprocess, "Popen", side_effect=AssertionError("daemon")):
            result = kit.export_images(args)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertFalse(result["daemon_checked"])
        self.assertEqual(result["scope"], "image-export")
        self.assertFalse(result["complete_target"])
        self.assertFalse((self.root / "bundle").exists())

    def test_export_cli_requires_approval_before_profile_lookup(self):
        with redirect_stdout(io.StringIO()), patch.object(kit.ops, "_read_json", side_effect=AssertionError("read")):
            self.assertEqual(kit.main(["export-images", "--export-profile", "missing", "--output", "new", "--apply"]), 2)

    def test_export_daemon_identity_mismatch(self):
        with patch.object(kit, "bounded_docker_metadata", return_value=b"different-daemon"):
            with self.assertRaisesRegex(kit.Error, "identity mismatch"):
                kit.approved_daemon("approved-daemon")

    def test_export_image_identity_and_architecture_mismatch(self):
        item = export_document()["images"][0]
        with patch.object(kit, "bounded_docker_metadata", return_value=(item["image_id"] + ";linux/arm64").encode()):
            with self.assertRaisesRegex(kit.Error, "architecture mismatch"):
                kit.approved_image(item)

    def test_inspection_rejects_legacy_repository_sidecar(self):
        path = self.cache / "image.tar"
        identity = image_archive(path)
        with tarfile.open(path, "a:") as archive:
            data = b'{"private-repository":{"release":"layer-id"}}'
            member = tarfile.TarInfo("repositories")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(kit.Error, "repository tag"):
            kit.inspect_image_archive(path, [identity])

    def test_inspection_rejects_oci_named_reference(self):
        path = self.cache / "image.tar"
        identity = image_archive(path)
        with tarfile.open(path, "a:") as archive:
            data = json.dumps({"schemaVersion": 2, "manifests": [{"annotations": {"org.opencontainers.image.ref.name": "private:tag"}}]}).encode()
            member = tarfile.TarInfo("index.json")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(kit.Error, "named image"):
            kit.inspect_image_archive(path, [identity])

    def test_inspection_rejects_layer_sources_and_registry_urls(self):
        path = self.cache / "image.tar"
        identity = image_archive(path)
        def layer_sources(entries):
            rows = json.loads(entries["manifest.json"])
            rows[0]["LayerSources"] = {"sha256:" + "a" * 64: {"urls": ["https://registry.invalid/layer"]}}
            entries["manifest.json"] = json.dumps(rows).encode()
        rewrite_tar(path, change=layer_sources)
        with self.assertRaisesRegex(kit.Error, "tag-free|structurally complete"):
            kit.inspect_image_archive(path, [identity])

        path = self.cache / "oci.tar"
        def descriptor_url(entries, index, rows):
            index["manifests"][0]["urls"] = ["https://registry.invalid/root"]
        identity, _ = oci_archive(path, descriptor_url)
        with self.assertRaisesRegex(kit.Error, "registry URL"):
            kit.inspect_image_archive(path, [identity], architecture="linux/amd64")

        def registry_annotation(entries, index, rows):
            index["manifests"][0]["annotations"] = {
                "containerd.io/distribution.source.registry.invalid": "repo/name"}
        identity, _ = oci_archive(path, registry_annotation)
        with self.assertRaisesRegex(kit.Error, "registry URL"):
            kit.inspect_image_archive(path, [identity], architecture="linux/amd64")

    def test_oci_manifest_list_identity_and_legacy_config_are_both_bound(self):
        path = self.cache / "oci.tar"
        identity, config = oci_archive(path)
        kit.inspect_image_archive(path, [identity], architecture="linux/amd64")
        kit.inspect_image_archive(path, [config], architecture="linux/amd64")
        with self.assertRaisesRegex(kit.Error, "architecture mismatch"):
            kit.inspect_image_archive(path, [identity], architecture="linux/arm64")
        with self.assertRaisesRegex(kit.Error, "identities"):
            kit.inspect_image_archive(path, ["sha256:" + "b" * 64])

    def test_oci_rejects_tampered_blob_missing_layer_and_wrong_size(self):
        path = self.cache / "oci.tar"
        def tamper(entries, index, rows):
            entries[rows[0]["Layers"][0]] += b"changed"
        def missing(entries, index, rows):
            del entries[rows[0]["Layers"][0]]
        def wrong_size(entries, index, rows):
            index["manifests"][0]["size"] += 1
        for mutation in (tamper, missing, wrong_size):
            identity, _ = oci_archive(path, mutation)
            with self.subTest(case=mutation.__name__), self.assertRaises(kit.Error):
                kit.inspect_image_archive(path, [identity])

    def test_oci_rejects_unbound_config_or_layers(self):
        path = self.cache / "oci.tar"
        def extra(entries, index, rows):
            entries["unbound.json"] = b'{"architecture":"amd64","os":"linux","extra":1}'
            rows.append({"Config": "unbound.json", "RepoTags": [], "Layers": []})
        def mismatch(entries, index, rows):
            rows[0]["Layers"] = []
        for mutation in (extra, mismatch):
            identity, _ = oci_archive(path, mutation)
            with self.assertRaises(kit.Error):
                kit.inspect_image_archive(path, [identity])

    def test_oci_rejects_named_index_and_missing_root(self):
        path = self.cache / "oci.tar"
        def named(entries, index, rows):
            index["annotations"] = {"io.containerd.image.name": "not-permitted:tag"}
        def missing(entries, index, rows):
            del entries["blobs/sha256/" + index["manifests"][0]["digest"][7:]]
        for mutation in (named, missing):
            identity, _ = oci_archive(path, mutation)
            with self.assertRaises(kit.Error):
                kit.inspect_image_archive(path, [identity])

    def test_oci_buildkit_provenance_is_verified_but_not_counted_as_image(self):
        path = self.cache / "oci.tar"
        identity, _ = oci_archive(path, attestation=True)
        kit.inspect_image_archive(path, [identity], architecture="linux/amd64")
        identity, _ = oci_archive(path, attestation=True, attestation_target="sha256:" + "d" * 64)
        with self.assertRaises(kit.Error):
            kit.inspect_image_archive(path, [identity])
        def missing_proof(entries, index, rows):
            for name, payload in list(entries.items()):
                if b"synthetic_provenance" in payload:
                    del entries[name]
        identity, _ = oci_archive(path, missing_proof, attestation=True)
        with self.assertRaisesRegex(kit.Error, "incomplete OCI"):
            kit.inspect_image_archive(path, [identity])

    def test_missing_nonlocal_buildkit_proof_requires_exact_missing_sibling_binding(self):
        path = self.cache / "oci.tar"
        identity, config = oci_archive(path, attestation=True, missing_attestation=True)
        kit.inspect_image_archive(path, [identity], architecture="linux/amd64")
        kit.inspect_image_archive(path, [config], architecture="linux/amd64")
        for fields in ({"missing_attestation_target": "present"},
                       {"missing_attestation_target": "sha256:" + "b" * 64},
                       {"missing_attestation_target": ["invalid"]},
                       {"missing_platform": "amd64"}):
            identity, _ = oci_archive(path, attestation=True, missing_attestation=True, **fields)
            with self.subTest(fields=fields), self.assertRaisesRegex(kit.Error, "platform|provenance"):
                kit.inspect_image_archive(path, [identity], architecture="linux/amd64")

    @unittest.skipIf(os.name == "nt", "image export requires descriptor-anchored POSIX staging")
    def test_export_atomic_roundtrip_only_fixed_save_command(self):
        identity = image_archive(self.cache / "synthetic.tar")
        payload = (self.cache / "synthetic.tar").read_bytes()
        profile = self.root / "export.json"
        profile.write_text(json.dumps(export_document(identity)))
        args = argparse.Namespace(export_profile=str(profile), output=str(self.root / "exported"), daemon_id="approved-daemon", apply=True)
        def metadata(argv):
            return b"approved-daemon" if argv[0] == "info" else (identity + ";linux/amd64").encode()
        with patch.object(kit, "bounded_docker_metadata", side_effect=metadata), patch.object(kit.subprocess, "Popen", return_value=SavedProcess(payload)) as popen:
            result = kit.export_images(args)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["containers_started"], 0)
        self.assertEqual(result["scope"], "image-export")
        self.assertFalse(result["complete_target"])
        self.assertEqual(result["manifest_sha256"], digest(self.root / "exported/manifest.json"))
        self.assertEqual(popen.call_args.args[0], ["docker", "image", "save", identity])
        value = kit.verify(self.root / "exported")
        self.assertEqual(value["artifacts"][0]["image_ids"], [identity])
        self.assertEqual(value["artifacts"][0]["redistribution"], "local-only")
        self.assertEqual((self.root / "exported" / value["artifacts"][0]["path"]).read_bytes(), payload)
        self.assertEqual(result["removed_annotation_count"], 0)
        self.assertEqual((self.root / "exported").stat().st_mode & 0o777, 0o700)
        with self.assertRaises(kit.Error):
            kit.export_images(args)

    @unittest.skipIf(os.name == "nt", "image export requires descriptor-anchored POSIX staging")
    def test_export_bound_failure_never_publishes_or_leaves_partial_file(self):
        profile = self.root / "export.json"
        value = export_document()
        value["max_archive_bytes"] = 100
        profile.write_text(json.dumps(value))
        args = argparse.Namespace(export_profile=str(profile), output=str(self.root / "exported"), daemon_id="approved-daemon", apply=True)
        process = SavedProcess(b"x" * 101)
        with patch.object(kit, "approved_daemon"), patch.object(kit, "approved_image"), patch.object(kit.subprocess, "Popen", return_value=process):
            with self.assertRaises(kit.Error):
                kit.export_images(args)
        self.assertTrue(process.killed)
        self.assertFalse((self.root / "exported").exists())
        self.assertEqual(list(self.root.glob(".image-export-*")), [])

    @unittest.skipIf(os.name == "nt", "image export requires descriptor-anchored POSIX staging")
    def test_multi_image_export_publishes_actual_archive_hashes_not_placeholders(self):
        value, payloads = export_document(), []
        template = value["images"][0]
        value["images"] = []
        for number in range(3):
            path = self.cache / ("synthetic-" + str(number) + ".tar")
            identity = image_archive(path, marker=number)
            payloads.append(path.read_bytes())
            value["images"].append(dict(template, id="image-" + str(number), image_id=identity))
        profile = self.root / "export.json"
        profile.write_text(json.dumps(value), encoding="utf-8")
        args = argparse.Namespace(export_profile=str(profile), output=str(self.root / "exported"),
                                  daemon_id="approved-daemon", apply=True)
        with patch.object(kit, "approved_daemon"), patch.object(kit, "approved_image"), \
             patch.object(kit.subprocess, "Popen", side_effect=[SavedProcess(payload) for payload in payloads]) as process:
            result = kit.export_images(args)
        verified = kit.verify(self.root / "exported", expected_manifest_sha256=result["manifest_sha256"])
        self.assertEqual(result["images"], 3)
        self.assertEqual(result["total_bytes"], sum(map(len, payloads)))
        self.assertEqual(process.call_count, 3)
        for item, payload, requested in zip(verified["artifacts"], payloads, value["images"]):
            self.assertEqual(item["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertNotEqual(item["sha256"], requested["image_id"][7:])
            self.assertEqual(item["size"], len(payload))
            self.assertEqual(item["image_ids"], [requested["image_id"]])
        self.assertEqual(list(self.root.glob(".image-export-*")), [])


class ExportNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "original"
        self.source.mkdir(mode=0o700)
        self.path = self.source / "image.tar"

    @staticmethod
    def registry_metadata(entries, index, rows):
        index["annotations"] = {"containerd.io/distribution.source.docker.io": "private-registry-path",
                                "org.opencontainers.image.created": "2026-01-01T00:00:00Z"}
        index["manifests"][0]["annotations"] = {"containerd.io/distribution.source.ghcr.io": "private-repository-path"}

    def create(self, mutation=None):
        identity, _ = oci_archive(self.path, mutation or self.registry_metadata)
        raw = self.path.read_bytes()
        item = {"id": "cached-image", "path": "image.tar", "kind": "image", "component": "synthetic",
                "architecture": "linux/amd64", "version": identity, "compatible_with": [], "runtime_roles": [],
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "license": "UNREVIEWED",
                "redistribution": "local-only", "image_ids": [identity]}
        value = {"schema": kit.SCHEMA, "release_commit": "a" * 40, "scope": "image-export", "targets": [],
                 "required_ids": [item["id"]], "artifacts": [item]}
        (self.source / "manifest.json").write_text(json.dumps(value), encoding="utf-8")
        return identity, value

    def arguments(self, **changes):
        result = dict(root=str(self.source), output=str(self.root / "normalized"), apply=False,
                      expected_manifest_sha256=digest(self.source / "manifest.json"), expected_release_commit="a" * 40)
        result.update(changes)
        return argparse.Namespace(**result)

    def create_legacy(self):
        identity, value = self.create()
        item = {key: val for key, val in value["artifacts"][0].items()
                if key not in {"version", "compatible_with", "runtime_roles"}}
        legacy = {"schema": kit.LEGACY_SCHEMA, "release_commit": value["release_commit"],
                  "required_ids": [item["id"]], "artifacts": [item]}
        (self.source / "manifest.json").write_text(json.dumps(legacy), encoding="utf-8")
        return identity, legacy

    def rewritten(self, **kwargs):
        with self.path.open("rb") as source, tempfile.TemporaryFile() as output:
            result = kit._rewrite_export_archive(source, output.fileno(), **kwargs)
            output.seek(0)
            return result, output.read()

    def export_fresh(self, identity, payload, *, max_bytes=1024 * 1024):
        profile = self.root / "fresh-export.json"
        value = export_document(identity)
        value["max_archive_bytes"] = max_bytes
        profile.write_text(json.dumps(value), encoding="utf-8")
        args = argparse.Namespace(export_profile=str(profile), output=str(self.root / "fresh"),
                                  daemon_id="approved-daemon", apply=True)
        with patch.object(kit, "approved_daemon"), patch.object(kit, "approved_image"), \
             patch.object(kit.subprocess, "Popen", return_value=SavedProcess(payload)) as process:
            result = kit.export_images(args)
        self.assertEqual(process.call_args.args[0], ["docker", "image", "save", identity])
        return result

    def assert_fresh_not_published(self):
        self.assertFalse((self.root / "fresh").exists())
        self.assertEqual(list(self.root.glob(".image-export-*")), [])

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_docker_registry_export_is_normalized_and_strictly_verified(self):
        identity, _ = self.create()
        original = self.path.read_bytes()
        result = self.export_fresh(identity, original)
        self.assertEqual(result["removed_annotation_count"], 2)
        self.assertEqual(result["strict_output_verification"], "PASS")
        self.assertFalse(result["complete_target"])
        verified = kit.verify(self.root / "fresh", expected_manifest_sha256=result["manifest_sha256"])
        self.assertEqual(verified["artifacts"][0]["image_ids"], [identity])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list((self.root / "fresh").glob(".docker-save-*")), [])
        self.assertEqual(list(self.root.glob(".image-export-*")), [])
        self.assertNotIn("private-registry-path", json.dumps(result))

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_named_references_and_urls_fail_without_output(self):
        for owner in ("root", "descriptor"):
            for fields in ({"annotations": {"org.opencontainers.image.ref.name": "private-tag"}},
                           {"annotations": {"io.containerd.image.name": "private-name"}},
                           {"urls": ["https://registry.invalid/private"]}):
                def mutate(entries, index, rows):
                    self.registry_metadata(entries, index, rows)
                    (index if owner == "root" else index["manifests"][0]).update(fields)
                identity, _ = self.create(mutate)
                with self.subTest(owner=owner, fields=list(fields)), self.assertRaises(kit.Error):
                    self.export_fresh(identity, self.path.read_bytes())
                self.assert_fresh_not_published()

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_legacy_tags_are_not_hidden_by_root_normalization(self):
        def mutate(entries, index, rows):
            self.registry_metadata(entries, index, rows)
            rows[0]["RepoTags"] = ["private:not-permitted"]
        identity, _ = self.create(mutate)
        with self.assertRaises(kit.Error):
            self.export_fresh(identity, self.path.read_bytes())
        self.assert_fresh_not_published()

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_addressed_metadata_is_not_changed_to_force_acceptance(self):
        def mutate(entries, index, rows):
            self.registry_metadata(entries, index, rows)
            descriptor = index["manifests"][0]
            old_name = "blobs/sha256/" + descriptor["digest"][7:]
            metadata = json.loads(entries.pop(old_name))
            metadata["annotations"] = {"containerd.io/distribution.source.docker.io": "private-nested-source"}
            raw = json.dumps(metadata).encode()
            descriptor["digest"], descriptor["size"] = "sha256:" + hashlib.sha256(raw).hexdigest(), len(raw)
            entries["blobs/sha256/" + descriptor["digest"][7:]] = raw
        identity, _ = self.create(mutate)
        with self.assertRaisesRegex(kit.Error, "registry URL"):
            self.export_fresh(identity, self.path.read_bytes())
        self.assert_fresh_not_published()

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_normalized_bytes_also_obey_export_budget(self):
        identity, _ = self.create()
        original = self.path.read_bytes()
        # Docker/Go may end a tar after the mandatory two zero records, while
        # Python's rewritten tar adds record padding. Bound the output too.
        with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as archive:
            end = max(member.offset_data + ((member.size + 511) // 512) * 512 for member in archive)
        payload = original[:end + 1024]
        with self.assertRaisesRegex(kit.Error, "normalized export exceeds byte budget"):
            self.export_fresh(identity, payload, max_bytes=len(payload))
        self.assert_fresh_not_published()

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_strict_failure_cleans_both_unpublished_stages(self):
        identity, _ = self.create()
        with patch.object(kit, "inspect_image_archive", side_effect=kit.Error("strict failure")), \
             self.assertRaisesRegex(kit.Error, "strict failure"):
            self.export_fresh(identity, self.path.read_bytes())
        self.assert_fresh_not_published()

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_raw_cleanup_failure_cannot_publish_unlisted_raw_bytes(self):
        identity, _ = self.create()
        cleanup = kit.ops._StagingDirectory.cleanup
        def leave_raw(stage):
            if stage.name.startswith(".docker-save-"):
                stage.close()
            else:
                cleanup(stage)
        with patch.object(kit.ops._StagingDirectory, "cleanup", new=leave_raw), self.assertRaises(kit.Error):
            self.export_fresh(identity, self.path.read_bytes())
        self.assertFalse((self.root / "fresh").exists())
        self.assertEqual(len(list(self.root.glob(".image-export-*/.docker-save-*/image.tar"))), 1)

    @unittest.skipIf(os.name == "nt", "fresh export uses anchored POSIX staging")
    def test_fresh_raw_growth_is_detected_before_any_publication(self):
        identity, _ = self.create()
        original = kit._rewrite_export_archive
        def growing(source, destination, **kwargs):
            result = original(source, destination, **kwargs)
            raw = list(self.root.glob(".image-export-*/.docker-save-*/image.tar"))
            self.assertEqual(len(raw), 1)
            with raw[0].open("ab") as writer:
                writer.write(b"changed-source")
            return result
        with patch.object(kit, "_rewrite_export_archive", side_effect=growing), \
             self.assertRaisesRegex(kit.Error, "grew"):
            self.export_fresh(identity, self.path.read_bytes())
        self.assertFalse((self.root / "fresh").exists())
        # An unexpectedly modified inode is retained, never broadly removed.
        self.assertEqual(len(list(self.root.glob(".image-export-*/.docker-save-*/image.tar"))), 1)

    def test_strict_verifier_still_rejects_original_registry_metadata(self):
        identity, _ = self.create()
        with self.assertRaisesRegex(kit.Error, "registry URL"):
            kit.inspect_image_archive(self.path, [identity], architecture="linux/amd64")

    def test_only_root_registry_annotations_change_blobs_and_other_payloads_unchanged(self):
        identity, _ = self.create()
        original = self.path.read_bytes()
        result, payload = self.rewritten()
        self.assertEqual(result["removed_annotations"], 2)
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["bytes"], len(payload))
        self.assertEqual(self.path.read_bytes(), original)
        kit.inspect_image_archive(None, [identity], architecture="linux/amd64", fileobj=io.BytesIO(payload))
        def contents(raw):
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                return {item.name: archive.extractfile(item).read() for item in archive if item.isfile()}
        before, after = contents(original), contents(payload)
        self.assertEqual(set(before), set(after))
        for name in before:
            if name != "index.json":
                self.assertEqual(before[name], after[name], name)
        index = json.loads(after["index.json"])
        self.assertEqual(index["annotations"], {"org.opencontainers.image.created": "2026-01-01T00:00:00Z"})
        self.assertEqual(index["manifests"][0]["annotations"], {})

    def test_no_annotation_change_preserves_entire_archive_bytes(self):
        self.create(lambda entries, index, rows: None)
        result, payload = self.rewritten()
        self.assertEqual(result["removed_annotations"], 0)
        self.assertEqual(payload, self.path.read_bytes())

    def test_named_references_and_url_metadata_are_never_stripped(self):
        for owner in ("root", "descriptor"):
            for fields in ({"annotations": {"org.opencontainers.image.ref.name": "private-tag"}},
                           {"annotations": {"io.containerd.image.name": "private-name"}},
                           {"urls": ["https://registry.invalid/private"]}):
                def mutate(entries, index, rows):
                    (index if owner == "root" else index["manifests"][0]).update(fields)
                self.create(mutate)
                with self.subTest(owner=owner, fields=list(fields)), self.assertRaises(kit.Error):
                    self.rewritten()

    def test_nested_addressed_registry_metadata_remains_a_strict_failure(self):
        def mutate(entries, index, rows):
            self.registry_metadata(entries, index, rows)
            descriptor = index["manifests"][0]
            old_name = "blobs/sha256/" + descriptor["digest"][7:]
            metadata = json.loads(entries.pop(old_name))
            metadata["annotations"] = {"containerd.io/distribution.source.docker.io": "private-nested-source"}
            raw = json.dumps(metadata).encode()
            descriptor["digest"], descriptor["size"] = "sha256:" + hashlib.sha256(raw).hexdigest(), len(raw)
            entries["blobs/sha256/" + descriptor["digest"][7:]] = raw
        identity, _ = self.create(mutate)
        _, payload = self.rewritten()
        with self.assertRaisesRegex(kit.Error, "registry URL"):
            kit.inspect_image_archive(None, [identity], fileobj=io.BytesIO(payload))

    def test_duplicate_or_oversized_root_json_is_rejected(self):
        for raw in (b'{"schemaVersion":2,"schemaVersion":2,"manifests":[]}', b" " * (1024 * 1024 + 1)):
            with self.assertRaises(kit.Error):
                kit._normalized_export_index(raw)
        with self.assertRaises(kit.Error):
            kit._normalized_export_index(b"[" * 2000 + b"0" + b"]" * 2000)

    def test_malformed_root_annotations_are_rejected(self):
        for field in ([], None, {"containerd.io/distribution.source.docker.io": ["invalid"]}):
            with self.assertRaises(kit.Error):
                kit._normalized_export_index(json.dumps({"schemaVersion": 2, "manifests": [{}], "annotations": field}).encode())

    def test_byte_budget_and_raw_tar_safety_apply_before_publication(self):
        self.create()
        with self.assertRaisesRegex(kit.Error, "byte budget"):
            self.rewritten(limit=1024)
        self.path.write_bytes(self.path.read_bytes() + b"private-trailer" + b"\0" * 497)
        with patch.object(kit.tarfile, "open", side_effect=AssertionError("unsafe tar reached parser")), self.assertRaises(kit.Error):
            self.rewritten()

    def test_preview_checks_trusted_bytes_without_writes_or_docker(self):
        self.create()
        before = {path.name: path.read_bytes() for path in self.source.iterdir()}
        with patch.object(kit.subprocess, "Popen", side_effect=AssertionError("Docker")), \
             patch.object(kit.ops._StagingDirectory, "create", side_effect=AssertionError("write")):
            result = kit.normalize_images(self.arguments())
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["removed_annotation_count"], 2)
        self.assertEqual(result["strict_output_verification"], "NOT_RUN")
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.source.iterdir()})
        self.assertNotIn("private-registry-path", json.dumps(result))

    def test_preview_rejects_bad_manifest_hash_changed_source_and_overwrite(self):
        self.create()
        with self.assertRaises(kit.Error):
            kit.normalize_images(self.arguments(expected_manifest_sha256="f" * 64))
        with self.assertRaises(kit.Error):
            kit.normalize_images(self.arguments(output=str(self.source)))
        self.path.write_bytes(self.path.read_bytes() + b"changed")
        with self.assertRaisesRegex(kit.Error, "checksum or size"):
            kit.normalize_images(self.arguments())

    def test_post_migration_hash_rejects_growth_without_unbounded_reads(self):
        self.create()
        with self.path.open("rb") as source:
            before = os.fstat(source.fileno())
            calls = []
            class GrowingStream:
                def seek(self, offset):
                    source.seek(offset)
                def fileno(self):
                    return source.fileno()
                def read(self, size):
                    calls.append(size)
                    result = source.read(size)
                    if len(calls) == 1:
                        with self_outer.path.open("ab") as writer:
                            writer.write(b"growing-source")
                    return result
            self_outer = self
            with self.assertRaisesRegex(kit.Error, "grew"):
                kit._rehash_original_export(GrowingStream(), before)
        self.assertTrue(all(0 < size <= before.st_size + 1 for size in calls))
        self.assertLessEqual(len(calls), 2)

    def test_post_migration_hash_rechecks_descriptor_identity_after_read(self):
        self.create()
        with self.path.open("rb") as source:
            before = os.fstat(source.fileno())
            with patch.object(kit.ops, "_stat_identity", side_effect=["changed", "original"]), \
                 self.assertRaisesRegex(kit.Error, "changed"):
                kit._rehash_original_export(source, before)

    def test_image_only_legacy_preview_migrates_only_to_partial_v2_scope(self):
        _, legacy = self.create_legacy()
        original = copy.deepcopy(legacy)
        result = kit.normalize_images(self.arguments())
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["scope"], "image-export")
        self.assertEqual(result["source_schema"], kit.LEGACY_SCHEMA)
        self.assertFalse(result["complete_target"])
        migrated = kit._normalization_manifest(legacy)
        self.assertEqual(legacy, original)
        self.assertEqual(migrated["schema"], kit.SCHEMA)
        self.assertEqual(migrated["targets"], [])
        self.assertEqual(migrated["artifacts"][0]["version"], legacy["artifacts"][0]["image_ids"][0])
        self.assertEqual(migrated["artifacts"][0]["compatible_with"], [])
        self.assertEqual(migrated["artifacts"][0]["runtime_roles"], [])

    def test_legacy_mixed_optional_or_multi_identity_archives_are_not_migrated(self):
        _, legacy = self.create_legacy()
        mixed = copy.deepcopy(legacy)
        mixed["artifacts"].append(dict(mixed["artifacts"][0], id="license", path="license.txt", kind="license", image_ids=[], architecture="all"))
        mixed["required_ids"].append("license")
        optional = copy.deepcopy(legacy)
        optional["artifacts"].append(dict(optional["artifacts"][0], id="optional-image", path="other.tar", image_ids=["sha256:" + "f" * 64]))
        multi = copy.deepcopy(legacy)
        multi["artifacts"][0]["image_ids"].append("sha256:" + "f" * 64)
        for value in (mixed, optional, multi):
            with self.subTest(case=len(value["artifacts"])), self.assertRaisesRegex(kit.Error, "legacy normalization"):
                kit._normalization_manifest(value)

    @unittest.skipIf(os.name == "nt", "normalization uses anchored POSIX staging")
    def test_legacy_image_only_migration_preserves_original_manifest_and_payload_ids(self):
        identity, _ = self.create_legacy()
        original = (self.source / "manifest.json").read_bytes()
        result = kit.normalize_images(self.arguments(apply=True))
        migrated = kit.verify(self.root / "normalized", expected_manifest_sha256=result["manifest_sha256"])
        self.assertEqual(migrated["schema"], kit.SCHEMA)
        self.assertEqual(migrated["scope"], "image-export")
        self.assertEqual(migrated["artifacts"][0]["image_ids"], [identity])
        self.assertEqual(result["source_manifest_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(result["source_schema"], kit.LEGACY_SCHEMA)
        self.assertEqual((self.source / "manifest.json").read_bytes(), original)

    @unittest.skipIf(os.name == "nt", "normalization uses anchored POSIX staging")
    def test_normalized_bundle_strict_roundtrip_preserves_original_and_ids(self):
        _, value = self.create()
        before = {path.name: path.read_bytes() for path in self.source.iterdir()}
        result = kit.normalize_images(self.arguments(apply=True))
        verified = kit.verify(self.root / "normalized", expected_manifest_sha256=result["manifest_sha256"])
        self.assertEqual(result["strict_output_verification"], "PASS")
        self.assertEqual(verified["artifacts"][0]["image_ids"], value["artifacts"][0]["image_ids"])
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.source.iterdir()})
        self.assertEqual((self.root / "normalized").stat().st_mode & 0o777, 0o700)
        with self.assertRaises(kit.Error):
            kit.normalize_images(self.arguments(apply=True))

    @unittest.skipIf(os.name == "nt", "normalization uses anchored POSIX staging")
    def test_unchanged_strict_failure_never_publishes_partial_bundle(self):
        def mutate(entries, index, rows):
            self.registry_metadata(entries, index, rows)
            rows[0]["RepoTags"] = ["private:not-permitted"]
        self.create(mutate)
        with self.assertRaises(kit.Error):
            kit.normalize_images(self.arguments(apply=True))
        self.assertFalse((self.root / "normalized").exists())
        self.assertEqual(list(self.root.glob(".normalized-export-*")), [])


if __name__ == "__main__":
    unittest.main()
