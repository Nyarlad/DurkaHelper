#!/usr/bin/env python3
"""Check a private offline cache and prepare the strict v2 assembly manifest.

This does not download, execute installers, inspect Docker, or prove cold-start
readiness. Pins authenticate an explicitly reviewed cache recipe; source archive
provenance and license suitability still require operator review.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location("inventory_bundle", Path(__file__).with_name("toolchain_bundle.py"))
kit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit)
ops, Error = kit.ops, kit.Error
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "durkahelper.toolchain-inventory.v1"
REPORT_SCHEMA = "durkahelper.toolchain-readiness.v1"
NATIVE_COMPONENTS = {"container-runtime", "python", "ripgrep"}
ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
SHA = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
ASSET_FIELDS = {"id", "path", "kind", "component", "architecture", "version", "sha256", "size",
                "license", "redistribution", "source_pins"}


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _path(value):
    value = ops._portable_relative_posix(value, "cache member")
    if (set(part.casefold() for part in value.split("/")) & kit.FORBIDDEN or
            any(part.casefold().startswith(".env.") for part in value.split("/")) or
            Path(value).suffix.lower() in {".key", ".pem", ".pcap", ".pcapng", ".db", ".sqlite", ".log"}):
        raise Error("private operational data is not an inventory member")
    return value


def recipe(value):
    fields = {"schema", "release_commit", "target", "receipt", "image_export", "artifacts"}
    ops._strict_keys(value, fields, fields, "toolchain inventory")
    if value["schema"] != SCHEMA or not _matches(COMMIT, value["release_commit"]):
        raise Error("invalid inventory schema or release")
    ops._strict_keys(value["target"], {"id", "platform"}, {"id", "platform"}, "inventory target")
    if not _matches(ID, value["target"]["id"]):
        raise Error("invalid target identity")
    ops._deployment_enum(value["target"]["platform"], kit.NATIVE_PLATFORMS, "target platform")
    for key in ("receipt", "image_export"):
        reference = value[key]
        ops._strict_keys(reference, {"path", "sha256"}, {"path", "sha256"}, "inventory reference")
        _path(reference["path"])
        if not _matches(SHA, reference["sha256"]):
            raise Error("inventory reference requires a detached checksum")
    if value["receipt"]["path"].casefold() == value["image_export"]["path"].casefold():
        raise Error("ambiguous inventory references")
    assets = value["artifacts"]
    if not isinstance(assets, list) or len(assets) > 128:
        raise Error("inventory requires at most 128 non-image artifacts")
    ids, paths, component_kinds = set(), set(), set()
    total = 0
    for asset in assets:
        ops._strict_keys(asset, ASSET_FIELDS, ASSET_FIELDS, "inventory artifact")
        if not _matches(ID, asset["id"]) or not _matches(ID, asset["component"]):
            raise Error("invalid artifact identity")
        component, kind = asset["component"], asset["kind"]
        if (not isinstance(kind, str) or component not in kit.REQUIRED_COMPONENT_KINDS or
                kind == "image" or kind not in kit.REQUIRED_COMPONENT_KINDS[component]):
            raise Error("artifact outside the maintained component contract")
        path = _path(asset["path"])
        if (asset["id"] in ids or path.casefold() in paths or
                (component, kind) in component_kinds or path.casefold() == "manifest.json" or
                path.casefold() in {value[key]["path"].casefold() for key in ("receipt", "image_export")}):
            raise Error("ambiguous cache artifact")
        ids.add(asset["id"])
        paths.add(path.casefold())
        component_kinds.add((component, kind))
        ops._deployment_enum(asset["architecture"], {"all", *kit.NATIVE_PLATFORMS}, "artifact architecture")
        if asset["architecture"] not in {"all", value["target"]["platform"]}:
            raise Error("cache artifact architecture does not match target")
        if kind in {"client", "runtime", "installer"} and asset["architecture"] != value["target"]["platform"]:
            raise Error("native artifacts require the exact target platform")
        version = asset["version"]
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,127}", version) or
                set(re.split(r"[:/@._+-]+", version.casefold())) & kit.FLOATING_VERSIONS):
            raise Error("artifact requires an exact version")
        if not _matches(SHA, asset["sha256"]):
            raise Error("artifact checksum required")
        ops._positive_int(asset["size"], "artifact size", kit.MAX_ARTIFACT)
        total += asset["size"]
        if not isinstance(asset["license"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+() -]{0,127}", asset["license"]):
            raise Error("artifact license reference required")
        if asset["redistribution"] != "local-only":
            raise Error("inventory preparation is local-only, not redistribution approval")
        pins = asset["source_pins"]
        if not isinstance(pins, dict) or len(pins) > 32:
            raise Error("invalid source pin inventory")
        for name, commit in pins.items():
            if name != ".":
                _path(name)
            if not _matches(COMMIT, commit):
                raise Error("source pin must be a full commit")
        if kind == "source":
            if pins.get(".") != version:
                raise Error("source archive must declare its root commit")
        elif pins:
            raise Error("only source archives declare source pins")
        if kind == "core" and version != value["release_commit"]:
            raise Error("core release differs from inventory release")
    if total > kit.MAX_TOTAL:
        raise Error("inventory exceeds total byte budget")
    return value


def _json_member(root, identity, reference):
    """Read a checksum-bound JSON member without following cache ancestor links."""
    descriptor = ops._open_anchored_regular(root, reference["path"], identity)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > ops.MAX_PROFILE_BYTES:
            raise Error("inventory reference exceeds limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(ops.MAX_PROFILE_BYTES + 1)
        if len(raw) > ops.MAX_PROFILE_BYTES or ops._stat_identity(before) != ops._stat_identity(os.fstat(descriptor)):
            raise Error("inventory reference changed")
        if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise Error("inventory reference checksum mismatch")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=ops._unique_object,
                          parse_constant=ops._reject_constant)
    finally:
        os.close(descriptor)


def _receipt(value):
    fields = {"schema", "compose_sha256", "runtime_sha256", "images"}
    ops._strict_keys(value, fields, fields, "deployment receipt")
    if (value["schema"] != "durkahelper.deployment-build.v2" or
            not _matches(SHA, value["compose_sha256"]) or not _matches(SHA, value["runtime_sha256"]) or
            not isinstance(value["images"], dict) or set(value["images"]) != set(kit.MAINTAINED_ROLES) or
            any(not isinstance(i, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", i) for i in value["images"].values())):
        raise Error("receipt must pin exactly the maintained runtime roles")
    for group in kit.SHARED_IMAGE_IDENTITY_GROUPS:
        if len({value["images"][role] for role in group}) != 1:
            raise Error("receipt shared image identities disagree")
    return value


def _pin_problem(asset, lock, platform):
    """Return a safe category, never a URL, path, checksum or lock value."""
    component, kind = asset["component"], asset["kind"]
    if kind in {"core", "license"}:
        return None
    pinned = lock.get("components", {}).get(component, {})
    if kind == "source":
        commit = pinned.get("source", {}).get("commit")
        submodules = pinned.get("submodules", {})
        if not _matches(COMMIT, commit) or submodules.get("status") != "EXISTING":
            return "unresolved-source-pin"
        expected = {".": commit}
        for entry in submodules.get("items", []):
            if not isinstance(entry, dict) or not _matches(COMMIT, entry.get("commit")):
                return "unresolved-submodule-pin"
            expected[entry.get("path")] = entry["commit"]
        return None if asset["source_pins"] == expected else "source-pin-mismatch"
    if kind == "client":
        system, arch = platform.split("/")
        candidates = [entry for entry in pinned.get("release", {}).get("assets", [])
                      if entry.get("os") == system and entry.get("architecture") == arch]
        version = pinned.get("version")
        if not version or len(candidates) != 1:
            return "unresolved-client-pin"
        candidate = candidates[0]
        if (asset["version"].removeprefix("v") != str(version).removeprefix("v") or
                asset["sha256"] != candidate.get("published_sha256") or asset["size"] != candidate.get("size")):
            return "client-pin-mismatch"
        return None
    # Native prerequisites need a platform-specific official asset pin in the
    # maintained lock. A locally measured hash cannot authenticate its origin.
    candidate = pinned.get("asset", {})
    candidates = pinned.get("assets", [])
    if candidates:
        candidates = [entry for entry in candidates if entry.get("platform") == platform]
        candidate = candidates[0] if len(candidates) == 1 else {}
    elif not any(entry.get("arch") == platform.split("/")[1] and
                 entry.get("os") in ({"darwin", "macos"} if platform.startswith("darwin/") else {platform.split("/")[0]})
                 for entry in pinned.get("architectures", [])):
        candidate = {}
    checksum = candidate.get("sha256") or candidate.get("digest")
    if isinstance(checksum, str):
        checksum = checksum.removeprefix("sha256:")
    if not _matches(SHA, checksum) or not pinned.get("version"):
        return "unresolved-prerequisite-pin"
    if (asset["sha256"] != checksum or asset["version"] != pinned["version"] or
            (candidate.get("size") is not None and asset["size"] != candidate["size"])):
        return "prerequisite-pin-mismatch"
    return None


def inspect(root, value, lock):
    """Return a sanitized report and, only when complete, a validated manifest."""
    value = recipe(value)
    if not isinstance(lock, dict) or lock.get("schema") != "durkahelper.toolchain-lock.v1" or not isinstance(lock.get("components"), dict):
        raise Error("invalid maintained toolchain lock")
    root = ops._canonical_root_directory(Path(root))
    identity = ops._root_anchor_identity(root.lstat())
    receipt = _receipt(_json_member(root, identity, value["receipt"]))
    exported = kit.manifest(_json_member(root, identity, value["image_export"]), expected_scope="image-export")
    kit._check_release_commit(exported, value["release_commit"])
    if set(receipt["images"].values()) != {i for item in exported["artifacts"] for i in item["image_ids"]}:
        raise Error("image export does not exactly cover the deployment receipt")
    target_platform = value["target"]["platform"]
    container_platform = "linux/" + target_platform.split("/")[1]
    sources = {item["component"]: item["id"] for item in value["artifacts"] if item["kind"] == "source"}
    artifacts, issues = [], []
    export_parent = PurePosixPath(value["image_export"]["path"]).parent
    for exported_item in exported["artifacts"]:
        item = copy.deepcopy(exported_item)
        roles = sorted(role for role, image in receipt["images"].items() if image in item["image_ids"])
        components = {kit.ROLE_IMAGE_COMPONENTS[role] for role in roles}
        platforms = {kit.FIXED_ROLE_PLATFORMS.get(role, container_platform) for role in roles}
        if len(components) != 1 or platforms != {item["architecture"]}:
            raise Error("image archive cannot map unambiguously to target roles")
        item["component"] = components.pop()
        item["path"] = _path((export_parent / item["path"]).as_posix())
        item["runtime_roles"] = roles
        item["compatible_with"] = [sources[item["component"]]] if item["component"] in sources else []
        item["redistribution"] = "local-only"
        artifacts.append(item)
    ids = {item["id"] for item in artifacts}
    paths = {item["path"].casefold() for item in artifacts}
    reference_paths = {value[key]["path"].casefold() for key in ("receipt", "image_export")}
    if paths & reference_paths:
        raise Error("image payload collides with an inventory reference")
    worker = next(item["id"] for item in artifacts if "neo-worker" in item["runtime_roles"])
    for original in value["artifacts"]:
        item = {key: val for key, val in original.items() if key != "source_pins"}
        if item["id"] in ids or item["path"].casefold() in paths:
            raise Error("image and artifact inventory collide")
        ids.add(item["id"])
        paths.add(item["path"].casefold())
        item.update(image_ids=[], runtime_roles=[], compatible_with=[])
        if item["kind"] == "client" and "neo" in sources:
            item["compatible_with"] = [worker, sources["neo"]]
        try:
            problem = _pin_problem(original, lock, target_platform)
        except (AttributeError, KeyError, TypeError):
            problem = "invalid-component-pin"
        if problem:
            issues.append({"component": item["component"], "kind": item["kind"], "issue": problem})
        artifacts.append(item)
    if sum(item["size"] for item in artifacts) > kit.MAX_TOTAL:
        raise Error("complete cache exceeds byte budget")
    # Verify each declared file independently so all missing/corrupt items are
    # reported in one pass. Exceptions are deliberately not copied to evidence.
    for item in artifacts:
        if ops._root_anchor_identity(root.lstat()) != identity:
            raise Error("cache root changed during inventory")
        try:
            kit.check_files(root, {"artifacts": [item]})
        except (Error, OSError, ValueError, kit.tarfile.TarError):
            issues.append({"component": item["component"], "kind": item["kind"], "issue": "cache-file-unverified"})
    if ops._root_anchor_identity(root.lstat()) != identity:
        raise Error("cache root changed during inventory")
    have = {(item["component"], item["kind"]) for item in artifacts}
    for component, kinds in sorted(kit.REQUIRED_COMPONENT_KINDS.items()):
        for kind in sorted(kinds):
            if (component, kind) not in have:
                issues.append({"component": component, "kind": kind, "issue": "missing-artifact"})
    issues = sorted({(item["component"], item["kind"], item["issue"]) for item in issues})
    issues = [dict(zip(("component", "kind", "issue"), item)) for item in issues]
    existing_issues = [item for item in issues if item["component"] not in NATIVE_COMPONENTS]
    candidate = None
    if not issues:
        candidate = kit.manifest({
            "schema": kit.SCHEMA, "release_commit": value["release_commit"], "scope": "complete-target",
            "required_ids": [item["id"] for item in artifacts], "artifacts": artifacts,
            "targets": [{**value["target"],
                "container_platforms": sorted({container_platform, *kit.FIXED_ROLE_PLATFORMS.values()}),
                "deployment_contract_sha256": kit.DEPLOYMENT_CONTRACT_SHA256,
                "runtime_roles": [{"id": role, "component": component,
                    "platform": kit.FIXED_ROLE_PLATFORMS.get(role, container_platform),
                    "image_id": receipt["images"][role]} for role, component in kit.MAINTAINED_ROLES.items()],
                "artifact_ids": [item["id"] for item in artifacts]}]})
    report = {
        "schema": REPORT_SCHEMA, "status": "PASS" if candidate else "BLOCKED", "action": "inventory",
        "target_platform": target_platform, "release_commit": value["release_commit"],
        "artifacts_declared": len(artifacts), "runtime_roles_bound": len(receipt["images"]),
        "existing_runtime_inventory": "PASS" if not existing_issues else "BLOCKED",
        "clean_machine_inventory": "PASS" if candidate else "BLOCKED", "issues": issues,
        "manifest_sha256": hashlib.sha256(ops._canonical(candidate)).hexdigest() if candidate else None,
        "complete_target": candidate is not None, "offline_runtime": "NOT_RUN", "competition_ready": False,
        "installed_prerequisites": "NOT_CHECKED", "source_provenance": "DECLARED_NOT_VERIFIED",
        "redistribution": "local-only", "daemon_checked": False,
        "verification_scope": "receipt identities, declared pins, payload hashes and image structure; not installation or runtime acceptance",
    }
    return report, candidate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="Private cache directory; files are never modified")
    parser.add_argument("--inventory", required=True, help="Operator-reviewed inventory recipe JSON")
    parser.add_argument("--expected-inventory-sha256", required=True, help="Detached trusted recipe digest")
    parser.add_argument("--lock", default=str(ROOT / "config/toolchain.lock.json"))
    parser.add_argument("--emit-manifest", help="Create a NEW assembly manifest only when the full inventory passes")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    args = parser.parse_args(argv)
    try:
        if args.apply and (not args.emit_manifest or not args.approval_id or not ops.APPROVAL_ID.fullmatch(args.approval_id)):
            raise Error("manifest publication requires output and a non-secret approval ID")
        value, raw = ops._read_json(args.inventory, ops.MAX_PROFILE_BYTES)
        kit._check_manifest_digest(raw, args.expected_inventory_sha256, required=True)
        lock, _ = ops._read_json(args.lock, ops.MAX_PROFILE_BYTES)
        report, candidate = inspect(args.root, value, lock)
        if args.emit_manifest:
            report["manifest_written"] = False
            if candidate and args.apply:
                ops._atomic_write_new(args.emit_manifest, ops._canonical(candidate))
                report["manifest_written"] = True
            elif candidate:
                report["action"] = "manifest-preview"
        print(json.dumps(report, sort_keys=True))
        return 0 if candidate else 2
    except (Error, OSError, ValueError, TypeError, RecursionError, kit.tarfile.TarError):
        print(json.dumps({"schema": REPORT_SCHEMA, "status": "BLOCKED", "error": "invalid-or-unreadable-inventory", "details": "suppressed", "exit_code": 2}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
