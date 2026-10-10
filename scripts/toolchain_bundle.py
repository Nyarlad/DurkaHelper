#!/usr/bin/env python3
"""Assemble and verify explicitly inventoried offline toolchain artifacts.

Operator-local companion to build_offline_bundle.py, not a downloader or a
publisher. Verification proves the declared inventory, not disconnected runtime
acceptance or third-party redistribution rights.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import threading
import zlib

SPEC = importlib.util.spec_from_file_location("toolchain_ops", Path(__file__).with_name("defense_ops.py"))
ops = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ops)
Error = ops.DefenseError
LEGACY_SCHEMA = "durkahelper.toolchain-manifest.v1"
SCHEMA = "durkahelper.toolchain-manifest.v2"
EXPORT_SCHEMA = "durkahelper.image-export.v1"
MAX_ARTIFACT = 32 * 1024 ** 3
MAX_TOTAL = 96 * 1024 ** 3
MAX_PAX_BYTES = 16 * 1024
MAX_TAR_METADATA = 4 * 1024 * 1024
MAX_LAYER_EXPANDED = 8 * 1024 ** 3
CHUNK = 1024 * 1024
FORBIDDEN = {".git", ".ssh", ".aws", ".gnupg", "secrets", ".env", "id_ed25519", "id_rsa"}
ARTIFACT_KINDS = {"core", "image", "source", "client", "license", "installer", "runtime"}
NATIVE_PLATFORMS = {"linux/amd64", "linux/arm64", "darwin/arm64", "windows/amd64"}
CONTAINER_PLATFORMS = {"linux/amd64", "linux/arm64"}
REQUIRED_COMPONENT_KINDS = {
    "durkahelper": {"core", "license"},
    "postgres": {"image", "license"},
    "redis": {"image", "license"},
    "s4dfarm": {"image", "source", "license"},
    "neo": {"image", "source", "client", "license"},
    "packmate": {"image", "source", "license"},
    "container-runtime": {"installer", "license"},
    "python": {"runtime", "license"},
    "ripgrep": {"runtime", "license"},
}
INTEGRATION_COMPONENTS = {"s4dfarm", "neo", "packmate"}
FLOATING_VERSIONS = {"latest", "main", "master", "head", "current", "stable", "edge", "nightly", "snapshot"}
MAINTAINED_ROLES = {
    "postgres": "s4dfarm",
    "redis": "s4dfarm",
    "neo-redis": "neo",
    "farm": "s4dfarm",
    "celery": "s4dfarm",
    "front": "s4dfarm",
    "neo-server": "neo",
    "neo-worker": "neo",
    "packmate-db": "packmate",
    "packmate": "packmate",
}
ROLE_IMAGE_COMPONENTS = {
    "postgres": "postgres",
    "redis": "redis",
    "neo-redis": "redis",
    "farm": "s4dfarm",
    "celery": "s4dfarm",
    "front": "s4dfarm",
    "neo-server": "neo",
    "neo-worker": "neo",
    "packmate-db": "postgres",
    "packmate": "packmate",
}
TARGET_PLATFORM_ROLES = tuple(role for role in MAINTAINED_ROLES if role != "packmate")
FIXED_ROLE_PLATFORMS = {"packmate": "linux/amd64"}
SHARED_IMAGE_IDENTITY_GROUPS = (("redis", "neo-redis"),)
# SHA-256 of the canonical maintained-deployment.v2 role/owner/image-origin,
# target-platform and shared-image topology document.  This independent
# constant prevents a manifest from defining and authenticating its own
# convenient variant of the maintained deployment.
DEPLOYMENT_CONTRACT_SHA256 = "a2327cb0dd091d387d33b283337c048778b6b7aa9bef5a344d19aa48c0d9322b"
CONTRACT_SHA256 = DEPLOYMENT_CONTRACT_SHA256


def _manifest_scope(value):
    return value["scope"] if value.get("schema") == SCHEMA else "legacy-inventory"


def _legacy_manifest(value):
    """The published v1 parser: a partial inventory, never a complete kit."""
    fields = {"schema", "release_commit", "required_ids", "artifacts"}
    ops._strict_keys(value, fields, fields, "legacy toolchain manifest")
    if (value["schema"] != LEGACY_SCHEMA or not isinstance(value["release_commit"], str) or
            not re.fullmatch(r"[0-9a-f]{40}", value["release_commit"])):
        raise Error("invalid legacy toolchain schema or commit")
    entries = value["artifacts"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise Error("toolchain requires 1..256 explicit artifacts")
    ids, paths, total = set(), set(), 0
    for item in entries:
        fields = {"id", "path", "kind", "component", "architecture", "sha256", "size",
                  "license", "redistribution", "image_ids"}
        ops._strict_keys(item, fields, fields, "legacy toolchain artifact")
        for field in ("id", "component"):
            if not isinstance(item[field], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", item[field]):
                raise Error("invalid toolchain artifact identifier")
        path = ops._portable_relative_posix(item["path"], "toolchain path")
        if (set(part.lower() for part in path.split("/")) & FORBIDDEN or path == "manifest.json" or
                any(part.lower().startswith(".env.") for part in path.split("/")) or
                Path(path).suffix.lower() in {".key", ".pem", ".pcap", ".pcapng", ".db", ".sqlite", ".log"}):
            raise Error("private operational data is not a toolchain artifact")
        if item["id"] in ids or path.casefold() in paths:
            raise Error("duplicate toolchain identity or path")
        ids.add(item["id"])
        paths.add(path.casefold())
        ops._deployment_enum(item["kind"], {"core", "image", "source", "client", "license"}, "artifact kind")
        ops._deployment_enum(item["architecture"], {"all", *NATIVE_PLATFORMS}, "artifact architecture")
        ops._deployment_enum(item["redistribution"], {"local-only", "reviewed"}, "redistribution")
        if not isinstance(item["license"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+() -]{0,127}", item["license"]):
            raise Error("artifact license reference required")
        if not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise Error("artifact checksum required")
        ops._positive_int(item["size"], "artifact bytes", MAX_ARTIFACT)
        total += item["size"]
        image_ids = item["image_ids"]
        if (not isinstance(image_ids, list) or len(image_ids) > 64 or
                any(not isinstance(identity, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity)
                    for identity in image_ids) or len(set(image_ids)) != len(image_ids)):
            raise Error("invalid immutable image identities")
        if (item["kind"] == "image") != bool(image_ids):
            raise Error("only image archives declare immutable image identities")
        if item["kind"] == "image" and item["architecture"] not in CONTAINER_PLATFORMS:
            raise Error("image archives require an explicit supported Linux architecture")
    required = value["required_ids"]
    if (not isinstance(required, list) or any(not isinstance(identifier, str) for identifier in required) or
            len(required) != len(set(required)) or not required or not set(required) <= ids):
        raise Error("required toolchain inventory is incomplete")
    if total > MAX_TOTAL:
        raise Error("toolchain exceeds its total byte budget")
    return value


def manifest(value, *, expected_scope=None):
    """Validate v2 complete/image-export manifests or the partial v1 inventory."""
    if not isinstance(value, dict):
        raise Error("invalid toolchain manifest")
    if value.get("schema") == LEGACY_SCHEMA:
        result = _legacy_manifest(value)
        if expected_scope is not None and expected_scope != "legacy-inventory":
            raise Error("toolchain scope is not valid for this action")
        return result
    fields = {"schema", "release_commit", "scope", "targets", "required_ids", "artifacts"}
    ops._strict_keys(value, fields, fields, "toolchain manifest")
    if value["schema"] != SCHEMA or not isinstance(value["release_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["release_commit"]):
        raise Error("invalid toolchain schema or commit")
    scope = value["scope"]
    ops._deployment_enum(scope, {"complete-target", "image-export"}, "toolchain scope")
    if expected_scope is not None and scope != expected_scope:
        raise Error("toolchain scope is not valid for this action")
    entries = value["artifacts"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise Error("toolchain requires 1..256 explicit artifacts")
    ids, paths, payloads, image_identities, total = set(), set(), {}, set(), 0
    for item in entries:
        fields = {"id", "path", "kind", "component", "architecture", "version", "compatible_with",
                  "runtime_roles", "sha256", "size", "license", "redistribution", "image_ids"}
        ops._strict_keys(item, fields, fields, "toolchain artifact")
        for field in ("id", "component"):
            if not isinstance(item[field], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", item[field]):
                raise Error("invalid toolchain artifact identifier")
        path = ops._portable_relative_posix(item["path"], "toolchain path")
        if (set(p.lower() for p in path.split("/")) & FORBIDDEN or path == "manifest.json" or
                any(p.lower().startswith(".env.") for p in path.split("/")) or
                Path(path).suffix.lower() in {".key", ".pem", ".pcap", ".pcapng", ".db", ".sqlite", ".log"}):
            raise Error("private operational data is not a toolchain artifact")
        if item["id"] in ids or path.casefold() in paths:
            raise Error("duplicate toolchain identity or path")
        ids.add(item["id"])
        paths.add(path.casefold())
        ops._deployment_enum(item["kind"], ARTIFACT_KINDS, "artifact kind")
        ops._deployment_enum(item["architecture"], {"all", "linux/amd64", "linux/arm64", "darwin/arm64", "windows/amd64"}, "artifact architecture")
        ops._deployment_enum(item["redistribution"], {"local-only", "reviewed"}, "redistribution")
        version = item["version"]
        version_tokens = set(re.split(r"[:/@._+-]+", version.casefold())) if isinstance(version, str) else set()
        if (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,127}", version) or
                version_tokens.intersection(FLOATING_VERSIONS)):
            raise Error("artifact version must be an exact non-floating pin")
        compatible = item["compatible_with"]
        roles = item["runtime_roles"]
        if (not isinstance(compatible, list) or len(compatible) > 64 or
                any(not isinstance(i, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", i) for i in compatible) or
                len(compatible) != len(set(compatible))):
            raise Error("invalid artifact compatibility identities")
        if (not isinstance(roles, list) or len(roles) > 64 or
                any(not isinstance(i, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", i) for i in roles) or
                len(roles) != len(set(roles))):
            raise Error("invalid runtime role identities")
        if item["kind"] not in {"client", "image"} and compatible:
            raise Error("only client and image artifacts declare compatibility identities")
        if item["kind"] != "image" and roles:
            raise Error("only image artifacts cover runtime roles")
        if not isinstance(item["license"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+() -]{0,127}", item["license"]):
            raise Error("artifact license reference required")
        if not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise Error("artifact checksum required")
        ops._positive_int(item["size"], "artifact bytes", MAX_ARTIFACT)
        total += item["size"]
        payload = (item["sha256"], item["size"])
        if item["kind"] != "license" and payload in payloads:
            raise Error("duplicate artifact payload identity is ambiguous")
        if item["kind"] != "license":
            payloads[payload] = item["id"]
        image_ids = item["image_ids"]
        if (not isinstance(image_ids, list) or len(image_ids) > 64 or
                any(not isinstance(i, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", i) for i in image_ids) or
                len(set(image_ids)) != len(image_ids)):
            raise Error("invalid immutable image identities")
        if (item["kind"] == "image") != bool(image_ids):
            raise Error("only image archives declare immutable image identities")
        if item["kind"] == "image" and item["architecture"] not in {"linux/amd64", "linux/arm64"}:
            raise Error("image archives require an explicit supported Linux architecture")
        if image_identities.intersection(image_ids):
            raise Error("duplicate immutable image identity is ambiguous")
        image_identities.update(image_ids)
    required = value["required_ids"]
    if (not isinstance(required, list) or any(not isinstance(i, str) for i in required) or
            len(required) != len(set(required)) or not required or set(required) != ids):
        raise Error("required toolchain inventory is incomplete")
    if total > MAX_TOTAL:
        raise Error("toolchain exceeds its total byte budget")

    by_id = {item["id"]: item for item in entries}
    for item in entries:
        if item["id"] in item["compatible_with"] or not set(item["compatible_with"]) <= ids:
            raise Error("artifact compatibility identity is missing or recursive")

    targets = value["targets"]
    if scope == "image-export":
        if targets != [] or any(item["kind"] != "image" or item["compatible_with"] or item["runtime_roles"] for item in entries):
            raise Error("image-export scope may contain only unassigned image archives")
        return value

    for item in entries:
        component = item["component"]
        if component not in REQUIRED_COMPONENT_KINDS or item["kind"] not in REQUIRED_COMPONENT_KINDS[component]:
            raise Error("artifact is outside the maintained component contract")
        if item["kind"] == "core" and item["version"] != value["release_commit"]:
            raise Error("DurkaHelper core version must equal release commit")
        if item["kind"] == "source" and not re.fullmatch(r"[0-9a-f]{40}", item["version"]):
            raise Error("source artifacts require exact commit pins")
        peers = [by_id[identifier] for identifier in item["compatible_with"]]
        if item["kind"] == "image" and component in INTEGRATION_COMPONENTS:
            if (len(peers) != 1 or peers[0]["kind"] != "source" or
                    peers[0]["component"] != component):
                raise Error("integration image provenance must name its exact component source")
        elif item["kind"] == "image" and peers:
            raise Error("dependency images cannot declare unrelated source provenance")
        elif item["kind"] == "client":
            if (len(peers) != 2 or {peer["kind"] for peer in peers} != {"image", "source"} or
                    any(peer["component"] != component for peer in peers)):
                raise Error("client compatibility mismatch")

    if not isinstance(targets, list) or not 1 <= len(targets) <= 16:
        raise Error("complete toolchain requires 1..16 target platforms")
    seen_targets, covered_artifacts = set(), set()
    for target in targets:
        target_fields = {"id", "platform", "container_platforms", "deployment_contract_sha256",
                         "runtime_roles", "artifact_ids"}
        ops._strict_keys(target, target_fields, target_fields, "toolchain target")
        if (not isinstance(target["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", target["id"]) or
                target["id"] in seen_targets):
            raise Error("invalid or duplicate toolchain target identity")
        seen_targets.add(target["id"])
        ops._deployment_enum(target["platform"], NATIVE_PLATFORMS, "target platform")
        if target["deployment_contract_sha256"] != DEPLOYMENT_CONTRACT_SHA256:
            raise Error("target deployment contract digest mismatch")
        container_platforms = target["container_platforms"]
        if (not isinstance(container_platforms, list) or not container_platforms or len(container_platforms) > 2 or
                any(not isinstance(platform, str) or platform not in CONTAINER_PLATFORMS for platform in container_platforms) or
                len(container_platforms) != len(set(container_platforms))):
            raise Error("invalid target container platforms")
        target_ids = target["artifact_ids"]
        if (not isinstance(target_ids, list) or not target_ids or any(not isinstance(i, str) for i in target_ids) or
                len(target_ids) != len(set(target_ids)) or not set(target_ids) <= ids):
            raise Error("target artifact inventory is incomplete or ambiguous")
        covered_artifacts.update(target_ids)
        target_entries = [by_id[identifier] for identifier in target_ids]
        for item in target_entries:
            if not set(item["compatible_with"]) <= set(target_ids):
                raise Error("target omits a required compatibility or provenance edge")
        missing_kinds = ARTIFACT_KINDS - {item["kind"] for item in target_entries}
        if missing_kinds:
            raise Error("target is missing required artifact kind: " + ",".join(sorted(missing_kinds)))

        role_records = target["runtime_roles"]
        if not isinstance(role_records, list) or len(role_records) != len(MAINTAINED_ROLES):
            raise Error("target runtime role inventory is incomplete")
        role_map = {}
        for role in role_records:
            role_fields = {"id", "component", "platform", "image_id"}
            ops._strict_keys(role, role_fields, role_fields, "target runtime role")
            if (not isinstance(role["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", role["id"]) or
                    role["id"] in role_map or not isinstance(role["component"], str) or
                    MAINTAINED_ROLES.get(role["id"]) != role["component"] or
                    not isinstance(role["platform"], str) or role["platform"] not in container_platforms or
                    not isinstance(role["image_id"], str) or
                    not re.fullmatch(r"sha256:[0-9a-f]{64}", role["image_id"])):
                raise Error("invalid or duplicate target runtime role")
            role_map[role["id"]] = role
        if set(role_map) != set(MAINTAINED_ROLES):
            raise Error("target runtime role inventory is incomplete")
        target_container_platform = "linux/" + target["platform"].split("/", 1)[1]
        expected_container_platforms = {target_container_platform, *FIXED_ROLE_PLATFORMS.values()}
        if set(container_platforms) != expected_container_platforms:
            raise Error("target container platforms do not match maintained topology")
        for role_id in TARGET_PLATFORM_ROLES:
            if role_map[role_id]["platform"] != target_container_platform:
                raise Error("runtime role platform does not match maintained topology")
        for role_id, platform in FIXED_ROLE_PLATFORMS.items():
            if role_map[role_id]["platform"] != platform:
                raise Error("runtime role platform does not match maintained topology")
        for group in SHARED_IMAGE_IDENTITY_GROUPS:
            if len({role_map[role_id]["image_id"] for role_id in group}) != 1:
                raise Error("shared runtime roles must use one immutable image identity")

        component_kinds = {}
        covered_roles = {}
        for item in target_entries:
            component_kinds.setdefault(item["component"], set()).add(item["kind"])
            architecture = item["architecture"]
            if item["kind"] == "image":
                if architecture not in container_platforms:
                    raise Error("target architecture mismatch for image artifact")
                if not item["runtime_roles"]:
                    raise Error("complete target image does not cover a runtime role")
                mapped_image_ids = set()
                for role_id in item["runtime_roles"]:
                    role = role_map.get(role_id)
                    if (role is None or ROLE_IMAGE_COMPONENTS.get(role_id) != item["component"] or
                            role["platform"] != architecture or role["image_id"] not in item["image_ids"] or
                            role_id in covered_roles):
                        raise Error("runtime role coverage is missing or ambiguous")
                    covered_roles[role_id] = item["id"]
                    mapped_image_ids.add(role["image_id"])
                if mapped_image_ids != set(item["image_ids"]):
                    raise Error("image identities are not exactly mapped to runtime roles")
            elif item["kind"] in {"client", "installer", "runtime"}:
                if architecture not in {"all", target["platform"]}:
                    raise Error("target architecture mismatch for native artifact")
            elif architecture not in {"all", target["platform"]}:
                raise Error("target architecture mismatch for portable artifact")
        if set(covered_roles) != set(role_map):
            raise Error("runtime role coverage is missing or ambiguous")

        if set(component_kinds) != set(REQUIRED_COMPONENT_KINDS):
            raise Error("target component inventory is incomplete")
        for component, kinds in REQUIRED_COMPONENT_KINDS.items():
            if component_kinds.get(component) != kinds:
                raise Error("target component inventory is incomplete: " + component)
    if covered_artifacts != ids:
        raise Error("complete toolchain contains artifacts not assigned to a target")
    return value


def _manifest_digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _check_release_commit(value, expected_release_commit):
    if expected_release_commit is None:
        return
    if (not isinstance(expected_release_commit, str) or
            not re.fullmatch(r"[0-9a-f]{40}", expected_release_commit)):
        raise Error("expected release commit must be an exact commit ID")
    if value["release_commit"] != expected_release_commit:
        raise Error("toolchain release commit does not match trusted expectation")


def _check_manifest_digest(raw, expected_manifest_sha256, *, required):
    if expected_manifest_sha256 is None:
        if required:
            raise Error("trusted detached expected manifest SHA-256 is required")
        return _manifest_digest(raw)
    if (not isinstance(expected_manifest_sha256, str) or
            not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256)):
        raise Error("invalid expected manifest SHA-256")
    observed = _manifest_digest(raw)
    if observed != expected_manifest_sha256:
        raise Error("manifest does not match trusted detached SHA-256")
    return observed


def _tar_number(field):
    # POSIX octal and non-negative GNU base-256 sizes; never signed/negative.
    if field[:1] == b"\x80":
        return int.from_bytes(field[1:], "big")
    value = field.strip(b"\0 ")
    if not value or any(c not in b"01234567" for c in value):
        raise Error("invalid image tar numeric field")
    return int(value, 8)


def _pax_fields(data):
    """Only bounded, framing-safe local PAX overrides are supported."""
    result, offset = {}, 0
    allowed = {"path", "size", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname", "comment"}
    while offset < len(data):
        space = data.find(b" ", offset, offset + 16)
        length_text = data[offset:space] if space != -1 else b""
        if not length_text.isdigit() or length_text.startswith(b"0"):
            raise Error("invalid image PAX record")
        length = int(length_text)
        end = offset + length
        if end > len(data) or end <= space + 2 or data[end - 1:end] != b"\n":
            raise Error("invalid image PAX record")
        record = data[space + 1:end - 1]
        if b"=" not in record or b"\0" in record:
            raise Error("invalid image PAX record")
        try:
            key, value = record.decode("utf-8", "strict").split("=", 1)
        except UnicodeError as exc:
            raise Error("invalid image PAX encoding") from exc
        if key not in allowed or key in result:
            raise Error("unsupported or duplicate image PAX field")
        if key in {"path", "uname", "gname"} and (not value or len(value.encode("utf-8")) > 4096):
            raise Error("image PAX text exceeds bounds")
        if key in {"size", "uid", "gid"} and (not re.fullmatch(r"[0-9]{1,12}", value) or int(value) > MAX_ARTIFACT):
            raise Error("invalid image PAX numeric field")
        if key in {"mtime", "atime", "ctime"} and not re.fullmatch(r"-?[0-9]{1,16}(?:\.[0-9]{1,9})?", value):
            raise Error("invalid image PAX timestamp")
        result[key] = value
        offset = end
    return result


def _preflight_image_tar(stream):
    """Bound raw extension records before tarfile can allocate their payloads.

    Scan headers without extracting or buffering layer data. One local PAX or
    GNU long-name record may precede a regular/directory member. Global PAX,
    chained extensions, sparse files, links and devices are not image exports.
    """
    stream.seek(0, os.SEEK_END)
    archive_size = stream.tell()
    if not 1024 <= archive_size <= MAX_ARTIFACT or archive_size % 512:
        raise Error("image tar size exceeds bounds or framing is truncated")
    stream.seek(0)
    headers, metadata_bytes, pending = 0, 0, None
    zero = b"\0" * 512
    while True:
        header = stream.read(512)
        if len(header) != 512:
            raise Error("image tar end marker is missing")
        if header == zero:
            if pending is not None or stream.read(512) != zero:
                raise Error("invalid image tar end marker")
            # Go emits exactly two zero records; Python also pads to 10 KiB.
            # Permit either, but no hidden concatenated archive or huge trailer.
            if archive_size - stream.tell() > tarfile.RECORDSIZE:
                raise Error("image tar trailing padding exceeds bounds")
            if stream.read(tarfile.RECORDSIZE).strip(b"\0"):
                raise Error("image tar contains trailing data")
            stream.seek(0)
            return
        headers += 1
        if headers > 40000:
            raise Error("image tar raw header limit exceeded")
        recorded = _tar_number(header[148:156])
        if recorded != sum(header[:148]) + 8 * ord(" ") + sum(header[156:]):
            raise Error("invalid image tar header checksum")
        size, kind = _tar_number(header[124:136]), header[156:157]
        if kind in {tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME}:
            bound = MAX_PAX_BYTES if kind == tarfile.XHDTYPE else 4096
            metadata_bytes += size
            if pending is not None or not 0 < size <= bound or metadata_bytes > MAX_TAR_METADATA:
                raise Error("image tar extended metadata exceeds bounds")
            payload = stream.read(size)
            if len(payload) != size:
                raise Error("truncated image tar metadata")
            if kind == tarfile.XHDTYPE:
                pending = _pax_fields(payload)
            else:
                if not payload.endswith(b"\0") or b"\0" in payload[:-1]:
                    raise Error("invalid image tar long name")
                pending = {}
        elif kind in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            if pending is not None and "size" in pending:
                size = int(pending["size"])
            pending = None
            if size > MAX_ARTIFACT or (kind == tarfile.DIRTYPE and size):
                raise Error("invalid image tar member size")
            if stream.tell() + size > archive_size:
                raise Error("truncated image tar member")
            stream.seek(size, os.SEEK_CUR)
        else:
            raise Error("unsupported image tar entry type")
        padding = (-size) % 512
        data = stream.read(padding)
        if len(data) != padding or data.strip(b"\0"):
            raise Error("invalid image tar padding")


def inspect_image_archive(path, expected_ids, *, fileobj=None, architecture=None):
    """Verify tag-free legacy saves and Docker's OCI-backed image identities.

    A Docker 29 image ID can be a manifest-list digest, not a config digest.
    Missing *other-platform* branches of that list are normal in a platform-
    specific export. Every included image must still have a complete, hashed
    chain to its config and layers and match the declared platform.
    """
    if fileobj is None:
        # Use the same descriptor for raw preflight and structured inspection.
        with open(path, "rb") as stream:
            return inspect_image_archive(None, expected_ids, fileobj=stream, architecture=architecture)
    _preflight_image_tar(fileobj)
    members, hashes, total = {}, {}, 0
    with tarfile.open(None, "r:", fileobj=fileobj) as archive:
        for member in archive:
            normalized = PurePosixPath(member.name)
            if (normalized.is_absolute() or ".." in normalized.parts or "\\" in member.name or
                    normalized.as_posix() != member.name.rstrip("/") or
                    normalized.as_posix() in members or not (member.isfile() or member.isdir()) or member.issparse()):
                raise Error("unsafe image archive member")
            members[normalized.as_posix()] = member
            total += member.size
            if len(members) > 20000 or total > MAX_ARTIFACT:
                raise Error("image archive exceeds inspection bounds")
            if member.isfile():
                digest = hashlib.sha256()
                with archive.extractfile(member) as stream:
                    for part in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(part)
                hashes[member.name] = digest.hexdigest()
                if member.name.startswith("blobs/") and member.name != "blobs/sha256/" + digest.hexdigest():
                    raise Error("OCI blob digest mismatch or unsupported digest algorithm")

        def read_json(name):
            entry = members.get(name)
            if entry is None or not entry.isfile() or entry.size > 1024 * 1024:
                raise Error("image JSON missing or exceeds bounds")
            raw = archive.extractfile(entry).read()
            depth, quoted, escaped = 0, False, False
            for byte in raw:
                if quoted:
                    if escaped:
                        escaped = False
                    elif byte == 92:
                        escaped = True
                    elif byte == 34:
                        quoted = False
                elif byte == 34:
                    quoted = True
                elif byte in (91, 123):
                    depth += 1
                    if depth > 64:
                        raise Error("excessively nested image JSON")
                elif byte in (93, 125):
                    depth -= 1
            try:
                return json.loads(raw, object_pairs_hook=ops._unique_object,
                                  parse_constant=ops._reject_constant)
            except (ValueError, RecursionError) as exc:
                raise Error("invalid or excessively nested image JSON") from exc

        def no_names(value):
            if not isinstance(value, dict) or not isinstance(value.get("annotations", {}), dict):
                raise Error("invalid image descriptor")
            if {"org.opencontainers.image.ref.name", "io.containerd.image.name"} & value.get("annotations", {}).keys():
                raise Error("image archive contains named image references")
            if value.get("urls") not in (None, []):
                raise Error("image archive contains registry URL metadata")
            if any(str(key).startswith("containerd.io/distribution.source.")
                   for key in value.get("annotations", {})):
                raise Error("image archive contains registry URL metadata")

        def descriptor(value, missing=False):
            no_names(value)
            digest = value.get("digest")
            if (not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or
                    type(value.get("size")) is not int or not 0 <= value["size"] <= MAX_ARTIFACT):
                raise Error("invalid OCI content descriptor")
            name = "blobs/sha256/" + digest[7:]
            if name not in hashes:
                if missing:
                    return None
                raise Error("incomplete OCI content chain")
            if members[name].size != value["size"]:
                raise Error("OCI descriptor size mismatch")
            return name

        expanded, layer_hashes = [0], {}

        def layer_identity(name):
            if name in layer_hashes:
                return layer_hashes[name]
            with archive.extractfile(members[name]) as stream:
                prefix = stream.read(4)
                stream.seek(0)
                if prefix[:2] == b"\x1f\x8b":
                    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    digest, size = hashlib.sha256(), 0
                    try:
                        while True:
                            part = stream.read(CHUNK)
                            if not part:
                                if not decompressor.eof:
                                    raise Error("truncated compressed image layer")
                                break
                            while part:
                                remaining = min(MAX_LAYER_EXPANDED - size, MAX_ARTIFACT - expanded[0])
                                output = decompressor.decompress(part, min(CHUNK, remaining + 1))
                                size += len(output)
                                expanded[0] += len(output)
                                if size > MAX_LAYER_EXPANDED or expanded[0] > MAX_ARTIFACT:
                                    raise Error("expanded image layers exceed bounds")
                                digest.update(output)
                                part = decompressor.unconsumed_tail
                                if decompressor.eof:
                                    if decompressor.unused_data or stream.read(1):
                                        raise Error("compressed image layer has trailing or concatenated data")
                                    break
                            if decompressor.eof:
                                break
                    except zlib.error as exc:
                        raise Error("invalid compressed image layer") from exc
                    result = digest.hexdigest()
                else:
                    # Do not silently hash compressed bytes as a DiffID. Gzip
                    # is the bounded stdlib-supported image-layer codec.
                    if (prefix in {b"\x28\xb5\x2f\xfd", b"\xfd7zX", b"\x04\x22\x4d\x18"} or
                            prefix[:3] == b"BZh" or
                            len(prefix) == 4 and prefix[1:] == b"\x2a\x4d\x18" and 0x50 <= prefix[0] <= 0x5f):
                        raise Error("unsupported compression for config-based image layer identity")
                    size = members[name].size
                    expanded[0] += size
                    if size > MAX_LAYER_EXPANDED or expanded[0] > MAX_ARTIFACT:
                        raise Error("expanded image layers exceed bounds")
                    result = hashes[name]
            layer_hashes[name] = "sha256:" + result
            return layer_hashes[name]

        def bind_config_layers():
            for name, layers in rows:
                rootfs = configs[name].get("rootfs")
                if (not isinstance(rootfs, dict) or rootfs.get("type") != "layers" or
                        not isinstance(rootfs.get("diff_ids"), list) or len(rootfs["diff_ids"]) != len(layers) or
                        any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                            for value in rootfs["diff_ids"])):
                    raise Error("invalid image config layer identity contract")
                for layer, identity in zip(layers, rootfs["diff_ids"]):
                    if layer_identity(layer) != identity:
                        raise Error("image layer bytes do not match config identity")

        if "repositories" in members and read_json("repositories") not in ({}, None):
            raise Error("image archive contains repository tag assignments")
        manifests = read_json("manifest.json")
        if not isinstance(manifests, list) or not 1 <= len(manifests) <= 64:
            raise Error("docker-save image manifest missing")
        found, rows, configs = set(), set(), {}
        for row in manifests:
            if (not isinstance(row, dict) or set(row) - {"Config", "RepoTags", "Layers", "LayerSources"} or
                    not {"Config", "Layers"} <= set(row) or row.get("RepoTags") not in (None, []) or
                    row.get("LayerSources") not in (None, {}) or
                    not isinstance(row["Config"], str) or row["Config"] not in hashes or
                    not isinstance(row["Layers"], list) or len(row["Layers"]) > 1024 or
                    any(not isinstance(layer, str) or layer not in hashes for layer in row["Layers"])):
                raise Error("image archive must be tag-free and structurally complete")
            config = read_json(row["Config"])
            if not isinstance(config, dict) or (architecture and architecture != str(config.get("os")) + "/" + str(config.get("architecture"))):
                raise Error("image configuration architecture mismatch")
            key = (row["Config"], tuple(row["Layers"]))
            if key in rows:
                raise Error("duplicate image manifest row")
            rows.add(key)
            configs[row["Config"]] = config
            found.add("sha256:" + hashes[row["Config"]])
        if "index.json" not in members:
            if found != set(expected_ids):
                raise Error("image archive identities do not match manifest")
            bind_config_layers()
            return

        index = read_json("index.json")
        no_names(index)
        if (index.get("schemaVersion") != 2 or not isinstance(index.get("manifests"), list) or
                not 1 <= len(index["manifests"]) <= 64):
            raise Error("invalid OCI root index")
        roots, reachable, visits = set(), set(), [0]
        image_manifests, attestation_targets = set(), set()
        selected_platforms = {architecture} if architecture else {
            str(value.get("os")) + "/" + str(value.get("architecture")) for value in configs.values()}

        def platform_claim(item):
            value = item.get("platform")
            if (not isinstance(value, dict) or not isinstance(value.get("os"), str) or
                    not isinstance(value.get("architecture"), str) or not value["os"] or not value["architecture"]):
                raise Error("invalid or unknown OCI platform claim")
            return value["os"] + "/" + value["architecture"]

        def walk(item, depth=0):
            visits[0] += 1
            if depth > 8 or visits[0] > 4096:
                raise Error("OCI content graph exceeds bounds")
            name = descriptor(item)
            metadata = read_json(name)
            no_names(metadata)
            if metadata.get("schemaVersion") != 2:
                raise Error("unsupported OCI manifest version")
            if "manifests" in metadata:
                children = metadata["manifests"]
                if not isinstance(children, list) or not 1 <= len(children) <= 1024:
                    raise Error("invalid OCI manifest list")
                available = [(child, descriptor(child, missing=True)) for child in children]
                missing_other_platforms = {
                    child["digest"] for child, child_name in available
                    if child_name is None and
                    child.get("annotations", {}).get("vnd.docker.reference.type") != "attestation-manifest" and
                    platform_claim(child) not in selected_platforms | {"unknown/unknown"}}
                leaves = set()
                for child, child_name in available:
                    if child_name is not None:
                        leaves.update(walk(child, depth + 1))
                    elif child.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                        # Docker omits both a nonlocal image and its BuildKit
                        # attachment. The pinned parent must bind the missing
                        # proof to that exact absent non-selected sibling.
                        target = child["annotations"].get("vnd.docker.reference.digest")
                        if (child.get("platform") != {"os": "unknown", "architecture": "unknown"} or
                                not isinstance(target, str) or target not in missing_other_platforms):
                            raise Error("selected OCI platform or provenance content is missing")
                    elif platform_claim(child) in selected_platforms | {"unknown/unknown"}:
                        raise Error("selected OCI platform or provenance content is missing")
                if not leaves:
                    raise Error("OCI manifest list contains no complete platform")
                if "platform" in item and any(
                        platform_claim(item) != str(configs[config].get("os")) + "/" + str(configs[config].get("architecture"))
                        for config, _ in leaves):
                    raise Error("OCI index platform disagrees with image configuration")
                return leaves
            config = descriptor(metadata.get("config"))
            layers = metadata.get("layers")
            if not isinstance(layers, list) or len(layers) > 1024:
                raise Error("invalid OCI layers")
            key = (config, tuple(descriptor(layer) for layer in layers))
            annotations = item.get("annotations", {})
            if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
                # BuildKit provenance is carried along with an image, but is
                # not itself runnable and has no legacy manifest.json row.
                # Preserve and verify its bytes; never count it as a platform.
                target = annotations.get("vnd.docker.reference.digest")
                attestation_config = read_json(config)
                if (not isinstance(target, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", target) or
                        item.get("platform") != {"os": "unknown", "architecture": "unknown"} or
                        not isinstance(attestation_config, dict) or attestation_config.get("os") != "unknown" or
                        attestation_config.get("architecture") != "unknown" or not 1 <= len(layers) <= 16 or
                        any(layer.get("mediaType") != "application/vnd.in-toto+json" for layer in layers) or key in rows):
                    raise Error("invalid OCI provenance attachment")
                attestation_targets.add(target)
                return set()
            if key not in rows:
                raise Error("OCI and docker-save image records disagree")
            if "platform" in item and platform_claim(item) != str(configs[config].get("os")) + "/" + str(configs[config].get("architecture")):
                raise Error("OCI descriptor platform disagrees with image configuration")
            image_manifests.add(item["digest"])
            return {key}

        for item in index["manifests"]:
            no_names(item)
            descriptor(item)
            identity = item["digest"]
            if identity in roots:
                raise Error("duplicate OCI root image")
            roots.add(identity)
            reachable.update(walk(item))
        if (reachable != rows or not attestation_targets <= image_manifests or
                (roots != set(expected_ids) and found != set(expected_ids))):
            raise Error("image archive identities do not match manifest")
        # A pinned root authenticates the compressed OCI blobs, but runnable
        # filesystem identity is the config's uncompressed DiffID chain.  Both
        # bindings are mandatory regardless of which accepted image ID the
        # detached inventory pins.
        bind_config_layers()


def export_profile(value, *, expected_release_commit=None):
    fields = {"schema", "release_commit", "images", "max_archive_bytes", "max_total_bytes", "timeout_seconds"}
    ops._strict_keys(value, fields, fields, "image export profile")
    if value["schema"] != EXPORT_SCHEMA:
        raise Error("invalid image export schema")
    if not isinstance(value["release_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["release_commit"]):
        raise Error("invalid image export release commit")
    _check_release_commit(value, expected_release_commit)
    ops._positive_int(value["max_archive_bytes"], "export archive limit", MAX_ARTIFACT)
    ops._positive_int(value["max_total_bytes"], "export total limit", MAX_TOTAL)
    ops._positive_int(value["timeout_seconds"], "export timeout", 1800)
    if value["max_archive_bytes"] > value["max_total_bytes"]:
        raise Error("per-archive limit cannot exceed the total export limit")
    if not isinstance(value["images"], list) or not 1 <= len(value["images"]) <= 64:
        raise Error("export requires 1..64 explicit image identities")
    artifacts, seen = [], set()
    for item in value["images"]:
        fields = {"id", "component", "architecture", "image_id", "license", "redistribution", "reviewed_for_secrets"}
        ops._strict_keys(item, fields, fields, "export image")
        if item["reviewed_for_secrets"] is not True or item["redistribution"] != "local-only":
            raise Error("image exports require explicit secret review and remain local-only")
        if not isinstance(item["architecture"], str) or item["architecture"] not in {"linux/amd64", "linux/arm64"}:
            raise Error("export supports Linux amd64/arm64 image configurations only")
        if (not isinstance(item["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", item["id"]) or
                not isinstance(item["image_id"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["image_id"])):
            raise Error("export requires safe artifact labels and exact local image IDs")
        if item["image_id"] in seen:
            raise Error("duplicate image ID; label each unique image once")
        seen.add(item["image_id"])
        artifacts.append({"id": item["id"], "path": "images/" + item["id"] + ".tar", "kind": "image",
                          "component": item["component"], "architecture": item["architecture"],
                          "version": item["image_id"], "compatible_with": [], "runtime_roles": [],
                          "sha256": item["image_id"][7:],
                          "size": 1, "license": item["license"], "redistribution": "local-only", "image_ids": [item["image_id"]]})
    # Reuse the inventory's strict portable IDs, paths, checksums and metadata
    # contract. Placeholder checksum/size are validation-only, never published.
    # Derive distinct placeholders from the already-unique image identities so
    # the real manifest's duplicate-payload gate remains enabled for all inputs.
    manifest({"schema": SCHEMA, "release_commit": value["release_commit"], "scope": "image-export", "targets": [],
              "required_ids": [item["id"] for item in artifacts], "artifacts": artifacts}, expected_scope="image-export")
    return value


def bounded_docker_metadata(arguments):
    """Only fixed internal callers supply arguments; bound output before buffering."""
    data, errors = bytearray(), []
    process = subprocess.Popen(["docker"] + arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def drain():
        try:
            while True:
                part = process.stdout.read(4096)
                if not part:
                    break
                if len(data) + len(part) > 65536:
                    raise Error("Docker metadata exceeded its byte limit")
                data.extend(part)
        except (OSError, Error) as error:
            errors.append(error)
            process.kill()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=20)
        reader.join(timeout=5)
        if code or errors or reader.is_alive():
            raise Error("Docker metadata unavailable or exceeded limits")
        return bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        reader.join(timeout=5)
        process.stdout.close()


def approved_daemon(identity):
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", identity):
        raise Error("export requires the explicitly approved Docker daemon identity")
    if bounded_docker_metadata(["info", "--format", "{{.ID}}"]).decode().strip() != identity:
        raise Error("Docker daemon identity mismatch")


def approved_image(item):
    result = bounded_docker_metadata(["image", "inspect", "--format", "{{.Id}};{{.Os}}/{{.Architecture}}", item["image_id"]]).decode().strip()
    if result != item["image_id"] + ";" + item["architecture"]:
        raise Error("approved image identity or architecture mismatch")


def _save_image_stream(staging, relative, identity, limit, timeout):
    """Capture untrusted docker-save bytes into an unpublished private inode."""
    descriptor = staging.open_new_file(relative)
    process, reader = None, None
    result, errors = {"bytes": 0}, []
    digest = hashlib.sha256()
    try:
        process = subprocess.Popen(["docker", "image", "save", identity], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        def drain():
            try:
                while True:
                    part = process.stdout.read(1024 * 1024)
                    if not part:
                        break
                    if result["bytes"] + len(part) > limit:
                        raise Error("image export exceeded its byte budget")
                    ops._write_all(descriptor, part)
                    digest.update(part)
                    result["bytes"] += len(part)
            except (OSError, Error) as error:
                errors.append(error)
                process.kill()

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        code = process.wait(timeout=timeout)
        reader.join(timeout=5)
        if code or errors or reader.is_alive() or not result["bytes"]:
            raise Error("image export failed or exceeded bounds; no complete bundle published")
        os.fsync(descriptor)
        staging._finalize_file_record(relative, descriptor)
        result["sha256"] = digest.hexdigest()
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if reader is not None:
                reader.join(timeout=5)
            process.stdout.close()
        # Finalize even a partial inode once its writer has stopped, allowing
        # descriptor-anchored cleanup of only our own unpublished staging data.
        if reader is None or not reader.is_alive():
            try:
                staging._finalize_file_record(relative, descriptor)
            except (Error, OSError):
                pass
        os.close(descriptor)
    return result


def save_image(staging, relative, identity, limit, timeout, architecture=None):
    """Normalize only root registry provenance, then strictly verify the export.

    Raw Docker output lives in a separately anchored, never-published child
    staging directory. Failure to clean that child prevents the outer staging
    ledger from publishing; raw bytes cannot accidentally become bundle files.
    """
    staging._assert_named_identity()
    raw_staging = ops._StagingDirectory.create(staging.path / "raw-image", ".docker-save-")
    try:
        if raw_staging.parent_identity != staging.identity:
            raise Error("export staging changed before raw capture")
        raw = _save_image_stream(raw_staging, "image.tar", identity, limit, timeout)
        raw_fd = ops._open_anchored_regular(raw_staging.path, "image.tar", raw_staging.identity)
        destination = None
        try:
            with os.fdopen(raw_fd, "rb", closefd=False) as stream:
                before = os.fstat(raw_fd)
                if before.st_size != raw["bytes"] or before.st_mode & 0o077 or before.st_uid != os.getuid():
                    raise Error("raw export inode ownership, permissions or size changed")
                destination = staging.open_new_file(relative)
                result = _rewrite_export_archive(stream, destination, limit=limit)
                if _rehash_original_export(stream, before) != raw["sha256"]:
                    raise Error("raw export archive changed during normalization")
        finally:
            os.close(raw_fd)
            if destination is not None:
                try:
                    staging._finalize_file_record(relative, destination)
                finally:
                    os.close(destination)
    finally:
        raw_staging.cleanup()
    # The normalizer is not a verifier. Names, URLs, addressed registry metadata,
    # identities, layers and architecture must still pass the unchanged checks.
    staged_fd = ops._open_anchored_regular(staging.path, relative, staging.identity)
    try:
        with os.fdopen(staged_fd, "rb", closefd=False) as stream:
            before = os.fstat(staged_fd)
            if before.st_size != result["bytes"] or before.st_mode & 0o077 or before.st_uid != os.getuid():
                raise Error("export inode ownership, permissions or size changed")
            inspect_image_archive(None, [identity], fileobj=stream, architecture=architecture)
            if _rehash_original_export(stream, before) != result["sha256"]:
                raise Error("export archive changed during inspection")
    finally:
        os.close(staged_fd)
    return result


def export_images(args):
    value, _ = ops._read_json(args.export_profile, ops.MAX_PROFILE_BYTES)
    export_profile(value, expected_release_commit=getattr(args, "expected_release_commit", None))
    target = ops._safe_output_parent(Path(args.output))
    if not args.apply:
        return {"status": "NOT_RUN", "action": "export-images", "images": len(value["images"]),
                "effects": "read approved daemon/images and publish a new private tag-free image bundle", "daemon_checked": False,
                "redistribution": "local-only", "scope": "image-export", "complete_target": False,
                "manifest_sha256": None, "offline_runtime": "NOT_RUN"}
    if os.name != "posix":
        raise Error("secure image export requires POSIX descriptor-anchored staging")
    approved_daemon(args.daemon_id)
    for item in value["images"]:
        approved_image(item)
    staging = ops._StagingDirectory.create(target, ".image-export-")
    total, removed_annotations, entries = 0, 0, []
    try:
        for item in value["images"]:
            approved_daemon(args.daemon_id)
            approved_image(item)
            remaining = value["max_total_bytes"] - total
            if remaining <= 0:
                raise Error("image export exhausted the total byte budget")
            relative = "images/" + item["id"] + ".tar"
            info = save_image(staging, relative, item["image_id"], min(value["max_archive_bytes"], remaining), value["timeout_seconds"], item["architecture"])
            total += info["bytes"]
            removed_annotations += info["removed_annotations"]
            approved_daemon(args.daemon_id)
            approved_image(item)
            entries.append({"id": item["id"], "path": relative, "kind": "image", "component": item["component"],
                            "architecture": item["architecture"], "version": item["image_id"],
                            "compatible_with": [], "runtime_roles": [], "sha256": info["sha256"], "size": info["bytes"],
                            "license": item["license"], "redistribution": "local-only", "image_ids": [item["image_id"]]})
        result = manifest({"schema": SCHEMA, "release_commit": value["release_commit"],
                           "scope": "image-export", "targets": [],
                           "required_ids": [item["id"] for item in entries], "artifacts": entries},
                          expected_scope="image-export")
        manifest_bytes = ops._canonical(result)
        staging.write_new_bytes("manifest.json", manifest_bytes)
        ops._publish_directory(staging, target)
    finally:
        staging.cleanup()
    return {"status": "PASS", "action": "export-images", "images": len(entries), "total_bytes": total,
            "scope": "image-export", "complete_target": False,
            "removed_annotation_count": removed_annotations, "strict_output_verification": "PASS",
            "manifest_sha256": _manifest_digest(manifest_bytes),
            "redistribution": "local-only", "containers_started": 0, "offline_runtime": "NOT_RUN",
            "rollback": "Docker daemon unchanged; remove only the exact new private export directory after retention review"}


def check_files(root, value):
    root = ops._canonical_root_directory(Path(root))
    identity = ops._root_anchor_identity(root.lstat())
    for item in value["artifacts"]:
        before, checksum = ops._hash_anchored_regular(root, item["path"], identity, MAX_ARTIFACT)
        if before.st_size != item["size"] or checksum != item["sha256"]:
            raise Error("toolchain artifact checksum/size mismatch")
        if item["kind"] == "image":
            descriptor = ops._open_anchored_regular(root, item["path"], identity)
            try:
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    if ops._stat_identity(os.fstat(descriptor)) != ops._stat_identity(before):
                        raise Error("image archive changed before inspection")
                    inspect_image_archive(None, item["image_ids"], fileobj=stream, architecture=item["architecture"])
                    if ops._stat_identity(os.fstat(descriptor)) != ops._stat_identity(before):
                        raise Error("image archive changed during inspection")
            finally:
                os.close(descriptor)
            after, repeated = ops._hash_anchored_regular(root, item["path"], identity, MAX_ARTIFACT)
            if ops._stat_identity(before) != ops._stat_identity(after) or repeated != checksum:
                raise Error("image archive changed during inspection")
    return root, identity


def _normalized_export_index(raw):
    """Remove only non-addressed Docker registry-source annotations.

    Root names and URLs still fail closed. Never traverse or rewrite a blob:
    changing a content-addressed OCI descriptor would change its image ID.
    """
    if len(raw) > 1024 * 1024:
        raise Error("export root index exceeds bounds")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise Error("export root index nesting exceeds bounds")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(raw, object_pairs_hook=ops._unique_object, parse_constant=ops._reject_constant)
    except (ValueError, RecursionError) as exc:
        raise Error("invalid export root index") from exc
    if (not isinstance(value, dict) or value.get("schemaVersion") != 2 or
            not isinstance(value.get("manifests"), list) or not 1 <= len(value["manifests"]) <= 64):
        raise Error("invalid export root index")
    removed = 0
    for descriptor in [value, *value["manifests"]]:
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("annotations", {}), dict):
            raise Error("invalid root image descriptor")
        annotations = descriptor.get("annotations", {})
        if {"org.opencontainers.image.ref.name", "io.containerd.image.name"} & annotations.keys():
            raise Error("named image references cannot be normalized")
        if descriptor.get("urls") not in (None, []):
            raise Error("image URL metadata cannot be normalized")
        for key in list(annotations):
            if key.startswith("containerd.io/distribution.source."):
                if not isinstance(annotations[key], str):
                    raise Error("invalid registry-source annotation")
                del annotations[key]
                removed += 1
    # Preserve the exact original bytes when no supported migration is needed.
    return (ops._canonical(value) if removed else raw), removed


def _export_migration_members(stream):
    """Preflight framing before parsing; retain bounded metadata, never layers."""
    _preflight_image_tar(stream)
    seen, members, total, replacement, removed = set(), [], 0, None, 0
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for member in archive:
            normalized = PurePosixPath(member.name)
            if (normalized.is_absolute() or ".." in normalized.parts or "\\" in member.name or
                    normalized.as_posix() != member.name.rstrip("/") or normalized.as_posix() in seen or
                    not (member.isfile() or member.isdir()) or member.issparse()):
                raise Error("unsafe export archive member")
            seen.add(normalized.as_posix())
            members.append(member)
            total += member.size
            if len(members) > 20000 or total > MAX_ARTIFACT:
                raise Error("export migration exceeds inspection bounds")
            if normalized.as_posix() == "index.json":
                if not member.isfile() or member.size > 1024 * 1024:
                    raise Error("export root index exceeds bounds")
                with archive.extractfile(member) as payload:
                    replacement, removed = _normalized_export_index(payload.read())
    return members, replacement, removed


def _rewrite_export_archive(source, destination, *, limit=MAX_ARTIFACT):
    """Stream a new archive; the caller must run unchanged strict verification."""
    members, replacement, removed = _export_migration_members(source)
    digest, count = hashlib.sha256(), 0

    class Writer:
        def write(self, payload):
            nonlocal count
            if count + len(payload) > limit:
                raise Error("normalized export exceeds byte budget")
            ops._write_all(destination, payload)
            digest.update(payload)
            count += len(payload)
            return len(payload)

    writer = Writer()
    if not removed:
        source.seek(0)
        for block in iter(lambda: source.read(CHUNK), b""):
            writer.write(block)
    else:
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:") as incoming, tarfile.open(
                fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as outgoing:
            for member in members:
                changed = copy.copy(member)
                # A changed index size must not retain a stale PAX size field.
                changed.pax_headers = dict(member.pax_headers)
                if member.name == "index.json":
                    changed.size = len(replacement)
                    changed.pax_headers.pop("size", None)
                    outgoing.addfile(changed, io.BytesIO(replacement))
                elif member.isfile():
                    with incoming.extractfile(member) as payload:
                        outgoing.addfile(changed, payload)
                else:
                    outgoing.addfile(changed)
    os.fsync(destination)
    return {"bytes": count, "sha256": digest.hexdigest(), "removed_annotations": removed}


def _rehash_original_export(stream, before):
    """Recheck the same descriptor with the original size as a hard budget."""
    stream.seek(0)
    repeated, consumed = hashlib.sha256(), 0
    bound = min(before.st_size, MAX_ARTIFACT)
    while True:
        block = stream.read(min(CHUNK, bound - consumed + 1))
        if not block:
            break
        consumed += len(block)
        if consumed > bound:
            raise Error("original export grew during post-migration verification")
        repeated.update(block)
    if consumed != before.st_size or ops._stat_identity(os.fstat(stream.fileno())) != ops._stat_identity(before):
        raise Error("original export changed during post-migration verification")
    return repeated.hexdigest()


def _normalization_manifest(value):
    """Permit only a complete image-only v1 inventory to become image-export.

    This narrow migration never upgrades a legacy inventory to complete-target,
    infers runtime roles, or treats an optional legacy artifact as required.
    """
    manifest(value)
    if value["schema"] == LEGACY_SCHEMA:
        entries = value["artifacts"]
        if (any(item["kind"] != "image" or len(item["image_ids"]) != 1 for item in entries) or
                set(value["required_ids"]) != {item["id"] for item in entries}):
            raise Error("legacy normalization requires an exact required image-only inventory with one ID per archive")
        value = {"schema": SCHEMA, "release_commit": value["release_commit"], "scope": "image-export", "targets": [],
                 "required_ids": list(value["required_ids"]),
                 "artifacts": [dict(item, version=item["image_ids"][0], compatible_with=[], runtime_roles=[])
                               for item in entries]}
    return manifest(value, expected_scope="image-export")


def normalize_images(args):
    """Migrate authenticated historical exports into a NEW private bundle."""
    root = ops._canonical_root_directory(Path(args.root))
    value, raw = ops._read_json(root / "manifest.json", ops.MAX_PROFILE_BYTES)
    source_manifest_sha256 = _check_manifest_digest(raw, getattr(args, "expected_manifest_sha256", None), required=True)
    source_schema = value.get("schema") if isinstance(value, dict) else None
    value = _normalization_manifest(value)
    _check_release_commit(value, getattr(args, "expected_release_commit", None))
    target = ops._safe_output_parent(Path(args.output))
    if target == root or root in target.parents or target in root.parents:
        raise Error("original export and normalized output must be disjoint")
    anchor = ops._root_anchor_identity(root.stat())
    plans = []
    for item in value["artifacts"]:
        before, digest = ops._hash_anchored_regular(root, item["path"], anchor, MAX_ARTIFACT)
        if before.st_size != item["size"] or digest != item["sha256"]:
            raise Error("original export checksum or size differs from trusted manifest")
        descriptor = ops._open_anchored_regular(root, item["path"], anchor)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                if ops._stat_identity(os.fstat(descriptor)) != ops._stat_identity(before):
                    raise Error("original export changed before migration preview")
                _, _, removed = _export_migration_members(stream)
                if ops._stat_identity(os.fstat(descriptor)) != ops._stat_identity(before):
                    raise Error("original export changed during migration preview")
        finally:
            os.close(descriptor)
        plans.append((item, before, removed))
    removed = sum(entry[2] for entry in plans)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "normalize-images", "scope": "image-export", "complete_target": False,
                "source_manifest_sha256": source_manifest_sha256, "source_schema": source_schema, "archives": len(plans),
                "removed_annotation_count": removed, "strict_output_verification": "NOT_RUN",
                "effects": "new private bundle; only top-level registry-source annotations removed; no Docker contact"}
    if os.name != "posix":
        raise Error("secure export migration requires POSIX staging")
    staging = ops._StagingDirectory.create(target, ".normalized-export-")
    entries, total = [], 0
    try:
        for item, before, expected_removed in plans:
            source_fd = ops._open_anchored_regular(root, item["path"], anchor)
            destination = None
            try:
                destination = staging.open_new_file(item["path"])
                with os.fdopen(source_fd, "rb", closefd=False) as stream:
                    if ops._stat_identity(os.fstat(source_fd)) != ops._stat_identity(before):
                        raise Error("original export changed before migration")
                    info = _rewrite_export_archive(stream, destination, limit=min(MAX_ARTIFACT, MAX_TOTAL - total))
                    if (info["removed_annotations"] != expected_removed or
                            ops._stat_identity(os.fstat(source_fd)) != ops._stat_identity(before)):
                        raise Error("original export changed during migration")
                    if _rehash_original_export(stream, before) != item["sha256"]:
                        raise Error("original export changed after migration")
                staging._finalize_file_record(item["path"], destination)
            finally:
                os.close(source_fd)
                if destination is not None:
                    try:
                        staging._finalize_file_record(item["path"], destination)
                    finally:
                        os.close(destination)
            changed = dict(item, size=info["bytes"], sha256=info["sha256"])
            # The normalizer has no permissive validation mode. Any named refs,
            # URLs, nested registry annotations or altered blobs still fail here.
            check_files(staging.path, {"artifacts": [changed]})
            entries.append(changed)
            total += info["bytes"]
        updated = manifest(dict(value, artifacts=entries), expected_scope="image-export")
        encoded = ops._canonical(updated)
        staging.write_new_bytes("manifest.json", encoded)
        _, repeated_raw = ops._read_json(root / "manifest.json", ops.MAX_PROFILE_BYTES)
        if repeated_raw != raw:
            raise Error("original export manifest changed during migration")
        ops._publish_directory(staging, target)
    finally:
        staging.cleanup()
    return {"status": "PASS", "action": "normalize-images", "scope": "image-export", "complete_target": False,
            "source_manifest_sha256": source_manifest_sha256, "source_schema": source_schema, "manifest_sha256": _manifest_digest(encoded),
            "archives": len(entries), "removed_annotation_count": removed, "strict_output_verification": "PASS",
            "original_export_changed": False, "image_ids_changed": False, "offline_runtime": "NOT_RUN",
            "rollback": "original export retained; remove only exact new private output after review"}


def assemble(args):
    value, raw_manifest = ops._read_json(args.manifest, ops.MAX_PROFILE_BYTES)
    value = manifest(value, expected_scope="complete-target")
    _check_manifest_digest(raw_manifest, getattr(args, "expected_manifest_sha256", None), required=True)
    _check_release_commit(value, getattr(args, "expected_release_commit", None))
    manifest_bytes = ops._canonical(value)
    manifest_sha256 = _manifest_digest(manifest_bytes)
    root, identity = check_files(args.root, value)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "assemble", "artifacts_verified": len(value["artifacts"]),
                "scope": "complete-target", "complete_target": True, "manifest_sha256": manifest_sha256,
                "effects": "new private artifact directory"}
    target = ops._safe_output_parent(Path(args.output))
    if target == root or root in target.parents or target in root.parents:
        raise Error("toolchain source and output must be disjoint")
    if os.name != "posix":
        raise Error("secure toolchain assembly requires POSIX staging")
    staging = ops._StagingDirectory.create(target, ".toolchain-")
    try:
        total = [0, MAX_TOTAL]
        for item in value["artifacts"]:
            before, checksum = ops._copy_stable(root, item["path"], (staging, item["path"]), MAX_ARTIFACT, total, identity)
            if before.st_size != item["size"] or checksum != item["sha256"]:
                raise Error("artifact changed after verification")
        staging.write_new_bytes("manifest.json", manifest_bytes)
        ops._publish_directory(staging, target)
    finally:
        staging.cleanup()
    return {"status": "PASS", "action": "assemble", "artifacts": len(value["artifacts"]),
            "total_bytes": total[0], "scope": "complete-target", "complete_target": True,
            "manifest_sha256": manifest_sha256, "offline_runtime": "NOT_RUN"}


def _verify_bundle(root, *, expected_manifest_sha256=None, expected_release_commit=None,
                   require_trusted_manifest=False):
    root = ops._canonical_root_directory(Path(root))
    value, raw_manifest = ops._read_json(root / "manifest.json", ops.MAX_PROFILE_BYTES)
    value = manifest(value)
    complete_target = _manifest_scope(value) == "complete-target"
    manifest_sha256 = _check_manifest_digest(
        raw_manifest, expected_manifest_sha256,
        required=require_trusted_manifest or complete_target)
    _check_release_commit(value, expected_release_commit)
    check_files(root, value)
    expected = {"manifest.json", *(item["path"] for item in value["artifacts"])}
    count = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            count += 1
            path = Path(directory) / name
            metadata = path.lstat()
            if count > 4096 or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise Error("unexpected toolchain filesystem entry")
            if stat.S_ISREG(metadata.st_mode) and path.relative_to(root).as_posix() not in expected:
                raise Error("unlisted file in toolchain bundle")
    # Detect replacement of the manifest path during the rest of verification.
    _repeated_value, repeated_raw = ops._read_json(root / "manifest.json", ops.MAX_PROFILE_BYTES)
    if repeated_raw != raw_manifest:
        raise Error("toolchain manifest changed during verification")
    return value, manifest_sha256


def verify(root, *, expected_manifest_sha256=None, expected_release_commit=None):
    value, _manifest_sha256 = _verify_bundle(
        root, expected_manifest_sha256=expected_manifest_sha256,
        expected_release_commit=expected_release_commit)
    return value


def import_images(args):
    value, manifest_sha256 = _verify_bundle(
        args.root, expected_manifest_sha256=getattr(args, "expected_manifest_sha256", None),
        expected_release_commit=getattr(args, "expected_release_commit", None),
        require_trusted_manifest=True)
    scope = _manifest_scope(value)
    complete_target = scope == "complete-target"
    images = [item for item in value["artifacts"] if item["kind"] == "image"]
    if not images:
        raise Error("no image archives in declared toolchain")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "import-images", "archives": len(images),
                "scope": scope, "complete_target": complete_target, "manifest_sha256": manifest_sha256,
                "effects": "load verified tag-free images into an explicitly selected daemon"}
    if os.name != "posix":
        raise Error("secure image import requires a private POSIX bundle")
    root = ops._canonical_root_directory(Path(args.root))
    root_metadata = root.lstat()
    identity = ops._root_anchor_identity(root_metadata)
    if root_metadata.st_uid != os.getuid() or root_metadata.st_mode & 0o077:
        raise Error("image import requires an owner-only bundle directory")
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            metadata = (Path(directory) / name).lstat()
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise Error("image import requires owner-only bundle contents")
    if not args.daemon_id or not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", args.daemon_id):
        raise Error("image import requires the approved Docker daemon identity")
    observed = subprocess.run(["docker", "info", "--format", "{{.ID}}"], check=False,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if observed.returncode or observed.stdout.decode().strip() != args.daemon_id:
        raise Error("Docker daemon identity mismatch")
    for item in images:
        # Pin the exact inode through verification and import. Do not reopen
        # its path in Docker, which would reintroduce a replacement race.
        fd = ops._open_anchored_regular(root, item["path"], identity)
        try:
            with os.fdopen(fd, "rb", closefd=False) as stream:
                before = os.fstat(fd)
                if before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size != item["size"]:
                    raise Error("image archive ownership, permissions or size changed")
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
                if digest.hexdigest() != item["sha256"]:
                    raise Error("image archive changed before import")
                stream.seek(0)
                inspect_image_archive(None, item["image_ids"], fileobj=stream, architecture=item["architecture"] if item["architecture"] != "all" else None)
                if ops._stat_identity(before) != ops._stat_identity(os.fstat(fd)):
                    raise Error("image archive changed during inspection")
                stream.seek(0)
                result = subprocess.run(["docker", "image", "load"], stdin=stream,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
                if result.returncode or ops._stat_identity(before) != ops._stat_identity(os.fstat(fd)):
                    raise Error("image import failed or source changed; imported immutable images are retained")
        finally:
            os.close(fd)
    return {"status": "PASS", "action": "import-images", "archives": len(images), "containers_started": 0,
            "scope": scope, "complete_target": complete_target, "manifest_sha256": manifest_sha256,
            "rollback": "loaded images retained; remove only unused exact image IDs after review", "offline_runtime": "NOT_RUN"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["assemble", "verify", "import-images", "export-images", "normalize-images"])
    parser.add_argument("--root")
    parser.add_argument("--manifest")
    parser.add_argument("--output")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-id")
    parser.add_argument("--daemon-id")
    parser.add_argument("--export-profile")
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--expected-release-commit")
    args = parser.parse_args(argv)
    try:
        if args.apply and (not args.approval_id or not ops.APPROVAL_ID.fullmatch(args.approval_id)):
            raise Error("mutations require --apply and a non-secret approval ID")
        if args.action == "export-images":
            if not args.export_profile or not args.output:
                raise Error("image export requires --export-profile and --output")
            result = export_images(args)
        elif not args.root:
            raise Error("this action requires --root")
        elif args.action == "normalize-images":
            if not args.output:
                raise Error("export normalization requires --output")
            result = normalize_images(args)
        elif args.action == "assemble":
            if not args.manifest or not args.output:
                raise Error("assembly requires --manifest and --output")
            result = assemble(args)
        elif args.action == "import-images":
            result = import_images(args)
        else:
            value, manifest_sha256 = _verify_bundle(
                args.root, expected_manifest_sha256=args.expected_manifest_sha256,
                expected_release_commit=args.expected_release_commit)
            scope = _manifest_scope(value)
            result = {"status": "PASS", "action": "verify", "artifacts": len(value["artifacts"]),
                      "scope": scope, "complete_target": scope == "complete-target",
                      "manifest_sha256": manifest_sha256, "offline_runtime": "NOT_RUN"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Error, OSError, ValueError, tarfile.TarError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        print(json.dumps({"status": "BLOCKED", "error": type(exc).__name__, "details": "suppressed", "exit_code": 2}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
