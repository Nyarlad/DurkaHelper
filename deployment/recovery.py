#!/usr/bin/env python3
"""Private native backup and quarantine restore for maintained deployments.

Preview never contacts Docker. Apply requires an approved daemon, a snapshot
and an exclusive maintenance window. The source is NEVER resumed automatically.
Quarantine stages cannot be opened by toolkit.up; promotion is a manual gate.
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
import secrets
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


kit = module("recovery_toolkit", "deployment/toolkit.py")
bundle = module("recovery_archive", "scripts/toolchain_bundle.py")
ops = bundle.ops
Error = ops.DefenseError
SCHEMA = "durkahelper.deployment-backup.v1"
STAGE_SCHEMA = "durkahelper.deployment-recovery-stage.v1"
STAGE_VERIFY_SCHEMA = "durkahelper.deployment-recovery-verification.v1"
PROMOTION_SCHEMA = "durkahelper.deployment-promotion-plan.v1"
ACCEPTANCE_SCHEMA = "durkahelper.deployment-promotion-acceptance.v1"
LABEL = "io.durkahelper.recovery"
HELPER_LABEL = "io.durkahelper.recovery-purpose"
BACKENDS = {"postgres": "farm", "packmate-db": "packmate", "redis": None, "neo-redis": None}
WRITERS = ("neo-worker", "celery", "front", "packmate", "neo-server", "farm")
COLD = ("redis", "neo-redis", "neo")
MAX_FILE = 1024 ** 3
MAX_TOTAL = 8 * 1024 ** 3
MAX_FILES = 20000
CHUNK = 1024 * 1024
RESUME = "python3 deployment/toolkit.py up --workspace <SOURCE_WORKSPACE> --apply --approval-id <ID>"
LIMITS = ["application-level farm/Neo/Packmate acceptance NOT_RUN", "automatic queue replay disabled",
          "promotion to a live deployment requires manual review", "physical Mac and large-data RPO/RTO NOT_RUN",
          "custom PostgreSQL roles/grants outside maintained credentials are not supported", "Redis TTL expiration continues during recovery"]
PROMOTION_BLOCKERS = ["component_native_data_restore", "runtime_uid_gid_mapping",
                      "application_acceptance", "operator_activation"]
PROMOTION_ROLLBACK = (
    "leave candidate non-runnable; keep backup and verified recovery stage stopped and unchanged"
)


def _promotion_acceptance_contract():
    return {
        "schema": ACCEPTANCE_SCHEMA,
        "checks": {
            "component_native_data_restore": "PASS|FAIL",
            "filesystem_ownership": "PASS|FAIL",
            "farm_authenticated": "PASS|FAIL",
            "neo_authenticated": "PASS|FAIL",
            "packmate_file": "PASS|FAIL",
            "restart_reconnect": "PASS|FAIL",
        },
        "submission_enabled": False,
        "worker_enabled": False,
        "capture_enabled": False,
        "rollback_confirmed": True,
    }


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, *, sink=None, stdin=None, collect=True, limit=1024 * 1024, timeout=60):
    """Bound output before buffering; never echo commands, credentials or stderr."""
    data, errors = bytearray(), []
    result = {"bytes": 0, "sha256": None, "prefix": b""}
    digest = hashlib.sha256()
    process = subprocess.Popen(argv, stdin=stdin if stdin is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def drain():
        try:
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                result["bytes"] += len(chunk)
                if result["bytes"] > limit:
                    raise Error("recovery command exceeded its byte budget")
                digest.update(chunk)
                if len(result["prefix"]) < 32:
                    result["prefix"] = (result["prefix"] + chunk)[:32]
                if sink is not None:
                    ops._write_all(sink, chunk)
                elif collect:
                    data.extend(chunk)
        except (OSError, Error) as error:
            errors.append(error)
            process.kill()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=timeout)
        reader.join(timeout=5)
        if code or errors or reader.is_alive():
            raise Error("recovery command failed or exceeded bounds; output suppressed")
        result["sha256"] = digest.hexdigest()
        return bytes(data) if collect and sink is None else result
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        reader.join(timeout=5)
        process.stdout.close()


def daemon(identity):
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", identity):
        raise Error("an explicitly approved Docker daemon ID is required")
    if run(["docker", "info", "--format", "{{.ID}}"]).decode().strip() != identity:
        raise Error("Docker daemon identity mismatch")


def require_apply(args):
    if not args.approval_id or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id):
        raise Error("apply requires a non-secret approval ID")
    if not args.snapshot_confirmed or not args.maintenance_confirmed:
        raise Error("apply requires snapshot and exclusive maintenance confirmation")
    if os.name != "posix" or os.geteuid() == 0:
        raise Error("recovery mutations require a non-root POSIX operator")
    daemon(args.daemon_id)


def require_promotion_apply(args):
    """Require explicit human review without treating an acknowledgement as a health check."""
    require_apply(args)
    if not getattr(args, "queue_reviewed", False) or not getattr(args, "ttl_reviewed", False):
        raise Error("promotion requires explicit queue/replay and TTL-expiry review acknowledgements")
    if not isinstance(getattr(args, "stage_project", None), str) or not re.fullmatch(
            r"dh-recovery-[a-f0-9]{12}", args.stage_project):
        raise Error("promotion requires the exact recovery stage project identity")
    for name in ("target_uid", "target_gid"):
        value = getattr(args, name, None)
        if type(value) is not int or not 0 <= value <= 2 ** 31 - 1:
            raise Error("promotion requires explicit numeric target UID and GID")
    if (hasattr(os, "geteuid") and args.target_uid != os.geteuid()) or (
            hasattr(os, "getegid") and args.target_gid != os.getegid()):
        raise Error("candidate owner UID/GID must match the non-root operator")


def private_root(path):
    root = ops._canonical_root_directory(Path(path))
    if os.name == "posix" and (root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077):
        raise Error("recovery roots must be owner-only private directories")
    return root


def new_target(path, source):
    target = ops._safe_output_parent(Path(path))
    # Resolve Windows short-name aliases consistently on both sides. Validate
    # the selected existing source leaf before resolving its spelling.
    source = ops._canonical_input_leaf(Path(source))
    # File identities also handle an 8.3 alias on the selected source directory
    # without requiring a realpath call denied by some Windows sandboxes.
    boundaries = {ops._root_anchor_identity(boundary.stat()) for boundary in (source, ROOT)}
    contained = any(ops._root_anchor_identity(parent.stat()) in boundaries for parent in target.parents)
    if contained or target.is_relative_to(source) or source.is_relative_to(target) or target.is_relative_to(ROOT):
        raise Error("destination must be new, outside source and repository")
    return target


def source_workspace(path):
    root, state, spec, profile = kit.workspace(path)
    private_root(root)
    runtime = maintained_runtime(root, state, spec, profile)
    files = set(state["files"]) | {"deployment.json", "runtime-compose.json", "build-receipt.json"}
    allowed = {"deployment.json", "compose.json", "profile.json", "model.json", "policy.json", "runtime-compose.json", "build-receipt.json", "operator-paths.json"}
    if any(name not in allowed and not name.startswith(("config/", "sources/")) for name in files):
        raise Error("unexpected private deployment inventory member")
    return root, state, runtime, profile, sorted(files)


def maintained_runtime(root, state, spec, profile):
    runtime = kit.check_build_receipt(root, spec)
    if profile["packmate"]["mode"] != "FILE" or set(runtime["services"]) != set(BACKENDS) | set(WRITERS):
        raise Error("only the maintained FILE deployment service set is supported")
    if any(s.get("labels") != {kit.LABEL: state["project"]} for s in runtime["services"].values()):
        raise Error("maintained deployment labels changed")
    # Regeneration rejects rehashed custom Compose commands, mounts and networks.
    env = spec["services"]["postgres"]["environment"]
    neo_text = kit.read(root / "config/neo-client.yml").decode()
    match = re.search(r'^grpc_auth_key: "([A-Za-z0-9_.-]{20,128})"$', neo_text, re.M)
    pairs = dict(line.split("=", 1) for line in kit.read(root / "config/packmate.properties").decode().splitlines())
    if match is None:
        raise Error("maintained Neo credentials are missing")
    credentials = kit.validate_credentials({"database_password": env["POSTGRES_PASSWORD"],
        "farm_password": spec["services"]["farm"]["environment"]["SERVER_PASSWORD"], "neo_key": match[1],
        "packmate_user": pairs.get("packmate.web.account-login"), "packmate_password": pairs.get("packmate.web.account-password")})
    images = kit.shared.image_map(ROOT / "config/integration-images.lock.json")
    if spec != kit.compose_spec(profile, credentials, state["project"], images):
        raise Error("deployment differs from the maintained Compose contract")
    return runtime


def ids(output):
    values = output.decode().split()
    if len(values) > 256 or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in values):
        raise Error("invalid or oversized Docker resource listing")
    return values


def exact_network_ids(name):
    """List only the exact named network without inspecting substring matches."""
    output = run(["docker", "network", "ls", "--no-trunc", "--filter", "name=" + name,
                  "--format", "{{.ID}} {{.Name}}"])
    lines = output.decode().splitlines()
    if len(lines) > 256:
        raise Error("invalid or oversized Docker network listing")
    result = []
    for line in lines:
        fields = line.split()
        if (len(fields) != 2 or not re.fullmatch(r"[a-f0-9]{64}", fields[0]) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", fields[1])):
            raise Error("invalid Docker network listing")
        if fields[1] == name:
            result.append(fields[0])
    return result


def _expected_network_names(project, runtime):
    definitions = runtime.get("networks")
    if not isinstance(definitions, dict) or not definitions:
        raise Error("deployment network contract is missing")
    result = {}
    for logical, definition in definitions.items():
        if (not isinstance(logical, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}", logical) or
                not isinstance(definition, dict)):
            raise Error("invalid deployment network contract")
        physical = definition.get("name", project + "_" + logical)
        if not isinstance(physical, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", physical):
            raise Error("invalid deployment network name")
        if physical in result.values():
            raise Error("duplicate deployment network name")
        result[logical] = physical
    return result


def _service_networks(service, expected):
    configured = service.get("networks")
    if isinstance(configured, list):
        logical = configured
    elif isinstance(configured, dict):
        logical = list(configured)
    else:
        raise Error("invalid service network contract")
    if len(logical) != len(set(logical)) or any(name not in expected for name in logical):
        raise Error("invalid service network contract")
    return {expected[name] for name in logical}


def owned(root, project, runtime, daemon_id, label=kit.LABEL, *, exclusive=True,
          require_no_networks=False, strict_networks=False):
    """Inspect only IDs/ownership/mounts; never fetch argv, environment or logs."""
    daemon(daemon_id)
    listing = ["docker", "ps", "--all", "--quiet", "--no-trunc"]
    if not exclusive:
        listing += ["--filter", "label=com.docker.compose.project=" + project]
    listed = ids(run(listing))
    result = {}
    expected_paths = [str(root / "data" / name) for name in (*BACKENDS, "neo")]
    fmt = ('{"id":{{json .Id}},"labels":{{json .Config.Labels}},"image":{{json .Image}},'
           '"running":{{json .State.Running}},"mounts":{{json .Mounts}},'
           '"networks":{{json .NetworkSettings.Networks}}}')
    for identity in listed:
        value = json.loads(run(["docker", "container", "inspect", "--format", fmt, identity]))
        labels, mounts = value.get("labels") or {}, value.get("mounts")
        if value.get("id") != identity or not isinstance(mounts, list):
            raise Error("invalid container identity or mounts")
        member = labels.get("com.docker.compose.project") == project
        if not member:
            if exclusive and any(m.get("Type") == "bind" and any(
                    Path(m.get("Source", "/")).is_relative_to(Path(p)) or Path(p).is_relative_to(Path(m.get("Source", "/")))
                    for p in expected_paths) for m in mounts):
                raise Error("database paths are shared with a non-owned container")
            continue
        name = labels.get("com.docker.compose.service")
        if labels.get(label) != project or name not in runtime["services"] or name in result or value.get("image") != runtime["services"][name]["image"]:
            raise Error("deployment container ownership or immutable image mismatch")
        expected = {}
        for volume in runtime["services"][name].get("volumes", []):
            source, destination, *flags = volume.split(":")
            if not source.startswith("./") or ".." in PurePosixPath(source).parts:
                raise Error("external or non-relative maintained mount")
            expected[destination] = (str(root / source[2:]), "ro" not in flags)
        actual = {m["Destination"]: (m["Source"], m["RW"]) for m in mounts if m.get("Type") == "bind"}
        tmpfs = {v.split(":", 1)[0] for v in runtime["services"][name].get("tmpfs", [])}
        if actual != expected or any(m.get("Type") != "bind" and not (m.get("Type") == "tmpfs" and m.get("Destination") in tmpfs) for m in mounts):
            raise Error("deployment mounted paths differ from the maintained workspace")
        result[name] = value
    expected_networks = _expected_network_names(project, runtime)
    labelled = ids(run(["docker", "network", "ls", "--quiet", "--no-trunc", "--filter",
                        "label=com.docker.compose.project=" + project]))
    exact = []
    if require_no_networks or strict_networks:
        for name in expected_networks.values():
            exact.extend(exact_network_ids(name))
    network_ids = list(dict.fromkeys(labelled + exact))
    networks = {}
    network_format = ('{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},'
                      '"internal":{{json .Internal}},"containers":{{json .Containers}}}')
    for identity in network_ids:
        value = json.loads(run(["docker", "network", "inspect", "--format", network_format, identity]))
        labels = value.get("labels") or {}
        if (value.get("id") != identity or not isinstance(value.get("name"), str) or
                identity in labelled and labels.get("com.docker.compose.project") != project or
                identity in exact and value.get("name") not in expected_networks.values()):
            raise Error("deployment network identity changed during inspection")
        if labels.get(label) != project or labels.get("com.docker.compose.project") != project:
            raise Error("deployment network ownership or membership mismatch")
        if value["name"] in networks:
            raise Error("deployment network name or count mismatch")
        networks[value["name"]] = value
    if require_no_networks and networks:
        raise Error("promotion project identity already has Docker resources")
    if strict_networks:
        if set(result) != set(runtime["services"]) or set(networks) != set(expected_networks.values()):
            raise Error("deployment network name or count mismatch")
        for logical, physical in expected_networks.items():
            value = networks[physical]
            expected_internal = runtime["networks"][logical].get("internal", False)
            # Docker keeps a stopped container's configured network identity in
            # container inspect, but removes its endpoint from network inspect
            # .Containers.  Bind the live endpoint set to running containers;
            # the attachment identity for every stopped container is checked
            # separately below.
            expected_members = {container["id"] for name, container in result.items()
                                if container["running"] and
                                physical in _service_networks(runtime["services"][name], expected_networks)}
            members = value.get("containers")
            if (type(expected_internal) is not bool or type(value.get("internal")) is not bool or
                    value["internal"] is not expected_internal or not isinstance(members, dict) or
                    set(members) != expected_members):
                raise Error("deployment network isolation or membership mismatch")
        by_id = {value["id"]: name for name, value in networks.items()}
        for name, container in result.items():
            attachments = container.get("networks")
            expected_attachments = _service_networks(runtime["services"][name], expected_networks)
            if not isinstance(attachments, dict) or set(attachments) != expected_attachments:
                raise Error("deployment container network attachment mismatch")
            if any(not isinstance(value, dict) or by_id.get(value.get("NetworkID")) != physical
                   for physical, value in attachments.items()):
                raise Error("deployment container network identity mismatch")
    elif any(not set(value.get("containers") or {}) <= {v["id"] for v in result.values()}
             for value in networks.values()):
        raise Error("deployment network ownership or membership mismatch")
    return result


def wait_strict_owned(context, timeout=10.0):
    """Wait briefly for Compose endpoint metadata to converge after `up`."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return owned(*context, exclusive=False, strict_networks=True)
        except Error:
            if time.monotonic() >= deadline:
                raise Error("recovery project network state did not converge")
            time.sleep(0.1)


def stop(source, names, *, exclusive=True, strict_networks=False):
    root, project, runtime, identity, label = source
    current = owned(root, project, runtime, identity, label, exclusive=exclusive,
                    strict_networks=strict_networks)
    selected = [current[name]["id"] for name in names if name in current and current[name]["running"]]
    if selected:
        run(["docker", "stop", "--time", "20"] + selected, timeout=90)
    after = owned(root, project, runtime, identity, label, exclusive=exclusive,
                  strict_networks=strict_networks)
    if any(after.get(name, {}).get("running") for name in names):
        raise Error("owned service did not stop; source must remain quiesced")


def pg_summary(identity, database):
    base = ["docker", "exec", identity, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-A", "-t", "-U", database, "-d", database, "-c"]
    names = run(base + ["SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name;"]).decode().split()
    # S4DFarm creates its public tables lazily, so an initialized PostgreSQL
    # database can legitimately have no application tables yet.
    if len(names) > 256 or any(not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name) for name in names):
        raise Error("unsupported application database schema")
    result = {}
    for name in names:
        value = run(base + ['COPY (SELECT row_to_json(t)::text FROM "' + name + '" t ORDER BY row_to_json(t)::text) TO STDOUT;'], collect=False, limit=MAX_FILE, timeout=120)
        result[name] = {"bytes": value["bytes"], "sha256": value["sha256"]}
    return result


def stream_file(staging, name, argv):
    fd = staging.open_new_file(name)
    try:
        result = run(argv, sink=fd, collect=False, limit=MAX_FILE, timeout=300)
        os.fsync(fd)
        staging._finalize_file_record(name, fd)
        return result
    finally:
        os.close(fd)


def cleanup_helpers(project, daemon_id, name=None):
    daemon(daemon_id)
    pattern = r"dh-cold-[a-f0-9]{24}"
    if name is not None and not re.fullmatch(pattern, name):
        raise Error("invalid registered recovery helper name")
    argv = ["docker", "ps", "--all", "--quiet", "--no-trunc"]
    argv += (["--filter", "name=^/" + name + "$"] if name else
             ["--filter", "label=" + LABEL + "=" + project, "--filter", "label=" + HELPER_LABEL + "=cold-read"])
    found = ids(run(argv))
    if len(found) > (1 if name else 16):
        raise Error("unexpected recovery helper listing")
    template = '{"id":{{json .Id}},"name":{{json .Name}},"owner":{{json (index .Config.Labels "' + LABEL + '")}},"purpose":{{json (index .Config.Labels "' + HELPER_LABEL + '")}}}'
    for identity in found:
        value = json.loads(run(["docker", "inspect", "--format", template, identity]))
        actual_name = value.get("name")
        if (value.get("id") != identity or value.get("owner") != project or value.get("purpose") != "cold-read" or
                not isinstance(actual_name, str) or not re.fullmatch("/" + pattern, actual_name) or
                name is not None and actual_name != "/" + name):
            raise Error("recovery helper ownership mismatch; cleanup refused")
        run(["docker", "rm", "--force", identity], timeout=20)


def helper(root, project, image, directory, daemon_id, *, staging=None, check=False):
    if directory not in COLD:
        raise Error("unsupported cold-copy directory")
    daemon(daemon_id)
    source = kit.safe_path(root / "data" / directory)
    if source != root / "data" / directory or (root / "data").is_symlink() or root.is_symlink() or source.is_symlink() or not source.is_dir():
        raise Error("cold-copy source must be a real owned directory")
    name = "dh-cold-" + secrets.token_hex(12)
    argv = ["docker", "create", "--name", name, "--label", LABEL + "=" + project,
            "--label", HELPER_LABEL + "=cold-read", "--network", "none", "--read-only",
            "--cap-drop=ALL", "--cap-add=DAC_READ_SEARCH", "--security-opt=no-new-privileges:true", "--memory=128m",
            "--cpus=0.5", "--pids-limit=32", "--log-driver=none", "--pull=never",
            "--mount", "type=bind,src=" + str(source) + ",dst=/data,readonly", "--entrypoint",
            "redis-check-rdb" if check else "tar", image]
    argv += ["/data/dump.rdb"] if check else ["-C", "/data", "-cf", "-", "."]
    # Register the name before create; an interrupted CLI may still create the
    # daemon-side container. Reconcile ownership even without a returned ID.
    try:
        identity = run(argv).decode().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise Error("cold helper creation returned an invalid identity")
        if check:
            run(["docker", "start", "--attach", identity])
            return None
        return stream_file(staging, "cold/" + directory + ".tar", ["docker", "start", "--attach", identity])
    finally:
        cleanup_helpers(project, daemon_id, name)


def cold_members(path, *, staging=None, directory=None, source_root=None, expected=None):
    """Validate the whole tar before any bounded descriptor-anchored extraction."""
    result, total = {}, 0
    path = Path(path)
    source_root = path.parent if source_root is None else source_root
    relative = path.relative_to(source_root).as_posix()
    fd = ops._open_anchored_regular(source_root, relative, ops._root_anchor_identity(source_root.stat()))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        if before.st_size > MAX_FILE:
            raise Error("cold backup archive exceeds bounds")
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            digest.update(chunk)
        if expected is not None and expected != {"bytes": before.st_size, "sha256": digest.hexdigest()}:
            raise Error("cold backup changed before use")
        stream.seek(0)
        bundle._preflight_image_tar(stream)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for member in archive:
                name = member.name[2:] if member.name.startswith("./") else member.name
                if name in {"", "."} and member.isdir():
                    continue
                normalized = PurePosixPath(name)
                if (name in {"", ".", ".."} or normalized.is_absolute() or normalized.as_posix() != name or ".." in normalized.parts or
                        "\\" in name or ":" in name or name in result or not (member.isfile() or member.isdir()) or member.issparse()):
                    raise Error("unsafe cold backup archive member")
                if member.isdir():
                    continue
                total += member.size
                if total > MAX_FILE or len(result) >= MAX_FILES:
                    raise Error("cold backup exceeds bounds")
                digest, prefix = hashlib.sha256(), b""
                with archive.extractfile(member) as source:
                    while True:
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
                        prefix = (prefix + chunk)[:32]
                result[name] = {"bytes": member.size, "sha256": digest.hexdigest()}
                if name == "dump.rdb" and not prefix.startswith(b"REDIS"):
                    raise Error("Redis native snapshot header missing")
                if name == "db.db" and (len(prefix) < 24 or struct.unpack_from("<II", prefix, 16) != (0xED0CDAED, 2)):
                    raise Error("Neo bbolt metadata header missing")
            required = "db.db" if directory == "neo" else "dump.rdb"
            if required not in result:
                raise Error("required cold component state missing")
            if staging is not None:
                for member in archive.getmembers():
                    name = member.name[2:] if member.name.startswith("./") else member.name
                    if name not in result or (directory != "neo" and name != "dump.rdb"):
                        continue
                    destination = "data/" + directory + "/" + name
                    fd = staging.open_new_file(destination)
                    try:
                        with archive.extractfile(member) as source:
                            for chunk in iter(lambda: source.read(CHUNK), b""):
                                ops._write_all(fd, chunk)
                        os.fsync(fd)
                        staging._finalize_file_record(destination, fd)
                    finally:
                        os.close(fd)
        if ops._stat_identity(before) != ops._stat_identity(os.fstat(stream.fileno())):
            raise Error("cold backup changed during use")
    return result


def inventory(staging):
    result, total = {}, 0
    for name, record in sorted(staging.ledger.items()):
        if record[0] == "file":
            metadata, digest = ops._hash_anchored_regular(staging.path, name, staging.identity, MAX_FILE)
            total += metadata.st_size
            if total > MAX_TOTAL or len(result) >= MAX_FILES:
                raise Error("private recovery inventory exceeds bounds")
            result[name] = {"bytes": metadata.st_size, "sha256": digest}
    return result


def backup(args):
    root, state, runtime, profile, files = source_workspace(args.workspace)
    target = new_target(args.output, root)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "backup", "effects": ["pause capture and writers", "native PG/Redis snapshots", "cold Neo/Redis state", "private source/config/receipt copy"], "source_auto_resume": False}
    require_apply(args)
    kit.check_build_receipt(root, kit.load(root / "compose.json"), kit.image_preflight(runtime, profile))
    # Retry also reconciles helpers whose create completed after interruption.
    cleanup_helpers(state["project"], args.daemon_id)
    source = (root, state["project"], runtime, args.daemon_id, kit.LABEL)
    anchor = ops._root_anchor_identity(root.stat())
    current = owned(*source)
    if any(name not in current or not current[name]["running"] for name in BACKENDS):
        raise Error("native backup requires all four owned database services running")
    staging = ops._StagingDirectory.create(target, ".native-backup-")
    started = time.monotonic()
    try:
        stop(source, WRITERS)
        current = owned(*source)
        summaries = {}
        for name, database in BACKENDS.items():
            identity = current[name]["id"]
            if database:
                summaries[name] = pg_summary(identity, database)
                result = stream_file(staging, "dumps/" + name + ".dump", ["docker", "exec", identity, "pg_dump", "-U", database, "-d", database,
                                     "--format=custom", "--compress=0", "--no-owner", "--no-privileges"])
                if not result["prefix"].startswith(b"PGDMP") or summaries[name] != pg_summary(identity, database):
                    raise Error("native dump invalid or quiesced database changed")
            elif run(["docker", "exec", identity, "redis-cli", "--raw", "SAVE"]).strip() != b"OK":
                raise Error("native Redis SAVE failed")
        stop(source, BACKENDS)
        cold = {}
        for directory in COLD:
            if root.is_symlink() or ops._root_anchor_identity(root.stat()) != anchor:
                raise Error("source workspace identity changed during backup")
            owned(*source)
            if directory != "neo":
                helper(root, state["project"], runtime["services"]["redis"]["image"], directory, args.daemon_id, check=True)
            helper(root, state["project"], runtime["services"]["redis"]["image"], directory, args.daemon_id, staging=staging)
            cold[directory] = cold_members(staging.path / "cold" / (directory + ".tar"), directory=directory, source_root=staging.path)
        total = [0, MAX_TOTAL]
        for name in files:
            _metadata, digest = ops._copy_stable(root, name, (staging, "private/" + name), MAX_FILE, total, anchor)
            if name in state["files"] and digest != state["files"][name]:
                raise Error("source immutable file changed before backup")
        source_workspace(root)
        if any(item["running"] for item in owned(*source).values()):
            raise Error("source resumed during backup; no complete backup published")
        manifest = {"schema": SCHEMA, "source_project": state["project"], "daemon_id": args.daemon_id,
            "files": inventory(staging), "cold": cold, "databases": summaries, "source_quiesced": True}
        staging.write_new_bytes("backup.json", ops._canonical(manifest))
        ops._publish_directory(staging, target)
    finally:
        staging.cleanup()
    return {"status": "PASS", "action": "backup", "capture_paused": True, "source_left_quiesced": True,
            "resume": RESUME, "warning": "review protocols and expired queues before separately enabling submission/worker",
            "private_only": True, "backup_seconds": round(time.monotonic() - started, 3), "limits": LIMITS}


def verify_backup(path):
    root = private_root(path)
    value, _ = ops._read_json(root / "backup.json", 8 * 1024 * 1024)
    fields = {"schema", "source_project", "daemon_id", "files", "cold", "databases", "source_quiesced"}
    ops._strict_keys(value, fields, fields, "native backup")
    if (value["schema"] != SCHEMA or value["source_quiesced"] is not True or
            not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", value["source_project"]) or not isinstance(value["files"], dict) or
            not isinstance(value["daemon_id"], str) or not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", value["daemon_id"]) or
            not 1 <= len(value["files"]) <= MAX_FILES or set(value["cold"]) != set(COLD) or set(value["databases"]) != {"postgres", "packmate-db"}):
        raise Error("invalid private recovery manifest")
    anchor, total = ops._root_anchor_identity(root.stat()), 0
    for name, expected in value["files"].items():
        ops._portable_relative_posix(name, "backup member")
        if not name.startswith(("private/", "dumps/", "cold/")) or set(expected) != {"bytes", "sha256"}:
            raise Error("invalid native backup member")
        metadata, digest = ops._hash_anchored_regular(root, name, anchor, MAX_FILE)
        total += metadata.st_size
        if expected != {"bytes": metadata.st_size, "sha256": digest} or total > MAX_TOTAL:
            raise Error("native backup checksum or byte budget mismatch")
    required = {"dumps/postgres.dump", "dumps/packmate-db.dump", "private/compose.json", "private/profile.json",
                "private/build-receipt.json", "private/runtime-compose.json", "private/deployment.json"} | {"cold/" + d + ".tar" for d in COLD}
    if not required <= set(value["files"]):
        raise Error("native backup inventory incomplete")
    for directory in COLD:
        relative = "cold/" + directory + ".tar"
        if cold_members(root / relative, directory=directory, source_root=root, expected=value["files"][relative]) != value["cold"][directory]:
            raise Error("cold state inventory mismatch")
    actual, entries = set(), 0
    for base, directories, names in os.walk(root, followlinks=False):
        for name in directories + names:
            entries += 1
            if entries > MAX_FILES * 2:
                raise Error("recovery filesystem inventory exceeds bounds")
            p = Path(base) / name
            mode = p.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise Error("unexpected recovery filesystem entry")
            if stat.S_ISREG(mode):
                actual.add(p.relative_to(root).as_posix())
    if actual != set(value["files"]) | {"backup.json"}:
        raise Error("unlisted private recovery files")
    state = kit.load(root / "private/deployment.json")
    if state.get("source_pins") != kit.shared.PINS or state.get("project") != value["source_project"]:
        raise Error("backup source provenance mismatch")
    maintained_runtime(root / "private", state, kit.load(root / "private/compose.json"), kit.validate_profile(kit.load(root / "private/profile.json")))
    for name, digest in state["files"].items():
        if value["files"].get("private/" + name, {}).get("sha256") != digest:
            raise Error("backup private source/config provenance mismatch")
    return root, value


def _stage_verification_payload(state, checks):
    body = {"schema": STAGE_VERIFY_SCHEMA, "project": state["project"],
            "daemon_id": state["daemon_id"], "backup_sha256": state["backup_sha256"],
            "compose_sha256": state["compose_sha256"], "stage_stopped": True,
            "writers_enabled": False, "checks": dict(sorted(checks.items()))}
    return dict(body, verification_sha256=sha(ops._canonical(body)))


def write_stage_verification(root, state, checks):
    """Publish a no-replace verification only after restore checks and a stopped-state inspection."""
    if set(checks) != set(BACKENDS) or not all(value is True for value in checks.values()):
        raise Error("a complete successful native check set is required")
    root = private_root(root)
    payload = ops._canonical(_stage_verification_payload(state, checks))
    if os.name != "posix" or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise Error("secure stage verification publication requires POSIX directory descriptors")
    before = ops._root_anchor_identity(root.stat())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".recovery-verification-" + secrets.token_hex(16) + ".tmp"
    final = "recovery-verification.json"
    descriptor = None
    temporary_anchor = None
    committed = False
    try:
        if ops._root_anchor_identity(os.fstat(directory)) != before:
            raise Error("recovery stage changed before verification publication")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW, 0o600, dir_fd=directory)
        created = os.fstat(descriptor)
        if not stat.S_ISREG(created.st_mode):
            raise Error("recovery verification staging file is not regular")
        temporary_anchor = ops._root_anchor_identity(created)
        ops._write_all(descriptor, payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        named = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or ops._stat_identity(metadata) != ops._stat_identity(named) or
                stat.S_IMODE(metadata.st_mode) != 0o600 or
                ops._root_anchor_identity(root.stat()) != before):
            raise Error("recovery verification file changed during publication")
        os.close(descriptor)
        descriptor = None
        # Complete every fallible validation and durability operation before
        # the hard-link commit. link(2) is atomic and cannot replace an
        # existing attestation.
        os.fsync(directory)
        try:
            os.link(temporary, final, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
        except BaseException:
            # Reconcile an interrupted link: if the final name is our exact
            # inode, publication committed and must report success.
            try:
                published = os.stat(final, dir_fd=directory, follow_symlinks=False)
            except OSError:
                raise
            if (not stat.S_ISREG(published.st_mode) or
                    ops._root_anchor_identity(published) != temporary_anchor):
                raise
            committed = True
        else:
            committed = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_anchor is not None:
            try:
                named = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                if ops._root_anchor_identity(named) == temporary_anchor:
                    os.unlink(temporary, dir_fd=directory)
            except OSError:
                pass
        if committed:
            # The link is the commit point. Durability and removal of the
            # temporary name are best-effort after that point so a complete,
            # acceptable final attestation is never reported as a failure.
            try:
                os.fsync(directory)
            except OSError:
                pass
        try:
            os.close(directory)
        except OSError:
            if not committed:
                raise


def verify_stage(path, manifest, runtime, profile, expected_project=None):
    """Verify restore attestation/spec/private files; DB directory bytes are not re-hashed."""
    root = private_root(path)
    state, _ = ops._read_json(root / "recovery-stage.json", 1024 * 1024)
    fields = {"schema", "project", "daemon_id", "compose_sha256", "backup_sha256"}
    ops._strict_keys(state, fields, fields, "recovery stage")
    project = state["project"]
    if (state["schema"] != STAGE_SCHEMA or not isinstance(project, str) or
            not re.fullmatch(r"dh-recovery-[a-f0-9]{12}", project) or
            expected_project is not None and project != expected_project or
            state["daemon_id"] != manifest.get("daemon_id") or
            state["backup_sha256"] != sha(ops._canonical(manifest))):
        raise Error("recovery stage identity or backup binding mismatch")
    spec, _ = ops._read_json(root / "recovery-compose.json", 8 * 1024 * 1024)
    expected_spec = stage_spec(runtime, project)
    if spec != expected_spec or state["compose_sha256"] != sha(ops._canonical(spec)):
        raise Error("recovery stage Compose contract changed")
    verification, _ = ops._read_json(root / "recovery-verification.json", 1024 * 1024)
    verify_fields = {"schema", "project", "daemon_id", "backup_sha256", "compose_sha256",
                     "stage_stopped", "writers_enabled", "checks", "verification_sha256"}
    ops._strict_keys(verification, verify_fields, verify_fields, "recovery stage verification")
    body = {name: verification[name] for name in verify_fields if name != "verification_sha256"}
    if (verification["schema"] != STAGE_VERIFY_SCHEMA or verification["project"] != project or
            verification["daemon_id"] != state["daemon_id"] or
            verification["backup_sha256"] != state["backup_sha256"] or
            verification["compose_sha256"] != state["compose_sha256"] or
            verification["stage_stopped"] is not True or verification["writers_enabled"] is not False or
            not isinstance(verification["checks"], dict) or set(verification["checks"]) != set(BACKENDS) or
            not all(value is True for value in verification["checks"].values()) or
            verification["verification_sha256"] != sha(ops._canonical(body))):
        raise Error("recovery stage verification is stale, incomplete or tampered")
    # Bound the filesystem shape and reject links/devices. Database content is
    # not re-hashed here: the checksummed native restore attestation is only a
    # bound record of the earlier restore checks, not a current byte inventory.
    entries = 0
    allowed = {"private", "data", "recovery-compose.json", "recovery-stage.json", "recovery-verification.json"}
    def walk_error(_error):
        raise Error("recovery stage filesystem cannot be inspected safely")

    # Component-native databases own the contents of these directories and can
    # legitimately make them unreadable to the non-root operator. Promotion
    # never consumes or certifies those bytes: validate the exact data-root
    # entries themselves, then deliberately prune their contents below.
    expected_data_roots = set((*BACKENDS, "neo"))
    try:
        with os.scandir(root / "data") as stream:
            data_roots = list(stream)
    except OSError:
        raise Error("recovery stage data roots cannot be inspected safely")
    if ({entry.name for entry in data_roots} != expected_data_roots or
            any(not entry.is_dir(follow_symlinks=False) for entry in data_roots)):
        raise Error("recovery stage data-root contract changed")

    for base, directories, names in os.walk(root, followlinks=False, onerror=walk_error):
        if Path(base) == root and "data" in directories:
            directories.remove("data")
        for name in directories + names:
            entries += 1
            if entries > MAX_FILES * 2:
                raise Error("recovery stage filesystem inventory exceeds bounds")
            candidate = Path(base) / name
            relative = candidate.relative_to(root)
            metadata = candidate.lstat()
            if relative.parts[0] not in allowed or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise Error("unexpected recovery stage filesystem entry")
    for folder in ("private", "data", *("data/" + name for name in (*BACKENDS, "neo"))):
        candidate = root / folder
        if candidate.is_symlink() or not candidate.is_dir():
            raise Error("recovery stage data layout is incomplete")
    anchor = ops._root_anchor_identity(root.stat())
    for name, expected in manifest.get("files", {}).items():
        if not name.startswith("private/"):
            continue
        metadata, digest = ops._hash_anchored_regular(root, name, anchor, MAX_FILE)
        if expected != {"bytes": metadata.st_size, "sha256": digest}:
            raise Error("recovery stage private source differs from backup")
    return root, state, spec, verification, runtime, profile


def stage_spec(runtime, project):
    spec = {"services": {}, "networks": {"quarantine": {"internal": True, "labels": {LABEL: project}}}}
    for name in BACKENDS:
        service = copy.deepcopy(runtime["services"][name])
        for field in ("ports", "depends_on", "profiles", "build"):
            service.pop(field, None)
        service.update(labels={LABEL: project}, networks=["quarantine"], restart="no")
        if name in {"redis", "neo-redis"}:
            service["command"] = ["redis-server", "--appendonly", "no", "--save", ""]
        spec["services"][name] = service
    return spec


def stage_command(root, project):
    return ["docker", "compose", "--project-name", project, "--project-directory", str(root), "--file", str(root / "recovery-compose.json")]


def restore(args):
    root, manifest = verify_backup(args.backup)
    target = new_target(args.output, root)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "restore-native-stage", "writers_enabled": False,
                "effects": ["new quarantine deployment", "native restore/checks", "stop quarantine databases"], "limits": LIMITS}
    require_apply(args)
    started = time.monotonic()
    runtime = kit.load(root / "private/runtime-compose.json")
    profile = kit.validate_profile(kit.load(root / "private/profile.json"))
    kit.check_build_receipt(root / "private", kit.load(root / "private/compose.json"), kit.image_preflight(runtime, profile))
    project = "dh-recovery-" + secrets.token_hex(6)
    spec = stage_spec(runtime, project)
    staging = ops._StagingDirectory.create(target, ".native-restore-")
    try:
        anchor, total = ops._root_anchor_identity(root.stat()), [0, MAX_TOTAL]
        for name in manifest["files"]:
            if name.startswith("private/"):
                metadata, digest = ops._copy_stable(root, name, (staging, name), MAX_FILE, total, anchor)
                if manifest["files"][name] != {"bytes": metadata.st_size, "sha256": digest}:
                    raise Error("private restore source changed before copying")
        for directory in (*BACKENDS, "neo"):
            staging.mkdir("data/" + directory)
        for directory in COLD:
            relative = "cold/" + directory + ".tar"
            if cold_members(root / relative, staging=staging, directory=directory, source_root=root, expected=manifest["files"][relative]) != manifest["cold"][directory]:
                raise Error("cold restore source changed before extraction")
        staging.write_new_bytes("recovery-compose.json", ops._canonical(spec))
        state = {"schema": STAGE_SCHEMA, "project": project, "daemon_id": args.daemon_id,
                 "compose_sha256": sha(ops._canonical(spec)), "backup_sha256": sha(ops._canonical(manifest))}
        staging.write_new_bytes("recovery-stage.json", ops._canonical(state))
        ops._publish_directory(staging, target)
    finally:
        staging.cleanup()
    context = (target, project, spec, args.daemon_id, LABEL)
    checks = {}
    try:
        if owned(*context, exclusive=False, require_no_networks=True):
            raise Error("new recovery project already has containers")
        run(stage_command(target, project) + ["up", "--detach", "--no-build", "--pull", "never"], timeout=180)
        current = wait_strict_owned(context)
        for name, database in BACKENDS.items():
            identity = current[name]["id"]
            if database:
                deadline = time.monotonic() + 60
                while True:
                    try:
                        # The official image briefly starts a socket-only
                        # initialization server before the final postmaster.
                        # TCP readiness excludes that transient server so a
                        # restore cannot race its shutdown.
                        run(["docker", "exec", identity, "pg_isready", "-h", "127.0.0.1",
                             "-U", database, "-d", database], timeout=5)
                        break
                    except Error:
                        if time.monotonic() >= deadline:
                            raise Error("quarantine database readiness timed out")
                        time.sleep(0.5)
                if run(["docker", "exec", identity, "psql", "-X", "-A", "-t", "-U", database, "-d", database, "-c",
                        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';"]).strip() != b"0":
                    raise Error("quarantine restore target is not empty")
                relative = "dumps/" + name + ".dump"
                fd = ops._open_anchored_regular(root, relative, ops._root_anchor_identity(root.stat()))
                try:
                    before = os.fstat(fd)
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: os.read(fd, CHUNK), b""):
                        digest.update(chunk)
                    if manifest["files"][relative] != {"bytes": before.st_size, "sha256": digest.hexdigest()}:
                        raise Error("native restore dump changed before use")
                    os.lseek(fd, 0, os.SEEK_SET)
                    run(["docker", "exec", "-i", identity, "pg_restore", "-U", database, "-d", database, "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges"], stdin=fd, timeout=300)
                    if ops._stat_identity(before) != ops._stat_identity(os.fstat(fd)):
                        raise Error("restore dump changed during use")
                finally:
                    os.close(fd)
                checks[name] = pg_summary(identity, database) == manifest["databases"][name]
            else:
                deadline = time.monotonic() + 60
                while True:
                    try:
                        if run(["docker", "exec", identity, "redis-cli", "--raw", "PING"], timeout=5).strip() != b"PONG":
                            raise Error("Redis not ready")
                        break
                    except Error:
                        if time.monotonic() >= deadline:
                            raise Error("quarantine Redis readiness timed out")
                        time.sleep(0.5)
                checks[name] = True
                run(["docker", "exec", identity, "redis-check-rdb", "/data/dump.rdb"])
        if not all(checks.values()):
            raise Error("restored database integrity differs from backup")
    finally:
        stop(context, BACKENDS, exclusive=False)
    verify_backup(root)
    stopped = owned(*context, exclusive=False, strict_networks=True)
    if set(stopped) != set(BACKENDS) or any(value["running"] for value in stopped.values()):
        raise Error("recovery stage stopped-state confirmation failed")
    write_stage_verification(target, state, checks)
    return {"status": "PASS", "action": "restore-native-stage", "checks": checks,
            "stage_left_stopped": True, "writers_enabled": False, "private_only": True,
            "restore_seconds": round(time.monotonic() - started, 3),
            "rollback": "source and backup untouched; only new quarantine databases stopped; all stage data retained", "limits": LIMITS}


def reproject_spec(spec, project):
    """Create a new project identity without changing commands, mounts or image provenance."""
    if not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", project):
        raise Error("invalid promotion project identity")
    result = copy.deepcopy(spec)
    for name, service in result["services"].items():
        service["labels"] = {kit.LABEL: project}
        if "build" in service:
            service["image"] = project + "-" + name + ":pinned"
    for network in result["networks"].values():
        network["labels"] = {kit.LABEL: project}
    return result


def _promotion_scaffold(spec, profile, project):
    """Return non-runnable candidate metadata; executable Compose artifacts stay absent."""
    projected = reproject_spec(spec, project)
    model = kit.model(projected, profile)
    return {
        "workspace/profile.json": ops._canonical(profile),
        "workspace/model.json": ops._canonical(model),
        "workspace/policy.json": ops._canonical(kit.policy(profile, model)),
    }


def _separate_promotion_target(target, *sources):
    target = Path(target)
    for source in sources:
        source = ops._canonical_input_leaf(Path(source))
        if target == source or target.is_relative_to(source) or source.is_relative_to(target):
            raise Error("promotion candidate must be new and independent from backup and stage")
    if target.is_relative_to(ROOT):
        raise Error("promotion candidate must remain outside the repository")
    return target


def _promotion_inputs(args, target):
    backup_root, manifest = verify_backup(args.backup)
    private = backup_root / "private"
    source_state = kit.load(private / "deployment.json")
    source_spec = kit.load(private / "compose.json")
    profile = kit.validate_profile(kit.load(private / "profile.json"))
    runtime = maintained_runtime(private, source_state, source_spec, profile)
    if manifest["daemon_id"] != args.daemon_id:
        raise Error("approved daemon differs from the independently verified backup")
    stage = verify_stage(args.stage, manifest, runtime, profile, args.stage_project)
    if stage[1]["daemon_id"] != args.daemon_id:
        raise Error("approved daemon differs from the verified recovery stage")
    _separate_promotion_target(target, backup_root, stage[0])
    return backup_root, manifest, source_state, source_spec, runtime, profile, stage


def _promotion_plan_body(project, source_state, manifest, stage_state, verification,
                         files, args):
    return {"schema": PROMOTION_SCHEMA, "status": "PARTIAL", "project": project,
            "source_project": source_state["project"], "stage_project": stage_state["project"],
            "daemon_id": args.daemon_id, "backup_sha256": sha(ops._canonical(manifest)),
            "stage_verification_sha256": verification["verification_sha256"],
            "candidate_files": files,
            "owner": {"uid": args.target_uid, "gid": args.target_gid,
                      "directory_mode": "0700", "private_file_mode": "0600",
                      "container_config_file_mode": "0644",
                      "runtime_data_ownership": "REQUIRES_COMPONENT_NATIVE_RESTORE"},
            "acknowledgements": {"queue_replay_reviewed": True, "ttl_expiry_reviewed": True},
            "disabled": {"submission": True, "worker": True, "capture": True,
                         "automatic_queue_replay": True},
            "stage_data_contract": {"bytes_consumed": False, "database_directories_rehashed": False,
                                    "native_restore_attestation": "BOUND_ONLY"},
            "candidate_contract": {"compose_spec": "ABSENT", "runtime_spec": "ABSENT",
                                   "build_receipt": "ABSENT", "deployment_state": "PENDING_ONLY"},
            "toolkit_runnable": False,
            "expected_application_acceptance": _promotion_acceptance_contract(),
            "rollback": PROMOTION_ROLLBACK,
            "blocked_on": PROMOTION_BLOCKERS}


def prepare_promotion(args):
    """Seal a new non-runnable candidate; never copy live DB files or start applications."""
    # Reject overwrite before reading any private source selected by the caller.
    target = ops._safe_output_parent(Path(args.output))
    backup_root, manifest, source_state, source_spec, runtime, profile, stage = _promotion_inputs(args, target)
    if not args.apply:
        return {"status": "PARTIAL", "action": "prepare-promotion", "candidate_created": False,
                "writers_enabled": False, "capture_enabled": False, "submission_enabled": False,
                "stage_data_consumed": False, "stage_database_bytes_certified": False,
                "blocked_on": PROMOTION_BLOCKERS,
                "next": "rerun with apply gates to seal a new non-runnable candidate"}
    require_promotion_apply(args)
    private = backup_root / "private"
    stage_context = (stage[0], stage[1]["project"], stage[2], args.daemon_id, LABEL)
    current = owned(*stage_context, exclusive=False, strict_networks=True)
    if set(current) != set(BACKENDS) or any(value["running"] for value in current.values()):
        raise Error("verified recovery stage must retain exactly four stopped owned databases")
    staging = None
    published = False
    try:
        identities = kit.image_preflight(runtime, profile)
        kit.check_build_receipt(private, source_spec, identities)
        project = "dh-deploy-" + secrets.token_hex(6)
        projected_spec = reproject_spec(source_spec, project)
        projected_runtime = kit.runtime_spec(projected_spec, identities)
        candidate_context = (target / "workspace", project, projected_runtime, args.daemon_id, kit.LABEL)
        if owned(*candidate_context, require_no_networks=True):
            raise Error("promotion project identity already has Docker resources")
        staging = ops._StagingDirectory.create(target, ".promotion-")
        total = [0, MAX_TOTAL]
        backup_anchor = ops._root_anchor_identity(backup_root.stat())
        for name, expected in sorted(manifest["files"].items()):
            if not name.startswith(("private/config/", "private/sources/")):
                continue
            destination = "workspace/" + name[len("private/"):]
            metadata, digest = ops._copy_stable(backup_root, name, (staging, destination), MAX_FILE,
                                                total, backup_anchor)
            if expected != {"bytes": metadata.st_size, "sha256": digest}:
                raise Error("promotion source changed while sealing candidate")
            mode = 0o644 if destination in {"workspace/config/neo-client.yml",
                                            "workspace/config/packmate.properties"} else 0o600
            staging.set_file_metadata(destination, mode)
        for directory in ("workspace/data", *("workspace/data/" + name for name in (*BACKENDS, "neo")),
                          "workspace/pcaps"):
            staging.mkdir(directory)
        generated = _promotion_scaffold(source_spec, profile, project)
        for name, data in generated.items():
            staging.write_new_bytes(name, data)
        workspace_files = {name[len("workspace/"):]: value["sha256"] for name, value in inventory(staging).items()
                           if name.startswith("workspace/") and not name.startswith("workspace/data/") and
                           not name.startswith("workspace/pcaps/")}
        pending = {"schema": kit.SCHEMA, "project": project, "files": workspace_files,
                   "source_pins": kit.shared.PINS, "approval_id": args.approval_id}
        staging.write_new_bytes("workspace/deployment.pending.json", ops._canonical(pending))
        candidate_files = inventory(staging)
        body = _promotion_plan_body(project, source_state, manifest, stage[1], stage[3],
                                    candidate_files, args)
        plan = dict(body, plan_sha256=sha(ops._canonical(body)))
        staging.write_new_bytes("promotion-plan.json", ops._canonical(plan))
        # Independently re-verify both immutable inputs immediately before the
        # one-way no-replace publication. Nothing runnable is published.
        verified_root, verified_manifest = verify_backup(backup_root)
        if verified_root != backup_root or verified_manifest != manifest:
            raise Error("backup identity changed during promotion preparation")
        verify_stage(stage[0], manifest, runtime, profile, args.stage_project)
        # This is the last Docker operation. A published candidate is therefore
        # always paired with an unambiguous successful return, and the stage is
        # confirmed stopped immediately before the filesystem commit.
        stop(stage_context, BACKENDS, exclusive=False, strict_networks=True)
        ops._publish_directory(staging, target)
        published = True
    finally:
        if staging is not None:
            try:
                staging.cleanup()
            except OSError:
                if not published:
                    raise
    return {"status": "PARTIAL", "action": "prepare-promotion", "candidate_created": True,
            "project": project, "toolkit_runnable": False, "compose_runnable": False,
            "runnable_artifacts_present": False, "writers_enabled": False,
            "capture_enabled": False, "submission_enabled": False,
            "stage_data_consumed": False, "stage_database_bytes_certified": False,
            "blocked_on": PROMOTION_BLOCKERS,
            "rollback": "candidate is non-runnable; backup and stopped recovery stage are retained"}


def _verify_acceptance(path, plan):
    value, _ = ops._read_json(Path(path), 1024 * 1024)
    fields = {"schema", "project", "plan_sha256", "checks", "submission_enabled",
              "worker_enabled", "capture_enabled", "rollback_confirmed"}
    ops._strict_keys(value, fields, fields, "promotion acceptance")
    check_names = {"component_native_data_restore", "filesystem_ownership", "farm_authenticated",
                   "neo_authenticated", "packmate_file", "restart_reconnect"}
    if (value["schema"] != ACCEPTANCE_SCHEMA or value["project"] != plan["project"] or
            value["plan_sha256"] != plan["plan_sha256"] or not isinstance(value["checks"], dict) or
            set(value["checks"]) != check_names or
            any(result != "PASS" for result in value["checks"].values()) or
            value["submission_enabled"] is not False or value["worker_enabled"] is not False or
            value["capture_enabled"] is not False or value["rollback_confirmed"] is not True):
        raise Error("promotion acceptance record is incomplete or not bound to this candidate")
    return value


def verify_promotion(args):
    """Verify the sealed candidate and optional human/app record without activating it."""
    candidate = private_root(args.output)
    backup_root, manifest, source_state, source_spec, runtime, profile, stage = _promotion_inputs(args, candidate)
    plan, _ = ops._read_json(candidate / "promotion-plan.json", 8 * 1024 * 1024)
    fields = {"schema", "status", "project", "source_project", "stage_project", "daemon_id",
              "backup_sha256", "stage_verification_sha256", "candidate_files", "owner",
              "acknowledgements", "disabled", "stage_data_contract", "candidate_contract",
              "toolkit_runnable", "expected_application_acceptance", "rollback", "blocked_on",
              "plan_sha256"}
    ops._strict_keys(plan, fields, fields, "promotion plan")
    body = {name: plan[name] for name in fields if name != "plan_sha256"}
    if (plan["schema"] != PROMOTION_SCHEMA or plan["status"] != "PARTIAL" or
            not isinstance(plan["project"], str) or not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", plan["project"]) or
            plan["source_project"] != manifest["source_project"] or
            plan["stage_project"] != stage[1]["project"] or plan["daemon_id"] != args.daemon_id or
            plan["backup_sha256"] != sha(ops._canonical(manifest)) or
            plan["stage_verification_sha256"] != stage[3]["verification_sha256"] or
            not isinstance(plan["candidate_files"], dict) or not 1 <= len(plan["candidate_files"]) <= MAX_FILES or
            plan["toolkit_runnable"] is not False or plan["blocked_on"] != PROMOTION_BLOCKERS or
            plan["acknowledgements"] != {"queue_replay_reviewed": True, "ttl_expiry_reviewed": True} or
            plan["disabled"] != {"submission": True, "worker": True, "capture": True,
                                 "automatic_queue_replay": True} or
            plan["stage_data_contract"] != {"bytes_consumed": False, "database_directories_rehashed": False,
                                             "native_restore_attestation": "BOUND_ONLY"} or
             plan["candidate_contract"] != {"compose_spec": "ABSENT", "runtime_spec": "ABSENT",
                                             "build_receipt": "ABSENT",
                                             "deployment_state": "PENDING_ONLY"} or
             plan["expected_application_acceptance"] != _promotion_acceptance_contract() or
             plan["rollback"] != PROMOTION_ROLLBACK or
             plan["plan_sha256"] != sha(ops._canonical(body))):
        raise Error("promotion plan binding or checksum mismatch")
    candidate_metadata = candidate.stat()
    expected_owner = {"uid": candidate_metadata.st_uid, "gid": candidate_metadata.st_gid,
                      "directory_mode": "0700", "private_file_mode": "0600",
                      "container_config_file_mode": "0644",
                      "runtime_data_ownership": "REQUIRES_COMPONENT_NATIVE_RESTORE"}
    if plan["owner"] != expected_owner or stat.S_IMODE(candidate_metadata.st_mode) != 0o700:
        raise Error("promotion candidate ownership contract mismatch")
    forbidden = {"compose.json", "runtime-compose.json", "build-receipt.json", "deployment.json",
                 "compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
    if (any((candidate / "workspace" / name).exists() for name in forbidden) or
            not (candidate / "workspace/deployment.pending.json").is_file()):
        raise Error("promotion candidate runnable-state contract changed")
    expected_material = {
        name: {"bytes": len(data), "sha256": sha(data)}
        for name, data in _promotion_scaffold(source_spec, profile, plan["project"]).items()
    }
    for name, record in manifest["files"].items():
        if name.startswith(("private/config/", "private/sources/")):
            expected_material["workspace/" + name[len("private/"):]] = record
    expected_names = set(expected_material) | {"workspace/deployment.pending.json"}
    if set(plan["candidate_files"]) != expected_names:
        raise Error("promotion candidate contains runnable or unexpected artifacts")
    if any(plan["candidate_files"][name] != record for name, record in expected_material.items()):
        raise Error("promotion candidate metadata or source binding mismatch")
    expected_directories = {"workspace", "workspace/data", "workspace/pcaps"} | {
        "workspace/data/" + name for name in (*BACKENDS, "neo")}
    for name in expected_names:
        expected_directories.update(str(parent) for parent in PurePosixPath(name).parents
                                    if str(parent) != ".")
    anchor = ops._root_anchor_identity(candidate.stat())
    actual = set()
    actual_directories = set()
    def walk_error(_error):
        raise Error("promotion candidate filesystem cannot be inspected safely")

    for base, directories, names in os.walk(candidate, followlinks=False, onerror=walk_error):
        for name in directories + names:
            item = Path(base) / name
            metadata = item.lstat()
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise Error("promotion candidate contains a special entry")
            if metadata.st_uid != plan["owner"]["uid"] or metadata.st_gid != plan["owner"]["gid"]:
                raise Error("promotion candidate entry ownership changed")
            if stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) != 0o700:
                raise Error("promotion candidate directory permissions changed")
            if stat.S_ISDIR(metadata.st_mode):
                actual_directories.add(item.relative_to(candidate).as_posix())
            else:
                actual.add(item.relative_to(candidate).as_posix())
    if actual != set(plan["candidate_files"]) | {"promotion-plan.json"}:
        raise Error("promotion candidate inventory changed")
    if actual_directories != expected_directories:
        raise Error("promotion candidate directory scaffold changed")
    for name, expected in plan["candidate_files"].items():
        ops._portable_relative_posix(name, "promotion candidate member")
        if set(expected) != {"bytes", "sha256"}:
            raise Error("invalid promotion candidate inventory record")
        metadata, digest = ops._hash_anchored_regular(candidate, name, anchor, MAX_FILE)
        if expected != {"bytes": metadata.st_size, "sha256": digest}:
            raise Error("promotion candidate file changed")
        expected_mode = 0o644 if name in {"workspace/config/neo-client.yml",
                                         "workspace/config/packmate.properties"} else 0o600
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise Error("promotion candidate file permissions changed")
    pending, pending_raw = ops._read_json(candidate / "workspace/deployment.pending.json", 8 * 1024 * 1024)
    pending_fields = {"schema", "project", "files", "source_pins", "approval_id"}
    ops._strict_keys(pending, pending_fields, pending_fields, "pending deployment")
    expected_pending_files = {name[len("workspace/"):]: record["sha256"]
                              for name, record in plan["candidate_files"].items()
                              if name.startswith("workspace/") and
                              name != "workspace/deployment.pending.json"}
    if (pending["schema"] != kit.SCHEMA or pending["project"] != plan["project"] or
            pending["source_pins"] != kit.shared.PINS or pending["files"] != expected_pending_files or
            not isinstance(pending["approval_id"], str) or
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", pending["approval_id"])):
        raise Error("pending deployment ownership contract changed")
    if (pending_raw != ops._canonical(pending) or
            plan["candidate_files"]["workspace/deployment.pending.json"] !=
            {"bytes": len(pending_raw), "sha256": sha(pending_raw)}):
        raise Error("pending deployment record changed")
    acceptance = None
    if getattr(args, "acceptance", None):
        acceptance = _verify_acceptance(args.acceptance, plan)
    return {"status": "PARTIAL", "action": "verify-promotion", "candidate_integrity": "PASS",
            "application_acceptance_record": "RECORDED_NOT_INDEPENDENTLY_EXECUTED" if acceptance else "NOT_RUN",
            "toolkit_runnable": False, "compose_runnable": False,
            "runnable_artifacts_present": False, "writers_enabled": False, "capture_enabled": False,
            "submission_enabled": False,
            "stage_data_consumed": False, "stage_database_bytes_certified": False,
            "blocked_on": ["independent_runtime_acceptance", "operator_activation"] if acceptance else PROMOTION_BLOCKERS,
            "rollback": "backup and verified stopped stage remain the rollback source"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["backup", "verify", "restore-native-stage", "cleanup-helpers",
                                           "prepare-promotion", "verify-promotion"])
    for name in ("workspace", "backup", "output", "approval-id", "daemon-id", "stage", "stage-project",
                 "acceptance"):
        parser.add_argument("--" + name)
    for name in ("target-uid", "target-gid"):
        parser.add_argument("--" + name, type=int)
    for name in ("apply", "snapshot-confirmed", "maintenance-confirmed", "queue-reviewed", "ttl-reviewed"):
        parser.add_argument("--" + name, action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "backup" and args.workspace and args.output:
            result = backup(args)
        elif args.action == "restore-native-stage" and args.backup and args.output:
            result = restore(args)
        elif args.action == "prepare-promotion" and args.backup and args.stage and args.output and args.stage_project:
            result = prepare_promotion(args)
        elif args.action == "verify-promotion" and args.backup and args.stage and args.output and args.stage_project:
            result = verify_promotion(args)
        elif args.action == "verify" and args.backup:
            verify_backup(args.backup)
            result = {"status": "PASS", "action": "verify", "private_only": True, "runtime": "NOT_RUN"}
        elif args.action == "cleanup-helpers" and args.workspace:
            _root, state, _runtime, _profile, _files = source_workspace(args.workspace)
            if args.apply:
                require_apply(args)
                cleanup_helpers(state["project"], args.daemon_id)
            result = {"status": "PASS" if args.apply else "NOT_RUN", "action": "cleanup-helpers",
                      "scope": "only exact owned cold-read helpers; no source services/data affected"}
        else:
            raise Error("required source/backup/output paths missing")
        print(json.dumps(result, sort_keys=True))
        return 2 if result.get("status") == "PARTIAL" else 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "error": type(error).__name__, "raw_output": "suppressed",
            "source_auto_resume": False, "resume_after_review": RESUME,
            "retained": "source and existing backups are never removed; inspect any newly published quarantine stage"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
