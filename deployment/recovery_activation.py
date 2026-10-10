#!/usr/bin/env python3
"""Restore applications into a NEW stopped deployment; never overwrite a source.

The separate inert promotion scaffold is intentionally not consumed or changed.
Redis is reset in the NEW deployment only, with an explicit data-loss gate:
its original queues, cache and session values remain in the verified backup.
Application acceptance precedes a second, receipt-bound activation approval.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import sys
import time
import urllib.error
import urllib.request

SPEC = importlib.util.spec_from_file_location("activation_recovery", Path(__file__).with_name("recovery.py"))
rec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rec)
kit, ops, Error = rec.kit, rec.ops, rec.Error
SCHEMA = "durkahelper.application-recovery.v1"
ACCEPTANCE = "durkahelper.application-recovery-acceptance.v1"
APPS = ("farm", "front", "neo-server", "packmate")
ACTIVE = tuple(rec.BACKENDS) + APPS
EMPTY_PCAP = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
CHECKS = {"postgres", "packmate-db", "candidate_redis_empty", "runtime_ownership",
          "farm_authenticated", "neo_authenticated", "packmate_authenticated",
          "packmate_capture_stopped", "restart_reconnect", "source_stopped", "stage_stopped"}
LIMITS = ["new candidate Redis state intentionally reset; original RDBs retained in backup",
          "real traffic, team LAN, physical Mac and large-data RPO/RTO not validated",
          "no worker, submission or capture automatically enabled",
          "Neo authentication and native state restored; task execution requires a separate synthetic drill"]


def selected(runtime, names=ACTIVE):
    result = copy.deepcopy(runtime)
    result["services"] = {name: result["services"][name] for name in names}
    return result


def inputs(args, target):
    data = rec._promotion_inputs(args, target)
    backup, manifest, original, spec, runtime, profile, stage = data
    source, state, source_runtime, source_profile, _ = rec.source_workspace(args.workspace)
    if (state != original or source_runtime != runtime or source_profile != profile or
            state["project"] != manifest["source_project"]):
        raise Error("selected source does not match the verified backup")
    rec._separate_promotion_target(target, source)
    return data, (source, state["project"], runtime, args.daemon_id, kit.LABEL)


def require_gates(args):
    rec.require_promotion_apply(args)
    if not args.discard_candidate_redis_state:
        raise Error("requires --discard-candidate-redis-state: new Redis queues, caches and sessions are reset; backup retained")


def stopped(context, *, strict=False):
    current = rec.owned(*context, exclusive=False, strict_networks=strict)
    if any(value["running"] for value in current.values()):
        raise Error("source or verified recovery stage is running; stop it separately before recovery")
    return current


def command(root, state):
    return kit.command(root, state, runtime=True)


def prepare_files(args, target, data):
    backup, manifest, original, spec, runtime, profile, stage = data
    project = "dh-deploy-" + secrets.token_hex(6)
    projected = rec.reproject_spec(spec, project)
    images = kit.image_preflight(runtime, profile)
    kit.check_build_receipt(backup / "private", spec, images)
    projected_runtime = kit.runtime_spec(projected, images)
    context = (target, project, selected(projected_runtime), args.daemon_id, kit.LABEL)
    if rec.owned(*context, exclusive=False, require_no_networks=True):
        raise Error("new candidate project already has Docker resources")
    # The pinned Neo server image currently runs as root. Reject a changed
    # runtime identity rather than broadly chmod/chown restored bbolt files.
    user = json.loads(rec.run(["docker", "image", "inspect", "--format", "{{json .Config.User}}",
                               images["neo-server"]]))
    if user not in ("", "0", "0:0", "root", "root:root"):
        raise Error("unsupported Neo runtime UID/GID; no ownership mutation attempted")
    staging = ops._StagingDirectory.create(target, ".application-recovery-")
    try:
        anchor, total = ops._root_anchor_identity(backup.stat()), [0, rec.MAX_TOTAL]
        for name, expected in sorted(manifest["files"].items()):
            if not name.startswith(("private/config/", "private/sources/")):
                continue
            destination = name[len("private/"):]
            meta, digest = ops._copy_stable(backup, name, (staging, destination), rec.MAX_FILE, total, anchor)
            if expected != {"bytes": meta.st_size, "sha256": digest}:
                raise Error("immutable recovery source changed")
            staging.set_file_metadata(destination, 0o644 if destination in {
                "config/neo-client.yml", "config/packmate.properties"} else 0o600)
        for name in (*rec.BACKENDS, "neo"):
            staging.mkdir("data/" + name)
        staging.mkdir("pcaps")
        # This is a closed empty file, never an automatic capture/import.
        staging.write_new_bytes("pcaps/" + profile["packmate"]["pcap_file"], EMPTY_PCAP, mode=0o644)
        relative = "cold/neo.tar"
        if rec.cold_members(backup / relative, staging=staging, directory="neo", source_root=backup,
                            expected=manifest["files"][relative]) != manifest["cold"]["neo"]:
            raise Error("Neo cold state changed while restoring")
        generated = {"compose.json": projected, "runtime-compose.json": projected_runtime, "profile.json": profile}
        model = kit.model(projected, profile)
        generated.update({"model.json": model, "policy.json": kit.policy(profile, model),
            "build-receipt.json": {"schema": "durkahelper.deployment-build.v2", "images": images,
                "compose_sha256": rec.sha(kit.shared.canonical(projected)),
                "runtime_sha256": rec.sha(kit.shared.canonical(projected_runtime))}})
        for name, value in generated.items():
            staging.write_new_bytes(name, kit.shared.canonical(value))
        files = {name: value["sha256"] for name, value in rec.inventory(staging).items()
                 if not name.startswith(("data/", "pcaps/"))}
        pending = {"schema": kit.SCHEMA, "project": project, "source_pins": kit.shared.PINS,
                   "approval_id": args.approval_id, "files": files}
        staging.write_new_bytes("deployment.pending.json", ops._canonical(pending))
        state = {"schema": SCHEMA, "project": project, "source_project": original["project"],
                 "stage_project": stage[1]["project"], "daemon_id": args.daemon_id,
                 "backup_sha256": rec.sha(ops._canonical(manifest)),
                 "stage_verification_sha256": stage[3]["verification_sha256"],
                 "pending_sha256": rec.sha(ops._canonical(pending)),
                 "owner": {"uid": args.target_uid, "gid": args.target_gid},
                 "redis_policy": "DISCARD_CANDIDATE_ALL_STATE_BACKUP_RETAINED",
                 "neo_runtime_owner": "0:0", "pcap_policy": "EMPTY_CLOSED_FILE_NO_AUTO_IMPORT"}
        staging.write_new_bytes("application-recovery.json", ops._canonical(state))
        # Validate once more before publishing a private, non-toolkit-runnable
        # candidate. No database service has been started at this point.
        if rec.verify_backup(backup)[1] != manifest:
            raise Error("backup changed during application recovery preparation")
        ops._publish_directory(staging, target)
    finally:
        staging.cleanup()
    # Only this exact newly published public-to-container directory needs
    # traversal by UID 65534. Its parent stays operator-only 0700.
    folder = ops._canonical_root_directory(target / "pcaps")
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(fd, 0o755)
    finally:
        os.close(fd)
    return workspace(target)


def workspace(path):
    root = rec.private_root(path)
    state = kit.load(root / "application-recovery.json")
    fields = {"schema", "project", "source_project", "stage_project", "daemon_id", "backup_sha256",
              "stage_verification_sha256", "pending_sha256", "owner", "redis_policy", "neo_runtime_owner", "pcap_policy"}
    ops._strict_keys(state, fields, fields, "application recovery")
    if (state["schema"] != SCHEMA or not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", state["project"]) or
            not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", state["source_project"]) or
            state["project"] == state["source_project"] or
            not re.fullmatch(r"dh-recovery-[a-f0-9]{12}", state["stage_project"]) or
            not re.fullmatch(r"[A-Za-z0-9:_.-]{8,128}", state["daemon_id"]) or
            any(not re.fullmatch(r"[a-f0-9]{64}", state[name]) for name in
                ("backup_sha256", "stage_verification_sha256", "pending_sha256")) or
            state["owner"] != {"uid": root.stat().st_uid, "gid": root.stat().st_gid} or
            state["redis_policy"] != "DISCARD_CANDIDATE_ALL_STATE_BACKUP_RETAINED" or
            state["neo_runtime_owner"] != "0:0" or state["pcap_policy"] != "EMPTY_CLOSED_FILE_NO_AUTO_IMPORT"):
        raise Error("application recovery identity or ownership contract changed")
    pending = kit.load(root / "deployment.pending.json")
    ops._strict_keys(pending, {"schema", "project", "source_pins", "approval_id", "files"},
                     {"schema", "project", "source_pins", "approval_id", "files"}, "pending deployment")
    if (rec.sha(ops._canonical(pending)) != state["pending_sha256"] or pending["schema"] != kit.SCHEMA or
            pending["project"] != state["project"] or pending["source_pins"] != kit.shared.PINS or
            not isinstance(pending["files"], dict) or not 1 <= len(pending["files"]) <= rec.MAX_FILES):
        raise Error("application recovery pending manifest changed")
    anchor = ops._root_anchor_identity(root.stat())
    for name, digest in pending["files"].items():
        ops._portable_relative_posix(name, "pending recovery member")
        if name.startswith(("data/", "pcaps/")) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise Error("invalid recovery immutable member")
        metadata, observed = ops._hash_anchored_regular(root, name, anchor, rec.MAX_FILE)
        if observed != digest or metadata.st_uid != state["owner"]["uid"]:
            raise Error("application recovery immutable input changed")
    for folder in ("data", *["data/" + name for name in (*rec.BACKENDS, "neo")], "pcaps"):
        if ops._canonical_root_directory(root / folder) != root / folder:
            raise Error("linked recovery data directory")
    runtime = rec.maintained_runtime(root, pending, kit.load(root / "compose.json"), kit.validate_profile(kit.load(root / "profile.json")))
    return root, state, pending, runtime, kit.load(root / "profile.json")


def ready(identity, database):
    deadline = time.monotonic() + 60
    while True:
        try:
            if database:
                rec.run(["docker", "exec", identity, "pg_isready", "-h", "127.0.0.1", "-U", database, "-d", database], timeout=5)
            elif rec.run(["docker", "exec", identity, "redis-cli", "--raw", "PING"], timeout=5).strip() != b"PONG":
                raise Error("candidate Redis not ready")
            return
        except Error:
            if time.monotonic() >= deadline:
                raise Error("candidate native database readiness timed out")
            time.sleep(0.5)


def restore_pg(backup, manifest, identity, name, database):
    base = ["docker", "exec", identity, "psql", "-X", "-A", "-t", "-U", database, "-d", database, "-c"]
    if rec.run(base + ["SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';"]).strip() != b"0":
        raise Error("application recovery database is not empty")
    relative = "dumps/" + name + ".dump"
    fd = ops._open_anchored_regular(backup, relative, ops._root_anchor_identity(backup.stat()))
    try:
        before = os.fstat(fd)
        digest = hashlib.sha256()
        for chunk in iter(lambda: os.read(fd, rec.CHUNK), b""):
            digest.update(chunk)
        if manifest["files"][relative] != {"bytes": before.st_size, "sha256": digest.hexdigest()}:
            raise Error("native application restore dump changed before use")
        os.lseek(fd, 0, os.SEEK_SET)
        rec.run(["docker", "exec", "-i", identity, "pg_restore", "-U", database, "-d", database,
                 "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges"], stdin=fd, timeout=300)
        if ops._stat_identity(before) != ops._stat_identity(os.fstat(fd)):
            raise Error("native application restore dump changed during use")
    finally:
        os.close(fd)
    if rec.pg_summary(identity, database) != manifest["databases"][name]:
        raise Error("restored application database differs from verified native backup")


def runtime_ownership(current):
    owners = {}
    for name, database in rec.BACKENDS.items():
        identity = current[name]["id"]
        account = "postgres" if database else "redis"
        uid = rec.run(["docker", "exec", identity, "id", "-u", account]).decode().strip()
        gid = rec.run(["docker", "exec", identity, "id", "-g", account]).decode().strip()
        if not all(re.fullmatch(r"[0-9]{1,10}", value) and 0 < int(value) < 2 ** 31 for value in (uid, gid)):
            raise Error("invalid native database runtime UID/GID")
        path = "/var/lib/postgresql/data" if database else "/data"
        actual = rec.run(["docker", "exec", identity, "stat", "-c", "%u:%g:%a", path]).decode().strip().split(":")
        # Official Redis's entrypoint can change only the owner, retaining the
        # operator's group. A 0700 root is accessible by its runtime UID only;
        # no broad group permission or recursive chmod is required.
        if (len(actual) != 3 or actual[0] != uid or
                not re.fullmatch(r"[0-9]{1,10}", actual[1]) or actual[2] != "700"):
            raise Error("component-native data ownership differs from its runtime account")
        owners[name] = actual[0] + ":" + actual[1]
    owners.update({"neo-server": "0:0", "packmate": "65534:65534"})
    return owners


def stopped_epochs(context):
    current = stopped(context, strict=True)
    result = {}
    for name, item in sorted(current.items()):
        value = json.loads(rec.run(["docker", "inspect", "--format",
            '{"id":{{json .Id}},"running":{{json .State.Running}},"started":{{json .State.StartedAt}},'
            '"finished":{{json .State.FinishedAt}},"restarts":{{json .RestartCount}}}', item["id"]]))
        if (set(value) != {"id", "running", "started", "finished", "restarts"} or value["id"] != item["id"] or
                value["running"] is not False or type(value["restarts"]) is not int or value["restarts"] < 0 or
                any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9T:.Z+-]{20,40}", value[key])
                    for key in ("started", "finished"))):
            raise Error("candidate stopped-container epoch changed during inspection")
        result[name] = value
    return result


def packmate_ready(root, profile, timeout=120):
    pairs = dict(line.split("=", 1) for line in kit.read(root / "config/packmate.properties").decode().splitlines())
    credentials = (pairs["packmate.web.account-login"] + ":" + pairs["packmate.web.account-password"]).encode("ascii")
    headers = {"Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"), "Accept-Encoding": "identity"}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), kit.shared.NoRedirect())
    url = "http://" + profile["bind_address"] + ":" + str(profile["ports"]["packmate"])
    deadline = time.monotonic() + timeout
    while True:
        try:
            values = []
            for path in ("/api/service/", "/api/pcap/started"):
                with opener.open(urllib.request.Request(url + path, headers=headers), timeout=5) as response:
                    data = response.read(1024 * 1024 + 1)
                    if response.status != 200 or len(data) > 1024 * 1024:
                        raise Error("Packmate recovery response rejected; raw data suppressed")
                    values.append(json.loads(data))
            if not isinstance(values[0], list) or values[1] is not False:
                raise Error("Packmate application or stopped-capture acceptance failed")
            return
        except (OSError, ValueError, urllib.error.URLError):
            if time.monotonic() >= deadline:
                raise Error("authenticated Packmate recovery readiness timed out")
            time.sleep(0.5)


def start_and_check(root, state, runtime, profile):
    context = (root, state["project"], selected(runtime), state["daemon_id"], kit.LABEL)
    rec.owned(*context, exclusive=False)
    rec.run(command(root, state) + ["up", "--detach", "--no-build", "--pull", "never", "farm", "front", "packmate"], timeout=180)
    kit.wait_farm(profile, runtime)
    rec.run(command(root, state) + ["up", "--detach", "--no-build", "--pull", "never", "neo-server"], timeout=60)
    kit.wait_neo(root, state, runtime)
    packmate_ready(root, profile)
    observed = rec.wait_strict_owned(context)
    if set(observed) != set(ACTIVE) or not all(value["running"] for value in observed.values()):
        raise Error("application recovery running service set mismatch")


def acceptance(root, state):
    value = kit.load(root / "recovery-acceptance.json")
    fields = {"schema", "project", "recovery_sha256", "checks", "runtime_owners", "redis_policy", "stopped_containers",
              "candidate_stopped", "submission_enabled", "worker_enabled", "capture_enabled", "seconds"}
    ops._strict_keys(value, fields, fields, "application recovery acceptance")
    if (value["schema"] != ACCEPTANCE or value["project"] != state["project"] or
            value["recovery_sha256"] != rec.sha(ops._canonical(state)) or
            not isinstance(value["checks"], dict) or set(value["checks"]) != CHECKS or
            not all(result is True for result in value["checks"].values()) or
            value["redis_policy"] != state["redis_policy"] or value["candidate_stopped"] is not True or
            any(value[key] is not False for key in ("submission_enabled", "worker_enabled", "capture_enabled")) or
            not isinstance(value["runtime_owners"], dict) or set(value["runtime_owners"]) != set(rec.BACKENDS) | {"neo-server", "packmate"} or
            any(not isinstance(owner, str) or not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", owner)
                for owner in value["runtime_owners"].values()) or
            not isinstance(value["stopped_containers"], dict) or set(value["stopped_containers"]) != set(ACTIVE) or
            type(value["seconds"]) not in (int, float) or not 0 <= value["seconds"] <= 86400):
        raise Error("application recovery acceptance is incomplete or not bound to this candidate")
    return value


def recover(args):
    target = ops._safe_output_parent(Path(args.output))
    data, source = inputs(args, target)
    if not args.apply:
        return {"status": "NOT_RUN", "action": "recover", "source_auto_resume": False,
                "redis_policy": "DISCARD_CANDIDATE_ALL_STATE_BACKUP_RETAINED", "limits": LIMITS,
                "effects": ["new native restore", "app authentication and restart checks", "leave candidate stopped and not toolkit-runnable"]}
    require_gates(args)
    stage = data[6]
    stage_context = (stage[0], stage[1]["project"], stage[2], args.daemon_id, rec.LABEL)
    stopped(source)
    stopped(stage_context, strict=True)
    started = time.monotonic()
    root, state, pending, runtime, profile = prepare_files(args, target, data)
    context = (root, state["project"], selected(runtime), args.daemon_id, kit.LABEL)
    checks = {}
    try:
        stopped(source)
        stopped(stage_context, strict=True)
        rec.run(command(root, state) + ["up", "--detach", "--no-build", "--pull", "never"] + list(rec.BACKENDS), timeout=180)
        current = rec.owned(*context, exclusive=False)
        if set(current) != set(rec.BACKENDS):
            raise Error("candidate native restore service set mismatch")
        for name, database in rec.BACKENDS.items():
            identity = current[name]["id"]
            ready(identity, database)
            if database:
                restore_pg(data[0], data[1], identity, name, database)
                checks[name] = True
            elif rec.run(["docker", "exec", identity, "redis-cli", "--raw", "DBSIZE"]).strip() != b"0":
                raise Error("candidate Redis contains state; refusing queue replay")
        checks["candidate_redis_empty"] = True
        owners = runtime_ownership(current)
        checks["runtime_ownership"] = True
        start_and_check(root, state, runtime, profile)
        rec.stop(context, APPS, exclusive=False)
        start_and_check(root, state, runtime, profile)
        checks.update({name: True for name in ("farm_authenticated", "neo_authenticated", "packmate_authenticated",
                                              "packmate_capture_stopped", "restart_reconnect")})
    finally:
        # Reconcile an interrupted Compose create by exact project ownership.
        # A cleanup failure is BLOCKED; no acceptance or runnable manifest exists.
        try:
            kit.cleanup_readiness_probes(state)
        finally:
            # A probe reconciliation failure must not skip stopping the
            # separately owned application stack. Either failure stays BLOCKED.
            rec.stop(context, ACTIVE, exclusive=False)
    epochs = stopped_epochs(context)
    stopped(source)
    stopped(stage_context, strict=True)
    checks.update(source_stopped=True, stage_stopped=True)
    if rec.verify_backup(data[0])[1] != data[1]:
        raise Error("backup changed during application acceptance")
    workspace(root)
    record = {"schema": ACCEPTANCE, "project": state["project"], "recovery_sha256": rec.sha(ops._canonical(state)),
              "checks": checks, "runtime_owners": owners, "stopped_containers": epochs,
              "redis_policy": state["redis_policy"], "candidate_stopped": True,
              "submission_enabled": False, "worker_enabled": False, "capture_enabled": False,
              "seconds": round(time.monotonic() - started, 3)}
    ops._atomic_write_new(root / "recovery-acceptance.json", ops._canonical(record))
    return {"status": "PASS", "action": "recover", "application_acceptance": "PASS", "toolkit_runnable": False,
            "candidate_stopped": True, "acceptance_sha256": rec.sha(ops._canonical(record)), "checks": checks,
            "limits": LIMITS, "next": "review acceptance; explicitly activate with its checksum; then separately toolkit up",
            "rollback": "source, backup, stage and candidate retained stopped; no data removed"}


def activate(args):
    root, state, pending, runtime, profile = workspace(args.output)
    data, source = inputs(args, root)
    record = acceptance(root, state)
    if (state["backup_sha256"] != rec.sha(ops._canonical(data[1])) or
            state["stage_verification_sha256"] != data[6][3]["verification_sha256"] or
            state["daemon_id"] != args.daemon_id):
        raise Error("activation provenance differs from verified recovery inputs")
    if (root / "deployment.json").exists():
        raise Error("candidate is already activated; no manifest overwritten")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "activate", "acceptance_sha256": rec.sha(ops._canonical(record)),
                "effects": ["publish maintained deployment ownership manifest", "no services started"], "limits": LIMITS}
    require_gates(args)
    if not args.activation_confirmed or args.acceptance_sha256 != rec.sha(ops._canonical(record)):
        raise Error("activation requires --activation-confirmed and the reviewed --acceptance-sha256")
    stage = data[6]
    stopped(source)
    stopped((stage[0], stage[1]["project"], stage[2], args.daemon_id, rec.LABEL), strict=True)
    if stopped_epochs((root, state["project"], selected(runtime), args.daemon_id, kit.LABEL)) != record["stopped_containers"]:
        raise Error("candidate restarted or changed after application acceptance; recover into a fresh candidate")
    kit.check_build_receipt(root, kit.load(root / "compose.json"), kit.image_preflight(runtime, profile))
    workspace(root)
    # The no-replace hard link is the final commit. A lost completion response
    # is reconciled by inode identity, never by mere file contents.
    anchor = ops._root_anchor_identity(root.stat())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        if ops._root_anchor_identity(os.fstat(directory)) != anchor:
            raise Error("candidate root changed before activation commit")
        descriptor = os.open("deployment.pending.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        metadata = os.fstat(descriptor)
        raw = b""
        while True:
            part = os.read(descriptor, 65536)
            if not part:
                break
            raw += part
            if len(raw) > 8 * 1024 * 1024:
                raise Error("pending manifest exceeds activation bound")
        before = os.stat("deployment.pending.json", dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != args.target_uid or
                ops._stat_identity(before) != ops._stat_identity(metadata) or
                ops._stat_identity(os.fstat(descriptor)) != ops._stat_identity(metadata) or
                raw != ops._canonical(pending) or rec.sha(raw) != state["pending_sha256"]):
            raise Error("pending deployment identity changed before activation")
        link_error = None
        try:
            os.link("deployment.pending.json", "deployment.json", src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except BaseException as error:
            link_error = error
        # Hold the verified source descriptor through the commit. link(2)
        # resolves its source NAME afresh, so a successful syscall alone does
        # not prove it linked the inode we verified before the call.
        published = None
        final_descriptor = None
        try:
            published = os.stat("deployment.json", dir_fd=directory, follow_symlinks=False)
            final_descriptor = os.open("deployment.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            final_metadata = os.fstat(final_descriptor)
            final_raw = b""
            while True:
                part = os.read(final_descriptor, 65536)
                if not part:
                    break
                final_raw += part
                if len(final_raw) > 8 * 1024 * 1024:
                    raise Error("published activation manifest exceeds bounds")
            if (not stat.S_ISREG(published.st_mode) or
                    ops._stat_identity(final_metadata) != ops._stat_identity(published) or
                    ops._root_anchor_identity(published) != ops._root_anchor_identity(os.fstat(descriptor)) or
                    final_raw != raw or rec.sha(final_raw) != state["pending_sha256"] or
                    ops._stat_identity(os.fstat(final_descriptor)) != ops._stat_identity(final_metadata) or
                    ops._root_anchor_identity(root.stat()) != anchor):
                raise Error("activation source changed at commit; candidate manifest rejected")
        except BaseException:
            if published is not None and link_error is None:
                # Remove only the exact new destination just inspected. Never
                # remove a concurrently replaced destination by pathname alone.
                try:
                    named = os.stat("deployment.json", dir_fd=directory, follow_symlinks=False)
                    if ops._root_anchor_identity(named) == ops._root_anchor_identity(published):
                        os.unlink("deployment.json", dir_fd=directory)
                except OSError:
                    pass
            if link_error is not None:
                raise link_error
            raise
        finally:
            if final_descriptor is not None:
                try:
                    os.close(final_descriptor)
                except OSError:
                    pass
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.fsync(directory)
        except OSError:
            pass
        try:
            os.close(directory)
        except OSError:
            pass
    return {"status": "PASS", "action": "activate", "toolkit_runnable": True, "candidate_stopped": True,
            "services_started": False, "limits": LIMITS,
            "next": "toolkit up on this NEW workspace; submission and worker remain separate explicit decisions",
            "rollback": "toolkit down on this candidate only; source and backup unchanged"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("recover", "verify", "activate", "stop"))
    parser.add_argument("--output", required=True)
    for name in ("workspace", "backup", "stage", "stage-project", "daemon-id", "approval-id", "acceptance-sha256"):
        parser.add_argument("--" + name)
    for name in ("apply", "snapshot-confirmed", "maintenance-confirmed", "queue-reviewed", "ttl-reviewed",
                 "discard-candidate-redis-state", "activation-confirmed"):
        parser.add_argument("--" + name, action="store_true")
    for name in ("target-uid", "target-gid"):
        parser.add_argument("--" + name, type=int)
    args = parser.parse_args(argv)
    try:
        if args.action in {"recover", "activate"}:
            if not all((args.workspace, args.backup, args.stage, args.stage_project, args.daemon_id)):
                raise Error("recover/activate require source workspace, backup, stage, exact stage project and daemon ID")
            result = recover(args) if args.action == "recover" else activate(args)
        else:
            root, state, pending, runtime, profile = workspace(args.output)
            if args.action == "verify":
                record = acceptance(root, state)
                result = {"status": "PASS", "configuration_integrity": "PASS", "runtime": "NOT_RUN",
                          "acceptance_sha256": rec.sha(ops._canonical(record)), "limits": LIMITS}
            elif not args.apply:
                result = {"status": "NOT_RUN", "action": "stop", "effects": ["stop only owned candidate services; retain data"]}
            else:
                rec.require_apply(args)
                if args.daemon_id != state["daemon_id"]:
                    raise Error("stop daemon differs from candidate identity")
                try:
                    kit.cleanup_readiness_probes(state)
                finally:
                    rec.stop((root, state["project"], selected(runtime), args.daemon_id, kit.LABEL), ACTIVE, exclusive=False)
                result = {"status": "PASS", "action": "stop", "data_retained": True}
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error) if isinstance(error, Error) else
                          "recovery rejected: " + type(error).__name__, "raw_output": "suppressed",
                          "rollback": "inspect exact candidate with stop; retain all source/backup/stage data"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
