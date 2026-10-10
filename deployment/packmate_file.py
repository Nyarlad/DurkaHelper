#!/usr/bin/env python3
"""Safely replace one closed PCAP in an existing maintained FILE deployment.

Only Packmate is stopped/restarted. Its database is retained and must already
be running. Processing is NOT started: configure services/patterns, then press
Start once in the UI. A FILE session must be restarted between closed files.
"""
from __future__ import annotations

import argparse
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

SPEC = importlib.util.spec_from_file_location("file_recovery_activation", Path(__file__).with_name("recovery_activation.py"))
activation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(activation)
rec, kit, ops, Error = activation.rec, activation.kit, activation.ops, activation.Error
MAX_BYTES = 512 * 1024 * 1024
MAX_BLOCK = 16 * 1024 * 1024
SCHEMA = "durkahelper.closed-pcap-replacement.v1"


def pcap_summary(descriptor):
    """Bound framing/hash validation, not traffic analysis or content acceptance."""
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or not 24 <= before.st_size <= MAX_BYTES:
        raise Error("closed capture must be a bounded regular file (24 bytes to 512 MiB)")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest, size, packets = hashlib.sha256(), 0, 0
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        def read(count, eof=False):
            nonlocal size
            value = stream.read(count)
            size += len(value)
            if size > MAX_BYTES or (len(value) != count and not (eof and not value)):
                raise Error("capture framing is truncated or exceeds byte bounds")
            digest.update(value)
            return value

        def discard(count):
            while count:
                take = min(count, 65536)
                read(take)
                count -= take

        magic = read(4)
        classic = {b"\xd4\xc3\xb2\xa1": ("<", 1000000), b"\xa1\xb2\xc3\xd4": (">", 1000000),
                   b"\x4d\x3c\xb2\xa1": ("<", 1000000000), b"\xa1\xb2\x3c\x4d": (">", 1000000000)}
        if magic in classic:
            endian, resolution = classic[magic]
            major, minor, zone, accuracy, snaplen, linktype = struct.unpack(endian + "HHIIII", read(20))
            if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_BLOCK:
                raise Error("unsupported PCAP version or snapshot length")
            while True:
                header = read(16, eof=True)
                if not header:
                    break
                seconds, fraction, captured, original = struct.unpack(endian + "IIII", header)
                if captured > min(snaplen, original) or fraction >= resolution:
                    raise Error("invalid PCAP packet lengths or timestamp framing")
                discard(captured)
                packets += 1
                if packets > 2_000_000:
                    raise Error("PCAP packet count exceeds bound")
            kind = "PCAP"
        elif magic == b"\x0a\x0d\x0d\x0a":
            endian, blocks, block_type = None, 0, magic
            while block_type:
                length_raw = read(4)
                if block_type == magic:
                    bom = read(4)
                    endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
                    if endian is None:
                        raise Error("invalid PCAPNG byte order marker")
                    length = struct.unpack(endian + "I", length_raw)[0]
                    if not 28 <= length <= MAX_BLOCK or length % 4:
                        raise Error("invalid PCAPNG section length")
                    version = read(4)
                    if struct.unpack(endian + "HH", version) != (1, 0):
                        raise Error("unsupported PCAPNG section version")
                    discard(length - 20)
                else:
                    length = struct.unpack(endian + "I", length_raw)[0]
                    if not 12 <= length <= MAX_BLOCK or length % 4:
                        raise Error("invalid PCAPNG block length")
                    number = struct.unpack(endian + "I", block_type)[0]
                    if number in {2, 3, 6}:
                        packets += 1
                    discard(length - 12)
                if struct.unpack(endian + "I", read(4))[0] != length:
                    raise Error("PCAPNG block footer mismatch")
                blocks += 1
                if blocks > 2_000_000:
                    raise Error("PCAPNG block count exceeds bound")
                block_type = read(4, eof=True)
            kind = "PCAPNG"
        else:
            raise Error("input is not a supported closed PCAP/PCAPNG container")
    if ops._stat_identity(before) != ops._stat_identity(os.fstat(descriptor)) or size != before.st_size:
        raise Error("capture changed while validating; close the writer and record a new checksum")
    return before, {"format": kind, "bytes": size, "sha256": digest.hexdigest(), "packet_records": packets,
                    "validation": "container framing only; upstream import acceptance not run"}


def inspect_file(path, expected=None):
    source = ops._canonical_input_leaf(Path(path))
    descriptor = ops._open_anchored_regular(source.parent, source.name, ops._root_anchor_identity(source.parent.stat()))
    try:
        metadata, summary = pcap_summary(descriptor)
    finally:
        os.close(descriptor)
    if expected is not None and summary["sha256"] != expected:
        raise Error("closed capture does not match independently recorded SHA-256")
    return source, metadata, summary


def gates(args):
    if not args.approval_id or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.approval_id):
        raise Error("replacement requires a non-secret approval ID")
    if not args.closed_pcap_confirmed or not args.maintenance_confirmed:
        raise Error("replacement requires closed capture and exclusive file-maintenance confirmations")
    if os.name != "posix" or os.geteuid() == 0:
        raise Error("FILE replacement requires a non-root POSIX operator")
    rec.daemon(args.daemon_id)


def stage_files(root, source, summary, previous, previous_summary):
    target = root / ("pcap-import-" + secrets.token_hex(8))
    staging = ops._StagingDirectory.create(target, ".closed-pcap-")
    try:
        for source_path, destination, expected in ((source, "incoming.pcap", summary), (previous, "previous.pcap", previous_summary)):
            metadata, digest = ops._copy_stable(source_path.parent, source_path.name, (staging, destination), MAX_BYTES,
                                               [0, MAX_BYTES], ops._root_anchor_identity(source_path.parent.stat()))
            if metadata.st_size != expected["bytes"] or digest != expected["sha256"]:
                raise Error("closed capture changed while creating immutable replacement/rollback copies")
        receipt = {"schema": SCHEMA, "configured_file": previous.name, "incoming": summary, "previous": previous_summary}
        staging.write_new_bytes("replacement.json", ops._canonical(receipt))
        ops._publish_directory(staging, target)
    finally:
        staging.cleanup()
    return target


def cutover(root, configured_name, transaction, expected_previous, expected_new):
    """Descriptor-anchored cutover, with a retained immutable rollback copy."""
    folder = ops._canonical_root_directory(root / "pcaps")
    anchor = ops._root_anchor_identity(folder.stat())
    directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source_fd = new_fd = old_fd = None
    temporary = ".pcap-next-" + secrets.token_hex(12)
    new_identity = None
    try:
        if ops._root_anchor_identity(os.fstat(directory)) != anchor:
            raise Error("configured capture directory changed")
        old_fd = os.open(configured_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        old_meta, old_summary = pcap_summary(old_fd)
        if old_summary != expected_previous:
            raise Error("previous configured capture changed before cutover")
        source_fd = ops._open_anchored_regular(transaction, "incoming.pcap", ops._root_anchor_identity(transaction.stat()))
        _, source_summary = pcap_summary(source_fd)
        if source_summary != expected_new:
            raise Error("immutable incoming capture changed before cutover")
        os.lseek(source_fd, 0, os.SEEK_SET)
        new_fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        new_identity = ops._root_anchor_identity(os.fstat(new_fd))
        copied = 0
        for chunk in iter(lambda: os.read(source_fd, 65536), b""):
            copied += len(chunk)
            if copied > min(MAX_BYTES, expected_new["bytes"]):
                raise Error("immutable incoming capture grew during copy")
            ops._write_all(new_fd, chunk)
        os.fchmod(new_fd, 0o644)
        os.fsync(new_fd)
        _, staged_summary = pcap_summary(new_fd)
        if staged_summary != expected_new:
            raise Error("incoming copy changed before cutover")
        named = os.stat(configured_name, dir_fd=directory, follow_symlinks=False)
        if (ops._stat_identity(named) != ops._stat_identity(old_meta) or
                ops._stat_identity(os.fstat(old_fd)) != ops._stat_identity(old_meta) or
                ops._root_anchor_identity(os.stat(temporary, dir_fd=directory, follow_symlinks=False)) != new_identity or
                ops._root_anchor_identity(folder.stat()) != anchor):
            raise Error("capture path changed before cutover; rollback retained")
        replace_error = None
        try:
            os.replace(temporary, configured_name, src_dir_fd=directory, dst_dir_fd=directory)
        except BaseException as error:
            replace_error = error
        named = os.stat(configured_name, dir_fd=directory, follow_symlinks=False)
        if ops._root_anchor_identity(named) != new_identity:
            if replace_error is not None:
                raise replace_error
            raise Error("capture destination changed at cutover; app must remain stopped; rollback retained")
        descriptor = os.open(configured_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            final_meta, final_summary = pcap_summary(descriptor)
            if ops._root_anchor_identity(final_meta) != new_identity or final_summary != expected_new:
                raise Error("capture destination bytes changed at cutover; app must remain stopped")
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        for descriptor in (source_fd, new_fd, old_fd):
            if descriptor is not None:
                os.close(descriptor)
        if new_identity is not None:
            try:
                named = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                if ops._root_anchor_identity(named) == new_identity:
                    os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def replace(args):
    if not isinstance(args.expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", args.expected_sha256):
        raise Error("an independently recorded lower-case SHA-256 is required")
    root, state, runtime, profile, _ = rec.source_workspace(args.workspace)
    source, _, summary = inspect_file(args.pcap, args.expected_sha256)
    previous, _, previous_summary = inspect_file(root / "pcaps" / profile["packmate"]["pcap_file"])
    if source == previous:
        raise Error("incoming capture must be separate from the configured current file")
    if not args.apply:
        return {"status": "NOT_RUN", "action": "replace", "daemon_contacted": False, "incoming": summary,
                "effects": ["stop only Packmate", "retain private previous capture", "atomic file replacement", "restart only Packmate"],
                "processing": "NOT_RUN; configure service/patterns then press Start once"}
    gates(args)
    context = (root, state["project"], runtime, args.daemon_id, kit.LABEL)
    current = rec.owned(*context, exclusive=False)
    if not current.get("packmate-db", {}).get("running"):
        raise Error("owned Packmate database must already be running; this helper never starts dependencies")
    kit.image_preflight({"services": {"packmate": runtime["services"]["packmate"]}}, profile)
    transaction = None
    succeeded = False
    try:
        rec.stop(context, ("packmate",), exclusive=False)
        transaction = stage_files(root, source, summary, previous, previous_summary)
        if rec.source_workspace(root)[2] != runtime:
            raise Error("maintained deployment changed during file replacement")
        current = rec.owned(*context, exclusive=False)
        if current.get("packmate", {}).get("running") or not current.get("packmate-db", {}).get("running"):
            raise Error("Packmate was restarted or database stopped while staging; no file replaced")
        cutover(root, previous.name, transaction, previous_summary, summary)
        current = rec.owned(*context, exclusive=False)
        if current.get("packmate", {}).get("running") or not current.get("packmate-db", {}).get("running"):
            raise Error("candidate Packmate was restarted or database stopped during maintenance")
        rec.run(kit.command(root, state, runtime=True) + ["up", "--detach", "--no-deps", "--no-build", "--pull", "never", "packmate"], timeout=120)
        activation.packmate_ready(root, profile)
        current = rec.owned(*context, exclusive=False)
        if not current.get("packmate", {}).get("running") or not current.get("packmate-db", {}).get("running"):
            raise Error("Packmate readiness is not bound to owned running resources")
        inspect_file(previous, summary["sha256"])
        succeeded = True
    finally:
        if not succeeded:
            rec.stop(context, ("packmate",), exclusive=False)
    return {"status": "PASS", "action": "replace", "authenticated_ready": True, "capture_started": False,
            "incoming": summary, "processing": "NOT_RUN; configure services/patterns then press Start once",
            "database": "retained; importing overlapping captures may create duplicate stored traffic",
            "rollback": {"relative_input": transaction.name + "/previous.pcap", "sha256": previous_summary["sha256"],
                         "procedure": "run this same explicit replacement command with previous.pcap and its checksum"},
            "limits": ["container framing checked, not upstream packet compatibility", "FILE is not continuous LIVE capture"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("replace",))
    for name in ("workspace", "pcap", "expected-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("approval-id", "daemon-id"):
        parser.add_argument("--" + name)
    for name in ("apply", "closed-pcap-confirmed", "maintenance-confirmed"):
        parser.add_argument("--" + name, action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(replace(args), sort_keys=True, indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error) if isinstance(error, Error) else
                          "closed capture replacement rejected: " + type(error).__name__, "raw_output": "suppressed",
                          "rollback": "inspect private pcap-import-* copies; do not delete them; restart only after a verified replacement"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
