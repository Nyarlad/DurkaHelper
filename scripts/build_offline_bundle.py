#!/usr/bin/env python3
"""Build or verify a deterministic, offline DurkaHelper source bundle."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zlib


SCHEMA = "durkahelper.offline-bundle.v1"
MANIFEST_NAME = "MANIFEST.json"
MAX_GIT_LIST_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 20_000
MAX_PAX_BYTES = 32 * 1024
MAX_RAW_TAR_HEADERS = MAX_MEMBERS * 2 + 2
CHUNK = 1024 * 1024

FORBIDDEN_COMPONENTS = {
    ".cache", ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".ssh",
    "__pycache__", ".codex-remote-attachments", "artifacts", "cache", "local", "logs", "secrets", "upstream",
}
FORBIDDEN_SUFFIXES = {
    ".accdb", ".cap", ".db", ".db3", ".jks", ".kdb", ".kdbx", ".key",
    ".keystore", ".log", ".mdb", ".p12", ".p7b", ".p8", ".pcap",
    ".pcapng", ".pem", ".pfx", ".pkcs8", ".ppk", ".secret", ".secrets",
    ".sqlite", ".sqlite3", ".wal",
}
WINDOWS_RESERVED = {
    "aux", "clock$", "con", "nul", "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
PRIVATE_KEY_HEADER = re.compile(br"-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY-----")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
ROOT_NAME = re.compile(r"DurkaHelper-([0-9a-f]{12})\Z")
LOWER_HEX = frozenset("0123456789abcdef")


class BundleError(Exception):
    """Expected failure whose message is safe to show to an operator."""


def _canonical_json(value) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BundleError("manifest contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise BundleError("manifest contains a non-finite number")


def _identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        getattr(metadata, "st_ctime_ns", 0),
    )


def _is_lower_hex(value: str, length: int) -> bool:
    """Validate a fixed-size Git identifier without compiling a dynamic regex."""
    return len(value) == length and all(character in LOWER_HEX for character in value)


def _has_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_relative_path(value: str, *, repository_path=True) -> str:
    if (not isinstance(value, str) or not value or len(value) > 4096 or
            value.startswith("/") or "\\" in value or ":" in value or
            _has_control(value) or unicodedata.normalize("NFC", value) != value):
        raise BundleError("bundle contains an unsafe path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BundleError("bundle contains an unsafe path")
    for part in parts:
        if (part.endswith((" ", ".")) or len(part.encode("utf-8")) > 255 or
                part.split(".", 1)[0].casefold() in WINDOWS_RESERVED):
            raise BundleError("bundle contains a non-portable path")
    if not repository_path:
        return value

    folded_parts = [part.casefold() for part in parts]
    if any(part in FORBIDDEN_COMPONENTS for part in folded_parts):
        raise BundleError("tracked forbidden path")
    name = parts[-1].casefold()
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        raise BundleError("tracked environment file")
    if (any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES) or
            any(marker in name for marker in (".db-", ".sqlite-", ".sqlite3-"))):
        raise BundleError("tracked sensitive or runtime-data file")
    if name in {"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}:
        raise BundleError("tracked private-key file")
    if value.casefold() == MANIFEST_NAME.casefold():
        raise BundleError("tracked path collides with bundle manifest")
    return value


def _canonical_parent_with_leaf(path: Path) -> Path:
    """Resolve legitimate ancestor links while preserving the final entry."""
    absolute = Path(os.path.abspath(path))
    try:
        parent = absolute.parent.resolve(strict=True)
    except PermissionError as exc:
        # Managed Windows sandboxes can deny realpath queries even when normal
        # file access succeeds.  Leaf no-follow checks still apply below.
        if os.name != "nt":
            raise BundleError("path parent is unavailable") from exc
        parent = absolute.parent
    except (OSError, RuntimeError) as exc:
        raise BundleError("path parent is unavailable") from exc
    if not parent.is_dir():
        raise BundleError("path parent is unavailable")
    return parent / absolute.name


def _reject_symlink_leaf(path: Path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BundleError("path metadata is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise BundleError("path leaf is a symbolic link")


def _worktree_identity(root: Path, relative: str):
    current = root
    parts = relative.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BundleError("tracked worktree path is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise BundleError("tracked path contains a symbolic link")
        if index + 1 == len(parts):
            if not stat.S_ISREG(metadata.st_mode):
                raise BundleError("tracked path is not a regular file")
            return _identity(metadata)
        if not stat.S_ISDIR(metadata.st_mode):
            raise BundleError("tracked path has a non-directory parent")
    raise BundleError("invalid tracked path")


def _git_environment():
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.upper().startswith("GIT_"):
            environment.pop(name, None)
    environment["GIT_ATTR_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_PAGER"] = "cat"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


def _git_command(git: str, arguments):
    return [git, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *arguments]


def _run_git(git: str, root: Path, arguments, *, limit=MAX_GIT_LIST_BYTES) -> bytes:
    try:
        completed = subprocess.run(
            _git_command(git, arguments),
            cwd=root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BundleError("local Git inspection failed") from exc
    if completed.returncode != 0:
        raise BundleError("local Git inspection failed")
    if len(completed.stdout) > limit:
        raise BundleError("local Git metadata exceeds limit")
    return completed.stdout


def _repository(git: str):
    current = Path.cwd()
    inside = _run_git(git, current, ["rev-parse", "--is-inside-work-tree"], limit=64)
    if inside.strip() != b"true":
        raise BundleError("current directory is not a Git worktree")
    raw_root = _run_git(git, current, ["rev-parse", "--show-toplevel"], limit=16 * 1024)
    try:
        root_text = os.fsdecode(raw_root.rstrip(b"\r\n"))
    except UnicodeError as exc:
        raise BundleError("Git worktree path is not decodable") from exc
    if not root_text or _has_control(root_text):
        raise BundleError("Git worktree path is unsafe")
    absolute_root = Path(os.path.abspath(root_text))
    try:
        root = absolute_root.resolve(strict=True)
    except PermissionError as exc:
        if os.name != "nt":
            raise BundleError("Git worktree root is unavailable") from exc
        root = absolute_root
    except (OSError, RuntimeError) as exc:
        raise BundleError("Git worktree root is unavailable") from exc
    if not root.is_dir():
        raise BundleError("Git worktree root is unavailable")
    expected_script = root / "scripts" / "build_offline_bundle.py"
    try:
        if not os.path.samefile(Path(__file__), expected_script):
            raise BundleError("builder must run from its repository")
    except OSError as exc:
        raise BundleError("builder must run from its repository") from exc
    return root


def _assert_clean(git: str, root: Path):
    index = _run_git(git, root, ["ls-files", "-v", "-z"])
    if index and not index.endswith(b"\0"):
        raise BundleError("Git index listing is invalid")
    for record in index.split(b"\0"):
        if record and (len(record) < 3 or record[:2] != b"H "):
            raise BundleError("Git index contains special tracked-file flags")
    status = _run_git(
        git,
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=no",
         "--ignore-submodules=none"],
    )
    if status:
        raise BundleError("tracked files or index differ from HEAD")


def _parse_tree(raw: bytes, object_format: str):
    if raw and not raw.endswith(b"\0"):
        raise BundleError("invalid Git tree listing")
    digest_length = hashlib.new(object_format).digest_size * 2
    entries = []
    paths = set()
    folded_paths = set()
    total = 0
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.split()
            path = raw_path.decode("utf-8", "strict")
        except (UnicodeError, ValueError) as exc:
            raise BundleError("invalid Git tree entry") from exc
        if object_type != b"blob" or mode not in {b"100644", b"100755"}:
            raise BundleError("tracked symlink, submodule, or special entry")
        try:
            size = int(raw_size)
        except ValueError as exc:
            raise BundleError("invalid Git blob size") from exc
        if size < 0 or size > MAX_MEMBER_BYTES:
            raise BundleError("tracked file exceeds bundle limit")
        try:
            object_text = object_id.decode("ascii")
        except UnicodeError as exc:
            raise BundleError("invalid Git object identifier") from exc
        if not _is_lower_hex(object_text, digest_length):
            raise BundleError("invalid Git object identifier")
        path = _validate_relative_path(path)
        folded = path.casefold()
        if path in paths or folded in folded_paths:
            raise BundleError("duplicate or case-colliding tracked path")
        paths.add(path)
        folded_paths.add(folded)
        total += size
        if len(entries) >= MAX_MEMBERS - 2 or total > MAX_TOTAL_BYTES:
            raise BundleError("tracked tree exceeds bundle limits")
        entries.append({
            "git_mode": mode.decode("ascii"),
            "mode": 0o755 if mode == b"100755" else 0o644,
            "object": object_text,
            "path": path,
            "size": size,
        })
    if not entries:
        raise BundleError("Git HEAD contains no regular files")
    entries.sort(key=lambda item: item["path"])
    return entries


def _git_snapshot(git: str, root: Path):
    _assert_clean(git, root)
    try:
        object_format = _run_git(
            git, root, ["rev-parse", "--show-object-format"], limit=32
        ).strip().decode("ascii")
    except UnicodeError as exc:
        raise BundleError("invalid Git object format") from exc
    if object_format not in {"sha1", "sha256"}:
        raise BundleError("unsupported Git object format")
    try:
        commit = _run_git(
            git, root, ["rev-parse", "--verify", "HEAD^{commit}"], limit=128
        ).strip().decode("ascii")
        commit_time_text = _run_git(
            git, root, ["show", "-s", "--format=%ct", commit], limit=64
        ).strip().decode("ascii")
        commit_time = int(commit_time_text)
    except (UnicodeError, ValueError) as exc:
        raise BundleError("invalid Git commit metadata") from exc
    expected_length = hashlib.new(object_format).digest_size * 2
    if (not _is_lower_hex(commit, expected_length) or
            not 0 <= commit_time <= 0xFFFFFFFF):
        raise BundleError("invalid Git commit metadata")
    tree_raw = _run_git(
        git, root, ["ls-tree", "-r", "-z", "-l", "--full-tree", commit]
    )
    entries = _parse_tree(tree_raw, object_format)
    if "scripts/build_offline_bundle.py" not in {item["path"] for item in entries}:
        raise BundleError("builder is not tracked in HEAD")
    worktree = {item["path"]: _worktree_identity(root, item["path"]) for item in entries}
    return {
        "commit": commit,
        "commit_time": commit_time,
        "entries": entries,
        "object_format": object_format,
        "tree_raw": tree_raw,
        "worktree": worktree,
    }


def _assert_snapshot_unchanged(git: str, root: Path, snapshot):
    _assert_clean(git, root)
    current_commit = _run_git(
        git, root, ["rev-parse", "--verify", "HEAD^{commit}"], limit=128
    ).strip()
    if current_commit != snapshot["commit"].encode("ascii"):
        raise BundleError("Git HEAD changed during bundle creation")
    current_tree = _run_git(
        git, root,
        ["ls-tree", "-r", "-z", "-l", "--full-tree", snapshot["commit"]],
    )
    if current_tree != snapshot["tree_raw"]:
        raise BundleError("Git tree changed during bundle creation")
    for path, before in snapshot["worktree"].items():
        if _worktree_identity(root, path) != before:
            raise BundleError("tracked worktree changed during bundle creation")


class _BlobReader:
    def __init__(self, stream, size: int, object_format: str):
        self.stream = stream
        self.remaining = size
        self.sha256 = hashlib.sha256()
        self.object_hash = hashlib.new(object_format)
        self.object_hash.update(f"blob {size}\0".encode("ascii"))
        self.private_key = False
        self.tail = b""

    def read(self, size=-1):
        if self.remaining == 0:
            return b""
        if size is None or size < 0 or size > self.remaining:
            size = self.remaining
        data = self.stream.read(size)
        if not data:
            raise BundleError("Git object read was incomplete")
        self.remaining -= len(data)
        self.sha256.update(data)
        self.object_hash.update(data)
        inspected = self.tail + data
        if PRIVATE_KEY_HEADER.search(inspected):
            self.private_key = True
        self.tail = inspected[-128:]
        return data


def _tar_info(name: str, *, size: int, mode: int, mtime: int, entry_type):
    info = tarfile.TarInfo(name)
    info.type = entry_type
    info.size = size
    info.mode = mode
    info.mtime = mtime
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.linkname = ""
    info.devmajor = 0
    info.devminor = 0
    info.pax_headers = {}
    return info


def _add_git_blob(archive, git: str, root: Path, root_name: str, entry, object_format: str,
                  commit_time: int):
    command = _git_command(git, ["cat-file", "blob", entry["object"]])
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
    except OSError as exc:
        raise BundleError("could not read a local Git object") from exc
    if process.stdout is None:
        process.kill()
        raise BundleError("could not read a local Git object")
    reader = _BlobReader(process.stdout, entry["size"], object_format)
    info = _tar_info(
        f"{root_name}/{entry['path']}",
        size=entry["size"],
        mode=entry["mode"],
        mtime=commit_time,
        entry_type=tarfile.REGTYPE,
    )
    try:
        archive.addfile(info, reader)
        try:
            return_code = process.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise BundleError("local Git object read timed out") from exc
        extra = process.stdout.read(1)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    if return_code != 0 or reader.remaining != 0 or extra:
        raise BundleError("local Git object read was unstable")
    if reader.object_hash.hexdigest() != entry["object"]:
        raise BundleError("local Git object hash mismatch")
    if reader.private_key:
        raise BundleError("tracked file contains private-key material")
    return {
        "git_mode": entry["git_mode"],
        "mode": entry["mode"],
        "path": entry["path"],
        "sha256": reader.sha256.hexdigest(),
        "size": entry["size"],
    }


def _prepare_output(value: Path):
    if not str(value).endswith(".tar.gz"):
        raise BundleError("output must end with .tar.gz")
    output = _canonical_parent_with_leaf(value)
    if _has_control(output.name):
        raise BundleError("output filename is unsafe")
    parent = output.parent
    sidecar = Path(str(output) + ".sha256")
    _reject_symlink_leaf(output)
    _reject_symlink_leaf(sidecar)
    if os.path.lexists(output) or os.path.lexists(sidecar):
        raise BundleError("output or checksum sidecar already exists")
    return output, sidecar


def _hash_regular_file(path: Path, limit: int):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError("regular file is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise BundleError("regular file exceeds limit")
        digest = hashlib.sha256()
        consumed = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                consumed += len(block)
                if consumed > limit:
                    raise BundleError("regular file exceeds limit")
                digest.update(block)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after) or consumed != before.st_size:
            raise BundleError("regular file changed while reading")
        return digest.hexdigest(), _identity(before)
    finally:
        os.close(descriptor)


def _write_sidecar(path: Path, archive_name: str, archive_sha256: str):
    descriptor, temporary_name = tempfile.mkstemp(prefix=".durkahelper-sidecar-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        payload = f"{archive_sha256}  {archive_name}\n".encode("utf-8")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        return temporary
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _unlink_if_same(path: Path, temporary: Path):
    try:
        if os.path.samefile(path, temporary):
            path.unlink()
    except OSError:
        pass


def _publish_pair(archive_temporary: Path, output: Path, sidecar_temporary: Path,
                  sidecar: Path):
    linked_sidecar = False
    linked_archive = False
    try:
        if os.path.lexists(output) or os.path.lexists(sidecar):
            raise BundleError("output or checksum sidecar already exists")
        os.link(sidecar_temporary, sidecar)
        linked_sidecar = True
        os.link(archive_temporary, output)
        linked_archive = True
        try:
            directory_descriptor = os.open(output.parent, os.O_RDONLY)
        except OSError:
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            except OSError:
                pass
            finally:
                os.close(directory_descriptor)
    except (OSError, BundleError) as exc:
        if linked_archive:
            _unlink_if_same(output, archive_temporary)
        if linked_sidecar:
            _unlink_if_same(sidecar, sidecar_temporary)
        if isinstance(exc, BundleError):
            raise
        raise BundleError("filesystem cannot atomically publish bundle") from exc


def build_bundle(output_value: Path):
    output, sidecar = _prepare_output(output_value)
    git = shutil.which("git")
    if git is None:
        raise BundleError("Git is required")
    root = _repository(git)
    snapshot = _git_snapshot(git, root)
    root_name = "DurkaHelper-" + snapshot["commit"][:12]

    descriptor, temporary_name = tempfile.mkstemp(prefix=".durkahelper-bundle-",
                                                   suffix=".tmp", dir=output.parent)
    temporary = Path(temporary_name)
    sidecar_temporary = None
    manifest_entries = []
    try:
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        with os.fdopen(descriptor, "wb") as raw_stream:
            with gzip.GzipFile(filename="", mode="wb", compresslevel=9,
                               fileobj=raw_stream, mtime=snapshot["commit_time"]) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|",
                                  format=tarfile.PAX_FORMAT, encoding="utf-8",
                                  errors="strict") as archive:
                    archive.addfile(_tar_info(
                        root_name,
                        size=0,
                        mode=0o755,
                        mtime=snapshot["commit_time"],
                        entry_type=tarfile.DIRTYPE,
                    ))
                    for entry in snapshot["entries"]:
                        manifest_entries.append(_add_git_blob(
                            archive, git, root, root_name, entry,
                            snapshot["object_format"], snapshot["commit_time"]
                        ))
                    total_bytes = sum(item["size"] for item in manifest_entries)
                    manifest = {
                        "commit": snapshot["commit"],
                        "commit_time": snapshot["commit_time"],
                        "files": manifest_entries,
                        "root": root_name,
                        "schema": SCHEMA,
                        "summary": {
                            "files": len(manifest_entries),
                            "total_bytes": total_bytes,
                        },
                    }
                    manifest_payload = _canonical_json(manifest)
                    if len(manifest_payload) > MAX_MANIFEST_BYTES:
                        raise BundleError("bundle manifest exceeds limit")
                    archive.addfile(
                        _tar_info(
                            f"{root_name}/{MANIFEST_NAME}",
                            size=len(manifest_payload),
                            mode=0o644,
                            mtime=snapshot["commit_time"],
                            entry_type=tarfile.REGTYPE,
                        ),
                        fileobj=_BytesReader(manifest_payload),
                    )
            raw_stream.flush()
            os.fsync(raw_stream.fileno())

        _assert_snapshot_unchanged(git, root, snapshot)
        archive_sha256, _archive_identity = _hash_regular_file(temporary, MAX_ARCHIVE_BYTES)
        sidecar_temporary = _write_sidecar(
            sidecar, output.name, archive_sha256
        )
        _publish_pair(temporary, output, sidecar_temporary, sidecar)
        return {
            "archive_sha256": archive_sha256,
            "files": len(manifest_entries),
            "root": root_name,
            "status": "created",
        }
    finally:
        for path in (temporary, sidecar_temporary):
            if path is not None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass


class _BytesReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.data) - self.offset
        end = min(self.offset + size, len(self.data))
        result = self.data[self.offset:end]
        self.offset = end
        return result


def _strict_gzip_chunks(raw_stream):
    """Yield one gzip member and reject concatenated or trailing raw data."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    while True:
        compressed = raw_stream.read(CHUNK)
        if not compressed:
            break
        pending = compressed
        while pending:
            try:
                payload = decompressor.decompress(pending, CHUNK)
            except zlib.error as exc:
                raise BundleError("archive gzip stream is invalid") from exc
            pending = decompressor.unconsumed_tail
            if decompressor.eof:
                if decompressor.unused_data or pending or raw_stream.read(1):
                    raise BundleError("archive has concatenated or trailing gzip data")
                try:
                    flushed = decompressor.flush()
                except zlib.error as exc:
                    raise BundleError("archive gzip stream is invalid") from exc
                if payload:
                    yield payload
                if flushed:
                    yield flushed
                return
            if payload:
                yield payload
            if not pending:
                break
    raise BundleError("archive gzip stream is truncated")


class _ChunkStream:
    """Small bounded buffer over a byte-chunk iterator."""
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.buffer = bytearray()
        self.finished = False

    def read(self, size: int) -> bytes:
        if size < 0:
            raise BundleError("invalid archive stream read")
        while len(self.buffer) < size and not self.finished:
            try:
                block = next(self.chunks)
            except StopIteration:
                self.finished = True
                break
            if block:
                self.buffer.extend(block)
        take = min(size, len(self.buffer))
        result = bytes(self.buffer[:take])
        del self.buffer[:take]
        return result


def _read_exact(stream: _ChunkStream, size: int, message: str) -> bytes:
    value = stream.read(size)
    if len(value) != size:
        raise BundleError(message)
    return value


def _consume_stream(stream: _ChunkStream, size: int, *, require_zero=False):
    remaining = size
    while remaining:
        block = _read_exact(
            stream, min(CHUNK, remaining), "archive tar stream is truncated"
        )
        if require_zero and block.strip(b"\0"):
            raise BundleError("archive tar padding is not canonical")
        remaining -= len(block)


def _tar_octal(field: bytes, label: str) -> int:
    value = field.rstrip(b"\0 ")
    if not value or any(character < ord("0") or character > ord("7") for character in value):
        raise BundleError("archive tar " + label + " is invalid")
    try:
        return int(value, 8)
    except ValueError as exc:
        raise BundleError("archive tar " + label + " is invalid") from exc


def _validate_tar_header(block: bytes):
    recorded = _tar_octal(block[148:156], "checksum")
    calculated = sum(block[:148]) + (ord(" ") * 8) + sum(block[156:])
    if recorded != calculated:
        raise BundleError("archive tar header checksum is invalid")
    return _tar_octal(block[124:136], "size"), block[156:157]


def _validate_strict_gzip_tar(raw_stream):
    """Validate the raw wrapper and canonical tar framing without extracting."""
    stream = _ChunkStream(_strict_gzip_chunks(raw_stream))
    zero_block = b"\0" * tarfile.BLOCKSIZE
    raw_headers = 0
    regular_bytes = 0
    pax_bytes = 0
    pending_pax = False
    offset = 0

    while True:
        header = _read_exact(stream, tarfile.BLOCKSIZE, "archive tar end marker is missing")
        offset += tarfile.BLOCKSIZE
        if header == zero_block:
            second = _read_exact(
                stream, tarfile.BLOCKSIZE, "archive tar end marker is incomplete"
            )
            offset += tarfile.BLOCKSIZE
            if second != zero_block or pending_pax:
                raise BundleError("archive tar end marker is invalid")
            canonical_size = (
                (offset + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE
            ) * tarfile.RECORDSIZE
            _consume_stream(stream, canonical_size - offset, require_zero=True)
            if stream.read(1):
                raise BundleError("archive has data after the canonical tar end")
            return

        raw_headers += 1
        if raw_headers > MAX_RAW_TAR_HEADERS:
            raise BundleError("archive raw tar header limit exceeded")
        size, entry_type = _validate_tar_header(header)
        if entry_type == tarfile.XHDTYPE:
            if pending_pax or size > MAX_PAX_BYTES:
                raise BundleError("archive PAX header is invalid or too large")
            pending_pax = True
            pax_bytes += size
            if pax_bytes > MAX_MEMBERS * MAX_PAX_BYTES:
                raise BundleError("archive PAX data exceeds limit")
        elif entry_type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
            pending_pax = False
            if size > MAX_MEMBER_BYTES:
                raise BundleError("archive member exceeds byte limit")
            regular_bytes += size
            if regular_bytes > MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES:
                raise BundleError("archive regular data exceeds byte limit")
        elif entry_type == tarfile.DIRTYPE:
            pending_pax = False
            if size != 0:
                raise BundleError("archive directory has data")
        else:
            raise BundleError("archive contains an unsupported raw tar entry")

        _consume_stream(stream, size)
        padding = (-size) % tarfile.BLOCKSIZE
        _consume_stream(stream, padding, require_zero=True)
        offset += size + padding


def _read_sidecar(path: Path, archive_name: str):
    path = _canonical_parent_with_leaf(path)
    if not os.path.lexists(path):
        return None
    _reject_symlink_leaf(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BundleError("checksum sidecar is unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 4096:
            raise BundleError("checksum sidecar is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(4097)
        after = os.fstat(descriptor)
        if (_identity(before) != _identity(after) or len(raw) != before.st_size or
                len(raw) > 4096):
            raise BundleError("checksum sidecar changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise BundleError("checksum sidecar is invalid") from exc
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\n?", value)
    if match is None or match.group(2) != archive_name:
        raise BundleError("checksum sidecar is invalid")
    return match.group(1)


def _scan_member(stream, size: int, *, retain=False):
    digest = hashlib.sha256()
    remaining = size
    content = bytearray() if retain else None
    tail = b""
    private_key = False
    while remaining:
        block = stream.read(min(CHUNK, remaining))
        if not block:
            raise BundleError("archive member is truncated")
        remaining -= len(block)
        digest.update(block)
        inspected = tail + block
        if PRIVATE_KEY_HEADER.search(inspected):
            private_key = True
        tail = inspected[-128:]
        if content is not None:
            content.extend(block)
    if stream.read(1):
        raise BundleError("archive member exceeds declared size")
    if private_key:
        raise BundleError("archive contains private-key material")
    return digest.hexdigest(), bytes(content) if content is not None else None


def _validate_member_metadata(member):
    if (member.uid != 0 or member.gid != 0 or member.uname not in {"", None} or
            member.gname not in {"", None} or member.linkname or
            member.devmajor != 0 or member.devminor != 0):
        raise BundleError("archive member metadata is not deterministic")
    if member.pax_headers:
        if set(member.pax_headers) != {"path"} or member.pax_headers["path"] != member.name:
            raise BundleError("archive contains unexpected extended metadata")


def _parse_manifest(raw: bytes, root_name: str):
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BundleError("bundle manifest is invalid") from exc
    required = {"schema", "commit", "commit_time", "root", "files", "summary"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != SCHEMA:
        raise BundleError("bundle manifest schema is invalid")
    if (not isinstance(value["commit"], str) or not COMMIT_ID.fullmatch(value["commit"]) or
            type(value["commit_time"]) is not int or
            not 0 <= value["commit_time"] <= 0xFFFFFFFF or
            value["root"] != root_name):
        raise BundleError("bundle manifest commit metadata is invalid")
    root_match = ROOT_NAME.fullmatch(root_name)
    if root_match is None or root_match.group(1) != value["commit"][:12]:
        raise BundleError("bundle root does not match manifest commit")
    if not isinstance(value["files"], list) or not 1 <= len(value["files"]) <= MAX_MEMBERS - 2:
        raise BundleError("bundle manifest file list is invalid")
    expected = {}
    folded_paths = set()
    total = 0
    previous = None
    for item in value["files"]:
        keys = {"git_mode", "mode", "path", "sha256", "size"}
        if not isinstance(item, dict) or set(item) != keys:
            raise BundleError("bundle manifest file entry is invalid")
        path = _validate_relative_path(item.get("path"))
        folded = path.casefold()
        if path in expected or folded in folded_paths or (previous is not None and path <= previous):
            raise BundleError("bundle manifest paths are not unique and sorted")
        folded_paths.add(folded)
        previous = path
        mode = item.get("mode")
        git_mode = item.get("git_mode")
        expected_git_mode = "100755" if mode == 0o755 else "100644" if mode == 0o644 else None
        if (git_mode != expected_git_mode or type(item.get("size")) is not int or
                not 0 <= item["size"] <= MAX_MEMBER_BYTES or
                not isinstance(item.get("sha256"), str) or
                not HEX_DIGEST.fullmatch(item["sha256"])):
            raise BundleError("bundle manifest file metadata is invalid")
        total += item["size"]
        if total > MAX_TOTAL_BYTES:
            raise BundleError("bundle manifest exceeds byte limit")
        expected[path] = item
    summary = value["summary"]
    if (not isinstance(summary, dict) or set(summary) != {"files", "total_bytes"} or
            summary["files"] != len(expected) or summary["total_bytes"] != total):
        raise BundleError("bundle manifest summary is invalid")
    return value, expected


def verify_bundle(archive_value: Path):
    if not str(archive_value).endswith(".tar.gz"):
        raise BundleError("archive must end with .tar.gz")
    archive_path = _canonical_parent_with_leaf(archive_value)
    _reject_symlink_leaf(archive_path)
    if not archive_path.is_file():
        raise BundleError("archive is unavailable")
    sidecar_path = Path(str(archive_path) + ".sha256")
    sidecar_digest = _read_sidecar(sidecar_path, archive_path.name)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(archive_path, flags)
    except OSError as exc:
        raise BundleError("archive is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or
                before.st_size > MAX_ARCHIVE_BYTES):
            raise BundleError("archive size is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            digest = hashlib.sha256()
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                digest.update(block)
            archive_sha256 = digest.hexdigest()
            if sidecar_digest is not None and sidecar_digest != archive_sha256:
                raise BundleError("archive checksum does not match sidecar")
            stream.seek(0)
            gzip_header = stream.read(10)
            if (len(gzip_header) != 10 or gzip_header[:3] != b"\x1f\x8b\x08" or
                    gzip_header[3] != 0 or gzip_header[8:] != b"\x02\xff"):
                raise BundleError("archive gzip header is invalid")
            gzip_mtime = int.from_bytes(gzip_header[4:8], "little")
            stream.seek(0)
            _validate_strict_gzip_tar(stream)
            stream.seek(0)

            root_name = None
            root_metadata = None
            manifest_raw = None
            manifest_metadata = None
            actual = {}
            member_names = []
            exact_names = set()
            folded_names = set()
            total = 0
            try:
                with tarfile.open(fileobj=stream, mode="r:gz", encoding="utf-8",
                                  errors="strict") as archive:
                    if archive.pax_headers:
                        raise BundleError("archive contains global extended metadata")
                    for member in archive:
                        if len(member_names) >= MAX_MEMBERS:
                            raise BundleError("archive member limit exceeded")
                        name = _validate_relative_path(member.name, repository_path=False)
                        folded = name.casefold()
                        if name in exact_names or folded in folded_names:
                            raise BundleError("archive contains duplicate member names")
                        exact_names.add(name)
                        folded_names.add(folded)
                        member_names.append(name)
                        _validate_member_metadata(member)

                        if root_name is None:
                            if member.type != tarfile.DIRTYPE or ROOT_NAME.fullmatch(name) is None:
                                raise BundleError("archive does not start with one safe root")
                            if member.size != 0 or member.mode != 0o755:
                                raise BundleError("archive root metadata is invalid")
                            root_name = name
                            root_metadata = member
                            continue
                        prefix = root_name + "/"
                        if not name.startswith(prefix):
                            raise BundleError("archive member escapes bundle root")
                        relative = name[len(prefix):]
                        if member.type != tarfile.REGTYPE or member.sparse is not None:
                            raise BundleError("archive contains a link or special member")
                        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                            raise BundleError("archive member exceeds byte limit")
                        source = archive.extractfile(member)
                        if source is None:
                            raise BundleError("archive member is unreadable")
                        if relative == MANIFEST_NAME:
                            if manifest_raw is not None or member.size > MAX_MANIFEST_BYTES:
                                raise BundleError("archive manifest is missing or duplicated")
                            _manifest_hash, manifest_raw = _scan_member(
                                source, member.size, retain=True
                            )
                            manifest_metadata = member
                            continue
                        relative = _validate_relative_path(relative)
                        if member.mode not in {0o644, 0o755}:
                            raise BundleError("archive file mode is invalid")
                        total += member.size
                        if total > MAX_TOTAL_BYTES:
                            raise BundleError("archive exceeds uncompressed byte limit")
                        sha256, _unused = _scan_member(source, member.size)
                        actual[relative] = {
                            "mode": member.mode,
                            "mtime": member.mtime,
                            "sha256": sha256,
                            "size": member.size,
                        }
            except (tarfile.TarError, EOFError, UnicodeError) as exc:
                raise BundleError("archive structure is invalid") from exc

            after = os.fstat(descriptor)
            if _identity(before) != _identity(after):
                raise BundleError("archive changed while verifying")
    finally:
        os.close(descriptor)

    if root_name is None or root_metadata is None or manifest_raw is None or manifest_metadata is None:
        raise BundleError("archive root or manifest is missing")
    manifest, expected = _parse_manifest(manifest_raw, root_name)
    commit_time = manifest["commit_time"]
    if gzip_mtime != commit_time:
        raise BundleError("gzip timestamp does not match commit")
    for metadata in (root_metadata, manifest_metadata):
        if metadata.mtime != commit_time:
            raise BundleError("archive member timestamp does not match commit")
    if manifest_metadata.mode != 0o644:
        raise BundleError("archive manifest mode is invalid")
    if set(actual) != set(expected):
        raise BundleError("archive members do not match manifest")
    for path, wanted in expected.items():
        found = actual[path]
        if (found["mode"] != wanted["mode"] or found["size"] != wanted["size"] or
                found["sha256"] != wanted["sha256"] or found["mtime"] != commit_time):
            raise BundleError("archive member does not match manifest")
    expected_order = [root_name]
    expected_order.extend(f"{root_name}/{path}" for path in expected)
    expected_order.append(f"{root_name}/{MANIFEST_NAME}")
    if member_names != expected_order:
        raise BundleError("archive member order is not deterministic")
    return {
        "archive_sha256": archive_sha256,
        "files": len(expected),
        "root": root_name,
        "sidecar": sidecar_digest is not None,
        "status": "verified",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path, metavar="ARCHIVE.tar.gz")
    group.add_argument("--verify", type=Path, metavar="ARCHIVE")
    args = parser.parse_args(argv)
    try:
        result = build_bundle(args.output) if args.output is not None else verify_bundle(args.verify)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except BundleError as exc:
        print(f"offline bundle: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"offline bundle: operation failed ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
