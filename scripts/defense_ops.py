#!/usr/bin/env python3
"""Bounded, read-only-by-default defense operations for DurkaHelper.

The profile format is declarative: it cannot name commands or executable
arguments.  Platform inventory adapters and every subprocess argument are
hardcoded in this file.  Mutating operations only create new local artifacts
and never overwrite an existing path.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import datetime as dt
import fnmatch
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


VERSION = "2.2.0"
TOOL = "DurkaHelper defense_ops"

PROFILE_SCHEMA = "durkahelper.profile.v1"
SNAPSHOT_SCHEMA = "durkahelper.snapshot.v1"
COMPARISON_SCHEMA = "durkahelper.comparison.v1"
BACKUP_SCHEMA = "durkahelper.backup-manifest.v1"
EVENT_SCHEMA = "durkahelper.event.v1"
VALIDATION_SCHEMA = "durkahelper.validation-record.v1"
APPROVED_DRIFT_SCHEMA = "durkahelper.approved-drift.v1"
SNAPSHOT_SCOPE_SCHEMA = "durkahelper.snapshot-scope.v1"
SNAPSHOT_TOOL_COMPATIBILITY = "durkahelper-defense-ops-major-2"
SCANNER_SCOPE_SCHEMA = "durkahelper.scanner-scope.v1"
SCANNER_SCOPE_V2 = "durkahelper.scanner-scope.v2"
SCANNER_PATH_SEMANTICS = "root-relative-posix.v1"
DEPLOYMENT_MODEL_SCHEMA = "durkahelper.deployment-model.v1"
DEPLOYMENT_POLICY_SCHEMA = "durkahelper.deployment-policy.v1"
DEPLOYMENT_AUDIT_SCHEMA = "durkahelper.deployment-audit.v1"

ADAPTER_SEMANTICS = {
    "platform": "platform-system-machine-release-python-v1",
    "processes": "process-name-uid-count-v1",
    "listeners": "listener-endpoint-no-pid-v1",
    "services": "service-state-no-pid-v1",
    "compose": "compose-explicit-project-config-hash-service-state-v1",
}

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_PROFILE_BYTES = 1024 * 1024
MAX_EVENTS = 100_000
MAX_EVENT_LINE = 1024 * 1024
MAX_HTTP_BODY = 1024 * 1024
MAX_ADAPTER_OUTPUT = 8 * 1024 * 1024
MAX_COMPOSE_FILE_BYTES = 16 * 1024 * 1024
CHUNK = 1024 * 1024
MAX_IMPORTED_FILE_BYTES = 4 * 1024 ** 3
MAX_IMPORTED_TOTAL_BYTES = 100 * 1024 ** 3
MAX_MTIME_NS = 253402300799999999999
DIRECTORY_STAGING_SUPPORTED = os.name == "posix"
ATOMIC_DIRFD_SUPPORTED = all(function in os.supports_dir_fd for function in
                             (os.open, os.stat, os.link, os.unlink))
DIRECTORY_DIRFD_SUPPORTED = all(function in os.supports_dir_fd for function in
                                (os.open, os.mkdir, os.stat, os.unlink, os.rmdir))

DEFAULT_ADAPTERS = ("platform", "processes", "listeners", "services")
ADAPTERS = DEFAULT_ADAPTERS + ("compose",)
COMMAND_KEYS = {
    "arg", "args", "argv", "cmd", "command", "commands", "exec",
    "executable", "hook", "program", "script", "shell", "subprocess",
}
SECRET_KEY = re.compile(
    r"password|passwd|pwd|secret|token|credential|authorization|cookie|"
    r"privatekey|apikey|accesskey|session|dsn|connectionstring", re.I)
SECRET_NAME = re.compile(
    r"(^|[._-])(secret|secrets|credential|credentials|token|tokens|password|"
    r"passwd|private[._-]?key)([._-]|$)", re.I)
SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.I),
)
LIVE_DATABASE_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".rdb", ".aof")
NATIVE_DUMP_SUFFIXES = (
    ".sql", ".dump", ".backup", ".bak", ".tar", ".gz", ".zst",
    ".xz", ".bz2", ".rdb",
)
SAFE_EVIDENCE_EXTENSIONS = (".json", ".jsonl")
SNAPSHOT_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "__pycache__", ".cache", "artifacts", "dist", "build", "target", "obj", "bin",
    ".ssh", ".aws", ".gnupg", ".kube",
}
APPROVAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,127}\Z")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z")
OPAQUE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class DefenseError(Exception):
    """Expected, sanitized validation or safety failure."""


class PartialError(DefenseError):
    """A requested read-only observation could not be completed."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DefenseError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise DefenseError("non-finite JSON number")


def _canonical(value) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _bounded_canonical(value, limit=MAX_JSON_BYTES, field="JSON artifact") -> bytes:
    payload = _canonical(value)
    if len(payload) > limit:
        raise PartialError(field + " exceeds byte limit")
    return payload


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _tool_record():
    return {"name": TOOL, "version": VERSION}


def _is_regular(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _canonical_parent_with_leaf(path: Path) -> Path:
    """Resolve existing ancestor links while leaving the final name untouched."""
    absolute = Path(os.path.abspath(path))
    try:
        parent = absolute.parent.resolve(strict=True)
    except PermissionError as exc:
        # Some managed Windows sandboxes deny realpath queries even when the
        # directory itself is readable.  Absolute NT paths still preserve the
        # leaf no-follow/no-overwrite checks used below.
        if os.name != "nt":
            raise DefenseError("path parent is unavailable") from exc
        parent = absolute.parent
    except (OSError, RuntimeError) as exc:
        raise DefenseError("path parent is unavailable") from exc
    if not parent.is_dir():
        raise DefenseError("path parent must be a directory")
    return parent / absolute.name


def _canonical_input_leaf(path: Path) -> Path:
    """Canonicalize ancestors but reject an input whose final entry is a link."""
    absolute = Path(os.path.abspath(path))
    try:
        if absolute.is_symlink():
            raise DefenseError("input leaf cannot be a symlink")
    except OSError as exc:
        raise DefenseError("path metadata unavailable") from exc
    canonical = _canonical_parent_with_leaf(absolute)
    try:
        if canonical.is_symlink():
            raise DefenseError("input leaf cannot be a symlink")
    except OSError as exc:
        raise DefenseError("path metadata unavailable") from exc
    return canonical


def _canonical_root_directory(path: Path) -> Path:
    """Resolve ancestor aliases while rejecting a symlink supplied as the root."""
    absolute = Path(os.path.abspath(path))
    try:
        metadata = absolute.lstat()
    except (OSError, RuntimeError) as exc:
        raise DefenseError("root path is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise DefenseError("root leaf cannot be a symlink")
    try:
        canonical = absolute if os.name == "nt" else absolute.parent.resolve(strict=True) / absolute.name
    except PermissionError as exc:
        if os.name != "nt":
            raise DefenseError("root path is unavailable") from exc
        canonical = absolute
    except (OSError, RuntimeError) as exc:
        raise DefenseError("root path is unavailable") from exc
    try:
        canonical_metadata = canonical.lstat()
    except OSError as exc:
        raise DefenseError("root path is unavailable") from exc
    if stat.S_ISLNK(canonical_metadata.st_mode):
        raise DefenseError("root leaf cannot be a symlink")
    if ((metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)) !=
            (canonical_metadata.st_dev, canonical_metadata.st_ino,
             stat.S_IFMT(canonical_metadata.st_mode))):
        raise DefenseError("root changed during canonicalization")
    if not canonical.is_dir():
        raise DefenseError("root must be a directory")
    return canonical


def _read_regular_bytes(path, limit=MAX_JSON_BYTES) -> bytes:
    path = _canonical_input_leaf(Path(path))
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise DefenseError("unreadable input") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise DefenseError("input is not a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        if len(data) > limit:
            raise DefenseError("input exceeds byte limit")
        if _stat_identity(before) != _stat_identity(after):
            raise DefenseError("input changed while reading")
        return data
    finally:
        os.close(fd)


def _read_json(path, limit=MAX_JSON_BYTES):
    raw = _read_regular_bytes(path, limit)
    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant), raw
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DefenseError("invalid JSON input") from exc


def _stat_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, getattr(value, "st_ctime_ns", 0))


def _safe_string(value, field, minimum=1, maximum=4096):
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or "\x00" in value:
        raise DefenseError("invalid " + field)
    return value


def _positive_int(value, field, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise DefenseError("invalid " + field)
    return value


def _positive_float_value(value, field="timeout", maximum=60.0):
    if type(value) not in (int, float):
        raise DefenseError("invalid " + field)
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= maximum:
        raise DefenseError("invalid " + field)
    return number


def _strict_keys(value, allowed, required=(), field="object"):
    if not isinstance(value, dict) or set(value) - set(allowed) or not set(required) <= set(value):
        raise DefenseError("invalid " + field + " fields")


def _normalized_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _reject_declarative_hazards(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if _normalized_key(key) in COMMAND_KEYS or SECRET_KEY.search(_normalized_key(key)):
                raise DefenseError("profile contains a forbidden field")
            _reject_declarative_hazards(child)
    elif isinstance(value, list):
        for child in value:
            _reject_declarative_hazards(child)


def _relative_posix(value, field="path", *, allow_dot=False) -> str:
    _safe_string(value, field, 1, 1024)
    if unicodedata.normalize("NFC", value) != value:
        raise DefenseError("non-NFC relative " + field)
    if "\\" in value or ":" in value or value.startswith("/"):
        raise DefenseError("invalid relative " + field)
    parts = value.split("/")
    if (any(part in {"", ".."} for part in parts) or
            any(part == "." for part in parts) and not (allow_dot and value == ".")):
        raise DefenseError("invalid relative " + field)
    if value == "." and not allow_dot:
        raise DefenseError("invalid relative " + field)
    return PurePosixPath(value).as_posix()


def _portable_relative_posix(value, field="path", *, allow_dot=False) -> str:
    normalized = _relative_posix(value, field, allow_dot=allow_dot)
    if normalized == ".":
        return normalized
    for component in normalized.split("/"):
        if (component.endswith((".", " ")) or
                any(ord(character) < 32 or character in '<>"|?*' for character in component)):
            raise DefenseError("nonportable relative " + field)
        stem = component.split(".", 1)[0].rstrip(" .").upper()
        if stem in WINDOWS_RESERVED_NAMES:
            raise DefenseError("reserved relative " + field)
    return normalized


def _portable_path_key(value):
    return unicodedata.normalize("NFC", value).casefold()


def _opaque_text_identifier(value) -> str:
    return "sha256:" + _sha256_bytes(value.encode("utf-8", errors="surrogatepass"))


def _opaque_root_identifier(root: Path) -> str:
    normalized = unicodedata.normalize("NFC", os.path.normcase(str(root)))
    return _opaque_text_identifier("durkahelper-root-v1\x00" + normalized)


def _relative_glob(value, field="glob") -> str:
    _safe_string(value, field, 1, 512)
    if unicodedata.normalize("NFC", value) != value:
        raise DefenseError("non-NFC relative " + field)
    if "\\" in value or ":" in value or value.startswith("/") or "\x00" in value:
        raise DefenseError("invalid relative " + field)
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise DefenseError("invalid relative " + field)
    return value


def _safe_output_target(path: Path):
    target = _canonical_parent_with_leaf(Path(path))
    try:
        parent_metadata = target.parent.lstat()
    except OSError as exc:
        raise DefenseError("output parent is unavailable") from exc
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
        raise DefenseError("output parent must be a real directory")
    if target.exists() or target.is_symlink():
        raise DefenseError("output already exists")
    parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino,
                       stat.S_IFMT(parent_metadata.st_mode))
    return target, parent_identity


def _safe_output_parent(path: Path):
    return _safe_output_target(path)[0]


def _atomic_write_new(path, data: bytes, mode=0o600):
    target, expected_parent_identity = _safe_output_target(Path(path))
    if os.name != "nt":
        if (not ATOMIC_DIRFD_SUPPORTED or not hasattr(os, "O_DIRECTORY") or
                not hasattr(os, "O_NOFOLLOW")):
            raise DefenseError("filesystem lacks safe atomic publication support")
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temporary_name = None
        try:
            if _root_anchor_identity(os.fstat(parent_fd)) != expected_parent_identity:
                raise DefenseError("output parent changed during validation")
            try:
                os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise DefenseError("output already exists")
            for _attempt in range(16):
                candidate = ".defense-" + secrets.token_hex(16)
                try:
                    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_BINARY", 0), mode, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            else:
                raise DefenseError("could not reserve temporary output")
            try:
                _write_all(fd, data)
                os.fsync(fd)
                try:
                    os.fchmod(fd, mode)
                except OSError:
                    pass
            finally:
                os.close(fd)
            try:
                os.link(temporary_name, target.name, src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd, follow_symlinks=False)
            except FileExistsError as exc:
                raise DefenseError("output already exists") from exc
            os.unlink(temporary_name, dir_fd=parent_fd)
            temporary_name = None
            os.fsync(parent_fd)
            return target
        finally:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)

    if _root_anchor_identity(target.parent.lstat()) != expected_parent_identity:
        raise DefenseError("output parent changed during validation")
    fd, temporary_name = tempfile.mkstemp(prefix=".defense-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(mode)
        except OSError:
            pass
        try:
            if os.name == "nt":
                # Windows rename is an atomic no-replace operation for a new
                # destination.  Hard links may be denied in managed sandboxes.
                os.rename(temporary, target)
                temporary = None
            else:
                # link(2) is atomic and fails when the destination already
                # exists, unlike POSIX rename(2), which would replace it.
                os.link(temporary, target, follow_symlinks=False)
        except (OSError, NotImplementedError) as exc:
            if target.exists() or target.is_symlink():
                raise DefenseError("output already exists") from exc
            if os.name == "nt" and isinstance(exc, PermissionError):
                # Some managed Windows sandboxes prohibit rename/link inside
                # their virtual Temp directory.  CREATE_NEW still preserves
                # the critical no-overwrite property; delete on any short
                # write so a partial result is never retained.
                direct_fd = None
                created = False
                created_identity = None
                try:
                    direct_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                        getattr(os, "O_BINARY", 0), mode)
                    created = True
                    metadata = os.fstat(direct_fd)
                    created_identity = (metadata.st_dev, metadata.st_ino)
                    with os.fdopen(direct_fd, "wb") as direct:
                        direct_fd = None
                        direct.write(data)
                        direct.flush()
                        os.fsync(direct.fileno())
                    try:
                        target.chmod(mode)
                    except OSError:
                        pass
                    return target
                except OSError as direct_exc:
                    if direct_fd is not None:
                        os.close(direct_fd)
                    if created:
                        try:
                            current = target.lstat()
                            if (current.st_dev, current.st_ino) == created_identity:
                                target.unlink()
                        except OSError:
                            pass
                    raise DefenseError("filesystem cannot create output safely") from direct_exc
            raise DefenseError("filesystem cannot atomically create output") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return target


def _publication_items(temporary: Path):
    items = sorted(temporary.iterdir(), key=lambda item: item.name)
    count = 0
    for item in items:
        try:
            metadata = item.lstat()
        except OSError as exc:
            raise DefenseError("temporary publication is unreadable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise DefenseError("temporary publication contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            for root, directories, files in os.walk(item, followlinks=False):
                count += len(directories) + len(files)
                if count > 100_000:
                    raise PartialError("temporary publication entry limit reached")
                for name in directories + files:
                    candidate = Path(root) / name
                    candidate_metadata = candidate.lstat()
                    if (stat.S_ISLNK(candidate_metadata.st_mode) or
                            not (stat.S_ISREG(candidate_metadata.st_mode) or
                                 stat.S_ISDIR(candidate_metadata.st_mode))):
                        raise DefenseError("temporary publication contains a special entry")
        elif not stat.S_ISREG(metadata.st_mode):
            raise DefenseError("temporary publication contains a special entry")
    manifests = [item for item in items if item.name == "manifest.json"]
    ordinary = [item for item in items if item.name != "manifest.json"]
    return ordinary + manifests


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


class _StagingDirectory:
    """Private output tree anchored to the directory descriptors that created it."""

    def __init__(self, target, path, parent_identity, identity, *, parent_fd=None,
                 directory_fd=None):
        self.target = target
        self.path = path
        self.name = path.name
        self.parent_identity = parent_identity
        self.identity = identity
        self.parent_fd = parent_fd
        self.directory_fd = directory_fd
        self.ledger = {}
        self.consumed = False
        self.closed = False

    @classmethod
    def create(cls, target: Path, prefix: str):
        target, parent_identity = _safe_output_target(Path(target))
        if not DIRECTORY_STAGING_SUPPORTED:
            raise PartialError("secure directory staging is unavailable on Windows")
        if (not DIRECTORY_DIRFD_SUPPORTED or not hasattr(os, "O_DIRECTORY") or
                not hasattr(os, "O_NOFOLLOW")):
            raise DefenseError("filesystem lacks safe staging support")
        parent_metadata = target.parent.lstat()
        if (parent_metadata.st_uid != os.geteuid() or
                stat.S_IMODE(parent_metadata.st_mode) & 0o022):
            raise PartialError("staging parent is not owner-controlled")
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_fd = None
        name = None
        created_identity = None
        try:
            if _root_anchor_identity(os.fstat(parent_fd)) != parent_identity:
                raise DefenseError("output parent changed during validation")
            try:
                os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise DefenseError("output already exists")
            for _attempt in range(16):
                candidate = prefix + secrets.token_hex(16)
                try:
                    os.mkdir(candidate, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                name = candidate
                created = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISDIR(created.st_mode) or stat.S_ISLNK(created.st_mode):
                    raise DefenseError("staging creation did not produce a directory")
                created_identity = _root_anchor_identity(created)
                break
            else:
                raise DefenseError("could not reserve staging directory")
            directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=parent_fd)
            identity = _root_anchor_identity(os.fstat(directory_fd))
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if identity != created_identity or _root_anchor_identity(current) != identity:
                raise DefenseError("staging directory changed during creation")
            return cls(target, target.parent / name, parent_identity, identity,
                       parent_fd=parent_fd, directory_fd=directory_fd)
        except BaseException:
            if directory_fd is not None:
                os.close(directory_fd)
            if name is not None and created_identity is not None:
                try:
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if _root_anchor_identity(current) == created_identity:
                        os.rmdir(name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)
            raise

    def _assert_open(self):
        if self.closed:
            raise DefenseError("staging directory is closed")

    def _assert_named_identity(self):
        self._assert_open()
        if self.parent_fd is not None:
            self._assert_parent_path_identity()
            if _root_anchor_identity(os.fstat(self.parent_fd)) != self.parent_identity:
                raise DefenseError("staging parent changed")
            current = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            if _root_anchor_identity(current) != self.identity:
                raise DefenseError("staging directory changed")
            if _root_anchor_identity(os.fstat(self.directory_fd)) != self.identity:
                raise DefenseError("staging descriptor changed")
            return
        if (_root_anchor_identity(self.path.parent.lstat()) != self.parent_identity or
                _root_anchor_identity(self.path.lstat()) != self.identity):
            raise DefenseError("staging directory changed")

    def _assert_parent_path_identity(self):
        self._assert_open()
        try:
            current = self.target.parent.lstat()
        except OSError as exc:
            raise DefenseError("staging parent path is unavailable") from exc
        if _root_anchor_identity(current) != self.parent_identity:
            raise DefenseError("staging parent path changed")

    def _relative_parts(self, relative):
        normalized = _portable_relative_posix(str(relative), "staging path")
        if normalized == ".":
            raise DefenseError("staging path must name an entry")
        return normalized, normalized.split("/")

    def _open_parent_fd(self, parts, create):
        current_fd = os.dup(self.directory_fd)
        traversed = []
        try:
            for part in parts:
                traversed.append(part)
                relative = "/".join(traversed)
                created = False
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=current_fd)
                        created = True
                    except FileExistsError:
                        pass
                before = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                    raise DefenseError("staging parent entry is not a directory")
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=current_fd)
                identity = _root_anchor_identity(os.fstat(next_fd))
                after = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if (_root_anchor_identity(before) != identity or
                        _root_anchor_identity(after) != identity):
                    os.close(next_fd)
                    raise DefenseError("staging directory changed during traversal")
                record = self.ledger.get(relative)
                if created:
                    if record is not None:
                        os.close(next_fd)
                        raise DefenseError("duplicate staging directory")
                    self.ledger[relative] = ("directory", identity, identity, True)
                elif (record is None or record[0] != "directory" or
                      record[1] != identity):
                    os.close(next_fd)
                    raise DefenseError("untracked staging directory")
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except BaseException:
            os.close(current_fd)
            raise

    def mkdir(self, relative):
        _normalized, parts = self._relative_parts(relative)
        if self.directory_fd is not None:
            self._assert_named_identity()
            descriptor = self._open_parent_fd(parts, True)
            os.close(descriptor)
            return
        self._assert_named_identity()
        destination = self.path.joinpath(*parts)
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._assert_named_identity()

    def open_new_file(self, relative, mode=0o600):
        normalized, parts = self._relative_parts(relative)
        self._assert_named_identity()
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        if self.directory_fd is not None:
            parent_fd = self._open_parent_fd(parts[:-1], True)
            try:
                descriptor = os.open(parts[-1], flags, mode, dir_fd=parent_fd)
                metadata = os.fstat(descriptor)
                named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                identity = _stat_identity(metadata)
                anchor = _root_anchor_identity(metadata)
                if (not stat.S_ISREG(metadata.st_mode) or
                        _stat_identity(named) != identity or normalized in self.ledger):
                    os.close(descriptor)
                    raise DefenseError("staging file changed during creation")
                self.ledger[normalized] = ("file", anchor, identity, False)
                return descriptor
            finally:
                os.close(parent_fd)
        destination = self.path.joinpath(*parts)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._assert_named_identity()
        return os.open(destination, flags, mode)

    def write_new_bytes(self, relative, payload: bytes, mode=0o600):
        normalized, _parts = self._relative_parts(relative)
        descriptor = self.open_new_file(relative, mode)
        try:
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            if hasattr(os, "fchmod"):
                try:
                    os.fchmod(descriptor, mode)
                except OSError:
                    pass
            self._finalize_file_record(normalized, descriptor)
        finally:
            os.close(descriptor)

    def _finalize_file_record(self, normalized, descriptor):
        record = self.ledger.get(normalized)
        if record is None or record[0] != "file":
            raise DefenseError("untracked staging file")
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or
                _root_anchor_identity(metadata) != record[1]):
            raise DefenseError("staging file identity changed")
        parts = normalized.split("/")
        parent_fd = self._open_parent_fd(parts[:-1], False)
        try:
            named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)
        identity = _stat_identity(metadata)
        if _stat_identity(named) != identity:
            raise DefenseError("staging file changed during finalization")
        self.ledger[normalized] = ("file", record[1], identity, True)

    def set_file_metadata(self, relative, mode, mtime_ns=None):
        normalized, parts = self._relative_parts(relative)
        self._assert_named_identity()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        if self.directory_fd is not None:
            parent_fd = self._open_parent_fd(parts[:-1], False)
            try:
                descriptor = os.open(parts[-1], flags, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        else:
            descriptor = os.open(self.path.joinpath(*parts), flags)
        try:
            metadata = os.fstat(descriptor)
            record = self.ledger.get(normalized)
            if (not stat.S_ISREG(metadata.st_mode) or record is None or
                    record[0] != "file" or
                    _root_anchor_identity(metadata) != record[1] or
                    (record[3] and _stat_identity(metadata) != record[2])):
                raise DefenseError("staging entry is not regular")
            if self.directory_fd is None:
                destination = self.path.joinpath(*parts)
                destination.chmod(mode & 0o755)
            else:
                os.fchmod(descriptor, mode & 0o755)
            if mtime_ns is not None and self.directory_fd is not None:
                os.utime(descriptor, ns=(mtime_ns, mtime_ns))
            elif mtime_ns is not None:
                try:
                    os.utime(destination, ns=(mtime_ns, mtime_ns), follow_symlinks=False)
                except NotImplementedError:
                    os.utime(destination, ns=(mtime_ns, mtime_ns))
            self._finalize_file_record(normalized, descriptor)
        finally:
            os.close(descriptor)

    def _ledger_plan(self, *, manifest_last=False):
        children = {}
        for relative, record in self.ledger.items():
            if record[0] == "file" and not record[3]:
                raise DefenseError("staging file was not finalized")
            parent, _separator, name = relative.rpartition("/")
            children.setdefault(parent, []).append((name, relative, record))

        def build(parent):
            entries = sorted(children.get(parent, []), key=lambda value: value[0])
            if not parent and manifest_last:
                entries.sort(key=lambda value: (value[0] == "manifest.json", value[0]))
            result = []
            for name, relative, record in entries:
                kind, _anchor, identity, _finalized = record
                descendants = build(relative) if kind == "directory" else []
                result.append((name, kind, identity, descendants))
            return result

        plan = build("")
        represented = set()

        def collect(entries, parent=""):
            for name, kind, _identity, descendants in entries:
                relative = name if not parent else parent + "/" + name
                represented.add(relative)
                if kind == "directory":
                    collect(descendants, relative)

        collect(plan)
        if represented != set(self.ledger):
            raise DefenseError("staging ledger hierarchy is invalid")
        return plan

    def publication_plan(self, *, manifest_last=False):
        self._assert_named_identity()
        plan = self._ledger_plan(manifest_last=manifest_last)
        _validate_tree_fd(self.directory_fd, plan)
        self._assert_named_identity()
        return plan

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.directory_fd is not None:
            os.close(self.directory_fd)
            self.directory_fd = None
        if self.parent_fd is not None:
            os.close(self.parent_fd)
            self.parent_fd = None

    def cleanup(self):
        if self.closed:
            return
        try:
            if not self.consumed:
                if self.directory_fd is not None:
                    try:
                        plan = self.publication_plan()
                        _remove_tree_contents_fd(self.directory_fd, plan)
                    except (OSError, DefenseError):
                        pass
                    try:
                        current = os.stat(self.name, dir_fd=self.parent_fd,
                                          follow_symlinks=False)
                        if _root_anchor_identity(current) == self.identity:
                            os.rmdir(self.name, dir_fd=self.parent_fd)
                    except OSError:
                        pass
                else:
                    try:
                        if _root_anchor_identity(self.path.lstat()) == self.identity:
                            shutil.rmtree(self.path)
                    except OSError:
                        pass
        finally:
            self.close()


def _publication_plan_fd(directory_fd: int, state, *, manifest_last=False):
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise DefenseError("temporary publication is unreadable") from exc
    if manifest_last and "manifest.json" in names:
        names.remove("manifest.json")
        names.append("manifest.json")
    plan = []
    for name in names:
        state[0] += 1
        if state[0] > 100_000:
            raise PartialError("temporary publication entry limit reached")
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISREG(metadata.st_mode):
            state[1] += metadata.st_size
            if state[1] > MAX_IMPORTED_TOTAL_BYTES:
                raise PartialError("temporary publication byte limit reached")
            plan.append((name, "file", _stat_identity(metadata), None))
        elif stat.S_ISDIR(metadata.st_mode):
            named_identity = _root_anchor_identity(metadata)
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=directory_fd)
            try:
                identity = _root_anchor_identity(os.fstat(child_fd))
                if identity != named_identity:
                    raise DefenseError("temporary publication directory changed")
                children = _publication_plan_fd(child_fd, state)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _root_anchor_identity(current) != identity:
                    raise DefenseError("temporary publication directory changed")
            finally:
                os.close(child_fd)
            plan.append((name, "directory", identity, children))
        else:
            raise DefenseError("temporary publication contains a special entry")
    return plan


def _copy_regular_to_dirfd(source_directory_fd: int, name: str, destination_fd: int,
                           expected_identity):
    source_flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    source_fd = os.open(name, source_flags, dir_fd=source_directory_fd)
    target_fd = None
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or _stat_identity(before) != expected_identity:
            raise DefenseError("temporary publication contains a special entry")
        target_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                            getattr(os, "O_BINARY", 0), 0o600,
                            dir_fd=destination_fd)
        while True:
            block = os.read(source_fd, CHUNK)
            if not block:
                break
            _write_all(target_fd, block)
        # Publication is a descriptor-anchored copy on POSIX, not a rename.
        # Preserve the already-sanitized staging metadata so restore-stage does
        # not silently collapse every restored file to mode 0600 or lose the
        # recorded timestamp.  Staging producers create only regular files and
        # have already stripped unsafe mode bits.
        os.fchmod(target_fd, stat.S_IMODE(before.st_mode) & 0o755)
        os.utime(target_fd, ns=(before.st_mtime_ns, before.st_mtime_ns))
        os.fsync(target_fd)
        after = os.fstat(source_fd)
        if _stat_identity(before) != _stat_identity(after):
            raise PartialError("temporary publication changed during copy")
        published = os.fstat(target_fd)
        named = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
        published_identity = _stat_identity(published)
        if (not stat.S_ISREG(named.st_mode) or
                _stat_identity(named) != published_identity):
            raise DefenseError("publication file changed during copy")
        return (name, "file", published_identity, [])
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(source_fd)


def _copy_tree_to_dirfd(source_parent_fd: int, name: str, destination_fd: int,
                        expected_identity, children):
    source_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=source_parent_fd)
    child_fd = None
    try:
        if _root_anchor_identity(os.fstat(source_fd)) != expected_identity:
            raise DefenseError("temporary publication directory changed")
        os.mkdir(name, 0o700, dir_fd=destination_fd)
        created = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
        if not stat.S_ISDIR(created.st_mode) or stat.S_ISLNK(created.st_mode):
            raise DefenseError("publication directory creation was replaced")
        created_identity = _root_anchor_identity(created)
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                           getattr(os, "O_NOFOLLOW", 0), dir_fd=destination_fd)
        if _root_anchor_identity(os.fstat(child_fd)) != created_identity:
            raise DefenseError("publication directory changed during creation")
        current = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication directory changed during creation")
        published_children = []
        for child_name, kind, identity, descendants in children:
            if kind == "directory":
                published_children.append(
                    _copy_tree_to_dirfd(source_fd, child_name, child_fd, identity, descendants)
                )
            else:
                published_children.append(
                    _copy_regular_to_dirfd(source_fd, child_name, child_fd, identity)
                )
        os.fsync(child_fd)
        current = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication directory changed during copy")
        return (name, "directory", created_identity, published_children)
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(source_fd)


def _validate_tree_fd(directory_fd: int, plan):
    """Validate exact recursive membership and identities without changing the tree."""
    expected_names = [entry[0] for entry in plan]
    if sorted(os.listdir(directory_fd)) != sorted(expected_names):
        raise DefenseError("publication tree membership changed")
    for name, kind, identity, children in plan:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if kind == "directory":
            if (not stat.S_ISDIR(current.st_mode) or
                    _root_anchor_identity(current) != identity):
                raise DefenseError("publication directory identity changed")
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=directory_fd)
            try:
                if _root_anchor_identity(os.fstat(child_fd)) != identity:
                    raise DefenseError("publication directory identity changed")
                _validate_tree_fd(child_fd, children)
            finally:
                os.close(child_fd)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _root_anchor_identity(current) != identity:
                raise DefenseError("publication directory identity changed")
        else:
            if not stat.S_ISREG(current.st_mode) or _stat_identity(current) != identity:
                raise DefenseError("publication file identity changed")
            flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            descriptor = os.open(name, flags, dir_fd=directory_fd)
            try:
                if _stat_identity(os.fstat(descriptor)) != identity:
                    raise DefenseError("publication file identity changed")
            finally:
                os.close(descriptor)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _stat_identity(current) != identity:
                raise DefenseError("publication file identity changed")


def _remove_tree_contents_fd(directory_fd: int, plan=None):
    """Remove only an identity-checked tree; abort on injection or replacement."""
    if plan is None:
        plan = _publication_plan_fd(directory_fd, [0, 0])
    _validate_tree_fd(directory_fd, plan)
    for name, kind, identity, children in reversed(plan):
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if kind == "directory":
            if (not stat.S_ISDIR(current.st_mode) or
                    _root_anchor_identity(current) != identity):
                raise DefenseError("cleanup directory identity changed")
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=directory_fd)
            try:
                if _root_anchor_identity(os.fstat(child_fd)) != identity:
                    raise DefenseError("cleanup directory identity changed")
                _remove_tree_contents_fd(child_fd, children)
            finally:
                os.close(child_fd)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _root_anchor_identity(current) != identity:
                raise DefenseError("cleanup directory identity changed")
            os.rmdir(name, dir_fd=directory_fd)
        else:
            if not stat.S_ISREG(current.st_mode) or _stat_identity(current) != identity:
                raise DefenseError("cleanup file identity changed")
            flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            descriptor = os.open(name, flags, dir_fd=directory_fd)
            try:
                if _stat_identity(os.fstat(descriptor)) != identity:
                    raise DefenseError("cleanup file identity changed")
            finally:
                os.close(descriptor)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _stat_identity(current) != identity:
                raise DefenseError("cleanup file identity changed")
            os.unlink(name, dir_fd=directory_fd)
    if os.listdir(directory_fd):
        raise DefenseError("cleanup tree membership changed")


def _ensure_incomplete_marker(directory_fd: int):
    """Best-effort persistent failure marker for an owned publication target."""
    try:
        current = os.stat(".INCOMPLETE", dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        marker_fd = os.open(".INCOMPLETE", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600, dir_fd=directory_fd)
        try:
            os.fsync(marker_fd)
            identity = _stat_identity(os.fstat(marker_fd))
            named = os.stat(".INCOMPLETE", dir_fd=directory_fd,
                            follow_symlinks=False)
            if _stat_identity(named) != identity:
                raise DefenseError("publication marker changed during recovery")
        finally:
            os.close(marker_fd)
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        return
    if not stat.S_ISREG(current.st_mode):
        raise DefenseError("publication failure marker is not regular")


def _publish_staging_directory(staging: _StagingDirectory, target: Path):
    staging._assert_open()
    target = _canonical_parent_with_leaf(Path(target))
    if target != staging.target:
        raise DefenseError("publication target changed")
    if target.exists() or target.is_symlink():
        raise DefenseError("output already exists")
    staging._assert_named_identity()

    if staging.directory_fd is None:
        _publication_items(staging.path)
        if (_root_anchor_identity(target.parent.lstat()) != staging.parent_identity or
                _root_anchor_identity(staging.path.lstat()) != staging.identity):
            raise DefenseError("staging directory changed during validation")
        try:
            os.rename(staging.path, target)
        except OSError as exc:
            raise DefenseError("could not safely publish directory") from exc
        staging.consumed = True
        return target

    parent_fd = staging.parent_fd
    source_fd = staging.directory_fd
    target_fd = None
    created = False
    created_identity = None
    cleanup_plan = []
    committed_after_exception = False
    ready_to_commit = False
    try:
        if _root_anchor_identity(target.parent.lstat()) != staging.parent_identity:
            raise DefenseError("output parent changed during validation")
        try:
            os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DefenseError("output already exists")
        plan = staging.publication_plan(manifest_last=True)
        staging._assert_named_identity()
        os.mkdir(target.name, 0o700, dir_fd=parent_fd)
        created = True
        created_metadata = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(created_metadata.st_mode) or
                stat.S_ISLNK(created_metadata.st_mode)):
            raise DefenseError("publication target creation was replaced")
        created_identity = _root_anchor_identity(created_metadata)
        target_fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
        if _root_anchor_identity(os.fstat(target_fd)) != created_identity:
            raise DefenseError("publication target changed during creation")
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication target changed during creation")
        marker_fd = os.open(".INCOMPLETE", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                            dir_fd=target_fd)
        try:
            os.fsync(marker_fd)
            marker_identity = _stat_identity(os.fstat(marker_fd))
            marker_named = os.stat(".INCOMPLETE", dir_fd=target_fd,
                                   follow_symlinks=False)
            if _stat_identity(marker_named) != marker_identity:
                raise DefenseError("publication marker changed during creation")
            cleanup_plan.append((".INCOMPLETE", "file", marker_identity, []))
        finally:
            os.close(marker_fd)
        for name, kind, identity, children in plan:
            if kind == "directory":
                cleanup_plan.append(
                    _copy_tree_to_dirfd(source_fd, name, target_fd, identity, children)
                )
            else:
                cleanup_plan.append(
                    _copy_regular_to_dirfd(source_fd, name, target_fd, identity)
                )
        if staging.publication_plan(manifest_last=True) != plan:
            raise PartialError("temporary publication membership changed during copy")
        staging._assert_named_identity()
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication target changed during copy")
        _validate_tree_fd(target_fd, cleanup_plan)
        os.fsync(target_fd)
        os.fsync(parent_fd)
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication target changed during finalization")
        _remove_tree_contents_fd(source_fd, plan)
        staging._assert_named_identity()
        os.rmdir(staging.name, dir_fd=parent_fd)
        staging._assert_parent_path_identity()
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (_root_anchor_identity(current) != created_identity or
                _root_anchor_identity(os.fstat(target_fd)) != created_identity):
            raise DefenseError("publication target changed before commit")
        _validate_tree_fd(target_fd, cleanup_plan)
        staging._assert_parent_path_identity()
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (_root_anchor_identity(current) != created_identity or
                _root_anchor_identity(os.fstat(target_fd)) != created_identity):
            raise DefenseError("publication target changed at commit")
        try:
            os.stat(staging.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DefenseError("staging directory still exists at commit")
        ready_to_commit = True
        os.unlink(".INCOMPLETE", dir_fd=target_fd)
        try:
            os.stat(".INCOMPLETE", dir_fd=target_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DefenseError("publication marker still exists after commit")
        cleanup_plan = [entry for entry in cleanup_plan if entry[0] != ".INCOMPLETE"]
        staging.consumed = True
        # Marker removal is the commit point.  Once it succeeds, do not turn a
        # completed publication into a failed, markerless result.  Durability
        # fsync is best-effort because rollback is no longer possible after the
        # producer staging tree has been consumed.
        try:
            os.fsync(target_fd)
            os.fsync(parent_fd)
        except OSError:
            pass
    except BaseException as exc:
        target_is_owned = False
        if target_fd is not None and created_identity is not None:
            try:
                named = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                target_is_owned = (
                    _root_anchor_identity(os.fstat(target_fd)) == created_identity and
                    _root_anchor_identity(named) == created_identity
                )
            except (OSError, DefenseError):
                pass
        if target_is_owned:
            try:
                staging._assert_parent_path_identity()
                try:
                    os.stat(staging.name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    source_absent = True
                else:
                    source_absent = False
                try:
                    os.stat(".INCOMPLETE", dir_fd=target_fd, follow_symlinks=False)
                except FileNotFoundError:
                    marker_absent = True
                else:
                    marker_absent = False
                completed_plan = [entry for entry in cleanup_plan
                                  if entry[0] != ".INCOMPLETE"]
                if ready_to_commit and source_absent and marker_absent:
                    _validate_tree_fd(target_fd, completed_plan)
                    current = os.stat(target.name, dir_fd=parent_fd,
                                      follow_symlinks=False)
                    committed_after_exception = (
                        _root_anchor_identity(current) == created_identity and
                        _root_anchor_identity(os.fstat(target_fd)) == created_identity
                    )
            except (OSError, DefenseError):
                pass
        if committed_after_exception:
            staging.consumed = True
        elif target_fd is not None and created_identity is not None:
            try:
                if _root_anchor_identity(os.fstat(target_fd)) == created_identity:
                    _ensure_incomplete_marker(target_fd)
            except BaseException:
                pass
        if committed_after_exception:
            pass
        elif isinstance(exc, DefenseError):
            raise
        else:
            raise DefenseError("could not safely publish directory") from exc
    finally:
        if target_fd is not None:
            os.close(target_fd)
    return target


def _publish_directory(temporary: Path, target: Path):
    if isinstance(temporary, _StagingDirectory):
        return _publish_staging_directory(temporary, target)
    if not DIRECTORY_STAGING_SUPPORTED:
        raise PartialError("secure directory publication is unavailable on Windows")
    target, expected_parent_identity = _safe_output_target(target)
    temporary = _canonical_input_leaf(temporary)
    if temporary.parent != target.parent:
        raise DefenseError("temporary publication must share the output parent")
    if os.name == "nt":
        _publication_items(temporary)
        if _root_anchor_identity(target.parent.lstat()) != expected_parent_identity:
            raise DefenseError("output parent changed during validation")
        # Windows rename is an atomic no-replace operation for directories.
        try:
            os.rename(temporary, target)
        except OSError as exc:
            raise DefenseError("could not safely publish directory") from exc
        return target

    if (not DIRECTORY_DIRFD_SUPPORTED or not hasattr(os, "O_DIRECTORY") or
            not hasattr(os, "O_NOFOLLOW")):
        raise DefenseError("filesystem lacks safe directory publication support")

    parent_fd = None
    source_fd = None
    target_fd = None
    created = False
    created_identity = None
    cleanup_plan = []
    committed_after_exception = False
    ready_to_commit = False
    try:
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if _root_anchor_identity(os.fstat(parent_fd)) != expected_parent_identity:
            raise DefenseError("output parent changed during validation")
        source_metadata = os.stat(temporary.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(source_metadata.st_mode):
            raise DefenseError("temporary publication must be a directory")
        source_identity = _root_anchor_identity(source_metadata)
        source_fd = os.open(temporary.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
        if _root_anchor_identity(os.fstat(source_fd)) != source_identity:
            raise DefenseError("temporary publication changed during validation")
        plan = _publication_plan_fd(source_fd, [0, 0], manifest_last=True)
        os.mkdir(target.name, 0o700, dir_fd=parent_fd)
        created = True
        created_metadata = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(created_metadata.st_mode) or
                stat.S_ISLNK(created_metadata.st_mode)):
            raise DefenseError("publication target creation was replaced")
        created_identity = _root_anchor_identity(created_metadata)
        target_fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
        if _root_anchor_identity(os.fstat(target_fd)) != created_identity:
            raise DefenseError("publication target changed during creation")
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication target changed during creation")
        marker_fd = os.open(".INCOMPLETE", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                            dir_fd=target_fd)
        try:
            os.fsync(marker_fd)
            marker_identity = _stat_identity(os.fstat(marker_fd))
            marker_named = os.stat(".INCOMPLETE", dir_fd=target_fd,
                                   follow_symlinks=False)
            if _stat_identity(marker_named) != marker_identity:
                raise DefenseError("publication marker changed during creation")
            cleanup_plan.append((".INCOMPLETE", "file", marker_identity, []))
        finally:
            os.close(marker_fd)
        for name, kind, identity, children in plan:
            if kind == "directory":
                cleanup_plan.append(
                    _copy_tree_to_dirfd(source_fd, name, target_fd, identity, children)
                )
            else:
                cleanup_plan.append(
                    _copy_regular_to_dirfd(source_fd, name, target_fd, identity)
                )
        if _publication_plan_fd(source_fd, [0, 0], manifest_last=True) != plan:
            raise PartialError("temporary publication membership changed during copy")
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication target changed during copy")
        _validate_tree_fd(target_fd, cleanup_plan)
        os.fsync(target_fd)
        os.fsync(parent_fd)
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if _root_anchor_identity(current) != created_identity:
            raise DefenseError("publication target changed during finalization")
        _remove_tree_contents_fd(source_fd, plan)
        os.rmdir(temporary.name, dir_fd=parent_fd)
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (_root_anchor_identity(current) != created_identity or
                _root_anchor_identity(os.fstat(target_fd)) != created_identity):
            raise DefenseError("publication target changed before commit")
        _validate_tree_fd(target_fd, cleanup_plan)
        if _root_anchor_identity(target.parent.lstat()) != expected_parent_identity:
            raise DefenseError("output parent changed at commit")
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (_root_anchor_identity(current) != created_identity or
                _root_anchor_identity(os.fstat(target_fd)) != created_identity):
            raise DefenseError("publication target changed at commit")
        try:
            os.stat(temporary.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DefenseError("temporary publication still exists at commit")
        ready_to_commit = True
        os.unlink(".INCOMPLETE", dir_fd=target_fd)
        try:
            os.stat(".INCOMPLETE", dir_fd=target_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise DefenseError("publication marker still exists after commit")
        cleanup_plan = [entry for entry in cleanup_plan if entry[0] != ".INCOMPLETE"]
        try:
            os.fsync(target_fd)
            os.fsync(parent_fd)
        except OSError:
            pass
    except BaseException as exc:
        target_is_owned = False
        if target_fd is not None and created_identity is not None:
            try:
                named = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                target_is_owned = (
                    _root_anchor_identity(os.fstat(target_fd)) == created_identity and
                    _root_anchor_identity(named) == created_identity
                )
            except (OSError, DefenseError):
                pass
        if target_is_owned:
            try:
                if _root_anchor_identity(target.parent.lstat()) != expected_parent_identity:
                    raise DefenseError("output parent changed")
                try:
                    os.stat(temporary.name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    source_absent = True
                else:
                    source_absent = False
                try:
                    os.stat(".INCOMPLETE", dir_fd=target_fd, follow_symlinks=False)
                except FileNotFoundError:
                    marker_absent = True
                else:
                    marker_absent = False
                completed_plan = [entry for entry in cleanup_plan
                                  if entry[0] != ".INCOMPLETE"]
                if ready_to_commit and source_absent and marker_absent:
                    _validate_tree_fd(target_fd, completed_plan)
                    committed_after_exception = True
            except (OSError, DefenseError):
                pass
        if not committed_after_exception and target_fd is not None and created_identity is not None:
            try:
                if _root_anchor_identity(os.fstat(target_fd)) == created_identity:
                    _ensure_incomplete_marker(target_fd)
            except BaseException:
                pass
        if committed_after_exception:
            pass
        elif isinstance(exc, DefenseError):
            raise
        else:
            raise DefenseError("could not safely publish directory") from exc
    finally:
        if target_fd is not None:
            os.close(target_fd)
        if source_fd is not None:
            os.close(source_fd)
        if parent_fd is not None:
            os.close(parent_fd)
    return target


def _profile_hash(profile) -> str:
    return _sha256_bytes(_canonical(profile))


def _snapshot_scope(settings, requested, compose=None):
    adapter_config = {}
    if "compose" in requested and compose is not None:
        adapter_config["compose"] = {
            "config_files": list(compose["files"]),
            "project_sha256": _opaque_text_identifier(compose["project"]),
            "services": list(compose["services"]),
        }
    payload = {
        "adapter_config": adapter_config,
        "adapter_semantics": {name: ADAPTER_SEMANTICS[name] for name in sorted(requested)},
        "files": {
            "content_semantics": "sha256-size-mode-mtime-v1",
            "exclude": sorted(set(settings.get("exclude", []))),
            "include": sorted(set(settings.get("include", ["*"]))),
            "max_file_bytes": settings.get("max_file_bytes", 64 * 1024 * 1024),
            "max_files": settings.get("max_files", 20_000),
            "max_total_bytes": settings.get("max_total_bytes", 4 * 1024 * 1024 * 1024),
            "path_semantics": "portable-nfc-casefold-v1",
        },
        "schema": SNAPSHOT_SCOPE_SCHEMA,
        "tool_compatibility": SNAPSHOT_TOOL_COMPATIBILITY,
    }
    return {**payload, "sha256": _sha256_bytes(_canonical(payload))}


def _validate_tool_record(value, field="tool"):
    _strict_keys(value, {"name", "version"}, {"name", "version"}, field)
    if value["name"] != TOOL or not isinstance(value["version"], str) or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", value["version"]):
        raise DefenseError("invalid " + field)
    return value


def _tool_major(value):
    _validate_tool_record(value)
    return int(value["version"].split(".", 1)[0])


def _validate_profile_reference(value, field="profile"):
    _strict_keys(value, {"name", "sha256"}, {"name", "sha256"}, field)
    _safe_string(value["name"], field + " name", 1, 120)
    if not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"]):
        raise DefenseError("invalid " + field + " hash")
    return value


def _validate_snapshot_scope(value):
    _strict_keys(value, {"schema", "tool_compatibility", "adapter_semantics", "adapter_config",
                         "files", "sha256"},
                 {"schema", "tool_compatibility", "adapter_semantics", "adapter_config",
                  "files", "sha256"},
                 "snapshot scope")
    if (value["schema"] != SNAPSHOT_SCOPE_SCHEMA or
            value["tool_compatibility"] != SNAPSHOT_TOOL_COMPATIBILITY):
        raise DefenseError("invalid snapshot scope schema")
    semantics = value["adapter_semantics"]
    if not isinstance(semantics, dict) or set(semantics) - set(ADAPTERS):
        raise DefenseError("invalid adapter semantics")
    for name, semantic in semantics.items():
        if semantic != ADAPTER_SEMANTICS[name]:
            raise DefenseError("invalid adapter semantics")
    adapter_config = value["adapter_config"]
    if not isinstance(adapter_config, dict) or set(adapter_config) - {"compose"}:
        raise DefenseError("invalid adapter configuration scope")
    if ("compose" in semantics) != ("compose" in adapter_config):
        raise DefenseError("compose adapter scope is incomplete")
    if "compose" in adapter_config:
        compose = adapter_config["compose"]
        _strict_keys(compose, {"config_files", "project_sha256", "services"},
                     {"config_files", "project_sha256", "services"}, "compose scope")
        if not isinstance(compose["project_sha256"], str) or not OPAQUE_ID.fullmatch(
                compose["project_sha256"]):
            raise DefenseError("invalid compose project scope")
        for field in ("config_files", "services"):
            values = compose[field]
            if (not isinstance(values, list) or not values or values != sorted(set(values)) or
                    len(values) > 128):
                raise DefenseError("invalid compose scope " + field)
        for path in compose["config_files"]:
            _portable_relative_posix(path, "compose config path")
        for service in compose["services"]:
            if not IDENTIFIER.fullmatch(service if isinstance(service, str) else ""):
                raise DefenseError("invalid compose service scope")
    files = value["files"]
    _strict_keys(files, {"content_semantics", "exclude", "include", "max_file_bytes",
                         "max_files", "max_total_bytes", "path_semantics"},
                 {"content_semantics", "exclude", "include", "max_file_bytes", "max_files",
                  "max_total_bytes", "path_semantics"}, "snapshot file scope")
    if (files["content_semantics"] != "sha256-size-mode-mtime-v1" or
            files["path_semantics"] != "portable-nfc-casefold-v1"):
        raise DefenseError("unsupported snapshot file semantics")
    for field in ("include", "exclude"):
        patterns = files[field]
        if (not isinstance(patterns, list) or len(patterns) > 128 or
                any(not isinstance(pattern, str) for pattern in patterns) or
                patterns != sorted(set(patterns))):
            raise DefenseError("invalid snapshot scope patterns")
        for pattern in patterns:
            _relative_glob(pattern, field)
    _positive_int(files["max_files"], "max_files", 100_000)
    _positive_int(files["max_file_bytes"], "max_file_bytes", 1024 ** 3)
    _positive_int(files["max_total_bytes"], "max_total_bytes", 20 * 1024 ** 3)
    payload = {key: value[key] for key in ("adapter_config", "adapter_semantics", "files", "schema",
                                           "tool_compatibility")}
    if (not isinstance(value["sha256"], str) or
            value["sha256"] != _sha256_bytes(_canonical(payload))):
        raise DefenseError("snapshot scope hash mismatch")
    return value


def _validate_url(value):
    _safe_string(value, "health URL", 1, 4096)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise DefenseError("invalid health URL") from exc
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise DefenseError("invalid health URL")
    _ = port
    return value


def _validate_profile(data):
    _strict_keys(data, {"schema", "name", "snapshot", "compose", "health", "backup", "evidence"},
                 {"schema", "name"}, "profile")
    if data["schema"] != PROFILE_SCHEMA:
        raise DefenseError("unsupported profile schema")
    _safe_string(data["name"], "profile name", 1, 120)
    _reject_declarative_hazards(data)

    if "snapshot" in data:
        item = data["snapshot"]
        _strict_keys(item, {"adapters", "include", "exclude", "max_files",
                            "max_file_bytes", "max_total_bytes"}, field="snapshot profile")
        if "adapters" in item:
            adapters = item["adapters"]
            if (not isinstance(adapters, list) or len(adapters) > len(ADAPTERS) or
                    any(not isinstance(adapter, str) for adapter in adapters) or
                    len(set(adapters)) != len(adapters) or
                    any(adapter not in ADAPTERS for adapter in adapters)):
                raise DefenseError("invalid snapshot adapters")
        for field in ("include", "exclude"):
            if field in item:
                values = item[field]
                if not isinstance(values, list) or len(values) > 128:
                    raise DefenseError("invalid snapshot " + field)
                item[field] = [_relative_glob(value, field) for value in values]
        if "max_files" in item:
            _positive_int(item["max_files"], "max_files", 100_000)
        if "max_file_bytes" in item:
            _positive_int(item["max_file_bytes"], "max_file_bytes", 1024 ** 3)
        if "max_total_bytes" in item:
            _positive_int(item["max_total_bytes"], "max_total_bytes", 20 * 1024 ** 3)

    if "compose" in data:
        compose = data["compose"]
        _strict_keys(compose, {"project", "files", "services"},
                     {"project", "files", "services"}, "compose profile")
        project = compose["project"]
        if (not isinstance(project, str) or
                not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project)):
            raise DefenseError("invalid compose project")
        files = compose["files"]
        if (not isinstance(files, list) or not 1 <= len(files) <= 8 or
                files != sorted(set(files))):
            raise DefenseError("invalid compose files")
        compose["files"] = [_portable_relative_posix(path, "compose config path")
                            for path in files]
        if any(not path.lower().endswith((".yml", ".yaml")) for path in compose["files"]):
            raise DefenseError("compose configs must be YAML files")
        services = compose["services"]
        if (not isinstance(services, list) or not 1 <= len(services) <= 128 or
                services != sorted(set(services)) or
                any(not IDENTIFIER.fullmatch(service if isinstance(service, str) else "")
                    for service in services)):
            raise DefenseError("invalid compose services")
    snapshot_adapters = data.get("snapshot", {}).get("adapters", list(DEFAULT_ADAPTERS))
    if ("compose" in snapshot_adapters) != ("compose" in data):
        raise DefenseError("compose profile and adapter must be configured together")

    if "health" in data:
        checks = data["health"]
        if not isinstance(checks, list) or not 1 <= len(checks) <= 128:
            raise DefenseError("health must contain 1..128 checks")
        names = set()
        for check in checks:
            _strict_keys(check, {"name", "url", "status", "contains", "timeout"},
                         {"name", "url"}, "health check")
            name = _safe_string(check["name"], "health name", 1, 120)
            if name in names:
                raise DefenseError("duplicate health name")
            names.add(name)
            _validate_url(check["url"])
            if "status" in check and (type(check["status"]) is not int or
                                       not 100 <= check["status"] <= 599):
                raise DefenseError("invalid health status")
            if "contains" in check:
                _safe_string(check["contains"], "health contains", 0, 4096)
            if "timeout" in check:
                _positive_float_value(check["timeout"])

    if "backup" in data:
        backup = data["backup"]
        _strict_keys(backup, {"entries", "exclude", "max_files", "max_file_bytes",
                              "max_total_bytes"}, {"entries"}, "backup profile")
        entries = backup["entries"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
            raise DefenseError("backup entries must contain 1..256 items")
        seen = set()
        portable_seen = set()
        normalized = []
        for entry in entries:
            _strict_keys(entry, {"path", "kind"}, {"path", "kind"}, "backup entry")
            path = _portable_relative_posix(entry["path"], "backup path", allow_dot=True)
            if (not isinstance(entry["kind"], str) or
                    entry["kind"] not in {"file", "tree", "native_dump"}):
                raise DefenseError("invalid backup kind")
            portable_key = _portable_path_key(path)
            if path in seen or portable_key in portable_seen:
                raise DefenseError("duplicate backup path")
            seen.add(path)
            portable_seen.add(portable_key)
            normalized.append((path, entry["kind"]))
        for path, kind in normalized:
            for other, _other_kind in normalized:
                if path != other and kind == "tree" and (path == "." or other.startswith(path + "/")):
                    raise DefenseError("overlapping backup entries")
        if "exclude" in backup:
            if not isinstance(backup["exclude"], list) or len(backup["exclude"]) > 128:
                raise DefenseError("invalid backup exclude")
            backup["exclude"] = [_relative_glob(value, "backup exclude") for value in backup["exclude"]]
        if "max_files" in backup:
            _positive_int(backup["max_files"], "max_files", 100_000)
        if "max_file_bytes" in backup:
            _positive_int(backup["max_file_bytes"], "max_file_bytes", 4 * 1024 ** 3)
        if "max_total_bytes" in backup:
            _positive_int(backup["max_total_bytes"], "max_total_bytes", 100 * 1024 ** 3)

    if "evidence" in data:
        evidence = data["evidence"]
        _strict_keys(evidence, {"allow_extensions", "max_files", "max_file_bytes",
                                "max_total_bytes"}, field="evidence profile")
        if "allow_extensions" in evidence:
            extensions = evidence["allow_extensions"]
            if (not isinstance(extensions, list) or not 1 <= len(extensions) <= 2 or
                    any(not isinstance(value, str) for value in extensions) or
                    len(set(extensions)) != len(extensions) or
                    any(value not in SAFE_EVIDENCE_EXTENSIONS for value in extensions)):
                raise DefenseError("invalid evidence extensions")
        if "max_files" in evidence:
            _positive_int(evidence["max_files"], "max_files", 1024)
        if "max_file_bytes" in evidence:
            _positive_int(evidence["max_file_bytes"], "max_file_bytes", 64 * 1024 ** 2)
        if "max_total_bytes" in evidence:
            _positive_int(evidence["max_total_bytes"], "max_total_bytes", 1024 ** 3)
    return data


def load_profile(path):
    data, _raw = _read_json(path, MAX_PROFILE_BYTES)
    return _validate_profile(data)


def _matches(path, patterns):
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _secret_filename(name):
    lowered = name.lower()
    return (lowered == ".env" or lowered.startswith(".env.") or
            lowered.endswith((".pem", ".key", ".p12", ".pfx", ".kdbx")) or
            bool(SECRET_NAME.search(lowered)))


def _bounded_walk(root: Path, include, exclude, max_files, skip_dirs=(),
                  skip_secret_dirs=False, require_portable=False):
    stack = [root]
    skipped_directory_names = {name.casefold() for name in skip_dirs}
    seen = 0
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as stream:
                remaining = max_files * 10 - seen
                if remaining <= 0:
                    yield "limit", root, "entry_limit_reached"
                    return
                entries = []
                for entry in stream:
                    entries.append(entry)
                    if len(entries) > remaining:
                        yield "limit", root, "entry_limit_reached"
                        return
                entries.sort(key=lambda value: value.name)
        except (OSError, PermissionError) as exc:
            yield "issue", directory, "directory_unreadable"
            continue
        directories = []
        for entry in entries:
            seen += 1
            if seen > max_files * 10:
                yield "limit", root, "entry_limit_reached"
                return
            path = Path(entry.path)
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                yield "issue", path, "path_outside_root"
                continue
            if _matches(rel, exclude):
                yield "skip", path, "excluded"
            elif entry.is_symlink():
                yield "skip", path, "symlink"
            elif entry.is_dir(follow_symlinks=False):
                if (entry.name.casefold() in skipped_directory_names or
                        skip_secret_dirs and _secret_filename(entry.name)):
                    yield "skip", path, "excluded_directory"
                elif require_portable:
                    try:
                        _portable_relative_posix(rel, "discovered path")
                    except DefenseError:
                        yield "nonportable", path, _opaque_text_identifier(rel)
                    else:
                        directories.append(path)
                else:
                    directories.append(path)
            elif entry.is_file(follow_symlinks=False):
                if _matches(rel, include):
                    if require_portable:
                        try:
                            rel = _portable_relative_posix(rel, "discovered path")
                        except DefenseError:
                            yield "nonportable", path, _opaque_text_identifier(rel)
                            continue
                    yield "file", path, rel
                else:
                    yield "skip", path, "not_included"
            else:
                yield "skip", path, "special"
        stack.extend(reversed(directories))


def _hash_regular(path: Path, max_bytes: int):
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise PartialError("not_regular")
        if before.st_size > max_bytes:
            raise PartialError("file_too_large")
        digest = hashlib.sha256()
        consumed = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                consumed += len(block)
                if consumed > max_bytes:
                    raise PartialError("file_too_large")
                digest.update(block)
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after):
            raise PartialError("file_changed_during_read")
        return before, digest.hexdigest()
    finally:
        os.close(fd)


def _known_executable(candidates):
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and not path.is_symlink():
            return str(path)
    return None


def _platform_command(adapter):
    system = platform.system()
    if system == "Darwin":
        commands = {
            "processes": (["/bin/ps", "-axo", "pid=,ppid=,uid=,comm="], "/bin/ps"),
            "listeners": (["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcPn"],
                          "/usr/sbin/lsof"),
            "services": (["/bin/launchctl", "list"], "/bin/launchctl"),
        }
        return commands.get(adapter)
    if system == "Windows":
        base = r"C:\Windows"
        commands = {
            "processes": ([str(Path(base) / "System32" / "tasklist.exe"), "/fo", "csv", "/nh"],
                          str(Path(base) / "System32" / "tasklist.exe")),
            "services": ([str(Path(base) / "System32" / "sc.exe"), "query", "state=", "all"],
                         str(Path(base) / "System32" / "sc.exe")),
        }
        return commands.get(adapter)
    if system == "Linux" and adapter == "services":
        executable = _known_executable(("/usr/bin/systemctl", "/bin/systemctl"))
        if executable:
            return ([executable, "list-units", "--type=service", "--all", "--no-legend",
                     "--no-pager", "--plain"], executable)
    return None


def _platform_subprocess_environment():
    # Do not let user-controlled loader, locale, or proxy variables influence
    # the small allowlist of trusted read-only platform tools.
    if os.name == "nt":
        system_root = r"C:\Windows"
        return {
            "PATH": system_root + r"\System32;" + system_root,
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "SystemRoot": system_root,
            "WINDIR": system_root,
        }
    return {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}


def _run_platform_command(argv, executable, timeout=15):
    if not argv or argv[0] != executable or not _is_regular(Path(executable)):
        raise PartialError("adapter_tool_missing")
    try:
        # Spool hardcoded adapter output to private temporary files so a large
        # process/service table cannot cause an unbounded in-memory capture.
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout,
                                       stderr=stderr, timeout=timeout, check=False,
                                       shell=False, env=_platform_subprocess_environment())
            stdout_size = stdout.tell()
            stderr_size = stderr.tell()
            if stdout_size > MAX_ADAPTER_OUTPUT or stderr_size > MAX_ADAPTER_OUTPUT:
                raise PartialError("adapter_output_limit")
            stdout.seek(0)
            stderr.seek(0)
            stdout_bytes = stdout.read(MAX_ADAPTER_OUTPUT + 1)
            stderr_bytes = stderr.read(MAX_ADAPTER_OUTPUT + 1)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PartialError("adapter_execution_failed") from exc
    if completed.returncode != 0:
        raise PartialError("adapter_permission_or_runtime_failure")
    if stderr_bytes.strip():
        raise PartialError("adapter_reported_warning")
    try:
        return stdout_bytes.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PartialError("adapter_output_encoding") from exc


def _adapter_platform():
    return {
        "machine": platform.machine(),
        "python": platform.python_version(),
        "release": platform.release(),
        "system": platform.system(),
    }


def _linux_processes():
    root = Path("/proc")
    if not root.is_dir():
        raise PartialError("proc_unavailable")
    records = []
    partial = False
    try:
        pids = sorted((entry for entry in root.iterdir() if entry.name.isdigit()),
                      key=lambda value: int(value.name))
    except OSError as exc:
        raise PartialError("proc_unreadable") from exc
    if len(pids) > 100_000:
        partial = True
    for path in pids[:100_000]:
        try:
            data = (path / "status").read_text(encoding="utf-8", errors="strict")
            fields = {}
            for line in data.splitlines():
                key, separator, value = line.partition(":")
                if separator and key in {"Name", "PPid", "Uid"}:
                    fields[key] = value.strip()
            records.append({
                "name": fields.get("Name", "?"),
                "pid": int(path.name),
                "ppid": int(fields.get("PPid", "0").split()[0]),
                "uid": int(fields.get("Uid", "-1").split()[0]),
            })
        except FileNotFoundError:
            # A process exiting during enumeration is normal and does not make
            # the remaining observation misleading.
            continue
        except (OSError, UnicodeError, ValueError, IndexError):
            # Processes may exit while /proc is being read.  Keep the snapshot
            # useful but make the adapter explicitly partial.
            partial = True
    return records, partial


def _processes_adapter():
    system = platform.system()
    if system == "Linux":
        return _linux_processes()
    command = _platform_command("processes")
    if not command:
        raise PartialError("adapter_unsupported")
    output = _run_platform_command(*command)
    records = []
    if system == "Darwin":
        for line in output.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) != 4:
                continue
            try:
                pid, ppid, uid = map(int, parts[:3])
            except ValueError:
                continue
            records.append({"pid": pid, "ppid": ppid, "uid": uid, "name": parts[3]})
    elif system == "Windows":
        for row in csv.reader(output.splitlines()):
            if len(row) < 2:
                continue
            try:
                pid = int(row[1])
            except ValueError:
                continue
            records.append({"pid": pid, "ppid": None, "uid": None, "name": row[0]})
    return sorted(records, key=lambda value: (value["pid"], value["name"])), False


def _decode_proc_address(value, ipv6=False):
    address, port = value.split(":", 1)
    packed = bytes.fromhex(address)
    if ipv6:
        # Linux /proc exposes IPv6 as four native-endian 32-bit words.
        packed = b"".join(packed[index:index + 4][::-1] for index in range(0, 16, 4))
    else:
        packed = packed[::-1]
    return str(ipaddress.ip_address(packed)), int(port, 16)


def _linux_listeners():
    records = []
    partial = False
    for filename, protocol, ipv6 in (
            ("/proc/net/tcp", "tcp", False), ("/proc/net/tcp6", "tcp6", True),
            ("/proc/net/udp", "udp", False), ("/proc/net/udp6", "udp6", True)):
        path = Path(filename)
        try:
            stream = path.open("r", encoding="ascii", errors="strict")
        except (OSError, UnicodeError):
            partial = True
            continue
        with stream:
            consumed = 0
            for line_number, line in enumerate(stream):
                consumed += len(line.encode("ascii"))
                if consumed > MAX_ADAPTER_OUTPUT or line_number > 100_000:
                    partial = True
                    break
                if line_number == 0:
                    continue
                parts = line.split()
                if len(parts) < 10:
                    partial = True
                    continue
                state = parts[3]
                if protocol.startswith("tcp") and state != "0A":
                    continue
                try:
                    address, port = _decode_proc_address(parts[1], ipv6)
                except (ValueError, IndexError):
                    partial = True
                    continue
                records.append({"address": address, "port": port, "protocol": protocol,
                                "state": "listen" if protocol.startswith("tcp") else "bound"})
    records.sort(key=lambda value: (value["protocol"], value["address"], value["port"]))
    return records, partial


def _darwin_listeners():
    command = _platform_command("listeners")
    if not command:
        raise PartialError("adapter_tool_missing")
    output = _run_platform_command(*command)
    records = []
    current_pid = None
    current_name = None
    for line in output.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p" and value.isdigit():
            current_pid = int(value)
        elif tag == "c":
            current_name = value
        elif tag == "n":
            match = re.search(r"(?:\[([^]]+)\]|([^:]+)):(\d+)(?:\s|$)", value)
            if match:
                records.append({"address": match.group(1) or match.group(2),
                                "name": current_name, "pid": current_pid,
                                "port": int(match.group(3)), "protocol": "tcp",
                                "state": "listen"})
    records.sort(key=lambda value: (value["port"], value.get("pid") or -1,
                                    value.get("name") or ""))
    return records, False


def _listeners_adapter():
    if platform.system() == "Linux":
        return _linux_listeners()
    if platform.system() == "Darwin":
        return _darwin_listeners()
    raise PartialError("adapter_unsupported")


def _services_adapter():
    command = _platform_command("services")
    if not command:
        raise PartialError("adapter_tool_missing")
    output = _run_platform_command(*command)
    system = platform.system()
    records = []
    if system == "Linux":
        for line in output.splitlines():
            fields = line.split(None, 4)
            if len(fields) >= 4:
                records.append({"name": fields[0], "load": fields[1],
                                "active": fields[2], "sub": fields[3]})
    elif system == "Darwin":
        for line in output.splitlines()[1:]:
            fields = line.split(None, 2)
            if len(fields) == 3:
                try:
                    pid = None if fields[0] == "-" else int(fields[0])
                except ValueError:
                    continue
                records.append({"name": fields[2], "pid": pid, "status": fields[1]})
    elif system == "Windows":
        name = state_value = None
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("SERVICE_NAME:"):
                if name is not None:
                    records.append({"name": name, "state": state_value or "unknown"})
                name = stripped.partition(":")[2].strip()
                state_value = None
            elif stripped.startswith("STATE"):
                fields = stripped.split()
                state_value = fields[3].lower() if len(fields) >= 4 else "unknown"
        if name is not None:
            records.append({"name": name, "state": state_value or "unknown"})
    return sorted(records, key=lambda value: value["name"]), False


def _docker_executable():
    system = platform.system()
    if system == "Darwin":
        return _known_executable((
            "/Applications/Docker.app/Contents/Resources/bin/docker",
            "/opt/homebrew/bin/docker", "/usr/local/bin/docker", "/usr/bin/docker",
        ))
    if system == "Linux":
        return _known_executable(("/usr/bin/docker", "/usr/local/bin/docker", "/bin/docker"))
    if system == "Windows":
        return _known_executable((
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            r"C:\ProgramData\DockerDesktop\version-bin\docker.exe",
        ))
    return None


def _compose_adapter(root: Path, compose):
    executable = _docker_executable()
    if not executable:
        raise PartialError("adapter_tool_missing")
    root_identity = _root_anchor_identity(root.lstat())
    config_files = []
    for relative in compose["files"]:
        metadata, digest = _hash_anchored_regular(
            root, relative, root_identity, MAX_COMPOSE_FILE_BYTES
        )
        config_files.append({"path": relative, "sha256": digest, "size": metadata.st_size})

    project = compose["project"]
    template = '{{.Label "com.docker.compose.service"}}\t{{.State}}\t{{.Status}}'
    argv = [executable, "ps", "--all", "--filter",
            "label=com.docker.compose.project=" + project, "--format", template]
    output = _run_platform_command(argv, executable)
    groups = Counter()
    partial = False
    for line in output.splitlines():
        fields = line.split("\t", 2)
        if len(fields) != 3:
            partial = True
            continue
        service, state, status_text = (field.strip() for field in fields)
        if not IDENTIFIER.fullmatch(service) or not state or len(state) > 64:
            partial = True
            continue
        health_match = re.search(r"\((healthy|unhealthy|starting)\)", status_text)
        health = health_match.group(1) if health_match else "none"
        groups[(service, state, health)] += 1
    observed_services = {key[0] for key in groups}
    for service in compose["services"]:
        if service not in observed_services:
            groups[(service, "missing", "none")] = 0
    services = [
        {"count": count, "health": health, "service": service, "state": state}
        for (service, state, health), count in sorted(groups.items())
    ]
    return {
        "config_files": config_files,
        "project_sha256": _opaque_text_identifier(project),
        "services": services,
    }, partial


def _adapter_preflight(name, profile_data=None):
    if name == "platform":
        return True, None
    system = platform.system()
    if name == "processes" and system == "Linux":
        return Path("/proc").is_dir(), None if Path("/proc").is_dir() else "proc_unavailable"
    if name == "listeners" and system == "Linux":
        ok = Path("/proc/net").is_dir()
        return ok, None if ok else "proc_net_unavailable"
    if name == "listeners" and system not in {"Darwin", "Linux"}:
        return False, "adapter_unsupported"
    if name == "compose":
        if not profile_data or "compose" not in profile_data:
            return False, "compose_profile_missing"
        executable = _docker_executable()
        return (bool(executable), None if executable else "adapter_tool_missing")
    command = _platform_command(name)
    if not command or not _is_regular(Path(command[1])):
        return False, "adapter_tool_missing"
    return True, None


def command_preflight(args):
    profile_data = load_profile(args.profile)
    snapshot_profile = profile_data.get("snapshot", {})
    requested = snapshot_profile.get("adapters", list(DEFAULT_ADAPTERS))
    checks = [{"name": "python", "ok": sys.version_info >= (3, 10),
               "reason": None if sys.version_info >= (3, 10) else "python_too_old"}]
    for adapter in requested:
        ok, reason = _adapter_preflight(adapter, profile_data)
        checks.append({"name": "adapter:" + adapter, "ok": ok, "reason": reason})
    if "health" in profile_data:
        checks.append({"name": "health-profile", "ok": True, "reason": None})
    if "backup" in profile_data:
        checks.append({"name": "backup-profile", "ok": True, "reason": None})
    if "backup" in profile_data or "evidence" in profile_data:
        checks.append({
            "name": "directory-staging",
            "ok": DIRECTORY_STAGING_SUPPORTED,
            "reason": None if DIRECTORY_STAGING_SUPPORTED else "platform_unsupported",
        })
    partial = not all(check["ok"] for check in checks)
    result = {"command": "preflight", "exit_code": 2 if partial else 0,
              "partial": partial, "platform": _adapter_platform(),
              "profile": {"name": profile_data["name"], "sha256": _profile_hash(profile_data)},
              "checks": checks, "tool": _tool_record()}
    print(_canonical(result).decode("utf-8"), end="")
    return result["exit_code"]


def _snapshot_files(root, settings):
    include = settings.get("include", ["*"])
    exclude = settings.get("exclude", [])
    max_files = settings.get("max_files", 20_000)
    max_file_bytes = settings.get("max_file_bytes", 64 * 1024 * 1024)
    max_total_bytes = settings.get("max_total_bytes", 4 * 1024 * 1024 * 1024)
    files = []
    issues = []
    skipped = Counter()
    portable_paths = set()
    total = 0
    for kind, path, detail in _bounded_walk(root, include, exclude, max_files,
                                            SNAPSHOT_SKIP_DIRS, skip_secret_dirs=True,
                                            require_portable=True):
        if kind == "skip":
            skipped[detail] += 1
            if detail == "symlink" or (detail == "special" and _matches(
                    path.relative_to(root).as_posix(), include)):
                try:
                    raw_rel = path.relative_to(root).as_posix()
                except ValueError:
                    raw_rel = "."
                try:
                    issue_path = _portable_relative_posix(raw_rel, "snapshot issue path",
                                                         allow_dot=True)
                except DefenseError:
                    issue_path = _opaque_text_identifier(raw_rel)
                issues.append({"component": "files", "path": issue_path,
                               "reason": "included_" + detail})
            continue
        if kind == "nonportable":
            skipped["nonportable_path"] += 1
            issues.append({"component": "files", "path": detail,
                           "reason": "nonportable_path"})
            continue
        if kind in {"issue", "limit"}:
            rel = "."
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                pass
            issues.append({"component": "files", "path": rel, "reason": detail})
            if kind == "limit":
                break
            continue
        rel = detail
        portable_key = _portable_path_key(rel)
        if portable_key in portable_paths:
            skipped["casefold_collision"] += 1
            issues.append({"component": "files", "path": _opaque_text_identifier(rel),
                           "reason": "casefold_collision"})
            continue
        portable_paths.add(portable_key)
        if _secret_filename(path.name):
            skipped["secret_filename"] += 1
            continue
        if len(files) >= max_files:
            issues.append({"component": "files", "path": rel, "reason": "file_limit_reached"})
            break
        try:
            metadata, digest = _hash_regular(path, max_file_bytes)
        except (OSError, PartialError):
            issues.append({"component": "files", "path": rel, "reason": "unreadable_or_unstable"})
            continue
        if total + metadata.st_size > max_total_bytes:
            issues.append({"component": "files", "path": rel, "reason": "total_byte_limit_reached"})
            break
        total += metadata.st_size
        files.append({"mode": stat.S_IMODE(metadata.st_mode), "mtime_ns": metadata.st_mtime_ns,
                      "path": rel, "sha256": digest, "size": metadata.st_size})
    return files, issues, dict(sorted(skipped.items())), total


def command_snapshot(args):
    profile_data = load_profile(args.profile)
    root = _canonical_root_directory(Path(args.root))
    if root.name.casefold() in {name.casefold() for name in SNAPSHOT_SKIP_DIRS} or _secret_filename(root.name):
        raise DefenseError("snapshot root is a secret or excluded directory")
    settings = profile_data.get("snapshot", {})
    files, issues, skipped, total = _snapshot_files(root, settings)
    requested = settings.get("adapters", list(DEFAULT_ADAPTERS))
    adapter_data = {}
    for name in requested:
        try:
            if name == "platform":
                data, partial = _adapter_platform(), False
            elif name == "processes":
                data, partial = _processes_adapter()
            elif name == "listeners":
                data, partial = _listeners_adapter()
            elif name == "services":
                data, partial = _services_adapter()
            elif name == "compose":
                data, partial = _compose_adapter(root, profile_data["compose"])
            else:  # Profile validation should make this unreachable.
                raise PartialError("adapter_not_allowed")
            adapter_data[name] = data
            if partial:
                issues.append({"component": "adapter:" + name, "path": None,
                               "reason": "observation_partial"})
        except PartialError as exc:
            adapter_data[name] = None
            issues.append({"component": "adapter:" + name, "path": None,
                           "reason": str(exc)})
    partial = bool(issues)
    result = {
        "adapters": adapter_data,
        "created_at": _now(),
        "files": files,
        "issues": sorted(issues, key=lambda value: (value["component"], value.get("path") or "",
                                                       value["reason"])),
        "limits": {"max_file_bytes": settings.get("max_file_bytes", 64 * 1024 * 1024),
                   "max_files": settings.get("max_files", 20_000),
                   "max_total_bytes": settings.get("max_total_bytes", 4 * 1024 * 1024 * 1024)},
        "partial": partial,
        "profile": {"name": profile_data["name"], "sha256": _profile_hash(profile_data)},
        "root": _opaque_root_identifier(root),
        "schema": SNAPSHOT_SCHEMA,
        "scope": _snapshot_scope(settings, requested, profile_data.get("compose")),
        "skipped": skipped,
        "summary": {"files": len(files), "total_bytes": total},
        "tool": _tool_record(),
    }
    _validate_snapshot(result)
    output_path = _atomic_write_new(
        args.output, _bounded_canonical(result, MAX_JSON_BYTES, "snapshot")
    )
    print(json.dumps({"output": str(output_path), "partial": partial,
                      "files": len(files), "exit_code": 2 if partial else 0}, sort_keys=True))
    return 2 if partial else 0


def _validate_adapter_value(name, value):
    if value is None:
        return
    if name == "platform":
        _strict_keys(value, {"machine", "python", "release", "system"},
                     {"machine", "system"}, "platform adapter")
        for field, item in value.items():
            _safe_string(item, "platform " + field, 0, 512)
        return
    if name == "compose":
        _strict_keys(value, {"config_files", "project_sha256", "services"},
                     {"config_files", "project_sha256", "services"}, "compose adapter")
        if not isinstance(value["project_sha256"], str) or not OPAQUE_ID.fullmatch(
                value["project_sha256"]):
            raise DefenseError("invalid compose project identifier")
        configs = value["config_files"]
        if not isinstance(configs, list) or not 1 <= len(configs) <= 8:
            raise DefenseError("invalid compose config records")
        config_paths = []
        for record in configs:
            _strict_keys(record, {"path", "sha256", "size"}, {"path", "sha256", "size"},
                         "compose config record")
            path = _portable_relative_posix(record["path"], "compose config path")
            if (type(record["size"]) is not int or
                    not 0 <= record["size"] <= MAX_COMPOSE_FILE_BYTES or
                    not isinstance(record["sha256"], str) or
                    not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
                raise DefenseError("invalid compose config metadata")
            config_paths.append(path)
        if config_paths != sorted(set(config_paths)):
            raise DefenseError("compose configs are not deterministically ordered")
        services = value["services"]
        if not isinstance(services, list) or len(services) > 100_000:
            raise DefenseError("invalid compose service records")
        ordering = []
        for record in services:
            _strict_keys(record, {"count", "health", "service", "state"},
                         {"count", "health", "service", "state"},
                         "compose service record")
            if (not IDENTIFIER.fullmatch(record["service"] if isinstance(
                    record["service"], str) else "") or
                    not isinstance(record["state"], str) or
                    not 1 <= len(record["state"]) <= 64 or
                    record["health"] not in {"healthy", "unhealthy", "starting", "none"} or
                    type(record["count"]) is not int or not 0 <= record["count"] <= 100_000):
                raise DefenseError("invalid compose service state")
            ordering.append((record["service"], record["state"], record["health"]))
        if ordering != sorted(set(ordering)):
            raise DefenseError("compose services are not deterministically ordered")
        return
    if not isinstance(value, list) or len(value) > 100_000:
        raise DefenseError("invalid adapter records")
    for record in value:
        if name == "processes":
            _strict_keys(record, {"name", "pid", "ppid", "uid"},
                         {"name", "pid", "ppid", "uid"}, "process adapter record")
            _safe_string(record["name"], "process name", 0, 1024)
            for field in ("pid", "ppid", "uid"):
                if record[field] is not None and type(record[field]) is not int:
                    raise DefenseError("invalid process adapter identifier")
        elif name == "listeners":
            _strict_keys(record, {"address", "name", "pid", "port", "protocol", "state"},
                         {"address", "port", "protocol", "state"}, "listener adapter record")
            _safe_string(record["address"], "listener address", 1, 256)
            _safe_string(record["protocol"], "listener protocol", 1, 32)
            _safe_string(record["state"], "listener state", 1, 64)
            if type(record["port"]) is not int or not 0 <= record["port"] <= 65535:
                raise DefenseError("invalid listener port")
            if "pid" in record and record["pid"] is not None and type(record["pid"]) is not int:
                raise DefenseError("invalid listener pid")
            if "name" in record and record["name"] is not None:
                _safe_string(record["name"], "listener name", 0, 1024)
        elif name == "services":
            _strict_keys(record, {"active", "load", "name", "pid", "state", "status", "sub"},
                         {"name"}, "service adapter record")
            _safe_string(record["name"], "service name", 1, 1024)
            if "pid" in record and record["pid"] is not None and type(record["pid"]) is not int:
                raise DefenseError("invalid service pid")
            for field in set(record) - {"name", "pid"}:
                _safe_string(record[field], "service " + field, 0, 256)
        else:
            raise DefenseError("unsupported adapter")


def _validate_snapshot(data):
    allowed = {"schema", "tool", "created_at", "profile", "root", "partial", "issues",
               "limits", "files", "adapters", "scope", "skipped", "summary"}
    _strict_keys(data, allowed, allowed, "snapshot")
    if data["schema"] != SNAPSHOT_SCHEMA or type(data["partial"]) is not bool:
        raise DefenseError("invalid snapshot schema")
    _validate_tool_record(data["tool"], "snapshot tool")
    _parse_timestamp(data["created_at"])
    _validate_profile_reference(data["profile"], "snapshot profile")
    scope = _validate_snapshot_scope(data["scope"])
    _safe_string(data["root"], "snapshot root identifier", 1, 4096)
    if not OPAQUE_ID.fullmatch(data["root"]):
        raise DefenseError("snapshot root must be opaque")

    limits = data["limits"]
    _strict_keys(limits, {"max_file_bytes", "max_files", "max_total_bytes"},
                 {"max_file_bytes", "max_files", "max_total_bytes"}, "snapshot limits")
    _positive_int(limits["max_files"], "max_files", 100_000)
    _positive_int(limits["max_file_bytes"], "max_file_bytes", 1024 ** 3)
    _positive_int(limits["max_total_bytes"], "max_total_bytes", 20 * 1024 ** 3)
    if any(limits[key] != scope["files"][key] for key in limits):
        raise DefenseError("snapshot limits do not match scope")

    if not isinstance(data["files"], list) or len(data["files"]) > limits["max_files"]:
        raise DefenseError("invalid snapshot files")
    indexed = {}
    portable_keys = set()
    for item in data["files"]:
        _strict_keys(item, {"path", "size", "mtime_ns", "mode", "sha256"},
                     {"path", "size", "mtime_ns", "mode", "sha256"}, "snapshot file")
        path = _portable_relative_posix(item["path"], "snapshot path")
        portable_key = _portable_path_key(path)
        if path in indexed or portable_key in portable_keys:
            raise DefenseError("duplicate snapshot file")
        if (type(item["size"]) is not int or not 0 <= item["size"] <= limits["max_file_bytes"] or
                type(item["mtime_ns"]) is not int or not 0 <= item["mtime_ns"] <= MAX_MTIME_NS or
                type(item["mode"]) is not int or not 0 <= item["mode"] <= 0o7777 or
                not isinstance(item["sha256"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise DefenseError("invalid snapshot file metadata")
        indexed[path] = item
        portable_keys.add(portable_key)

    issues = data["issues"]
    if not isinstance(issues, list) or len(issues) > 100_000:
        raise DefenseError("invalid snapshot issues")
    for issue in issues:
        _strict_keys(issue, {"component", "path", "reason"},
                     {"component", "path", "reason"}, "snapshot issue")
        _safe_string(issue["component"], "snapshot issue component", 1, 120)
        _safe_string(issue["reason"], "snapshot issue reason", 1, 120)
        if issue["path"] is not None:
            _safe_string(issue["path"], "snapshot issue path", 1, 4096)
    if data["partial"] != bool(issues):
        raise DefenseError("snapshot partial status is inconsistent")

    if not isinstance(data["adapters"], dict) or set(data["adapters"]) - set(ADAPTERS):
        raise DefenseError("invalid snapshot adapters")
    if set(data["adapters"]) != set(scope["adapter_semantics"]):
        raise DefenseError("snapshot adapters do not match scope")
    for name, value in data["adapters"].items():
        _validate_adapter_value(name, value)
        if value is None and not any(issue["component"] == "adapter:" + name for issue in issues):
            raise DefenseError("missing adapter has no partial issue")

    if not isinstance(data["skipped"], dict) or len(data["skipped"]) > 128:
        raise DefenseError("invalid snapshot skipped summary")
    for key, value in data["skipped"].items():
        _safe_string(key, "snapshot skipped key", 1, 120)
        if type(value) is not int or value < 0:
            raise DefenseError("invalid snapshot skipped count")
    summary = data["summary"]
    _strict_keys(summary, {"files", "total_bytes"}, {"files", "total_bytes"},
                 "snapshot summary")
    if (type(summary["files"]) is not int or type(summary["total_bytes"]) is not int or
            summary["files"] != len(data["files"]) or
            summary["total_bytes"] != sum(item["size"] for item in data["files"]) or
            summary["total_bytes"] > limits["max_total_bytes"]):
        raise DefenseError("snapshot summary is inconsistent")
    return data, indexed


def _semantic_adapter(name, value):
    if value is None or name == "platform":
        return value
    if name == "processes":
        counts = Counter((record["name"], record["uid"]) for record in value)
        return [{"count": count, "name": key[0], "uid": key[1]}
                for key, count in sorted(counts.items(), key=lambda item: (item[0][0],
                                                                           item[0][1] is None,
                                                                           item[0][1] or -1))]
    if name == "listeners":
        records = {(record["address"], record["port"], record["protocol"], record["state"])
                   for record in value}
        return [{"address": address, "port": port, "protocol": protocol, "state": state}
                for address, port, protocol, state in sorted(records)]
    if name == "compose":
        return value
    records = []
    for record in value:
        records.append({key: record[key] for key in sorted(record) if key != "pid"})
    return sorted(records, key=_canonical)


def _snapshot_comparison(before_data, after_data, before_sha, after_sha):
    before, old = _validate_snapshot(before_data)
    after, new = _validate_snapshot(after_data)
    reasons = []
    if before["partial"]:
        reasons.append("baseline_partial")
    if after["partial"]:
        reasons.append("current_partial")
    before_scope = before["scope"]
    after_scope = after["scope"]
    if before_scope["tool_compatibility"] != after_scope["tool_compatibility"]:
        reasons.append("tool_semantics_changed")
    if before_scope["adapter_semantics"] != after_scope["adapter_semantics"]:
        reasons.append("adapter_semantics_changed")
    if before_scope["sha256"] != after_scope["sha256"]:
        reasons.append("snapshot_scope_changed")
    if before["profile"] != after["profile"]:
        reasons.append("profile_changed")
    current_major = int(VERSION.split(".", 1)[0])
    if (_tool_major(before["tool"]) != _tool_major(after["tool"]) or
            _tool_major(before["tool"]) != current_major or
            _tool_major(after["tool"]) != current_major):
        reasons.append("tool_incompatible")
    if before["root"] != after["root"]:
        reasons.append("root_changed")
    if set(before["adapters"]) != set(after["adapters"]):
        reasons.append("adapter_scope_changed")
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    content_changed = []
    metadata_changed = []
    for path in sorted(old.keys() & new.keys()):
        if old[path]["sha256"] != new[path]["sha256"] or old[path]["size"] != new[path]["size"]:
            content_changed.append(path)
        elif (old[path]["mode"], old[path]["mtime_ns"]) != (new[path]["mode"], new[path]["mtime_ns"]):
            metadata_changed.append(path)
    changed_adapters = sorted(
        name for name in set(before["adapters"]) & set(after["adapters"])
        if _semantic_adapter(name, before["adapters"][name]) !=
        _semantic_adapter(name, after["adapters"][name]))
    comparable = not reasons
    drift_count = len(added) + len(removed) + len(content_changed) + len(metadata_changed) + len(changed_adapters)
    exit_code = 2 if not comparable else 1 if drift_count else 0
    return {
        "baseline": {"created_at": before["created_at"], "sha256": before_sha},
        "comparable": comparable,
        "compared_at": _now(),
        "current": {"created_at": after["created_at"], "sha256": after_sha},
        "drift": {"adapters_changed": changed_adapters, "files_added": added,
                  "files_content_changed": content_changed,
                  "files_metadata_changed": metadata_changed, "files_removed": removed},
        "exit_code": exit_code,
        "partial": not comparable,
        "profile": before["profile"],
        "reasons": reasons,
        "schema": COMPARISON_SCHEMA,
        "scope": {"baseline_sha256": before_scope["sha256"],
                  "current_sha256": after_scope["sha256"]},
        "summary": {"adapter_changes": len(changed_adapters), "drift_count": drift_count,
                    "files_added": len(added), "files_content_changed": len(content_changed),
                    "files_metadata_changed": len(metadata_changed), "files_removed": len(removed)},
        "tool": _tool_record(),
    }


def command_compare(args):
    baseline, baseline_raw = _read_json(args.baseline)
    current, current_raw = _read_json(args.current)
    result = _snapshot_comparison(baseline, current, _sha256_bytes(baseline_raw),
                                  _sha256_bytes(current_raw))
    print(_canonical(result).decode("utf-8"), end="")
    return result["exit_code"]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_opener():
    return build_opener(ProxyHandler({}), _NoRedirect())


def _health_probe(check):
    started = time.monotonic()
    result = {"name": check["name"], "ok": False, "status": None}
    try:
        request = Request(check["url"], headers={"User-Agent": f"DurkaHelper-defense-ops/{VERSION}"})
        try:
            response = _http_opener().open(request, timeout=float(check.get("timeout", 3.0)))
        except HTTPError as exc:
            response = exc
        with response:
            result["status"] = response.code
            body = response.read(MAX_HTTP_BODY + 1)
        if len(body) > MAX_HTTP_BODY:
            raise ValueError("response limit")
        text = body.decode("utf-8", errors="replace")
        result["ok"] = (result["status"] == check.get("status", 200) and
                        check.get("contains", "") in text)
    except (OSError, ValueError) as exc:
        result["error"] = type(exc).__name__
    result["ms"] = round((time.monotonic() - started) * 1000)
    return result


def command_health(args):
    profile_data = load_profile(args.profile)
    checks = profile_data.get("health")
    if not checks:
        raise DefenseError("profile has no health checks")
    # Profile validation happens in full before the first connection.
    results = [_health_probe(check) for check in checks]
    failed = sum(not result["ok"] for result in results)
    output = {"checked_at": _now(), "command": "health", "exit_code": 1 if failed else 0,
              "profile": {"name": profile_data["name"], "sha256": _profile_hash(profile_data)},
              "results": results, "summary": {"failed": failed, "total": len(results)},
              "tool": _tool_record()}
    print(_canonical(output).decode("utf-8"), end="")
    return output["exit_code"]


def _resolve_profile_path(root: Path, relative: str):
    parts = [] if relative == "." else relative.split("/")
    current = root
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                raise DefenseError("backup source contains a symlink")
        except OSError as exc:
            raise DefenseError("backup source metadata unavailable") from exc
    try:
        current.relative_to(root)
    except ValueError as exc:
        raise DefenseError("backup source leaves root") from exc
    return current


def _live_database_name(path: str):
    lowered = path.lower()
    return (lowered.endswith(LIVE_DATABASE_SUFFIXES) or ".sqlite-" in lowered or
            lowered.endswith((".db-wal", ".db-shm", ".db-journal")))


def _backup_sources(root: Path, backup):
    excluded = backup.get("exclude", [])
    max_files = backup.get("max_files", 20_000)
    sources = []
    seen = set()
    portable_seen = set()
    for entry in backup["entries"]:
        rel = PurePosixPath(entry["path"]).as_posix()
        source = _resolve_profile_path(root, rel)
        kind = entry["kind"]
        if not source.exists():
            raise DefenseError("backup source is missing")
        if kind in {"file", "native_dump"}:
            if not _is_regular(source):
                raise DefenseError("backup source is not a regular file")
            if kind != "native_dump" and _live_database_name(rel):
                raise DefenseError("live database files cannot be copied")
            if kind == "native_dump" and not rel.lower().endswith(NATIVE_DUMP_SUFFIXES):
                raise DefenseError("native dump has an unrecognized dump suffix")
            if rel not in seen and not _matches(rel, excluded):
                portable_key = _portable_path_key(rel)
                if portable_key in portable_seen:
                    raise DefenseError("case-fold-colliding backup source")
                seen.add(rel)
                portable_seen.add(portable_key)
                sources.append((rel, source, kind))
        else:
            if not source.is_dir():
                raise DefenseError("backup tree source is not a directory")
            prefix = "" if rel == "." else rel + "/"
            for found_kind, path, detail in _bounded_walk(source, ["*"], [], max_files,
                                                          require_portable=True):
                if found_kind in {"issue", "limit"}:
                    raise PartialError("backup tree is unreadable or exceeds limits")
                if found_kind == "nonportable":
                    raise DefenseError("backup tree contains a nonportable path")
                if found_kind == "skip":
                    if detail in {"symlink", "special"}:
                        raise DefenseError("backup tree contains a symlink or special file")
                    continue
                child = prefix + detail
                if _matches(child, excluded):
                    continue
                if _live_database_name(child):
                    raise DefenseError("backup tree contains a live database file")
                if child in seen:
                    raise DefenseError("duplicate backup source")
                portable_key = _portable_path_key(child)
                if portable_key in portable_seen:
                    raise DefenseError("case-fold-colliding backup source")
                seen.add(child)
                portable_seen.add(portable_key)
                sources.append((child, path, "tree"))
                if len(sources) > max_files:
                    raise PartialError("backup file limit reached")
    return sorted(sources, key=lambda value: value[0])


def _root_anchor_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))


def _open_anchored_regular(root: Path, relative: str, expected_root_identity):
    relative = _portable_relative_posix(relative, "backup source")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    if (os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and
            os.open in os.supports_dir_fd):
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        current_fd = root_fd
        try:
            if _root_anchor_identity(os.fstat(root_fd)) != expected_root_identity:
                raise PartialError("backup root changed during read")
            parts = relative.split("/")
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=current_fd)
                if current_fd != root_fd:
                    os.close(current_fd)
                current_fd = next_fd
            fd = os.open(parts[-1], flags, dir_fd=current_fd)
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                os.close(fd)
                raise DefenseError("backup source is not regular")
            return fd
        except OSError as exc:
            raise PartialError("backup source identity unavailable") from exc
        finally:
            if current_fd != root_fd:
                os.close(current_fd)
            os.close(root_fd)

    # Windows has no Python dirfd traversal.  Preserve no-follow leaf checks
    # and verify every current ancestor before opening; the POSIX competition
    # paths above use the stronger descriptor-anchored implementation.
    source = root.joinpath(*relative.split("/"))
    current = root
    try:
        if _root_anchor_identity(root.lstat()) != expected_root_identity:
            raise PartialError("backup root changed during read")
        for part in relative.split("/")[:-1]:
            current = current / part
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise PartialError("backup source parent changed during read")
        return os.open(source, flags)
    except OSError as exc:
        raise PartialError("backup source identity unavailable") from exc


def _hash_anchored_regular(root: Path, relative: str, expected_root_identity,
                           max_bytes: int):
    fd = _open_anchored_regular(root, relative, expected_root_identity)
    try:
        before = os.fstat(fd)
        if before.st_size > max_bytes:
            raise PartialError("compose_config_too_large")
        digest = hashlib.sha256()
        consumed = 0
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            consumed += len(block)
            if consumed > max_bytes:
                raise PartialError("compose_config_too_large")
            digest.update(block)
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after):
            raise PartialError("compose_config_changed_during_read")
        return before, digest.hexdigest()
    finally:
        os.close(fd)


def _copy_stable(root: Path, relative: str, destination: Path, max_bytes: int,
                 total_state, expected_root_identity):
    fd = _open_anchored_regular(root, relative, expected_root_identity)
    staging_destination = (isinstance(destination, tuple) and len(destination) == 2 and
                           isinstance(destination[0], _StagingDirectory))
    if staging_destination:
        staging, staging_relative = destination
        destination_path = None
    else:
        destination_path = Path(destination)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise DefenseError("backup source is not regular")
        if before.st_size > max_bytes:
            raise PartialError("backup file byte limit reached")
        if total_state[0] + before.st_size > total_state[1]:
            raise PartialError("backup total byte limit reached")
        if staging_destination:
            target_fd = staging.open_new_file(staging_relative, 0o600)
        else:
            destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target_fd = os.open(destination_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                getattr(os, "O_BINARY", 0), 0o600)
        digest = hashlib.sha256()
        consumed = 0
        with os.fdopen(fd, "rb", closefd=False) as source_stream, os.fdopen(target_fd, "wb") as target:
            while True:
                block = source_stream.read(CHUNK)
                if not block:
                    break
                consumed += len(block)
                if consumed > max_bytes:
                    raise PartialError("backup file byte limit reached")
                digest.update(block)
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after):
            if not staging_destination:
                try:
                    destination_path.unlink()
                except OSError:
                    pass
            raise PartialError("backup source changed while reading")
        if staging_destination:
            staging.set_file_metadata(staging_relative, 0o600)
        else:
            try:
                destination_path.chmod(0o600)
            except OSError:
                pass
        total_state[0] += consumed
        return before, digest.hexdigest()
    finally:
        os.close(fd)


def _regular_path_identity(root: Path, relative: str, expected_root_identity):
    fd = _open_anchored_regular(root, relative, expected_root_identity)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise DefenseError("backup source is not regular")
        return _stat_identity(metadata)
    finally:
        os.close(fd)


def _manifest_bundle_hash(entries):
    return _sha256_bytes(_canonical(entries))


def command_backup_create(args):
    profile_data = load_profile(args.profile)
    backup = profile_data.get("backup")
    if not backup:
        raise DefenseError("profile has no backup entries")
    root = _canonical_root_directory(Path(args.root))
    root_identity = _root_anchor_identity(root.lstat())
    target = _safe_output_parent(Path(args.output))
    sources = _backup_sources(root, backup)
    if not sources:
        raise DefenseError("backup selection is empty")
    max_file_bytes = backup.get("max_file_bytes", 1024 * 1024 * 1024)
    total_state = [0, backup.get("max_total_bytes", 20 * 1024 * 1024 * 1024)]
    identities = {relative: _regular_path_identity(root, relative, root_identity)
                  for relative, source, _kind in sources}
    staging = _StagingDirectory.create(target, ".defense-backup-")
    try:
        staging.mkdir("files")
        manifest_entries = []
        for number, (relative, source, kind) in enumerate(sources, 1):
            stored = f"files/{number:06d}.bin"
            metadata, digest = _copy_stable(root, relative, (staging, stored), max_file_bytes,
                                            total_state, root_identity)
            if _stat_identity(metadata) != identities[relative]:
                raise PartialError("backup source changed before copy")
            manifest_entries.append({
                "kind": kind,
                "mode": stat.S_IMODE(metadata.st_mode),
                "mtime_ns": metadata.st_mtime_ns,
                "sha256": digest,
                "size": metadata.st_size,
                "source": relative,
                "stored": stored,
            })
        rechecked_sources = _backup_sources(root, backup)
        if ([(relative, kind) for relative, _source, kind in rechecked_sources] !=
                [(relative, kind) for relative, _source, kind in sources]):
            raise PartialError("backup source membership changed during copy")
        for relative, source, _kind in sources:
            if _regular_path_identity(root, relative, root_identity) != identities[relative]:
                raise PartialError("backup source set changed during copy")
        manifest = {
            "bundle_sha256": _manifest_bundle_hash(manifest_entries),
            "created_at": _now(),
            "entries": manifest_entries,
            "profile": {"name": profile_data["name"], "sha256": _profile_hash(profile_data)},
            "root": _opaque_root_identifier(root),
            "schema": BACKUP_SCHEMA,
            "summary": {"files": len(manifest_entries), "total_bytes": total_state[0]},
            "tool": _tool_record(),
        }
        _validate_backup_manifest(manifest)
        manifest_payload = _bounded_canonical(manifest, MAX_JSON_BYTES, "backup manifest")
        staging.write_new_bytes("manifest.json", manifest_payload)
        _publish_directory(staging, target)
    finally:
        staging.cleanup()
    output = {"backup": str(target), "bundle_sha256": manifest["bundle_sha256"],
              "exit_code": 0, "files": len(manifest_entries), "total_bytes": total_state[0]}
    print(_canonical(output).decode("utf-8"), end="")
    return 0


def _validate_backup_manifest(data):
    _strict_keys(data, {"schema", "tool", "created_at", "profile", "root", "entries",
                        "summary", "bundle_sha256"},
                 {"schema", "tool", "created_at", "profile", "root", "entries",
                  "summary", "bundle_sha256"}, "backup manifest")
    if (data["schema"] != BACKUP_SCHEMA or not isinstance(data["bundle_sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", data["bundle_sha256"])):
        raise DefenseError("invalid backup manifest schema")
    _validate_tool_record(data["tool"], "backup tool")
    _parse_timestamp(data["created_at"])
    _validate_profile_reference(data["profile"], "backup profile")
    if not isinstance(data["root"], str) or not OPAQUE_ID.fullmatch(data["root"]):
        raise DefenseError("backup root must be opaque")
    if not isinstance(data["entries"], list) or not 1 <= len(data["entries"]) <= 100_000:
        raise DefenseError("invalid backup entries")
    sources = set()
    portable_sources = set()
    stored_paths = set()
    total_bytes = 0
    ordered_sources = []
    for number, entry in enumerate(data["entries"], 1):
        _strict_keys(entry, {"source", "stored", "kind", "size", "sha256", "mode", "mtime_ns"},
                     {"source", "stored", "kind", "size", "sha256", "mode", "mtime_ns"},
                     "backup manifest entry")
        source = _portable_relative_posix(entry["source"], "backup source", allow_dot=True)
        stored = _relative_posix(entry["stored"], "backup stored path")
        portable_key = _portable_path_key(source)
        if (stored != f"files/{number:06d}.bin" or source in sources or
                portable_key in portable_sources or stored in stored_paths):
            raise DefenseError("duplicate or invalid backup entry")
        if (not isinstance(entry["kind"], str) or
                entry["kind"] not in {"file", "tree", "native_dump"}):
            raise DefenseError("invalid backup entry kind")
        if (type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_IMPORTED_FILE_BYTES or
                type(entry["mode"]) is not int or not 0 <= entry["mode"] <= 0o7777 or
                type(entry["mtime_ns"]) is not int or not 0 <= entry["mtime_ns"] <= MAX_MTIME_NS or
                not isinstance(entry["sha256"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise DefenseError("invalid backup entry metadata")
        sources.add(source)
        portable_sources.add(portable_key)
        stored_paths.add(stored)
        ordered_sources.append(source)
        total_bytes += entry["size"]
        if total_bytes > MAX_IMPORTED_TOTAL_BYTES:
            raise DefenseError("backup manifest total exceeds limit")
    if ordered_sources != sorted(ordered_sources):
        raise DefenseError("backup entries are not deterministically ordered")
    for index, source in enumerate(ordered_sources):
        if source == "." or any(other.startswith(source + "/")
                                for other in ordered_sources[index + 1:]):
            raise DefenseError("backup source paths overlap")
    summary = data["summary"]
    _strict_keys(summary, {"files", "total_bytes"}, {"files", "total_bytes"},
                 "backup summary")
    if (type(summary["files"]) is not int or type(summary["total_bytes"]) is not int or
            summary["files"] != len(data["entries"]) or summary["total_bytes"] != total_bytes):
        raise DefenseError("backup summary is inconsistent")
    if data["bundle_sha256"] != _manifest_bundle_hash(data["entries"]):
        raise DefenseError("backup manifest bundle hash mismatch")
    return data


def _load_backup(backup_path):
    backup = _canonical_input_leaf(Path(backup_path))
    if not backup.is_dir():
        raise DefenseError("backup must be a directory")
    manifest, raw = _read_json(backup / "manifest.json")
    return backup, _validate_backup_manifest(manifest), raw


def _verify_backup(backup, manifest):
    expected = {entry["stored"] for entry in manifest["entries"]}
    expected_directories = {"files"}
    for stored in expected:
        parent = PurePosixPath(stored).parent
        while parent.as_posix() not in {".", ""}:
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual = set()
    actual_directories = {"files"}
    files_root = backup / "files"
    if not files_root.is_dir() or files_root.is_symlink():
        raise DefenseError("backup files directory is invalid")
    try:
        top_level = sorted(item.name for item in backup.iterdir())
    except OSError as exc:
        raise DefenseError("backup directory is unreadable") from exc
    if top_level != ["files", "manifest.json"]:
        raise DefenseError("backup contains unexpected top-level entries")
    for root, directories, files in os.walk(files_root, followlinks=False):
        directories.sort()
        files.sort()
        for name in list(directories):
            path = Path(root) / name
            if path.is_symlink():
                raise DefenseError("backup contains a symlink")
            actual_directories.add(path.relative_to(backup).as_posix())
        for name in files:
            path = Path(root) / name
            if path.is_symlink() or not _is_regular(path):
                raise DefenseError("backup contains a non-regular file")
            actual.add(path.relative_to(backup).as_posix())
    problems = []
    for entry in manifest["entries"]:
        path = backup / PurePosixPath(entry["stored"])
        try:
            metadata, digest = _hash_regular(path, max(entry["size"], 1))
        except (OSError, PartialError):
            problems.append({"path": entry["stored"], "reason": "missing_or_unreadable"})
            continue
        if metadata.st_size != entry["size"] or digest != entry["sha256"]:
            problems.append({"path": entry["stored"], "reason": "checksum_mismatch"})
    for extra in sorted(actual - expected):
        problems.append({"path": extra, "reason": "unexpected_file"})
    for missing in sorted(expected - actual):
        if not any(item["path"] == missing for item in problems):
            problems.append({"path": missing, "reason": "missing_file"})
    for extra in sorted(actual_directories - expected_directories):
        problems.append({"path": extra, "reason": "unexpected_directory"})
    return sorted(problems, key=lambda value: (value["path"], value["reason"]))


def command_backup_verify(args):
    backup, manifest, _raw = _load_backup(args.backup)
    problems = _verify_backup(backup, manifest)
    output = {"backup": str(backup), "checked_at": _now(), "exit_code": 1 if problems else 0,
              "problems": problems, "summary": {"files": len(manifest["entries"]),
                                                  "problems": len(problems)},
              "tool": _tool_record()}
    print(_canonical(output).decode("utf-8"), end="")
    return output["exit_code"]


def _validate_approval_id(value):
    if (not isinstance(value, str) or not APPROVAL_ID.fullmatch(value) or
            value.lower() in {"approved", "approval", "yes", "true", "apply", "restore"}):
        raise DefenseError("a specific safe approval id is required")
    return value


def _safe_restore_mode(value):
    if type(value) is not int or not 0 <= value <= 0o7777:
        raise DefenseError("invalid restore mode")
    return value & 0o755


def command_restore_stage(args):
    backup, manifest, _raw = _load_backup(args.backup)
    problems = _verify_backup(backup, manifest)
    if problems:
        output = {"command": "restore-stage", "exit_code": 1, "problems": problems,
                  "status": "backup_verification_failed", "tool": _tool_record()}
        print(_canonical(output).decode("utf-8"), end="")
        return 1
    target = _safe_output_parent(Path(args.target))
    try:
        target.relative_to(backup)
    except ValueError:
        pass
    else:
        raise DefenseError("restore staging target cannot be inside the backup")
    if not args.apply:
        output = {"apply_required": True, "backup": str(backup), "command": "restore-stage",
                  "exit_code": 0, "files": len(manifest["entries"]), "status": "safe_to_stage",
                  "target": str(target), "tool": _tool_record()}
        print(_canonical(output).decode("utf-8"), end="")
        return 0
    approval_id = _validate_approval_id(args.approval_id)
    backup_root_identity = _root_anchor_identity(backup.lstat())
    staging = _StagingDirectory.create(target, ".defense-restore-")
    try:
        for entry in manifest["entries"]:
            state = [0, max(entry["size"], 1)]
            metadata, digest = _copy_stable(
                backup, entry["stored"], (staging, entry["source"]),
                max(entry["size"], 1), state,
                backup_root_identity
            )
            if metadata.st_size != entry["size"] or digest != entry["sha256"]:
                raise DefenseError("backup changed during restore")
            # Never restore set-id/sticky bits or group/world write access.
            # Preserve only the original owner rwx and shared read/execute bits.
            safe_mode = _safe_restore_mode(entry["mode"])
            try:
                staging.set_file_metadata(entry["source"], safe_mode, entry["mtime_ns"])
            except OSError as exc:
                raise PartialError("could not restore required file metadata") from exc
        _publish_directory(staging, target)
    finally:
        staging.cleanup()
    output = {"approval_id": approval_id, "backup": str(backup), "command": "restore-stage",
              "exit_code": 0, "files": len(manifest["entries"]), "status": "staged",
              "target": str(target), "tool": _tool_record()}
    print(_canonical(output).decode("utf-8"), end="")
    return 0


def _parse_timestamp(value):
    _safe_string(value, "timestamp", 20, 40)
    if not RFC3339.fullmatch(value):
        raise DefenseError("timestamp must be RFC3339 with timezone")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DefenseError("invalid event timestamp") from exc
    if parsed.tzinfo is None:
        raise DefenseError("event timestamp needs a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _secret_string(value):
    return any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS)


def _validate_safe_attributes(value, field="attributes"):
    if not isinstance(value, dict) or len(value) > 64:
        raise DefenseError("invalid " + field)
    result = {}
    for key, item in value.items():
        _safe_string(key, field + " key", 1, 64)
        if SECRET_KEY.search(_normalized_key(key)) or _normalized_key(key) in COMMAND_KEYS:
            raise DefenseError(field + " contains a forbidden key")
        if item is not None and type(item) not in (str, int, float, bool):
            raise DefenseError(field + " values must be scalar")
        if type(item) is float and not math.isfinite(item):
            raise DefenseError(field + " contains a non-finite number")
        if isinstance(item, str):
            _safe_string(item, field + " value", 0, 4096)
            if _secret_string(item):
                raise DefenseError(field + " contains secret-looking text")
        result[key] = item
    return result


def _validate_event(value):
    _strict_keys(value, {"schema", "id", "timestamp", "source", "kind", "severity",
                         "summary", "attributes"},
                 {"schema", "timestamp", "source", "kind", "severity", "summary"}, "event")
    if value["schema"] != EVENT_SCHEMA:
        raise DefenseError("unsupported event schema")
    _parse_timestamp(value["timestamp"])
    _safe_string(value["source"], "event source", 1, 120)
    if _secret_string(value["source"]):
        raise DefenseError("event source contains secret-looking text")
    if not IDENTIFIER.fullmatch(value["kind"] if isinstance(value["kind"], str) else ""):
        raise DefenseError("invalid event kind")
    if (not isinstance(value["severity"], str) or
            value["severity"] not in {"info", "low", "medium", "high", "critical"}):
        raise DefenseError("invalid event severity")
    _safe_string(value["summary"], "event summary", 1, 512)
    if _secret_string(value["summary"]):
        raise DefenseError("event summary contains secret-looking text")
    if "id" in value:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                            value["id"] if isinstance(value["id"], str) else ""):
            raise DefenseError("invalid event id")
    if "attributes" in value:
        _validate_safe_attributes(value["attributes"])
    return value


def _validate_validation_record(value):
    _strict_keys(value, {"schema", "id", "timestamp", "check", "status", "summary",
                         "evidence", "attributes"},
                 {"schema", "id", "timestamp", "check", "status", "summary"},
                 "validation record")
    if value["schema"] != VALIDATION_SCHEMA:
        raise DefenseError("unsupported validation record schema")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                        value["id"] if isinstance(value["id"], str) else ""):
        raise DefenseError("invalid validation id")
    _parse_timestamp(value["timestamp"])
    _safe_string(value["check"], "validation check", 1, 120)
    if (not isinstance(value["status"], str) or
            value["status"] not in {"pass", "fail", "partial", "blocked", "not_run",
                                    "skipped_not_applicable"}):
        raise DefenseError("invalid validation status")
    _safe_string(value["summary"], "validation summary", 1, 512)
    if _secret_string(value["summary"]):
        raise DefenseError("validation summary contains secret-looking text")
    if "evidence" in value:
        evidence = value["evidence"]
        if not isinstance(evidence, list) or len(evidence) > 128:
            raise DefenseError("invalid validation evidence")
        for reference in evidence:
            _relative_posix(reference, "evidence reference")
    if "attributes" in value:
        _validate_safe_attributes(value["attributes"])
    return value


def _parse_events_bytes(raw, suffix):
    events = []
    if suffix == ".jsonl":
        for line_number, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            if len(line) > MAX_EVENT_LINE:
                raise DefenseError("event line exceeds limit")
            try:
                event = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                                   parse_constant=_reject_constant)
            except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
                raise DefenseError("invalid JSONL event") from exc
            events.append(_validate_event(event))
            if len(events) > MAX_EVENTS:
                raise DefenseError("event count exceeds limit")
    elif suffix == ".json":
        try:
            value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                               parse_constant=_reject_constant)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise DefenseError("invalid JSON event") from exc
        values = value if isinstance(value, list) else [value]
        if len(values) > MAX_EVENTS:
            raise DefenseError("event count exceeds limit")
        events.extend(_validate_event(item) for item in values)
    else:
        raise DefenseError("events must be .json or .jsonl")
    return events


def _read_events(path):
    raw = _read_regular_bytes(path, MAX_JSON_BYTES)
    return _parse_events_bytes(raw, Path(path).suffix.lower())


def command_timeline(args):
    events = []
    total_bytes = 0
    for path in args.events:
        try:
            size = Path(path).lstat().st_size
        except OSError as exc:
            raise DefenseError("event input unavailable") from exc
        total_bytes += size
        if total_bytes > MAX_JSON_BYTES:
            raise DefenseError("combined events exceed byte limit")
        events.extend(_read_events(path))
        if len(events) > MAX_EVENTS:
            raise DefenseError("event count exceeds limit")
    if not events:
        raise DefenseError("timeline has no events")
    identifiers = set()
    for event in events:
        if "id" in event:
            if event["id"] in identifiers:
                raise DefenseError("duplicate event id")
            identifiers.add(event["id"])
    events.sort(key=lambda value: (_parse_timestamp(value["timestamp"]), value["source"],
                                   value["kind"], value.get("id", ""), value["summary"],
                                   _canonical(value)))
    payload = b"".join(_canonical(event) for event in events)
    output_path = _atomic_write_new(args.output, payload)
    findings = sum(event["severity"] in {"high", "critical"} for event in events)
    print(json.dumps({"events": len(events), "exit_code": 1 if findings else 0,
                      "high_or_critical": findings,
                      "output": str(output_path)}, sort_keys=True))
    return 1 if findings else 0


def _validate_comparison(value):
    fields = {"schema", "tool", "compared_at", "baseline", "current", "profile", "scope",
              "comparable", "partial", "reasons", "drift", "summary", "exit_code"}
    _strict_keys(value, fields, fields,
                 "comparison")
    if value["schema"] != COMPARISON_SCHEMA or type(value["comparable"]) is not bool or type(value["partial"]) is not bool:
        raise DefenseError("invalid comparison schema")
    if type(value["exit_code"]) is not int or value["exit_code"] not in {0, 1, 2}:
        raise DefenseError("invalid comparison exit code")
    _validate_tool_record(value["tool"], "comparison tool")
    _parse_timestamp(value["compared_at"])
    _validate_profile_reference(value["profile"], "comparison profile")
    for name in ("baseline", "current"):
        item = value[name]
        _strict_keys(item, {"created_at", "sha256"}, {"created_at", "sha256"},
                     name + " comparison input")
        _parse_timestamp(item["created_at"])
        if not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise DefenseError("invalid comparison input hash")
    scope = value["scope"]
    _strict_keys(scope, {"baseline_sha256", "current_sha256"},
                 {"baseline_sha256", "current_sha256"}, "comparison scope")
    if any(not isinstance(scope[key], str) or not re.fullmatch(r"[0-9a-f]{64}", scope[key])
           for key in scope):
        raise DefenseError("invalid comparison scope hash")
    if (not isinstance(value["drift"], dict) or not isinstance(value["reasons"], list) or
            len(value["reasons"]) > 16 or
            any(not isinstance(reason, str) for reason in value["reasons"]) or
            len(set(value["reasons"])) != len(value["reasons"])):
        raise DefenseError("invalid comparison content")
    allowed_drift = {"adapters_changed", "files_added", "files_content_changed",
                     "files_metadata_changed", "files_removed"}
    if set(value["drift"]) != allowed_drift:
        raise DefenseError("invalid comparison drift")
    for name, items in value["drift"].items():
        if (not isinstance(items, list) or len(items) > 100_000 or
                any(not isinstance(item, str) for item in items) or
                items != sorted(set(items))):
            raise DefenseError("invalid comparison drift entries")
        if name == "adapters_changed":
            if any(item not in ADAPTERS for item in items):
                raise DefenseError("invalid comparison adapter drift")
        else:
            for item in items:
                _portable_relative_posix(item, "comparison path")
    summary = value["summary"]
    summary_fields = {"adapter_changes", "drift_count", "files_added",
                      "files_content_changed", "files_metadata_changed", "files_removed"}
    _strict_keys(summary, summary_fields, summary_fields, "comparison summary")
    expected = {
        "adapter_changes": len(value["drift"]["adapters_changed"]),
        "files_added": len(value["drift"]["files_added"]),
        "files_content_changed": len(value["drift"]["files_content_changed"]),
        "files_metadata_changed": len(value["drift"]["files_metadata_changed"]),
        "files_removed": len(value["drift"]["files_removed"]),
    }
    expected["drift_count"] = sum(expected.values())
    if any(type(summary[key]) is not int or summary[key] != expected[key] for key in summary_fields):
        raise DefenseError("comparison summary is inconsistent")
    if value["comparable"] == value["partial"] or value["comparable"] != (not value["reasons"]):
        raise DefenseError("comparison compatibility status is inconsistent")
    expected_exit = 2 if value["partial"] else 1 if summary["drift_count"] else 0
    if value["exit_code"] != expected_exit:
        raise DefenseError("comparison exit code is inconsistent")
    return value


def _validate_approved_drift(value, comparison, baseline_sha256, current_sha256):
    fields = {"schema", "id", "reviewed_at", "baseline_sha256", "current_sha256", "drift"}
    _strict_keys(value, fields, fields, "approved drift")
    if value["schema"] != APPROVED_DRIFT_SCHEMA:
        raise DefenseError("unsupported approved drift schema")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}",
                        value["id"] if isinstance(value["id"], str) else ""):
        raise DefenseError("invalid approved drift id")
    reviewed_at = _parse_timestamp(value["reviewed_at"])
    if reviewed_at < _parse_timestamp(comparison["current"]["created_at"]):
        raise DefenseError("approved drift predates current snapshot")
    if (value["baseline_sha256"] != baseline_sha256 or
            value["current_sha256"] != current_sha256):
        raise DefenseError("approved drift is bound to different snapshots")
    drift = value["drift"]
    if not isinstance(drift, dict) or set(drift) != set(comparison["drift"]):
        raise DefenseError("invalid approved drift entries")
    normalized = {}
    for name, entries in drift.items():
        if (not isinstance(entries, list) or len(entries) > 100_000 or
                entries != sorted(set(entries))):
            raise DefenseError("invalid approved drift entries")
        if name == "adapters_changed":
            if any(entry not in ADAPTERS for entry in entries):
                raise DefenseError("invalid approved adapter drift")
        else:
            for entry in entries:
                _portable_relative_posix(entry, "approved drift path")
        normalized[name] = entries
    if normalized != comparison["drift"]:
        raise DefenseError("approved drift does not exactly match observed drift")
    return value


def _reject_evidence_secrets(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if SECRET_KEY.search(_normalized_key(key)) or _normalized_key(key) in COMMAND_KEYS:
                raise DefenseError("evidence contains a forbidden key")
            _reject_evidence_secrets(child)
    elif isinstance(value, list):
        for child in value:
            _reject_evidence_secrets(child)
    elif isinstance(value, str):
        if _secret_string(value) or _secret_filename(Path(value).name):
            raise DefenseError("evidence contains secret-looking text")


def _validate_scanner_scope(value):
    fields = {"schema", "root", "rules_sha256", "exclude", "limits",
              "path_semantics", "sha256"}
    if isinstance(value, dict) and value.get("schema") == SCANNER_SCOPE_V2:
        fields |= {"semantic_revision", "context_sha256"}
    _strict_keys(value, fields, fields, "scanner scope")
    if (value["schema"] not in {SCANNER_SCOPE_SCHEMA, SCANNER_SCOPE_V2} or
            value["path_semantics"] != SCANNER_PATH_SEMANTICS or
            not isinstance(value["root"], str) or not OPAQUE_ID.fullmatch(value["root"]) or
            not isinstance(value["rules_sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", value["rules_sha256"])):
        raise DefenseError("invalid scanner scope")
    exclude = value["exclude"]
    if (not isinstance(exclude, list) or len(exclude) > 10_000 or
            exclude != sorted(set(exclude)) or
            any(not isinstance(item, str) or not 1 <= len(item) <= 4096 or "\x00" in item
                for item in exclude)):
        raise DefenseError("invalid scanner scope exclusions")
    limits = value["limits"]
    _strict_keys(limits, {"max_bytes", "max_files", "max_findings"},
                 {"max_bytes", "max_files", "max_findings"}, "scanner scope limits")
    for name in ("max_bytes", "max_files", "max_findings"):
        _positive_int(limits[name], "scanner " + name, 2 ** 63 - 1)
    body = {name: value[name] for name in
            ("schema", "root", "rules_sha256", "exclude", "limits", "path_semantics")}
    if value["schema"] == SCANNER_SCOPE_V2:
        if (value["semantic_revision"] not in {"bounded-source-signals.v2", "bounded-source-signals.v3"} or
                not isinstance(value["context_sha256"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", value["context_sha256"])):
            raise DefenseError("invalid scanner context semantics")
        body.update({name: value[name] for name in ("semantic_revision", "context_sha256")})
    expected = _sha256_bytes(json.dumps(body, ensure_ascii=True, sort_keys=True,
                                        separators=(",", ":"), allow_nan=False).encode("utf-8"))
    if value["sha256"] != expected:
        raise DefenseError("invalid scanner scope digest")
    return {**body, "sha256": expected}


def _sanitize_scanner_report(value):
    if (not isinstance(value, dict) or value.get("tool") != "DurkaHelper defense_scan" or
            value.get("offline") is not True or type(value.get("partial")) is not bool or
            type(value.get("exit_code")) is not int or value.get("exit_code") not in {0, 1, 2}):
        raise DefenseError("invalid scanner report")
    version = value.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,63}", version):
        raise DefenseError("invalid scanner version")
    findings = value.get("findings")
    issues = value.get("issues")
    if (not isinstance(findings, list) or not isinstance(issues, list) or
            len(findings) > 100_000 or len(issues) > 100_000):
        raise DefenseError("invalid scanner report")
    expected_exit_code = 2 if issues else 1 if findings else 0
    if (value["partial"] != bool(issues) or
            value["exit_code"] != expected_exit_code):
        raise DefenseError("inconsistent scanner report status")
    created_at = value.get("created_at")
    scope = value.get("scope")
    if (created_at is None) != (scope is None):
        raise DefenseError("incomplete scanner scope metadata")
    if created_at is not None:
        _parse_timestamp(created_at)
        scope = _validate_scanner_scope(scope)
    safe_findings = []
    for item in findings:
        if not isinstance(item, dict):
            raise DefenseError("invalid scanner finding")
        path, line, rule = item.get("path"), item.get("line"), item.get("rule")
        _relative_posix(path, "scanner finding path")
        if (type(line) is not int or line < 1 or not isinstance(rule, str) or len(rule) > 100 or
                not re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+", rule)):
            raise DefenseError("invalid scanner finding")
        safe_findings.append({"line": line, "path": path, "rule": rule})
    safe_issues = []
    for item in issues:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("reason"), str):
            raise DefenseError("invalid scanner issue")
        _relative_posix(item["path"], "scanner issue path", allow_dot=True)
        _safe_string(item["reason"], "scanner issue reason", 1, 120)
        safe_issues.append({"path": item["path"], "reason": item["reason"]})
    return {"exit_code": value["exit_code"], "findings": sorted(safe_findings,
            key=lambda item: (item["path"], item["line"], item["rule"])),
            "issues": sorted(safe_issues, key=lambda item: (item["path"], item["reason"])),
            "offline": True, "partial": value["partial"], "tool": value["tool"],
            "version": version, "created_at": created_at, "scope": scope}


def _hashed_record_groups(records):
    counts = Counter(_sha256_bytes(_canonical(record)) for record in records)
    return [{"count": count, "record_sha256": digest}
            for digest, count in sorted(counts.items())]


def _safe_adapter_evidence(name, value):
    if value is None:
        return {"available": False, "records": 0}
    if name == "platform":
        return {"available": True, **{key: value[key] for key in
                ("machine", "python", "release", "system") if key in value}}
    if name == "compose":
        return {
            "available": True,
            "config_files": [
                {"content_sha256": item["sha256"],
                 "path_sha256": _opaque_text_identifier(item["path"]),
                 "size": item["size"]}
                for item in value["config_files"]
            ],
            "project_sha256": value["project_sha256"],
            "service_groups": _hashed_record_groups(value["services"]),
            "services": len(value["services"]),
        }
    semantic = _semantic_adapter(name, value)
    return {"available": True, "groups": _hashed_record_groups(semantic),
            "records": len(value)}


def _safe_snapshot_evidence(value):
    snapshot, _indexed = _validate_snapshot(value)
    issue_counts = Counter((item["component"], item["reason"]) for item in snapshot["issues"])
    return {
        "adapters": {name: _safe_adapter_evidence(name, snapshot["adapters"][name])
                     for name in sorted(snapshot["adapters"])},
        "created_at": snapshot["created_at"],
        "files": [{"content_sha256": item["sha256"],
                   "path_sha256": _opaque_text_identifier(item["path"]),
                   "size": item["size"]} for item in snapshot["files"]],
        "issues": [{"component": component, "count": count, "reason": reason}
                   for (component, reason), count in sorted(issue_counts.items())],
        "partial": snapshot["partial"],
        "profile_sha256": snapshot["profile"]["sha256"],
        "root": snapshot["root"],
        "schema": "durkahelper.snapshot-evidence.safe.v1",
        "scope_sha256": snapshot["scope"]["sha256"],
        "summary": dict(snapshot["summary"]),
        "tool": dict(snapshot["tool"]),
    }


def _safe_comparison_evidence(value):
    comparison = _validate_comparison(value)
    drift = {"adapters_changed": list(comparison["drift"]["adapters_changed"])}
    for name in ("files_added", "files_content_changed", "files_metadata_changed", "files_removed"):
        drift[name] = [_opaque_text_identifier(path) for path in comparison["drift"][name]]
    return {
        "baseline": dict(comparison["baseline"]),
        "comparable": comparison["comparable"],
        "compared_at": comparison["compared_at"],
        "current": dict(comparison["current"]),
        "drift": drift,
        "exit_code": comparison["exit_code"],
        "partial": comparison["partial"],
        "profile_sha256": comparison["profile"]["sha256"],
        "reasons": list(comparison["reasons"]),
        "schema": "durkahelper.comparison-evidence.safe.v1",
        "scope": dict(comparison["scope"]),
        "summary": dict(comparison["summary"]),
        "tool": dict(comparison["tool"]),
    }


def _safe_backup_evidence(value):
    manifest = _validate_backup_manifest(value)
    return {
        "bundle_sha256": manifest["bundle_sha256"],
        "created_at": manifest["created_at"],
        "entries": [{"content_sha256": entry["sha256"], "kind": entry["kind"],
                     "safe_mode": _safe_restore_mode(entry["mode"]), "size": entry["size"],
                     "source_sha256": _opaque_text_identifier(entry["source"])}
                    for entry in manifest["entries"]],
        "profile_sha256": manifest["profile"]["sha256"],
        "root": manifest["root"],
        "schema": "durkahelper.backup-evidence.safe.v1",
        "summary": dict(manifest["summary"]),
        "tool": dict(manifest["tool"]),
    }


def _sanitize_operation_result(value):
    command = value.get("command") if isinstance(value, dict) else None
    if command == "health":
        allowed = {"checked_at", "command", "exit_code", "profile", "results", "summary", "tool"}
        if (set(value) != allowed or type(value.get("exit_code")) is not int or
                value["exit_code"] not in {0, 1} or not isinstance(value.get("results"), list)):
            raise DefenseError("invalid health result")
        _parse_timestamp(value["checked_at"])
        _validate_tool_record(value["tool"], "health result tool")
        _validate_profile_reference(value["profile"], "health result profile")
        results = []
        for item in value["results"]:
            if not isinstance(item, dict) or set(item) - {"name", "ok", "status", "ms", "error"}:
                raise DefenseError("invalid health result")
            if (not isinstance(item.get("name"), str) or type(item.get("ok")) is not bool or
                    item.get("status") is not None and type(item.get("status")) is not int or
                    type(item.get("ms")) is not int):
                raise DefenseError("invalid health result")
            if item.get("status") is not None and not 100 <= item["status"] <= 599:
                raise DefenseError("invalid health status result")
            if item["ms"] < 0 or item["ms"] > 3_600_000:
                raise DefenseError("invalid health duration")
            error = item.get("error")
            if error is not None:
                _safe_string(error, "health error", 1, 120)
            results.append({"error": error, "ms": item["ms"],
                            "name_sha256": _opaque_text_identifier(item["name"]),
                            "ok": item["ok"], "status": item.get("status")})
        summary = value["summary"]
        _strict_keys(summary, {"failed", "total"}, {"failed", "total"}, "health summary")
        if (type(summary["failed"]) is not int or type(summary["total"]) is not int or
                summary["total"] != len(results) or
                summary["failed"] != sum(not item["ok"] for item in results)):
            raise DefenseError("inconsistent health summary")
        if value["exit_code"] != (1 if summary["failed"] else 0):
            raise DefenseError("inconsistent health exit code")
        return {"checked_at": value["checked_at"], "operation": command,
                "exit_code": value["exit_code"], "profile_sha256": value["profile"]["sha256"],
                "results": results, "schema": "durkahelper.operation-result.safe.v1",
                "summary": dict(summary), "tool": dict(value["tool"])}
    if command == "preflight":
        allowed = {"checks", "command", "exit_code", "partial", "platform", "profile", "tool"}
        if (set(value) != allowed or not isinstance(value.get("checks"), list) or
                type(value.get("partial")) is not bool or
                type(value.get("exit_code")) is not int or value["exit_code"] not in {0, 2}):
            raise DefenseError("invalid preflight result")
        _validate_tool_record(value["tool"], "preflight result tool")
        _validate_profile_reference(value["profile"], "preflight result profile")
        _validate_adapter_value("platform", value["platform"])
        checks = []
        for item in value["checks"]:
            if (not isinstance(item, dict) or set(item) != {"name", "ok", "reason"} or
                    not isinstance(item["name"], str) or type(item["ok"]) is not bool or
                    item["reason"] is not None and not isinstance(item["reason"], str)):
                raise DefenseError("invalid preflight result")
            if item["reason"] is not None:
                _safe_string(item["reason"], "preflight reason", 1, 120)
            checks.append({"name_sha256": _opaque_text_identifier(item["name"]),
                           "ok": item["ok"], "reason": item["reason"]})
        if value["partial"] != any(not item["ok"] for item in checks):
            raise DefenseError("inconsistent preflight result")
        if value["exit_code"] != (2 if value["partial"] else 0):
            raise DefenseError("inconsistent preflight exit code")
        return {"checks": checks, "operation": command, "exit_code": value["exit_code"],
                "partial": value["partial"], "platform": dict(value["platform"]),
                "profile_sha256": value["profile"]["sha256"],
                "schema": "durkahelper.operation-result.safe.v1", "tool": dict(value["tool"])}
    if command == "restore-stage":
        allowed = {"approval_id", "apply_required", "backup", "command", "exit_code", "files",
                   "problems", "status", "target", "tool"}
        if (set(value) - allowed or not {"command", "exit_code", "status", "tool"} <= set(value) or
                type(value["exit_code"]) is not int or value["exit_code"] not in {0, 1} or
                not isinstance(value["status"], str) or
                value["status"] not in {"backup_verification_failed", "safe_to_stage", "staged"}):
            raise DefenseError("invalid restore-stage result")
        _validate_tool_record(value["tool"], "restore result tool")
        files = value.get("files", 0)
        if type(files) is not int or not 0 <= files <= 100_000:
            raise DefenseError("invalid restore result file count")
        problems = value.get("problems", [])
        if not isinstance(problems, list) or len(problems) > 100_000:
            raise DefenseError("invalid restore problems")
        reasons = Counter()
        for item in problems:
            if not isinstance(item, dict) or not isinstance(item.get("reason"), str):
                raise DefenseError("invalid restore problem")
            _safe_string(item["reason"], "restore problem reason", 1, 120)
            reasons[item["reason"]] += 1
        expected_exit = 1 if value["status"] == "backup_verification_failed" else 0
        if value["exit_code"] != expected_exit:
            raise DefenseError("inconsistent restore result")
        return {"exit_code": value["exit_code"], "files": files, "operation": command,
                "problem_summary": [{"count": count, "reason": reason}
                                    for reason, count in sorted(reasons.items())],
                "schema": "durkahelper.operation-result.safe.v1", "status": value["status"],
                "tool": dict(value["tool"])}
    raise DefenseError("unrecognized operation result")


def _normalize_evidence_file(path, max_bytes):
    path = Path(path)
    lowered_name = path.name.lower()
    if (path.suffix.lower() not in SAFE_EVIDENCE_EXTENSIONS or
            any(marker in lowered_name for marker in (".pcap", ".pcapng", ".log", "neo-info",
                                                       "neo_info", "compose-config", "compose_config"))):
        raise DefenseError("raw traffic, logs, Neo info, and Compose expansion are not evidence inputs")
    raw = _read_regular_bytes(path, max_bytes)
    if path.suffix.lower() == ".jsonl":
        events = _parse_events_bytes(raw, ".jsonl")
        normalized = b"".join(_canonical(event) for event in events)
        return normalized, EVENT_SCHEMA, len(events)
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DefenseError("invalid structured evidence") from exc
    if not isinstance(value, dict):
        raise DefenseError("evidence JSON must be an object")
    schema = value.get("schema")
    if schema == SNAPSHOT_SCHEMA:
        normalized_value = _safe_snapshot_evidence(value)
    elif schema == COMPARISON_SCHEMA:
        normalized_value = _safe_comparison_evidence(value)
    elif schema == BACKUP_SCHEMA:
        if (path.parent / ".INCOMPLETE").exists():
            raise DefenseError("backup publication is incomplete")
        normalized_value = _safe_backup_evidence(value)
    elif schema == EVENT_SCHEMA:
        normalized_value = _validate_event(value)
    elif schema == VALIDATION_SCHEMA:
        normalized_value = _validate_validation_record(value)
    elif schema == DEPLOYMENT_AUDIT_SCHEMA:
        normalized_value = _validate_deployment_audit_report(value)
    elif value.get("tool") == "DurkaHelper defense_scan":
        normalized_value = _sanitize_scanner_report(value)
        schema = "durkahelper.scanner-report.safe.v1"
    elif (isinstance(value.get("command"), str) and
          value.get("command") in {"health", "preflight", "restore-stage"}):
        normalized_value = _sanitize_operation_result(value)
        schema = "durkahelper.operation-result.safe.v1"
    else:
        raise DefenseError("unrecognized evidence schema")
    _reject_evidence_secrets(normalized_value)
    return _canonical(normalized_value), schema, 1


def command_evidence(args):
    profile_data = load_profile(args.profile)
    settings = profile_data.get("evidence", {})
    allowed = settings.get("allow_extensions", list(SAFE_EVIDENCE_EXTENSIONS))
    max_files = settings.get("max_files", 128)
    max_file_bytes = settings.get("max_file_bytes", 16 * 1024 * 1024)
    max_total_bytes = settings.get("max_total_bytes", 256 * 1024 * 1024)
    if not 1 <= len(args.input) <= max_files:
        raise DefenseError("invalid evidence input count")
    target = _safe_output_parent(Path(args.output))
    normalized = []
    total = 0
    for path_text in args.input:
        path = Path(path_text)
        if path.suffix.lower() not in allowed:
            raise DefenseError("evidence extension is not allowed by the profile")
        payload, schema, records = _normalize_evidence_file(path, max_file_bytes)
        total += len(payload)
        if total > max_total_bytes:
            raise DefenseError("evidence total byte limit reached")
        normalized.append((payload, schema, records, path.suffix.lower()))
    normalized.sort(key=lambda item: (item[1], item[3], _sha256_bytes(item[0]), item[0]))
    staging = _StagingDirectory.create(target, ".defense-evidence-")
    try:
        manifest_entries = []
        for number, (payload, schema, records, suffix) in enumerate(normalized, 1):
            name = f"artifact-{number:03d}{suffix}"
            staging.write_new_bytes(name, payload)
            manifest_entries.append({"artifact": name, "records": records, "schema": schema,
                                     "sha256": _sha256_bytes(payload), "size": len(payload)})
        manifest = {"created_at": _now(), "format": 1, "kind": "sanitized-evidence-bundle",
                    "artifacts": manifest_entries,
                    "profile": {"name_sha256": _opaque_text_identifier(profile_data["name"]),
                                "sha256": _profile_hash(profile_data)},
                    "tool": _tool_record()}
        manifest_payload = _bounded_canonical(manifest, MAX_JSON_BYTES, "evidence manifest")
        staging.write_new_bytes("manifest.json", manifest_payload)
        _publish_directory(staging, target)
    finally:
        staging.cleanup()
    print(json.dumps({"artifacts": len(normalized), "evidence": str(target), "exit_code": 0,
                      "total_bytes": total}, sort_keys=True))
    return 0


def _deployment_list(value, field, maximum=128):
    if not isinstance(value, list) or len(value) > maximum:
        raise DefenseError("invalid deployment " + field)
    return value


def _deployment_enum(value, choices, field):
    if not isinstance(value, str) or value not in choices:
        raise DefenseError("invalid deployment " + field)


def _deployment_id(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise DefenseError("invalid deployment identifier")


def _deployment_ip(value):
    if not isinstance(value, str) or "%" in value:
        raise DefenseError("deployment bindings require literal IP addresses")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DefenseError("deployment bindings require literal IP addresses") from exc
    spellings = {str(parsed)}
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        # Python 3.14 changed IPv4-mapped IPv6 rendering to dotted decimal.
        # Accept both stable compressed spellings, not arbitrary textual aliases.
        mapped = int(parsed.ipv4_mapped)
        spellings.update({"::ffff:" + str(parsed.ipv4_mapped),
                          "::ffff:" + format(mapped >> 16, "x") + ":" + format(mapped & 65535, "x")})
    if value not in spellings or parsed.is_multicast:
        raise DefenseError("invalid deployment bind address")
    return parsed


def _deployment_port(value, *, publication=False):
    fields = {"host_port", "container_port", "protocol", "service" if publication else "host_ip"}
    _strict_keys(value, fields, fields, "deployment publication")
    for field in ("host_port", "container_port"):
        _positive_int(value[field], "deployment port", 65535)
    _deployment_enum(value["protocol"], {"tcp", "udp"}, "protocol")
    if publication:
        _deployment_id(value["service"])
    else:
        _deployment_ip(value["host_ip"])


def _deployment_image(value):
    # References, not URLs or command lines. Never echo an untrusted value.
    if (not isinstance(value, str) or len(value) > 256 or "://" in value or
            not re.fullmatch(r"[a-z0-9][a-z0-9._/:@-]*", value)):
        raise DefenseError("invalid deployment image reference")


def _validate_deployment_inputs(model, policy):
    model_fields = {"schema", "source_sha256", "platform", "services"}
    _strict_keys(model, model_fields, model_fields, "deployment model")
    if (model["schema"] != DEPLOYMENT_MODEL_SCHEMA or
            not isinstance(model["source_sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", model["source_sha256"])):
        raise DefenseError("invalid deployment model schema or provenance")
    _strict_keys(model["platform"], {"os", "architecture", "runtime"},
                 {"os", "architecture", "runtime"}, "deployment platform")
    _deployment_enum(model["platform"]["os"], {"linux", "darwin"}, "OS")
    _deployment_enum(model["platform"]["architecture"], {"amd64", "arm64"}, "architecture")
    _deployment_enum(model["platform"]["runtime"], {"docker-engine", "docker-desktop"}, "runtime")
    services = _deployment_list(model["services"], "services", 64)
    if not services:
        raise DefenseError("deployment model must describe services")
    service_fields = {"id", "role", "image", "architectures", "mode", "ports", "mounts",
                      "privileged", "network_mode", "capabilities", "nonroot", "healthcheck",
                      "memory_limit_mb", "cpu_limit", "restart"}
    identifiers = set()
    for service in services:
        _strict_keys(service, service_fields, service_fields, "deployment service")
        _deployment_id(service["id"])
        if service["id"] in identifiers:
            raise DefenseError("duplicate deployment service")
        identifiers.add(service["id"])
        _deployment_enum(service["role"], {"ui", "api", "backend", "worker", "capture"}, "role")
        _deployment_image(service["image"])
        arches = _deployment_list(service["architectures"], "architectures", 2)
        for architecture in arches:
            _deployment_enum(architecture, {"amd64", "arm64"}, "image architecture")
        if len(set(arches)) != len(arches):
            raise DefenseError("duplicate deployment architecture")
        _deployment_enum(service["mode"], {"none", "file", "live"}, "mode")
        _deployment_enum(service["network_mode"], {"bridge", "host", "none"}, "network mode")
        _deployment_enum(service["restart"], {"no", "always", "on-failure", "unless-stopped"}, "restart")
        for field in ("privileged", "healthcheck"):
            if type(service[field]) is not bool:
                raise DefenseError("invalid deployment boolean")
        if service["nonroot"] is not None and type(service["nonroot"]) is not bool:
            raise DefenseError("invalid deployment nonroot evidence")
        if service["memory_limit_mb"] is not None:
            _positive_int(service["memory_limit_mb"], "deployment memory", 1048576)
        cpu = service["cpu_limit"]
        if cpu is not None and (type(cpu) not in {int, float} or not math.isfinite(cpu) or not 0 < cpu <= 1024):
            raise DefenseError("invalid deployment CPU limit")
        for port in _deployment_list(service["ports"], "ports"):
            _deployment_port(port)
        capabilities = _deployment_list(service["capabilities"], "capabilities", 64)
        for capability in capabilities:
            if not isinstance(capability, str) or not re.fullmatch(r"(?:CAP_)?[A-Z][A-Z0-9_]{0,63}", capability):
                raise DefenseError("invalid deployment capability")
        for mount in _deployment_list(service["mounts"], "mounts", 64):
            fields = {"kind", "target", "source_scope", "read_only"}
            _strict_keys(mount, fields, fields, "deployment mount")
            _deployment_enum(mount["kind"], {"bind", "volume", "tmpfs"}, "mount kind")
            _deployment_enum(mount["source_scope"], {"approved-data", "approved-config", "outside", "socket", "host-root", "unknown"}, "mount scope")
            target = mount["target"]
            if (not isinstance(target, str) or not target.startswith("/") or len(target) > 1024 or
                    "\\" in target or any(ord(c) < 32 for c in target) or
                    str(PurePosixPath(target)) != target or ".." in PurePosixPath(target).parts):
                raise DefenseError("invalid deployment mount target")
            if type(mount["read_only"]) is not bool:
                raise DefenseError("invalid deployment mount access")
    policy_fields = {"schema", "team_lan", "approved_bind_addresses", "approved_publications",
                     "approved_images", "require_healthcheck", "require_resource_limits",
                     "require_nonroot", "require_restart", "allow_amd64_emulation", "approved_live_capture"}
    _strict_keys(policy, policy_fields, policy_fields, "deployment policy")
    if policy["schema"] != DEPLOYMENT_POLICY_SCHEMA:
        raise DefenseError("invalid deployment policy schema")
    for field in ("team_lan", "require_healthcheck", "require_resource_limits", "require_nonroot",
                  "require_restart", "allow_amd64_emulation"):
        if type(policy[field]) is not bool:
            raise DefenseError("invalid deployment policy boolean")
    for address in _deployment_list(policy["approved_bind_addresses"], "approved addresses"):
        _deployment_ip(address)
    for port in _deployment_list(policy["approved_publications"], "approved publications"):
        _deployment_port(port, publication=True)
        if port["service"] not in identifiers:
            raise DefenseError("policy refers to an unknown service")
    for reference in _deployment_list(policy["approved_images"], "approved images"):
        _deployment_image(reference)
        if not re.search(r"(?:@|^)sha256:[0-9a-f]{64}$", reference):
            raise DefenseError("approved images must use immutable digests")
    for identifier in _deployment_list(policy["approved_live_capture"], "approved capture"):
        _deployment_id(identifier)
        if identifier not in identifiers:
            raise DefenseError("capture approval refers to an unknown service")
    return model, policy


def deployment_audit(model, policy, *, checked_at=None):
    """Audit declared metadata only. This does not inspect a running daemon."""
    _validate_deployment_inputs(model, policy)
    findings, issues = [], []
    arch = model["platform"]["architecture"]
    approved_ports = {(p["service"], p["host_port"], p["container_port"], p["protocol"])
                      for p in policy["approved_publications"]}
    observed_ports = set()
    bind_groups = {}

    def add(destination, identifier, check, kind="deployment"):
        destination.append({"service_sha256": _sha256_bytes(identifier.encode("utf-8")),
                            "check": check, "kind": kind})

    for service in model["services"]:
        sid = service["id"]
        emit = lambda check, kind="deployment": add(findings, sid, check, kind)
        unknown = lambda check: add(issues, sid, check, "coverage")
        if not re.search(r"(?:@|^)sha256:[0-9a-f]{64}$", service["image"]):
            emit("image_unpinned")
        elif service["image"] not in policy["approved_images"]:
            emit("image_lock_mismatch")
        if not service["architectures"]:
            unknown("image_architecture_unknown")
        elif arch not in service["architectures"]:
            if not (arch == "arm64" and "amd64" in service["architectures"] and policy["allow_amd64_emulation"]):
                emit("image_architecture_incompatible")
            else:
                # Permission to emulate is not evidence that it works.
                unknown("emulation_runtime_unverified")
        for port in service["ports"]:
            key = (sid, port["host_port"], port["container_port"], port["protocol"])
            observed_ports.add(key)
            if service["role"] in {"backend", "worker"}:
                emit("internal_service_published", "security")
            if key not in approved_ports:
                emit("publication_unapproved", "security")
            address = _deployment_ip(port["host_ip"])
            # Normalize IPv4-mapped IPv6 aliases for conservative collision
            # detection. Only declarations are checked; no local socket probe.
            address = getattr(address, "ipv4_mapped", None) or address
            bindings = bind_groups.setdefault((port["host_port"], port["protocol"]), {})
            bindings.setdefault(address, set()).add((sid, port["container_port"]))
            if port["host_ip"] not in policy["approved_bind_addresses"] or address.is_unspecified:
                emit("bind_unapproved_or_wildcard", "security")
            if policy["team_lan"] and address.is_loopback:
                emit("team_ui_loopback_only", "availability")
        if service["ports"] and service["network_mode"] in {"none", "host"}:
            # Host mode ignores/rejects port mapping; none has no container
            # network endpoint to forward to. Neither fulfills this model.
            emit("publication_network_mode_incompatible", "availability")
        if service["privileged"]:
            emit("privileged_container", "security")
        live_allowed = (service["mode"] == "live" and sid in policy["approved_live_capture"] and
                        model["platform"]["os"] == "linux" and model["platform"]["runtime"] == "docker-engine")
        if service["mode"] == "live" and not live_allowed:
            emit("live_capture_not_approved", "security")
        if live_allowed:
            unknown("live_capture_visibility_requires_runtime_test")
        if service["network_mode"] == "host":
            if live_allowed:
                unknown("host_namespace_requires_runtime_boundary_test")
            else:
                emit("host_network_unapproved", "security")
        for capability in service["capabilities"]:
            normalized = capability.removeprefix("CAP_")
            if not (live_allowed and normalized == "NET_RAW"):
                emit("capability_not_minimal", "security")
        for mount in service["mounts"]:
            scope = mount["source_scope"]
            if scope in {"socket", "host-root"} or mount["target"] in {"/", "/var/run/docker.sock", "/run/docker.sock"}:
                emit("sensitive_host_mount", "security")
            elif scope == "unknown":
                unknown("mount_scope_unknown")
            elif scope == "outside" or (scope == "approved-config" and not mount["read_only"]):
                emit("mount_outside_policy", "security")
        if policy["require_nonroot"] and service["nonroot"] is not True:
            if service["nonroot"] is None:
                unknown("service_user_unknown")
            else:
                emit("service_runs_as_root", "security")
        if policy["require_healthcheck"] and not service["healthcheck"]:
            emit("healthcheck_missing", "availability")
        if policy["require_resource_limits"] and (service["memory_limit_mb"] is None or service["cpu_limit"] is None):
            emit("resource_limits_missing", "availability")
        if policy["require_restart"] and service["restart"] == "no":
            emit("restart_policy_missing", "availability")
    for addresses in bind_groups.values():
        if any(address.is_unspecified for address in addresses):
            # Wildcard listeners may overlap either IP family on dual-stack
            # systems. Fail closed instead of assuming IPV6_V6ONLY behavior.
            owners = {owner for bindings in addresses.values() for owner in bindings}
            overlapping = sum(len(bindings) for bindings in addresses.values()) > 1
            collisions = {sid for sid, _target in owners} if overlapping else set()
        else:
            collisions = {sid for bindings in addresses.values() if len(bindings) > 1
                          for sid, _target in bindings}
        for sid in collisions:
            add(findings, sid, "publication_bind_conflict", "availability")
    for sid, _host, _container, _protocol in approved_ports - observed_ports:
        add(findings, sid, "required_publication_missing", "availability")
    unique = lambda rows: [dict(zip(("service_sha256", "check", "kind"), row))
                           for row in sorted({(r["service_sha256"], r["check"], r["kind"]) for r in rows})]
    checked_at = checked_at or _now()
    _parse_timestamp(checked_at)
    findings, issues = unique(findings), unique(issues)
    return {"schema": DEPLOYMENT_AUDIT_SCHEMA, "checked_at": checked_at,
            "scope": "declared-model-only", "model_sha256": _sha256_bytes(_canonical(model)),
            "policy_sha256": _sha256_bytes(_canonical(policy)), "source_sha256": model["source_sha256"],
            "services": len(model["services"]), "findings": findings, "issues": issues,
            "status": "partial" if issues else "fail" if findings else "pass",
            "exit_code": 2 if issues else 1 if findings else 0}


def command_audit_deployment(args):
    model, _ = _read_json(args.model, MAX_PROFILE_BYTES)
    policy, _ = _read_json(args.policy, MAX_PROFILE_BYTES)
    result = deployment_audit(model, policy)
    print(_canonical(result).decode("utf-8"), end="")
    return result["exit_code"]


def _validate_deployment_audit_report(value):
    fields = {"schema", "checked_at", "scope", "model_sha256", "policy_sha256", "source_sha256",
              "services", "findings", "issues", "status", "exit_code"}
    _strict_keys(value, fields, fields, "deployment audit")
    if value["schema"] != DEPLOYMENT_AUDIT_SCHEMA or value["scope"] != "declared-model-only":
        raise DefenseError("invalid deployment audit scope")
    _parse_timestamp(value["checked_at"])
    for field in ("model_sha256", "policy_sha256", "source_sha256"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise DefenseError("invalid deployment audit digest")
    _positive_int(value["services"], "deployment service count", 64)
    checks = {"image_unpinned", "image_lock_mismatch", "image_architecture_unknown",
              "image_architecture_incompatible", "emulation_runtime_unverified", "internal_service_published",
              "publication_unapproved", "bind_unapproved_or_wildcard", "team_ui_loopback_only",
              "privileged_container", "live_capture_not_approved", "live_capture_visibility_requires_runtime_test",
              "host_namespace_requires_runtime_boundary_test", "host_network_unapproved", "capability_not_minimal",
              "sensitive_host_mount", "mount_scope_unknown", "mount_outside_policy", "service_user_unknown",
              "service_runs_as_root", "healthcheck_missing", "resource_limits_missing", "restart_policy_missing",
              "required_publication_missing", "publication_bind_conflict", "publication_network_mode_incompatible"}
    for field in ("findings", "issues"):
        for row in _deployment_list(value[field], "audit entries", 4096):
            _strict_keys(row, {"service_sha256", "check", "kind"}, {"service_sha256", "check", "kind"}, "audit entry")
            if not isinstance(row["service_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["service_sha256"]):
                raise DefenseError("invalid audit service digest")
            _deployment_enum(row["check"], checks, "audit check")
            _deployment_enum(row["kind"], {"coverage"} if field == "issues" else {"deployment", "security", "availability"}, "audit kind")
    expected = ("partial", 2) if value["issues"] else ("fail", 1) if value["findings"] else ("pass", 0)
    if type(value["exit_code"]) is not int or (value["status"], value["exit_code"]) != expected:
        raise DefenseError("inconsistent deployment audit status")
    return value


def _scanner_index(path):
    data, raw = _read_json(path)
    safe = _sanitize_scanner_report(data)
    indexed = {(item["path"], item["line"], item["rule"]) for item in safe["findings"]}
    return safe, indexed, _sha256_bytes(raw)


def command_patch_check(args):
    before, before_raw = _read_json(args.before)
    after, after_raw = _read_json(args.after)
    before_sha256 = _sha256_bytes(before_raw)
    after_sha256 = _sha256_bytes(after_raw)
    comparison = _snapshot_comparison(before, after, before_sha256, after_sha256)
    before_created = _parse_timestamp(comparison["baseline"]["created_at"])
    after_created = _parse_timestamp(comparison["current"]["created_at"])
    partial_reasons = list(comparison["reasons"])
    fail_reasons = []
    scanner_new = 0
    before_scanner_sha256 = None
    after_scanner_sha256 = None
    after_scanner_created = None
    if bool(args.before_scanner) != bool(args.after_scanner):
        raise DefenseError("both scanner reports are required together")
    if not args.before_scanner:
        partial_reasons.append("scanner_evidence_missing")
    else:
        old_report, old, before_scanner_sha256 = _scanner_index(args.before_scanner)
        new_report, new, after_scanner_sha256 = _scanner_index(args.after_scanner)
        if old_report["partial"] or old_report["exit_code"] == 2:
            partial_reasons.append("before_scanner_partial")
        if new_report["partial"] or new_report["exit_code"] == 2:
            partial_reasons.append("after_scanner_partial")
        if old_report.get("version") != new_report.get("version"):
            partial_reasons.append("scanner_version_changed")
        if old_report.get("scope") is None or new_report.get("scope") is None:
            partial_reasons.append("scanner_scope_unverified")
        elif old_report.get("scope") != new_report.get("scope"):
            partial_reasons.append("scanner_scope_changed")
        elif (old_report["scope"]["root"] != before["root"] or
              new_report["scope"]["root"] != after["root"]):
            partial_reasons.append("scanner_root_unbound")
        if old_report.get("created_at") is None or new_report.get("created_at") is None:
            partial_reasons.append("scanner_time_unverified")
        else:
            old_scanner_created = _parse_timestamp(old_report["created_at"])
            after_scanner_created = _parse_timestamp(new_report["created_at"])
            if old_scanner_created < before_created or old_scanner_created > after_created:
                partial_reasons.append("before_scanner_time_unbound")
            if after_scanner_created < after_created:
                partial_reasons.append("after_scanner_time_unbound")
        scanner_new = len(new - old)
        if scanner_new:
            fail_reasons.append("new_scanner_findings")
    health_failures = 0
    health_sha256 = None
    health_checked = None
    if not args.health_result:
        partial_reasons.append("health_evidence_missing")
    else:
        health_data, health_raw = _read_json(args.health_result, MAX_PROFILE_BYTES)
        health_sha256 = _sha256_bytes(health_raw)
        health = _sanitize_operation_result(health_data)
        if health.get("operation") != "health":
            raise DefenseError("patch health evidence must be a health result")
        health_checked = _parse_timestamp(health["checked_at"])
        if health["profile_sha256"] != after["profile"]["sha256"]:
            partial_reasons.append("health_profile_unbound")
        if health_checked < after_created:
            partial_reasons.append("health_time_unbound")
        health_failures = health["summary"]["failed"]
        if health_failures:
            fail_reasons.append("health_failure")
    validation_failures = 0
    validation_partial = 0
    validation_passes = 0
    validation_not_run = 0
    validation_skipped = 0
    validation_run_ids = set()
    validation_hashes = []
    deployment_bindings = {}
    audit_checked = None
    deployment_paths = [getattr(args, name, None) for name in
                        ("deployment_audit", "deployment_model", "deployment_policy")]
    if any(deployment_paths):
        if not all(deployment_paths):
            raise DefenseError("deployment audit requires its model and policy")
        audit, audit_raw = _read_json(deployment_paths[0], MAX_PROFILE_BYTES)
        model, _ = _read_json(deployment_paths[1], MAX_PROFILE_BYTES)
        policy, _ = _read_json(deployment_paths[2], MAX_PROFILE_BYTES)
        _validate_deployment_audit_report(audit)
        expected = deployment_audit(model, policy, checked_at=audit["checked_at"])
        if audit != expected:
            raise DefenseError("deployment audit does not match its model and policy")
        deployment_bindings = {"deployment_audit_sha256": _sha256_bytes(audit_raw),
                               "deployment_model_sha256": audit["model_sha256"],
                               "deployment_policy_sha256": audit["policy_sha256"]}
        audit_checked = _parse_timestamp(audit["checked_at"])
        if audit_checked < after_created:
            partial_reasons.append("deployment_audit_time_unbound")
        observed_config_hashes = {item["sha256"] for item in after["files"]}
        compose = after["adapters"].get("compose")
        if isinstance(compose, dict):
            observed_config_hashes.update(item["sha256"] for item in compose.get("config_files", []))
        if audit["source_sha256"] not in observed_config_hashes:
            partial_reasons.append("deployment_source_unbound")
        if audit["issues"]:
            partial_reasons.append("deployment_audit_incomplete")
        if audit["findings"]:
            fail_reasons.append("deployment_policy_failure")
    elif getattr(args, "require_deployment_audit", False):
        partial_reasons.append("deployment_audit_missing")
    for path in args.validation_record or []:
        record, validation_raw = _read_json(path, MAX_PROFILE_BYTES)
        validation_hashes.append(_sha256_bytes(validation_raw))
        _validate_validation_record(record)
        attributes = record.get("attributes", {})
        required_bindings = {
            "before_snapshot_sha256": before_sha256,
            "after_snapshot_sha256": after_sha256,
            "health_sha256": health_sha256,
            "before_scanner_sha256": before_scanner_sha256,
            "after_scanner_sha256": after_scanner_sha256,
            **deployment_bindings,
        }
        if (any(expected is None or attributes.get(name) != expected
                for name, expected in required_bindings.items()) or
                not isinstance(attributes.get("run_id"), str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", attributes["run_id"])):
            partial_reasons.append("validation_evidence_unbound")
        else:
            validation_run_ids.add(attributes["run_id"])
        record_time = _parse_timestamp(record["timestamp"])
        latest_dependency = max(timestamp for timestamp in
                                (after_created, health_checked, after_scanner_created, audit_checked)
                                if timestamp is not None)
        if record_time < latest_dependency:
            partial_reasons.append("validation_time_unbound")
        if record["status"] == "fail":
            validation_failures += 1
        elif record["status"] in {"partial", "blocked"}:
            validation_partial += 1
        elif record["status"] == "not_run":
            validation_not_run += 1
        elif record["status"] == "skipped_not_applicable":
            validation_skipped += 1
        else:
            validation_passes += 1
    if not args.validation_record:
        partial_reasons.append("validation_evidence_missing")
    elif not validation_passes and not validation_failures and not validation_partial:
        partial_reasons.append("validation_evidence_not_executed")
    if len(validation_run_ids) > 1:
        partial_reasons.append("validation_run_mismatch")
    if validation_failures:
        fail_reasons.append("validation_failure")
    if validation_partial or validation_not_run:
        partial_reasons.append("validation_incomplete")
    approved_drift = False
    approved_drift_id = None
    approved_drift_sha256 = None
    if args.approved_drift:
        approval, approval_raw = _read_json(args.approved_drift, MAX_JSON_BYTES)
        _validate_approved_drift(approval, comparison, before_sha256, after_sha256)
        approved_drift = True
        approved_drift_id = approval["id"]
        approved_drift_sha256 = _sha256_bytes(approval_raw)
    if comparison["summary"]["drift_count"] and not approved_drift:
        fail_reasons.append("snapshot_drift")
    if partial_reasons:
        status, exit_code = "partial", 2
    elif fail_reasons:
        status, exit_code = "fail", 1
    else:
        status, exit_code = "pass", 0
    validation_evidence_sha256 = _sha256_bytes(_canonical(sorted(validation_hashes)))
    run_id = next(iter(validation_run_ids)) if len(validation_run_ids) == 1 else None
    provenance = {
        "after_scanner_sha256": after_scanner_sha256,
        "after_snapshot_sha256": after_sha256,
        "approved_drift_sha256": approved_drift_sha256,
        "before_scanner_sha256": before_scanner_sha256,
        "before_snapshot_sha256": before_sha256,
        "health_sha256": health_sha256,
        "run_id": run_id,
        "validation_evidence_sha256": validation_evidence_sha256,
        **deployment_bindings,
    }
    identity = _sha256_bytes(_canonical(provenance))[:16]
    record = {
        "attributes": {
            "scanner_new_findings": scanner_new,
            "snapshot_drift_count": comparison["summary"]["drift_count"],
            "snapshot_drift_approved": approved_drift,
            "before_snapshot_sha256": before_sha256,
            "after_snapshot_sha256": after_sha256,
            "before_scanner_sha256": before_scanner_sha256,
            "after_scanner_sha256": after_scanner_sha256,
            "health_sha256": health_sha256,
            "validation_evidence_sha256": validation_evidence_sha256,
            "run_id": run_id,
            "approved_drift_id": approved_drift_id,
            "approved_drift_sha256": approved_drift_sha256,
            "health_failures": health_failures,
            "validation_failures": validation_failures,
            "validation_not_run": validation_not_run,
            "validation_partial": validation_partial,
            "validation_passes": validation_passes,
            "validation_skipped_not_applicable": validation_skipped,
            **deployment_bindings,
        },
        "check": "patch-check",
        "id": "patch-check-" + identity,
        "schema": VALIDATION_SCHEMA,
        "status": status,
        "summary": ("Patch validation is incomplete: " + ", ".join(sorted(set(partial_reasons)))
                    if partial_reasons else
                    "Patch validation found regressions: " + ", ".join(sorted(set(fail_reasons)))
                    if fail_reasons else
                    "Snapshot, health, scanner, and executed validation evidence passed."),
        "timestamp": _now(),
    }
    _validate_validation_record(record)
    print(_canonical(record).decode("utf-8"), end="")
    return exit_code


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)

    preflight = commands.add_parser("preflight", help="validate a declarative profile and adapter availability")
    preflight.add_argument("--profile", required=True)
    preflight.set_defaults(handler=command_preflight)

    snapshot = commands.add_parser("snapshot", help="create a read-only system and file snapshot")
    snapshot.add_argument("--profile", required=True)
    snapshot.add_argument("--root", required=True)
    snapshot.add_argument("--output", required=True)
    snapshot.set_defaults(handler=command_snapshot)

    compare = commands.add_parser("compare", help="compare two compatible snapshot documents")
    compare.add_argument("baseline", metavar="BASELINE")
    compare.add_argument("current", metavar="CURRENT")
    compare.set_defaults(handler=command_compare)

    health = commands.add_parser("health", help="run explicit safe HTTP health checks")
    health.add_argument("--profile", required=True)
    health.set_defaults(handler=command_health)

    backup = commands.add_parser("backup", help="create or verify a bounded backup")
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    backup_create = backup_commands.add_parser("create")
    backup_create.add_argument("--profile", required=True)
    backup_create.add_argument("--root", required=True)
    backup_create.add_argument("--output", required=True)
    backup_create.set_defaults(handler=command_backup_create)
    backup_verify = backup_commands.add_parser("verify")
    backup_verify.add_argument("backup", metavar="BACKUP")
    backup_verify.set_defaults(handler=command_backup_verify)

    restore = commands.add_parser("restore-stage", help="verify and optionally extract into a new staging path")
    restore.add_argument("backup", metavar="BACKUP")
    restore.add_argument("--target", required=True)
    restore.add_argument("--apply", action="store_true")
    restore.add_argument("--approval-id")
    restore.set_defaults(handler=command_restore_stage)

    patch_check = commands.add_parser("patch-check", help="compare before/after evidence and validation records")
    patch_check.add_argument("--before", required=True)
    patch_check.add_argument("--after", required=True)
    patch_check.add_argument("--before-scanner", "--scanner-before", dest="before_scanner")
    patch_check.add_argument("--after-scanner", "--scanner-after", dest="after_scanner")
    patch_check.add_argument("--health-result", required=False)
    patch_check.add_argument("--validation-record", action="append", default=[])
    patch_check.add_argument("--approved-drift")
    patch_check.add_argument("--deployment-audit")
    patch_check.add_argument("--deployment-model")
    patch_check.add_argument("--deployment-policy")
    patch_check.add_argument("--require-deployment-audit", action="store_true")
    patch_check.set_defaults(handler=command_patch_check)

    audit = commands.add_parser("audit-deployment", help="audit declared metadata, not a running daemon")
    audit.add_argument("--model", required=True)
    audit.add_argument("--policy", required=True)
    audit.set_defaults(handler=command_audit_deployment)

    timeline = commands.add_parser("timeline", help="normalize and sort event.v1 files")
    timeline.add_argument("--events", nargs="+", required=True)
    timeline.add_argument("--output", required=True)
    timeline.set_defaults(handler=command_timeline)

    evidence = commands.add_parser("evidence", help="build a sanitized structured evidence directory")
    evidence.add_argument("--profile", required=True)
    evidence.add_argument("--output", required=True)
    evidence.add_argument("--input", nargs="+", required=True)
    evidence.set_defaults(handler=command_evidence)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except DefenseError as exc:
        error = {"error": "blocked_or_invalid", "reason": str(exc), "exit_code": 2,
                 "tool": _tool_record()}
        print(_canonical(error).decode("utf-8"), end="", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, MemoryError) as exc:
        error = {"error": "operation_failed", "reason": type(exc).__name__, "exit_code": 2,
                 "tool": _tool_record()}
        print(_canonical(error).decode("utf-8"), end="", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        error = {"error": "interrupted", "exit_code": 2, "tool": _tool_record()}
        print(_canonical(error).decode("utf-8"), end="", file=sys.stderr)
        return 2
    except Exception as exc:
        error = {"error": "unexpected_failure", "reason": type(exc).__name__, "exit_code": 2,
                 "tool": _tool_record()}
        print(_canonical(error).decode("utf-8"), end="", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
