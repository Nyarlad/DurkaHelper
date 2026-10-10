#!/usr/bin/env python3
"""Back up explicitly approved scalar JSON settings, never whole config files."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile

MAX_FILE = 1024 * 1024
SENSITIVE = re.compile(r"password|passwd|pwd|secret|token|credential|auth|cookie|"
                       r"privatekey|apikey|accesskey|session|dsn|url|uri|connectionstring")


def sensitive_key(key):
    return bool(SENSITIVE.search(re.sub(r"[^a-z0-9]", "", key.lower())))


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError("non-finite JSON number")


def read_json(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("expected regular JSON file")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError("JSON file exceeds 1 MiB")
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)


def source_path(root, relative):
    if not isinstance(relative, str) or "\\" in relative or ":" in relative:
        raise ValueError("expected relative POSIX path")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("empty or traversal path component")
    rel = PurePosixPath(relative)
    if rel.suffix != ".json" or len(parts) > 16:
        raise ValueError("only relative JSON paths are supported")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("source symlinks are not supported")
    return current


def project_settings(source, allowed):
    if not isinstance(allowed, list) or not 1 <= len(allowed) <= 256:
        raise ValueError("allow must contain 1..256 key paths")
    output, seen = {}, set()
    for keys in allowed:
        if (not isinstance(keys, list) or not 1 <= len(keys) <= 16
                or any(not isinstance(k, str) or not k or len(k) > 128 for k in keys)):
            raise ValueError("each key path must be a nonempty list of strings")
        if any(sensitive_key(k) for k in keys):
            raise ValueError("sensitive field name is not allowed")
        key_tuple = tuple(keys)
        if key_tuple in seen:
            raise ValueError("duplicate key path")
        seen.add(key_tuple)
        value = source
        for key in keys:
            if not isinstance(value, dict) or key not in value:
                raise ValueError("selected field is missing")
            value = value[key]
        if isinstance(value, (dict, list)):
            raise ValueError("select scalar leaves, not entire objects or lists")
        # Never implicitly retain an unselected sibling or nested value.
        target = output
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value
    return output


def backup(root, manifest, output):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root must be a directory")
    if not isinstance(manifest, dict) or set(manifest) != {"files"}:
        raise ValueError("manifest needs only the files field")
    files = manifest["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= 64:
        raise ValueError("files must contain 1..64 entries")
    prepared, seen = [], set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "allow"}:
            raise ValueError("file entry needs path and allow")
        source = source_path(root, entry["path"])
        if entry["path"] in seen:
            raise ValueError("duplicate source path")
        seen.add(entry["path"])
        selected = project_settings(read_json(source), entry["allow"])
        payload = (json.dumps(selected, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode()
        prepared.append((entry["path"], payload))

    # Validate and sanitize every source before creating any backup files.
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    session = Path(tempfile.mkdtemp(prefix="config-", dir=output))
    try:
        session.chmod(0o700)
        index = {"format": 1, "kind": "selected-settings", "files": []}
        for number, (source, payload) in enumerate(prepared, 1):
            name = f"settings-{number:03d}.json"
            dest = session / name
            with dest.open("xb") as stream:
                stream.write(payload)
            dest.chmod(0o600)
            index["files"].append({"source": source, "backup": name,
                                   "sha256": hashlib.sha256(payload).hexdigest()})
        index_path = session / "manifest.json"
        index_path.write_text(json.dumps(index, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        index_path.chmod(0o600)
    except BaseException:
        shutil.rmtree(session)
        raise
    return session


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", required=True, type=Path, help="directory containing source configs")
    parser.add_argument("--output", type=Path, default=Path("artifacts/config-backups"))
    args = parser.parse_args()
    try:
        session = backup(args.root, read_json(args.manifest), args.output)
        print(session)
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"config backup: {type(exc).__name__}; no source values printed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
