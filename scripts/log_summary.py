#!/usr/bin/env python3
"""Summarize a local JSONL log without printing messages or arbitrary fields."""
import argparse
from collections import Counter
import json
from pathlib import Path
import stat
import sys

MAX_LINE = 256 * 1024
MAX_FILE = 64 * 1024 * 1024
LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
ALIASES = {"WARN": "WARNING", "FATAL": "CRITICAL"}


def summarize(stream, max_bytes=MAX_FILE):
    result = {"lines": 0, "records": 0, "blank_lines": 0, "invalid_lines": 0,
              "invalid_fields": 0, "http_errors": 0}
    levels, statuses = Counter(), Counter()
    consumed = 0
    while True:
        raw = stream.readline(MAX_LINE + 1)
        if not raw:
            break
        consumed += len(raw)
        too_long = len(raw) > MAX_LINE
        # Drain one oversized record without retaining it in memory.
        while len(raw) == MAX_LINE + 1 and not raw.endswith(b"\n"):
            if consumed > max_bytes:
                raise ValueError("log exceeds byte limit")
            raw = stream.readline(MAX_LINE + 1)
            consumed += len(raw)
        if consumed > max_bytes:
            raise ValueError("log exceeds byte limit")
        result["lines"] += 1
        if too_long:
            result["invalid_lines"] += 1
            continue
        if not raw.strip():
            result["blank_lines"] += 1
            continue
        try:
            record = json.loads(raw)
            if not isinstance(record, dict):
                raise ValueError("expected object")
        except (ValueError, UnicodeError, RecursionError):
            result["invalid_lines"] += 1
            continue
        result["records"] += 1
        if "level" in record:
            level = record["level"]
            if isinstance(level, str):
                level = ALIASES.get(level.upper(), level.upper())
            if not isinstance(level, str) or level not in LEVELS:
                result["invalid_fields"] += 1
            else:
                levels[level] += 1
        if "status" in record:
            status = record["status"]
            if type(status) is not int or not 100 <= status <= 599:
                result["invalid_fields"] += 1
            else:
                statuses[str(status)] += 1
                result["http_errors"] += int(status >= 400)
    result["levels"] = dict(sorted(levels.items()))
    result["statuses"] = dict(sorted(statuses.items()))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="local UTF-8 JSONL file, at most 64 MiB")
    args = parser.parse_args()
    try:
        info = args.log.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise ValueError("expected a regular file within size limit")
        with args.log.open("rb") as stream:
            result = summarize(stream)
        print(json.dumps(result, sort_keys=True))
        return 1 if result["invalid_lines"] or result["invalid_fields"] else 0
    except (OSError, ValueError) as exc:
        print(f"log summary: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
