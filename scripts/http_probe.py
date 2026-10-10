#!/usr/bin/env python3
"""One-pass HTTP status/content checks against an explicit JSON service list."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request

from common import http_url, limited_read, opener, positive_float


def validate(config):
    if not isinstance(config, list) or not 1 <= len(config) <= 128:
        raise ValueError("config must be a list of 1..128 checks")
    for item in config:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("each check needs a string name")
        if not item["name"].strip() or len(item["name"]) > 120:
            raise ValueError("name must contain 1..120 characters")
        if set(item) - {"name", "url", "status", "contains"}:
            raise ValueError("unknown check field")
        if not isinstance(item.get("url"), str) or any(c.isspace() for c in item["url"]):
            raise ValueError("url must be a string without whitespace")
        http_url(item["url"])
        expected = item.get("status", 200)
        if type(expected) is not int or not 100 <= expected <= 599:
            raise ValueError("status must be an integer HTTP status")
        if "contains" in item and not isinstance(item["contains"], str):
            raise ValueError("contains must be a string")
    return config


def probe(item, timeout):
    started = time.monotonic()
    result = {"name": item["name"], "ok": False, "status": None}
    try:
        req = Request(item["url"], headers={"User-Agent": "DurkaHelper/0.1"})
        try:
            response = opener().open(req, timeout=timeout)
        except HTTPError as exc:
            response = exc  # An expected 403/404 is a legitimate probe outcome.
        with response:
            result["status"] = response.code
            body = limited_read(response).decode("utf-8", errors="replace")
        result["ok"] = (result["status"] == item.get("status", 200)
                        and item.get("contains", "") in body)
    except (OSError, ValueError) as exc:
        result["error"] = type(exc).__name__
    result["ms"] = round((time.monotonic() - started) * 1000)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", help="JSON list with name, url, status and optional contains")
    parser.add_argument("--timeout", type=positive_float, default=3.0)
    parser.add_argument("--workers", type=int, choices=range(1, 17), default=4)
    args = parser.parse_args()
    try:
        with open(args.config, encoding="utf-8") as f:
            config = validate(json.load(f))
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(lambda x: probe(x, args.timeout), config))
        for result in results:
            print(json.dumps(result, ensure_ascii=False))
        return 0 if all(r["ok"] for r in results) else 1
    except (KeyError, TypeError, ValueError, OSError) as exc:
        print(f"probe configuration: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
