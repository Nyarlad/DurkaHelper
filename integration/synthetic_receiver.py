#!/usr/bin/env python3
"""Bounded synthetic receiver for S4DFarm's pinned ructf_http adapter only."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_PUT(self):
        if self.path != "/flags" or self.headers.get("X-Team-Token") != "fixture-only":
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 65536:
                raise ValueError()
            flags = json.loads(self.rfile.read(length))
            if not isinstance(flags, list) or len(flags) > 100:
                raise ValueError()
            if not all(isinstance(flag, str) and re.fullmatch(r"[A-Z0-9]{31}=", flag) for flag in flags):
                raise ValueError()
        except (ValueError, UnicodeError):
            self.send_error(400)
            return
        body = json.dumps([{"flag": flag, "msg": "accepted synthetic fixture"} for flag in flags]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def setup(self):
        super().setup()
        self.connection.settimeout(5)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Receiver).serve_forever()
