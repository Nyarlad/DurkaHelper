"""Small shared helpers; Python 3.10+, standard library only."""
import argparse
import math
import re
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener():
    # Direct connections and no redirects: do not forward farm credentials.
    return build_opener(ProxyHandler({}), NoRedirect())


def http_url(value):
    p = urlsplit(value)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise ValueError("expected an absolute http(s) URL")
    if p.username is not None or p.password is not None or p.fragment:
        raise ValueError("userinfo and fragments are not allowed in URLs")
    _ = p.port  # Validate malformed/out-of-range ports.
    return value


def positive_float(value):
    n = float(value)
    if not math.isfinite(n) or n <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return n


def flag_pattern(value):
    pattern = re.compile(value)
    if pattern.search("") is not None:
        raise ValueError("flag regex must not match the empty string")
    return pattern


def limited_read(response, limit=1024 * 1024):
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"response exceeds {limit} bytes")
    return data
