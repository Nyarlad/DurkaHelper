#!/usr/bin/env python3
"""Offline, read-only source triage. Python 3.10+, standard library only.

Never imports or executes scanned code. Rules are loaded only from the toolkit's
own rules directory, never discovered inside the target. No network/update API.
"""
from __future__ import annotations

import argparse
import ast
from bisect import bisect_right
from collections import Counter
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tokenize
import io
import unicodedata

VERSION = "1.8.0"
SCOPE_SCHEMA = "durkahelper.scanner-scope.v2"
CONTEXT_SCHEMA = "durkahelper.scanner-context.v1"
SEMANTIC_REVISION = "bounded-source-signals.v3"
INFRASTRUCTURE = {"docker-desktop", "compose", "vulnbox", "team-lan", "s4dfarm", "neo", "packmate"}
PATH_SEMANTICS = "root-relative-posix.v1"
RULE_PATH = Path(__file__).resolve().parents[1] / "rules" / "defense.json"
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
             "__pycache__", ".cache", ".ssh", ".aws", "artifacts", "dist", "build", "target", "obj", "bin"}
EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".php": "php", ".go": "go", ".java": "java", ".cs": "csharp",
    ".c": "native", ".h": "native", ".cpp": "native", ".hpp": "native", ".cc": "native",
    ".yaml": "config", ".yml": "config", ".toml": "config", ".json": "config",
    ".conf": "config", ".ini": "config", ".properties": "config", ".xml": "config",
    ".sh": "shell", ".bash": "shell", ".ejs": "template", ".html": "template",
    ".hbs": "template", ".j2": "template", ".twig": "template", ".erb": "template",
    ".rb": "ruby", ".rake": "ruby", ".rs": "rust", ".sql": "sql",
    ".acl": "config", ".cnf": "config", ".config": "config",
    ".cshtml": "csharp", ".razor": "csharp",
    ".service": "config", ".socket": "config",
}


def load_rules():
    data = json.loads(RULE_PATH.read_text(encoding="utf-8"))
    if data["schema_version"] != 1:
        raise ValueError("unsupported rules schema")
    rules = data["rules"]
    if len({r["id"] for r in rules}) != len(rules):
        raise ValueError("duplicate rule IDs")
    for rule in rules:
        for field in ("id", "title", "engine", "languages", "reason", "fix", "before", "after", "check", "doc", "family", "limitations"):
            if not rule.get(field):
                raise ValueError("incomplete rule: " + rule.get("id", "?"))
        if (rule.get("review_priority") not in {"normal", "high"}
                or rule.get("signal_kind") not in {"syntactic-review", "configuration-review"}
                or not isinstance(rule.get("cwe"), list)
                or any(not isinstance(item, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", item) for item in rule["cwe"])
                or type(rule.get("code_only", False)) is not bool):
            raise ValueError("invalid rule metadata")
        if rule["engine"] == "regex":
            rule["compiled"] = re.compile(rule["pattern"], re.MULTILINE | re.IGNORECASE)
            rule["compiled_languages"] = {}
            variants = rule.get("language_patterns", {})
            if not isinstance(variants, dict):
                raise ValueError("language patterns must be a mapping")
            for lang, pattern in variants.items():
                if lang not in rule["languages"] or not isinstance(pattern, str):
                    raise ValueError("invalid language pattern")
                rule["compiled_languages"][lang] = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
        elif rule["engine"] not in {"python-ast", "javascript-tokens"}:
            raise ValueError("unknown engine")
    return rules


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def validate_context(value=None):
    """Allow only non-secret context enums; context never filters detectors."""
    if value is None:
        value = {"schema": CONTEXT_SCHEMA, "infrastructure": [], "role": "both"}
    if not isinstance(value, dict) or set(value) != {"schema", "infrastructure", "role"}:
        raise ValueError("invalid scanner context")
    items = value["infrastructure"]
    if (value["schema"] != CONTEXT_SCHEMA or value["role"] not in ("defender", "administrator", "both")
            or not isinstance(items, list) or len(items) > len(INFRASTRUCTURE)
            or any(not isinstance(item, str) or item not in INFRASTRUCTURE for item in items)
            or len(items) != len(set(items))):
        raise ValueError("invalid scanner context")
    return {"schema": CONTEXT_SCHEMA, "infrastructure": sorted(items), "role": value["role"]}


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_context(filename):
    return validate_context(json.loads(read_regular(canonical_scan_root(filename), 16384),
                                       object_pairs_hook=_unique_json_object))


def review_metadata(rule, context):
    """Return authored explanations only, never strings taken from the target."""
    notes = []
    active = set(context["infrastructure"])
    family = rule["family"]
    if active & {"compose", "docker-desktop"} and family == "container-isolation":
        notes.append("Review this setting in the resolved deployment model; source text is not runtime evidence.")
    if active & {"team-lan", "s4dfarm", "neo", "packmate"} and family in {"authentication", "secret-handling", "network-exposure"}:
        notes.append("Check access from a separate authorized LAN client and keep credentials out of logs and broadcasts.")
    if "vulnbox" in active and family in {"injection", "file-access", "authentication"}:
        notes.append("Verify the service contract and checker behavior before applying a patch to a Vulnbox service.")
    return {"family": family, "cwe": list(rule["cwe"]),
            "review_priority": "high" if notes else rule["review_priority"],
            "signal_kind": rule["signal_kind"], "limitations": rule["limitations"],
            "context_notes": notes}


def rules_fingerprint(rules):
    """Hash only authored rule data, never runtime regex objects."""
    portable = []
    for rule in sorted(rules, key=lambda item: item["id"]):
        portable.append({key: value for key, value in rule.items()
                         if key not in {"compiled", "compiled_languages"}})
    return hashlib.sha256(_canonical_json(portable)).hexdigest()


def scan_scope(root, rules, exclude, max_bytes, max_files, max_findings, context=None):
    """Return a deterministic, non-secret description of scan comparability."""
    normalized_root = unicodedata.normalize("NFC", os.path.normcase(str(root)))
    root_digest = hashlib.sha256(
        ("durkahelper-root-v1\0" + normalized_root).encode(
            "utf-8", errors="surrogatepass"
        )
    ).hexdigest()
    body = {
        "schema": SCOPE_SCHEMA,
        "root": "sha256:" + root_digest,
        "rules_sha256": rules_fingerprint(rules),
        "exclude": sorted(set(exclude)),
        "limits": {
            "max_bytes": max_bytes,
            "max_files": max_files,
            "max_findings": max_findings,
        },
        "path_semantics": PATH_SEMANTICS,
        "semantic_revision": SEMANTIC_REVISION,
        "context_sha256": hashlib.sha256(_canonical_json(validate_context(context))).hexdigest(),
    }
    body["sha256"] = hashlib.sha256(_canonical_json(body)).hexdigest()
    return body


def language(path):
    name = path.name.lower()
    if name.startswith("dockerfile"):
        return "docker"
    if name == ".env.example" or name in {"nginx.conf", "redis.conf", "my.cnf", ".htaccess", "sshd_config", "sudoers"}:
        return "config"
    if name in {"gemfile", "rakefile"}:
        return "ruby"
    return EXTENSIONS.get(path.suffix.lower())


class PythonSignals(ast.NodeVisitor):
    """Syntactic signals only. No claim of type resolution or data-flow analysis."""

    def __init__(self):
        self.aliases = {}
        # Only immutable scalar/string-expression facts from straight-line code.
        # No mutable dict/list propagation, execution or interprocedural analysis.
        self.values = {}
        self.hits = set()
        self.issues = set()
        self.replaced_api_members = set()

    def resolved(self, node):
        return self.values.get(node.id, node) if isinstance(node, ast.Name) else node

    @staticmethod
    def literal_dict(node):
        """Known keys of an inline dict, respecting last-write-wins unpacking.

        Unknown spreads/keys invalidate earlier facts; no dict variable is
        evaluated or treated as an immutable copy of a mutable object.
        """
        result = {}
        if not isinstance(node, ast.Dict):
            return result
        for key, value in PythonSignals.dict_entries(node):
            if key is None:
                result.clear()
            else:
                result[key] = value
        return result

    @staticmethod
    def dict_entries(node):
        for key, value in zip(node.keys, node.values):
            if key is None and isinstance(value, ast.Dict):
                yield from PythonSignals.dict_entries(value)
            elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                yield key.value, value
            else:
                yield None, None

    INSTANCE_FACTORIES = {"requests.Session": "requests.Session",
                          "requests.sessions.Session": "requests.Session",
                          "requests.session": "requests.Session",
                          "requests.sessions.session": "requests.Session",
                          "httpx.Client": "httpx.Client", "httpx.AsyncClient": "httpx.AsyncClient",
                          "pickle.Unpickler": "pickle.Unpickler", "_pickle.Unpickler": "_pickle.Unpickler",
                          "flask.Flask": "flask.Flask", "flask.Blueprint": "flask.Blueprint",
                          "logging.getLogger": "logging.Logger"}
    TAR_FACTORIES = {"tarfile.open": "tarfile.TarFile", "tarfile.TarFile": "tarfile.TarFile",
                     "tarfile.TarFile.open": "tarfile.TarFile"}

    def constructed_type(self, node):
        if not isinstance(node, ast.Call):
            return ""
        factory = self.name(node.func)
        if factory in {"flask.Flask", "flask.Blueprint", "logging.getLogger"} and not self.known_binding(node.func):
            return ""
        return self.TAR_FACTORIES.get(factory, self.INSTANCE_FACTORIES.get(factory, ""))

    def known_binding(self, node):
        """Whether the new narrow detectors have an explicit local name fact."""
        if isinstance(node, ast.Name):
            return node.id in self.aliases and self.aliases[node.id] != "<local>"
        if isinstance(node, ast.Attribute):
            return self.name(node) not in self.replaced_api_members and self.known_binding(node.value)
        if isinstance(node, ast.Call):
            return self.known_binding(node.func)
        return False

    def forget(self, target):
        for item in ast.walk(target):
            if isinstance(item, ast.Attribute) and isinstance(item.ctx, (ast.Store, ast.Del)):
                self.replaced_api_members.add(self.name(item))
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                self.values.pop(item.id, None)
                self.aliases[item.id] = "<local>"

    def visit_Assign(self, node):
        self.visit(node.value)
        value = self.resolved(node.value)
        factory = self.constructed_type(node.value)
        for target in node.targets:
            self.visit(target)
            self.forget(target)
            if isinstance(target, ast.Name) and (isinstance(value, ast.Constant)
                                               or self.dynamic_string(value)
                                               or self.psycopg_sql(value) != "unknown"):
                self.values[target.id] = value
            elif isinstance(target, ast.Name) and factory:
                self.aliases[target.id] = factory
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                self.replaced_api_members.add(self.name(target))
            if (isinstance(target, ast.Subscript) and self.flask_config(target.value)
                    and isinstance(target.slice, ast.Constant)):
                self.config_signal(target.slice.value, node.value, node)
            if isinstance(target, ast.Attribute):
                if (target.attr == "debug" and self.name(target.value) == "flask.Flask"
                        and self.known_binding(target.value) and self.constant(node.value, True)):
                    self.hit("PY-DEBUG", node)
                if target.attr == "verify_mode" and self.name(node.value) == "ssl.CERT_NONE":
                    self.hit("PY-SSL-CONTEXT", node)
                if target.attr == "check_hostname" and self.constant(node.value, False):
                    self.hit("PY-SSL-CONTEXT", node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            # Reuse assignment handling, retaining the original line number.
            assignment = ast.Assign(targets=[node.target], value=node.value)
            ast.copy_location(assignment, node)
            self.visit_Assign(assignment)
        else:
            self.forget(node.target)

    def visit_AugAssign(self, node):
        self.generic_visit(node)
        self.forget(node.target)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.forget(node.target)

    def visit_Delete(self, node):
        for target in node.targets:
            self.forget(target)

    def visit_branch(self, node):
        # Do not carry scalar facts across branches, loops, exception handlers,
        # comprehensions or context managers. Scan each statement list locally.
        self.values = {}
        saved = self.aliases.copy()
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                self.values = {}
                self.aliases = saved.copy()
                for child in value:
                    if isinstance(child, ast.AST):
                        self.visit(child)
            elif isinstance(value, ast.AST):
                self.visit(value)
        self.invalidate_region_aliases(node, saved)
        self.values = {}

    def invalidate_region_aliases(self, node, saved):
        # Any store/import in a conditional region makes that alias uncertain.
        self.aliases = saved
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                self.aliases[child.id] = "<local>"
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    self.aliases[alias.asname or alias.name.split(".")[0]] = "<local>"

    def visit_context(self, node, *, asynchronous):
        # Retain only known constructor types with the matching context API.
        # Scalar facts never cross a context manager; __enter__/__exit__ may
        # affect application state and are never executed by this scanner.
        allowed = {"httpx.AsyncClient"} if asynchronous else {"tarfile.TarFile", "requests.Session", "httpx.Client"}
        saved = self.aliases.copy()
        self.values = {}
        for item in node.items:
            self.visit(item.context_expr)
            context_type = self.name(item.context_expr)
            if item.optional_vars is not None:
                self.forget(item.optional_vars)
                if isinstance(item.optional_vars, ast.Name) and context_type in allowed:
                    self.aliases[item.optional_vars.id] = context_type
        for statement in node.body:
            self.visit(statement)
        self.invalidate_region_aliases(node, saved)
        self.values = {}

    def visit_With(self, node):
        self.visit_context(node, asynchronous=False)

    def visit_AsyncWith(self, node):
        self.visit_context(node, asynchronous=True)

    visit_If = visit_branch
    visit_For = visit_branch
    visit_AsyncFor = visit_branch
    visit_While = visit_branch
    visit_Try = visit_branch
    visit_TryStar = visit_branch
    visit_Match = visit_branch
    visit_IfExp = visit_branch
    visit_ListComp = visit_branch
    visit_SetComp = visit_branch
    visit_DictComp = visit_branch
    visit_GeneratorExp = visit_branch

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self.name(node.value) + "." + node.attr
        if isinstance(node, ast.Call):
            return self.constructed_type(node)
        return ""

    def visit_Import(self, node):
        for alias in node.names:
            self.values.pop(alias.asname or alias.name.split(".")[0], None)
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                if alias.name != "*":
                    self.values.pop(alias.asname or alias.name, None)
                    self.aliases[alias.asname or alias.name] = node.module + "." + alias.name

    def visit_FunctionDef(self, node):
        saved, saved_values = self.aliases.copy(), self.values.copy()
        auth_seen = False
        for decorator in node.decorator_list:
            # Decorators are listed outermost first. Flask's registration
            # decorator must wrap the authentication decorator, not vice versa.
            if self.name(decorator) == "flask_login.login_required" and self.known_binding(decorator):
                auth_seen = True
            if (auth_seen and isinstance(decorator, ast.Call)
                    and self.name(decorator.func) in {
                        "flask.Flask.route", "flask.Blueprint.route",
                        *{"flask." + kind + "." + method for kind in ("Flask", "Blueprint")
                          for method in ("get", "post", "put", "patch", "delete")}}):
                self.hit("PY-AUTH-DECORATOR", decorator)
            if self.name(decorator) == "django.views.decorators.csrf.csrf_exempt":
                self.hit("PY-CSRF-EXEMPT", decorator)
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        self.values = {}
        # Parameters shadow imports. Function-local scalar facts do not escape.
        arguments = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        arguments += [arg for arg in (node.args.vararg, node.args.kwarg) if arg]
        for arg in arguments:
            self.aliases[arg.arg] = "<local>"
        for statement in node.body:
            self.visit(statement)
        self.aliases = saved
        self.aliases[node.name] = "<local>"
        self.values = saved_values
        self.values.pop(node.name, None)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        saved, saved_values = self.aliases.copy(), self.values.copy()
        self.values = {}
        self.generic_visit(node)
        self.aliases = saved
        self.aliases[node.name] = "<local>"
        self.values = saved_values
        self.values.pop(node.name, None)

    def visit_Lambda(self, node):
        saved, saved_values = self.aliases.copy(), self.values.copy()
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                    *[a for a in (node.args.vararg, node.args.kwarg) if a]]:
            self.aliases[arg.arg] = "<local>"
        self.values = {}
        self.visit(node.body)
        self.aliases, self.values = saved, saved_values

    def constant(self, node, value):
        node = self.resolved(node)
        return isinstance(node, ast.Constant) and node.value == value

    @staticmethod
    def literal_string(node):
        # Recognize syntax only: no evaluation, formatting, arbitrary constant
        # folding or recursive expansion of names (which may be self-referential).
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)
        if isinstance(node, ast.JoinedStr):
            return all(isinstance(part, ast.Constant) and isinstance(part.value, str) for part in node.values)
        return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
                and PythonSignals.literal_string(node.left) and PythonSignals.literal_string(node.right))

    def dynamic_string(self, node):
        node = self.resolved(node)
        if self.literal_string(node):
            return False
        return (isinstance(node, ast.JoinedStr)
                or isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
                or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format")

    def flask_config(self, node):
        return (isinstance(node, ast.Attribute) and node.attr == "config"
                and self.name(node.value) == "flask.Flask" and self.known_binding(node))

    def config_signal(self, key, value, node):
        if key == "DEBUG" and self.constant(value, True):
            self.hit("PY-DEBUG", node)
        if key in {"SESSION_COOKIE_HTTPONLY", "SESSION_COOKIE_SECURE"} and self.constant(value, False):
            self.hit("CFG-COOKIE-FLAGS", node)

    def psycopg_sql(self, node, depth=0, active=None):
        """Return safe/unsafe/unknown for a narrow, imported composable tree.

        SQL() never escapes its argument. Only literal SQL snippets and known
        quoting constructors are suppressed; unknown pieces remain reviewable.
        This says nothing about authorization to select an identifier.
        """
        node = self.resolved(node)
        active = set() if active is None else active
        if id(node) in active:
            return "unknown"  # A scalar/name cycle is not deep composition.
        if depth > 32:
            self.issues.add("python_composition_limit")
            return "unknown"
        active = active | {id(node)}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            states = [self.psycopg_sql(part, depth + 1, active) for part in (node.left, node.right)]
            return "unsafe" if "unsafe" in states else "safe" if states == ["safe", "safe"] else "unknown"
        if not isinstance(node, ast.Call):
            return "unknown"
        name = self.name(node.func)
        prefixes = ("psycopg.sql.", "psycopg2.sql.")
        if name.startswith(prefixes) and self.known_binding(node.func):
            kind = name.rsplit(".", 1)[-1]
            if kind == "SQL":
                return "safe" if len(node.args) == 1 and not node.keywords and self.literal_string(self.resolved(node.args[0])) else "unsafe"
            if kind in {"Identifier", "Literal", "Placeholder"}:
                return "safe"
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "join", "as_string"}:
            base = self.psycopg_sql(node.func.value, depth + 1, active)
            if base == "unknown":
                return "unknown"
            if node.func.attr == "as_string":
                return base
            if node.func.attr == "join":
                parts = node.args[0].elts if len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)) else [None]
            else:
                parts = [*node.args, *[kw.value if kw.arg else None for kw in node.keywords]]
            states = [base, *[self.psycopg_sql(part, depth + 1, active) for part in parts]]
            return "safe" if all(state == "safe" for state in states) else "unsafe"
        return "unknown"

    def hit(self, rule, node):
        self.hits.add((rule, node.lineno))

    def visit_Assert(self, node):
        # Runtime security checks must survive python -O; ordinary test asserts
        # are deliberately omitted by this name-based heuristic.
        sensitive = re.compile(r"(?:auth|permission|owner|admin|token|session|password|allowed)", re.I)
        if any(isinstance(item, ast.Name) and sensitive.search(item.id)
               or isinstance(item, ast.Attribute) and sensitive.search(item.attr)
               for item in ast.walk(node.test)):
            self.hit("PY-ASSERT-AUTH", node)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.name(node.func)
        tail = name.rsplit(".", 1)[-1]
        kwargs = {}
        for kw in node.keywords:
            if kw.arg:
                kwargs[kw.arg] = kw.value
            else:
                kwargs.update(self.literal_dict(kw.value))
        first = node.args[0] if node.args else None
        if (isinstance(node.func, ast.Attribute) and node.func.attr in {"update", "from_mapping"}
                and self.flask_config(node.func.value)):
            config = {}
            if len(node.args) <= 1:
                if node.args:
                    config.update(self.literal_dict(node.args[0]))
                for kw in node.keywords:
                    if kw.arg:
                        config[kw.arg] = kw.value
                    elif isinstance(kw.value, ast.Dict):
                        for key, value in self.dict_entries(kw.value):
                            if key is None:
                                config.clear()
                            else:
                                config[key] = value
                    else:
                        config.clear()
                for key, value in config.items():
                    self.config_signal(key, value, node)
        if (self.known_binding(node.func) and name.rsplit(".", 1)[0] in {"logging", "logging.Logger", "flask.Flask.logger"}
                and tail in {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}):
            sensitive = {"password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key", "authorization"}
            # Only direct values/format expressions, not arguments to a
            # potential redaction/hash helper. No source text is exported.
            def exposes(value):
                if isinstance(value, ast.Name):
                    return value.id.lower() in sensitive
                if isinstance(value, ast.Attribute):
                    return value.attr.lower() in sensitive
                if isinstance(value, ast.Subscript):
                    return isinstance(value.slice, ast.Constant) and isinstance(value.slice.value, str) and value.slice.value.lower() in sensitive
                if isinstance(value, ast.JoinedStr):
                    return any(exposes(item.value) for item in value.values if isinstance(item, ast.FormattedValue))
                if isinstance(value, (ast.Tuple, ast.List)):
                    return any(exposes(item) for item in value.elts)
                if isinstance(value, ast.Dict):
                    return any(exposes(item) for item in value.values)
                if isinstance(value, ast.BinOp):
                    return exposes(value.left) or exposes(value.right)
                return False
            if any(exposes(value) for value in node.args):
                self.hit("PY-LOG-CREDENTIALS", node)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.hit("PY-EVAL", node)
        subprocess_call = name in {"subprocess.run", "subprocess.call", "subprocess.check_call",
                                   "subprocess.check_output", "subprocess.Popen"}
        process_args = first if first is not None else kwargs.get("args")
        if name == "asyncio.create_subprocess_exec":
            process_args = ast.Tuple(elts=node.args, ctx=ast.Load())
        shell_argv = (isinstance(process_args, (ast.List, ast.Tuple)) and len(process_args.elts) > 1
                      and isinstance(process_args.elts[0], ast.Constant)
                      and isinstance(process_args.elts[0].value, str)
                      and process_args.elts[0].value.replace("\\", "/").rsplit("/", 1)[-1].lower()
                      in {"sh", "bash", "dash", "zsh", "ksh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
                      and any(isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                              and arg.value.lower() in {"-c", "-lc", "-ec", "/c", "-command", "-encodedcommand"}
                              for arg in process_args.elts[1:]))
        if (name in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
                     "asyncio.create_subprocess_shell"}
                or subprocess_call and (self.constant(kwargs.get("shell"), True) or shell_argv)
                or name == "asyncio.create_subprocess_exec" and shell_argv):
            self.hit("PY-SHELL", node)
        if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads", "dill.load", "dill.loads", "shelve.open",
                    "pickle.Unpickler.load", "_pickle.Unpickler.load", "jsonpickle.decode", "jsonpickle.loads",
                    "joblib.load", "pandas.read_pickle"}:
            self.hit("PY-DESERIALIZE", node)
        if name in {"numpy.load", "numpy.lib.format.read_array"}:
            # These APIs default to rejecting pickle; signal only an explicit
            # opt-in. Starred argv prevent a reliable positional index.
            position = 2 if name == "numpy.load" else 1
            allow_pickle = kwargs.get("allow_pickle")
            if (allow_pickle is None and len(node.args) > position
                    and not any(isinstance(arg, ast.Starred) for arg in node.args[:position + 1])):
                allow_pickle = node.args[position]
            if self.constant(allow_pickle, True):
                self.hit("PY-DESERIALIZE", node)
        if name in {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"}:
            loader = kwargs.get("Loader", node.args[1] if len(node.args) > 1 else None)
            if self.name(loader) not in {"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader"}:
                self.hit("PY-YAML", node)
        sql_arg = first
        if sql_arg is None:
            sql_arg = next((kwargs[k] for k in ("query", "sql", "operation", "statement", "sql_script", "raw_query", "text") if k in kwargs), None)
        if tail in {"execute", "executemany", "executescript", "raw", "text"}:
            composition = self.psycopg_sql(sql_arg)
            if composition == "unsafe" or composition != "safe" and self.dynamic_string(sql_arg):
                self.hit("PY-SQL", node)
        if tail in {"find", "find_one", "filter", "where"} and any(isinstance(arg, ast.BoolOp) for arg in node.args):
            self.hit("PY-ORM-BOOL", node)
        template_arg = first if first is not None else kwargs.get("source")
        if tail in {"render_template_string", "from_string"} and template_arg is not None and not isinstance(template_arg, ast.Constant):
            self.hit("PY-TEMPLATE", node)
        if self.constant(kwargs.get("verify"), False) and (name.startswith(("requests.", "httpx.")) or tail in {"get", "post", "put", "patch", "delete", "request"}):
            self.hit("PY-TLS", node)
        if name == "ssl._create_unverified_context":
            self.hit("PY-SSL-CONTEXT", node)
        if name == "django.views.decorators.csrf.csrf_exempt":
            self.hit("PY-CSRF-EXEMPT", node)
        if name in {"setattr", "builtins.setattr"} and len(node.args) > 1 and not isinstance(self.resolved(node.args[1]), ast.Constant):
            self.hit("PY-MASS-ASSIGN", node)
        redirect_keyword = "to" if name == "django.shortcuts.redirect" else "location"
        redirect_arg = first if first is not None else kwargs.get(redirect_keyword)
        if name in {"flask.redirect", "django.shortcuts.redirect", "werkzeug.utils.redirect"} and redirect_arg is not None and not isinstance(self.resolved(redirect_arg), ast.Constant):
            self.hit("PY-REDIRECT", node)
        if name in {"re.compile", "re.match", "re.fullmatch", "re.search", "re.findall", "re.finditer", "re.split", "re.sub", "re.subn"} and first is not None and not isinstance(self.resolved(first), ast.Constant):
            self.hit("PY-REGEX-DYNAMIC", node)
        if tail in {"run", "run_simple"} and self.constant(kwargs.get("debug", kwargs.get("use_debugger")), True):
            self.hit("PY-DEBUG", node)
        if name in {"jwt.decode", "jwt.decode_complete"} or name.endswith((".jwt.decode", ".jwt.decode_complete")):
            jose = name == "jose.jwt.decode"
            known_modern = jose or name == "jwt.decode_complete"
            jwt_args = kwargs.copy()
            valid_binding = True
            if known_modern:
                # Generic jwt.decode is version-dependent: PyJWT 1.x placed
                # verify third. Only these exact APIs have this known layout.
                for argument, position in (("algorithms", 2), ("options", 3)):
                    if (len(node.args) > position
                            and not any(isinstance(arg, ast.Starred) for arg in node.args[:position + 1])):
                        if argument in jwt_args:
                            valid_binding = False  # Runtime TypeError, not a disabled verifier.
                        else:
                            jwt_args[argument] = node.args[position]
            if valid_binding:
                options = self.literal_dict(jwt_args.get("options"))
                disabled = not known_modern and self.constant(jwt_args.get("verify"), False)
                disabled |= self.constant(options.get("verify_signature"), False)
                if any(self.constant(options.get("verify_" + claim), False)
                       and not (jose and self.constant(options.get("require_" + claim), True))
                       for claim in ("exp", "nbf", "aud", "iss")):
                    self.hit("PY-JWT-CLAIMS", node)
                if disabled:
                    self.hit("PY-JWT", node)
                algorithms = jwt_args.get("algorithms")
                algorithm_value = self.resolved(algorithms)
                fixed_algorithms = (isinstance(algorithms, (ast.List, ast.Tuple))
                                    and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in algorithms.elts))
                fixed_algorithms |= (jose and isinstance(algorithm_value, ast.Constant)
                                     and isinstance(algorithm_value.value, str))
                if algorithms is not None and not fixed_algorithms:
                    self.hit("PY-JWT-ALGORITHMS", node)
        archive_filter = kwargs.get("filter")
        data_filter = (self.constant(archive_filter, "data")
                       or self.name(archive_filter) == "tarfile.data_filter")
        tar_extract = name == "tarfile.TarFile.extract"
        unpack_tar = False
        if name == "shutil.unpack_archive":
            archive_format = kwargs.get("format")
            if (archive_format is None and len(node.args) > 2
                    and not any(isinstance(arg, ast.Starred) for arg in node.args[:3])):
                archive_format = node.args[2]
            unpack_tar = any(self.constant(archive_format, fmt)
                             for fmt in ("tar", "gztar", "bztar", "xztar", "zstdtar"))
        if (tail == "extractall" or tar_extract or unpack_tar) and not data_filter:
            self.hit("PY-ARCHIVE", node)
        if name in {"tempfile.mktemp"}:
            self.hit("PY-TEMP", node)
        if (tail == "XMLParser" or name in {"lxml.etree.XMLPullParser", "lxml.etree.ETCompatXMLParser",
                                           "lxml.etree.iterparse"}) and self.constant(kwargs.get("resolve_entities"), True):
            self.hit("PY-XML", node)
        if name in {"hashlib.md5", "hashlib.sha1"}:
            self.hit("PY-WEAK-HASH", node)
        if name.startswith("random.") and tail in {"random", "randint", "randrange", "getrandbits", "choice", "choices"}:
            self.hit("PY-RNG", node)
        file_arg = first if first is not None else kwargs.get("path_or_file")
        if tail == "send_file" and file_arg is not None and not isinstance(file_arg, ast.Constant):
            self.hit("PY-FILE", node)
        url_arg = first if first is not None else kwargs.get("url")
        http_owner = name.rsplit(".", 1)[0]
        http_call = (http_owner in {"requests", "httpx", "requests.Session", "requests.sessions.Session", "httpx.Client", "httpx.AsyncClient"}
                     and tail in {"get", "post", "put", "patch", "delete", "head", "options", "request"})
        http_call |= http_owner in {"httpx", "httpx.Client", "httpx.AsyncClient"} and tail == "stream"
        if http_call and tail in {"request", "stream"}:
            url_arg = (node.args[1] if len(node.args) > 1
                       and not any(isinstance(arg, ast.Starred) for arg in node.args[:2]) else kwargs.get("url"))
        if (http_call or name == "urllib.request.urlopen") and url_arg is not None and not isinstance(self.resolved(url_arg), ast.Constant):
            self.hit("PY-URL", node)
        if name in {"zlib.crc32", "zlib.adler32", "binascii.crc32", "binascii.crc_hqx"}:
            self.hit("PY-CRC", node)
        if tail in {"xpath", "XPath"} and self.dynamic_string(first):
            self.hit("PY-XPATH", node)
        if name == "uuid.UUID" and ({"bytes", "bytes_le"} & kwargs.keys()):
            self.hit("PY-UUID-BYTES", node)
        self.generic_visit(node)


def javascript_alias_patterns(source):
    """Bounded import-name hints, not a JavaScript parser or scope analysis.

    Source is never evaluated. Only exact known module/member pairs contribute
    patterns, and every target-controlled identifier is escaped first.
    """
    ident = r"[A-Za-z_$][\w$]{0,127}"
    module = r"['\"]((?:node:)?child_process|jsonwebtoken|jose)['\"]"
    bindings = []

    def bind(mod, local, member, end):
        mod = mod.removeprefix("node:")
        if not re.fullmatch(ident, local):
            return
        members = {"child_process": ("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"),
                   "jsonwebtoken": ("decode",), "jose": ("decodeJwt",)}[mod]
        for name in members if member is None else (member,):
            if name not in members:
                continue
            if len(bindings) >= 128:
                raise ValueError("javascript_alias_limit")
            rid = "JS-SHELL" if mod == "child_process" else "JS-JWT-DECODE"
            receiver = re.escape(local)
            if member is None:
                access = r"\s*(?:\?\.\s*|\.\s*)" + re.escape(name)
                access += r"|\s*(?:\?\.\s*)?\[\s*['\"]" + re.escape(name) + r"['\"]\s*\]"
                receiver += "(?:" + access + ")"
            suffix = r"\s*(?:\?\.)?\s*\("
            if mod == "child_process" and name not in {"exec", "execSync"}:
                suffix += r"\s*['\"](?:[^'\"\n]*/)?(?:sh|bash|dash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)['\"]"
            bindings.append((rid, re.compile(r"(?<![\w$.])" + receiver + suffix), end))

    for match in re.finditer(r"\bimport\s+(?:\*\s+as\s+)?(" + ident + r")\s+from\s*" + module, source):
        bind(match[2], match[1], None, match.end())
    for match in re.finditer(r"\b(" + ident + r")\s*=\s*require\s*\(\s*" + module + r"\s*\)", source):
        bind(match[2], match[1], None, match.end())
    esm = r"\bimport\s+(?:(" + ident + r")\s*,\s*)?\{([^}]{1,1500})\}\s+from\s*" + module
    cjs = r"\b(?:const|let|var)\s*\{([^}]{1,1500})\}\s*=\s*require\s*\(\s*" + module + r"\s*\)"
    for style, pattern in (("esm", esm), ("cjs", cjs)):
        for match in re.finditer(pattern, source):
            if style == "esm":
                default, body, mod = match.groups()
                if default:
                    bind(mod, default, None, match.end())
            else:
                body, mod = match.groups()
            for field in body.split(","):
                pair = re.fullmatch(r"\s*(" + ident + r")(?:\s*(?:as|:)\s*(" + ident + r"))?\s*", field)
                if pair:
                    bind(mod, pair[2] or pair[1], pair[1], match.end())
    return bindings


def javascript_boundary_signals(source):
    """Small bounded token contracts, NOT a JS parser or taint engine.

    Exact imports/constructors, inline objects and direct request properties
    only. Any observed redeclaration, parameter shadow or reassignment makes
    that binding unusable throughout this file. Regex literals, destructured
    imports, dynamic spreads/keys, wrappers and cross-file facts stay manual.
    """
    issues, tokens = [], []
    token_pattern = re.compile(r"[A-Za-z_$][\w$]*|[0-9]+|=>|\.\.\.|\?\.|===|==|!=|\+=|-=|\+\+|--|[^\s]")
    i = 0
    while i < len(source):
        if source[i].isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = len(source) if end < 0 else end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                issues.append("lexical_unterminated")
            i = len(source) if end < 0 else end + 2
            continue
        start = i
        if (source[i] == "/"
                and (not tokens or tokens[-1][0] in {"=", "(", "[", ":", ",", "return", "=>", "!", "?", ";"})):
            # Common regex-literal positions only; division and ambiguous
            # statement contexts are not resolved as by a full JS grammar.
            end, character_class = i + 1, False
            while end < len(source) and source[end] not in "\r\n":
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == "[":
                    character_class = True
                elif source[end] == "]":
                    character_class = False
                elif source[end] == "/" and not character_class:
                    break
                end += 1
            if end < len(source) and source[end] == "/":
                i = end + 1
                tokens.append(("<regex>", start))
                continue
        if source[i] in "\"'`":
            quote, closed = source[i], False
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i = min(len(source), i + 2)
                elif source[i] == quote:
                    i += 1
                    closed = True
                    break
                else:
                    i += 1
            if not closed:
                issues.append("lexical_unterminated")
            tokens.append(("<template>" if quote == "`" else source[start:i], start))
        else:
            match = token_pattern.match(source, i)
            value = match.group()
            i += len(value)
            tokens.append((value, start))
        if len(tokens) > 100000:
            return set(), ["javascript_token_limit"]
    texts = [item[0] for item in tokens]
    pairs, stack = {}, []
    for index, value in enumerate(texts):
        if value in {"(", "[", "{"}:
            stack.append(index)
            if len(stack) > 128:
                return set(), ["javascript_nesting_limit"]
        elif value in {")", "]", "}"} and stack and texts[stack[-1]] == {")": "(", "]": "[", "}": "{"}[value]:
            opening = stack.pop()
            pairs[opening] = index

    def literal(value):
        return value[1:-1] if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0] and "\\" not in value else None

    closing_pairs = {right: left for left, right in pairs.items()}

    def fields(begin, end):
        """Split top-level commas only, under a fixed expression budget."""
        if end - begin > 2048:
            issues.append("javascript_expression_limit")
            return []
        parts, start, pos = [], begin, begin
        while pos < end:
            if pos in pairs:
                pos = pairs[pos] + 1
                continue
            if texts[pos] == ",":
                parts.append((start, pos))
                start = pos + 1
            pos += 1
        if start < end:
            parts.append((start, end))
        return parts

    def object_values(begin, end):
        result = {}
        if begin >= end or texts[begin] != "{" or pairs.get(begin) != end - 1:
            return result
        for left, right in fields(begin + 1, end - 1):
            if right - left >= 3 and texts[left + 1] == ":":
                key = literal(texts[left]) or texts[left]
                if re.fullmatch(r"[A-Za-z_$][\w$]*", key):
                    result[key] = (left + 2, right)
                    continue
            # Unknown spreads/computed keys may override any preceding key.
            result.clear()
        return result

    def exact(span, value):
        return span is not None and texts[span[0]:span[1]] == [value]

    def direct_property(begin, end):
        if begin >= end or not re.fullmatch(r"[A-Za-z_$][\w$]*", texts[begin]):
            return None
        path = [texts[begin]]
        pos = begin + 1
        while pos < end:
            if texts[pos] in {".", "?."} and pos + 1 < end and re.fullmatch(r"[A-Za-z_$][\w$]*", texts[pos + 1]):
                path.append(texts[pos + 1])
                pos += 2
            elif texts[pos] == "[" and pos + 2 < end and texts[pos + 2] == "]" and literal(texts[pos + 1]) is not None:
                path.append(literal(texts[pos + 1]))
                pos += 3
            else:
                return None
        return path

    sensitive = {"password", "passwd", "secret", "token", "access_token", "refresh_token", "api_key", "authorization"}

    def exposes(begin, end, depth=0):
        if depth > 16 or end - begin > 2048:
            issues.append("javascript_expression_limit")
            return False
        if begin >= end:
            return False
        path = direct_property(begin, end)
        if path:
            return path[-1].lower() in sensitive
        if texts[begin] == "{" and pairs.get(begin) == end - 1:
            return any(exposes(left, right, depth + 1) for left, right in object_values(begin, end).values())
        if texts[begin] == "[" and pairs.get(begin) == end - 1:
            return any(exposes(left, right, depth + 1) for left, right in fields(begin + 1, end - 1))
        pos = begin
        while pos < end:
            if pos in pairs:
                pos = pairs[pos] + 1
                continue
            if texts[pos] == "+":
                return exposes(begin, pos, depth + 1) or exposes(pos + 1, end, depth + 1)
            pos += 1
        return False  # Calls (including alleged redactors) are not traced.

    # Parameters are a conservative file-wide uncertainty, not scope typing.
    parameter_names = set()
    for pos, value in enumerate(texts):
        if value == "(" and pos in pairs and pairs[pos] + 1 < len(texts) and texts[pairs[pos] + 1] == "{":
            if pos and texts[pos - 1] not in {"if", "for", "while", "switch", "with"}:
                parameter_names.update(texts[pos + 1:pairs[pos]])
        if value == "function":
            opening = pos + 1 if pos + 1 < len(texts) and texts[pos + 1] == "(" else pos + 2
            if opening in pairs:
                parameter_names.update(texts[opening + 1:pairs[opening]])
        if value == "=>" and pos:
            if texts[pos - 1] == ")":
                opening = closing_pairs.get(pos - 1)
                if opening is not None:
                    parameter_names.update(texts[opening + 1:pos - 1])
            else:
                parameter_names.add(texts[pos - 1])
    occurrences = {}
    for pos, value in enumerate(texts):
        occurrences.setdefault(value, []).append(pos)

    def binding_valid(local, declaration):
        if local in parameter_names:
            return False
        for pos in occurrences.get(local, []):
            if pos == declaration:
                continue
            previous = texts[pos - 1] if pos else ""
            following = texts[pos + 1] if pos + 1 < len(texts) else ""
            if previous in {"const", "let", "var", "function", "class", "import"} or following in {"=", "+=", "-=", "++", "--"}:
                return False
            # Known API member replaced with a local function/value.
            if following in {".", "?."}:
                end = pos + 1
                while end + 1 < len(texts) and texts[end] in {".", "?."}:
                    end += 2
                if end < len(texts) and texts[end] in {"=", "+=", "-=", "++", "--"}:
                    return False
            if previous in {"{", ","} and following in {"}", ","}:
                # Destructured declarations/imports cannot establish a fact.
                left = max(0, pos - 128)
                if any(texts[k] in {"const", "let", "var", "import"} for k in range(left, pos)):
                    return False
        return True

    bindings = {}
    for pos, value in enumerate(texts):
        mod = None
        if value == "import" and pos + 3 < len(texts):
            if texts[pos + 2] == "from":
                local_pos, module_pos = pos + 1, pos + 3
            elif texts[pos + 1:pos + 3] == ["*", "as"] and pos + 5 < len(texts) and texts[pos + 4] == "from":
                local_pos, module_pos = pos + 3, pos + 5
            else:
                continue
            mod = literal(texts[module_pos])
        elif (value in {"const", "let", "var"} and pos + 6 < len(texts)
              and texts[pos + 2:pos + 5] == ["=", "require", "("] and texts[pos + 6] == ")"
              and binding_valid("require", -1)):
            local_pos, module_pos = pos + 1, pos + 5
            mod = literal(texts[module_pos])
        if mod in {"cors", "express-session", "pg", "mysql", "mysql2", "mysql2/promise"} and binding_valid(texts[local_pos], local_pos):
            bindings[texts[local_pos]] = (mod, module_pos + 1)
    if len(bindings) > 128:
        return set(), ["javascript_alias_limit"]
    # Direct default/namespace driver factories; named imports remain manual.
    for pos, value in enumerate(texts):
        if value not in {"const", "let", "var"} or pos + 7 >= len(texts) or texts[pos + 2] != "=":
            continue
        factory_pos = pos + 4 if texts[pos + 3] == "new" else pos + 3
        binding = bindings.get(texts[factory_pos])
        if not binding or factory_pos < binding[1] or texts[factory_pos + 1] != ".":
            continue
        mod, _ = binding
        factory = texts[factory_pos + 2]
        if texts[factory_pos + 3] != "(" or factory_pos + 3 not in pairs:
            continue
        if ((mod == "pg" and texts[pos + 3] == "new" and factory in {"Pool", "Client"})
                or mod in {"mysql", "mysql2", "mysql2/promise"} and factory in {"createPool", "createConnection"}):
            if binding_valid(texts[pos + 1], pos + 1):
                bindings[texts[pos + 1]] = ("sql-driver", factory_pos + 3)
                if len(bindings) > 128:
                    return set(), ["javascript_alias_limit"]

    hits = set()
    newlines = [pos for pos, char in enumerate(source) if char == "\n"]
    console_known = binding_valid("console", -1)
    for pos, value in enumerate(texts):
        if pos and texts[pos - 1] in {".", "?."}:
            continue
        binding = bindings.get(value)
        if binding and pos < binding[1]:
            binding = None
        opening, rid = None, None
        if binding and binding[0] in {"cors", "express-session"} and pos + 1 < len(texts) and texts[pos + 1] == "(":
            opening = pos + 1
        elif pos + 3 < len(texts) and texts[pos + 1] in {".", "?."} and texts[pos + 3] == "(":
            if binding and binding[0] == "sql-driver" and texts[pos + 2] in {"query", "execute"}:
                opening, rid = pos + 3, "JS-SQL"
            elif value == "console" and console_known and texts[pos + 2] in {"log", "info", "warn", "error", "debug", "trace"}:
                opening, rid = pos + 3, "JS-LOG-CREDENTIALS"
        if opening not in pairs:
            continue
        arguments = fields(opening + 1, pairs[opening])
        if not arguments:
            continue
        if rid == "JS-LOG-CREDENTIALS":
            matched = any(exposes(left, right) for left, right in arguments)
        elif rid == "JS-SQL":
            path = direct_property(*arguments[0])
            matched = bool(path and len(path) >= 3 and path[0] in {"req", "request"} and path[1] in {"body", "query", "params"})
        else:
            options = object_values(*arguments[0])
            if binding[0] == "cors":
                rid = "CFG-CORS"
                matched = exact(options.get("origin"), "true") and exact(options.get("credentials"), "true")
            else:
                rid = "CFG-COOKIE-FLAGS"
                cookie = options.get("cookie")
                matched = bool(cookie and exact(object_values(*cookie).get("httpOnly"), "false"))
        if matched:
            hits.add((rid, bisect_right(newlines, tokens[pos][1]) + 1))
    return hits, sorted(set(issues))


def redis_acl_passwordless(line):
    """Conservative shared token subset of redis.conf and external ACL files.

    This reads a complete physical line, not an effective ACL. Quotes, escapes,
    selectors, unknown operations and interior non-space whitespace stay manual.
    Never include tokens (which can contain passwords) in a report.
    """
    line = line.strip(" \t\r\n")
    if any(char in line for char in "\"'\\()") or any(char.isspace() and char != " " for char in line):
        return False
    tokens = line.split(" ")
    if len(tokens) < 3 or tokens[0] != "user" or not tokens[1]:
        return False
    enabled = passwordless = None
    neutral = {"allkeys", "resetkeys", "allcommands", "nocommands", "allchannels", "resetchannels"}
    for token in tokens[2:]:
        operation = token.lower()
        if not token:
            continue
        if operation == "on":
            enabled = True
        elif operation == "off":
            enabled = False
        elif operation == "reset":
            enabled = passwordless = False
        elif operation == "nopass":
            passwordless = True
        elif operation == "resetpass" or token.startswith(">"):
            # Even a lone > adds the empty password and clears the nopass flag;
            # absence of this signal does not establish password strength.
            passwordless = False
        elif token.startswith("#"):
            if not re.fullmatch(r"#[0-9a-f]{64}", token):
                return False
            passwordless = False
        elif token.startswith("!"):
            if not re.fullmatch(r"![0-9a-f]{64}", token):
                return False
        elif (operation in neutral or token.startswith(("<", "~", "&", "+", "-"))
              or operation.startswith(("%r~", "%w~", "%rw~"))):
            # Access grants/revocations and password removals do not change
            # either flag. Validity and least privilege are separate reviews.
            continue
        else:
            return False
    return enabled is True and passwordless is True


def bounded_regex_windows(lines):
    """Whole LF lines only; never invent an end-of-token by slicing a line.

    Each window has at most 12 lines and 8192 characters, including CR/LF.
    Adaptive overlap retains every supported line after a size boundary. A
    multi-line match beyond these window bounds remains outside the contract.
    Only actually skipped oversized lines make the analysis partial.
    """
    windows = []
    skipped_line = False
    start = 0
    while start < len(lines):
        if len(lines[start]) > 8192:
            skipped_line = True
            start += 1
            continue
        end, size = start, 0
        while end < len(lines) and end - start < 12 and size + len(lines[end]) <= 8192:
            size += len(lines[end])
            end += 1
        windows.append((start, "".join(lines[start:end])))
        if end == len(lines):
            break
        if len(lines[end]) > 8192:
            # Do not concatenate supported lines across omitted input.
            start = end
        else:
            start = max(start + 1, end - 6)
    return windows, ["regex_line_limit"] if skipped_line else []


def lexical_noncode(source, lang):
    """Bounded lexical exclusions for opt-in new rules, not a full parser.

    Common quoted literals/comments are recognized. Language-specific regex
    literals, macros, heredocs and complex interpolation still need review.
    Offsets and physical line numbers are never changed.
    """
    excluded = bytearray(len(source))
    issues = []
    i = 0
    while i < len(source):
        start = i
        closing = None
        if source.startswith("<!--", i) and lang == "template":
            closing = "-->"
        elif source.startswith("{#", i) and lang == "template":
            closing = "#}"
        elif source.startswith("/*", i) and lang in {"javascript", "php", "go", "java", "csharp", "native", "rust", "sql"}:
            closing = "*/"
        elif (lang == "ruby" and source.startswith("=begin", i)
              and (i == 0 or source[i - 1] == "\n")
              and (i + 6 == len(source) or source[i + 6].isspace())):
            end = re.compile(r"(?m)^=end(?:\s|$)").search(source, i + 6)
            if end is None:
                issues.append("lexical_unterminated")
                i = len(source)
            else:
                i = end.end()
            excluded[start:i] = b"\x01" * (i - start)
            continue
        elif lang == "sql" and source[i] == "$":
            marker = re.match(r"\$(?:[A-Za-z_][A-Za-z0-9_]{0,63})?\$", source[i:i + 66])
            if marker:
                closing = marker.group()
        if closing:
            end = source.find(closing, i + (len(closing) if lang == "sql" and source[i] == "$" else 2))
            if end < 0:
                issues.append("lexical_unterminated")
            i = len(source) if end < 0 else end + len(closing)
        elif ((source.startswith("//", i) and lang in {"javascript", "php", "go", "java", "csharp", "native", "rust"})
              or (source[i] == "#" and lang in {"python", "php", "ruby", "shell", "config", "docker"})
              or (source.startswith("--", i) and lang == "sql")):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
        elif source[i] in {"'", '"', "`"} and lang != "template":
            quote = source[i]
            if (lang == "rust" and quote == "'"
                    and not re.match(r"'(?:[^'\\\n]|\\(?:[nrt0'\"\\]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}))'", source[i:i + 16])):
                # Rust lifetimes/labels are not character literals.
                i += 1
                continue
            i += 1
            closed = False
            while i < len(source):
                if source[i] == "\\":
                    i = min(len(source), i + 2)
                elif source[i] == quote:
                    i += 1
                    closed = True
                    break
                else:
                    i += 1
            if not closed:
                issues.append("lexical_unterminated")
        else:
            i += 1
            continue
        excluded[start:i] = b"\x01" * (i - start)
    return excluded, sorted(set(issues))


def scan_text(source, lang, rules):
    hits = set()
    problems = []
    if lang == "python":
        try:
            tree = ast.parse(source)
            count = 0
            for _ in ast.walk(tree):
                count += 1
                if count > 200000:
                    raise ValueError("AST node limit")
            visitor = PythonSignals()
            visitor.visit(tree)
            hits.update(visitor.hits)
            problems.extend(sorted(visitor.issues))
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            # Avoid including offending source/secret text from SyntaxError.
            problems.append("python_parse_failed:" + type(exc).__name__)
    # str.splitlines also treats VT/FF/NEL/Unicode separators as line breaks.
    # Regex MULTILINE and import hints use LF; preserve that physical layout.
    parts = source.split("\n")
    lines = [line + "\n" for line in parts[:-1]] + ([parts[-1]] if parts[-1] else [])
    line_offsets = []
    offset = 0
    for line_text in lines:
        line_offsets.append(offset)
        offset += len(line_text)
    if lang == "javascript":
        boundary_hits, boundary_issues = javascript_boundary_signals(source)
        hits.update(boundary_hits)
        problems.extend(boundary_issues)
        try:
            newlines = [i for i, char in enumerate(source) if char == "\n"]
            # Import declarations and call sites may be far apart. Known call
            # prefixes are searched under the file-size and alias-count limits.
            for rid, pattern, declaration_end in javascript_alias_patterns(source):
                for match in pattern.finditer(source, declaration_end):
                    hits.add((rid, bisect_right(newlines, match.start()) + 1))
        except ValueError:
            problems.append("javascript_alias_limit")
    regex_rules = [rule for rule in rules if rule["engine"] == "regex" and lang in rule["languages"]]
    noncode, lexical_issues = lexical_noncode(source, lang) if any(rule.get("code_only") for rule in regex_rules) else (None, [])
    windows, regex_issues = bounded_regex_windows(lines) if regex_rules else ([], [])
    problems.extend(regex_issues)
    for rule in regex_rules:
        pattern = rule.get("compiled_languages", {}).get(lang, rule["compiled"])
        for start, window in windows:
            if lang == "sql" and rule["id"] in {"SQL-BYPASSRLS", "SQL-PUBLIC-GRANT", "SQL-SERVER-ROLE"}:
                base = line_offsets[start]
                window = "".join(" " if noncode[base + pos] and char not in "\r\n" else char
                                 for pos, char in enumerate(window))
            for match in pattern.finditer(window):
                absolute = line_offsets[start] + match.start()
                if rule.get("code_only") and noncode[absolute]:
                    # Only flag uncertain lexical exclusions when they hide a
                    # candidate for these opt-in rules. This is not a general
                    # syntax validator for all legacy textual rules.
                    if lexical_issues and "lexical_unterminated" not in problems:
                        problems.append("lexical_unterminated")
                    continue
                if rule["id"] == "PHP-SHELL" and re.search(r"(?:->|::)\s*$", source[max(0, absolute - 128):absolute]):
                    # PDO::exec is SQL, not PHP's exec(). Receiver semantics
                    # for arbitrary user methods require manual review.
                    continue
                line = start + window.count("\n", 0, match.start()) + 1
                if rule["id"] == "CFG-REDIS-ACL":
                    physical_start = source.rfind("\n", 0, absolute) + 1
                    physical_end = source.find("\n", absolute)
                    if physical_end < 0:
                        physical_end = len(source)
                    physical_line = source[physical_start:physical_end].rstrip("\r")
                    if not redis_acl_passwordless(physical_line):
                        continue
                hits.add((rule["id"], line))
    return sorted(hits, key=lambda h: (h[1], h[0])), problems


def secret_file(name):
    return ((name == ".env" or name.startswith(".env.")) and name != ".env.example"
            or name.endswith((".pem", ".key", ".p12", ".pfx")))


def canonical_scan_root(path):
    """Resolve ancestor links while retaining a no-symlink file boundary.

    macOS exposes ordinary locations such as /tmp through a symlinked ancestor.
    Resolve only ancestors so a leaf swap cannot be followed by canonicalization.
    The final entry supplied as the root must never itself be a symlink.
    """
    requested = Path(os.path.abspath(path))
    metadata = requested.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("root leaf is a symlink")
    # Path.resolve() calls a privileged handle API on Windows and can fail for
    # otherwise readable files in managed environments.  Windows does not need
    # the macOS ancestor canonicalization this branch exists to support.
    canonical = requested if os.name == "nt" else requested.parent.resolve(strict=True) / requested.name
    canonical_metadata = canonical.lstat()
    if stat.S_ISLNK(canonical_metadata.st_mode):
        raise ValueError("root leaf is a symlink")
    if ((metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)) !=
            (canonical_metadata.st_dev, canonical_metadata.st_ino,
             stat.S_IFMT(canonical_metadata.st_mode))):
        raise ValueError("root changed during canonicalization")
    return canonical


def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, getattr(metadata, "st_ctime_ns", 0))


def read_regular(path, limit):
    # Prevent leaf symlink swaps and FIFO hangs. Parents should be quiescent:
    # this is a local snapshot reader, not an OS sandbox for racing attackers.
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):
            raise ValueError("not_regular")
        if meta.st_size > limit:
            raise ValueError("file_too_large")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)
        after = os.fstat(fd)
        if len(content) > limit:
            raise ValueError("file_too_large")
        if file_identity(meta) != file_identity(after) or len(content) != meta.st_size:
            raise ValueError("file_changed_during_read")
        if b"\x00" in content:
            raise ValueError("binary_file")
        if path.suffix.lower() == ".py":
            encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
            return content.decode(encoding)
        return content.decode("utf-8-sig")
    finally:
        os.close(fd)


def scan(root, rules, *, exclude=(), max_bytes=1048576, max_files=20000, max_findings=10000, context=None):
    context = validate_context(context)
    root = canonical_scan_root(root)
    if not root.exists() or not (root.is_dir() or root.is_file()):
        raise ValueError("root must be an existing regular file or directory")
    exclude = tuple(sorted(set(exclude)))
    by_id = {r["id"]: r for r in rules}
    report = {"tool": "DurkaHelper defense_scan", "version": VERSION, "offline": True,
              "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
              "scope": scan_scope(root, rules, exclude, max_bytes, max_files, max_findings, context),
              "findings": [], "issues": [], "skipped": {}, "files_scanned": 0,
              "entries_seen": 0, "partial": False}
    skipped = Counter()

    def problem(path, reason):
        report["issues"].append({"path": str(path), "reason": reason})
        report["partial"] = True

    def paths():
        if root.is_file():
            yield root, root.name
            return
        stack = [root]
        while stack:
            directory = stack.pop()
            try:
                # Bound enumeration even when a directory has millions of entries.
                entries = []
                with os.scandir(directory) as items:
                    for entry in items:
                        report["entries_seen"] += 1
                        if report["entries_seen"] > max_files * 10:
                            problem(".", "entry_limit_reached")
                            return
                        entries.append(entry)
                for entry in sorted(entries, key=lambda e: e.name):
                    path = Path(entry.path)
                    rel = path.relative_to(root).as_posix()
                    if any(fnmatch.fnmatchcase(rel, pattern) for pattern in exclude):
                        skipped["user_excluded"] += 1
                    elif entry.is_symlink():
                        skipped["symlink"] += 1
                        problem(rel, "symlink")
                    elif entry.is_dir(follow_symlinks=False):
                        if entry.name in SKIP_DIRS:
                            skipped["excluded_directory"] += 1
                        else:
                            stack.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        yield path, rel
                    else:
                        skipped["non_regular"] += 1
                        problem(rel, "non_regular")
            except OSError:
                problem(directory.relative_to(root).as_posix(), "directory_unreadable")

    for path, rel in paths():
        if secret_file(path.name.lower()):
            skipped["secret_filename"] += 1
            continue
        lang = language(path)
        if not lang:
            skipped["unsupported_type"] += 1
            continue
        if report["files_scanned"] >= max_files:
            problem(rel, "file_limit_reached")
            break
        report["files_scanned"] += 1
        try:
            source = read_regular(path, max_bytes)
        except (OSError, ValueError, UnicodeError, SyntaxError, LookupError) as exc:
            reason = str(exc) if type(exc) is ValueError and str(exc) in {
                "not_regular", "file_too_large", "file_changed_during_read", "binary_file"
            } else "read_or_encoding_failed"
            problem(rel, reason)
            continue
        hits, issues = scan_text(source, lang, rules)
        for issue in issues:
            problem(rel, issue)
        for rule_id, line in hits:
            if len(report["findings"]) >= max_findings:
                problem(rel, "finding_limit_reached")
                break
            rule = by_id[rule_id]
            report["findings"].append({"path": rel, "line": line, "rule": rule_id,
                "title": rule["title"], "confidence": "review", "reason": rule["reason"],
                "fix": rule["fix"], "patch_example": {"before": rule["before"], "after": rule["after"]},
                "check": rule["check"], "doc": rule["doc"], "engine": rule["engine"],
                "detection": rule.get("detection", "Syntactic signal; review context using the linked reference."),
                **review_metadata(rule, context)})
        if report["issues"] and report["issues"][-1]["reason"] == "finding_limit_reached":
            break
    if not report["files_scanned"]:
        problem(".", "no_supported_files_scanned")
    report["findings"].sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    report["skipped"] = dict(sorted(skipped.items()))
    report["exit_code"] = 2 if report["partial"] else 1 if report["findings"] else 0
    return report


def terminal(value):
    # Escape filenames/control characters instead of interpreting terminal escapes.
    return json.dumps(str(value), ensure_ascii=True)[1:-1] if not str(value).isprintable() else str(value)


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def configure_text_output():
    """Keep CLI diagnostics printable on legacy Windows code pages."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (AttributeError, OSError, ValueError):
                pass


def main(argv=None):
    configure_text_output()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", help="local source directory or file")
    parser.add_argument("--json", action="store_true", help="JSON report to stdout, including patch templates")
    parser.add_argument("--patches", action="store_true", help="show before/after templates in text output")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--explain", metavar="RULE_ID")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="relative path glob; repeatable")
    parser.add_argument("--context", metavar="CONTEXT.json", help="non-secret infrastructure context; never disables rules")
    parser.add_argument("--max-bytes", type=positive, default=1048576)
    parser.add_argument("--max-files", type=positive, default=20000)
    parser.add_argument("--max-findings", type=positive, default=10000)
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    try:
        rules = load_rules()
        if args.list_rules:
            for rule in rules:
                print(rule["id"], "|", ",".join(rule["languages"]), "|", rule["title"])
            return 0
        if args.explain:
            rule = next((r for r in rules if r["id"] == args.explain), None)
            if rule is None:
                parser.error("unknown rule ID")
            print(json.dumps({k: v for k, v in rule.items()
                              if k not in {"compiled", "compiled_languages", "pattern", "language_patterns"}},
                             ensure_ascii=False, indent=2))
            return 0
        if not args.root:
            parser.error("provide a root, --list-rules, or --explain")
        report = scan(args.root, rules, exclude=args.exclude, max_bytes=args.max_bytes,
                      max_files=args.max_files, max_findings=args.max_findings,
                      context=load_context(args.context) if args.context else None)
    except (OSError, ValueError, KeyError, re.error, RecursionError, MemoryError) as exc:
        error = {"error": "invalid input or rule pack", "type": type(exc).__name__, "exit_code": 2}
        print(json.dumps(error) if args.json else "ERROR: invalid input or rule pack (" + type(exc).__name__ + ")")
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        for finding in report["findings"]:
            print(f"{terminal(finding['path'])}:{finding['line']} [{finding['rule']}] {finding['title']}")
            print("  Why review:", finding["reason"])
            print("  Remediation:", finding["fix"])
            print("  Verify:", finding["check"])
            print("  Reference:", finding["doc"])
            print("  Review priority:", finding["review_priority"], "|", finding["signal_kind"])
            for note in finding["context_notes"]:
                print("  Context:", note)
            if args.patches:
                print("  Before example:\n" + finding["patch_example"]["before"])
                print("  After example:\n" + finding["patch_example"]["after"])
        for issue in report["issues"]:
            print("ISSUE:", terminal(issue["path"]), issue["reason"])
        print(f"Scanned: {report['files_scanned']}; findings: {len(report['findings'])}; partial: {report['partial']}; skipped: {report['skipped']}")
        print("Signals require review; zero findings is not a security verdict. Offline templates: --explain RULE_ID / --patches.")
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
