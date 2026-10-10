"""Offline scanner tests; no vulnerable fixture is executed."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "defense_scan.py"
spec = importlib.util.spec_from_file_location("defense_scan_under_test", SCRIPT)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ScannerTests(unittest.TestCase):
    def test_acl_and_cnf_configs_are_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "users.acl").write_text("user default on nopass ~* &* +@all")
            (root / "app.cnf").write_text("display_errors = On")
            report = scanner.scan(root, scanner.load_rules())
            self.assertEqual(report["files_scanned"], 2)
            self.assertEqual(report["issues"], [])
            self.assertTrue({"CFG-REDIS-ACL", "PHP-DISPLAY-ERRORS"} <=
                            {f["rule"] for f in report["findings"]})

    def test_new_patterns_keep_legitimate_context_visible(self):
        self.assertNotIn("PHP-LOOSE-COMPARE",
                         self.ids("$ok = $token === $provided;", "php"))
        self.assertNotIn("SQL-BYPASSRLS",
                         self.ids("ALTER ROLE app NOBYPASSRLS NOSUPERUSER;", "sql"))
        self.assertIn("CS-IGNORE-FILTERS",
                      self.ids("db.Notes.IgnoreQueryFilters().Where(n => n.OwnerId == uid)", "csharp"))
        self.assertIn("JAVA-XML",
                      self.ids("var f = DocumentBuilderFactory.newInstance();", "java"))

    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def ids(self, text, lang="python"):
        hits, issues = scanner.scan_text(text, lang, self.rules)
        self.assertEqual(issues, [])
        return {rid for rid, _ in hits}

    def test_all_rule_positive_examples(self):
        for rule in self.rules:
            with self.subTest(rule=rule["id"]):
                self.assertNotIn("\x00", rule["before"] + rule["after"])
                self.assertIn(rule["id"], self.ids(rule["before"], rule["languages"][0]))

    def test_numpy_pickle_opt_in_variants(self):
        examples = [
            "import numpy as np\nnp.load(path, allow_pickle=True)",
            "from numpy import load as read\nread(path, None, True)",
            "from numpy.lib.format import read_array as read\nread(stream, True)",
            "import numpy.lib.format as fmt\nallow = True\nfmt.read_array(stream, allow_pickle=allow)",
            "import numpy\nnumpy.load(\n    path,\n    **{'allow_pickle': True},\n)",
            "from numpy import load\nload(path, **{'allow_pickle': False, **{'allow_pickle': True}})",
        ]
        for code in examples:
            with self.subTest(code=code):
                self.assertIn("PY-DESERIALIZE", self.ids(code))

    def test_numpy_pickle_disabled_and_unresolved_cases(self):
        examples = [
            "import numpy as np\nnp.load(path)",
            "import numpy as np\nnp.load(path, None, False)",
            "import numpy as np\nnp.load(path, allow_pickle=False)",
            "import numpy.lib.format as fmt\nfmt.read_array(stream, False)",
            "import numpy as np\nnp.load(path, **{'allow_pickle': True, **{'allow_pickle': False}})",
            "import numpy as np\nnp.load(path, **{'allow_pickle': True, **options})",
            "import numpy as np\nnp.load(path, *modes, True)",
            "import numpy as np\nnp.load(path, allow_pickle=runtime_setting)",
            "import numpy as np\nnp = safe_reader\nnp.load(path, allow_pickle=True)",
            "custom.load(path, allow_pickle=True)",
        ]
        for code in examples:
            with self.subTest(code=code):
                self.assertNotIn("PY-DESERIALIZE", self.ids(code))

    def test_lxml_entity_resolution_alternate_apis(self):
        examples = [
            "from lxml import etree as xml\nxml.XMLPullParser(resolve_entities=True)",
            "from lxml.etree import ETCompatXMLParser as Parser\nParser(resolve_entities=True)",
            "import lxml.etree\nresolve = True\nlxml.etree.iterparse(stream, resolve_entities=resolve)",
            "from lxml.etree import iterparse as parse\nparse(\n    stream,\n    **{'resolve_entities': True},\n)",
        ]
        for code in examples:
            with self.subTest(code=code):
                self.assertIn("PY-XML", self.ids(code))
        for code in [
            "from lxml import etree\netree.iterparse(stream, resolve_entities=False)",
            "from lxml import etree\netree.XMLPullParser(resolve_entities='internal')",
            "from lxml import etree\netree.ETCompatXMLParser()",
            "from xml.etree.ElementTree import iterparse\niterparse(stream)",
            "custom.iterparse(stream, resolve_entities=True)",
            "custom.XMLPullParser(resolve_entities=True)",
        ]:
            with self.subTest(code=code):
                self.assertNotIn("PY-XML", self.ids(code))

    def test_yaml_base_loaders_do_not_construct_python_objects(self):
        for loader in ("BaseLoader", "CBaseLoader", "SafeLoader", "CSafeLoader"):
            for code in [
                f"import yaml as y\ny.load(data, Loader=y.{loader})",
                f"from yaml import load_all as read, {loader} as Loader\nread(data, Loader)",
                f"import yaml\nyaml.load(data, **{{'Loader': yaml.{loader}}})",
            ]:
                with self.subTest(code=code):
                    self.assertNotIn("PY-YAML", self.ids(code))

    def test_data_loader_findings_have_stable_locations_and_documentation(self):
        # Authored after the implementation: verify report metadata on a real
        # inert file, not just the detector's in-memory ID set.
        source = ("import numpy as np\nfrom lxml import etree\nimport yaml\n"
                  "np.load(path, allow_pickle=True)\n"
                  "etree.iterparse(stream, resolve_entities=True)\n"
                  "yaml.load(data, Loader=yaml.BaseLoader)\n")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "loaders.py"
            path.write_text(source, encoding="utf-8")
            report = scanner.scan(path, self.rules)
        self.assertFalse(report["partial"])
        findings = {finding["rule"]: finding for finding in report["findings"]}
        self.assertEqual(set(findings), {"PY-DESERIALIZE", "PY-XML"})
        for rid, line, anchor in (("PY-DESERIALIZE", 4, "py-deserialize"),
                                  ("PY-XML", 5, "py-xml")):
            self.assertEqual((findings[rid]["path"], findings[rid]["line"]), ("loaders.py", line))
            self.assertEqual(findings[rid]["doc"], f"docs/vulnerabilities/python.md#{anchor}")
            self.assertEqual(findings[rid]["confidence"], "review")
            self.assertTrue(findings[rid]["reason"] and findings[rid]["detection"])

    def test_data_loader_local_rebinding_does_not_leave_stale_signals(self):
        for code, rid in [
            ("import numpy as np\ndef read(np):\n    np.load(path, allow_pickle=True)", "PY-DESERIALIZE"),
            ("import numpy as np\nflag=True\nflag=False\nnp.load(path, None, flag)", "PY-DESERIALIZE"),
            ("from lxml.etree import XMLPullParser as Parser\nParser=safe_parser\nParser(resolve_entities=True)", "PY-XML"),
            ("from lxml import etree\nflag=True\nflag=False\netree.iterparse(stream, resolve_entities=flag)", "PY-XML"),
        ]:
            with self.subTest(code=code):
                self.assertNotIn(rid, self.ids(code))

    def test_shell_helper_and_explicit_interpreter_forms(self):
        examples = [
            "from subprocess import getoutput as capture\ncapture(command)",
            "import subprocess as sp\nsp.getstatusoutput(command)",
            "import asyncio as aio\nawait aio.create_subprocess_shell(command)",
            "import subprocess\nsubprocess.run(['/bin/sh', '-c', command], shell=False)",
            "import subprocess\nsubprocess.run(args=['bash', '-lc', command])",
            "import subprocess\nsubprocess.Popen(['cmd.exe', '/c', command])",
        ]
        for code in examples:
            with self.subTest(code=code):
                self.assertIn("PY-SHELL", self.ids(code))
        self.assertNotIn("PY-SHELL", self.ids("import subprocess\nsubprocess.run(['file', '--', name], shell=False)"))

    def test_scalar_assignment_reaches_sql_and_security_flags(self):
        self.assertIn("PY-SQL", self.ids("query = f'SELECT {column}'\ncopy = query\ndb.execute(copy)"))
        self.assertIn("PY-SQL", self.ids("def f(name):\n    query: str = 'SELECT '+name\n    db.execute(query)"))
        self.assertIn("PY-TLS", self.ids("import requests\nverify_peer = False\nrequests.get('https://example.invalid', verify=verify_peer)"))
        self.assertIn("PY-SHELL", self.ids("import subprocess\nuse_shell = True\nsubprocess.run(command, shell=use_shell)"))
        self.assertNotIn("PY-SQL", self.ids("query = 'SELECT * FROM notes WHERE id=?'\ndb.execute(query, (uid,))"))

    def test_scalar_assignment_kills_stale_facts(self):
        examples = [
            "query = f'SELECT {name}'\nquery = 'SELECT 1'\ndb.execute(query)",
            "query = f'SELECT {name}'\nquery = build_safe_query()\ndb.execute(query)",
            "query = f'SELECT {name}'\nquery, count = safe_result\ndb.execute(query)",
            "query = f'SELECT {name}'\nquery += suffix\ndb.execute(query)",
            "query = f'SELECT {name}'\ndel query\ndb.execute(query)",
        ]
        for code in examples:
            with self.subTest(code=code):
                self.assertNotIn("PY-SQL", self.ids(code))

    def test_scalar_facts_do_not_cross_control_flow_or_scope(self):
        examples = [
            "query = f'SELECT {name}'\nif condition:\n    query = 'SELECT 1'\ndb.execute(query)",
            "if condition:\n    query = f'SELECT {name}'\nelse:\n    query = 'SELECT 1'\ndb.execute(query)",
            "query = f'SELECT {name}'\nfor query in safe_queries:\n    db.execute(query)",
            "query = f'SELECT {name}'\ndef f(query):\n    db.execute(query)",
            "def f():\n    query = f'SELECT {name}'\ndef g():\n    db.execute(query)",
            "query = f'SELECT {name}'\nresult = [db.execute(query) for query in safe_queries]",
        ]
        for code in examples:
            with self.subTest(code=code):
                self.assertNotIn("PY-SQL", self.ids(code))
        self.assertIn("PY-SQL", self.ids("if condition:\n    query = f'SELECT {name}'\n    db.execute(query)"))

    def test_import_rebinding_and_lambda_parameters(self):
        for code in [
            "import pickle as p\np = safe_loader\np.loads(data)",
            "import pickle\ndef f(pickle):\n    pickle.loads(data)",
            "import pickle\nf = lambda pickle: pickle.loads(data)",
            "import pickle\nif condition:\n    pickle = safe_loader\npickle.loads(data)",
        ]:
            with self.subTest(code=code):
                self.assertNotIn("PY-DESERIALIZE", self.ids(code))
        self.assertIn("PY-DESERIALIZE", self.ids("import pickle as p\ndef f():\n    p.loads(data)"))

    def test_no_mutable_container_propagation_claim(self):
        # Arbitrary mutation is not modelled; a dict variable is intentionally
        # outside coverage instead of being treated as a frozen snapshot.
        self.assertNotIn("PY-JWT", self.ids("import jwt\noptions = {'verify_signature': False}\noptions['verify_signature'] = True\njwt.decode(token, key, options=options)"))

    def test_requests_method_first_and_literal_url(self):
        self.assertIn("PY-URL", self.ids("import requests as r\nr.request('GET', user_url)"))
        self.assertIn("PY-URL", self.ids("from httpx import request as send\nsend(method='POST', url=target)"))
        self.assertIn("PY-URL", self.ids("import requests\nrequests.head(target)"))
        self.assertNotIn("PY-URL", self.ids("import requests\nrequests.request(method, 'https://example.invalid')"))
        self.assertNotIn("PY-URL", self.ids("import requests\nurl = 'https://example.invalid'\nrequests.get(url)"))

    def test_python_jwt_variants_and_claims(self):
        self.assertIn("PY-JWT", self.ids("from jwt import decode_complete as decode\ndecode(token, options={'verify_signature': False})"))
        self.assertIn("PY-JWT", self.ids("from jose import jwt\njwt.decode(token, key, options={'verify_signature': False})"))
        self.assertIn("PY-JWT-ALGORITHMS", self.ids("import jwt\njwt.decode(token, key, algorithms=allowed_from_config)"))
        self.assertIn("PY-JWT-CLAIMS", self.ids("import jwt\njwt.decode_complete(token, key, options={'verify_aud': False})"))
        self.assertNotIn("PY-JWT-ALGORITHMS", self.ids("import jwt\njwt.decode(token, key, algorithms=('RS256',))"))
        self.assertNotIn("PY-JWT-CLAIMS", self.ids("import jwt\njwt.decode(token, key, options={'verify_exp': True})"))

    def test_python_csrf_ssl_and_mass_assignment_aliases(self):
        self.assertIn("PY-CSRF-EXEMPT", self.ids("from django.views.decorators.csrf import csrf_exempt as exempt\n@exempt\ndef view(request):\n    pass"))
        self.assertNotIn("PY-CSRF-EXEMPT", self.ids("# @csrf_exempt\nlabel = 'csrf_exempt(view)'"))
        self.assertIn("PY-SSL-CONTEXT", self.ids("import ssl as tls\nctx.verify_mode = tls.CERT_NONE"))
        self.assertNotIn("PY-SSL-CONTEXT", self.ids("import ssl\nctx.verify_mode = ssl.CERT_REQUIRED\nctx.check_hostname = True"))
        self.assertIn("PY-MASS-ASSIGN", self.ids("setattr(user, key, value)"))
        self.assertNotIn("PY-MASS-ASSIGN", self.ids("setattr(user, 'display_name', name)"))

    def test_config_json_quotes_and_multiline_forms(self):
        examples = [
            ('{"hostPID": true}', "CFG-K8S-HOST"),
            ('{"allowPrivilegeEscalation":\n true}', "CFG-PRIV-ESCALATION"),
            ('{"ValidateLifetime": false}', "CS-JWT-VALIDATION"),
            ('MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE="*"', "CFG-ACTUATOR"),
            ('SPRING_H2_CONSOLE_ENABLED=true', "CFG-H2-CONSOLE"),
            ('network_mode: "host"', "CFG-K8S-HOST"),
            ('security_opt: ["seccomp=unconfined"]', "CFG-UNCONFINED"),
        ]
        for source, rid in examples:
            with self.subTest(rule=rid):
                self.assertIn(rid, self.ids(source, "config"))

    def test_regex_fixed_forms_avoid_explicit_false_positives(self):
        examples = [
            ("CS-JWT-VALIDATION", "ValidateIssuerSigningKey = false;", "csharp"),
            ("CS-TLS-VALIDATION", "handler.ServerCertificateCustomValidationCallback = VerifyPeer;", "csharp"),
            ("JS-JWT-OPTIONS", "const options = {ignoreExpiration: false};", "javascript"),
            ("JS-HTTP-PARSER", "const options = {insecureHTTPParser: false};", "javascript"),
            ("PHP-CURL-TLS", "curl_setopt($c, CURLOPT_SSL_VERIFYHOST, 2);", "php"),
            ("PHP-EXTRACT", "$value = extract_field($data);", "php"),
            ("CFG-SSH-EMPTY-PASSWORD", "# PermitEmptyPasswords yes", "config"),
            ("CFG-PRIV-ESCALATION", "allowPrivilegeEscalation: false", "config"),
            ("CFG-K8S-RBAC", "name: cluster-admin-readonly", "config"),
            ("SQL-SQLITE-FK", "PRAGMA foreign_keys = ON;", "sql"),
            ("GO-TLS-MIN", "MinVersion: tls.VersionTLS13", "go"),
            ("RUST-TLS", ".danger_accept_invalid_certs(false)", "rust"),
        ]
        for rid, source, lang in examples:
            with self.subTest(rule=rid):
                self.assertNotIn(rid, self.ids(source, lang))

    def test_ruby_rust_php_and_jwt_alternate_forms(self):
        examples = [
            ("RUBY-CSRF", "skip_before_filter(:verify_authenticity_token)", "ruby"),
            ("RUST-COMMAND", 'std::process::Command::new("/bin/bash")\n.arg("-c").arg(text)', "rust"),
            ("PHP-CURL-TLS", "curl_setopt_array($h, [CURLOPT_SSL_VERIFYPEER => 0]);", "php"),
            ("PHP-XML-FLAGS", "$reader->substituteEntities = true;", "php"),
            ("JAVA-SPRING-CSRF", "http.csrf(AbstractHttpConfigurer::disable);", "java"),
            ("JAVA-SPRING-CSRF", "http.csrf().disable();", "java"),
            ("JS-JWT-DECODE", "const claims = decodeJwt(raw);", "javascript"),
            ("GO-JWT-UNVERIFIED", "jwt.NewParser(jwt.WithoutClaimsValidation())", "go"),
            ("SQL-SQLITE-FK", "PRAGMA foreign_keys(0);", "sql"),
        ]
        for rid, source, lang in examples:
            with self.subTest(rule=rid):
                self.assertIn(rid, self.ids(source, lang))

    def test_runtime_config_names_are_in_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, source in {
                "sshd_config": "PermitEmptyPasswords yes",
                "sudoers": "app ALL=(ALL) NOPASSWD: ALL",
                "web.config": "ValidateLifetime = false",
                "app.service": 'Environment="NODE_OPTIONS=--insecure-http-parser"',
                ".htaccess": "# static web root settings",
                "View.cshtml": "@Html.Raw(Model.About)",
            }.items():
                (root / name).write_text(source)
            report = scanner.scan(root, self.rules)
            self.assertEqual(report["files_scanned"], 6)
            self.assertFalse(report["partial"])
            self.assertTrue({"CFG-SSH-EMPTY-PASSWORD", "CFG-SUDO-ALL", "CS-JWT-VALIDATION",
                             "JS-HTTP-PARSER", "CS-HTML-RAW"}
                            <= {f["rule"] for f in report["findings"]})

    def test_fixed_examples_and_contextual_signals(self):
        # A validated dynamic send_file remains a signal: no taint analysis.
        for rule in self.rules:
            with self.subTest(rule=rule["id"]):
                ids = self.ids(rule["after"], rule["languages"][0])
                if rule.get("review_after"):
                    self.assertIn(rule["id"], ids)
                else:
                    self.assertNotIn(rule["id"], ids)

    def test_ast_ignores_comments_and_string_literals(self):
        self.assertEqual(self.ids('# eval(payload)\nnote = "pickle.loads(payload)"'), set())

    def test_python_import_aliases(self):
        self.assertIn("PY-SHELL", self.ids("from os import system as run\nrun(command)"))
        self.assertIn("PY-DESERIALIZE", self.ids("import pickle as p\np.loads(blob)"))
        self.assertIn("PY-YAML", self.ids("from yaml import load as parse\nparse(blob)"))
        self.assertIn("PY-JWT", self.ids("from jwt import decode as decode_token\ndecode_token(token, verify=False)"))
        self.assertNotIn("PY-DESERIALIZE", self.ids("import pickle\ndef f(pickle):\n    pickle.load(data)"))

    def test_safe_python_calls(self):
        code = """import yaml as y
from yaml import SafeLoader as Safe
import subprocess as sp
import jwt
import requests
db.execute('SELECT * FROM notes WHERE id=?', (note_id,))
User.find(User.name == name, User.password == password)
y.load(data, Loader=Safe)
y.load(data, y.CSafeLoader)
sp.run(['/bin/echo', text], shell=False)
jwt.decode(token, key, algorithms=['HS256'])
requests.get('https://example.invalid', verify=True)
"""
        self.assertEqual(self.ids(code), set())

    def test_multiline_ast_and_sql_variants(self):
        for query in ("f'SELECT {name}'", "'SELECT '+name", "'SELECT {}'.format(name)"):
            with self.subTest(query=query):
                self.assertIn("PY-SQL", self.ids("db.execute(\n" + query + "\n)"))
        self.assertIn("PY-ORM-BOOL", self.ids("User.find(\nUser.name == name\nor User.password == password\n)"))

    def test_multiline_regex_and_overlap_deduplication(self):
        code = "\n" * 6 + "db.query(\n\"SELECT id FROM notes WHERE name=\" + name\n);"
        hits, issues = scanner.scan_text(code, "javascript", self.rules)
        self.assertEqual(issues, [])
        self.assertEqual([h for h in hits if h[0] == "JS-SQL"], [("JS-SQL", 7)])
        self.assertIn("JS-SQL", self.ids("db.query(" + chr(96) + "SELECT " + "$" + "{name}" + chr(96) + ")", "javascript"))

    def test_go_sum_safe_and_unsafe(self):
        self.assertIn("GO-HASH-SUM", self.ids("h.Sum(data)", "go"))
        self.assertNotIn("GO-HASH-SUM", self.ids("h.Sum(nil)", "go"))
        # h.Sum(buf[:0]) can be a legitimate optimization; intentionally flagged.
        self.assertIn("GO-HASH-SUM", self.ids("h.Sum(buf[:0])", "go"))

    def test_secret_key_annotation_and_no_default(self):
        self.assertIn("CFG-SECRET", self.ids("class Settings:\n    jwt_key: str = 'secret'"))
        self.assertNotIn("CFG-SECRET", self.ids("jwt_key = os.environ['JWT_KEY']"))

    def test_yaml_tls_config_multiline(self):
        self.assertIn("CFG-DOCKER-PRIV", self.ids("privileged:\n  true", "config"))
        self.assertIn("JS-TLS", self.ids("rejectUnauthorized:\n false", "javascript"))

    def test_read_only_offline_and_no_secret_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "executed"
            source = root / "app.py"
            payload = "JWT_SECRET = 'DO_NOT_LEAK_123'\n" + f"open({str(marker)!r}, 'w').write('executed')\n"
            source.write_text(payload)
            before = source.read_bytes()
            with patch.object(socket, "socket", side_effect=AssertionError("network")), \
                 patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")), \
                 patch.object(urllib.request, "urlopen", side_effect=AssertionError("HTTP")):
                # Include rule loading; neither path needs an online service.
                report = scanner.scan(root, scanner.load_rules())
            self.assertEqual(report["exit_code"], 1)
            self.assertFalse(marker.exists())
            self.assertEqual(source.read_bytes(), before)
            serialized = json.dumps(report)
            self.assertNotIn("DO_NOT_LEAK_123", serialized)
            self.assertNotIn("executed')", serialized)
            self.assertIn("patch_example", report["findings"][0])

    def test_json_does_not_leak_syntax_error_source(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "bad.py").write_text("UNKNOWN_SUPER_SECRET = (")
            report = scanner.scan(temp, self.rules)
            self.assertEqual(report["exit_code"], 2)
            self.assertNotIn("UNKNOWN_SUPER_SECRET", json.dumps(report))
            self.assertEqual(report["issues"][0]["reason"], "python_parse_failed:SyntaxError")

    def test_skips_symlinks_vendor_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "ok.py").write_text("value = 1")
            (root / ".env").write_text("JWT_SECRET='DONTREAD'")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "bad.js").write_text("eval(input)")
            try:
                (root / "link.py").symlink_to(root / "ok.py")
                (root / "dirlink").symlink_to(root, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlink creation is unavailable: {type(exc).__name__}")
            report = scanner.scan(root, self.rules)
            self.assertEqual(report["files_scanned"], 1)
            self.assertEqual(report["skipped"]["symlink"], 2)
            self.assertEqual(report["skipped"]["secret_filename"], 1)
            self.assertEqual(report["skipped"]["excluded_directory"], 1)
            self.assertEqual(report["exit_code"], 2)
            self.assertTrue(report["partial"])
            self.assertEqual({(issue["path"], issue["reason"]) for issue in report["issues"]},
                             {("dirlink", "symlink"), ("link.py", "symlink")})
            excluded = scanner.scan(root, self.rules, exclude=["dirlink", "link.py"])
            self.assertEqual(excluded["exit_code"], 0)
            self.assertFalse(excluded["partial"])
            self.assertEqual(excluded["skipped"]["user_excluded"], 2)
            alias_report = scanner.scan(root / "dirlink" / "ok.py", self.rules)
            self.assertEqual(alias_report["files_scanned"], 1)
            self.assertEqual(alias_report["exit_code"], 0)
            with self.assertRaisesRegex(ValueError, "symlink"):
                scanner.scan(root / "link.py", self.rules)

    def test_target_cannot_supply_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "rules").mkdir()
            (root / "rules" / "defense.json").write_text('{"disable_all": true}')
            (root / "app.py").write_text("eval(input)")
            report = scanner.scan(root, self.rules)
            self.assertIn("PY-EVAL", {f["rule"] for f in report["findings"]})

    def test_limits_produce_partial_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.py").write_text("eval(x)\nexec(x)")
            (root / "b.py").write_text("eval(x)")
            for kwargs, reason in (({"max_files": 1}, "file_limit_reached"),
                                   ({"max_findings": 1}, "finding_limit_reached"),
                                   ({"max_bytes": 1}, "file_too_large")):
                with self.subTest(kwargs=kwargs):
                    report = scanner.scan(root, self.rules, **kwargs)
                    self.assertTrue(report["partial"])
                    self.assertEqual(report["exit_code"], 2)
                    self.assertIn(reason, {i["reason"] for i in report["issues"]})

    def test_directory_entry_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for n in range(11):
                (root / f"file{n}.txt").touch()
            report = scanner.scan(root, self.rules, max_files=1)
            self.assertIn("entry_limit_reached", {i["reason"] for i in report["issues"]})
            self.assertEqual(report["exit_code"], 2)

    def test_binary_invalid_encoding_and_read_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.py").write_bytes(b"\x00")
            (root / "b.js").write_bytes(b"\xff")
            report = scanner.scan(root, self.rules)
            self.assertEqual(report["exit_code"], 2)
            self.assertEqual(len(report["issues"]), 2)
            with patch.object(scanner, "read_regular", side_effect=PermissionError):
                report = scanner.scan(root, self.rules)
                self.assertEqual({i["reason"] for i in report["issues"]}, {"read_or_encoding_failed"})

    def test_file_change_during_read_is_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.py"
            path.write_text("value = 1", encoding="utf-8")
            before = path.stat()
            after = type("ChangedMetadata", (), {
                "st_dev": before.st_dev,
                "st_ino": before.st_ino,
                "st_mode": before.st_mode,
                "st_size": before.st_size,
                "st_mtime_ns": before.st_mtime_ns + 1,
                "st_ctime_ns": getattr(before, "st_ctime_ns", 0),
            })()
            with patch.object(scanner.os, "fstat", side_effect=[before, after]):
                report = scanner.scan(path, self.rules)
            self.assertEqual(report["exit_code"], 2)
            self.assertEqual(report["issues"], [{
                "path": "app.py", "reason": "file_changed_during_read"
            }])

    def test_python_encoding_cookie(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.py"
            path.write_bytes(b"# coding: latin-1\n# \xe9\neval(x)\n")
            self.assertEqual(scanner.scan(path, self.rules)["findings"][0]["line"], 3)

    def test_fifo_is_skipped(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("POSIX required")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os.mkfifo(root / "pipe.py")
            (root / "ok.py").write_text("value=1")
            report = scanner.scan(root, self.rules)
            self.assertEqual(report["skipped"]["non_regular"], 1)
            self.assertEqual(report["files_scanned"], 1)
            self.assertEqual(report["exit_code"], 2)
            self.assertEqual(report["issues"], [{"path": "pipe.py", "reason": "non_regular"}])
            excluded = scanner.scan(root, self.rules, exclude=["pipe.py"])
            self.assertEqual(excluded["exit_code"], 0)
            self.assertFalse(excluded["partial"])

    def test_empty_root_is_error(self):
        with tempfile.TemporaryDirectory() as temp:
            report = scanner.scan(temp, self.rules)
            self.assertEqual(report["exit_code"], 2)

    def test_user_exclusions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "unsafe.py").write_text("eval(x)")
            (root / "safe.py").write_text("x=1")
            report = scanner.scan(root, self.rules, exclude=["unsafe.py"])
            self.assertEqual(report["exit_code"], 0)
            self.assertEqual(report["skipped"]["user_excluded"], 1)

    def test_determinism(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "z.py").write_text("eval(x)")
            (root / "a.py").write_text("exec(x)\neval(x)")
            first = scanner.scan(root, self.rules)
            second = scanner.scan(root, self.rules)
            first_timestamp = first.pop("created_at")
            second_timestamp = second.pop("created_at")
            self.assertRegex(first_timestamp, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
            self.assertRegex(second_timestamp, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
            self.assertEqual(first, second)
            self.assertEqual([f["path"] for f in first["findings"]], ["a.py", "a.py", "z.py"])

    def test_scope_is_opaque_stable_and_covers_rules_exclusions_and_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text("value = 1", encoding="utf-8")
            report = scanner.scan(root, self.rules, exclude=["z/**", "a/**", "z/**"],
                                  max_bytes=2048, max_files=30, max_findings=40)
            scope = report["scope"]
            self.assertEqual(scope["schema"], "durkahelper.scanner-scope.v2")
            self.assertEqual(scope["path_semantics"], "root-relative-posix.v1")
            self.assertRegex(scope["root"], r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn(str(root), json.dumps(scope))
            self.assertRegex(scope["rules_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(scope["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(scope["exclude"], ["a/**", "z/**"])
            self.assertEqual(scope["limits"], {"max_bytes": 2048, "max_files": 30,
                                                "max_findings": 40})
            again = scanner.scan(root, list(reversed(self.rules)), exclude=["a/**", "z/**"],
                                 max_bytes=2048, max_files=30, max_findings=40)
            self.assertEqual(scope, again["scope"])
            changed_rules = [dict(rule) for rule in self.rules]
            changed_rules[0]["title"] += " changed"
            changed = scanner.scan(root, changed_rules, exclude=["a/**", "z/**"],
                                   max_bytes=2048, max_files=30, max_findings=40)
            self.assertNotEqual(scope["rules_sha256"], changed["scope"]["rules_sha256"])
            self.assertNotEqual(scope["sha256"], changed["scope"]["sha256"])

    def test_cli_output_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "a.py"
            for source, status in (("x=1", 0), ("eval(x)", 1), ("x=(", 2)):
                path.write_text(source)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    result = scanner.main([str(root), "--json"])
                report = json.loads(output.getvalue())
                self.assertEqual((result, report["exit_code"]), (status, status))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(scanner.main(["--explain", "PY-ORM-BOOL"]), 0)
            self.assertEqual(json.loads(output.getvalue())["id"], "PY-ORM-BOOL")
            path.write_text("eval(x)")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(scanner.main([str(root), "--patches"]), 1)
            self.assertIn("After example", output.getvalue())

    def test_control_characters_are_escaped(self):
        self.assertNotIn("\x1b", scanner.terminal("name\x1b[31m.py"))
        self.assertNotIn("\n", scanner.terminal("name\n.py"))
        self.assertNotIn("\u202e", scanner.terminal("name\u202e.py"))

    def test_unicode_signals_without_blanket_non_ascii_ban(self):
        self.assertIn("SRC-MIXED-IDENTIFIER", self.ids("uuіd = raw_value"))
        self.assertNotIn("SRC-MIXED-IDENTIFIER", self.ids("имя = 'обычная строка'"))
        self.assertNotIn("SRC-MIXED-IDENTIFIER", self.ids("cafe = 'café'"))
        self.assertIn("SRC-BIDI-CONTROL", self.ids("# comment \u202e hidden"))
        self.assertNotIn("SRC-BIDI-CONTROL", self.ids("# literal backslash-u202e"))

    def test_url_keyword_argument_gap(self):
        self.assertIn("PY-URL", self.ids("import requests\nrequests.post(url=server_url)"))
        self.assertIn("PY-URL", self.ids("from httpx import get as fetch\nfetch(url=user_url)"))
        self.assertNotIn("PY-URL", self.ids("import requests\nrequests.post(url='https://example.invalid')"))

    def test_assert_and_xpath_context(self):
        self.assertIn("PY-ASSERT-AUTH", self.ids("assert user.is_admin"))
        self.assertNotIn("PY-ASSERT-AUTH", self.ids("assert 2 + 2 == 4"))
        self.assertIn("PY-XPATH", self.ids("document.xpath(f'//item[@id={value}]')"))
        self.assertNotIn("PY-XPATH", self.ids("document.xpath('//item[@id=$id]', id=value)"))

    def test_new_file_types_reach_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.rb").write_text("Marshal.load(payload)")
            (root / "app.rs").write_text("let x = unsafe { std::str::from_utf8_unchecked(data) };")
            (root / "schema.sql").write_text("INSERT OR REPLACE INTO notes VALUES (?, ?);")
            report = scanner.scan(root, self.rules)
            self.assertEqual(report["files_scanned"], 3)
            self.assertFalse(report["partial"])
            self.assertTrue({"RUBY-OBJECT", "RUST-UNSAFE-CONVERSION", "SQL-UPSERT"}
                            <= {f["rule"] for f in report["findings"]})

    def test_go_shell_and_credential_input(self):
        self.assertIn("GO-SHELL", self.ids('exec.CommandContext(ctx, "/bin/sh", "-c", command)', "go"))
        self.assertNotIn("GO-SHELL", self.ids('exec.Command("/usr/bin/file", "--", filename)', "go"))
        self.assertIn("GO-MATH-RAND", self.ids('import rng "math/rand"', "go"))
        self.assertNotIn("GO-MATH-RAND", self.ids('import "crypto/rand"', "go"))

    def test_new_rule_safe_forms(self):
        examples = [
            ("C-SNPRINTF-FORMAT", 'snprintf(out, n, "%s", text);', "native"),
            ("C-RECV-TERMINATOR", "n = recv(fd, buf, nbytes, 0);\nprocess_bytes(buf, n);", "native"),
            ("PHP-PREFIX-MAC", "hash_hmac('sha256', $data, $key);", "php"),
            ("SQL-UPSERT", "INSERT INTO notes VALUES (?, ?);", "sql"),
            ("RUBY-OBJECT", "YAML.safe_load(payload, permitted_classes: [], aliases: false)", "ruby"),
            ("RUBY-SHELL", 'system("/usr/bin/file", "--", name)', "ruby"),
            ("RUST-SQL-FORMAT", 'sqlx::query("SELECT * FROM notes WHERE id=$1").bind(id)', "rust"),
        ]
        for rule, source, lang in examples:
            with self.subTest(rule=rule):
                self.assertNotIn(rule, self.ids(source, lang))


if __name__ == "__main__":
    unittest.main()
