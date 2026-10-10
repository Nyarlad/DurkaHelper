"""HTTP client syntax regressions. No client or target code is executed."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("http_scanner", ROOT / "scripts/defense_scan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class HttpClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scanner.load_rules()

    def ids(self, source):
        hits, issues = scanner.scan_text(source, "python", self.rules)
        self.assertEqual(issues, [])
        return {rid for rid, _ in hits}

    def test_client_context_url_and_send(self):
        for source in [
            "import requests as r\nwith r.Session() as client:\n    client.get(user_url)",
            "from requests.sessions import Session as Client\nwith Client() as client:\n    client.request('GET', user_url)",
            "import requests\nwith requests.session() as client:\n    client.request(method='GET', url=user_url)",
            "from httpx import Client as HttpClient\nwith HttpClient() as client:\n    client.post(user_url)",
            "import httpx as h\nasync with h.AsyncClient() as client:\n    await client.get(user_url)",
        ]:
            with self.subTest(source=source):
                self.assertIn("PY-URL", self.ids(source))
        self.assertIn("PY-TLS", self.ids(
            "import requests\nwith requests.Session() as client:\n    client.send(prepared, verify=False)"))

    def test_lowercase_session_factories(self):
        for source in [
            "from requests import session as make_client\nclient = make_client()\nclient.get(user_url)",
            "import requests\nrequests.session().get(user_url)",
            "import requests.sessions as sessions\nclient = sessions.session()\nclient.head(user_url)",
            "from requests.sessions import session as make_client\nwith make_client() as client:\n    client.options(user_url)",
        ]:
            with self.subTest(source=source):
                self.assertIn("PY-URL", self.ids(source))

    def test_httpx_stream_url_is_second_argument(self):
        for source in [
            "import httpx\nhttpx.stream('GET', user_url)",
            "from httpx import stream as stream_request\nstream_request(method='GET', url=user_url)",
            "import httpx as h\nclient = h.Client()\nclient.stream('GET', user_url)",
            "import httpx as h\nwith h.Client() as client:\n    with client.stream('GET', user_url) as response:\n        pass",
            "import httpx as h\nasync with h.AsyncClient() as client:\n    async with client.stream(method='GET', url=user_url) as response:\n        pass",
            "import httpx\nhttpx.AsyncClient().stream('GET', user_url)",
        ]:
            with self.subTest(source=source):
                self.assertIn("PY-URL", self.ids(source))
        self.assertIn("PY-TLS", self.ids("import httpx\nhttpx.stream('GET', 'https://example.invalid', verify=False)"))
        self.assertIn("PY-TLS", self.ids("import httpx\nhttpx.Client(verify=False).stream('GET', 'https://example.invalid')"))

    def test_static_urls_unrelated_streams_and_incorrect_context_kinds(self):
        for source in [
            "import httpx\nhttpx.stream(user_method, 'https://example.invalid')",
            "import httpx\nhttpx.stream(method='GET', url='https://example.invalid')",
            "import httpx\nwith httpx.Client() as client:\n    client.stream('GET', 'https://example.invalid')",
            "arbitrary.stream('GET', user_url)",
            "import requests\nrequests.stream('GET', user_url)",
            "import requests\nasync with requests.Session() as client:\n    await client.get(user_url)",
            "import httpx\nwith httpx.AsyncClient() as client:\n    client.get(user_url)",
            "import httpx\nasync with httpx.Client() as client:\n    await client.get(user_url)",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("PY-URL", self.ids(source))

    def test_context_alias_scope_rebinding_and_multiple_items(self):
        self.assertIn("PY-URL", self.ids(
            "import requests, httpx\nwith requests.Session() as first, httpx.Client() as second:\n"
            "    with second.stream('GET', user_url) as response:\n        first.get(user_url)"))
        for source in [
            "import httpx\nwith httpx.Client() as client:\n    client = custom\n    client.stream('GET', user_url)",
            "import httpx\nwith httpx.Client() as client:\n    pass\nclient.get(user_url)",
            "import httpx\nasync with httpx.AsyncClient() as client:\n    pass\nclient.get(user_url)",
            "import httpx\nwith httpx.Client() as client, other() as client:\n    client.get(user_url)",
            "import requests\nclient = requests.session()\nclient = custom\nclient.stream('GET', user_url)",
            "import httpx\nhttpx.stream(*unknown, user_url)",
        ]:
            with self.subTest(source=source):
                self.assertNotIn("PY-URL", self.ids(source))

    def test_context_clients_and_scalar_facts_after_implementation(self):
        self.assertIn("PY-URL", self.ids(
            "import httpx\nclient=httpx.AsyncClient()\nasync with client as active:\n"
            "    await active.get(user_url)"))
        self.assertNotIn("PY-URL", self.ids(
            "from httpx import Client\ndef f(Client):\n    with Client() as client:\n"
            "        client.stream('GET', user_url)"))
        self.assertNotIn("PY-URL", self.ids(
            "import httpx\nwith httpx.Client() as client:\n"
            "    url='https://example.invalid'\n    client.stream('GET', url)"))
        # Scalar facts do not cross a context boundary. The retained review
        # signal is documented, not a claim that the literal endpoint is unsafe.
        self.assertIn("PY-URL", self.ids(
            "import httpx\nurl='https://example.invalid'\nwith httpx.Client() as client:\n"
            "    client.stream('GET', url)"))

    def test_stream_report_location_and_documentation(self):
        source = ("import httpx\nasync with httpx.AsyncClient() as client:\n"
                  "    async with client.stream(\n        'GET', user_url\n    ) as response:\n        pass\n")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "request.py"
            path.write_text(source, encoding="utf-8")
            report = scanner.scan(path, self.rules)
        self.assertEqual(report["issues"], [])
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual((finding["rule"], finding["path"], finding["line"]),
                         ("PY-URL", "request.py", 3))
        self.assertEqual(finding["doc"], "docs/vulnerabilities/python.md#py-url")
        self.assertTrue(finding["reason"] and finding["detection"])


if __name__ == "__main__":
    unittest.main()
