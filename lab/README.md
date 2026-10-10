# Synthetic local defense lab

English | [Русский](README-RU.md)

This stdlib-only service is intentionally small and loopback-only. It does not connect to competition infrastructure. Run from the repository root with Python 3.10+.

Evidence: `REVIEWED`; effect `SERVICE-CHANGE` (one local process). Expected: a loopback listener, no external binding. Secrets: use only provided synthetic fixtures. Rollback: Ctrl-C stops the process.

```bash
python3 lab/health_service.py
```

Default port: 8080. Use --port 8081 for another explicit port, or --port 0 for an ephemeral port whose actual URL is printed. Update your probe profile accordingly. fixtures/service.json demonstrates configuration backup; the server does not load it.

| Request | Response |
|---|---|
| GET /health or /health?check=1 | 200 and {"status": "ok"} |
| GET /version | 200 and {"version": "demo"} |
| HEAD /health | GET headers without body |
| GET /missing | 404 |
| POST /health | 405; Allow: GET, HEAD |

The service writes JSONL level/status records to stderr without URLs or request contents.

In another terminal, evidence `REVIEWED`, effect `READ-ONLY`, same cwd; expected probe exit 0 and a log summary with two HTTP errors in the provided four-record fixture:

```bash
python3 scripts/http_probe.py config/services.example.json
python3 scripts/log_summary.py lab/fixtures/events.jsonl
```

Unit tests create/stop their own temporary loopback servers; no separately running lab is needed. Effect: temporary `WORKSPACE-WRITE`; expected suite pass.

```bash
python3 -m unittest discover -s tests -p 'test_defense*.py' -v
```

DEMO_ONLY_DO_NOT_COPY in fixtures/service.json is an inert test value, not a working password. External container tests are a separate opt-in [integration fixture](../integration/README.md).
