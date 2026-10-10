# Offline source scanner

English | [Русский](offline-scanner-RU.md)

[Catalog](vulnerabilities/README.md) · [Operator workflow](defense.md) · [Development](development.md)

Scanner 1.8.0 uses 174 local rules: 30 Python AST, 143 regex and one bounded JavaScript-token rule. Framework-specific token hints also extend existing rules. It is a bounded, deterministic review assistant—not a CVE database, dependency resolver, exploit detector or interprocedural taint engine.

## Safe first scan

Evidence: `REVIEWED`; historical execution is recorded separately. Effect: `READ-ONLY` (stdout redirection creates your chosen output file). Cwd: DurkaHelper root. Prerequisites: Python 3.10+, an authorized local service copy and a private output directory. No input code executes and no network requests occur. Rollback: none; review output before sharing it.

```bash
python3 -I -S scripts/defense_scan.py /path/to/service --patches
python3 -I -S scripts/defense_scan.py /path/to/service --json
python3 -I -S scripts/defense_scan.py --list-rules
python3 -I -S scripts/defense_scan.py --explain PY-SQL
```

Use the interpreter's isolated/no-site mode shown above to avoid loading target-controlled Python startup files. The scanner loads its own trusted rule pack, not rules supplied by the scanned directory. Do not install dependencies or import the target just to inspect it.

## Reading a finding

Each finding includes a root-relative path and physical line, stable rule ID, static explanation, fix template, verification guidance and an exact catalog link. New metadata adds family, CWE where applicable, review priority, signal kind and limitations. These are review classifications, not proof of reachability or exploitability.

Findings do not include raw source lines, argv, environment or discovered secret values. Filenames and hashes can still be sensitive. Text output safely represents unsupported console characters; JSON is portable.

A correct fix can retain a signal: for example a validated dynamic URL or bounded reader may still match. Conversely, deleting or moving code may remove a match without fixing authorization. Review the real source-to-sink path and verify behavior.

## Infrastructure context

The optional [context example](../config/scanner-context.example.json) is strictly non-secret:

```json
{
  "schema": "durkahelper.scanner-context.v1",
  "infrastructure": ["docker-desktop", "compose", "vulnbox", "team-lan", "s4dfarm", "neo", "packmate"],
  "role": "both"
}
```

Evidence: `REVIEWED`; effect `READ-ONLY`; same cwd/prerequisites as the first scan. Expected: the same applicable rules remain enabled, with contextual priorities/explanations. No runtime discovery or permission is implied.

```bash
python3 -I -S scripts/defense_scan.py /path/to/service \
  --context config/scanner-context.example.json --json
```

Allowed roles are defender, administrator and both. Context never disables rules, executes commands, authorizes network operations or reveals running Docker state. Its normalized meaning participates in the report scope fingerprint.

## Inputs and limits

Supported source/configuration families include Python, JavaScript/TypeScript, PHP, Go, Java, C#/.NET, C/C++, Ruby, Rust, SQL, templates, Dockerfiles, shell and common configuration formats. Language detection is filename-based; a supported filename does not prove runtime language or version.

Defaults: 1 MiB per file, 20,000 files, 10,000 findings. The scanner excludes common dependency/build/cache directories and secret-like filenames such as private-key formats and non-example .env files. Explicit exclusions are recorded in scope. Review whether excluded/generated/vendor code needs a separate authorized review.

Evidence: `REVIEWED`; effect `READ-ONLY`; cwd root. These options change coverage and therefore comparability:

```bash
python3 -I -S scripts/defense_scan.py /path/to/service \
  --exclude generated --max-bytes 1048576 --max-files 20000 --max-findings 10000 --json
```

Symlink leaves, nonregular files, unreadable/unstable files, parsing failures and exceeded limits produce incomplete/partial results, not false-clean success. Normal macOS ancestor links are distinguished from unsafe input leaves. Never relax these protections to make a report green.

Regex scanning uses bounded overlapping windows: up to 12 physical lines and 8,192 characters per window, with six-line overlap. Oversized physical lines are omitted with a partial issue. Patterns spread beyond the window, unknown wrappers and generated strings can be missed. New code-only detectors have lexical exclusions; older regex detectors may still match comments or string examples.

Python analysis is bounded syntactic AST traversal, with limited import-alias/scalar tracking and conservative invalidation. It does not resolve arbitrary types, branches, dynamic imports or values across function calls. Parse/node-limit failures are reported. JavaScript alias handling is bounded rather than a complete parser or scope/taint engine.

## JSON, scope and comparison

Reports include tool version, timestamp, offline flag, scope, findings, issues, skipped counts, scanned counts, partial and exit code. Scope v2 binds canonical root identity, rule fingerprint, path semantics, exclusions, limits and scanner context. Context ordering is normalized before hashing. Cross-version or cross-scope comparisons are not interchangeable.

Evidence: `REVIEWED`; effect `READ-ONLY`. Cwd: root; prerequisites two private JSON reports from intentionally comparable scans. Expected: new/existing/not-observed sets, or exit 2 when comparison is incomplete. No input files are changed.

```bash
python3 -I -S scripts/defense_diff.py before-scan.json after-scan.json --json
```

Older reports remain readable where supported, but missing scope, v1/v2 differences, version changes or partial reports prevent an unqualified comparable result. Matching uses path/line/rule: moving a line can appear as a removed and added signal. “Not observed” never means “vulnerability fixed.”

| Exit | Meaning |
|---|---|
| 0 | Complete supported scan without findings; or complete comparison without actionable new signals |
| 1 | Findings/new signals needing review |
| 2 | Invalid, partial, blocked or incomparable result; also no supported input |

## Coverage and next steps

Evidence: `REVIEWED`; effect `READ-ONLY`; cwd root. The check evaluates inert strings only; it does not execute the snippets.

```bash
python3 scripts/scanner_coverage.py --check
python3 scripts/scanner_coverage.py --json
```

The ledger reports rule/language pairs, independently authored positives/negatives and honest legacy gaps. Metadata before/after examples do not count as independent evidence. For fixes use the [catalog](vulnerabilities/README.md) and [patch verification](patch-validation.md); for container policy use [deployment auditing](local-tools.md#deployment-audit), not a claim that YAML regex proves runtime safety.

## Framework and database boundaries

| Area | Expanded signals | Manual verification |
|---|---|---|
| Flask | Explicit debugger/session config; auth order including put/patch/delete; credentials in app.logger | Test the registered HTTP endpoint, not just a function call. Keep HttpOnly; do not force Secure onto an HTTP-only checker. |
| Psycopg | SQL(nonliteral), raw/unknown format/join/as_string pieces; known quoting compositions suppress this signal | Bind values using the deployed driver. Identifier quotes a name but does not authorize selection of any table. |
| PostgreSQL | ROLE/USER bypass, meaningful PUBLIC grants, server file/program roles | Inspect the real runtime role, inheritance and ownership. Change only approved service rights; retest queries, migrations and recovery. |
| JS/TS | Request SQL to recognized pg/mysql bindings, reflective credentialed cors, disabled session HttpOnly, direct credential logging | Bind values, allowlist origins, retain HttpOnly and log categories. Test failed auth, sessions, real response headers and the checker. |

JS hints use bounded tokens, not a complete parser: 100,000 tokens per file, 128 nested delimiters, 2,048 tokens per inspected expression. Exact default/namespace imports and direct driver constructors are recognized. Observed reassignment/parameter shadowing disables a binding conservatively file-wide. Named imports, regex ambiguity, templates, dynamic keys/spreads, acquired connections, custom loggers and cross-file flows remain manual. A helper called redact() is not trusted or executed: its return value lies outside direct-value detection.

Docker privilege/socket/root-user signals remain enabled. Scan local Compose/Dockerfile sources, then use deployment-model auditing for binds, backend exposure, mounts, image pins and runtime policy. Neither source scan verifies the running daemon. See [traffic capture](traffic-capture.md) for LIVE and closed-PCAP routes.

Version 1.8.0 advances semantic revision to v3. Old revision-v2 reports remain readable but old/new comparison exits 2. Rescan both copies with the same scanner/context before patch verification; no manual digest cards are required.
