# SQL / databases: find, fix and verify

English | [Русский](sql-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

18 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [SQL-UPSERT — Upsert/replace requires ownership review](#sql-upsert)
- [SQL-DEFINER — SECURITY DEFINER and search_path trust](#sql-definer)
- [SQL-BYPASSRLS — Application role bypasses RLS](#sql-bypassrls)
- [SQL-PUBLIC-GRANT — Broad privileges granted to PUBLIC](#sql-public-grant)
- [SQL-RLS-POLICY — RLS USING, WITH CHECK and policy composition](#sql-rls-policy)
- [SQL-IDENTIFIERS — Parameters do not substitute table names or ORDER BY](#sql-identifiers)
- [SQL-COLLATION — Authorization and uniqueness use different canonicalization](#sql-collation)
- [SQL-TRANSACTION — Check and mutation are not one atomic operation](#sql-transaction)
- [SQL-POOL-CONTEXT — Connection pools retain tenant or search_path](#sql-pool-context)
- [SQL-SQLITE-FK — SQLite foreign_keys explicitly disabled](#sql-sqlite-fk)
- [SQL-MYSQL-PRIVILEGES — MySQL runtime user has admin privileges](#sql-mysql-privileges)
- [SQL-SECOND-ORDER — Stored data becomes SQL again](#sql-second-order)
- [SQL-NESTED-DSL — Multiple query-language layers](#sql-nested-dsl)
- [SQL-RLS-DISABLE — PostgreSQL table RLS disabled](#sql-rls-disable)
- [SQL-TOKEN-PREFIX — Secret token checked by prefix or range](#sql-token-prefix)
- [SQL-NULL-AUTH — NULL changes authorization logic](#sql-null-auth)
- [SQL-RLS-ALLOW-ALL — RLS policy has an unconditional expression](#sql-rls-allow-all)
- [SQL-SERVER-ROLE — PostgreSQL server file/program role granted](#sql-server-role)

<a id="sql-upsert"></a>

## SQL-UPSERT. Upsert/replace requires ownership review

**Search:** scanner rule SQL-UPSERT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SQL-UPSERT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~sql
INSERT INTO notes(id, owner, body) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE body=VALUES(body);
~~~

**Fix:** Separate create/update, normalize before authorization, enforce ownership in atomic UPDATE and check rows, uniqueness and transactions.

~~~sql
UPDATE notes SET body=? WHERE id=? AND owner=?;
~~~

**Verification:** Case/Unicode/trigger conflicts cannot update another owner; normal edits work.

**A/D variant:** Key normalization after authorization plus upsert. **RuCTF / rusi-trainer, author write-up.** Authorization used the original name, but a database trigger normalized the key before insertion; a conflict converted the insert into an update.

**Patch:** Apply consistent canonicalization/collation, separate insert from update, and enforce ownership in the mutation itself. Switching database engines is not a universal fix.
**Test:** Unicode/case variants, uniqueness conflicts and concurrent inserts.
**Search:** SQL-UPSERT; review triggers and key comparison manually.

[Source/write-up 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/rusi-trainer/README.md).

<a id="sql-definer"></a>

## SQL-DEFINER. SECURITY DEFINER and search_path trust

**Search:** scanner rule SQL-DEFINER. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SQL-DEFINER` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~sql
CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT value FROM settings $$;
~~~

**Fix:** Prefer INVOKER unless elevated rights are needed; otherwise use a minimal owner, fixed safe search_path with pg_temp last, qualified names and restricted EXECUTE.

~~~sql
CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY INVOKER AS $$ SELECT value FROM app.settings $$;
~~~

**Verification:** Callers cannot replace objects using temporary/writable schemas; valid calls work.

**Reference:** [primary source](https://www.postgresql.org/docs/current/sql-createfunction.html).

<a id="sql-bypassrls"></a>

## SQL-BYPASSRLS. Application role bypasses RLS

**Search:** scanner rule SQL-BYPASSRLS. Use `--explain SQL-BYPASSRLS` for the exact detector contract. Bounded SQL: CREATE/ALTER ROLE or USER with explicit SUPERUSER/BYPASSRLS, comments and quoted strings excluded, unquoted keywords and statements up to 300 characters. Later overrides, ownership, inherited roles and effective runtime policy remain manual.

**Vulnerable example:**

~~~sql
ALTER ROLE app BYPASSRLS;
~~~

**Fix:** Use a runtime role without elevated attributes and review table ownership separately; FORCE RLS does not constrain superuser/BYPASSRLS.

~~~sql
ALTER ROLE app NOBYPASSRLS NOSUPERUSER;
~~~

**Verification:** Actual runtime roles for two tenants cannot cross boundaries; migration role is separate.

**Reference:** [primary source](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

<a id="sql-public-grant"></a>

## SQL-PUBLIC-GRANT. Broad privileges granted to PUBLIC

**Search:** scanner rule SQL-PUBLIC-GRANT. Use `--explain SQL-PUBLIC-GRANT` for the exact detector contract. Bounded SQL: GRANT ALL or SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER/CREATE/USAGE/EXECUTE/CONNECT/TEMPORARY/TEMP privilege lists ON an object TO PUBLIC. Comments/strings excluded; no cross-statement matching. Quoted identifiers, defaults, complex grants, effective rights and intentional public objects remain manual.

**Vulnerable example:**

~~~sql
GRANT ALL ON notes TO PUBLIC;
~~~

**Fix:** Grant only required actions to specific roles; review existing/default privileges, sequences and functions. Never revoke unrelated infrastructure rights.

~~~sql
GRANT SELECT, INSERT, UPDATE ON notes TO app;
~~~

**Verification:** Neighbor roles cannot read data; app ID generation and old records work.

**Reference:** [primary source](https://www.postgresql.org/docs/current/sql-grant.html).

<a id="sql-rls-policy"></a>

## SQL-RLS-POLICY. RLS USING, WITH CHECK and policy composition

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'CREATE POLICY|ROW LEVEL SECURITY|USING|WITH CHECK' .
~~~

Review the application role, SELECT/UPDATE/INSERT, owner bypass and OR composition between permissive policies.

**Vulnerable example:**

A new broad policy makes an earlier restriction ineffective, or a tenant-changing update is unchecked.

**Fix:** Define policies for reads and resulting row state according to the contract; test the effective role. RLS does not replace application object-level authorization.

**Verification:** Other tenants' rows stay hidden, tenant changes are denied, and migrations/checkers still work.

**Reference:** [primary source](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

<a id="sql-identifiers"></a>

## SQL-IDENTIFIERS. Parameters do not substitute table names or ORDER BY

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ORDER BY|table_name|column_name|quote_ident|identifier' .
~~~

Find dynamic identifiers and sorting directions separately from data values.

**Vulnerable example:**

Concatenated request order/column values change syntax; an identifier placeholder does not behave as expected.

**Fix:** Map allowed identifiers/directions explicitly, using the driver's quoting API where required; parameterize values.

**Verification:** Permitted sorting remains available; unknown fields/directions are rejected.

<a id="sql-collation"></a>

## SQL-COLLATION. Authorization and uniqueness use different canonicalization

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'COLLATE|LOWER\(|UPPER\(|UNIQUE|TRIGGER|citext' .
~~~

Compare application equality, database collation, triggers and the unique index.

**Vulnerable example:**

Two names differ during authorization but identify the same row during a write.

**Fix:** Canonicalize consistently before both checks and writes; use stable owner IDs and migrate conflicts rather than merely switching databases.

**Verification:** Case, Unicode and trailing spaces on the actual database, including old references and uniqueness.

<a id="sql-transaction"></a>

## SQL-TRANSACTION. Check and mutation are not one atomic operation

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'SELECT|UPDATE|DELETE|BEGIN|FOR UPDATE|version' .
~~~

Review isolation level, write predicates and affected-row counts.

**Vulnerable example:**

Two requests pass a SELECT check and both spend the resource or modify an object after ownership changes.

**Fix:** Conditional UPDATE/DELETE with owner/version/balance predicates, transactions and bounded retries; choose the necessary isolation level.

**Verification:** Deterministic races, conflicts/rollback and legitimate concurrency.

<a id="sql-pool-context"></a>

## SQL-POOL-CONTEXT. Connection pools retain tenant or search_path

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'SET ROLE|SET search_path|set_config|tenant|pool|RESET' .
~~~

Distinguish session SET from transaction-local SET; inspect connection return after exceptions.

**Vulnerable example:**

The next request inherits the previous role, schema or tenant.

**Fix:** SET LOCAL inside the correct transaction or reliable reset; do not derive ownership from client-controlled session variables.

**Verification:** Two tenants sharing a connection, rollback/exceptions and ordinary subsequent requests.

**Reference:** [primary source](https://www.postgresql.org/docs/current/ddl-schemas.html).

<a id="sql-sqlite-fk"></a>

## SQL-SQLITE-FK. SQLite foreign_keys explicitly disabled

**Search:** scanner rule SQL-SQLITE-FK. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SQL-SQLITE-FK` for details. Regex: PRAGMA foreign_keys=OFF/0/false or foreign_keys(OFF/0/false). Review missing ON, pool hooks and compile options.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'PRAGMA foreign_keys|sqlite3.connect|Data Source|FOREIGN KEY' .
~~~

Check the effective PRAGMA after every connection opens and before a transaction begins.

**Vulnerable example:**

The DDL declares foreign keys and the app trusts ownership relationships, but enforcement is disabled.

**Fix:** Enable FK on every connection outside transactions, verify the result and existing violations, and migrate invalid records separately.

**Verification:** Every connection reports foreign_keys=1; foreign_key_check is empty and invalid owners fail.

**Reference:** [primary source](https://www.sqlite.org/pragma.html#pragma_foreign_keys).

**Scanner example before:**

~~~sql
PRAGMA foreign_keys = OFF;
~~~

**Fix template:**

~~~sql
PRAGMA foreign_keys = ON;
~~~

Primary documentation: [reference 1](https://www.sqlite.org/foreignkeys.html).

<a id="sql-mysql-privileges"></a>

## SQL-MYSQL-PRIVILEGES. MySQL runtime user has admin privileges

**Search:** scanner rule SQL-MYSQL-PRIVILEGES. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SQL-MYSQL-PRIVILEGES` for details. Regex: GRANT with FILE/SUPER or ALL [PRIVILEGES] ON *.*. Review other dangerous dynamic privileges, roles and existing grants.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'GRANT|FILE|SUPER|ALL PRIVILEGES|secure_file_priv|local_infile' .
~~~

Read SHOW GRANTS for the application's own role; review FILE, file read/write and both sides of LOCAL INFILE configuration.

**Vulnerable example:**

An ordinary application has filesystem or administrative privileges that amplify a query bug.

**Fix:** Separate runtime/migration accounts; remove unnecessary global grants and GRANT OPTION; match account hosts to topology.

**Verification:** SHOW GRANTS contains only required actions; migrations/checker still work.

**Reference:** [primary source](https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html).

**Scanner example before:**

~~~sql
GRANT FILE, SUPER ON *.* TO 'app'@'%';
~~~

**Fix template:**

~~~sql
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'app'@'localhost';
~~~

Primary documentation: [reference 1](https://dev.mysql.com/doc/refman/8.4/en/privileges-provided.html).

<a id="sql-second-order"></a>

## SQL-SECOND-ORDER. Stored data becomes SQL again

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'execute|query|EXECUTE|format\(|quote|SELECT' .
~~~

Trace stored values into subsequent queries, exports and jobs; persistence does not make data trusted.

**Vulnerable example:**

The insert parameterizes a value, but a later operation concatenates it into SQL.

**Fix:** Parameterize every sink, including stored procedures and jobs; use a separate identifier allowlist.

**Verification:** A stored delimiter remains data in every subsequent operation.

<a id="sql-nested-dsl"></a>

## SQL-NESTED-DSL. Multiple query-language layers

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'LIKE|database|tenant|parse|execute' .
~~~

Separate the outer DSL, inner SQL and database selection; inspect how both layers interpret delimiters.

**Vulnerable example:**

**Reference:** The museumorphosis author write-up from RuCTF describes a custom SQL DSL with an unsafe boundary between query text and database selection.
**Search:** SQL inside another language's strings, regex instead of a real parser, user-controlled LIKE text and database/tenant names.

**Fix:** Parameterize values at each layer; derive database selection from a verified server-side tenant and use an unambiguous DSL parser. Escaping inner SQL does not prove the outer language safe.

**Verification:** Delimiters of both languages, contractual wildcards, attempted database changes and access restricted to the correct tenant.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/museumorphosis/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/museumorphosis/README.md).

<a id="sql-rls-disable"></a>

## SQL-RLS-DISABLE. PostgreSQL table RLS disabled

**Search:** scanner rule SQL-RLS-DISABLE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SQL-RLS-DISABLE` for details. Regex: ALTER TABLE ... DISABLE ROW LEVEL SECURITY. Does not infer missing ENABLE, broad policies or connection role.

**Vulnerable example:** Disabling RLS removes the server-side row boundary when access depends on its policies.

~~~sql
ALTER TABLE notes DISABLE ROW LEVEL SECURITY;
~~~

**Fix:** Install intended policies and enable RLS; runtime must not be superuser/BYPASSRLS. FORCE constrains table owners, not these bypass roles.

~~~sql
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes FORCE ROW LEVEL SECURITY;
-- Install reviewed owner/tenant policies before serving traffic.
~~~

**Verification:** Test SELECT/INSERT/UPDATE/DELETE with two runtime identities/tenants and separate migration role.

Primary documentation: [reference 1](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

<a id="sql-token-prefix"></a>

## SQL-TOKEN-PREFIX. Secret token checked by prefix or range

**Search:** scanner rule SQL-TOKEN-PREFIX. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SQL-TOKEN-PREFIX` for details. Regex: nonce/token/reset_token/api_key before LIKE, >= or <= in SQL text. Counters/log searches may be legitimate; inspect renamed fields, substr, startsWith and application-side partial comparisons.

**Vulnerable example:** If a nonce/token is a bearer secret, partial matching drastically reduces the effective search space.

~~~sql
SELECT content FROM exports WHERE username = $1 AND nonce >= $2 AND nonce < $3;
~~~

**Fix:** Require the complete canonical token with valid length/type, exact equality and binding to user/purpose/expiry; rate limiting is separate.

~~~sql
SELECT content FROM exports WHERE username = $1 AND nonce = $2;
-- Before querying: require the full canonical token, correct length/type and purpose.
~~~

**Verification:** Empty, short, prefix, extra-suffix and foreign-user tokens fail; complete valid tokens work.

Primary documentation: [reference 1](https://github.com/enowars/enowars10-service-flagdrive/blob/d1575098fe2c516460136bb5fba11d9a1c4af3f7/documentation/FLAGSTORE_0.md).

**A/D variant:** FlagDrive's ENOWARS10 authors describe selecting exports by a short nonce prefix. Require full length and exact equality; the rule flags SQL range comparisons, while the bearer-secret meaning requires manual review.

<a id="sql-null-auth"></a>

## SQL-NULL-AUTH. NULL changes authorization logic

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'NOT IN|!=|<>|IS NULL|IS NOT NULL|COALESCE|LEFT JOIN|owner|tenant' .
~~~

Construct a TRUE/FALSE/UNKNOWN table for authorization conditions and LEFT JOIN results. Trace nullable booleans into allow/deny decisions and check for NULL inside NOT IN subqueries.

**Vulnerable example:** A denial condition `owner <> actor` becomes UNKNOWN for NULL and execution falls through to allow; missing ACL entries become default allow.

**Fix:** Permit access only for an explicitly true positive check. Use NOT NULL and referential integrity where NULL is invalid; otherwise define its exact meaning. Do not merge owners into a shared COALESCE default.

**Verification:** NULL owners, missing ACLs, empty joins and NULL subquery values never grant access; ordinary own/shared cases remain valid.

Reference: [primary documentation](https://www.postgresql.org/docs/current/functions-comparison.html). The explanation and adaptation recipe were written for this catalog.

<a id="sql-rls-allow-all"></a>

## SQL-RLS-ALLOW-ALL. RLS policy has an unconditional expression

**Search:** scanner rule SQL-RLS-ALLOW-ALL. Use `--explain SQL-RLS-ALLOW-ALL` for the exact detector contract. Regex with lexical exclusions: USING(true) or WITH CHECK(true). May be intentional and does not associate expressions with CREATE POLICY, roles or commands; effective policies and application authorization require review.

**Vulnerable example:**

~~~sql
CREATE POLICY open_notes ON notes USING (true);
~~~

**Fix:** Define role/tenant-aware USING and WITH CHECK expressions for the actual identity model; review permissive-policy combinations and bypass roles.

~~~sql
CREATE POLICY owned_notes ON notes USING (owner_id = current_user);
~~~

**Verification:** Two runtime identities cannot read/change each other's rows; inserts and updates enforce the intended owner and valid operations work.

[Primary reference 1](https://www.postgresql.org/docs/current/sql-createpolicy.html)

<a id="sql-server-role"></a>

## SQL-SERVER-ROLE. PostgreSQL server file/program role granted

**Search:** scanner rule SQL-SERVER-ROLE. Use `--explain SQL-SERVER-ROLE` for details. Bounded SQL: unquoted GRANT role lists containing pg_read_server_files, pg_write_server_files or pg_execute_server_program before TO. Comments/strings excluded; REVOKE and pg_monitor alone do not signal. Quoted roles, inheritance, later revocations, versions and effective permissions remain manual.

**Vulnerable example:**

~~~sql
GRANT pg_read_server_files TO app;
~~~

**Fix:** Separate application and administrator roles. Grant only required object privileges, not server file/program access; review memberships and revoke only approved service-owned grants with rollback.

~~~sql
GRANT SELECT ON notes TO app;
~~~

**Verification:** The actual runtime role cannot read/write server files or execute server programs; ordinary queries, migrations and recovery still work.

[Primary reference](https://www.postgresql.org/docs/14/predefined-roles.html)
