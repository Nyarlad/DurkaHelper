# JavaScript / TypeScript: find, fix and verify

English | [Русский](javascript-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

28 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [JS-SHELL — Shell API Node.js](#js-shell)
- [JS-EVAL — Dynamic JavaScript execution](#js-eval)
- [JS-SQL — Dynamic Node.js SQL](#js-sql)
- [JS-NOSQL — Request body used as a MongoDB filter](#js-nosql)
- [JS-MASS-ASSIGN — Mass assignment](#js-mass-assign)
- [JS-PROTOTYPE — Deep merge of an untrusted object](#js-prototype)
- [JS-TLS — Node.js TLS verification disabled](#js-tls)
- [JS-HTML — HTML sink](#js-html)
- [JS-TRUST-PROXY — Unrestricted trust in proxy headers](#js-trust-proxy)
- [JS-CURL-ARGV — Node.js curl: review URL and options](#js-curl-argv)
- [JS-SESSION-STATE — Sensitive session state assignment](#js-session-state)
- [JS-VM — node:vm used as a security sandbox](#js-vm)
- [JS-REGEX-DYNAMIC — Regex built from client text](#js-regex-dynamic)
- [JS-TYPE-ASSERTION — TypeScript as does not validate JSON](#js-type-assertion)
- [JS-AWAIT-AUTH — Missing await on authorization checks](#js-await-auth)
- [JS-WEBSOCKET — Authorization only at the WebSocket handshake](#js-websocket)
- [JS-GRAPHQL — Resolvers and batching bypass a common guard](#js-graphql)
- [JS-SESSION-FIXATION — Session ID does not change at login](#js-session-fixation)
- [JS-SSRF — fetch/axios redirects and repeated DNS resolution](#js-ssrf)
- [JS-BUFFER-EXPOSURE — Uninitialized Buffer exposure](#js-buffer-exposure)
- [JS-JWT-DECODE — JWT decoded without signature verification](#js-jwt-decode)
- [JS-JWT-OPTIONS — Weakened JWT options](#js-jwt-options)
- [JS-HTTP-PARSER — Lenient Node.js HTTP parser](#js-http-parser)
- [JS-STATIC-DOTFILES — Static server allows dotfiles](#js-static-dotfiles)
- [JS-QUERY-SHAPE — Parameters change type between middleware](#js-query-shape)
- [JS-MIDDLEWARE-TRUST — Handlers assume middleware has run](#js-middleware-trust)
- [JS-REDIRECT-INPUT — Request field passed directly to an Express-style redirect](#js-redirect-input)
- [JS-LOG-CREDENTIALS — Credential-like value passed directly to console](#js-log-credentials)

<a id="js-shell"></a>

## JS-SHELL. Shell API Node.js

**Search:** scanner rule JS-SHELL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-SHELL` for details. Regex: bare exec/execSync, common child_process/cp receivers, shell:true/nonempty shell string and literal shell in spawn/execFile. Static ESM/CommonJS child_process imports support aliases and string bracket access; arbitrary object.exec is not a process call. Import hints are not scope/type/data-flow analysis: comments, shadowing and reassignment may match; review wrappers/dynamic imports.

**Vulnerable example:**

~~~javascript
child_process.exec(command);
~~~

**Fix:** Use a fixed executable and separate argv with validated options and bounded execution.

~~~javascript
child_process.execFile('/usr/bin/file', ['--', filename], {timeout: 3000}, callback);
~~~

**Verification:** Metacharacters stay data; dangerous options fail; normal commands work.

<details>
<summary>Expanded example and limitations</summary>

```javascript
// Vulnerable: a shell interprets the command string.
exec("printf '%s' '" + req.body.text + "' | sha256sum", callback);
```

**Patch for a content hash:**

<!-- example: js-sha256 -->

```javascript
const { createHash } = require("node:crypto");

function digestText(text) {
  if (typeof text !== "string") throw new TypeError("string required");
  return createHash("sha256").update(text, "utf8").digest("hex");
}
```

For ESM use `import { createHash } from "node:crypto"`. Preserve encoding and the external result format. If an external program is genuinely needed, fix the executable and pass arguments separately; execFile does not automatically prevent dangerous program options.

**Check:** Known digest, empty string, Unicode, quotes/newlines and no child process. SHA-256 alone is unsuitable for password storage.

</details>

<a id="js-eval"></a>

## JS-EVAL. Dynamic JavaScript execution

**Search:** scanner rule JS-EVAL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-EVAL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
const value = eval(input);
~~~

**Fix:** Parse schema-validated data or a restricted DSL instead of evaluating JavaScript.

~~~javascript
const value = JSON.parse(input); // validate schema
~~~

**Verification:** Code-like input stays data; valid input works within limits.

<a id="js-sql"></a>

## JS-SQL. Dynamic Node.js SQL

**Search:** scanner rule JS-SQL. Use `--explain JS-SQL` for the exact detector contract. Legacy regex with comment/string exclusions: query/execute string construction or text/sql objects (receiver untyped). Bounded tokens also detect direct req/request.body/query/params property as SQL to a default/namespace imported pg Pool/Client or mysql/mysql2 createPool/createConnection binding. Named imports, acquired connections, SQL variables, tagged templates, wrappers and cross-file flows remain manual.

**Vulnerable example:**

~~~javascript
db.query("SELECT id FROM notes WHERE name=" + name);
~~~

**Fix:** Use driver-supported bind parameters and allowlist identifiers.

~~~javascript
db.query("SELECT id FROM notes WHERE name=?", [name]);
~~~

**Verification:** Quotes do not alter query structure; ownership restrictions remain.

<details>
<summary>Expanded example and limitations</summary>

```javascript
// Vulnerable: client input controls the query and ownership is unchecked.
const result = await pool.query(`SELECT body FROM notes WHERE id = '${req.params.id}'`);
```

**node-postgres (pg) patch for private notes:**

<!-- example: js-read-note -->

```javascript
async function readPrivateNote(pool, currentUserId, noteId) {
  if (currentUserId == null) throw new Error("authentication required");
  const result = await pool.query(
    "SELECT body FROM notes WHERE id = $1 AND owner_id = $2",
    [noteId, currentUserId]
  );
  if (result.rows.length === 0) return null;
  return result.rows[0].body;
}
```

`null` means no accessible object; the route maps it to the API's normal response. Select column names/sorting direction from a fixed map, not request text. $1 placeholders are PostgreSQL-specific, not universal across JavaScript drivers.

**Check:** Owners can read, foreign records are absent, apostrophes remain data, wrong types do not change query meaning, and denied responses contain no foreign note body.

</details>

<a id="js-nosql"></a>

## JS-NOSQL. Request body used as a MongoDB filter

**Search:** scanner rule JS-NOSQL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-NOSQL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
collection.findOne(req.body);
~~~

**Fix:** Validate field types and build a server-owned filter with ownership constraints.

~~~javascript
if (typeof req.body.name !== 'string') throw new Error('invalid');
collection.findOne({name: req.body.name, ownerId: currentUser.id});
~~~

**Verification:** Operator objects and unknown fields cannot widen the query; normal lookups work.

<details>
<summary>Expanded example and limitations</summary>

```javascript
// Vulnerable: title may be an operator object rather than a string.
const note = await notes.findOne({ ownerId: currentUserId, title: req.body.title });
```

**Patch:** Validate types and build the filter yourself. The example assumes ownerId already has the expected identifier type from trusted context.

<!-- example: js-title-filter -->

```javascript
function privateTitleFilter(currentUserId, body) {
  if (currentUserId == null) throw new Error("authentication required");
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new TypeError("object required");
  }
  if (!Object.prototype.hasOwnProperty.call(body, "title") || typeof body.title !== "string") {
    throw new TypeError("title must be a string");
  }
  return { ownerId: currentUserId, title: body.title };
}
// In the handler: await notes.findOne(privateTitleFilter(currentUserId, req.body));
```

Do not fix this with String(req.body.title): objects become meaningless strings and the contract changes. Never spread the rest of req.body into the filter or mix it with server-side ownership predicates.

**Check:** Strings, Unicode and permitted empty titles work; objects, arrays and null titles fail **before database access**. A supplied ownerId never changes the filter.

</details>

<a id="js-mass-assign"></a>

## JS-MASS-ASSIGN. Mass assignment

**Search:** scanner rule JS-MASS-ASSIGN. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-MASS-ASSIGN` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
Object.assign(user, req.body);
~~~

**Fix:** Allowlist editable fields; derive owner, role and privileges on the server.

~~~javascript
user.displayName = validateName(req.body.displayName);
~~~

**Verification:** Additional/nested privilege fields fail or are ignored; normal edits work.

<details>
<summary>Expanded example and limitations</summary>

```javascript
// Vulnerable: clients can write ownerId/role and other administrative fields.
Object.assign(note, req.body);
```

**Patch for editing title and body:**

<!-- example: js-editable-note -->

```javascript
function editableNoteFields(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new TypeError("object required");
  }
  const result = {};
  for (const key of Object.keys(body)) {
    if (key !== "title" && key !== "body") throw new TypeError("unknown field");
    if (typeof body[key] !== "string") throw new TypeError("string required");
    result[key] = body[key];
  }
  return result;
}
// After authorization: update only editableNoteFields(req.body).
```

A field allowlist does not authorize the record. Do not remove one key then deep-merge the rest: nested paths remain dangerous. Client JSON containing __proto__ must not enter arbitrary merging.

**Check:** Partial title updates and permitted empty bodies work; ownerId, role, unknown fields and nested objects fail; the original object is not mutated.

</details>

<a id="js-prototype"></a>

## JS-PROTOTYPE. Deep merge of an untrusted object

**Search:** scanner rule JS-PROTOTYPE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-PROTOTYPE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
merge(settings, req.body);
~~~

**Fix:** Copy only schema-approved fields and reject prototype-related keys at every level.

~~~javascript
settings.theme = validateTheme(req.body.theme);
~~~

**Verification:** Nested prototype keys cannot affect unrelated objects; supported settings apply.

<a id="js-tls"></a>

## JS-TLS. Node.js TLS verification disabled

**Search:** scanner rule JS-TLS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-TLS` for details. Regex: rejectUnauthorized:false/assignment only in JavaScript/config; NODE_TLS_REJECT_UNAUTHORIZED with exact 0 or paired quotes. Shell KEY=0 ends at whitespace, shell separators or end. Docker covers first ENV KEY=0 or whole-value ENV KEY 0, including paired quotes. 0.1, 0-disabled and quoted whitespace do not match; # or // suffix belongs to the shell/Docker value and semicolon belongs to Docker ENV. Comments/strings may match. Review Docker RUN/later ENV keys, concatenation, expansions, continuations, custom Agent and effective overrides.

**Vulnerable example:**

~~~javascript
const options = {rejectUnauthorized: false};
~~~

**Fix:** Enable peer/hostname checks and configure the trusted CA instead of disabling validation globally.

~~~javascript
const options = {rejectUnauthorized: true};
~~~

**Verification:** Valid certificates work; wrong CA/hostname and expiry fail.

The same risk can be configured outside JavaScript through process environment:

~~~dockerfile
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
~~~

~~~bash
NODE_TLS_REJECT_UNAUTHORIZED=0 node server.js
~~~

Node.js disables normal validation only when the variable is exactly the string '0'. '0.1', '0-disabled' and '0 ' are not that flag; do not use these as fixes—remove the setting or explicitly restore validation. Merely comparing process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' disables nothing. [Node.js environment variable](https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue), [exact comparison in Node.js 22.14.0](https://github.com/nodejs/node/blob/v22.14.0/lib/internal/options.js).

For an internal CA retain the required trust through application CA settings or supported Node.js configuration. For example, with a preinstalled PEM file in the image:

~~~dockerfile
ENV NODE_TLS_REJECT_UNAUTHORIZED=1
ENV NODE_EXTRA_CA_CERTS=/etc/service-ca.pem
~~~

Check the file's path, availability and CA contents. CA trust does not replace hostname validation. Per-client ca settings and custom Agents need separate review. Test the actual Node.js version against the normal internal server and reject wrong CAs, wrong names and expired certificates.

Docker supports ENV KEY=value and legacy ENV KEY value. In the latter, the entire remainder is the value: ENV NODE_TLS_REJECT_UNAUTHORIZED 0 extra is not exactly '0'. Runtime configuration can override image ENV. [Dockerfile ENV](https://docs.docker.com/reference/dockerfile/#env).

In Dockerfiles the scanner checks only the first ENV key. Manually search RUN NODE_TLS_REJECT_UNAUTHORIZED=0 node server.js and settings after another first key. Shell/Dockerfile token boundaries differ: 0#suffix and 0//suffix belong to the value; 0; separates shell commands but remains the value in ENV KEY=0;. Quotes around exact 0 are supported, including legacy ENV KEY "0".

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS|rejectUnauthorized|https[.]Agent|tls[.]connect|env_file|environment:' .
~~~

Connect Dockerfiles/build stages, Compose/manifests, startup shell and code to the environment of the actual running process. Review later assignments and per-request parameters. Regex does not evaluate substitutions, startup order or effective environment and is not a complete shell/Dockerfile/JavaScript parser. Comments/examples can signal and need context review.

<a id="js-html"></a>

## JS-HTML. HTML sink

**Search:** scanner rule JS-HTML. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-HTML` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
element.innerHTML = message;
~~~

**Fix:** Use textContent for text or a reviewed context-appropriate sanitizer for supported rich HTML.

~~~javascript
element.textContent = message;
~~~

**Verification:** User markup cannot execute; intended presentation remains usable.

<a id="js-trust-proxy"></a>

## JS-TRUST-PROXY. Unrestricted trust in proxy headers

**Search:** scanner rule JS-TRUST-PROXY. Use `--explain JS-TRUST-PROXY` for the exact detector contract. Regex with comment/string exclusions: .set('trust proxy', true). Receiver untyped; true may be valid behind proxies that overwrite forwarded headers. No effective topology or proxy-hop verification; inspect all direct entrypoints and the immediate peer.

**Vulnerable example:**

~~~javascript
app.set('trust proxy', true);
~~~

**Fix:** Trust actual immediate proxies, not client X-Forwarded-* as authentication; do not change organizer networking.

~~~javascript
app.set('trust proxy', isKnownProxy); // implement topology-specific peer validation
~~~

**Verification:** Spoofed direct headers grant no trusted identity/IP/scheme; proxy works.

<a id="js-curl-argv"></a>

## JS-CURL-ARGV. Node.js curl: review URL and options

**Search:** scanner rule JS-CURL-ARGV. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-CURL-ARGV` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
spawn('/usr/bin/curl', [url, '-o', filename]);
~~~

**Fix:** Separate argv does not prevent option injection. Prefer bounded HTTP APIs; otherwise fix curl options/protocols, use -- before validated URL and choose server-side output.

~~~javascript
downloadValidatedHttpResource(url, destination); // bounded HTTP client, checked redirects/DNS and server-chosen output
~~~

**Verification:** Leading-dash URLs, forbidden schemes/redirects and output paths fail; normal downloads work.

**A/D variant:** Separate argv do not protect against program options. **ECSC / duogesto, author write-up.** curl interpreted client text as an option. **Patch:** A constrained HTTP client or fixed options, --, permitted schemes/redirects and server-selected output. **Test:** Leading dashes, other protocols, foreign paths and normal URLs. **Search:** JS-CURL-ARGV; shell:false is insufficient.

[source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/backend/app.mjs).

<a id="js-session-state"></a>

## JS-SESSION-STATE. Sensitive session state assignment

**Search:** scanner rule JS-SESSION-STATE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-SESSION-STATE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
const user = req.body;
req.session.user = user;
~~~

**Fix:** Build session DTOs from persisted validated records; bind related state server-side and reject client privilege fields.

~~~javascript
req.session.user = {id: savedUser.id, friends: savedUser.friends}; // server-validated fields only
~~~

**Verification:** Extra role/friends fields or endpoint reordering cannot change access; correct assignments may still match.

**A/D variant:** Unrelated endpoints overwrite operation context. **ECSC / duogesto, author write-up.** Another request changed the current task's author; completion combined an old answer with the new author. **Patch:** Store challenge ID, author and state together and verify their binding at completion. **Test:** Reordered requests and multiple tabs. **Search:** JS-SESSION-STATE; review semantics manually.

[source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/backend/app.mjs).

**A/D variant:** Safe database object, original request body in the session. **ECSC / duogesto, author write-up.** Session initialization retained client-supplied friends. **Patch:** Explicit session DTO from the verified persisted user; do not copy passwords or extra fields. **Test:** Registration with role/friends grants no privileges; ordinary login works. **Search:** JS-SESSION-STATE; account for the lack of taint analysis.

[source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/duogesto/backend/app.mjs).

<a id="js-vm"></a>

## JS-VM. node:vm used as a security sandbox

**Search:** scanner rule JS-VM. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-VM` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
vm.runInNewContext(userCode, context);
~~~

**Fix:** node:vm is not a security boundary for untrusted code. Use a restricted grammar or a separately designed execution isolation system.

~~~javascript
evaluateAllowedExpression(parsedInput); // implement a restricted grammar
~~~

**Verification:** Disallowed syntax fails; supported expressions work under time/memory limits.

**Reference:** [primary source](https://nodejs.org/api/vm.html).

<a id="js-regex-dynamic"></a>

## JS-REGEX-DYNAMIC. Regex built from client text

**Search:** scanner rule JS-REGEX-DYNAMIC. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-REGEX-DYNAMIC` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~javascript
const re = new RegExp(input);
~~~

**Fix:** Use includes for literal search; bound regex grammar/complexity and input when regex is a feature. A Promise timeout cannot interrupt synchronous regex execution.

~~~javascript
const found = text.includes(input);
~~~

**Verification:** Long near-matches cannot block the event loop; Unicode/case semantics remain compatible.

**Reference:** [primary source](https://nodejs.org/en/learn/asynchronous-work/dont-block-the-event-loop).

<a id="js-type-assertion"></a>

## JS-TYPE-ASSERTION. TypeScript as does not validate JSON

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'as [A-Z]|JSON.parse|req.body|parseInt|Number\(' .
~~~

Find unknown-to-type transitions; verify a real runtime schema before field access.

**Vulnerable example:**

`req.body as User` hides missing validation; parseInt accepts a numeric prefix.

**Fix:** A schema validator or explicit type/range/field checks, strict whole-string number parsing and separate server-derived IDs.

**Verification:** Arrays/null/objects replacing strings, numeric suffixes, NaN/Infinity and unsafe integers fail.

<a id="js-await-auth"></a>

## JS-AWAIT-AUTH. Missing await on authorization checks

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'authorize|isAllowed|verifyToken|Promise|async' .
~~~

Check the return type of every authorization helper used in an if; Promise objects are truthy regardless of eventual result.

**Vulnerable example:**

`if (isAllowed(user, note))` with async isAllowed permits execution before the decision.

**Fix:** Await the check and explicitly deny exceptions; do not continue response handling after rejected Promises.

**Verification:** Async true/false/error and delay cases; private data is never read before verification completes.

<a id="js-websocket"></a>

## JS-WEBSOCKET. Authorization only at the WebSocket handshake

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'WebSocket|upgrade|on\(.message|subscribe|room|channel' .
~~~

Compare handshake, every message/action, room joins and broadcasts; validate Origin separately from cookies.

**Vulnerable example:**

After login the client selects a foreign room or retains access after its privileges change.

**Fix:** Authenticate/authorize every operation and subscription, enforce session lifetime and permitted browser Origins, and bound messages.

**Verification:** Two users, role revocation, reconnect, foreign rooms and legitimate broadcast.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html).

<a id="js-graphql"></a>

## JS-GRAPHQL. Resolvers and batching bypass a common guard

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'resolver|resolve|GraphQL|DataLoader|context|mutation' .
~~~

Inspect nested resolvers, node(id), loaders and mutations; DataLoader caches must be request/user-scoped.

**Vulnerable example:**

The root query is protected, but a nested resolver loads by ID without owner checks, or a shared loader returns another user's cached result.

**Fix:** Resource authorization in resolvers/services, request-scoped loaders and contractual depth/cost/batch limits.

**Verification:** Foreign nodes, nested paths, aliases/batching and normal pagination.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).

<a id="js-session-fixation"></a>

## JS-SESSION-FIXATION. Session ID does not change at login

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'session|regenerate|login|logout|sessionID' .
~~~

Compare identifiers before/after login and the old ID's association with the new principal.

**Vulnerable example:**

A previously known anonymous session becomes authenticated.

**Fix:** Supported session-ID regeneration at privilege transitions, transferring only allowed state; logout invalidates server state.

**Verification:** Old IDs cannot authorize, shopping cart/permitted state survives and concurrent login does not lose sessions.

<a id="js-ssrf"></a>

## JS-SSRF. fetch/axios redirects and repeated DNS resolution

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'fetch\(|axios|undici|http.request|https.request' .
~~~

Trace URLs to actual connections and every redirect; JS-CURL-ARGV covers only curl calls.

**Vulnerable example:**

The initial hostname is checked but connection/redirect behavior selects another address or scheme.

**Fix:** Server-defined destinations or policy covering normalized URLs, allowed IPs/ports and actual connections; bound response size/time.

**Verification:** Mock DNS/redirects, contractually allowed internal addresses, timeouts and oversized bodies.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="js-buffer-exposure"></a>

## JS-BUFFER-EXPOSURE. Uninitialized Buffer exposure

**Search:** scanner rule JS-BUFFER-EXPOSURE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-BUFFER-EXPOSURE` for details. Regex: Buffer.allocUnsafe/allocUnsafeSlow. Full initialization before disclosure may remove risk on review; inspect legacy new Buffer and incorrect lengths separately.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'allocUnsafe|allocUnsafeSlow|write\(|subarray|res.end|socket.write' .
~~~

Compare allocation capacity, bytes actually initialized and transmitted length.

**Vulnerable example:**

`Buffer.allocUnsafe(n)` is transmitted whole after only partial initialization.

**Fix:** Initialize memory, emit only the written range and validate size/read results.

**Verification:** Short read, EOF and errors disclose no tail bytes; valid binary responses work.

**Reference:** [primary source](https://nodejs.org/api/buffer.html).

**Scanner example before:**

~~~javascript
const out = Buffer.allocUnsafe(size);
const n = await readInto(out);
res.end(out);
~~~

**Fix template:**

~~~javascript
const out = Buffer.alloc(size);
const n = await readInto(out);
res.end(out.subarray(0, n));
~~~

Primary documentation: [reference 1](https://nodejs.org/api/buffer.html#what-makes-bufferallocunsafe-and-bufferallocunsafeslow-unsafe).

<a id="js-jwt-decode"></a>

## JS-JWT-DECODE. JWT decoded without signature verification

**Search:** scanner rule JS-JWT-DECODE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-JWT-DECODE` for details. Regex: common jwt.decode/decodeJwt/jwtDecode and static ESM/CommonJS aliases for jsonwebtoken.decode/jose.decodeJwt. No scope/reassignment, re-export, dynamic import or claims-use analysis. Diagnostic decoding may be legitimate.

**Vulnerable example:** decode/decodeJwt extracts data without verification; it cannot establish an authenticated identity.

~~~javascript
const user = jwt.decode(token);
loadNotes(user.sub);
~~~

**Fix:** Verify signature and claims before access; await asynchronous verification and reject errors before proceeding.

~~~javascript
const claims = jwt.verify(token, key, { algorithms: ['RS256'], issuer: 'auth', audience: 'notes' });
loadNotes(claims.sub);
~~~

**Verification:** Modified payload, invalid signature and wrong issuer/audience grant no access.

Primary documentation: [reference 1](https://github.com/auth0/node-jsonwebtoken#jwtdecodetoken--options).

<a id="js-jwt-options"></a>

## JS-JWT-OPTIONS. Weakened JWT options

**Search:** scanner rule JS-JWT-OPTIONS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-JWT-OPTIONS` for details. Regex: ignoreExpiration/ignoreNotBefore/allowInvalidAsymmetricKeyTypes=true. Options may be separate from verify; inspect actual use.

**Vulnerable example:** Ignoring time constraints or accepting incompatible keys weakens token verification.

~~~javascript
jwt.verify(token, key, { ignoreExpiration: true, ignoreNotBefore: true });
~~~

**Fix:** Remove verification bypasses and fix algorithm/key/claims policy; require exp separately where needed.

~~~javascript
jwt.verify(token, key, { algorithms: ['RS256'], issuer: 'auth', audience: 'notes' });
~~~

**Verification:** Expired/premature tokens and wrong algorithms/key types fail.

Primary documentation: [reference 1](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback).

<a id="js-http-parser"></a>

## JS-HTTP-PARSER. Lenient Node.js HTTP parser

**Search:** scanner rule JS-HTTP-PARSER. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-HTTP-PARSER` for details. Regex: insecureHTTPParser:true or --insecure-http-parser. This alone does not prove request smuggling.

**Vulnerable example:** Different proxy/backend parsing rules create ambiguous request boundaries.

~~~javascript
http.createServer({ insecureHTTPParser: true }, handler);
~~~

**Fix:** Use strict parsers on every hop and align framing/normalization; check NODE_OPTIONS and CLI flags.

~~~javascript
http.createServer({ insecureHTTPParser: false }, handler);
~~~

**Verification:** Conflicting framing fails at the first hop; valid keep-alive requests stay separate.

Primary documentation: [reference 1](https://nodejs.org/api/http.html#httpcreateserveroptions-requestlistener).

<a id="js-static-dotfiles"></a>

## JS-STATIC-DOTFILES. Static server allows dotfiles

**Search:** scanner rule JS-STATIC-DOTFILES. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JS-STATIC-DOTFILES` for details. Regex: dotfiles:allow. Does not check actual root, middleware order, non-dot backups or symlinks.

**Vulnerable example:** A static root allowing dotfiles can expose configuration, history and keys.

~~~javascript
app.use(express.static(root, { dotfiles: 'allow' }));
~~~

**Fix:** Use a dedicated public root and deny dotfiles; allow required .well-known resources narrowly without secrets.

~~~javascript
app.use(express.static(publicDir, { dotfiles: 'deny' }));
~~~

**Verification:** Assets work; dotfiles, backups and files outside the root are unavailable.

Primary documentation: [reference 1](https://expressjs.com/en/4x/api.html#express.static).

<a id="js-query-shape"></a>

## JS-QUERY-SHAPE. Parameters change type between middleware

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'req\.(query|body|params)|URLSearchParams|querystring|qs\.|Object\.assign|\.\.\.' .
~~~

Review repeated query keys, scalar/array/object forms, parser settings and params/query/body merge order. Compare the checked field with the value actually passed to database/authentication code.

**Vulnerable example:** A validator checks one string, the next layer selects the last value/object, or body overwrites an already verified params owner.

**Fix:** Parse once into a precisely typed DTO; reject duplicates/unexpected structures according to contract. Never merge client fields into server-established principal context.

**Verification:** Duplicates, bracket notation, nested objects and body/query conflicts cannot change owner/filter; ordinary requests retain their results.

Reference: [primary documentation](https://expressjs.com/en/4x/api.html#req.query). The explanation and adaptation recipe were written for this catalog.

<a id="js-middleware-trust"></a>

## JS-MIDDLEWARE-TRUST. Handlers assume middleware has run

**Search:** manual review; no separate scanner rule. This ID identifies a catalog section. The scanner does not establish Next.js version, routing topology or authorization on every execution path.

~~~bash
rg -n --hidden -g '!node_modules/**' -g '!.git/**' -g 'middleware.*' -g 'proxy.*' -g 'next.config.*' -g '*.conf' -e 'matcher|NextResponse\.(next|rewrite|redirect)|x-middleware-subrequest|proxy_pass|proxy_set_header|standalone' .
rg -n --hidden -g '!node_modules/**' -g '!.git/**' -e 'next/server|export.*(GET|POST|PUT|PATCH|DELETE)|use server|verifySession|authorize|"next"|next@' .
~~~

Use the first search to map external entry → proxy/adapter → Next.js → matcher/rewrite → handler. Use the second to trace actual session/permission validation before reads/writes; inspect helper implementations and lockfiles, not only function names or package.json ranges. Test direct backend access bypassing the proxy. Locale/public-page middleware and handlers with independent authorization are similar-looking safe cases.

**Vulnerable example:** In CVE-2025-29927, an external x-middleware-subrequest reached Next.js recursion prevention and bypassed middleware. Handlers relying exclusively on middleware lost authorization. The postmortem confirms self-hosted next start and output: 'standalone' were affected; static export does not execute middleware. Vercel and the examined Netlify/Cloudflare Workers adapters were unaffected because of different routing. These are boundaries of that incident, not a guarantee for every platform configuration. [Developer postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass).

Minimal vulnerable arrangement; verifySession and data functions are project helpers:

~~~javascript
// middleware.js
import { NextResponse } from 'next/server';
import { verifySession } from './lib/auth.js';
export async function middleware(req) {
  if (!(await verifySession(req))) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}
export const config = { matcher: ['/api/notes/:path*'] };
~~~

~~~javascript
// app/api/notes/route.js
import { listNotes } from '../../../lib/data.js';
export async function GET(req) {
  return Response.json(await listNotes());
}
~~~

Historical advisory ranges: >=11.1.4 <12.3.5, >=13.0.0 <13.5.9, >=14.0.0 <14.2.25, >=15.0.0 <15.2.3. Versions 12.3.5, 13.5.9, 14.2.25 and 15.2.3 fix this specific CVE; the advisory lists no fixed 11.x release. [GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw).

**Fix:** Use a supported branch with current security updates. The historical minimum versions above are not present-day installation recommendations: a subsequent internal-header leakage fix required newer releases. [GHSA-223j-4rm8-mrmf](https://github.com/vercel/next.js/security/advisories/GHSA-223j-4rm8-mrmf), [project advisories](https://github.com/vercel/next.js/security/advisories). The upstream patch validates the internal header's origin; its regression test preserves the expected redirect when the header arrives externally. [Fix 52a078d and test](https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2).

Validate sessions and operation permissions in handlers/data access, including Server Actions; middleware may retain early redirects for user experience. verifySession below must verify the session, while listNotesForUser must scope queries to that verified actor, not a request value. [Next.js authorization and DAL](https://nextjs.org/docs/app/guides/authentication).

~~~javascript
// app/api/notes/route.js
import { verifySession } from '../../../lib/auth.js';
import { listNotesForUser } from '../../../lib/data.js';
export async function GET(req) {
  const session = await verifySession(req);
  if (!session) return new Response(null, { status: 401 });
  return Response.json(await listNotesForUser(session.userId));
}
~~~

Unified owner/tenant policy and alternative endpoints are covered by [CFG-OBJECT-POLICY](configuration.md#cfg-object-policy).

A temporary mitigation at the **external** nginx boundary removes client-supplied headers before forwarding to Next.js. Add it to each relevant proxy location while preserving other required headers/settings:

~~~nginx
proxy_set_header x-middleware-subrequest "";
~~~

An empty value omits the header from upstream requests. proxy_set_header directives inherit only when none are defined at the current level: inspect every location and ingress and restrict the backend to trusted entrypoints. This is not a complete proxy configuration. [nginx proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header). Do not indiscriminately remove internal headers on every inter-service hop: legitimate middleware fetch uses them to prevent recursion.

**Verification:** In an authorized environment, repeat tests with and without the externally supplied header. Include:

| Path | Expected result |
|---|---|
| Page, read/write API, rewrite and alternative URL | Anonymous callers receive no private data; owner operations work; foreign data remains inaccessible. |
| Server Action and direct handler call | Authorization runs independently of the page and middleware. |
| Every external ingress and direct backend | Externally supplied internal headers never disable protection; unauthorized backend entry is unavailable. |
| Internal middleware fetch | Expected responses/redirects work without recursive loops. |

Recheck cookies, sessions, response contracts and load after moving authorization: extra storage access and incompatible helpers can break normal operations. This catalog review checked sources and inert scanner examples; it did not execute Next.js or application HTTP tests. A clean scanner report does not prove this manual issue fixed.

<a id="js-redirect-input"></a>

## JS-REDIRECT-INPUT. Request field passed directly to an Express-style redirect

**Search:** scanner rule JS-REDIRECT-INPUT. Use `--explain JS-REDIRECT-INPUT` for the exact detector contract. Regex with lexical comment/string exclusions: res/response.redirect with direct req/request.query/body/params property, optionally following a literal status code. Not receiver typing or data-flow analysis; computed keys, aliases and upstream validation need review.

**Vulnerable example:**

~~~javascript
res.redirect(req.query.next);
~~~

**Fix:** Resolve redirects using a server-owned route table or an explicit normalized URL policy.

~~~javascript
res.redirect('/account');
~~~

**Verification:** External and scheme-relative destinations fail; approved navigation still works.

[Primary reference 1](https://expressjs.com/en/4x/api.html#res.redirect)

<a id="js-log-credentials"></a>

## JS-LOG-CREDENTIALS. Credential-like value passed directly to console

**Search:** scanner rule JS-LOG-CREDENTIALS. Use `--explain JS-LOG-CREDENTIALS` for details. Bounded JS tokens: console log/info/warn/error/debug/trace with direct sensitive names/properties, inline object/array values or concatenation. Observed console shadows/reassignments suppress hints file-wide. Templates, helper calls, custom loggers, dynamic keys and cross-file flows remain manual; absence of a signal does not verify redaction.

**Vulnerable example:**

~~~javascript
console.warn(req.headers.authorization);
~~~

**Fix:** Log stable event categories and approved identifiers, not credential values. Inspect failed-login and exception paths; implement and test any redaction helper independently.

~~~javascript
console.warn('authentication failed');
~~~

**Verification:** Synthetic canary credentials never appear in stdout, logs, exported evidence or screen broadcasts; failure categories remain useful.

[Primary reference](https://nodejs.org/api/console.html)
