# PHP: find, fix and verify

English | [Русский](php-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

23 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [PHP-SQL — Dynamic PHP SQL](#php-sql)
- [PHP-OBJECT — Untrusted PHP unserialize](#php-object)
- [PHP-SHELL — PHP code or shell execution](#php-shell)
- [PHP-INCLUDE — Client-selected include path](#php-include)
- [PHP-PREFIX-MAC — Hash concatenation instead of MAC](#php-prefix-mac)
- [PHP-PARSE-STR — parse_str key normalization](#php-parse-str)
- [PHP-LOOSE-COMPARE — Loose comparison of token or signature](#php-loose-compare)
- [PHP-UPLOAD — Moving an uploaded file](#php-upload)
- [PHP-DISPLAY-ERRORS — PHP displays errors to clients](#php-display-errors)
- [PHP-XSS — Raw data reaches HTML, attributes or JavaScript](#php-xss)
- [PHP-SESSION — Session fixation, strict mode and stale state](#php-session)
- [PHP-WRAPPERS — Filesystem APIs accept URLs or wrappers](#php-wrappers)
- [PHP-EXTRACT — extract overwrites local variables](#php-extract)
- [PHP-SERIALIZE-MAGIC — Magic methods and trust in stored data](#php-serialize-magic)
- [PHP-CSRF — Cookies authorize mutations without CSRF protection](#php-csrf)
- [PHP-REGEX-ERROR — preg_match errors become permission](#php-regex-error)
- [PHP-XML-FLAGS — XML entity substitution or DTD enabled](#php-xml-flags)
- [PHP-TEMPLATE — Template built from dynamic text](#php-template)
- [PHP-CURL-TLS — cURL certificate or hostname checks disabled](#php-curl-tls)
- [PHP-URL-INCLUDE — Remote resource inclusion enabled](#php-url-include)
- [PHP-SESSION-CONFIG — Weakened PHP session configuration](#php-session-config)
- [PHP-MASS-ASSIGN — Array keys choose columns and privileges](#php-mass-assign)
- [PHP-LDAP-FILTER — LDAP filter concatenates a PHP variable](#php-ldap-filter)

<a id="php-sql"></a>

## PHP-SQL. Dynamic PHP SQL

**Search:** scanner rule PHP-SQL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-SQL` for details. Regex: query/exec/prepare with concatenation, double-quoted interpolation and mysqli_query/pg_query with an ordinary connection argument. Escaping, other interpolation and SQL variables are not fully parsed.

**Vulnerable example:**

~~~php
$db->query("SELECT id FROM notes WHERE name=" . $name);
~~~

**Fix:** Use driver-supported prepared statements and bound values; allowlist identifiers.

~~~php
$stmt = $db->prepare("SELECT id FROM notes WHERE name = ?");
$stmt->execute([$name]);
~~~

**Verification:** Quotes stay data and ownership conditions remain.

<details>
<summary>Expanded example and limitations</summary>

```php
// Vulnerable: client input is interpolated into SQL.
$row = $pdo->query("SELECT body FROM notes WHERE id = '" . $_GET['id'] . "'")->fetch();
```

**PDO patch for a private note:**

```php
function readPrivateNote(PDO $pdo, ?int $userId, int $noteId): ?string {
    if ($userId === null) {
        throw new RuntimeException('authentication required');
    }
    $stmt = $pdo->prepare('SELECT body FROM notes WHERE id = :id AND owner_id = :owner');
    $stmt->bindValue(':id', $noteId, PDO::PARAM_INT);
    $stmt->bindValue(':owner', $userId, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row === false ? null : $row['body'];
}
```

Validate the numeric ID first: `(int) $_GET['id']` silently converts some invalid strings. Configure PDO error handling and do not return SQL exceptions to clients. Placeholders represent values, not table/column names. Native prepares may be appropriate for supported drivers, but do not change application-wide settings blindly; driver behavior differs.

**Check:** Owner, other user, no session, missing record, invalid ID and another searchable text field containing an apostrophe. Preserve intended sharing.

</details>

<a id="php-object"></a>

## PHP-OBJECT. Untrusted PHP unserialize

**Search:** scanner rule PHP-OBJECT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-OBJECT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~php
$value = unserialize($data);
~~~

**Fix:** Prefer schema-validated JSON; migrate trusted legacy records separately. allowed_classes alone is not a complete input policy.

~~~php
$value = json_decode($data, true, 32, JSON_THROW_ON_ERROR); // validate schema
~~~

**Verification:** Unexpected object types fail without construction; valid records stay readable.

<details>
<summary>Expanded example and limitations</summary>

```php
// Vulnerable with untrusted input: object restoration has side effects.
$profile = unserialize($_COOKIE['profile']);
```

**Patch for a simple profile when the protocol supports JSON:**

```php
function decodeProfile(string $raw): array {
    $value = json_decode($raw, false, 32, JSON_THROW_ON_ERROR);
    if (!($value instanceof stdClass)) {
        throw new InvalidArgumentException('object required');
    }
    $fields = get_object_vars($value);
    if (array_keys($fields) !== ['display_name'] || !is_string($fields['display_name'])) {
        throw new InvalidArgumentException('unexpected profile fields');
    }
    return ['display_name' => $fields['display_name']];
}
```

Depth 32 is an example bound, not a competition requirement; bound body size before parsing according to contract. Role and owner come from the server. PHP warns against untrusted unserialize even with allowed_classes: that flag alone is not a complete fix.

**Check:** Valid profile, unknown field, array instead of object, wrong type and malformed JSON. Format migration must support old clients/data; never retain unserialize fallback for client strings.

</details>

<a id="php-shell"></a>

## PHP-SHELL. PHP code or shell execution

**Search:** scanner rule PHP-SHELL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-SHELL` for details. Regex: eval/shell_exec/system/passthru/popen/exec and string/variable proc_open. Literal argv arrays in proc_open's first argument (including PHP 8 command:) are excluded unless explicitly launching shell; arrays require PHP 7.4+. Review executable/options, reordered named arguments, backticks, variable functions, wrappers and runtime version. Custom same-named functions/comments may match.

**Vulnerable example:**

~~~php
shell_exec($command);
~~~

**Fix:** Prefer a library operation; otherwise use a fixed executable and validated argv without a shell.

~~~php
$size = filesize($checkedPath);
~~~

**Verification:** Metacharacters and dangerous options cannot change the operation.

proc_open accepts argv arrays from PHP 7.4; the named command argument requires PHP 8.0. Arrays pass arguments without an implicit shell. A genuinely required utility can run without shell, for example on PHP 8+:

~~~php
$process = proc_open(
    command: ['/usr/bin/file', '--', $checkedName],
    descriptor_spec: $descriptors,
    pipes: $pipes
);
~~~

The executable is fixed; $checkedName still needs authorization and path checks. `--` is valid only for utilities supporting that separator. `command: array('/usr/bin/file', '--', $checkedName)` also avoids PHP-SHELL. The exclusion covers only a literal-array first argument; reordered named arguments and variable arrays remain review signals. [proc_open arrays and Windows limitations](https://github.com/php/doc-en/blob/master/reference/exec/functions/proc-open.xml#L68), [PHP 8 named arguments](https://www.php.net/manual/en/migration80.new-features.php#migration80.new-features.core.named-arguments), [PHP 8.0 proc_open signature](https://github.com/php/php-src/blob/php-8.0.0/ext/standard/basic_functions.stub.php#L1156).

Explicit shell execution remains risky and still signals even with an array:

~~~php
$process = proc_open(command: ['sh', '-c', $command], descriptor_spec: $descriptors, pipes: $pipes);
~~~

Do not convert a pipeline to argv by simply splitting text: move operations to a library or connect processes explicitly. Review executable, options, PATH, cwd and environment. On Windows array escaping assumes VC-runtime-compatible command-line parsing; other parsers may differ. Close pipes/processes and check errors, runtime/output limits and the old result format.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'proc_open|proc_close|proc_terminate|shell_exec|descriptor_spec|bypass_shell' .
~~~

After a match trace actual argv and every argument's origin. In an authorized test environment check spaces, quotes, leading dashes, normal files and process failure. Absence of PHP-SHELL does not prove argument safety. This catalog review checked source and scanner behavior; it did not run PHP or the discovered commands.

<a id="php-include"></a>

## PHP-INCLUDE. Client-selected include path

**Search:** scanner rule PHP-INCLUDE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-INCLUDE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~php
include $_GET['page'];
~~~

**Fix:** Select server-owned include paths from a closed allowlist, never client paths/URLs.

~~~php
$pages = ['home' => __DIR__ . '/pages/home.php'];
if (!isset($pages[$page])) { throw new Exception('bad page'); }
include $pages[$page];
~~~

**Verification:** Only approved pages load; traversal and remote schemes fail.

<details>
<summary>Expanded example and limitations</summary>

```php
// Vulnerable: the client controls the executable PHP file path.
include $_GET['page'];
```

**Patch when the contract selects one of several known pages:**

```php
$pages = [
    'help' => __DIR__ . '/pages/help.php',
    'profile' => __DIR__ . '/pages/profile.php',
];
$page = $_GET['page'] ?? 'help';
if (!is_string($page) || !array_key_exists($page, $pages)) {
    http_response_code(404);
    exit;
}
require $pages[$page];
```

The server defines paths. The profile page still requires authorization before private data is returned. basename() neither restricts selection to the intended pages nor checks access. If the feature displays user-uploaded files, include must not implement that display.

**Check:** Both normal pages, unknown names and an array in place of page; anonymous callers cannot open private pages; only permitted selection changes.

</details>

<a id="php-prefix-mac"></a>

## PHP-PREFIX-MAC. Hash concatenation instead of MAC

**Search:** scanner rule PHP-PREFIX-MAC. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-PREFIX-MAC` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~php
$tag = sha1($key . $payload);
~~~

**Fix:** Use HMAC rather than a hash of secret concatenated with data, compare with hash_equals and migrate/version old formats.

~~~php
$tag = hash_hmac('sha256', $payload, $key);
~~~

**Verification:** Changed/appended data fails; tags bind purpose and all authentication fields.

**A/D variant:** Secret-prefix hash mislabeled HMAC. **ECSC / Diese, author and source.** Signatures used SHA1(secret || data). **Patch:** Real HMAC, token versioning and safe migration of existing signatures. **Test:** Changed/added fields fail validation. **Search:** PHP-PREFIX-MAC; a function named hmac guarantees nothing.

[source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [source/write-up 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

<a id="php-parse-str"></a>

## PHP-PARSE-STR. parse_str key normalization

**Search:** scanner rule PHP-PARSE-STR. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-PARSE-STR` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~php
parse_str($token_data, $params);
~~~

**Fix:** Use identical schemas before signing/after parsing; account for dots/spaces becoming underscores, arrays and duplicate keys.

~~~php
$params = parse_and_validate_canonical_share_dto($token_data); // one schema, duplicate policy, server-owned fields
~~~

**Verification:** Alternate spellings cannot change owner/document; signer and verifier agree.

**A/D variant:** Parameter-key normalization after signing. **ECSC / Diese, author and source.** parse_str merges certain distinct names and changes field meaning. **Patch:** An allowlist and one canonical signer/verifier DTO schema; reject ambiguous duplicates. **Test:** Dots, spaces, underscores and arrays. **Search:** PHP-PARSE-STR; the call itself need not be vulnerable.

[source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [source/write-up 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

<a id="php-loose-compare"></a>

## PHP-LOOSE-COMPARE. Loose comparison of token or signature

**Search:** scanner rule PHP-LOOSE-COMPARE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-LOOSE-COMPARE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~php
$ok = $token == $provided;
~~~

**Fix:** Validate types; use hash_equals for tags, === for ordinary values and password_verify for passwords. Numeric-string semantics depend on version/operands.

~~~php
$ok = is_string($provided) && hash_equals($token, $provided);
~~~

**Verification:** Numbers, arrays and numeric strings cannot grant access; valid values work.

**Reference:** [primary source](https://www.php.net/manual/en/language.operators.comparison.php).

<a id="php-upload"></a>

## PHP-UPLOAD. Moving an uploaded file

**Search:** scanner rule PHP-UPLOAD. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-UPLOAD` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~php
move_uploaded_file($tmp, $webroot . $name);
~~~

**Fix:** Check upload error/size/type; use non-overwriting server-generated names outside executable web roots and authorize downloads.

~~~php
move_uploaded_file($validatedTmp, $serverChosenPrivatePath);
~~~

**Verification:** Test upload/download, collisions, wrong owner/type and full disk. The call remains a review signal.

**Reference:** [primary source](https://www.php.net/manual/en/features.file-upload.php).

<a id="php-display-errors"></a>

## PHP-DISPLAY-ERRORS. PHP displays errors to clients

**Search:** scanner rule PHP-DISPLAY-ERRORS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-DISPLAY-ERRORS` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~php
display_errors = On
~~~

**Fix:** Disable client error output and retain redacted local logs; check effective php.ini/FPM and runtime ini_set.

~~~php
display_errors = Off
~~~

**Verification:** Parse/database/type errors yield expected public responses while private diagnostics remain.

**Reference:** [primary source](https://www.php.net/manual/en/errorfunc.configuration.php).

<a id="php-xss"></a>

## PHP-XSS. Raw data reaches HTML, attributes or JavaScript

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'echo|print|htmlspecialchars|json_encode|<script' .
~~~

Identify the output context; htmlspecialchars for HTML text does not make a string safe JavaScript.

**Vulnerable example:**

`echo $title` inside HTML lacks encoding; JSON enters script without an appropriate serializer.

**Fix:** Template autoescape or htmlspecialchars with ENT_QUOTES/ENT_SUBSTITUTE and UTF-8 for HTML; separate safe JavaScript/URL handling.

**Verification:** Quotes, tags and Unicode render as data; legitimate formatting remains intact.

<details>
<summary>Expanded example and limitations</summary>

```php
// Vulnerable with untrusted title: the browser interprets it as markup.
echo '<p>' . $title . '</p>';
```

**Patch for HTML text content:**

```php
echo '<p>' . htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
```

Validate $title as a string first. Store original text and encode on output to avoid cumulative double escaping during edits. This is not JavaScript/CSS encoding or URL validation; those contexts need different mechanisms. Intentionally supported HTML requires sanitizing the permitted subset rather than turning all markup into text.

**Check:** <, >, &, quotes and Unicode render as text; existing records and save/open/edit cycles preserve original content.

</details>

<a id="php-session"></a>

## PHP-SESSION. Session fixation, strict mode and stale state

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'session_start|session_regenerate_id|session.use_strict_mode|session_id' .
~~~

Trace externally supplied session IDs, login-time regeneration and role storage.

**Vulnerable example:**

An unknown external ID is accepted and remains unchanged after login.

**Fix:** session.use_strict_mode, supported regeneration with concurrent requests considered, server-derived roles and consistent Secure/HttpOnly/SameSite settings.

**Verification:** The old ID cannot authorize; normal parallel requests retain state.

**Reference:** [primary source](https://www.php.net/manual/en/session.security.ini.php).

<a id="php-wrappers"></a>

## PHP-WRAPPERS. Filesystem APIs accept URLs or wrappers

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'file_get_contents|fopen|copy\(|file_exists|is_file|phar|stream_context' .
~~~

Determine whether each API accepts a path or stream URL; check installed PHP version and required wrappers.

**Vulnerable example:**

Users select a scheme/local path instead of an allowed object; open_basedir is not a complete sandbox.

**Fix:** Server-side paths derived from authorized IDs; a separate policy-constrained HTTP client for URLs; no client-selected wrapper.

**Verification:** Valid files load; external URLs, foreign files and unsupported schemes never reach the operation.

<a id="php-extract"></a>

## PHP-EXTRACT. extract overwrites local variables

**Search:** scanner rule PHP-EXTRACT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-EXTRACT` for details. Regex: any extract(...); trusted template contexts need manual classification.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'extract\(|parse_str|\$\$|GLOBALS|register_globals' .
~~~

Compare imported keys with authorization/config variable names; two-argument parse_str has a different risk from its historical behavior.

**Vulnerable example:**

`extract($_REQUEST)` overwrites locals, or `$$key` selects a sensitive variable.

**Fix:** Read explicit allowed fields. EXTR_SKIP reduces overwrites but does not replace schema/type and new-name controls.

**Verification:** Input is_admin/owner/config cannot alter access; approved values retain types.

**Reference:** [primary source](https://www.php.net/manual/en/function.extract.php).

**Scanner example before:**

~~~php
extract($_POST);
if ($is_admin) { show_private_data(); }
~~~

**Fix template:**

~~~php
$display_name = validate_display_name($_POST['display_name'] ?? '');
~~~

Primary documentation: [reference 1](https://www.php.net/manual/en/function.extract.php).

<a id="php-serialize-magic"></a>

## PHP-SERIALIZE-MAGIC. Magic methods and trust in stored data

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '__wakeup|__unserialize|__destruct|__toString|unserialize' .
~~~

Trace PHP-OBJECT sinks to reachable classes and side effects; a database is not trusted merely because client input was stored there.

**Vulnerable example:**

A deserialized object performs file/network operations before its result is checked.

**Fix:** DTOs without type selection or side effects; separate compatible migration, not fallback to an unsafe parser.

**Verification:** Unknown types have no effects; legitimate legacy formats follow the migration plan.

<a id="php-csrf"></a>

## PHP-CSRF. Cookies authorize mutations without CSRF protection

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'csrf|POST|PUT|DELETE|REQUEST_METHOD|SameSite' .
~~~

Review forms and cookie-authenticated JSON endpoints, middleware exceptions and Origin/Referer policies.

**Vulnerable example:**

The browser automatically attaches a cookie to state-changing requests from another context.

**Fix:** Framework CSRF tokens and architecture-appropriate origin checks. SameSite supplements, not replaces, server-side checks. Bearer APIs have a different threat context.

**Verification:** Wrong/missing tokens fail; normal forms and supported API clients work.

<a id="php-regex-error"></a>

## PHP-REGEX-ERROR. preg_match errors become permission

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'preg_match|preg_last_error|preg_replace' .
~~~

Distinguish false, 0 and 1; find negated results and regex limits.

**Vulnerable example:**

An engine error on long input enters the 'prohibited content not found' branch.

**Fix:** Compare results strictly against 1/0/false according to meaning; fail closed on errors and bound length/complexity.

**Verification:** Match, no-match and engine errors produce distinct expected responses; normal Unicode remains supported.

**Reference:** [primary source](https://www.php.net/manual/en/function.preg-match.php).

<a id="php-xml-flags"></a>

## PHP-XML-FLAGS. XML entity substitution or DTD enabled

**Search:** scanner rule PHP-XML-FLAGS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-XML-FLAGS` for details. Regex: LIBXML_NOENT/DTDLOAD/DTDATTR/DTDVALID and substituteEntities/resolveExternals=true. Numeric ini/database masks are not decoded; inspect bits against runtime constants.

**Vulnerable example:** NOENT substitutes entities; NONET alone does not prevent local-file access.

~~~php
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_NONET);
~~~

**Fix:** Disable entity substitution/external DTD loading, bound input and check libxml version. Use LIBXML_NO_XXE where supported; NONET alone is insufficient.

~~~php
$doc->resolveExternals = false;
$doc->substituteEntities = false;
$doc->loadXML($boundedXml, LIBXML_NONET);
~~~

**Verification:** Ordinary XML works; entities/DTD read no files or network and nesting/size are limited.

Primary documentation: [reference 1](https://www.php.net/manual/en/libxml.constants.php), [reference 2](https://github.com/enowars/enowars7-service-oldschool#vulnerabilities).

<a id="php-template"></a>

## PHP-TEMPLATE. Template built from dynamic text

**Search:** scanner rule PHP-TEMPLATE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-TEMPLATE` for details. Regex: createTemplate($...) and Smarty display/fetch with eval: or string:. Inspect variable loaders, custom filters and database templates.

**Vulnerable example:** When user data becomes template source, users gain the template engine's capabilities.

~~~php
$template = $twig->createTemplate($profileText);
echo $template->render($vars);
~~~

**Fix:** Separate trusted template source from values; user templates need explicit sandbox/loader/function/resource policy.

~~~php
echo $twig->render('profile.html.twig', ['about' => $profileText]);
~~~

**Verification:** Profile template expressions remain data; private templates/files are unavailable.

Primary documentation: [reference 1](https://twig.symfony.com/doc/3.x/api.html#loading-templates-from-a-string).

<a id="php-curl-tls"></a>

## PHP-CURL-TLS. cURL certificate or hostname checks disabled

**Search:** scanner rule PHP-CURL-TLS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-CURL-TLS` for details. Regex: CURLOPT_SSL_VERIFYPEER=false/0 and CURLOPT_SSL_VERIFYHOST=false/0/1 in arguments/setopt_array. Variable values are not evaluated.

**Vulnerable example:** Disabling server validation permits substitution of outbound HTTPS results.

~~~php
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
~~~

**Fix:** Verify peer and hostname with the trusted CA; use VERIFYHOST=2, not historical ambiguous 1.

~~~php
curl_setopt_array($ch, [CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_CAINFO => $trustedCA]);
~~~

**Verification:** Correct CA/host works; wrong CA/host and expiry fail without fallback.

Primary documentation: [reference 1](https://www.php.net/manual/en/function.curl-setopt.php).

<a id="php-url-include"></a>

## PHP-URL-INCLUDE. Remote resource inclusion enabled

**Search:** scanner rule PHP-URL-INCLUDE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-URL-INCLUDE` for details. Regex: allow_url_include=On/1/true in ini/config/assignment. Review runtime overrides and effective include paths separately.

**Vulnerable example:** URL include increases the consequences of controlling an include/require path.

~~~config
allow_url_include = On
~~~

**Fix:** Disable allow_url_include in the effective SAPI config; select include paths from a closed server-side map.

~~~config
allow_url_include = Off
~~~

**Verification:** Normal modules load; client URLs cannot become executable code.

Primary documentation: [reference 1](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include).

<a id="php-session-config"></a>

## PHP-SESSION-CONFIG. Weakened PHP session configuration

**Search:** scanner rule PHP-SESSION-CONFIG. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PHP-SESSION-CONFIG` for details. Regex: explicit unsafe use_strict_mode/use_only_cookies/use_trans_sid values. Missing settings and ini_set argument forms need manual review.

**Vulnerable example:** Attacker-selected session IDs and IDs in URLs enable fixation or leakage.

~~~config
session.use_strict_mode = 0
session.use_only_cookies = 0
session.use_trans_sid = 1
~~~

**Fix:** Enable strict mode and cookie-only transport, disable URL rewriting and regenerate IDs at login; review custom handlers/cookies.

~~~config
session.use_strict_mode = 1
session.use_only_cookies = 1
session.use_trans_sid = 0
~~~

**Verification:** Unknown fixed IDs fail, login changes the ID, URLs/logs contain no IDs and sessions work.

Primary documentation: [reference 1](https://www.php.net/manual/en/session.configuration.php).

<a id="php-mass-assign"></a>

## PHP-MASS-ASSIGN. Array keys choose columns and privileges

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '\$_(POST|GET|REQUEST)|array_keys|array_merge|profileData|UPDATE|SET|fill\(|update\(' .
~~~

Trace keys as well as values from requests into UPDATE/ORM and owner/admin/association assignment. Review nested fields and numeric indices.

**Vulnerable example:** SQL values are parameterized but column names come from request keys; role fields or relationships to foreign objects are updated wholesale.

**Fix:** Explicitly map allowed input fields to fixed columns and types. Check privileges, owners and relationships separately; placeholders do not escape SQL identifiers.

**Verification:** Unknown columns, administrative fields and foreign relationships fail without mutation; allowed fields persist.

Reference: [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html). The explanation and adaptation recipe were written for this catalog.

**A/D variant:** Oldschool's mass update could change an administrative relationship; column names also entered SQL without restriction. [Author description](https://github.com/enowars/enowars7-service-oldschool#vulnerabilities).

<a id="php-ldap-filter"></a>

## PHP-LDAP-FILTER. LDAP filter concatenates a PHP variable

**Search:** scanner rule PHP-LDAP-FILTER. Use `--explain PHP-LDAP-FILTER` for the exact detector contract. Regex with lexical exclusions: ldap_search/list/read with simple first two arguments and a string concatenated directly with a variable as the third argument. Variables may already be escaped; prebuilt filters and interpolation need manual review.

**Vulnerable example:**

~~~php
ldap_search($conn, $base, '(uid=' . $name . ')');
~~~

**Fix:** Escape values for LDAP filter context, not DN context; keep attribute names and search scope trusted.

~~~php
$filter = '(uid=' . ldap_escape($name, '', LDAP_ESCAPE_FILTER) . ')';
ldap_search($conn, $base, $filter);
~~~

**Verification:** LDAP metacharacters in a value do not widen results; authorized lookups work.

[Primary reference 1](https://www.php.net/manual/en/function.ldap-escape.php)
