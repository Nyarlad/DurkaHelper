# Python: find, fix and verify

English | [Русский](python-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

40 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [PY-EVAL — Executing text as Python](#py-eval)
- [PY-SHELL — Python shell execution](#py-shell)
- [PY-DESERIALIZE — Python object deserialization](#py-deserialize)
- [PY-YAML — YAML with a potentially unsafe loader](#py-yaml)
- [PY-SQL — SQL assembled from string expressions](#py-sql)
- [PY-ORM-BOOL — Python and/or used in an ORM expression](#py-orm-bool)
- [PY-TEMPLATE — Dynamic template source](#py-template)
- [PY-TLS — TLS verify=False](#py-tls)
- [PY-DEBUG — Python web debugger enabled](#py-debug)
- [PY-JWT — JWT signature verification disabled](#py-jwt)
- [PY-ARCHIVE — Archive extraction requires path review](#py-archive)
- [PY-TEMP — Non-atomic temporary filename](#py-temp)
- [PY-XML — XML entity resolution enabled](#py-xml)
- [PY-WEAK-HASH — MD5/SHA1: review the purpose](#py-weak-hash)
- [PY-RNG — Non-cryptographic randomness near a possible secret](#py-rng)
- [PY-FILE — Dynamic file-serving path](#py-file)
- [PY-URL — Dynamic outbound URL](#py-url)
- [PY-CRC — CRC/Adler near an integrity boundary](#py-crc)
- [PY-XPATH — XPath assembled from strings](#py-xpath)
- [PY-UUID-BYTES — UUID bytes/bytes_le protocol boundary](#py-uuid-bytes)
- [PY-ASSERT-AUTH — Access control using assert](#py-assert-auth)
- [PY-DJANGO-HOSTS — Django wildcard ALLOWED_HOSTS](#py-django-hosts)
- [PY-HTML-SAFE — HTML escaping explicitly bypassed](#py-html-safe)
- [PY-MASS-ASSIGN — Request fields become model attributes](#py-mass-assign)
- [PY-DECORATOR-AUTH — A route is registered before the authorization wrapper](#py-decorator-auth)
- [PY-ASYNC-CONTEXT — Global current_user leaks across async requests](#py-async-context)
- [PY-REDIRECT — Dynamic redirect destination](#py-redirect)
- [PY-PASSWORD-HASH — Fast digests used for password storage](#py-password-hash)
- [PY-ZIP-LIMITS — Archive traversal, symlinks and expanded volume](#py-zip-limits)
- [PY-JSON-DUPLICATES — Parsers disagree on repeated keys](#py-json-duplicates)
- [PY-CACHE-KEY — Authorization-cache key collisions](#py-cache-key)
- [PY-JWT-DEPENDENCY — Vulnerable JWT-verification dependencies](#py-jwt-dependency)
- [PY-CHALLENGE-STATE — Challenge disclosure before commitment](#py-challenge-state)
- [PY-SSL-CONTEXT — TLS context verification disabled](#py-ssl-context)
- [PY-CSRF-EXEMPT — Django view excluded from CSRF](#py-csrf-exempt)
- [PY-JWT-ALGORITHMS — JWT algorithms taken from an expression](#py-jwt-algorithms)
- [PY-JWT-CLAIMS — JWT expiry or recipient checks disabled](#py-jwt-claims)
- [PY-REGEX-DYNAMIC — Dynamic regular-expression pattern](#py-regex-dynamic)
- [PY-AUTH-DECORATOR — Flask route registers before login protection](#py-auth-decorator)
- [PY-LOG-CREDENTIALS — Credential-like value passed directly to logging](#py-log-credentials)

<a id="py-eval"></a>

## PY-EVAL. Executing text as Python

**Search:** scanner rule PY-EVAL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-EVAL` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
eval(payload)
~~~

**Fix:** Use JSON plus a schema for data, or a limited parser for a DSL; do not move code into another eval.

~~~python
import json
value = json.loads(payload)
if not isinstance(value, dict):
    raise ValueError('object required')
~~~

**Verification:** Valid documents parse, Python expressions are not executed, and input size is bounded.

<a id="py-shell"></a>

## PY-SHELL. Python shell execution

**Search:** scanner rule PY-SHELL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-SHELL` for details. AST: explicit shell=True or inline **dict, shell helpers and literal shell argv in subprocess/asyncio.create_subprocess_exec. Variable argv, wrappers and complex branching are not evaluated.

**Vulnerable example:**

~~~python
import subprocess
subprocess.run(command, shell=True)
~~~

**Fix:** Use a fixed executable and separate argv without a shell; allowlist arguments according to the utility contract.

~~~python
import subprocess
subprocess.run(['/usr/bin/file', '--', filename], shell=False, check=True, timeout=3)
~~~

**Verification:** Metacharacters remain data, dangerous options fail, and normal operations work.

<details>
<summary>Expanded example and limitations</summary>

**Recognize:** User text is concatenated into a command using shell=True.

```python
# Vulnerable: data becomes part of an interpreter command.
digest = subprocess.check_output("printf '%s' '" + text + "' | sha256sum", shell=True)
```

**Patch for a content SHA-256 digest:**

<!-- example: py-sha256 -->

```python
import hashlib

def digest_text(text):
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
```

Preserve expected encoding and response format. The sha256sum shell utility prints extra fields/newlines that the API may process separately. If a command serves another purpose, see [argument boundaries](README.md).

**Check:** Known digest, empty text, quotes, newlines, Unicode and no external execution. This recipe is not suitable for password hashing.

</details>

<a id="py-deserialize"></a>

## PY-DESERIALIZE. Python object deserialization

**Search:** scanner rule PY-DESERIALIZE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-DESERIALIZE` for details. AST: pickle/dill/shelve, jsonpickle.decode/loads, joblib.load, pandas.read_pickle and direct or simply assigned Unpickler(...).load. numpy.load and numpy.lib.format.read_array require known allow_pickle=True (keyword or third/second positional argument respectively). Import aliases, simple scalar assignments and inline **dict are supported; old defaults, mutable dictionaries, wrappers and data trust need review.

**Vulnerable example:**

~~~python
import pickle
value = pickle.loads(data)
~~~

**Fix:** For pickle-like formats, use schema-validated JSON where compatible and migrate trusted legacy records separately. For NumPy retain numeric .npy/.npz with allow_pickle=False, dtype/shape and size checks; migrate object arrays separately. Never load an untrusted pickle to convert it.

~~~python
import json
value = json.loads(data)  # validate schema
~~~

**Verification:** Valid records remain readable; unknown fields/types and object arrays fail; dtype, shape and volume are checked.

<details>
<summary>Expanded example and limitations</summary>

**Recognize:** Pickle arrives from cookies, request bodies, uploads or database rows previously writable by clients. Base64 does not establish trust.

```python
# Vulnerable with untrusted raw input: loading can execute code.
profile = pickle.loads(raw)
```

**Patch for simple profile exchange**, if the protocol already permits JSON or a compatible migration is agreed:

<!-- example: py-profile -->

```python
import json

def decode_profile(raw):
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"display_name"}:
        raise ValueError("unexpected profile fields")
    if not isinstance(value["display_name"], str):
        raise ValueError("display_name must be a string")
    return {"display_name": value["display_name"]}
```

The HTTP layer must bound body size before reading; a JSON schema does not automatically bound parsing cost. Role and owner are server-derived. Never fall back to pickle.loads after JSON errors or migrate old records with an unsafe parser before establishing their trusted origin.

**Check:** Valid names, Unicode and permitted empty values work; arrays, numbers and unknown administrative fields fail; old clients/data remain compatible. If the checker requires the old format, parser replacement without a migration plan is not deployable.

</details>

Object-oriented JSON also needs scrutiny: jsonpickle.decode is not ordinary json.loads. [jsonpickle](https://jsonpickle.readthedocs.io/en/latest/), [joblib.load](https://joblib.readthedocs.io/en/stable/generated/joblib.load.html) and [pandas.read_pickle](https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html) warn about untrusted input. Establish serialized-object provenance before loading.

**NumPy object arrays.** numpy.load with allow_pickle=True permits object deserialization from files. It is numpy.load's third positional argument and numpy.lib.format.read_array's second. Determine whether clients can replace the file/storage record; .npy/.npz extensions prove nothing. [numpy.load](https://numpy.org/doc/stable/reference/generated/numpy.load.html), [read_array](https://numpy.org/doc/stable/reference/generated/numpy.lib.format.read_array.html).

~~~python
import numpy as np
values = np.load(upload_path, allow_pickle=True)
~~~

For a numeric .npy contract, the proposed patch preserves array format:

~~~python
import numpy as np
values = np.load(upload_path, allow_pickle=False)
if not isinstance(values, np.ndarray) or values.dtype.kind not in "iuf":
    raise ValueError("numeric array required")
~~~

Validate permitted dtypes, dimensions and element counts. Bound input before loading; checks after array allocation do not replace memory limits. allow_pickle=False rejects legacy object arrays: migrate trusted data first, with no unsafe fallback. For .npz preserve the container API and close NpzFile; the example above is only for one numeric .npy array.

Search parameters/versions manually without importing the target project:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'numpy|allow_pickle|read_array|requirements|poetry.lock|uv.lock' .
~~~

Connect imports to calls and inspect lockfiles/deployed metadata plus actual file origins. The scanner cannot establish package version, file trust or values in variable dictionaries. Omitted allow_pickle does not signal: check that version's default. Verify old numeric dtypes/shapes still load, object arrays fail without executing content, oversized input is bounded and old data follows the migration plan.

<a id="py-yaml"></a>

## PY-YAML. YAML with a potentially unsafe loader

**Search:** scanner rule PY-YAML. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-YAML` for details. AST: yaml.load/load_all/unsafe_load/unsafe_load_all, excluding SafeLoader/CSafeLoader/BaseLoader/CBaseLoader, with import aliases, positional Loader and inline **dict. BaseLoader/CBaseLoader return scalars as strings. Review version defaults, wrappers and resource limits.

**Vulnerable example:**

~~~python
import yaml
value = yaml.load(data, Loader=yaml.Loader)
~~~

**Fix:** Use safe_load, validate fields/types, and bound document size and complexity.

~~~python
import yaml
value = yaml.safe_load(data)  # validate schema
~~~

**Verification:** Ordinary YAML works; object tags and unexpected structures fail.

yaml.BaseLoader/CBaseLoader do not instantiate arbitrary Python objects and do not trigger this rule. They turn scalars into strings: false is not False, and a nonempty string is truthy. They are appropriate only with explicit schema-based string conversion; never replace SafeLoader globally without type tests. SafeLoader/CSafeLoader preserve standard YAML types but do not replace schemas or size/depth bounds. Review custom constructors separately. [PyYAML loaders/types](https://pyyaml.org/wiki/PyYAMLDocumentation).

~~~python
import yaml
raw_settings = yaml.load(data, Loader=yaml.BaseLoader)
# Strings are expected; validate structure and convert fields separately.
~~~

For wrappers, loader overrides and versions:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'yaml[.]|Loader|add_constructor|PyYAML|requirements|poetry.lock|uv.lock' .
~~~

Match calls to imports, selected loaders and registered constructors. Read versions from lockfiles/deployment metadata without importing the service. Test numbers, booleans, dates, empty scalars and legacy documents on the actual runtime. With a BaseLoader contract, no PY-YAML signal means only no recognized dangerous object loading, not proven parser safety.

<a id="py-sql"></a>

## PY-SQL. SQL assembled from string expressions

**Search:** scanner rule PY-SQL. Use `--explain PY-SQL` for the exact detector contract. AST: string construction at SQL sinks and keywords, including simple assignments. Imported psycopg/psycopg2.sql SQL(nonliteral) or format/join with unknown/raw pieces signal. Literal SQL plus known Identifier/Literal/Placeholder compositions suppress this signal only, not identifier authorization. Mutable composition, wrappers, cross-function flows and driver versions remain manual.

**Vulnerable example:**

~~~python
db.execute("SELECT id FROM notes WHERE name=%s" % name)
~~~

**Fix:** Bind values using the actual driver's parameter API; select identifiers from a server-side allowlist.

~~~python
db.execute("SELECT id FROM notes WHERE name=?", (name,))  # sqlite3
~~~

**Verification:** Quotes remain data; ownership restrictions and normal queries remain correct.

Splitting fixed SQL across string literals does not introduce injection:

~~~python
db.execute("SELECT " + "1")
db.execute(f"SELECT 1")
~~~

These forms do not trigger PY-SQL. The exception covers literals, their concatenation and f-strings without substitutions, not general constant evaluation. .format() still signals and needs review. No signal proves neither ownership nor fixed-query meaning nor driver settings. Keep bind parameters for user values instead of switching interpolation styles. [sqlite3 query parameters](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).

<details>
<summary>Expanded example and limitations</summary>

**Recognize:** execute with f-strings, %, .format() or concatenated SQL; object selection lacks ownership checks.

```python
# Vulnerable: client_id controls SQL; ownership is not constrained.
row = db.execute(f"SELECT body FROM notes WHERE id = '{client_id}'").fetchone()
```

**Minimal sqlite3 patch for private notes:**

<!-- example: py-read-note -->

```python
def read_private_note(db, user_id, note_id):
    if user_id is None:
        raise PermissionError("authentication required")
    row = db.execute(
        "SELECT body FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user_id),
    ).fetchone()
    if row is None:
        raise LookupError("not found")
    return row[0]
```

`?` is sqlite3 syntax. With psycopg use %s **inside SQL** plus a separate value tuple, never Python's % interpolation operator. Column names do not become safe by passing them as value parameters.

**Check:** Owners read old records; other users/anonymous callers cannot. Quoted string IDs remain values; list/export paths enforce the same policy. Validate numeric IDs where required by contract.

</details>

**A/D variant:** SQL blacklists overlook interactions between parameters. **ECSC / fonograph, author write-up.** Character filtering did not preserve boundaries between neighboring string arguments. **Patch:** Driver parameters instead of manual assembly/blacklists. **Test:** Quotes/backslashes in each parameter and combinations, plus normal text. **Search:** PY-SQL; a sanitize function's presence does not clear the finding.

[source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/db.py); [source/write-up 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/handlers.py).

<a id="py-orm-bool"></a>

## PY-ORM-BOOL. Python and/or used in an ORM expression

**Search:** scanner rule PY-ORM-BOOL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-ORM-BOOL` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
User.find(User.name == name and User.password == password)
~~~

**Fix:** Use the ORM's documented expression composition, not Python short-circuit operators; retain all ownership/authentication predicates.

~~~python
User.find(User.name == name, User.password == password)  # Beanie
~~~

**Verification:** Both predicates appear in the actual query; wrong passwords and other users' objects fail.

**A/D variant:** Python and instead of Beanie predicate composition. **Reference:** explorers, CTF Cup source and pinned Beanie 1.23.6. Full MongoDB authorization was not reproduced here. The scanner found PY-ORM-BOOL in the source.

~~~python
# before
User.find(User.username == name and User.password == password)
# after: Beanie accepts multiple criteria
User.find(User.username == name, User.password == password)
~~~

**Test:** All four valid/invalid username/password combinations, different users and empty values; inspect the actual generated filter. Use the installed ORM's API rather than copying unrelated syntax.

[source/write-up 1](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/app/api.py); [source/write-up 2](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/requirements.txt).

<a id="py-template"></a>

## PY-TEMPLATE. Dynamic template source

**Search:** scanner rule PY-TEMPLATE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-TEMPLATE` for details. AST: render_template_string/from_string by method name, first argument or source=, import aliases and inline **dict. Nonliteral source requires review; custom same-named methods may match. Review dictionary variables, wrappers, environment type, trust and autoescape.

**Vulnerable example:**

~~~python
from flask import render_template_string
render_template_string(source=user_text)
~~~

**Fix:** Keep template source trusted and pass untrusted values as parameters; review autoescape and loader boundaries.

~~~python
from flask import render_template_string
render_template_string(source='<p>{{ message }}</p>', message=user_text)
~~~

**Verification:** Template syntax in a user field stays data; expected formatting is preserved.

source= in Flask render_template_string and Jinja Environment.from_string denotes template source. Autoescape escapes output but does not prevent expressions in untrusted source from executing. A message parameter in a fixed template remains data. Review import aliases, wrappers and configuration-loaded templates; the scanner does not establish string provenance. [Flask render_template_string](https://flask.palletsprojects.com/en/stable/api/#flask.render_template_string), [Jinja from_string](https://jinja.palletsprojects.com/en/stable/api/#jinja2.Environment.from_string).

<details>
<summary>Expanded example and limitations</summary>

**Recognize:** render_template_string or Environment.from_string receives request text, including text concatenated with HTML.

```python
# Vulnerable: the user controls template source.
return render_template_string(request.form["message"])
```

**Flask patch:**

```python
from flask import render_template, request

message = request.form["message"]
return render_template("message.html", message=message)
```

`templates/message.html` is a fixed project file:

```html
<p>{{ message }}</p>
```

Do not add |safe. Flask enables autoescape for HTML templates by default; verify the app has not disabled it. HTML escaping and preventing user-template compilation are separate boundaries.

**Check:** {{ 2 + 3 }} appears literally, not as an evaluated result; quotes/HTML render as text; normal messages work. If the service is intentionally a template editor, this substitution changes its contract: design an allowed language instead of applying this shortcut.

</details>

<a id="py-tls"></a>

## PY-TLS. TLS verify=False

**Search:** scanner rule PY-TLS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-TLS` for details. AST: verify=False, simple local scalar or inline **dict, respecting overwrite order. Known requests Session/session and httpx Client/AsyncClient with matching with/async with, Session.send and httpx.stream are supported. Generic get/post/put/patch/delete/request remains an untyped heuristic. Dictionary variables, client properties, runtime config and wrappers are not evaluated.

**Vulnerable example:**

~~~python
import requests
requests.get(url, verify=False)
~~~

**Fix:** Enable certificate/hostname checks and configure the trusted CA instead of bypassing verification.

~~~python
import requests
requests.get(url, verify=True, timeout=3)
~~~

**Verification:** Correct CA/hostname works; invalid, expired or wrong-host certificates fail without fallback.

requests.Session.send applies verify to prepared-request transmission, including inside with requests.session(). Preserve the required CA trust chain; do not disable verification to fix certificate errors. For prepared requests also inspect how environment settings are merged. [Requests prepared requests/TLS](https://requests.readthedocs.io/en/latest/user/advanced/).

~~~python
import requests
with requests.session() as session:
    with session.send(prepared_request, verify=False, timeout=3) as response:
        response.raise_for_status()
~~~

Restore verify=True or supply the approved CA bundle path. The scanner examines explicit flags; it does not reconstruct prepared_request URLs, adapter settings or application-wide trust policy.

httpx.Client/AsyncClient configure validation at construction. Client.stream does not accept verify; module-level httpx.stream does. To preserve streaming with TLS validation:

~~~python
import httpx
with httpx.Client(verify=True, timeout=3) as client:
    with client.stream('GET', approved_url) as response:
        response.raise_for_status()
        # Read inside the context, bounded by the service contract.
~~~

For a private CA use an ssl.SSLContext supported by the installed HTTPX version. The context manager closes responses. TLS does not authorize destinations, so dynamic approved_url still triggers PY-URL pending review. [HTTPX Client/stream](https://www.python-httpx.org/api/).

<a id="py-debug"></a>

## PY-DEBUG. Python web debugger enabled

**Search:** scanner rule PY-DEBUG. Use `--explain PY-DEBUG` for the exact detector contract. AST: explicit debug/use_debugger=True at run/run_simple (legacy name heuristic). Known imported Flask instances: DEBUG=True via config subscript/update/from_mapping or app.debug=True. Inline dictionaries and aliases supported; custom factories, runtime overrides, configuration files and branches remain manual.

**Vulnerable example:**

~~~python
app.run(debug=True)
~~~

**Fix:** Disable the debugger in the competition runtime and retain private, redacted diagnostics.

~~~python
app.run(debug=False)
~~~

**Verification:** Errors expose no interactive console or stack trace; health checks work.

<a id="py-jwt"></a>

## PY-JWT. JWT signature verification disabled

**Search:** scanner rule PY-JWT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-JWT` for details. AST: options.verify_signature=False with inline **kwargs/options and overwrite order. Only jose.jwt.decode and jwt.decode_complete bind fourth positional options; generic jwt.decode is version-ambiguous. Legacy verify=False remains only for generic jwt.decode. Review *args, mutable dictionaries, wrappers and instance settings; explicit positional/keyword duplicates are not treated as executable JWT calls.

**Vulnerable example:**

~~~python
import jwt
claims = jwt.decode(token, options={'verify_signature': False})
~~~

**Fix:** Verify signatures with a trusted key and fixed algorithm policy; validate required claims and values using the installed library version.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['HS256'], audience='service', options={'require': ['exp', 'sub', 'aud']})
~~~

**Verification:** Modified, unsigned, expired and wrong-audience tokens fail; valid sessions work.

For recognized jose.jwt.decode and jwt.decode_complete, inline options may be the fourth positional argument:

~~~python
from jose import jwt
claims = jwt.decode(token, key, ['HS256'], {'verify_signature': False})
~~~

The generic jwt.decode positional contract is version-dependent: PyJWT 1.7.1 uses third verify, fourth algorithms and fifth options; 2.10.1 uses third algorithms and fourth options. The scanner does not identify the installed distribution/version and does not interpret these generic jwt.decode positions. [PyJWT 1.7.1](https://github.com/jpadilla/pyjwt/blob/1.7.1/jwt/api_jwt.py), [PyJWT 2.10.1](https://github.com/jpadilla/pyjwt/blob/2.10.1/jwt/api_jwt.py).

verify=False does not disable validation in PyJWT 2.x decode_complete. python-jose 3.5.0 decode does not accept that argument and raises TypeError. These forms do not trigger solely for the legacy argument. Generic jwt.decode(..., verify=False) remains a legacy-version heuristic. Actual options={'verify_signature': False} remains detected. [python-jose 3.5.0 decode](https://github.com/mpdavis/python-jose/blob/3.5.0/jose/jwt.py).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'decode_complete|jwt[.]decode|from jose|from jwt|import jwt|PyJWT|python-jose|verify_signature|options=|requirements|poetry.lock|uv.lock' .
~~~

Identify imports, deployed/locked versions, argument positions, instance settings and result consumers. Unverified diagnostic claims must not become authorization. decode_complete returns a structure containing payload, not just claims; preserve this return contract. Parse errors or TypeError must not enable an unverified fallback.

JWT semantics in these sections were reviewed against pinned source versions; JWT libraries were not executed for that review. Versions identify reviewed APIs, not recommendations to install obsolete releases. Check the service's supported version, security updates and call contract.

<a id="py-archive"></a>

## PY-ARCHIVE. Archive extraction requires path review

**Search:** scanner rule PY-ARCHIVE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-ARCHIVE` for details. AST: any extractall is a heuristic including ZIP; extract requires known tarfile.open/TarFile/TarFile.open through aliases, constructors, simple assignment or with/as. shutil.unpack_archive requires known tar/gztar/bztar/xztar/zstdtar format, including third argument. filter='data' or tarfile.data_filter (aliases/inline **dict included) suppresses this signal, not all risks. Review custom filters, extension-inferred format, extraction_filter, versions, quotas, wrappers and complex control flow.

A missing filter requires reviewing Python version and TarFile.extraction_filter: Python 3.14 defaults to data; earlier behavior was equivalent to fully_trusted. Instance/class/subclass overrides change this. Even a safe default does not suppress the scanner heuristic. [tarfile filters](https://docs.python.org/3/library/tarfile.html#extraction-filters).

**Vulnerable example:** Untrusted tar extraction without path, member-type or UNIX-metadata restrictions.

~~~python
import tarfile
with tarfile.open(upload_path) as archive:
    archive.extract(member, destination, filter='fully_trusted')
~~~

**Fix:** Validate paths, links, member types and quotas; use tarfile's data filter where supported. A filter is not a resource limit or a complete ZIP policy.

~~~python
import tarfile
with tarfile.open(upload_path) as archive:
    archive.extract(member, new_destination, filter=tarfile.data_filter)
~~~

For shutil the rule considers only explicitly selected built-in tar formats:

~~~python
import shutil
shutil.unpack_archive(upload_path, new_destination, format='gztar', filter='data')
~~~

format='zip' does not trigger this tar signal; ZIP accepts no filter argument. Do not apply the shown tar patch to ZIP. Extension-based detection, custom unpackers and replacement registrations need review of the actual implementation. [shutil.unpack_archive](https://docs.python.org/3/library/shutil.html#shutil.unpack_archive).

data_filter restricts escapes and dangerous types/metadata but may allow internal links. It neither isolates races with another process mutating the directory nor bounds expanded volume. Archives requiring owners, UNIX permissions or special files need a separate compatibility policy. Errors can leave partial output: never publish it as complete; a new directory simplifies cleanup. [PEP 706 scope/limitations](https://peps.python.org/pep-0706/).

API support alone does not imply all security fixes. The October 1, 2026 releases—3.10.22, 3.11.17, 3.12.15, 3.13.16 and 3.14.8—include tar-filter bypass fixes; verify equivalent distribution backports. [Python announcement](https://blog.python.org/2026/10/python-31022-31117/).

**Verification:** Traversal, links, device entries and oversized archives fail; ordinary archives remain inside the root.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'tarfile|extractall|[.]extract[(]|unpack_archive|register_unpack_format|extraction_filter|data_filter|errorlevel|FROM python|requires-python' .
~~~

Identify import/archive type, input source, format, effective filter, error handling and destination-directory access. Check versions/backports from image/deployment metadata without importing the target. Generic extractall matches also include ZIP/unknown objects: review the actual API rather than asserting tar traversal.

<a id="py-temp"></a>

## PY-TEMP. Non-atomic temporary filename

**Search:** scanner rule PY-TEMP. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-TEMP` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
import tempfile
name = tempfile.mktemp()
~~~

**Fix:** Create a private temporary file atomically and retain its handle; never reopen an untrusted name.

~~~python
import tempfile
with tempfile.TemporaryFile() as output:
    output.write(data)
~~~

**Verification:** Concurrent requests obtain separate files and cannot overwrite existing files or links.

<a id="py-xml"></a>

## PY-XML. XML entity resolution enabled

**Search:** scanner rule PY-XML. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-XML` for details. AST: XMLParser by method name; lxml.etree.XMLPullParser/ETCompatXMLParser/iterparse by resolved import name/alias. Requires known resolve_entities=True, including scalar variables or inline **dict. Review defaults, lxml version, DTD, input type and wrappers. This does not determine CVE applicability.

**Vulnerable example:**

~~~python
from lxml import etree
parser = etree.ETCompatXMLParser(resolve_entities=True)
~~~

**Fix:** Disable entity/DTD loading and network access; bound document complexity for the actual parser.

~~~python
from lxml import etree
parser = etree.ETCompatXMLParser(resolve_entities=False, load_dtd=False, no_network=True)
~~~

Review the same settings in XMLPullParser and iterparse. If internal entities are required, consider resolve_entities='internal' on a supporting version and test limits. False may change tree/text semantics; preserve the required service behavior.

**Verification:** Ordinary XML parses; external resources are not read and oversized input fails.

Calls without explicit settings and version-specific defaults need manual review:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'lxml|XMLParser|XMLPullParser|ETCompatXMLParser|iterparse|resolve_entities|requirements|poetry.lock|uv.lock' .
~~~

Match import, API and locked/deployed version, then trace untrusted XML. Before lxml 6.1, iterparse and ETCompatXMLParser defaulted to external-entity resolution and could read local files; 6.1.0 changed the default to 'internal'. Updating does not fix explicit resolve_entities=True. The scanner finds explicit unsafe settings, not version-based CVEs. [GHSA-vfmq-68hx-4jfw / CVE-2026-41066](https://github.com/lxml/lxml/security/advisories/GHSA-vfmq-68hx-4jfw).

<a id="py-weak-hash"></a>

## PY-WEAK-HASH. MD5/SHA1: review the purpose

**Search:** scanner rule PY-WEAK-HASH. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-WEAK-HASH` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
import hashlib
digest = hashlib.md5(password)
~~~

**Fix:** Use a supported password KDF for passwords and HMAC/signatures for authenticity; ordinary checksums need a separate decision.

~~~python
import hashlib
digest = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)
~~~

**Verification:** Authentication checks work and legacy data has a migration path.

<a id="py-rng"></a>

## PY-RNG. Non-cryptographic randomness near a possible secret

**Search:** scanner rule PY-RNG. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-RNG` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
import random
token = str(random.getrandbits(128))
~~~

**Fix:** Use secrets or a supported CSPRNG with sufficient entropy for tokens; handle generator errors.

~~~python
import secrets
token = secrets.token_urlsafe(32)
~~~

**Verification:** No predictable fallback is used; token format and sessions stay compatible.

<a id="py-file"></a>

## PY-FILE. Dynamic file-serving path

**Search:** scanner rule PY-FILE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-FILE` for details. AST: send_file by method name, first argument or path_or_file= with aliases/inline **dict. Nonliteral paths still signal after safe owned-record lookup; custom same-named methods may match. Review authorization, root, links, wrappers and dictionary variables.

**Vulnerable example:**

~~~python
from flask import send_file
result = send_file(path_or_file=user_path)
~~~

**Fix:** Resolve a server-owned record after authorization and enforce the storage root; review symlinks and races.

~~~python
from flask import send_file
record = load_owned_file(file_id, current_user.id)
result = send_file(path_or_file=record.storage_path)
~~~

**Verification:** Other owners' files, traversal and external symlinks fail; authorized downloads work.

path_or_file= is modern Flask API syntax. load_owned_file represents an actually implemented owner check and server-side path lookup, not a cosmetic rename. The corrected call still triggers PY-FILE because the scanner does not verify authorization, links or replacement races. A dynamic argument might also be an already opened trusted file object, which the API legitimately supports. [Flask send_file](https://flask.palletsprojects.com/en/stable/api/#flask.send_file).

<a id="py-url"></a>

## PY-URL. Dynamic outbound URL

**Search:** scanner rule PY-URL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-URL` for details. AST: requests/httpx/urlopen and known Session/session, requests.sessions.Session/session, Client/AsyncClient via aliases, local assignment or immediate constructor. with/as supports requests Session/httpx Client and async with/as supports AsyncClient; facts are invalidated after the region. request(method,url), httpx.stream and Client/AsyncClient.stream use second argument or url=. Literal URLs do not signal. No URL/DNS/redirect validation analysis; review wrappers, returned clients, mutable config and complex relationships.

**Vulnerable example:**

~~~python
import requests
response = requests.get(user_url)
~~~

**Fix:** Apply explicit destination/scheme/port policy, validate resolved addresses and every redirect, and bound time/response size.

~~~python
import requests
response = requests.get('https://api.example.invalid/status', timeout=3, allow_redirects=False)
~~~

**Verification:** Approved endpoints work; forbidden destinations and redirects cannot cross the trust boundary.

Switching to context managers and streaming does not change URL provenance:

~~~python
import httpx
async def fetch(user_url):
    async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
        async with client.stream('GET', user_url) as response:
            response.raise_for_status()
            # Bound response reads; the URL has not been authorized yet.
~~~

Choose a contract-compatible fix: a fixed server endpoint, or a validated dynamic address with scheme/host/port/path/redirect policy. Allowlisted dynamic URLs still trigger PY-URL: the scanner cannot prove validation quality. Literal URLs do not signal, but do not prove DNS, proxy or later redirects safe.

Close streaming responses after size overflow, cancellation and read failures. async with client.stream closes on exit; manual streaming requires guaranteed aclose(). Preserve client lifetime/pool reuse instead of creating a pool each iteration. [HTTPX async streaming](https://www.python-httpx.org/async/).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'requests|httpx|urlopen|base_url|proxies|proxy=|trust_env|allow_redirects|follow_redirects|HTTP_PROXY|HTTPS_PROXY|NO_PROXY' .
~~~

Trace input to the complete URL and combine client/base_url, proxy and environment settings. Review actual resolution, every redirect, internal-address access, cross-destination credential forwarding, timeouts and body limits. A per-operation timeout may not bound the whole chain. Request/PreparedRequest objects, factory clients, custom transports and interprocedural flows require manual review in an authorized test environment; the scanner itself makes no network requests.

**A/D variant:** Checking hostname while accepting the whole client URL. **FAUST / quickr-maps, source.** A server string was interpolated into a URL, only hostname was checked, then requests consumed it. Path/query changes remain a separate boundary.

**Patch:** Clients select symbolic names from a server map; the server builds the entire URL, route and owner. **Test:** URL delimiters cannot change route, port or principal. **Search:** PY-URL, including url= keyword coverage. The complete bypass chain was not reproduced here.

[source/write-up 1](https://github.com/fausecteam/faustctf-2024-quickr-maps/blob/fe77e8f1926117b788108f7614271f3133a1f607/location_portal/src/main.py); [source/write-up 2](https://github.com/fausecteam/faustctf-2024-quickr-maps/blob/fe77e8f1926117b788108f7614271f3133a1f607/private_loc/main.go).

<a id="py-crc"></a>

## PY-CRC. CRC/Adler near an integrity boundary

**Search:** scanner rule PY-CRC. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-CRC` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
import zlib
tag = zlib.crc32(payload)
~~~

**Fix:** Use HMAC/signatures for authenticity or unique IDs plus authorization; ordinary checksums may remain CRC.

~~~python
import hmac
tag = hmac.digest(key, payload, 'sha256')
~~~

**Verification:** Modified messages without the key fail; formats/records stay compatible.

<a id="py-xpath"></a>

## PY-XPATH. XPath assembled from strings

**Search:** scanner rule PY-XPATH. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-XPATH` for details. AST: xpath/XPath by method name and string construction in first argument or simple assignment. String literals, Add-concatenated literals and f-strings without FormattedValue do not signal; %, format and interpolated f-strings require review. No arbitrary evaluation; inspect wrappers, XPath variables and trust.

**Vulnerable example:**

~~~python
node.xpath("//user[name='%s']" % username)
~~~

**Fix:** Bind variables with the actual API and keep XPath fixed; do not quote data into syntax.

~~~python
node.xpath("//user[name=$name]", name=username)
~~~

**Verification:** Quotes/brackets stay data; search scope/ownership does not expand.

A fixed XPath split across literals does not trigger PY-XPATH:

~~~python
node.xpath("//" + "user")
node.xpath(f"//user")
~~~

Only recognized strings without substituted values, concatenated literals and interpolation-free f-strings are excluded. The scanner neither executes XPath nor evaluates arbitrary Python expressions. XPath variables bind data; axes, node names and expression text require server-side policy. Select the actual library's API: name= in this example is lxml-specific. [lxml XPath parameters](https://lxml.de/xpathxslt.html#the-xpath-method).

<a id="py-uuid-bytes"></a>

## PY-UUID-BYTES. UUID bytes/bytes_le protocol boundary

**Search:** scanner rule PY-UUID-BYTES. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-UUID-BYTES` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
import uuid
value = uuid.UUID(bytes_le=wire_bytes)
~~~

**Fix:** Agree on canonical text or documented byte order across languages/cache/DB; bytes_le is not inherently unsafe.

~~~python
import uuid
value = uuid.UUID(wire_text)  # canonical text contract
~~~

**Verification:** Asymmetric vectors and round trips agree; old references remain valid.

**A/D variant:** UUID meaning changes between C# and Python. **RuCTF / hyperborea-legends, author write-up.** Different UUID byte order in cache and primary paths changed the object to which authorization applied.

**Patch:** One documented wire format with boundary conversion; canonical text is preferable if protocol-compatible. **Test:** Asymmetric known vectors, cross-language round-trips and old records. **Search:** PY-UUID-BYTES and CS-GUID-BYTES identify review locations only.

[source/write-up 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/hyperborea-legends/README.md).

<a id="py-assert-auth"></a>

## PY-ASSERT-AUTH. Access control using assert

**Search:** scanner rule PY-ASSERT-AUTH. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-ASSERT-AUTH` for details. Bounded syntactic AST analysis, not type resolution or interprocedural taint analysis. Review actual API, inputs and authorization.

**Vulnerable example:**

~~~python
assert note.owner_id == current_user.id
~~~

**Fix:** Use explicit denial active under -O; do not blanket-replace ordinary test assertions.

~~~python
if note.owner_id != current_user.id:
    raise PermissionError('access denied')
~~~

**Verification:** Unauthorized objects fail in normal/optimized mode; authorized actions work.

<a id="py-django-hosts"></a>

## PY-DJANGO-HOSTS. Django wildcard ALLOWED_HOSTS

**Search:** scanner rule PY-DJANGO-HOSTS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-DJANGO-HOSTS` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~python
ALLOWED_HOSTS = ["*"]
~~~

**Fix:** Allowlist actual hostnames/IPs including the checker; use get_host instead of raw Host and review trusted proxy headers separately.

~~~python
ALLOWED_HOSTS = ["service.internal"]
~~~

**Verification:** Unknown Host fails; normal host/checker works.

**Reference:** [primary source](https://docs.djangoproject.com/en/5.2/ref/settings/#allowed-hosts).

<a id="py-html-safe"></a>

## PY-HTML-SAFE. HTML escaping explicitly bypassed

**Search:** scanner rule PY-HTML-SAFE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-HTML-SAFE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~python
html = mark_safe(message)
~~~

**Fix:** Use autoescaped templates; sanitize permitted rich HTML. HTML escaping does not secure JS or URL contexts.

~~~python
html = message
~~~

**Verification:** Tags/quotes stay data without breaking supported formatting.

**Reference:** [primary source](https://docs.djangoproject.com/en/5.2/topics/security/).

<a id="py-mass-assign"></a>

## PY-MASS-ASSIGN. Request fields become model attributes

**Search:** scanner rule PY-MASS-ASSIGN. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-MASS-ASSIGN` for details. AST: setattr with nonliteral attribute name. **kwargs, wrappers, ORM update and constructors are not automatically covered.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'setattr|__dict__|model_validate|update\(|request.json' .
~~~

Trace field lists into the ORM; locate owner/role/tenant and nested DTOs.

**Vulnerable example:**

`setattr(model, key, value)` over client JSON applies administrative fields.

**Fix:** Explicitly allowlist editable attributes; derive owner/role and nested privileges server-side.

**Verification:** Unknown/admin fields do not alter state; permitted edits remain functional.

**Scanner example before:**

~~~python
for field, value in payload.items():
    setattr(account, field, value)
~~~

**Fix template:**

~~~python
account.display_name = validate_display_name(payload['display_name'])
~~~

<a id="py-decorator-auth"></a>

## PY-DECORATOR-AUTH. A route is registered before the authorization wrapper

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '@.*route|@.*get|@.*post|login_required|permission_required' .
~~~

Expand decorator application order and inspect the function actually saved in the router.

**Vulnerable example:**

Authorization wraps the local name, but the router already retains the unwrapped function.

**Fix:** Put authorization inside route registration or use the framework's supported dependency/policy mechanism; check every HTTP method.

**Verification:** Sessionless requests through the actual router fail; direct unit calls alone are insufficient.

<a id="py-async-context"></a>

## PY-ASYNC-CONTEXT. Global current_user leaks across async requests

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'global|current_user|ContextVar|threading.local|asyncio' .
~~~

Find principal assignments and awaits between assignment/use; ensure ContextVar tokens reset in finally.

**Vulnerable example:**

A global variable or thread-local serves multiple coroutines sharing a thread.

**Fix:** Request-scoped objects/ContextVar with token restoration; pass explicit verified context into jobs.

**Verification:** Barrier-interleaved requests from different users; exceptions leave no foreign context.

<a id="py-redirect"></a>

## PY-REDIRECT. Dynamic redirect destination

**Search:** scanner rule PY-REDIRECT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-REDIRECT` for details. AST: flask.redirect/werkzeug.utils.redirect first argument or location=; django.shortcuts.redirect first argument or to=. Import aliases/inline **dict supported; literals or known simple scalar values do not signal. Review trust, wrappers, runtime kwargs, route resolution and reverse-proxy redirects.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'redirect\(|next|return_url|urljoin' .
~~~

Trace Location construction: relative paths must not become network-path URLs or another origin.

**Vulnerable example:**

`redirect(request.args['next'])` selects an external destination; startswith('/') is insufficient.

**Fix:** Resolve destinations from an allowlist or verify approved scheme/host/path after normalization; do not trust user-controlled return URLs.

**Verification:** External, scheme-relative and malformed destinations fail; supported navigation works.

**Scanner example before:**

~~~python
from flask import redirect
return_url = request.args['next']
response = redirect(return_url)
~~~

**Fix template:**

~~~python
from flask import redirect
response = redirect('/profile')
~~~

Primary documentation: [reference 1](https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme).

Named arguments do not change the trust boundary:

~~~python
from flask import redirect
response = redirect(location=request.args['next'])
~~~

~~~python
from django.shortcuts import redirect
response = redirect(to=request.GET['next'])
~~~

Flask/Werkzeug uses location=; Django uses to=. Django also accepts view names and objects with get_absolute_url(): inspect destination meaning and the final Location rather than treating every dynamic value as an external URL. A fixed route may use redirect(location='/profile') or Django redirect(to='profile') if that named route exists. Preserve parameters, methods and status behavior; forcing all navigation onto one route changes the service contract. [Flask redirect](https://flask.palletsprojects.com/en/stable/api/#flask.redirect), [Django 5.2 redirect](https://docs.djangoproject.com/en/5.2/topics/http/shortcuts/#redirect).

Fully validated dynamic destinations still signal. The scanner does not reproduce URLconf, get_absolute_url, browser normalization or effective Host/proxy behavior; verify those relationships through normal navigation.

<a id="py-password-hash"></a>

## PY-PASSWORD-HASH. Fast digests used for password storage

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'password|hashlib|sha256|md5|pbkdf2' .
~~~

Inspect registration/login, salt, work factor, stored-record format and migration branches.

**Vulnerable example:**

sha256(password) without adaptive cost permits rapid guessing against a leaked database.

**Fix:** A supported framework password hasher, Argon2id or suitable KDF; retain salt/parameters in records and upgrade after successful login.

**Verification:** Existing users log in and migrate; wrong passwords never overwrite hashes; long input is bounded.

<a id="py-zip-limits"></a>

## PY-ZIP-LIMITS. Archive traversal, symlinks and expanded volume

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'zipfile|tarfile|extractall|extract\(' .
~~~

Beyond PY-ARCHIVE, inspect entries, actual expanded volume and filesystem boundaries; path filters do not bound size.

**Vulnerable example:**

An archive writes outside the root or fills storage despite a small compressed input.

**Fix:** Separate destination, validation of every path/type/link, entry-count and actual expanded-byte limits, then atomic publication.

**Verification:** Normal archive, absolute paths, outward links, many entries, mid-run failure and temporary-data cleanup.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="py-json-duplicates"></a>

## PY-JSON-DUPLICATES. Parsers disagree on repeated keys

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'json.loads|object_pairs_hook|orjson|signature|canonical' .
~~~

Compare signer, API and downstream parsing: first/last duplicate, numeric handling and key normalization.

**Vulnerable example:**

Signature verification sees one owner interpretation while the operation uses another.

**Fix:** One canonical DTO before signing and after reading; explicit duplicate/numeric policy and rejection of ambiguous documents.

**Verification:** Repeated owners, key ordering, Unicode and large numbers produce identical meaning or explicit rejection.

<a id="py-cache-key"></a>

## PY-CACHE-KEY. Authorization-cache key collisions

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'cache|memoize|lru_cache' .
~~~

Compare complete keys across users and argument pairs sharing a prefix; find truncation and invalidation.

**Vulnerable example:**

**Reference:** hermicache, RuCTF author write-up. A shared cache built string keys from functions/arguments and truncated them to 90 characters.

**Search:** Ambiguous concatenation, prefix/slice keys, missing user/tenant/permission version and shared caching of public results and authentication.

**Fix:** Serialize complete typed tuples with required context. Never cache password-verification success under a shared key. Preserve computational caching needed for SLA. Example principle:

~~~python
# before: cache[(function + str(arguments))[:90]]
# after: no truncation, no ambiguous concatenation
key = json.dumps([function, tenant_id, user_id, arguments],
                 separators=(",", ":"), ensure_ascii=False)
~~~

**Verification:** Distinct argument pairs sharing a prefix, different users, role/password changes and legitimate repeat computation.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/hermicache/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/hermicache/README.md).

<a id="py-jwt-dependency"></a>

## PY-JWT-DEPENDENCY. Vulnerable JWT-verification dependencies

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'python-jwt|PyJWT|jwt|requirements|lock' .
~~~

Compare distribution name, lock, vendored copies and actual loaded version; python-jwt and PyJWT differ.

**Vulnerable example:**

**Reference:** deutsches-flugzeug, saarCTF author overview; python-jwt advisory CVE-2022-39227. The dependency was vulnerable even when calls looked normal. **Search:** Exact distribution name, lock/version, imported module, vendored copies and image/lock mismatch.

**Fix:** A fixed compatible version with locally prepared packages/image; editing a lockfile does not replace an already running container.

**Verification:** Signature, all claims, lifetime, wrong key, normal sessions and the confirmed regression case. The fix threshold for this particular CVE was python-jwt 3.3.4, not PyJWT; it is not a recommendation to pin that old release indefinitely.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/deutsches-flugzeug/overview.md).

**Reference:** [primary source](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/deutsches-flugzeug/overview.md).

<a id="py-challenge-state"></a>

## PY-CHALLENGE-STATE. Challenge disclosure before commitment

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'chall|comm|resp|init_get|finish_get' .
~~~

Map init/finish state transitions; repeated init must not change commitments after the challenge is known.

**Vulnerable example:**

**ECSC / fonograph, author write-up.** Protocol steps reused incorrectly updated challenge state.

**Fix:** Fresh challenges after commitment, bound to session/object, with atomic one-time consumption.

**Verification:** Repeated init, reordered/replayed finish, parallel sessions and normal exchanges.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/db.py); [source/write-up 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/backend/handlers.py).

**Reference:** [primary source](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/fonograph/README.md).

<a id="py-ssl-context"></a>

## PY-SSL-CONTEXT. TLS context verification disabled

**Search:** scanner rule PY-SSL-CONTEXT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-SSL-CONTEXT` for details. AST: ssl._create_unverified_context(), verify_mode=ssl.CERT_NONE and check_hostname=False assignments with import aliases. Assignment receiver type is not established.

**Vulnerable example:** CERT_NONE, disabled hostname validation or an unverified client TLS context can accept an unintended server.

~~~python
import ssl
context = ssl._create_unverified_context()
~~~

**Fix:** Enable certificate/hostname verification and configure the correct CA rather than an unverified context.

~~~python
import ssl
context = ssl.create_default_context(cafile=trusted_ca_file)
~~~

**Verification:** Correct peers work; wrong CA/hostname and expiry fail.

For a server without mTLS, CERT_NONE means no client certificate is requested; this is normal unless the contract requires them. check_hostname concerns a client authenticating a server. The scanner cannot distinguish role/effective object type; do not require mTLS merely to silence a finding. [Python ssl.CERT_NONE](https://docs.python.org/3/library/ssl.html#ssl.CERT_NONE).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'PROTOCOL_TLS_CLIENT|PROTOCOL_TLS_SERVER|create_default_context|CERT_NONE|check_hostname|server_side|server_hostname' .
~~~

Connect context construction to use; review server_side, create_default_context purpose and client-certificate requirements. When changing server configuration test existing clients and the agreed authentication mechanism.

<a id="py-csrf-exempt"></a>

## PY-CSRF-EXEMPT. Django view excluded from CSRF

**Search:** scanner rule PY-CSRF-EXEMPT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-CSRF-EXEMPT` for details. AST: django.views.decorators.csrf.csrf_exempt decorator/call with import alias. An exemption alone is not proof of a flaw on a bearer-only endpoint.

**Vulnerable example:** A cookie-authenticated mutation without CSRF validation accepts cross-context browser requests.

~~~python
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def update(request):
    return change_profile(request)
~~~

**Fix:** Retain CSRF on cookie-authenticated browser routes; narrow exemptions to independently authenticated stateless endpoints.

~~~python
from django.views.decorators.csrf import csrf_protect
@csrf_protect
def update(request):
    return change_profile(request)
~~~

**Verification:** Browser mutations need the correct token; authorized API/webhook requests still work.

Primary documentation: [reference 1](https://docs.djangoproject.com/en/5.2/ref/csrf/).

<a id="py-jwt-algorithms"></a>

## PY-JWT-ALGORITHMS. JWT algorithms taken from an expression

**Search:** scanner rule PY-JWT-ALGORITHMS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-JWT-ALGORITHMS` for details. AST: algorithms outside an inline list/tuple of strings; exact jose.jwt.decode also permits known literal/scalar strings. Only jose.jwt.decode and jwt.decode_complete use third positional algorithms; generic jwt.decode uses keyword only. Explicit None signals; missing arguments, *args, mutable config, version and allowlist origin need review. Explicit duplicate algorithms/options arguments are not analyzed as executable calls.

**Vulnerable example:** Untrusted alg values must not choose the permitted signature-verification algorithm.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=[header['alg']])
~~~

**Fix:** Bind allowed algorithms to trusted key configuration; never mix HMAC/RSA for the same key material.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['RS256'], audience='notes', issuer='auth')
~~~

**Verification:** Wrong algorithm/key type/signature fails; issuer, audience and expiry are checked.

Primary documentation: [reference 1](https://pyjwt.readthedocs.io/en/stable/api.html).

In known python-jose 3.5.0, a fixed algorithms='HS256' string is valid and does not signal; ['HS256'] also works. This does not permit deriving algorithms from token headers. Explicit algorithms=None still requires review: meaning depends on library/key type. Omission does not prove an allowlist. [python-jose 3.5.0](https://github.com/mpdavis/python-jose/blob/3.5.0/jose/jwt.py), [PyJWT 2.10.1 algorithms/PyJWK](https://pyjwt.readthedocs.io/en/2.10.1/api.html).

A trusted algorithm-list variable may retain PY-JWT-ALGORITHMS; trace it to key configuration. For positional calls first verify imports/versions as in [PY-JWT](#py-jwt). No signal proves neither key strength, provenance nor purpose separation.

<a id="py-jwt-claims"></a>

## PY-JWT-CLAIMS. JWT expiry or recipient checks disabled

**Search:** scanner rule PY-JWT-CLAIMS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-JWT-CLAIMS` for details. AST: inline options with verify_exp/verify_nbf/verify_aud/verify_iss=False, scalar booleans and inline spreads. Only jose.jwt.decode/jwt.decode_complete consider fourth positional options. Only jose.jwt.decode require_X=True suppresses corresponding verify_X=False, not other claims/signature. Review external dictionaries, *args, duplicates, instance config, versions and required presence.

**Vulnerable example:** A valid signature does not make expired or other-application tokens acceptable.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['HS256'], options={'verify_exp': False})
~~~

**Fix:** Validate expiry, issuer, audience and required presence separately. The after example uses PyJWT 2.x options.require; python-jose uses require_*. Check decode_complete's result shape.

~~~python
import jwt
claims = jwt.decode(token, key, algorithms=['HS256'], audience='notes', issuer='auth', options={'require': ['exp', 'sub', 'iss', 'aud']})
~~~

**Verification:** Expired, premature, missing-claim and other-application tokens fail; sessions work with the selected library/result shape.

Primary documentation: [PyJWT 2.10.1 require/verify](https://pyjwt.readthedocs.io/en/2.10.1/api.html).

python-jose 3.5.0 uses separate require_* options:

~~~python
from jose import jwt
claims = jwt.decode(
    token, key, algorithms=['HS256'], audience='notes', issuer='auth',
    options={'require_exp': True, 'require_sub': True,
             'require_aud': True, 'require_iss': True},
)
~~~

In this library require_exp=True requires the claim and restores corresponding verify_exp. Thus known verify_exp=False, require_exp=True does not trigger PY-JWT-CLAIMS; requiring another field does not suppress disabled verification. This differs from PyJWT require=[...]. require_signature does not restore signature verification, which happens before claim validation. [python-jose 3.5.0 claims](https://github.com/mpdavis/python-jose/blob/3.5.0/jose/jwt.py).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'verify_exp|verify_nbf|verify_aud|verify_iss|require_|require["\x27]|PyJWT[(]|options|decode_complete' .
~~~

Review instance settings, options construction, overrides and API versions. Variable dictionaries and missing-claim requirements are not proven automatically. Match iss/aud to the receiver, then test old legitimate tokens and new negative cases. Requiring a new field can break sessions: coordinate issuance/migration before tightening acceptance.

<a id="py-regex-dynamic"></a>

## PY-REGEX-DYNAMIC. Dynamic regular-expression pattern

**Search:** scanner rule PY-REGEX-DYNAMIC. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain PY-REGEX-DYNAMIC` for details. AST: re.compile/match/search/fullmatch/findall/finditer/split/sub/subn with nonliteral first argument. Does not measure regex complexity; safe re.escape still signals.

**Vulnerable example:** User-provided regex changes search semantics and may cause excessive backtracking.

~~~python
import re
found = re.search(request_pattern, text)
~~~

**Fix:** For literal search use escaping/string operations; a regex feature needs constrained grammar, lengths and execution budget.

~~~python
import re
found = re.search(re.escape(search_text), bounded_text)
~~~

**Verification:** Metacharacters stay literal where intended; long near-matches cannot block the handler.

A correct patch may retain this signal: the detector does not prove the stated invariant.

Primary documentation: [reference 1](https://docs.python.org/3/library/re.html#re.escape).

<a id="py-auth-decorator"></a>

## PY-AUTH-DECORATOR. Flask route registers before login protection

**Search:** scanner rule PY-AUTH-DECORATOR. Use `--explain PY-AUTH-DECORATOR` for the exact detector contract. AST: imported flask_login.login_required above route/get/post/put/patch/delete on a known Flask/Blueprint constructor. Aliases and straight-line rebinding respected. Custom decorators, factories, dynamic routes and other registration methods remain manual.

**Vulnerable example:**

~~~python
from flask import Flask
from flask_login import login_required
app = Flask(__name__)
@login_required
@app.route('/private')
def private():
    return 'private'
~~~

**Fix:** Put the known Flask route decorator outside login_required; verify authorization using the registered endpoint, not only direct function calls.

~~~python
from flask import Flask
from flask_login import login_required
app = Flask(__name__)
@app.route('/private')
@login_required
def private():
    return 'private'
~~~

**Verification:** Anonymous requests must fail through the real route; authenticated requests and checker behavior must still work.

[Primary reference 1](https://flask.palletsprojects.com/en/stable/patterns/viewdecorators/)

<a id="py-log-credentials"></a>

## PY-LOG-CREDENTIALS. Credential-like value passed directly to logging

**Search:** scanner rule PY-LOG-CREDENTIALS. Use `--explain PY-LOG-CREDENTIALS` for the exact detector contract. AST: known logging module/getLogger or Flask app.logger methods with direct sensitive names/attributes/subscripts, dict/list values or simple format expressions. Names: password/passwd/secret/token/access_token/refresh_token/api_key/authorization. Helper calls, logging kwargs, wrappers and other names are not traced; no helper-call signal does not verify redaction.

**Vulnerable example:**

~~~python
import logging
logging.warning('authentication failed: %s', password)
~~~

**Fix:** Log stable event categories and approved identifiers, never credential values or Authorization headers; test failed login and exception paths.

~~~python
import logging
logging.warning('authentication failed')
~~~

**Verification:** Canary credentials must not appear in stdout, logs, evidence or broadcasts; useful failure diagnostics remain available.

[Primary reference 1](https://docs.python.org/3/library/logging.html)
