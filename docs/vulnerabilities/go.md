# Go: find, fix and verify

English | [Русский](go-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

19 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [GO-SQL — Dynamic Go SQL](#go-sql)
- [GO-HASH-SUM — Non-empty argument to hash.Sum](#go-hash-sum)
- [GO-HTML — Go autoescape bypass](#go-html)
- [GO-TLS — InsecureSkipVerify](#go-tls)
- [GO-SHELL — Go exec.Command launches a shell](#go-shell)
- [GO-CRC — CRC near an identifier or trust boundary](#go-crc)
- [GO-MATH-RAND — math/rand near a possible secret](#go-math-rand)
- [GO-READALL-BODY — ReadAll on a request body](#go-readall-body)
- [GO-PPROF — pprof registered on an HTTP mux](#go-pprof)
- [GO-FILESERVER — FileServer publishes a file tree](#go-fileserver)
- [GO-AUTH-RETURN — Execution continues after http.Error](#go-auth-return)
- [GO-JSON-FIELDS — JSON entities and ambiguous keys](#go-json-fields)
- [GO-RACE — Shared map/slice state and check-then-use](#go-race)
- [GO-ERROR-DEFAULT — Ignored errors produce a zero principal](#go-error-default)
- [GO-SSRF — HTTP clients and redirects](#go-ssrf)
- [GO-ZIP-PATH — filepath.Join does not enforce containment](#go-zip-path)
- [GO-TLS-MIN — Obsolete minimum TLS version](#go-tls-min)
- [GO-JWT-UNVERIFIED — JWT without signature or claims verification](#go-jwt-unverified)
- [GO-UPLOAD-PATH — Multipart filename used directly in a joined path](#go-upload-path)

<a id="go-sql"></a>

## GO-SQL. Dynamic Go SQL

**Search:** scanner rule GO-SQL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-SQL` for details. Regex: Query/QueryRow/Exec/Prepare and Context forms with concatenation or fmt.Sprintf. Simple context expressions are supported; review complex syntax, fmt aliases and preassembled SQL.

**Vulnerable example:**

~~~go
db.Query("SELECT id FROM notes WHERE name=" + name)
~~~

**Fix:** Bind values using actual driver placeholders; allowlist identifiers.

~~~go
db.Query("SELECT id FROM notes WHERE name=$1", name)
~~~

**Verification:** Quotes remain values; legitimate queries and ownership checks work.

<details>
<summary>Expanded example and limitations</summary>

```go
// Vulnerable: client input becomes SQL syntax.
q := fmt.Sprintf("SELECT body FROM notes WHERE id = '%s'", inputID)
err := db.QueryRowContext(ctx, q).Scan(&body)
```

**Patch for a private note:**

```go
import (
    "context"
    "database/sql"
)

func ReadPrivateNote(ctx context.Context, db *sql.DB, userID, noteID int64) (string, error) {
    var body string
    err := db.QueryRowContext(ctx,
        "SELECT body FROM notes WHERE id = $1 AND owner_id = $2",
        noteID, userID,
    ).Scan(&body)
    return body, err
}
```

Parse the ID with a checked conversion before this call. Map sql.ErrNoRows to the normal unavailable-object response; never return body as success for other errors. Verify placeholder syntax for MySQL or another driver.

**Check:** Owner, other user, missing object, invalid ID, context cancellation/timeout and old records. After list iteration check rows.Err().

</details>

<a id="go-hash-sum"></a>

## GO-HASH-SUM. Non-empty argument to hash.Sum

**Search:** scanner rule GO-HASH-SUM. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-HASH-SUM` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~go
digest := h.Sum(record.Hash[:])
~~~

**Fix:** Use Write to hash bytes and Sum(nil) for the digest; Sum appends a digest instead of hashing its argument.

~~~go
h.Write(record.Hash[:])
digest := h.Sum(nil)
~~~

**Verification:** Known vectors match; legacy digest formats are migrated deliberately.

**A/D variant:** Sum does not hash its argument. **Reference:** certified-transparency, analysis of three saarCTF source files. Checksum passed Hash to Sum; ToHash copied the first 32 output bytes. Go semantics mean those bytes could be the original Hash rather than the digest of previously written Size/Timestamp. The full service was not reproduced. Scanner: GO-HASH-SUM.

~~~go
// Before: return ToHash(h.Sum(record.Hash[:]))
// After: include data in hash state, then extract only the digest.
h.Write(record.Hash[:])
return ToHash(h.Sum(nil))
~~~

**Test:** Change Size, Timestamp and Hash individually; each old signature must fail. Plan signature-format migration and legacy-data compatibility. A nonempty Sum argument is not always wrong: buf[:0] can reuse preallocated storage. Inspect the consumer of the result.

[source/write-up 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/certified-transparency/service/pkg/models/serialization.go); [source/write-up 2](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/certified-transparency/service/pkg/models/models.go); [source/write-up 3](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/certified-transparency/service/pkg/signatures.go).

<a id="go-html"></a>

## GO-HTML. Go autoescape bypass

**Search:** scanner rule GO-HTML. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-HTML` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~go
value := template.HTML(input)
~~~

**Fix:** Pass strings to html/template; use trusted HTML only after a reviewed sanitizer if needed.

~~~go
value := input // string passed to html/template
~~~

**Verification:** User tags/quotes render as text; intended formatting works.

<details>
<summary>Expanded example and limitations</summary>

```go
// Vulnerable when message is client-controlled.
err := page.Execute(w, template.HTML(message))
```

**Patch for rendering ordinary text:**

```go
import (
    "html/template"
    "io"
)

func RenderMessage(w io.Writer, message string) error {
    page, err := template.New("message").Parse("<p>{{.}}</p>")
    if err != nil {
        return err
    }
    return page.Execute(w, message)
}
```

The template is fixed and the data is an ordinary string. Use html/template, not text/template, for HTML. Do not replace the problem with template.JS/template.URL, which also assert trust. A fixed template may be parsed once at startup. Account for partial HTTP responses on render failure; buffer first where necessary.

**Check:** Markup/quotes display as text, Unicode survives, message itself is never compiled, and contractual formatting remains available.

</details>

<a id="go-tls"></a>

## GO-TLS. InsecureSkipVerify

**Search:** scanner rule GO-TLS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-TLS` for details. Regex: InsecureSkipVerify:true and .InsecureSkipVerify=true assignments including newlines; ==, != and false do not match. VerifyConnection does not suppress review: inspect object type, reachability, callback and effective config. Comments/strings may match.

**Vulnerable example:**

~~~go
cfg := tls.Config{InsecureSkipVerify: true}
~~~

**Fix:** Use normal certificate/hostname verification and the required CA; review custom verification callbacks.

~~~go
cfg := tls.Config{InsecureSkipVerify: false}
~~~

**Verification:** Correct peers work and invalid certificates fail.

Dangerous configuration can be assigned after construction:

~~~go
cfg := &tls.Config{}
cfg.InsecureSkipVerify = true
~~~

For an ordinary TLS client restore false and configure RootCAs/ServerName for the intended server. Test trusted certificates, unknown CAs, wrong names and expiry, preserving the legitimate internal CA.

With InsecureSkipVerify: true, an application may implement its own VerifyConnection validation. The flag can be justified only if that callback fully checks the required chain and name; a callback's mere presence proves nothing. The scanner does not analyze its body and retains the signal. Comparing cfg.InsecureSkipVerify == true does not change configuration and does not independently trigger GO-TLS. [Go: tls.Config](https://pkg.go.dev/crypto/tls#Config).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'InsecureSkipVerify|VerifyConnection|VerifyPeerCertificate|RootCAs|ServerName|TLSClientConfig' .
~~~

Connect the configuration to the transport actually used; trace every assignment and callback error return, including resumed TLS sessions. Variable values and effective configuration need manual review. Regex can match comments/examples; a match does not establish execution.

<a id="go-shell"></a>

## GO-SHELL. Go exec.Command launches a shell

**Search:** scanner rule GO-SHELL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-SHELL` for details. Regex: any receiver.Command/CommandContext with literal shell and -c/-lc/-ec. Simple context expressions including r.Context() work; nested commas may hide a call. Inspect receiver type and command trust.

**Vulnerable example:**

~~~go
cmd := exec.Command("sh", "-c", command)
~~~

**Fix:** Use fixed executable plus argv. Pass stdin records without a shell and validate their separators.

~~~go
cmd := exec.Command("/usr/bin/file", "--", filename)
~~~

**Verification:** Metacharacters stay data; dangerous options/separators fail; supported arguments work.

<details>
<summary>Expanded example and limitations</summary>

```go
// Vulnerable: exec.Command starts a shell that parses input text.
out, err := exec.Command("sh", "-c", "printf '%s' '"+message+"' | sha256sum").Output()
```

**Patch for a content SHA-256 digest:**

```go
import (
    "crypto/sha256"
    "encoding/hex"
)

func DigestText(message string) string {
    sum := sha256.Sum256([]byte(message))
    return hex.EncodeToString(sum[:])
}
```

Go strings contain bytes; this example preserves them unchanged. Validate UTF-8 separately if the protocol requires it. Preserve the external response format, which may differ from raw sha256sum output. This is not password hashing.

**Check:** Known digest, empty string, Unicode, quotes/newlines and no subprocess. If an external command is genuinely required, separate executable/arguments and bound runtime with context; the program may still interpret arguments as options.

</details>

**A/D variant:** Shell hidden in an internal backend. **ENOWARS / replme, author write-up.** An internal handler interpolated a password into a shell command. **Patch:** Call a fixed utility without shell; pass data over stdin while validating its format delimiters. Do not arbitrarily restrict passwords to letters without checking the contract. **Test:** Spaces/permitted characters work; record delimiters fail. **Search:** GO-SHELL and the complete call chain.

[source/write-up 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [source/write-up 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [source/write-up 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [source/write-up 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [source/write-up 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [source/write-up 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

<a id="go-crc"></a>

## GO-CRC. CRC near an identifier or trust boundary

**Search:** scanner rule GO-CRC. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-CRC` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~go
resource := service.CRC.Calculate(username)
~~~

**Fix:** CRC is not an ownership boundary. Use unique server-owned IDs plus authorization or HMAC for authenticity.

~~~go
resource := sha256.Sum256([]byte(username))
~~~

**Verification:** Collisions cannot change ownership; old IDs have a migration path.

**A/D variant:** CRC as the boundary between users' resources. **ENOWARS / replme, author and patch.** A name's CRC selected a container; collisions merged unrelated resources.

**Patch:** Server-generated unique IDs or a cryptographic mapping, separate ownership checks and migration of existing resources. A cryptographic hash is not authorization. **Test:** Equal checksums for different names must not share a resource. **Search:** GO-CRC; PY-CRC covers the analogous Python risk.

[source/write-up 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [source/write-up 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [source/write-up 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [source/write-up 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [source/write-up 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [source/write-up 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

<a id="go-math-rand"></a>

## GO-MATH-RAND. math/rand near a possible secret

**Search:** scanner rule GO-MATH-RAND. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-MATH-RAND` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~go
import "math/rand"
rand.Seed(time.Now().UnixMilli())
~~~

**Fix:** Use crypto/rand and handle errors; alphabet shuffling/hidden seeds do not create a CSPRNG.

~~~go
import "crypto/rand"
_, err := rand.Read(token)
if err != nil { return err }
~~~

**Verification:** Entropy/length suffice and failure never creates a predictable fallback.

**A/D variant:** Go tokens seeded from time. **RuCTF / werk, author write-up.** math/rand and creation time constrained token unpredictability. **Patch:** crypto/rand, adequate length and error handling; permuting an alphabet does not fix a weak generator. **Test:** Token contract and generator failure without predictable fallback. **Search:** GO-MATH-RAND including import aliases; review custom PRNGs separately.

[source/write-up 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/werk/README.md).

<a id="go-readall-body"></a>

## GO-READALL-BODY. ReadAll on a request body

**Search:** scanner rule GO-READALL-BODY. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-READALL-BODY` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~go
body, err := io.ReadAll(r.Body)
~~~

**Fix:** Limit the body before reading and handle excess size; the rule does not track earlier MaxBytesReader calls.

~~~go
r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
body, err := io.ReadAll(r.Body)
if err != nil { return } // map to an appropriate client error
~~~

**Verification:** Test limit-1/limit/limit+1 and streams without Content-Length.

<a id="go-pprof"></a>

## GO-PPROF. pprof registered on an HTTP mux

**Search:** scanner rule GO-PPROF. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-PPROF` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~go
import _ "net/http/pprof"
~~~

**Fix:** Do not expose DefaultServeMux debug handlers as the business API; separate muxes and authorize diagnostic endpoints.

~~~go
// use a separate authenticated diagnostics mux when diagnostics is required
~~~

**Verification:** Normal API works; anonymous clients cannot obtain profiles/heap. Import alone does not prove exposure.

**Reference:** [primary source](https://pkg.go.dev/net/http/pprof).

<a id="go-fileserver"></a>

## GO-FILESERVER. FileServer publishes a file tree

**Search:** scanner rule GO-FILESERVER. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-FILESERVER` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~go
http.Handle("/", http.FileServer(http.Dir(".")))
~~~

**Fix:** Use a dedicated public root without secrets/databases; authorize private files separately and review symlinks/listing.

~~~go
http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./public"))))
~~~

**Verification:** Assets work; .env, source, foreign files and outward symlinks are unavailable.

**Reference:** [primary source](https://pkg.go.dev/net/http#FileServer).

<a id="go-auth-return"></a>

## GO-AUTH-RETURN. Execution continues after http.Error

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'http.Error|WriteHeader|StatusForbidden|StatusUnauthorized' .
~~~

Trace execution after each denial, including deferred effects and goroutines.

**Vulnerable example:**

`http.Error(w, ..., 403)` writes a response but does not stop the handler; subsequent code reads or mutates data.

**Fix:** Explicit return before side effects; require a checked authorization result on every path, including helpers.

**Verification:** Denial does not mutate the database or append private response data; authorized requests work.

<a id="go-json-fields"></a>

## GO-JSON-FIELDS. JSON entities and ambiguous keys

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'json.NewDecoder|json.Unmarshal|Decode\(|DisallowUnknownFields' .
~~~

Review exported entity fields, tags, duplicate keys and case variants; DisallowUnknownFields does not solve duplicates.

**Vulnerable example:**

Decoding into the model accepts Owner/Role, or parsers choose different duplicate keys.

**Fix:** Dedicated DTO, allowlisted fields, EOF/type validation; signed input requires an explicit duplicate-key/canonicalization policy.

**Verification:** Extra authorization fields, second JSON documents, nulls, duplicate keys and ordinary payloads.

<a id="go-race"></a>

## GO-RACE. Shared map/slice state and check-then-use

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'map\[|sync.Mutex|RWMutex|go func|LoadOrStore|owner' .
~~~

Identify the shared-state owner; a lock must cover the check and mutation, not only individual accesses.

**Vulnerable example:**

Two goroutines both pass balance/authorization checks and mutate state.

**Fix:** An atomic operation/critical section or database transaction; avoid global locks across slow I/O.

**Verification:** Barrier-based invariant tests and race detector in an isolated environment. No race report does not prove the absence of logical races.

<a id="go-error-default"></a>

## GO-ERROR-DEFAULT. Ignored errors produce a zero principal

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ParseInt|Atoi|Unmarshal|Verify|Find|_, _|err' .
~~~

Find ignored parse/auth/database errors; determine whether zero identifies a global/default object.

**Vulnerable example:**

`id, _ := strconv.Atoi(input)` turns invalid input into zero with special privileges.

**Fix:** Check errors and range before use; distinguish not-found from backend failure.

**Verification:** Invalid IDs/database timeouts never authorize or expose another user's data; explicitly handle zero if it is valid by contract.

<a id="go-ssrf"></a>

## GO-SSRF. HTTP clients and redirects

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'http.Get|Client.Do|NewRequest|CheckRedirect|DialContext' .
~~~

Trace custom transports, redirect policies, DNS and connection reuse.

**Vulnerable example:**

The URL is checked before Client.Do, but redirect/transport behavior reaches another destination.

**Fix:** Fixed destinations or a unified URL/redirect/connection policy, timeouts and body limits. Do not prohibit legitimate private-network destinations without checking the contract.

**Verification:** Mock redirects/DNS/timeouts, normal upstream and oversized responses.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="go-zip-path"></a>

## GO-ZIP-PATH. filepath.Join does not enforce containment

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'archive/zip|archive/tar|filepath.Join|EvalSymlinks|MkdirAll' .
~~~

Inspect entry/link names; compare the cleaned path with the root and the actual open operation.

**Vulnerable example:**

`Join(root, entry)` writes without checking escapes or symlinks.

**Fix:** Validate relative paths and entry types, use safe directory-relative opening with a symlink policy, limits and cleanup.

**Verification:** Valid nested paths, escapes, link entries and parent replacement between check and write.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="go-tls-min"></a>

## GO-TLS-MIN. Obsolete minimum TLS version

**Search:** scanner rule GO-TLS-MIN. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-TLS-MIN` for details. Regex: MinVersion:tls.VersionSSL30/TLS10/TLS11 and assignments, including newlines; ==, !=, TLS12/TLS13 and 0 do not signal. SSL30 is obsolete and unsupported by modern Go. Review object/effective config/version; numbers, aliases, variables and external listener settings are not evaluated.

**Vulnerable example:** The setting lowers the minimum of the TLS client/server actually using it, if that runtime version/mode supports the old protocols.

~~~go
cfg := &tls.Config{}
cfg.MinVersion = tls.VersionTLS10
~~~

**Fix:** Choose TLS 1.2/1.3 minimum compatible with checker/peers while retaining certificate checks.

~~~go
cfg := &tls.Config{}
cfg.MinVersion = tls.VersionTLS12
~~~

**Verification:** Normal peers connect; versions below the chosen minimum fail.

Both MinVersion: tls.VersionTLS10 and cfg.MinVersion = tls.VersionTLS10 need review. Comparisons ==/!= do not change settings and do not trigger this signal. TLS12/TLS13 and 0 do not trigger it either; 0 selects the runtime default, not a verified security policy.

VersionSSL30 remains a legacy-configuration signal: the constant's existence does not mean modern Go supports SSLv3. Runtime version/mode and later overrides affect actual behavior. [Go: tls.Config](https://pkg.go.dev/crypto/tls#Config), [Go 1.24 MinVersion contract](https://github.com/golang/go/blob/go1.24.0/src/crypto/tls/common.go#L756).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'MinVersion|MaxVersion|TLSClientConfig|GetConfigForClient|crypto/tls|GODEBUG|GOFIPS140' .
~~~

Connect the object to the real TLS client/listener; review mutations, configuration callbacks, import aliases, numeric constants and environment-derived values. Regex establishes neither type nor reachability and may match comments. Semantics were reviewed against primary sources; this catalog review did not execute Go or TLS connections.

<a id="go-jwt-unverified"></a>

## GO-JWT-UNVERIFIED. JWT without signature or claims verification

**Search:** scanner rule GO-JWT-UNVERIFIED. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain GO-JWT-UNVERIFIED` for details. Regex: ParseUnverified and WithoutClaimsValidation; does not prove authentication uses the result. The example targets golang-jwt/jwt/v5.

**Vulnerable example:** Parsed does not mean verified; errors or disabled validation must never authorize a JWT.

~~~go
token, _, err := parser.ParseUnverified(raw, &claims)
~~~

**Fix:** Use a validating API with trusted keyfunc, algorithms and claims; check err before using token/claims.

~~~go
token, err := jwt.ParseWithClaims(raw, &claims, trustedKeyFunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("auth"), jwt.WithAudience("notes"), jwt.WithExpirationRequired())
if err != nil || !token.Valid { return ErrUnauthorized }
~~~

**Verification:** Signature/expiry/audience checks work, error nil tokens do not panic and valid tokens pass.

Primary documentation: [reference 1](https://pkg.go.dev/github.com/golang-jwt/jwt/v5).

<a id="go-upload-path"></a>

## GO-UPLOAD-PATH. Multipart filename used directly in a joined path

**Search:** scanner rule GO-UPLOAD-PATH. Use `--explain GO-UPLOAD-PATH` for the exact detector contract. Regex with lexical exclusions: filepath.Join with a simple first argument and a direct header/fileHeader/file.Filename second argument. The MIME parser may normalize filenames; the rule does not prove traversal, imported types or missing earlier validation.

**Vulnerable example:**

~~~go
path := filepath.Join(root, header.Filename)
~~~

**Fix:** Choose a non-overwriting server-side storage name outside executable/public roots; authorize downloads and enforce upload size/type.

~~~go
path := filepath.Join(root, serverGeneratedID)
~~~

**Verification:** Alternate separators, traversal, collisions and other-owner requests cannot change the chosen storage path; ordinary uploads work.

[Primary reference 1](https://pkg.go.dev/mime/multipart#FileHeader)
