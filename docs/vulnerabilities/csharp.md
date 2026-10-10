# C# / .NET: find, fix and verify

English | [Русский](csharp-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

20 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [CS-DESERIALIZE — Type-controlled .NET deserialization](#cs-deserialize)
- [CS-ENUM — Enum.TryParse requires an allowed-value check](#cs-enum)
- [CS-SQL — Dynamic .NET SQL](#cs-sql)
- [CS-GUID-BYTES — Byte-order Guid protocol boundary](#cs-guid-bytes)
- [CS-PROCESS — .NET process creation](#cs-process)
- [CS-IGNORE-FILTERS — Global query filters disabled](#cs-ignore-filters)
- [CS-ALLOWANON — AllowAnonymous route](#cs-allowanon)
- [CS-MASS-ASSIGN — Client entities update the database wholesale](#cs-mass-assign)
- [CS-XML — XML parser permits DTD or external resolver](#cs-xml)
- [CS-HTML-RAW — HTML output without escaping](#cs-html-raw)
- [CS-PATH — Path.Combine and GetFullPath do not check ownership](#cs-path)
- [CS-ARCHIVE — ZipArchive entries escape the directory](#cs-archive)
- [CS-CLAIMS — Incomplete JWT or claims validation](#cs-claims)
- [CS-ASYNC-VOID — async void hides authorization errors](#cs-async-void)
- [CS-REGEX-TIMEOUT — Untrusted regex input without a budget](#cs-regex-timeout)
- [CS-AUTH-FILTER-REDUCE — Simplification removes a mandatory authorization condition](#cs-auth-filter-reduce)
- [CS-COLLIDING-PRINCIPAL — A normalized character sum replaces a unique user ID](#cs-colliding-principal)
- [CS-JWT-VALIDATION — Weakened .NET token validation](#cs-jwt-validation)
- [CS-TLS-VALIDATION — HTTPS validation callback always accepts](#cs-tls-validation)
- [CS-LDAP-FILTER — DirectorySearcher filter concatenates a value](#cs-ldap-filter)

<a id="cs-deserialize"></a>

## CS-DESERIALIZE. Type-controlled .NET deserialization

**Search:** scanner rule CS-DESERIALIZE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-DESERIALIZE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~csharp
var formatter = new BinaryFormatter();
~~~

**Fix:** Use explicit DTOs and a supported serializer with schema/size checks; remove unrestricted type activation and migrate legacy data.

~~~csharp
var value = JsonSerializer.Deserialize<MessageDto>(json); // validate fields
~~~

**Verification:** Unknown types fail before side effects; valid records parse.

**A/D variant:** Deserialization triggers setter side effects. **FAUST / todo-list, source and organizer patch.** TypeNameHandling.Objects permits runtime-type selection; setting Filter model fields writes to the database. Checking the result after object construction may be too late.

**Patch:** A concrete DTO without external type selection, explicit validation and a separate persistence operation. **Test:** Unknown types create neither objects nor rows; normal import/export remains compatible. **Search:** CS-DESERIALIZE.

[source/write-up 1](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/deserialize.patch); [source/write-up 2](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/TodoController.cs); [source/write-up 3](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/Serializer.cs); [source/write-up 4](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/UserManager.cs); [source/write-up 5](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Models/Filter.cs).

<a id="cs-enum"></a>

## CS-ENUM. Enum.TryParse requires an allowed-value check

**Search:** scanner rule CS-ENUM. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-ENUM` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~csharp
bool ok = Enum.TryParse(input, out FilterKind kind);
~~~

**Fix:** Validate allowed named values; parsing success alone does not prove enum membership.

~~~csharp
if (!TryParseAllowedFilter(input, out FilterKind kind)) return BadRequest(); // helper validates named allowlist
~~~

**Verification:** Unnamed numeric values and unsupported flags fail; supported filters work.

**A/D variant:** Numeric enum values outside the allowed set. **Reference:** sneakers, RuCTF author write-up. TryParse may accept a number with no declared name. Scanner: CS-ENUM, including already-corrected call sites.

~~~csharp
if (!Enum.TryParse<FilterKind>(input, out var kind) ||
    !Enum.IsDefined(typeof(FilterKind), kind))
    return BadRequest();
~~~

Flags require an explicit allowed mask and combination policy. **Test:** Every allowed name, undeclared numbers, negative/oversized values and combinations. Value validation is not authorization.

[source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/sneakers/README.md).

<a id="cs-sql"></a>

## CS-SQL. Dynamic .NET SQL

**Search:** scanner rule CS-SQL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-SQL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~csharp
context.Notes.FromSqlRaw("SELECT * FROM notes WHERE name=" + name);
~~~

**Fix:** Use provider-supported parameters and allowlisted identifiers.

~~~csharp
context.Notes.FromSqlRaw("SELECT * FROM notes WHERE name={0}", name);
~~~

**Verification:** Quotes cannot change SQL structure; tenant restrictions remain.

<details>
<summary>Expanded example and limitations</summary>

```csharp
// Vulnerable: interpolation has already put client data into SQL source.
var rows = await db.Notes
    .FromSqlRaw($"SELECT * FROM Notes WHERE Title = '{title}'")
    .ToListAsync(ct);
```

**Minimal patch for a simple search: owner-scoped LINQ:**

```csharp
using Microsoft.EntityFrameworkCore;

var rows = await db.Notes
    .Where(n => n.OwnerId == currentUserId && n.Title == title)
    .ToListAsync(ct);
```

When raw SQL is necessary, FromSqlInterpolated receives a FormattableString and parameterizes values. Do not first convert it to string and then pass it to FromSqlRaw. FromSql appeared in EF Core 7; select the installed version's API. Column names require fixed selection.

**Check:** Apostrophes/Unicode remain literal search data, foreign rows are absent, and pagination/old records work. Test custom providers and LINQ translation against the actual database, not only an in-memory substitute.

</details>

<a id="cs-guid-bytes"></a>

## CS-GUID-BYTES. Byte-order Guid protocol boundary

**Search:** scanner rule CS-GUID-BYTES. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-GUID-BYTES` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~csharp
var value = new Guid(wireBytes);
~~~

**Fix:** Agree on byte order with peers; use canonical text or explicit conversion, not arbitrary reversal.

~~~csharp
var value = Guid.ParseExact(wireText, "D");
~~~

**Verification:** Asymmetric UUID vectors agree across C#/Python, database and cache.

<a id="cs-process"></a>

## CS-PROCESS. .NET process creation

**Search:** scanner rule CS-PROCESS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-PROCESS` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~csharp
Process.Start("sh", "-c " + command);
~~~

**Fix:** Prefer a library operation or fixed executable plus ArgumentList. UseShellExecute=false does not neutralize explicit sh/cmd or option injection.

~~~csharp
var digest = SHA256.HashData(Encoding.UTF8.GetBytes(text));
~~~

**Verification:** Quotes stay data and expected output format is preserved.

<details>
<summary>Expanded example and limitations</summary>

```csharp
// Vulnerable on Linux: UseShellExecute=false does not prevent explicit /bin/sh.
var psi = new System.Diagnostics.ProcessStartInfo("/bin/sh") { UseShellExecute = false };
psi.ArgumentList.Add("-c");
psi.ArgumentList.Add("printf '%s' '" + text + "' | sha256sum");
System.Diagnostics.Process.Start(psi);
```

**Patch for text SHA-256, .NET 6+:**

```csharp
using System.Security.Cryptography;
using System.Text;

static string DigestText(string text)
{
    ArgumentNullException.ThrowIfNull(text);
    byte[] sum = SHA256.HashData(Encoding.UTF8.GetBytes(text));
    return Convert.ToHexString(sum).ToLowerInvariant();
}
```

Preserve external formatting and encoding. If a process is genuinely required, separate executable and ArgumentList; users must still not select dangerous program options. Content SHA-256 is not standalone password storage.

**Check:** Known digest, empty text, Unicode, quotes/newlines; no child process or environment leakage on failure.

</details>

**Reference:** [primary source](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist).

<a id="cs-ignore-filters"></a>

## CS-IGNORE-FILTERS. Global query filters disabled

**Search:** scanner rule CS-IGNORE-FILTERS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-IGNORE-FILTERS` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~csharp
var rows = db.Notes.IgnoreQueryFilters().ToList();
~~~

**Fix:** Do not disable tenant/auth filters merely for soft-delete; admin bypass requires explicit authorization and query restrictions.

~~~csharp
var rows = db.Notes.Where(n => n.OwnerId == userId).ToList();
~~~

**Verification:** Test two tenants, deleted records and exports against the actual provider SQL.

**Reference:** [primary source](https://learn.microsoft.com/en-us/ef/core/querying/filters).

<a id="cs-allowanon"></a>

## CS-ALLOWANON. AllowAnonymous route

**Search:** scanner rule CS-ALLOWANON. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-ALLOWANON` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~csharp
[AllowAnonymous]
public IActionResult PrivateNote() => View();
~~~

**Fix:** Review effective endpoint metadata/ownership; AllowAnonymous may override Authorize. Login/health may be intentionally public.

~~~csharp
[Authorize]
public IActionResult PrivateNote() => View();
~~~

**Verification:** Public login works; private endpoints and nested operations require authorization.

**Reference:** [primary source](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple).

<a id="cs-mass-assign"></a>

## CS-MASS-ASSIGN. Client entities update the database wholesale

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Update\(|TryUpdateModelAsync|Bind\(|FromBody|SaveChanges' .
~~~

Compare DTOs, entities and mutable fields; ensure a second client object is not used after safely loading the owned one.

**Vulnerable example:**

`db.Update(clientNote)` applies OwnerId/Role from JSON.

**Fix:** Editable-fields DTO, lookup by ID+owner and explicit assignment; use concurrency tokens if ownership can change.

**Verification:** Owned fields change; another user's record/owner does not. Distinguish absent fields from null according to contract.

<details>
<summary>Expanded example and limitations</summary>

```csharp
// Vulnerable: the supplied entity may contain OwnerId and administrative fields.
db.Update(clientNote);
await db.SaveChangesAsync(ct);
```

**Patch:** Separate editable-fields DTO and an owner-scoped entity lookup. Declare the DTO in the project:

```csharp
public sealed record EditNoteRequest(string? Title, string? Body);
```

Controller action fragment with parameters `id` and `EditNoteRequest dto`:

```csharp
if (dto.Title is null || dto.Body is null)
    return BadRequest();

var note = await db.Notes.SingleOrDefaultAsync(
    n => n.Id == id && n.OwnerId == currentUserId, ct);
if (note is null)
    return NotFound();

note.Title = dto.Title;
note.Body = dto.Body;
await db.SaveChangesAsync(ct);
return NoContent();
```

This is a full update of both fields, not JSON Merge Patch. For partial updates distinguish omitted fields from explicit null. Do not pass a second request object to Update after safely loading the first. Concurrent ownership changes require a suitable transaction, conditional mutation or concurrency token.

**Check:** Owners edit title/body; foreign records/owners remain unchanged; supplied OwnerId is ignored; empty strings persist if allowed; wrong types fail. Unknown JSON fields may be ignored by the serializer—do not promise rejection without explicit configuration.

</details>

**Reference:** [primary source](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/model-binding).

<a id="cs-xml"></a>

## CS-XML. XML parser permits DTD or external resolver

**Search:** scanner rule CS-XML. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-XML` for details. Regex: DtdProcessing.Parse, XmlResolver=new XmlUrlResolver and ProhibitDtd=false. Defaults depend on framework/API; absence of a match is not proof of safety.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'XmlReaderSettings|DtdProcessing|XmlResolver|XmlDocument|XslCompiledTransform' .
~~~

Review explicit settings and the actual .NET version; modern safe defaults do not apply to every older API.

**Vulnerable example:**

An enabled DTD/resolver fetches external resources or expands the document.

**Fix:** Prohibit DTD, remove external resolver and bound input; pass these settings to the actual XmlReader.

**Verification:** Ordinary XML works; external resources/DTD fail and size is bounded.

**Reference:** [primary source](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings).

**Scanner example before:**

~~~csharp
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
~~~

**Fix template:**

~~~csharp
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1048576 };
~~~

Primary documentation: [reference 1](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075).

<a id="cs-html-raw"></a>

## CS-HTML-RAW. HTML output without escaping

**Search:** scanner rule CS-HTML-RAW. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-HTML-RAW` for details. Regex: Html.Raw and new HtmlString. Sanitization is not inferred from a call; trusted static markup may be legitimate.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Html.Raw|HtmlString|IHtmlContent|WriteLiteral' .
~~~

Determine data origin and Razor's actual HTML, JavaScript or attribute context.

**Vulnerable example:**

`Html.Raw(model.Text)` treats user-controlled HTML as trusted.

**Fix:** Use regular Razor output or an allowlisted HTML sanitizer for supported rich text; consider URL/JS context.

**Verification:** Untrusted tags, attributes and URLs cannot execute script; permitted text renders.

**Scanner example before:**

~~~csharp
@Html.Raw(Model.About)
~~~

**Fix template:**

~~~csharp
@Model.About
~~~

Primary documentation: [reference 1](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting).

<a id="cs-path"></a>

## CS-PATH. Path.Combine and GetFullPath do not check ownership

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Path.Combine|GetFullPath|File.Read|File.Write|PhysicalFile' .
~~~

Compare full path/root with OS, separator and symlink semantics; authorize the selected ID.

**Vulnerable example:**

An absolute second path replaces the root, or string StartsWith accepts a similarly named sibling directory.

**Fix:** Server-side names, component-aware containment and symlink policy; open writes without replacement races.

**Verification:** Windows/Linux forms, shared prefixes, outward links and own/foreign files.

<a id="cs-archive"></a>

## CS-ARCHIVE. ZipArchive entries escape the directory

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ZipArchive|ExtractToFile|ExtractToDirectory|FullName' .
~~~

Review the actual API version and custom entry loop; a safe helper does not protect separately implemented writes.

**Vulnerable example:**

`entry.FullName` becomes a path without containment or size limits.

**Fix:** Validate root/links and actual expanded volume; use a separate temporary tree and atomic publication.

**Verification:** Ordinary archives, absolute/traversal names, duplicate entries and expanded-size overflow.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="cs-claims"></a>

## CS-CLAIMS. Incomplete JWT or claims validation

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'TokenValidationParameters|ValidateIssuer|ValidateAudience|RequireExpirationTime|FindFirst' .
~~~

Review server-side issuer/audience/key/algorithm policy and missing claims; a signature does not authorize an object.

**Vulnerable example:**

A token intended for another purpose is accepted for authentication, or missing subject becomes a default user.

**Fix:** Explicit library validation contract, required subject/purpose and resource authorization; rotate keys without indefinite legacy fallback.

**Verification:** Wrong issuer/audience/expiry/purpose plus valid sessions and old data.

<a id="cs-async-void"></a>

## CS-ASYNC-VOID. async void hides authorization errors

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'async void|Task.Run|Authorize|async Task|GetAwaiter' .
~~~

Ensure callers await verification; background exceptions must not leave successful responses.

**Vulnerable example:**

Authorization or writes start without await while the handler continues returning data.

**Fix:** A Task-returning pipeline with await, fail-closed errors and request-scoped cancellation.

**Verification:** False/error/delayed checks never return protected data; legitimate requests complete.

<a id="cs-regex-timeout"></a>

## CS-REGEX-TIMEOUT. Untrusted regex input without a budget

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'new Regex|Regex.Match|Regex.IsMatch|Regex.Replace' .
~~~

Review timeout overloads/NonBacktracking support in the installed runtime and input length limits.

**Vulnerable example:**

A complex expression consumes a worker on a long near-match.

**Fix:** Bound size, simplify patterns, use supported timeout/NonBacktracking modes and treat RegexMatchTimeoutException as rejection.

**Verification:** Timeout never becomes permission; ordinary strings and required regex constructs still work.

<a id="cs-auth-filter-reduce"></a>

## CS-AUTH-FILTER-REDUCE. Simplification removes a mandatory authorization condition

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Distinct|Remove|Reduce|AdminFilter|Equals' .
~~~

Compare mandatory access conditions before and after query-tree simplification; inspect structural equality of filters.

**Vulnerable example:**

**Reference:** sneakers, RuCTF author write-up. Filter-object equality and expression simplification could remove AdminFilter.

**Search:** distinct/remove/set/dedup/reduce on query ASTs, record structural equality where identity was expected, and combinations of client/server filters.

**Fix:** Add mandatory authorization outside user-controlled simplification and verify it before execution. Changing record to class in one write-up is not a universal remedy.

**Verification:** Equivalent, duplicate and nested filters never broaden access; predicate order does not affect permissions.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/sneakers/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/sneakers/README.md).

<a id="cs-colliding-principal"></a>

## CS-COLLIDING-PRINCIPAL. A normalized character sum replaces a unique user ID

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'UserId|UserName|ToLower|Reverse|Sum' .
~~~

Compare normalized names, computed IDs and owner keys across export/read/update.

**Vulnerable example:**

**FAUST / todo-list, source and organizer patch.** Name transformations and character sums identify owners; different names can collide.

**Fix:** Authorize with stable unique principals from trusted storage and migrate existing records coherently. Fix every read/export path.

**Verification:** Two names sharing the old ID never share access.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/deserialize.patch); [source/write-up 2](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/TodoController.cs); [source/write-up 3](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/Serializer.cs); [source/write-up 4](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Services/UserManager.cs); [source/write-up 5](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/service/service/Models/Filter.cs).

**Reference:** [primary source](https://github.com/fausecteam/faustctf-2024-todo-list-service/blob/e9ee8b8807c64eeb6f71a72e16f709a558525d2c/patches/deserialize.patch).

<a id="cs-jwt-validation"></a>

## CS-JWT-VALIDATION. Weakened .NET token validation

**Search:** scanner rule CS-JWT-VALIDATION. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-JWT-VALIDATION` for details. Regex: explicit false for ValidateLifetime/Issuer/Audience and RequireSignedTokens/ExpirationTime. ValidateIssuerSigningKey=false alone is not treated as missing signature verification.

**Vulnerable example:** Disabling lifetime/issuer/audience validation or signature requirements accepts tokens outside the intended contract.

~~~csharp
new TokenValidationParameters { ValidateLifetime = false, ValidateAudience = false, RequireSignedTokens = false };
~~~

**Fix:** Validate signature, key, time, issuer and audience; custom validators must retain these invariants.

~~~csharp
new TokenValidationParameters { ValidateLifetime = true, ValidateAudience = true, ValidAudience = "notes", ValidateIssuer = true, ValidIssuer = "auth", RequireSignedTokens = true, RequireExpirationTime = true, IssuerSigningKey = trustedKey };
~~~

**Verification:** Unsigned, expired and foreign tokens fail; valid tokens pass.

Primary documentation: [reference 1](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters).

<a id="cs-tls-validation"></a>

## CS-TLS-VALIDATION. HTTPS validation callback always accepts

**Search:** scanner rule CS-TLS-VALIDATION. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CS-TLS-VALIDATION` for details. Regex: DangerousAcceptAnyServerCertificateValidator and simple true-lambdas for certificate callbacks. Arbitrary methods and block-bodied lambdas need manual review.

**Vulnerable example:** An unconditional certificate-accepting callback bypasses standard TLS validation.

~~~csharp
handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
~~~

**Fix:** Use default certificate checks and trusted CA; custom trust must not unconditionally accept.

~~~csharp
var handler = new HttpClientHandler();
var client = new HttpClient(handler);
~~~

**Verification:** Valid certificates work; wrong host/CA and expiry fail.

Primary documentation: [reference 1](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.dangerousacceptanyservercertificatevalidator).

<a id="cs-ldap-filter"></a>

## CS-LDAP-FILTER. DirectorySearcher filter concatenates a value

**Search:** scanner rule CS-LDAP-FILTER. Use `--explain CS-LDAP-FILTER` for the exact detector contract. Regex with lexical exclusions: new DirectorySearcher with a first string literal concatenated with an identifier. Does not inspect Filter assignments, interpolated strings, helper implementations or arbitrary type aliases.

**Vulnerable example:**

~~~csharp
var query = new DirectorySearcher("(uid=" + name + ")");
~~~

**Fix:** Use a reviewed LDAP filter builder with filter-context escaping and fixed attribute/scope policy; the helper is application-specific.

~~~csharp
var query = new DirectorySearcher(BuildReviewedLdapFilter(name)); // helper implements filter-context escaping
~~~

**Verification:** Metacharacters cannot add conditions or broaden results; supported lookups remain compatible.

[Primary reference 1](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher.filter)
