# Java: find, fix and verify

English | [Русский](java-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

18 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [JAVA-OBJECT — Java ObjectInputStream](#java-object)
- [JAVA-RNG — java.util.Random near a possible secret](#java-rng)
- [JAVA-SQL — Dynamic JDBC SQL](#java-sql)
- [JAVA-PROCESS — Java process execution](#java-process)
- [JAVA-JACKSON-TYPES — Jackson default typing](#java-jackson-types)
- [JAVA-XML — XML parser needs an external-resource policy](#java-xml)
- [JAVA-EXPRESSION — Client text parsed as SpEL](#java-expression)
- [JAVA-PATH — Path resolve without a root boundary](#java-path)
- [JAVA-ZIP-SLIP — ZipEntry becomes an output path](#java-zip-slip)
- [JAVA-SPRING-BIND — Spring binds request data into a domain entity](#java-spring-bind)
- [JAVA-SECURITY-MATCHER — Matcher ordering and method security](#java-security-matcher)
- [JAVA-THREADLOCAL — ThreadLocal leaks the previous request's user](#java-threadlocal)
- [JAVA-REGEX-DOS — A regular expression blocks a worker](#java-regex-dos)
- [JAVA-JNDI — Dynamic JNDI lookup name](#java-jndi)
- [JAVA-ERROR-LEAK — Stack traces and SQL in API errors](#java-error-leak)
- [JAVA-HOSTNAME-VERIFY — Hostname verifier accepts every peer](#java-hostname-verify)
- [JAVA-SPRING-CSRF — Spring Security CSRF disabled](#java-spring-csrf)
- [JAVA-LDAP-FILTER — JNDI search filter assembled by concatenation](#java-ldap-filter)

<a id="java-object"></a>

## JAVA-OBJECT. Java ObjectInputStream

**Search:** scanner rule JAVA-OBJECT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-OBJECT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~java
ObjectInputStream in = new ObjectInputStream(stream);
~~~

**Fix:** Prefer constrained DTO parsing over native object deserialization; migrate trusted legacy data separately.

~~~java
Message value = parseValidatedMessage(stream);
~~~

**Verification:** Unknown types cannot be constructed; ordinary messages stay compatible.

<a id="java-rng"></a>

## JAVA-RNG. java.util.Random near a possible secret

**Search:** scanner rule JAVA-RNG. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-RNG` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~java
Random rng = new Random();
~~~

**Fix:** Use SecureRandom and sufficient token length for secrets.

~~~java
SecureRandom rng = new SecureRandom();
~~~

**Verification:** No predictable seed or fallback exists; valid tokens work.

**A/D variant:** Public PRNG output and secret challenges. **Reference:** 8-bit-oracle, the author's write-up and saarCTF Java source. One java.util.Random instance generated both public values and challenges. Hashing a 32-bit value does not enlarge its secret space. Scanner: JAVA-RNG; Random outside a security context can be legitimate.

**Patch:** Use sufficiently long SecureRandom.nextBytes output without predictable seeds; public statistics must not share secret-generator state.
**Test:** Challenge format and one-time use, randomness source/length and the normal verification workflow. Statistical tests do not prove cryptographic strength.

[Source/write-up 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/8-bit-oracle/README.md); [source/write-up 2](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/8-bit-oracle/service/_8BitOracle/src/Util.java).

<a id="java-sql"></a>

## JAVA-SQL. Dynamic JDBC SQL

**Search:** scanner rule JAVA-SQL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-SQL` for details. Regex: executeQuery/executeUpdate/execute/prepareStatement/prepareCall with concatenation or String.format. PreparedStatement does not secure already-built SQL; inspect SQL variables and formatter wrappers.

**Vulnerable example:**

~~~java
statement.executeQuery("SELECT id FROM notes WHERE name=" + name);
~~~

**Fix:** Bind values with PreparedStatement, not already-concatenated SQL; allowlist identifiers.

~~~java
PreparedStatement q = connection.prepareStatement("SELECT id FROM notes WHERE name=?");
q.setString(1, name);
q.executeQuery();
~~~

**Verification:** Quotes stay data and ownership remains enforced.

<details>
<summary>Expanded example and limitations</summary>

```java
// Vulnerable: inputId is interpolated into SQL without an owner constraint.
ResultSet rs = statement.executeQuery("SELECT body FROM notes WHERE id = '" + inputId + "'");
```

**JDBC patch for a private note:**

```java
import java.sql.*;
import java.util.Optional;

final class NoteReader {
    static Optional<String> read(Connection db, Long userId, long noteId) throws SQLException {
        if (userId == null) throw new SecurityException("authentication required");
        try (PreparedStatement st = db.prepareStatement(
                "SELECT body FROM notes WHERE id = ? AND owner_id = ?")) {
            st.setLong(1, noteId);
            st.setLong(2, userId);
            try (ResultSet rows = st.executeQuery()) {
                return rows.next() ? Optional.of(rows.getString("body")) : Optional.empty();
            }
        }
    }
}
```

The example assumes `body NOT NULL`. If NULL is allowed, distinguish it from a missing row. The statement/result set are closed, but not the caller-owned connection. Parse incoming IDs with error handling. PreparedStatement around an already concatenated query does not fix injection.

**Check:** Owner, other user, anonymous caller; invalid/missing IDs; old data; database errors must not become successful empty responses.

</details>

<a id="java-process"></a>

## JAVA-PROCESS. Java process execution

**Search:** scanner rule JAVA-PROCESS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-PROCESS` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~java
Runtime.getRuntime().exec(command);
~~~

**Fix:** Use a library operation or fixed executable with validated argv and bounded time/output.

~~~java
runValidatedConversion(inputPath); // fixed executable and validated argv inside
~~~

**Verification:** Arguments cannot choose another operation; output stays compatible.

<details>
<summary>Expanded example and limitations</summary>

```java
// Vulnerable: ProcessBuilder does not protect an explicit shell command.
Process p = new ProcessBuilder("sh", "-c", "printf '%s' '" + text + "' | sha256sum").start();
```

**Patch for a string's SHA-256 digest:**

```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class ContentDigest {
    static String of(String text) throws NoSuchAlgorithmException {
        byte[] sum = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(sum);
    }
}
```

`HexFormat` requires Java 17; on older runtimes use the existing reviewed hex encoder rather than upgrading the entire service for this example. Never share mutable MessageDigest state across threads. Preserve the response format; this digest is not a password-storage algorithm.

**Check:** Known digest, empty text, Unicode and quotes; reject null at the API boundary; no external program runs.

</details>

<a id="java-jackson-types"></a>

## JAVA-JACKSON-TYPES. Jackson default typing

**Search:** scanner rule JAVA-JACKSON-TYPES. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-JACKSON-TYPES` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~java
mapper.enableDefaultTyping();
~~~

**Fix:** Prefer explicit DTOs; required polymorphism needs a narrow type set/validator for the installed version, not a package-wide allowlist.

~~~java
// deserialize into a fixed DTO without client-selected implementation types
~~~

**Verification:** Unknown types fail before side effects; valid documents remain readable.

**Reference:** [primary source](https://github.com/FasterXML/jackson-docs/wiki/JacksonPolymorphicDeserialization).

<a id="java-xml"></a>

## JAVA-XML. XML parser needs an external-resource policy

**Search:** scanner rule JAVA-XML. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-XML` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~java
var f = DocumentBuilderFactory.newInstance();
~~~

**Fix:** Restrict DTD/entities/schema/XSLT on the actual factory and set limits; never silently ignore unsupported security options.

~~~java
var f = DocumentBuilderFactory.newInstance();
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
// also configure DTD/entity policy and parser-specific limits
~~~

**Verification:** Parser reads no external files/URLs; ordinary XML and size limits work.

**Reference:** [primary source](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html).

<a id="java-expression"></a>

## JAVA-EXPRESSION. Client text parsed as SpEL

**Search:** scanner rule JAVA-EXPRESSION. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-EXPRESSION` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~java
parser.parseExpression(input).getValue(context);
~~~

**Fix:** Use fixed operations/arguments or a restricted DSL and evaluation context; never expose arbitrary reflection.

~~~java
lookupAllowedOperation(operationId, validatedArguments);
~~~

**Verification:** Disallowed operations cannot reach runtime; approved calculations work.

**Reference:** [primary source](https://docs.spring.io/spring-framework/reference/core/expressions.html).

<a id="java-path"></a>

## JAVA-PATH. Path resolve without a root boundary

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'resolve\(|readAllBytes|new File|Paths.get|toRealPath' .
~~~

Compare root and target Paths after normalization/link resolution; check ownership and open-time races.

**Vulnerable example:**

`Files.readAllBytes(base.resolve(name))` reads a client-selected name without a boundary.

**Fix:** Derive a server-side filename from an authorized ID, or enforce Path containment with an explicit symlink policy and safe opening; bound reads.

**Verification:** Sibling directory with a shared prefix, absolute path, symlink, another owner's object and a legitimate file.

<details>
<summary>Expanded example and limitations</summary>

```java
// Vulnerable: name can move the read outside the permitted directory.
byte[] data = Files.readAllBytes(base.resolve(name));
```

**Patch for existing files in a trusted immutable tree:**

```java
import java.io.IOException;
import java.nio.file.*;

final class FileBoundary {
    static Path existingFile(Path base, String name) throws IOException {
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("path required");
        Path relative = Path.of(name);
        if (relative.isAbsolute()) throw new IllegalArgumentException("relative path required");
        Path root = base.toRealPath();
        Path target = root.resolve(relative).toRealPath();
        if (!target.startsWith(root) || !Files.isRegularFile(target)) {
            throw new IllegalArgumentException("outside allowed directory");
        }
        return target;
    }
}
```

`startsWith` here is a **Path** method, not string-prefix comparison. `toRealPath` requires existence and resolves symlinks. A mutable tree still permits TOCTOU between checking and opening: use platform-supported directory-relative safe opening. This snippet is not for writing or archive extraction. Authorization and read limits remain separate requirements.

**Check:** Allowed file, similarly named sibling directory, absolute path, outward link, missing file and another user's file.

</details>

**Reference:** [primary source](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/Path.html).

<a id="java-zip-slip"></a>

## JAVA-ZIP-SLIP. ZipEntry becomes an output path

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ZipInputStream|ZipFile|getName\(|resolve\(' .
~~~

Trace every entry through target selection to writing, including directory names and link metadata.

**Vulnerable example:**

An archive name is joined to a directory without containment or checking the actual filesystem tree.

**Fix:** Validate all paths/types, avoid untrusted links, limit expanded size/entries and publish only after success.

**Verification:** Ordinary archive, absolute/traversal entries, volume overflow and cleanup after rejection.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="java-spring-bind"></a>

## JAVA-SPRING-BIND. Spring binds request data into a domain entity

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '@ModelAttribute|@RequestBody|DataBinder|setAllowedFields|BeanUtils' .
~~~

Compare public setters, nested properties and ownership fields with incoming data.

**Vulnerable example:**

The binder writes owner/admin/status into an entity before authorization.

**Fix:** A dedicated request DTO with allowed fields, copied explicitly after authorization; restrict nested paths.

**Verification:** Administrative fields and nested updates cannot change; legitimate partial updates work.

<a id="java-security-matcher"></a>

## JAVA-SECURITY-MATCHER. Matcher ordering and method security

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'SecurityFilterChain|requestMatchers|permitAll|PreAuthorize|EnableMethodSecurity' .
~~~

Check the first matching rule, all HTTP methods, dispatch types and whether method security is actually enabled.

**Vulnerable example:**

A broad permitAll precedes a private rule, or the method annotation is inactive.

**Fix:** Explicit route policy with default denial for private areas and resource checks in the service layer; preserve intended public endpoints.

**Verification:** Anonymous, ordinary and administrator users get their expected routes/methods; error/forward dispatch does not bypass authorization.

<a id="java-threadlocal"></a>

## JAVA-THREADLOCAL. ThreadLocal leaks the previous request's user

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ThreadLocal|SecurityContext|Executor|CompletableFuture|remove\(' .
~~~

Review set/remove inside finally and context propagation into thread pools.

**Vulnerable example:**

A thread is reused after an exception with the previous principal still attached.

**Fix:** Use the framework's security-context lifecycle or explicit cleanup; give async tasks minimal immutable context.

**Verification:** Sequential different users on the same worker and an exception between context setup and cleanup.

<a id="java-regex-dos"></a>

## JAVA-REGEX-DOS. A regular expression blocks a worker

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Pattern.compile|Matcher|matches\(|replaceAll' .
~~~

Review nested quantifiers and long near-matches; request timeout does not necessarily interrupt the matcher.

**Vulnerable example:**

Backtracking on client input occupies a worker beyond the HTTP timeout.

**Fix:** Simplify the pattern or use a deterministic parser, limit input length and, where compatible, use a bounded-complexity engine.

**Verification:** Long failing matches finish within budget; normal formats and Unicode remain compatible.

<a id="java-jndi"></a>

## JAVA-JNDI. Dynamic JNDI lookup name

**Search:** scanner rule JAVA-JNDI. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-JNDI` for details. Regex: InitialContext.doLookup or ctx/context/initialContext.lookup with a non-string argument. Inspect arbitrary receiver names and indirect calls manually.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'InitialContext|JndiTemplate|lookup\(|NamingManager' .
~~~

Trace the name/provider URL and local object factories; disabling remote codebases does not remove other effects.

**Vulnerable example:**

The client selects the resource/service for a lookup using application privileges.

**Fix:** Use a closed map of trusted local names and restrict providers; JDK updates do not replace input validation.

**Verification:** Valid resources resolve; unknown/external names cannot initiate lookups or change backend.

**Scanner example before:**

~~~java
Object value = context.lookup(requestName);
~~~

**Fix template:**

~~~java
Object value = context.lookup("java:comp/env/jdbc/Notes");
~~~

Primary documentation: [reference 1](https://docs.oracle.com/en/java/javase/21/docs/api/java.naming/javax/naming/InitialContext.html).

<a id="java-error-leak"></a>

## JAVA-ERROR-LEAK. Stack traces and SQL in API errors

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'printStackTrace|getMessage\(|ResponseEntity|ExceptionHandler' .
~~~

Compare private logs with client response bodies for authorization, SQL and parser failures.

**Vulnerable example:**

An exception exposes SQL, paths, connection strings or secret arguments to the client.

**Fix:** Return a standard encoded error with correlation ID; redact sensitive values before logging.

**Verification:** Diagnostics remain private; error responses contain no private data.

<a id="java-hostname-verify"></a>

## JAVA-HOSTNAME-VERIFY. Hostname verifier accepts every peer

**Search:** scanner rule JAVA-HOSTNAME-VERIFY. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-HOSTNAME-VERIFY` for details. Regex: NoopHostnameVerifier/ALLOW_ALL_HOSTNAME_VERIFIER and setHostnameVerifier with a simple true-lambda. Review complex callbacks and TrustManager separately.

**Vulnerable example:** Certificate-chain validation without hostname validation does not authenticate the intended server.

~~~java
builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
~~~

**Fix:** Restore the default verifier and trusted store instead of always-true callbacks.

~~~java
builder.setSSLHostnameVerifier(new DefaultHostnameVerifier());
~~~

**Verification:** Trusted CA certificates for another host fail; the intended endpoint works.

Primary documentation: [reference 1](https://hc.apache.org/httpcomponents-client-5.5.x/current/httpclient5/apidocs/org/apache/hc/client5/http/ssl/NoopHostnameVerifier.html).

<a id="java-spring-csrf"></a>

## JAVA-SPRING-CSRF. Spring Security CSRF disabled

**Search:** scanner rule JAVA-SPRING-CSRF. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain JAVA-SPRING-CSRF` for details. Regex: csrf().disable(), csrf(x -> x.disable()) and csrf(AbstractHttpConfigurer::disable). Review individual security chains and matchers.

**Vulnerable example:** Global disable can remove CSRF protection from cookie-authenticated operations.

~~~java
http.csrf(csrf -> csrf.disable());
~~~

**Fix:** Keep protection for browser routes; restrict exemptions to an explicit bearer/webhook contract with no cookie fallback.

~~~java
http.csrf(Customizer.withDefaults());
~~~

**Verification:** Valid CSRF requests work; cookie POST without a token fails; approved API scenarios work.

Primary documentation: [reference 1](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html).

<a id="java-ldap-filter"></a>

## JAVA-LDAP-FILTER. JNDI search filter assembled by concatenation

**Search:** scanner rule JAVA-LDAP-FILTER. Use `--explain JAVA-LDAP-FILTER` for the exact detector contract. Regex with lexical exclusions: ctx/context/dirContext.search with a simple first argument and directly concatenated string filter. Does not resolve receiver types, prebuilt filters, wrappers or earlier escaping.

**Vulnerable example:**

~~~java
ctx.search(base, "(uid=" + name + ")", controls);
~~~

**Fix:** Use JNDI filter arguments with a fixed filter, and retain explicit search scope and authorization.

~~~java
ctx.search(base, "(uid={0})", new Object[] { name }, controls);
~~~

**Verification:** Filter metacharacters remain values; unauthorized entries stay inaccessible and valid searches work.

[Primary reference 1](https://docs.oracle.com/javase/jndi/tutorial/ldap/search/search.html)
