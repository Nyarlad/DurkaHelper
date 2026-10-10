# C / C++: find, fix and verify

English | [Русский](c-cpp-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

28 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [C-BOUNDS — Unbounded C/C++ copy](#c-bounds)
- [C-FORMAT — Variable used as a format string](#c-format)
- [C-SHELL — C/C++ shell execution](#c-shell)
- [C-PRNG — Ordinary PRNG/LCG near a possible secret](#c-prng)
- [C-SNPRINTF-FORMAT — Variable format in bounded printf](#c-snprintf-format)
- [C-RECV-TERMINATOR — recv/read result used as an index](#c-recv-terminator)
- [C-ATOI — atoi without checked conversion](#c-atoi)
- [C-REALLOC — Overwriting the only pointer with realloc](#c-realloc)
- [C-SIZE-OVERFLOW — Size arithmetic overflow](#c-size-overflow)
- [CPP-LIFETIME — A pointer or view outlives its owner](#cpp-lifetime)
- [C-PARTIAL-IO — TCP does not preserve message boundaries](#c-partial-io)
- [C-SIGNED-LENGTH — Signed lengths become huge size_t values](#c-signed-length)
- [C-DOUBLE-FREE — Multiple owners free the same object](#c-double-free)
- [C-UNINITIALIZED — Exposing padding or uninitialized tails](#c-uninitialized)
- [C-TEMPFILE-RACE — Temporary filename without atomic creation](#c-tempfile-race)
- [C-JIT-RETURN — Not every JIT function path terminates](#c-jit-return)
- [C-HEADER-SECRET — A special header branch changes a secret](#c-header-secret)
- [C-OBJECT-TOCTOU — Re-reading mutable references after authorization](#c-object-toctou)
- [C-EXEC-FAILURE — Failed exec leaves a child on the server path](#c-exec-failure)
- [CPP-CACHED-LIFETIME — Cached pointers survive object destruction](#cpp-cached-lifetime)
- [C-BLOCK-TAIL — Four-byte block processing corrupts the tail](#c-block-tail)
- [C-ALLOC-FAILURE — Allocation failure becomes a NULL write](#c-alloc-failure)
- [C-FD-NUL — Descriptor leaks amplify a read_line off-by-one](#c-fd-nul)
- [C-REENTRANCY-AUTH — A callback runs between authorization and signing](#c-reentrancy-auth)
- [C-BUILTIN-TYPES — One builtin overload omits argument-type checks](#c-builtin-types)
- [C-HASH-INDEX — Hash-table indices exceed the upper boundary](#c-hash-index)
- [C-STRNCPY — strncpy may omit NUL termination](#c-strncpy)
- [C-COPY-LENGTH — Copy length comes directly from source strlen](#c-copy-length)

<a id="c-bounds"></a>

## C-BOUNDS. Unbounded C/C++ copy

**Search:** scanner rule C-BOUNDS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-BOUNDS` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
strcpy(destination, source);
~~~

**Fix:** Check length/capacity before copying and check snprintf's result; mechanical strncpy replacement is insufficient.

~~~c
size_t n = strlen(source);
if (n >= capacity) return ERROR;
memcpy(destination, source, n + 1);
~~~

**Verification:** Test empty, boundary and oversized input; use ASan/UBSan where available.

<details>
<summary>Expanded example and limitations</summary>

```c
/* Vulnerable: capacity and available source length are unchecked. */
char dst[64];
memcpy(dst, src, client_len);
dst[client_len] = '\0';
```

**Patch for a protocol field defined as a C string without embedded NUL:**

<!-- example: c-copy-text -->

```c
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

bool copy_text(char *dst, size_t capacity, const char *src,
               size_t available, size_t requested) {
    if (dst == NULL || src == NULL || capacity == 0) return false;
    if (requested > available || requested >= capacity) return false;
    if (memchr(src, '\0', requested) != NULL) return false;
    memmove(dst, src, requested);
    dst[requested] = '\0';
    return true;
}
```

available means bytes actually accessible, not the client's claimed size. Reject negative signed lengths **before** conversion to size_t. memmove permits overlap; failure leaves dst unchanged. The caller must handle false rather than transmit old buffer contents.

**Check:** Empty string, capacity−1, capacity, insufficient source, zero capacity and embedded NUL; rejection leaves the buffer unchanged. Binary data may contain NUL and needs a different explicit-length contract. Silent strncpy truncation can corrupt identifiers or checker data.

</details>

<a id="c-format"></a>

## C-FORMAT. Variable used as a format string

**Search:** scanner rule C-FORMAT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-FORMAT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
printf(message);
~~~

**Fix:** Use a fixed format and checked arguments; pass explicit lengths for binary data.

~~~c
printf("%s", message);
~~~

**Verification:** Percent characters print without interpreting directives.

<details>
<summary>Expanded example and limitations</summary>

```c
/* Vulnerable: message controls the format and argument interpretation. */
printf(message);
```

**Patch when message is a valid NUL-terminated string:**

<!-- example: c-write-message -->

```c
#include <stdbool.h>
#include <stdio.h>

bool write_message(FILE *out, const char *message) {
    if (out == NULL || message == NULL) return false;
    return fputs(message, out) != EOF;
}
```

Alternatively use fprintf(out, "%s", message) with a fixed format. For length-delimited network buffers use validated length and fwrite rather than assuming NUL termination. Handle write errors separately.

**Check:** %s, %% and Unicode print literally; empty strings work; avoid extra newlines if the protocol forbids them.

</details>

<a id="c-shell"></a>

## C-SHELL. C/C++ shell execution

**Search:** scanner rule C-SHELL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-SHELL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
system(command);
~~~

**Fix:** Use execve/posix_spawn with fixed program and validated argv; handle errors.

~~~c
run_fixed_tool(validated_filename); // fixed executable + argv inside
~~~

**Verification:** Metacharacters are not interpreted by a shell.

<a id="c-prng"></a>

## C-PRNG. Ordinary PRNG/LCG near a possible secret

**Search:** scanner rule C-PRNG. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-PRNG` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
srand((unsigned)time(NULL));
token = rand();
~~~

**Fix:** Use system CSPRNG/supported crypto and check results; ordinary non-security randomness may use a PRNG.

~~~c
if (!fill_from_os_csprng(token, sizeof token)) return ERROR; // implement using supported OS/library API
~~~

**Verification:** No predictable seed/fallback exists; token format stays compatible.

**A/D variant:** Access identifiers from a time-seeded LCG. **ENOWARS / piratesay, author write-up.** An identifier permitted user switching while its generator depended on startup time.

**Patch:** System CSPRNG and server-side credential/user binding. A hidden constant seed is not a sound fix. **Test:** New IDs and old sessions according to migration policy; entropy failure without fallback. **Search:** C-PRNG; inspect custom generators manually.

[source/write-up 1](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/documentation/README.md); [source/write-up 2](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/cli.c); [source/write-up 3](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/session.c).

<a id="c-snprintf-format"></a>

## C-SNPRINTF-FORMAT. Variable format in bounded printf

**Search:** scanner rule C-SNPRINTF-FORMAT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-SNPRINTF-FORMAT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
snprintf(out, capacity, message);
~~~

**Fix:** Use a fixed format; buffer limits do not secure untrusted format strings. Trace wrappers/macros.

~~~c
snprintf(out, capacity, "%s", message);
~~~

**Verification:** Percent characters stay text, truncation is handled; legitimate wrappers may still match.

**A/D variant:** Format strings in a 'safe' wrapper. **ENOWARS / piratesay, author write-up.** Bounded writes and filtering a few specifiers did not stop another layer interpreting user text as a format.

**Patch:** Fixed format at the final sink, data passed separately; trace macro → wrapper → printf-family. **Test:** Literal percent signs and handled truncation. **Search:** C-FORMAT, C-SNPRINTF-FORMAT; arbitrary wrapper names are not recognized automatically.

[source/write-up 1](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/documentation/README.md); [source/write-up 2](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/cli.c); [source/write-up 3](https://github.com/enowars/enowars8-service-piratesay/blob/32973478dbe903d0a2446539ecbddf3b1c334e60/service_source/src/session.c).

<a id="c-recv-terminator"></a>

## C-RECV-TERMINATOR. recv/read result used as an index

**Search:** scanner rule C-RECV-TERMINATOR. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-RECV-TERMINATOR` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
n = recv(fd, buffer, sizeof buffer, 0);
buffer[n] = '\0';
~~~

**Fix:** Reserve NUL space, handle negative/EOF results before indexing, and handle short reads. Correct code may still match.

~~~c
ssize_t n = recv(fd, buffer, sizeof buffer - 1, 0);
if (n <= 0) return ERROR;
buffer[n] = '\0';
~~~

**Verification:** Test errors, EOF, full buffer, short reads and normal messages.

<a id="c-atoi"></a>

## C-ATOI. atoi without checked conversion

**Search:** scanner rule C-ATOI. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-ATOI` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
int size = atoi(input);
~~~

**Fix:** Use checked conversion with end-pointer, range and errno validation; define the accepted numeric grammar.

~~~c
// use strtol/strtoull with errno, end pointer, sign and application bounds checks
~~~

**Verification:** Empty, trailing junk, signs and overflow fail; permitted boundary values work.

**Reference:** [primary source](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/rules/error-handling-err/err34-c/).

<a id="c-realloc"></a>

## C-REALLOC. Overwriting the only pointer with realloc

**Search:** scanner rule C-REALLOC. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-REALLOC` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~c
buffer = realloc(buffer, size);
~~~

**Fix:** Keep the original pointer until allocation succeeds; handle zero size and overflow according to the intended contract.

~~~c
void *next = realloc(buffer, size);
if (next == NULL) { /* preserve buffer; handle error */ }
else { buffer = next; }
~~~

**Verification:** Allocation failure leaks no original allocation and does not cause invalid access.

**Reference:** [primary source](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/memory-management-mem/mem04-c/).

<a id="c-size-overflow"></a>

## C-SIZE-OVERFLOW. Size arithmetic overflow

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'malloc|calloc|resize|reserve|sizeof|memcpy' .
~~~

Check SIZE_MAX and the application limit before multiplying/adding; check sign before casting.

**Vulnerable example:**

`malloc(count * sizeof(Item))` allocates less than the later copy requires after overflow.

**Fix:** Checked multiplication/addition and actual capacity; handle zero and allocation failure separately.

**Verification:** Zero, boundaries, product/sum overflow, negative inputs and existing buffers.

<details>
<summary>Expanded example and limitations</summary>

```c
/* Vulnerable: count * sizeof(Item) can overflow. */
Item *items = malloc(count * sizeof(*items));
```

**Patch for arithmetic and the agreed size limit:**

<!-- example: c-array-bytes -->

```c
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool array_bytes(size_t count, size_t item_size, size_t max_bytes, size_t *out) {
    if (out == NULL || item_size == 0) return false;
    if (count > SIZE_MAX / item_size) return false;
    size_t total = count * item_size;
    if (total > max_bytes) return false;
    *out = total;
    return true;
}
```

Call this before malloc with sizeof(*items) and a contractual limit; check allocation success. Handle count zero explicitly: malloc(0) returning NULL does not alone imply failure. Never use out after rejection. Adding headers/terminators needs a separate addition check; this function checks only multiplication.

**Check:** Zero, one, exact budget, budget overflow and products above SIZE_MAX; errors never copy into stale/NULL buffers.

</details>

<a id="cpp-lifetime"></a>

## CPP-LIFETIME. A pointer or view outlives its owner

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'c_str\(|string_view|span|return.*data|return.*&' .
~~~

Identify the data owner and destruction/reallocation points; inspect async callbacks and lambda captures.

**Vulnerable example:**

A temporary string's c_str or a local buffer's string_view is returned.

**Fix:** Return an owning object/copy; transfer ownership through async completion. A view does not extend lifetime.

**Verification:** Results survive return, later calls do not corrupt them, and async work retains data until completion.

<details>
<summary>Expanded example and limitations</summary>

```cpp
// Vulnerable: the temporary string dies before the returned pointer is used.
const char* make_label(const std::string& name) {
    return (std::string("hello ") + name).c_str();
}
```

**Patch: return an owning object, not a pointer into destroyed storage:**

<!-- example: cpp-label -->

```cpp
#include <string>

std::string make_label(const std::string& name) {
    return std::string("hello ") + name;
}
```

The caller stores std::string label = make_label(name). Its c_str may be passed to a synchronous API that does not retain the pointer past the string's lifetime. Async operations need ownership/copies. string_view alone neither prolongs lifetime nor fixes this issue.

**Check:** Results remain valid after return and subsequent calls, including empty names and Unicode; async paths retain data through completion.

</details>

<a id="c-partial-io"></a>

## C-PARTIAL-IO. TCP does not preserve message boundaries

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'recv|read\(|send|write\(|Content-Length|length' .
~~~

Compare frame length with accumulated bytes and review short-read/write loops, EINTR and EOF.

**Vulnerable example:**

One recv is treated as a complete request, or a partial send causes the next frame to merge with a private response.

**Fix:** Explicit framing, bounded accumulation, partial-operation handling and timeouts; retain the checker protocol.

**Verification:** Byte-by-byte fragmentation, two coalesced frames, mid-frame EOF and normal messages.

<a id="c-signed-length"></a>

## C-SIGNED-LENGTH. Signed lengths become huge size_t values

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ssize_t|size_t|uint32_t|int.*len|memcpy|recv' .
~~~

Trace every cast between reading/parsing and allocation/indexing.

**Vulnerable example:**

A negative read result or client integer is converted to unsigned before validation.

**Fix:** Check errors, sign and range before conversion; verify source/destination capacity.

**Verification:** read=-1, EOF, negative fields, maximum and normal payloads.

<a id="c-double-free"></a>

## C-DOUBLE-FREE. Multiple owners free the same object

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'free\(|delete|unique_ptr|shared_ptr|goto.*fail' .
~~~

Trace success/error cleanup and ownership transfers; look for two shared_ptr instances built from one raw pointer.

**Vulnerable example:**

An error path and its caller both free an object, or reset destroys an object still in use.

**Fix:** One explicit owner/RAII with explicit ownership transfer; clearing one alias does not repair others.

**Verification:** Failure at every construction step, repeated cleanup and normal lifecycle.

<a id="c-uninitialized"></a>

## C-UNINITIALIZED. Exposing padding or uninitialized tails

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'malloc|struct|send|write|sizeof|memcpy' .
~~~

Compare initialized fields with transmitted struct sizeof and padding.

**Vulnerable example:**

`send(fd, &record, sizeof record, ...)` exposes padding or previous contents.

**Fix:** Explicit field/length serialization and initialized buffers; never use native layout as an implicit wire protocol.

**Verification:** Different compiler/layout choices, short input and no uninitialized response bytes.

<a id="c-tempfile-race"></a>

## C-TEMPFILE-RACE. Temporary filename without atomic creation

**Search:** scanner rule C-TEMPFILE-RACE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-TEMPFILE-RACE` for details. Regex: tmpnam/tempnam/mktemp. Custom filename schemes, reopening after mkstemp and directory TOCTOU need manual review.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'tmpnam|mktemp|access\(|stat\(|fopen|open\(' .
~~~

Trace existence-check → open and parent-directory permissions.

**Vulnerable example:**

A shared temporary filename is checked, then opened for overwrite through a replaced symlink.

**Fix:** Create a private file atomically, retain its fd, check errors/modes and close/remove it on all paths.

**Verification:** Concurrent operations get separate fds; existing files/symlinks are not overwritten.

**Scanner example before:**

~~~native
char name[L_tmpnam];
tmpnam(name);
FILE *f = fopen(name, "w");
~~~

**Fix template:**

~~~native
char name[] = "/tmp/app-XXXXXX";
int fd = mkstemp(name);
if (fd < 0) return ERROR;
unlink(name);
/* use fd; close(fd) on every exit */
~~~

Primary documentation: [reference 1](https://pubs.opengroup.org/onlinepubs/9799919799/functions/mkstemp.html).

<a id="c-jit-return"></a>

## C-JIT-RETURN. Not every JIT function path terminates

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'return|emit|jit|compile|bytecode' .
~~~

Map function control-flow exits; a conditional return does not cover the other branch or fall-through.

**Vulnerable example:**

**Reference:** dcs, RuCTF author write-up: a conditional return was mistakenly considered sufficient and execution continued beyond the function. **Search:** Custom VMs/JITs/DSLs, searching for a return node rather than reachability analysis, and constants placed next to instructions.

**Fix:** Control-flow analysis requiring every reachable exit to return a value or terminate with a defined error. Separate code/data and validate indices/types before generation.

**Verification:** Both conditional branches, nesting, empty functions and normal computations. Disabling JIT entirely is acceptable only if the functional contract remains intact.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/dcs/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/dcs/README.md).

<a id="c-header-secret"></a>

## C-HEADER-SECRET. A special header branch changes a secret

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'getenv|HTTP_USER_AGENT|SECRET_KEY|constructor' .
~~~

Read init/constructor and debug/test branches; client headers must not change keys.

**Vulnerable example:**

**Reference:** reversaar, saarCTF C-source analysis: a special HTTP_USER_AGENT-linked path modified SECRET_KEY. **Search:** Constructor/init hooks, header getenv, magic constants, debug/test/admin branches in release builds and hidden signing switches.

**Fix:** Remove the unintended transition specifically; secret configuration must not depend on requests. Inspect startup code, not only routes.

**Verification:** Different headers do not change keys, privileges or storage format; normal initialization survives. There is no scanner signature for the specific magic value; manually trace input-to-secret relationships.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/reversaar/service/src/array.c).

**Reference:** [primary source](https://github.com/saarsec/saarctf-2024/blob/3a06d18974ca177c6dd251a11bdf9b4b334f382a/reversaar/service/src/array.c).

<a id="c-object-toctou"></a>

## C-OBJECT-TOCTOU. Re-reading mutable references after authorization

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'background|fork|exec|open|read' .
~~~

Find repeated mutable-object reads after checks/external calls; compare object identity and snapshots.

**Vulnerable example:**

**RuCTF / memos, author write-up.** An external operation occurred between checking background access and reading it; another request could replace the selected object.

**Fix:** Use the same validated snapshot/descriptor or atomically check its version before use.

**Verification:** Barrier-controlled request interleaving and legitimate long-running operations.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

<a id="c-exec-failure"></a>

## C-EXEC-FAILURE. Failed exec leaves a child on the server path

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'fork|execve|execvp|waitpid' .
~~~

Trace every fork/exec error and child termination, including oversized argument vectors.

**Vulnerable example:**

**RuCTF / memos, author write-up.** A child could continue server logic after execve failed.

**Fix:** Check fork/exec/wait; on child-side exec failure close extra descriptors and terminate with failing _exit.

**Verification:** Missing executables, excessive arguments and fork failure never create a second server.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/memos/README.md).

<a id="cpp-cached-lifetime"></a>

## CPP-CACHED-LIFETIME. Cached pointers survive object destruction

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'cache|delete|free|flush|shared_ptr|weak_ptr' .
~~~

Identify the cached pointer's owner and destruction point; trace method calls after eviction.

**Vulnerable example:**

**RuCTF / perune, author write-up.** Subsequent cache traversal called a virtual method on a freed object.

**Fix:** Explicit ownership, removal of every reference at destruction, safe handles/weak references or validated generation IDs.

**Verification:** Different create/delete/flush orderings and available sanitizers; absence of a crash proves nothing by itself.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/perune/readme.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/perune/readme.md).

<a id="c-block-tail"></a>

## C-BLOCK-TAIL. Four-byte block processing corrupts the tail

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'xor|chacha|uint32_t|length|remaining' .
~~~

Check one-to-three-byte remainders with a four-byte stride against actual allocation.

**Vulnerable example:**

**ECSC / Diese HSM, author write-up.** XOR crossed the end when length was not word-aligned.

**Fix:** Complete blocks followed by a separately bounded tail; check alignment.

**Verification:** Lengths 0–9, buffer boundaries, canaries and valid nonces.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [source/write-up 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

**Reference:** [primary source](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md).

<a id="c-alloc-failure"></a>

## C-ALLOC-FAILURE. Allocation failure becomes a NULL write

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'malloc|calloc|alloc|memcpy' .
~~~

Trace NULL/allocation failures to the first write, including custom allocators and firmware address spaces.

**Vulnerable example:**

**ECSC / Diese HSM, author and source.** An allocator result was unchecked while address zero was accessible in firmware.

**Fix:** Checked size arithmetic, message limits and allocation-failure handling across the entire chain.

**Verification:** Failure at every allocation and truncated packets.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md); [source/write-up 2](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/webapp/src/classes/Utils.class.php); [source/write-up 3](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/hsm/src/msg.c).

**Reference:** [primary source](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/Diese/README.md).

<a id="c-fd-nul"></a>

## C-FD-NUL. Descriptor leaks amplify a read_line off-by-one

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'read_line|open|close|fopen|fclose' .
~~~

Inspect descriptor closure on login failures and NUL writes when buffers are full.

**Vulnerable example:**

**ECSC / CookingNonna, author write-up.** Failed login leaked an fd while a terminator could be written beyond a full buffer.

**Fix:** Unified cleanup for every failure; reserve NUL space, check read/EOF and compare open results with -1.

**Verification:** Capacities 0/1/max, long lines and repeated failures without descriptor growth.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/CookingNonna/README.md).

**Reference:** [primary source](https://github.com/ECSC2024/ECSC2024-CTF-AD/blob/2a92e17384ad228072a84fb076a35066fe2ffeff/sources/CookingNonna/README.md).

<a id="c-reentrancy-auth"></a>

## C-REENTRANCY-AUTH. A callback runs between authorization and signing

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'callback|SignToken|Len|ByRef' .
~~~

Find user callbacks after ownership checks; determine whether they can mutate the signed arguments.

**Vulnerable example:**

**ICC / MaScroll, author write-up.** An overridable Len changed a reference argument after its owner check.

**Fix:** Validate an immutable copy; do not invoke user code between verification and the sensitive operation.

**Verification:** A callback changes the original, but only the checked copy is signed.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

**Reference:** [primary source](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

<a id="c-builtin-types"></a>

## C-BUILTIN-TYPES. One builtin overload omits argument-type checks

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'FastRand|CryptoRand|variant|overload|builtin' .
~~~

Compare every overload's argument types, including the common first argument and error paths.

**Vulnerable example:**

**ICC / MaScroll, author write-up.** One generator call form skipped type checks; the resulting memory error affected cryptographic state.

**Fix:** Uniform type/arity/length validation for every overload, with correct ownership and buffers.

**Verification:** Type/argument-count matrix; errors never modify RNG or signing state.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

**Reference:** [primary source](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

<a id="c-hash-index"></a>

## C-HASH-INDEX. Hash-table indices exceed the upper boundary

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'TABLE_SIZE|capacity|hash|table\[' .
~~~

Calculate min/max indices and array size for every branch; inspect insert/find and representation changes.

**Vulnerable example:**

**DEF CON / bisbee, source and header.** A remainder modulo TABLE_SIZE plus one indexed a TABLE_SIZE-element array.

**Fix:** Keep indices in [0, capacity), consistently across operations; review list/hashmap migration and update counters.

**Verification:** First/last buckets, collisions, repeated updates and representation switching.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [source/write-up 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [source/write-up 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [source/write-up 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [source/write-up 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [source/write-up 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Reference:** [primary source](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).

<a id="c-strncpy"></a>

## C-STRNCPY. strncpy may omit NUL termination

**Search:** scanner rule C-STRNCPY. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain C-STRNCPY` for details. Regex: strncpy. Review later NUL termination and actual capacity; memcpy without length checks is not a fix.

**Vulnerable example:** strncpy does not terminate sufficiently long input; later string APIs read beyond the buffer.

~~~native
strncpy(out, input, sizeof out);
puts(out);
~~~

**Fix:** Choose reject-too-long or explicit bounded truncation with NUL space; use explicit lengths for binary data.

~~~native
size_t n = bounded_input_length;
if (n >= sizeof out) return ERROR;
memcpy(out, input, n);
out[n] = '\0';
~~~

**Verification:** Test empty/capacity-1/capacity/capacity+1; truncation cannot change identity.

Primary documentation: [reference 1](https://pubs.opengroup.org/onlinepubs/9799919799/functions/strncpy.html).

<a id="c-copy-length"></a>

## C-COPY-LENGTH. Copy length comes directly from source strlen

**Search:** scanner rule C-COPY-LENGTH. Use `--explain C-COPY-LENGTH` for the exact detector contract. Regex with lexical exclusions: memcpy/memmove with simple first two arguments and strlen/strnlen directly as length. Does not prove missing preceding checks or actual buffer sizes; custom same-named APIs and macros require review.

**Vulnerable example:**

~~~native
memcpy(dest, input, strlen(input) + 1);
~~~

**Fix:** Validate readable source length and destination capacity before copying, including terminator and arithmetic overflow.

~~~native
size_t n = validated_length;
if (n >= capacity) return ERROR;
memcpy(dest, input, n + 1);
~~~

**Verification:** Test empty input, capacity boundaries, missing terminator and overflow using sanitizers where available.

[Primary reference 1](https://pubs.opengroup.org/onlinepubs/9799919799/functions/memcpy.html)
