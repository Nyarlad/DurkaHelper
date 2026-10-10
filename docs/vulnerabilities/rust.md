# Rust: find, fix and verify

English | [Русский](rust-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

18 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [RUST-UNSAFE-CONVERSION — Rust unchecked/raw conversion](#rust-unsafe-conversion)
- [RUST-SQL-FORMAT — Rust SQL using format!](#rust-sql-format)
- [RUST-STATIC-MUT — Shared mutable Rust state](#rust-static-mut)
- [RUST-AUTHORIZATION — A typed ID does not authorize its owner](#rust-authorization)
- [RUST-SERDE-FIELDS — serde entities accept administrative fields](#rust-serde-fields)
- [RUST-PANIC-INPUT — unwrap and byte slicing on request input](#rust-panic-input)
- [RUST-COMMAND — Shell launched from Rust](#rust-command)
- [RUST-LOCK-AWAIT — Holding locks across await](#rust-lock-await)
- [RUST-UNBOUNDED-READ — Potentially unbounded Rust stream read](#rust-unbounded-read)
- [RUST-FFI-OWNERSHIP — FFI retains a pointer after drop](#rust-ffi-ownership)
- [RUST-SSRF — reqwest redirects and URL policies](#rust-ssrf)
- [RUST-NUMERIC-CAST — as truncates a size value](#rust-numeric-cast)
- [RUST-DISTRIBUTED-CAS — Logical races in distributed state](#rust-distributed-cas)
- [RUST-FFI-LENGTH — Passing declared length instead of Rust buffer length to C](#rust-ffi-length)
- [RUST-PATH-PREFIX — Prefix validation and filesystem fallback](#rust-path-prefix)
- [RUST-FFI-ABI — C and Rust extern return types disagree](#rust-ffi-abi)
- [RUST-TLS — Rust HTTP accepts invalid certificates](#rust-tls)
- [RUST-JWT-VALIDATION — Rust JWT checks disabled](#rust-jwt-validation)

<a id="rust-unsafe-conversion"></a>

## RUST-UNSAFE-CONVERSION. Rust unchecked/raw conversion

**Search:** scanner rule RUST-UNSAFE-CONVERSION. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUST-UNSAFE-CONVERSION` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~rust
let text = unsafe { std::str::from_utf8_unchecked(data) };
~~~

**Fix:** Prefer checked APIs; necessary unsafe needs length, alignment, lifetime, initialization and aliasing proofs. Do not remove it blindly.

~~~rust
let text = std::str::from_utf8(data)?;
~~~

**Verification:** Test invalid UTF-8/length/index and EOF; use Miri/sanitizers where prepared.

<a id="rust-sql-format"></a>

## RUST-SQL-FORMAT. Rust SQL using format!

**Search:** scanner rule RUST-SQL-FORMAT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUST-SQL-FORMAT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~rust
sqlx::query(&format!("SELECT * FROM notes WHERE name={}", name));
~~~

**Fix:** Use driver binding and allowlisted identifiers; placeholder syntax is database-specific.

~~~rust
sqlx::query("SELECT * FROM notes WHERE name=$1").bind(name);
~~~

**Verification:** Quotes remain data and ownership predicates work.

<a id="rust-static-mut"></a>

## RUST-STATIC-MUT. Shared mutable Rust state

**Search:** scanner rule RUST-STATIC-MUT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUST-STATIC-MUT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~rust
static mut CURRENT_USER: u64 = 0;
~~~

**Fix:** Use ownership or synchronized primitives with clear invariants; review all unsafe accesses and cross-request state.

~~~rust
static CURRENT_USER: std::sync::Mutex<u64> = std::sync::Mutex::new(0);
~~~

**Verification:** Concurrent requests do not race or leak another user's data; ordinary operations work.

**Reference:** [primary source](https://doc.rust-lang.org/reference/items/static-items.html).

<a id="rust-authorization"></a>

## RUST-AUTHORIZATION. A typed ID does not authorize its owner

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Path<|State<|Extension<|find_by_id|owner|tenant' .
~~~

Trace extractors to SELECT/UPDATE and session verification; a compile-time type does not bind the ID to the caller.

**Vulnerable example:**

A deserialized NoteId loads another user's record.

**Fix:** Query by ID plus server-derived owner/policy; check tenant boundaries for nested resources and jobs.

**Verification:** Owner, other user, anonymous caller, cross-tenant access, lists and exports.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

<a id="rust-serde-fields"></a>

## RUST-SERDE-FIELDS. serde entities accept administrative fields

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Deserialize|flatten|default|deny_unknown_fields|serde' .
~~~

Compare request DTOs/entities, role defaults and flatten; deny_unknown_fields has compatibility limitations with flatten.

**Vulnerable example:**

The client supplies owner/admin, or a missing field's default grants privileges.

**Fix:** A separate allowlisted DTO, explicit validation and server-derived authorization fields; a bool type is not a permission check.

**Verification:** Extra/missing fields, nulls, nested objects and normal payloads.

<a id="rust-panic-input"></a>

## RUST-PANIC-INPUT. unwrap and byte slicing on request input

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'unwrap\(|expect\(|\[[0-9]+\.\.|parse::<|from_utf8' .
~~~

Review Result/Option handling and UTF-8 boundaries; determine whether panic terminates a task, worker or process.

**Vulnerable example:**

`parse().unwrap()` or `&name[..32]` panics on malformed, short or multibyte input.

**Fix:** Controlled errors, checked get/ranges and size bounds; do not conceal every failure with an empty default.

**Verification:** Invalid UTF-8/numbers, short strings, multibyte boundaries and normal requests.

<a id="rust-command"></a>

## RUST-COMMAND. Shell launched from Rust

**Search:** scanner rule RUST-COMMAND. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUST-COMMAND` for details. Regex: Command::new with literal sh/bash/dash/zsh/cmd/powershell/pwsh. A command may be trusted; review -c, variable executables and .args.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Command::new|\.arg\(|\.args\(|sh|cmd.exe' .
~~~

Review the executable, every argument, environment and cwd; separate argv do not disable a program's dangerous options.

**Vulnerable example:**

`Command::new("sh").arg("-c").arg(input)` gives a shell client-controlled text.

**Fix:** Use a fixed executable, separate arguments, allowlisted options and bounded time/output.

**Verification:** Metacharacters stay data; dangerous options cannot change behavior.

**Scanner example before:**

~~~rust
Command::new("sh").arg("-c").arg(command).output()?;
~~~

**Fix template:**

~~~rust
Command::new("/usr/bin/file").arg("--").arg(validated_name).output()?;
~~~

Primary documentation: [reference 1](https://doc.rust-lang.org/std/process/struct.Command.html).

<a id="rust-lock-await"></a>

## RUST-LOCK-AWAIT. Holding locks across await

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'lock\(|\.await|Mutex|RwLock|DashMap' .
~~~

Review guard scope, reentrancy and the ordering of multiple locks.

**Vulnerable example:**

A request holds a lock during I/O while another path waits on a dependent resource, causing deadlock or exhaustion.

**Fix:** Minimize critical sections; use snapshots/versions with a repeated atomic check. Do not release a lock between authorization and mutation without equivalent protection.

**Verification:** Barrier-controlled concurrent requests, cancellation and slow upstreams do not block the whole application.

<a id="rust-unbounded-read"></a>

## RUST-UNBOUNDED-READ. Potentially unbounded Rust stream read

**Search:** scanner rule RUST-UNBOUNDED-READ. Regex with lexical exclusions: stream/socket/request/reader.read_to_end/read_to_string. Receiver names are hints, not types; an already bounded receiver may match and other names/wrappers may be missed.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'read_to_end|read_to_string|read_line|collect\(|to_bytes' .
~~~

Trace bounds on bytes actually read and time spent, including chunked streams.

**Vulnerable example:**

A client-controlled stream accumulates in memory until EOF.

**Fix:** Bound reads, detect limit+1 and enforce an appropriate timeout; Read::take alone silently stops at its limit.

**Verification:** Test EOF, limit-1, limit, limit+1 and a slow never-ending source; valid maximum documents work.


**Scanner example before:**

~~~rust
stream.read_to_end(&mut payload)?;
~~~

**Fix template:**

~~~rust
let mut bounded = stream.take(MAX_BYTES + 1);
bounded.read_to_end(&mut payload)?;
if payload.len() as u64 > MAX_BYTES { return Err(too_large()); }
~~~


<a id="rust-ffi-ownership"></a>

## RUST-FFI-OWNERSHIP. FFI retains a pointer after drop

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'CString|into_raw|from_raw|as_ptr|extern|free' .
~~~

Compare lifetimes, allocators and both sides' pointer-retention contracts.

**Vulnerable example:**

C retains as_ptr from a temporary Rust object, or C free releases memory belonging to another allocator.

**Fix:** Explicit ownership transfer with a matching deallocator; keep owners alive through callbacks, use FFI-safe types and handle panic boundaries.

**Verification:** Delayed callbacks, duplicate frees, C-side errors and normal teardown.

**Reference:** [primary source](https://doc.rust-lang.org/nomicon/ffi.html).

<a id="rust-ssrf"></a>

## RUST-SSRF. reqwest redirects and URL policies

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'reqwest|Client::builder|redirect|Url::parse|resolve' .
~~~

Review URL parsing, redirect policy and transport DNS; a Url value proves parsing, not permission.

**Vulnerable example:**

An initially permitted URL redirects into a different trust zone.

**Fix:** A server-side destination map or destination policy on every redirect and actual connection, with limits.

**Verification:** Mock DNS/redirects/timeouts, normal upstream access and prohibited schemes.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="rust-numeric-cast"></a>

## RUST-NUMERIC-CAST. as truncates a size value

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e ' as u8| as u16| as u32| as usize|wrapping_|unchecked_' .
~~~

Check source range and destination type before allocation, indexing or database lookup.

**Vulnerable example:**

A wide integer is truncated by as, making distinct IDs/sizes identical.

**Fix:** TryFrom, checked arithmetic and protocol bounds; reject negative values before unsigned conversion.

**Verification:** Maximum, maximum+1, negative and normal values under release/debug behavior.

<a id="rust-distributed-cas"></a>

## RUST-DISTRIBUTED-CAS. Logical races in distributed state

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'etcd|txn|compare|round|version' .
~~~

Compare read/write revisions across workers; a process-local Mutex does not protect a remote transaction.

**Vulnerable example:**

**RuCTF / rustest, author write-up.** Multiple requests checked the same round version and independently recorded a result.

**Fix:** Storage transactions/CAS on the version and atomic consumption of one-use state. A single process's Mutex is insufficient across workers.

**Verification:** Parallel answers produce exactly one state transition; retries never score twice.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/rustest/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-2023/blob/0cc333e44f2ba6908ff6c5d613146e3b00173315/writeups/rustest/README.md).

<a id="rust-ffi-length"></a>

## RUST-FFI-LENGTH. Passing declared length instead of Rust buffer length to C

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'extern|as_ptr|as_mut_ptr|size_t|memcpy' .
~~~

Compare pointer/length pairs on both sides: the actual allocated slice length, not the client's claim.

**Vulnerable example:**

**DEF CON / bisbee, source.** FFI store_data receives decoded_data.as_ptr() and an independently selected block_size; C copies size bytes.

**Fix:** Check declared size against the actual slice and limit; pass the validated buffer's length.

**Verification:** Smaller, equal and larger sizes, decoding failures and empty input.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [source/write-up 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [source/write-up 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [source/write-up 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [source/write-up 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [source/write-up 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Reference:** [primary source](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).

**A/D variant:** In FlagDrive (ENOWARS10), capacity was calculated over a whole structure including an administrative flag, although data belonged only in the token array. Use the subarray's actual length/capacity, remove invalid reinterpretation and retain separate ownership checks. Test maximum token length and maximum+1 without changing adjacent authorization state. [Author write-up](https://github.com/enowars/enowars10-service-flagdrive/blob/d1575098fe2c516460136bb5fba11d9a1c4af3f7/documentation/FLAGSTORE_1.md). This is a service-specific memory-boundary/conversion defect, not a claim of a compiler defect.

<a id="rust-path-prefix"></a>

## RUST-PATH-PREFIX. Prefix validation and filesystem fallback

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'username|canonicalize|create_dir|fs::read|fs::write' .
~~~

Compare the validated prefix with the entire path; check UTF-8 boundaries and alternative filesystem fallbacks.

**Vulnerable example:**

**DEF CON / bisbee, source.** Only part of username is checked, while the full name forms a path; an internal database miss falls back to file reading.

**Fix:** Validate the complete name and UTF-8 boundaries, select storage paths server-side, and apply identical authorization to primary and fallback paths.

**Verification:** Short/long/multibyte names, separators in the suffix and database misses.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [source/write-up 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [source/write-up 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [source/write-up 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [source/write-up 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [source/write-up 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Reference:** [primary source](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).

<a id="rust-ffi-abi"></a>

## RUST-FFI-ABI. C and Rust extern return types disagree

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'extern|store_data|c_void|size_t' .
~~~

Compare C headers/implementation with Rust declarations: return type, signedness, layout and calling convention.

**Vulnerable example:**

**DEF CON / bisbee, source and header.** C store_data returns void; Rust declares i8 and uses that result to select a fallback.

**Fix:** A shared ABI contract/generated bindings; consume status only through a real, identically typed return value. Never base error handling on an uninitialized result.

**Verification:** Builds with warnings, size/signedness/return-type agreement and ordinary storage failures.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs); [source/write-up 2](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.c); [source/write-up 3](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv.h); [source/write-up 4](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.c); [source/write-up 5](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_hashmap.h); [source/write-up 6](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/db/kv_list.c).

**Reference:** [primary source](https://github.com/Nautilus-Institute/finals-2024/blob/f17456fed4ff40e6f4f1237ed4b82c242e52ec67/bisbee/src/service/src/main.rs).

<a id="rust-tls"></a>

## RUST-TLS. Rust HTTP accepts invalid certificates

**Search:** scanner rule RUST-TLS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUST-TLS` for details. Regex: danger_accept_invalid_certs/hostnames(true), including reqwest/native-tls-like builders. Review variable values and custom verifiers.

**Vulnerable example:** Dangerous builder flags disable certificate/hostname validation.

~~~rust
let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
~~~

**Fix:** Use default validation and add the internal root CA instead of bypassing checks.

~~~rust
let client = reqwest::Client::builder().add_root_certificate(trusted_ca).build()?;
~~~

**Verification:** Correct CA/host works; invalid certificates/hostnames fail.

Primary documentation: [reference 1](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html).

<a id="rust-jwt-validation"></a>

## RUST-JWT-VALIDATION. Rust JWT checks disabled

**Search:** scanner rule RUST-JWT-VALIDATION. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUST-JWT-VALIDATION` for details. Regex: insecure_disable_signature_validation, validate_exp/validate_aud=false and legacy dangerous_*decode. API depends on jsonwebtoken version.

**Vulnerable example:** Without signature or expiry validation, decoded claims are insufficient grounds for granting access.

~~~rust
validation.insecure_disable_signature_validation();
validation.validate_exp = false;
~~~

**Fix:** Use verifying decode with a trusted key and Validation contract; check its result before access.

~~~rust
let mut validation = Validation::new(Algorithm::RS256);
validation.set_audience(&["notes"]);
validation.set_issuer(&["auth"]);
validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);
~~~

**Verification:** Invalid signatures, expiry and missing required fields fail.

Primary documentation: [reference 1](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html).
