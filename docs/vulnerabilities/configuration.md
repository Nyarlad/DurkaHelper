# Configuration and trust boundaries: find, fix and verify

English | [Русский](configuration-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

64 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [CFG-SECRET — Literal secret or default key](#cfg-secret)
- [CFG-DEBUG — Debug enabled in configuration](#cfg-debug)
- [CFG-CORS — Broad CORS policy](#cfg-cors)
- [CFG-DOCKER-PRIV — Privileged container](#cfg-docker-priv)
- [CFG-DOCKER-SOCKET — Docker socket exposed to a service](#cfg-docker-socket)
- [CFG-DOCKER-ROOT — Explicit Docker USER root](#cfg-docker-root)
- [CFG-WORLD-WRITE — Broad write permissions](#cfg-world-write)
- [CFG-NGINX-LIST — nginx directory listing](#cfg-nginx-list)
- [CFG-NGINX-ALIAS — Review nginx alias boundaries](#cfg-nginx-alias)
- [CFG-POSTGRES-TRUST — PostgreSQL trust](#cfg-postgres-trust)
- [CFG-REDIS-PROTECTION — Redis protected-mode disabled](#cfg-redis-protection)
- [TPL-RAW — Unescaped template output](#tpl-raw)
- [SRC-MIXED-IDENTIFIER — Mixed Latin/Cyrillic/Greek identifier](#src-mixed-identifier)
- [SRC-BIDI-CONTROL — Bidirectional text control in source](#src-bidi-control)
- [CFG-REDIS-ACL — Redis ACL user without a password](#cfg-redis-acl)
- [CFG-MONGO-NOAUTH — MongoDB authorization disabled](#cfg-mongo-noauth)
- [CFG-CAPABILITIES — Broad container capabilities](#cfg-capabilities)
- [CFG-BUILD-SECRET — Secret in Dockerfile ARG/ENV](#cfg-build-secret)
- [CFG-NGINX-AUTH-OFF — Nested nginx location disables auth_request](#cfg-nginx-auth-off)
- [CFG-FILE-MODE — Configuration, data-directory and ACL permissions](#cfg-file-mode)
- [CFG-BIND-MOUNT — Writable mounts expose hosts or neighboring data](#cfg-bind-mount)
- [CFG-K8S-RBAC — Workload bound to cluster-admin](#cfg-k8s-rbac)
- [CFG-NGINX-LOCATION — URI normalization and location selection](#cfg-nginx-location)
- [CFG-STATIC-SECRETS — Static roots expose .git, backups, databases and logs](#cfg-static-secrets)
- [CFG-COOKIE-FLAGS — Explicitly weakened session cookie flags](#cfg-cookie-flags)
- [CFG-TRUSTED-HEADERS — Backends trust client-supplied user, role or IP](#cfg-trusted-headers)
- [CFG-CACHE-AUTH — Shared HTTP caches retain personalized responses](#cfg-cache-auth)
- [CFG-DEBUG-ENDPOINT — Diagnostics become public APIs](#cfg-debug-endpoint)
- [CFG-ERROR-SECRET — Logs expose credentials or private request bodies](#cfg-error-secret)
- [CFG-RESOURCE-LIMITS — Body, decompression and multipart limits](#cfg-resource-limits)
- [CFG-UPLOAD-EXEC — Uploads become executable or active content](#cfg-upload-exec)
- [CFG-HTTP-PARSER — Proxy and backend disagree on framing](#cfg-http-parser)
- [CFG-CORS-CREDENTIALS — CORS reflects Origin with credentials](#cfg-cors-credentials)
- [CFG-RESET-TOKEN — Recovery or share tokens lack purpose or one-time use](#cfg-reset-token)
- [CFG-OBJECT-POLICY — Alternative endpoints expose an object directly](#cfg-object-policy)
- [CFG-DEPLOYED-CONFIG — Reviewing an example instead of effective configuration](#cfg-deployed-config)
- [CFG-MEDIA-CONVERTER — Media documents load additional resources](#cfg-media-converter)
- [CFG-FORMAT-TRANSITION — Injection through intermediate YAML](#cfg-format-transition)
- [CFG-PRINCIPAL-CONTEXT — Clients modify authorization context](#cfg-principal-context)
- [CFG-AUTH-TOCTOU — Authorization races and identifier reuse](#cfg-auth-toctou)
- [CFG-CUSTOM-CRYPTO — Algebraic leakage in custom cryptography](#cfg-custom-crypto)
- [CFG-SHARED-BACKEND-KEY — One credential spans all child environments](#cfg-shared-backend-key)
- [CFG-WINDOWS-NAMES — Filenames have different Windows meanings](#cfg-windows-names)
- [CFG-PROXY-REDIRECT — Reverse proxies follow redirects into trusted services](#cfg-proxy-redirect)
- [CFG-PROTOCOL-KEY — Degenerate values in cryptographic protocols](#cfg-protocol-key)
- [CFG-AGGREGATE-KEY — Incorrect public-key aggregation](#cfg-aggregate-key)
- [CFG-K8S-HOST — Container shares host namespaces](#cfg-k8s-host)
- [CFG-UNCONFINED — seccomp/AppArmor profile disabled](#cfg-unconfined)
- [CFG-PRIV-ESCALATION — Process privilege escalation allowed](#cfg-priv-escalation)
- [CFG-ACTUATOR — Spring Actuator exposes every endpoint](#cfg-actuator)
- [CFG-H2-CONSOLE — H2 web console enabled](#cfg-h2-console)
- [CFG-TLS-UPSTREAM — Proxy does not verify upstream TLS](#cfg-tls-upstream)
- [CFG-SSH-EMPTY-PASSWORD — SSHD permits empty passwords](#cfg-ssh-empty-password)
- [CFG-SUDO-ALL — Unrestricted passwordless sudo](#cfg-sudo-all)
- [CFG-JWT-KEY-SELECTION — Untrusted kid/jku selects verification keys](#cfg-jwt-key-selection)
- [CFG-SIGNED-REQUEST — Signatures are not bound to operations or preventable replays](#cfg-signed-request)
- [CFG-RATE-LIMIT-IDENTITY — Senders choose their rate-limit identity](#cfg-rate-limit-identity)
- [CFG-TOKEN-REVOCATION — Password or role changes fail to revoke access](#cfg-token-revocation)
- [CFG-FAIL-OPEN — Verification errors become permission](#cfg-fail-open)
- [CFG-LDAP-FILTER — LDAP filters or DNs built as strings](#cfg-ldap-filter)
- [CFG-CI-TRUST — Untrusted data and code cross CI trust boundaries](#cfg-ci-trust)
- [CFG-DOCKER-TCP — Docker daemon listens on every TCP interface](#cfg-docker-tcp)
- [CFG-FLOATING-IMAGE — Explicit latest image tag](#cfg-floating-image)
- [TPL-AUTOESCAPE-OFF — Template block disables autoescaping](#tpl-autoescape-off)

<a id="cfg-secret"></a>

## CFG-SECRET. Literal secret or default key

**Search:** scanner rule CFG-SECRET. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-SECRET` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
JWT_SECRET = "development"
~~~

**Fix:** Check active fallbacks; read secrets from private configuration. Rotate with migration/rollback for sessions and data.

~~~text
JWT_SECRET = load_existing_secret()
~~~

**Verification:** No shared fallback remains; legitimate sessions/data stay recoverable.

**A/D variant:** Shared signing secret. **Reference:** lost_museum, RuCTF author write-up: a fixed shared JWT key. **Search:** Key literals, defaults and identical keys across roles/teams. Scanner: CFG-SECRET, with partial name coverage.

**Patch:** An independently configured secret and explicit rotation policy. Do not simply change keys and invalidate every legitimate session. Temporarily accepting an old compromised key leaves its compromise active: use safe server-side migration/reverification, not indefinite fallback. **Test:** Old/new sessions according to migration policy, wrong signatures, expiry and purpose; never log keys.

[source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/lost_museum/README.md).

**A/D variant:** Default keys and mixed token purposes. **Reference:** explorers, CTF Cup config/auth/API review. Configuration contained a default jwt_key literal that environment could override. One JWT helper served different claim schemas. This calls for boundary review; it is not a reproduced authorization bypass.

**Patch:** Require key configuration; validate typ/purpose/audience and required fields at every receiver. A missing user_id is not a valid principal. **Test:** Share tokens cannot become authentication tokens or vice versa; invalid/empty subjects fail and legitimate sharing works. Scanner: CFG-SECRET for literals; purpose requires manual analysis.

[source/write-up 1](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/app/config.py); [source/write-up 2](https://github.com/C4T-BuT-S4D/ctfcup-2023-ad/blob/53d6b9b7369448ac6c5d7d8e9458f66b25271e8a/services/explorers/src/app/auth.py).

<a id="cfg-debug"></a>

## CFG-DEBUG. Debug enabled in configuration

**Search:** scanner rule CFG-DEBUG. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-DEBUG` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
DEBUG=true
~~~

**Fix:** Disable runtime debug and keep private diagnostics without secrets.

~~~text
DEBUG=false
~~~

**Verification:** Errors expose neither console nor stack trace.

<a id="cfg-cors"></a>

## CFG-CORS. Broad CORS policy

**Search:** scanner rule CFG-CORS. Use `--explain CFG-CORS` for the exact detector contract. Legacy wildcard header/config heuristic (untyped). JS bounded tokens also detect default imported/required cors with inline origin:true and credentials:true, literal quoted keys and last-write-wins fields. Observed shadows/reassignments suppress the new hint. Computed keys, variables, wrappers, actual response policy and other languages remain manual.

**Vulnerable example:**

~~~text
Access-Control-Allow-Origin: *
~~~

**Fix:** Allowlist actual origins and use Vary: Origin where needed; authentication and CSRF remain separate. A wildcard alone is not an auth bypass.

~~~text
Access-Control-Allow-Origin: https://ui.example.invalid
~~~

**Verification:** Authorized browsers work; unrelated origins cannot read private responses.

<a id="cfg-docker-priv"></a>

## CFG-DOCKER-PRIV. Privileged container

**Search:** scanner rule CFG-DOCKER-PRIV. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-DOCKER-PRIV` for details. Regex: privileged:true and cap_add with SYS_ADMIN/ALL, including quoted JSON keys. CFG-CAPABILITIES covers block capabilities; inspect effective Docker/Kubernetes config.

**Vulnerable example:**

~~~text
privileged: true
~~~

**Fix:** Identify minimum capabilities and change only authorized owned services, not organizer infrastructure.

~~~text
privileged: false
~~~

**Verification:** Service/checker works without unnecessary privileges.

<a id="cfg-docker-socket"></a>

## CFG-DOCKER-SOCKET. Docker socket exposed to a service

**Search:** scanner rule CFG-DOCKER-SOCKET. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-DOCKER-SOCKET` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
- /var/run/docker.sock:/var/run/docker.sock
~~~

**Fix:** Remove unnecessary mounts after checking dependencies/rules; never alter unrelated containers automatically.

~~~text
- app-data:/srv/data
~~~

**Verification:** Required service and approved management operations work.

<a id="cfg-docker-root"></a>

## CFG-DOCKER-ROOT. Explicit Docker USER root

**Search:** scanner rule CFG-DOCKER-ROOT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-DOCKER-ROOT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
USER root
~~~

**Fix:** Prepare an unprivileged user and directory permissions; missing USER is not detected by this rule.

~~~text
USER app
~~~

**Verification:** Volumes, ports, writes and restart work.

<a id="cfg-world-write"></a>

## CFG-WORLD-WRITE. Broad write permissions

**Search:** scanner rule CFG-WORLD-WRITE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-WORLD-WRITE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
chmod -R 777 /srv/app
~~~

**Fix:** Set intended owner/group and minimum modes; do not recursively replace permissions blindly.

~~~text
chmod 750 /srv/app
~~~

**Verification:** Service can write data; others cannot change code.

<a id="cfg-nginx-list"></a>

## CFG-NGINX-LIST. nginx directory listing

**Search:** scanner rule CFG-NGINX-LIST. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-NGINX-LIST` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
autoindex on;
~~~

**Fix:** Disable listing unless it is required functionality.

~~~text
autoindex off;
~~~

**Verification:** Downloads work; private directory contents are not enumerated.

<a id="cfg-nginx-alias"></a>

## CFG-NGINX-ALIAS. Review nginx alias boundaries

**Search:** scanner rule CFG-NGINX-ALIAS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-NGINX-ALIAS` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
location /files { alias /srv/files/; }
~~~

**Fix:** Align location /files/ with alias /srv/files/; review normalization/auth. Correct aliases also trigger review.

~~~text
location /files/ { root /srv; } # verify mapping and auth
~~~

**Verification:** Boundary URLs stay inside the root; old public URLs work.

<a id="cfg-postgres-trust"></a>

## CFG-POSTGRES-TRUST. PostgreSQL trust

**Search:** scanner rule CFG-POSTGRES-TRUST. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-POSTGRES-TRUST` for details. Regex: POSTGRES_HOST_AUTH_METHOD=trust including JSON; pg_hba local/host/hostssl/hostnossl/hostgssenc/hostnogssenc with trust and CIDR or separate IPv4 netmask. Inspect HBA order and actual matching entries.

**Vulnerable example:**

~~~text
POSTGRES_HOST_AUTH_METHOD: trust
~~~

**Fix:** Use supported auth and coordinated application credentials; do not change organizer accounts/network.

~~~text
POSTGRES_HOST_AUTH_METHOD: scram-sha-256
~~~

**Verification:** Application connects; unknown credentials fail.

<a id="cfg-redis-protection"></a>

## CFG-REDIS-PROTECTION. Redis protected-mode disabled

**Search:** scanner rule CFG-REDIS-PROTECTION. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-REDIS-PROTECTION` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
protected-mode no
~~~

**Fix:** Review ACL, credentials, bind and clients against game rules without blocking required traffic.

~~~text
protected-mode yes
~~~

**Verification:** Application connects with minimum required permissions.

<a id="tpl-raw"></a>

## TPL-RAW. Unescaped template output

**Search:** scanner rule TPL-RAW. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain TPL-RAW` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
{{ message | safe }}
~~~

**Fix:** Use normal escaped text output or a context-tested sanitizer for permitted HTML.

~~~text
{{ message }}
~~~

**Verification:** User markup stays text and layout remains intact.

<a id="src-mixed-identifier"></a>

## SRC-MIXED-IDENTIFIER. Mixed Latin/Cyrillic/Greek identifier

**Search:** scanner rule SRC-MIXED-IDENTIFIER. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SRC-MIXED-IDENTIFIER` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
uuіd = input_value
~~~

**Fix:** Inspect code points/references and use distinguishable names and the validated value; never blindly rename text.

~~~text
validated_uuid = parse_uuid(input_value)
~~~

**Verification:** Validation and consumption use the same value; invalid input fails. Strings/comments may be harmless.

**A/D variant:** Unicode lookalikes and unchecked identifiers. **ENOWARS / replme, author and patch.** A similar-looking variable letter left the original UUID unchecked; a filesystem operation used it rather than the middleware-authorized object.

**Patch:** Use the authorized object's ID, unambiguous variable names and filename/root checks. **Test:** Another query ID cannot change the authorized object; malformed UUIDs fail. **Search:** SRC-MIXED-IDENTIFIER; SRC-BIDI-CONTROL is an additional general check, not a claim about this service.

[source/write-up 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [source/write-up 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [source/write-up 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [source/write-up 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [source/write-up 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [source/write-up 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

<a id="src-bidi-control"></a>

## SRC-BIDI-CONTROL. Bidirectional text control in source

**Search:** scanner rule SRC-BIDI-CONTROL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain SRC-BIDI-CONTROL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
# direction ‮ marker
~~~

**Fix:** Inspect actual Unicode/token order and remove unnecessary controls; review legitimate localization separately.

~~~text
# explicit plain-text comment
~~~

**Verification:** Rendered and actual flow agree; copying does not restore controls.

<a id="cfg-redis-acl"></a>

## CFG-REDIS-ACL. Redis ACL user without a password

**Search:** scanner rule CFG-REDIS-ACL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-REDIS-ACL` for details. Regex selects user lines, then a bounded parser reads the physical line up to 8192 characters: lowercase user, one ASCII space before a nonempty username and ordinary modifier spaces. on/off/reset and nopass/resetpass/>password/#64lowerhex are processed in order; both final flags must be explicitly true. Names, passwords and key/channel patterns are not flags. Quotes, escapes, internal tabs, selectors and unknown operations need review; long lines are partial. This is not effective ACL analysis: inspect includes/runtime, grant validity, password strength and existing connections.

**Vulnerable example:**

~~~text
user default on nopass ~* &* +@all
~~~

**Fix:** First provision credentials and minimum commands/keys/channels for an app user; migrate clients and test AUTH/reconnect. Only then remove nopass or disable default. An empty > value is not a secure password.

~~~text
user default off
~~~

off prevents new authentication but does not terminate already authenticated connections. Plan their treatment while preserving administration and rollback. default on nopass makes new connections already authenticated; a named user's nopass accepts any AUTH password. [Redis ACL on/off behavior](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/).

**Verification:** New app-user connections work before disabling default; new anonymous connections then fail. Check existing connections, namespaces, Pub/Sub and transactions.

ACL directives apply in order. off after on, resetpass after nopass, or reset changes the result; nopass after adding a password re-enables unchecked authentication. >password and a valid # followed by 64 lowercase hex characters clear nopass. Even > with an empty password clears it: disappearance of the signal does not fix authentication. ~nopass is a key pattern, not a password directive. [Redis 7.2.7 ACL implementation](https://github.com/redis/redis/blob/7.2.7/src/acl.c).

The scanner parses a bounded common subset of redis.conf/aclfile lines. It tracks complete tokens/order within one line, not cross-line state or successful loading. Quotes, escaping, internal tabs and selectors need review because main-config/aclfile tokenization differs. Do not append inline comments to ACL lines: # may begin a password-hash token. Also review includes, requirepass, repeated definitions and runtime ACL SETUSER/ACL LOAD. [Redis 7.2.7 config parser](https://github.com/redis/redis/blob/7.2.7/src/config.c).

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -o -e '(^[[:blank:]]*(user|aclfile|include|requirepass)[[:blank:]])|ACL[[:blank:]]+(SETUSER|LOAD|SAVE|GETUSER|LIST)' .
~~~

The command prints directive names/locations only, not credential arguments. Privately trace loaded files and every update to the selected user. An authorized administrator should inspect effective flags/commands/keys/channels with ACL GETUSER app and test a new connection with correct/incorrect credentials. GETUSER also returns hashes: never copy them/password fields into reports, logs or shell history. requirepass in one file does not prove it applies to the running process. [Redis ACL GETUSER](https://redis.io/docs/latest/commands/acl-getuser/).

<a id="cfg-mongo-noauth"></a>

## CFG-MONGO-NOAUTH. MongoDB authorization disabled

**Search:** scanner rule CFG-MONGO-NOAUTH. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-MONGO-NOAUTH` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
security:
  authorization: disabled
~~~

**Fix:** Prepare application credentials and least-privilege roles before enabling auth on an owned service.

~~~text
security:
  authorization: enabled
~~~

**Verification:** Restart/reconnect and CRUD work; anonymous access fails. Do not alter organizer accounts.

**Reference:** [primary source](https://www.mongodb.com/docs/manual/core/authorization/).

<a id="cfg-capabilities"></a>

## CFG-CAPABILITIES. Broad container capabilities

**Search:** scanner rule CFG-CAPABILITIES. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-CAPABILITIES` for details. Regex: cap_add or capabilities.add with SYS_ADMIN/ALL in flow/block lists. capabilities.drop:[ALL] alone is not a grant. Bounded text windows are not YAML parsing; review nesting, merges/anchors and actual securityContext.

**Vulnerable example:**

~~~text
cap_add: [SYS_ADMIN]
~~~

**Fix:** Remove unnecessary capabilities only on owned services; retain proven requirements and verify user/port/volume permissions.

~~~text
cap_drop: [ALL]
~~~

**Verification:** Startup/checker and required syscalls work; do not apply this to organizer launchers.

**Reference:** [primary source](https://docs.docker.com/engine/security/).

<a id="cfg-build-secret"></a>

## CFG-BUILD-SECRET. Secret in Dockerfile ARG/ENV

**Search:** scanner rule CFG-BUILD-SECRET. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-BUILD-SECRET` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
ARG API_TOKEN=example
~~~

**Fix:** Use build secret mounts instead of ARG/ENV/layers. Rotate published secrets deliberately; later deletion does not erase an earlier layer.

~~~text
RUN --mount=type=secret,id=api_token build-with-secret
~~~

**Verification:** Build history/logs disclose no secret; runtime secrets are separate. The sample build command is a placeholder.

**Reference:** [primary source](https://docs.docker.com/build/building/secrets/).

<a id="cfg-nginx-auth-off"></a>

## CFG-NGINX-AUTH-OFF. Nested nginx location disables auth_request

**Search:** scanner rule CFG-NGINX-AUTH-OFF. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-NGINX-AUTH-OFF` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~text
location /export/ { auth_request off; }
~~~

**Fix:** Review location selection/inheritance and remove unintended auth bypass while preserving intended public endpoints.

~~~text
location /export/ { auth_request /verify; }
~~~

**Verification:** Protected resources require authentication through every matching location; health/login works.

**Reference:** [primary source](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

<a id="cfg-file-mode"></a>

## CFG-FILE-MODE. Configuration, data-directory and ACL permissions

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'chmod|chown|umask|setfacl|mode:|permissions' .
~~~

In an authorized environment inspect ls -ld for the file and every parent; on Linux also inspect getfacl. Compare process uid/gid.

**Vulnerable example:**

Another local user can read secrets, or a writable parent permits replacing a protected file.

**Fix:** Minimal file/parent permissions, separate writable data and private temporary storage; never chmod -R 777 or break volume ownership.

**Verification:** The app reads required config and writes data after restart; unrelated local users gain no access.

<a id="cfg-bind-mount"></a>

## CFG-BIND-MOUNT. Writable mounts expose hosts or neighboring data

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'volumes:|bind|source:|target:|read_only|hostPath' .
~~~

Match Compose/Kubernetes mounts to the authorized runtime inventory: host source, container destination, read/write mode and propagation.

**Vulnerable example:**

An unnecessary writable mount lets the application modify host code, configuration or directories.

**Fix:** Only necessary paths, read-only where possible and separate data volumes; preserve required runtime permissions.

**Verification:** Startup, writes, checker and restart work without changing code or unrelated directories.

**Reference:** [primary source](https://docs.docker.com/engine/storage/bind-mounts/).

<a id="cfg-k8s-rbac"></a>

## CFG-K8S-RBAC. Workload bound to cluster-admin

**Search:** scanner rule CFG-K8S-RBAC. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-K8S-RBAC` for details. Regex: name:cluster-admin. Does not connect roleRef to subjects or find equivalent wildcard roles; inspect remaining RBAC manually.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'automountServiceAccountToken|serviceAccountName|ClusterRole|verbs:|resources:' .
~~~

Trace pod → serviceAccount → RoleBinding/ClusterRoleBinding; review secrets, exec and bind/escalate permissions.

**Vulnerable example:**

A business pod receives an administrative token despite not needing Kubernetes API access.

**Fix:** Use a least-privilege Role and namespaced RoleBinding; review subjects, verbs, resources, names and impersonate/bind/escalate.

**Verification:** Runtime identity can perform only required operations, not read foreign Secrets or grant rights.

**Reference:** [primary source](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

**Scanner example before:**

~~~config
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
~~~

**Fix template:**

~~~config
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: notes-read-config
~~~

Primary documentation: [reference 1](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

<a id="cfg-nginx-location"></a>

## CFG-NGINX-LOCATION. URI normalization and location selection

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'location|alias|root|try_files|rewrite|proxy_pass' .
~~~

For the authorized configuration trace exact/prefix/regex locations and internal redirects; compare the URI the backend receives.

**Vulnerable example:**

Authorization checks one path while proxy/filesystem normalization or fallback selects another.

**Fix:** Unambiguous routes/root boundaries and authorization on the actual resource; consistent decoding policies across layers.

**Verification:** Slash/encoding variants, normal paths, regex locations and fallbacks never change permissions.

**Reference:** [primary source](https://nginx.org/en/docs/http/ngx_http_core_module.html).

<a id="cfg-static-secrets"></a>

## CFG-STATIC-SECRETS. Static roots expose .git, backups, databases and logs

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'static|document_root|root |alias |send_from_directory|FileServer' .
~~~

Inspect the actual public root, symlinks and fallback routes; locate files with rg --files --hidden -g !.git.

**Vulnerable example:**

The project root serves config, backup.sql, SQLite/WAL, archives or credentials.

**Fix:** A separate public build directory, private storage outside it and authenticated downloads; blocking one extension is insufficient.

**Verification:** Assets work; hidden files, backups and outward links are never served.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="cfg-cookie-flags"></a>

## CFG-COOKIE-FLAGS. Explicitly weakened session cookie flags

**Search:** scanner rule CFG-COOKIE-FLAGS. Use `--explain CFG-COOKIE-FLAGS` for the exact detector contract. Regex with lexical exclusions: bare Django SESSION_COOKIE_HTTPONLY/SESSION_COOKIE_SECURE/CSRF_COOKIE_SECURE=false/0. Python AST: known Flask config subscript/update/from_mapping with disabled session HttpOnly/Secure. JS bounded tokens: default imported express-session with inline cookie.httpOnly:false. Dynamic configs/defaults remain manual. JS secure:false alone is not a new signal; HTTPS/checker compatibility must be reviewed.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Set-Cookie|HttpOnly|SameSite|Secure|cookie.domain|cookie.path' .
~~~

Compare effective Set-Cookie with actual HTTP/TLS/proxy topology; Domain/Path are not authorization.

**Vulnerable example:**

Private cookies reach unnecessary hosts/paths, are unnecessarily accessible to JavaScript or disappear because Secure is misconfigured.

**Fix:** Keep session cookies HttpOnly and use Secure where the approved service transport supports HTTPS; changing Secure on an HTTP-only checker requires a coordinated transport decision.

**Verification:** Scripts cannot read session cookies; sessions work over the intended transport and secure cookies are not sent over plaintext.


**Scanner example before:**

~~~config
SESSION_COOKIE_HTTPONLY = False
~~~

**Fix template:**

~~~config
SESSION_COOKIE_HTTPONLY = True
~~~


<a id="cfg-trusted-headers"></a>

## CFG-TRUSTED-HEADERS. Backends trust client-supplied user, role or IP

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'X-User|X-Role|X-Forwarded|Forwarded|Remote-User|X-Original' .
~~~

Trace which component sets/clears headers and whether the backend is reachable around the trusted proxy.

**Vulnerable example:**

The application accepts client X-User as verified identity.

**Fix:** Application credentials or authenticated trusted peers, with forwarded identity sanitized according to topology; one secret header is not universal authentication.

**Verification:** Direct requests and forged headers confer no rights; legitimate proxy traffic works.

<a id="cfg-cache-auth"></a>

## CFG-CACHE-AUTH. Shared HTTP caches retain personalized responses

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'proxy_cache|Cache-Control|Vary|Authorization|Set-Cookie|cache_key' .
~~~

Review cache keys, bypass conditions and cookie/authenticated responses; compare two users at the same URL.

**Vulnerable example:**

A private response cached solely by URI is returned to another session.

**Fix:** Never share personalized responses under a common key; contractual private/no-store or full context isolation with correct invalidation.

**Verification:** User A then B at the same URL, logout/role changes and normal public caching.

<a id="cfg-debug-endpoint"></a>

## CFG-DEBUG-ENDPOINT. Diagnostics become public APIs

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'actuator|swagger|debug|pprof|metrics|heapdump|console|env' .
~~~

List actually registered endpoints and access policy for each; /health alone is not suspicious.

**Vulnerable example:**

Environment, heap dumps or configuration consoles expose secrets or application control.

**Fix:** Disable unnecessary diagnostics in the owned service or enforce application authorization; preserve required health/organizer monitoring.

**Verification:** Health/checker work; anonymous environment/dump/control access fails.

<a id="cfg-error-secret"></a>

## CFG-ERROR-SECRET. Logs expose credentials or private request bodies

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'logger|logging|console.log|print|Authorization|password|token' .
~~~

Find whole-request/config/exception logging, debug traces and every log destination.

**Vulnerable example:**

Passwords, signatures or private bodies are unnecessarily logged and exposed through endpoints/volumes.

**Fix:** Secret-free structured fields, redaction before serialization and minimal access/retention; preserve useful error codes.

**Verification:** Failed requests remain diagnosable without secret values or API stack traces.

<a id="cfg-resource-limits"></a>

## CFG-RESOURCE-LIMITS. Body, decompression and multipart limits

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'bodyLimit|maxRequest|client_max_body_size|multipart|decompress|timeout' .
~~~

Check limits before reads, after decompression, per part and per complete message; proxy and app limits may differ.

**Vulnerable example:**

Small compressed input expands into a huge body, or parts/headers are unbounded.

**Fix:** Contractual budgets for actual bytes, parts, time and output; cleanup on failure.

**Verification:** Limit±1, missing Content-Length, compressed bodies, many parts and the legitimate maximum.

<a id="cfg-upload-exec"></a>

## CFG-UPLOAD-EXEC. Uploads become executable or active content

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'upload|media|public|cgi|fastcgi|Content-Type|Content-Disposition' .
~~~

Compare storage paths, server handlers and browser MIME behavior; client filename/Content-Type does not prove type.

**Vulnerable example:**

An uploaded document executes server-side or opens as active HTML within the app origin.

**Fix:** Private nonexecutable storage, server-generated filenames, type validation and serving policy; safe download headers.

**Verification:** Upload/download/previews work without turning files into server code or cross-user origin scripts.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

<a id="cfg-http-parser"></a>

## CFG-HTTP-PARSER. Proxy and backend disagree on framing

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Content-Length|Transfer-Encoding|http_parser|proxy_http_version|keepalive' .
~~~

Check HTTP parser versions and contradictory length/encoding handling; test only an isolated environment.

**Vulnerable example:**

Layers disagree about request boundaries and a following request enters another context.

**Fix:** Compatible patched parsers, one strict framing policy and rejection of ambiguity; do not attempt payload-regex repairs.

**Verification:** Normal keepalive/chunked behavior, conflicting framing and safe connection closure without mixed responses.

<a id="cfg-cors-credentials"></a>

## CFG-CORS-CREDENTIALS. CORS reflects Origin with credentials

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Access-Control-Allow-Origin|allow_credentials|origin:|credentials:|CORS' .
~~~

Compare allowed and foreign Origin responses; browsers normally block wildcard+credentials, while arbitrary reflection is more dangerous.

**Vulnerable example:**

Every origin receives its own name reflected and permission to read private authenticated APIs.

**Fix:** Exact server-side origin allowlist, correct Vary and credential policy; CORS does not authorize nonbrowser requests.

**Verification:** The normal frontend works; foreign/null origins cannot read credentialed responses.

<a id="cfg-reset-token"></a>

## CFG-RESET-TOKEN. Recovery or share tokens lack purpose or one-time use

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'reset|recover|invite|share|token|expires|used_at' .
~~~

Trace issuance/verification and atomic consumption; compare login/share/reset audiences.

**Vulnerable example:**

A token for another operation or an already consumed token changes access again.

**Fix:** CSPRNG/signatures bound to purpose/resource/subject/expiry, with transactional one-time consumption where required; preserve legitimate sharing.

**Verification:** Replays/concurrent use, foreign objects/purposes, expiry and normal operation.

<a id="cfg-object-policy"></a>

## CFG-OBJECT-POLICY. Alternative endpoints expose an object directly

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'owner|tenant|download|export|delete|share|attachment|job' .
~~~

Trace every operation and nested path for one entity, including background jobs; unpredictable IDs are not permission.

**Vulnerable example:**

UI/read paths are protected, but export/download/delete look up IDs without owner checks.

**Fix:** One resource policy enforced for every operation, actor from verified session and explicit intended sharing.

**Verification:** Two users/tenants can access their own resources and never each other's through any endpoint.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

<a id="cfg-deployed-config"></a>

## CFG-DEPLOYED-CONFIG. Reviewing an example instead of effective configuration

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'env_file|environment:|include|args:|command:|config|settings' .
~~~

Compare entrypoint, includes, overrides and effective configuration. Expanded output may contain secrets; inspect it only privately.

**Vulnerable example:**

A sample is fixed while runtime environment/volumes supply an unsafe override.

**Fix:** Change the actual source of configuration, verify precedence and restart; keep secrets out of Git.

**Verification:** Correct effective values survive restart; the old copy never silently returns.

<a id="cfg-media-converter"></a>

## CFG-MEDIA-CONVERTER. Media documents load additional resources

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ffmpeg|magick|convert|thumbnail' .
~~~

Determine which additional files/URLs the decoder reads after receiving a document.

**Vulnerable example:**

**Reference:** bookster, RuCTF author write-up. An older FFmpeg could follow resources embedded in uploaded media while producing previews.

**Search:** FFmpeg, ImageMagick, PDF/SVG/XML conversion, thumbnails/previews and embedded playlists/URLs. Separate the input file from additional resources the parser fetches; HTTP-handler URL checks alone are insufficient.

**Fix:** Compatible patched builds, explicit allowed protocols/decoders, constrained input/output and process resources. Preserve promised formats/previews. Network firewall policy does not replace the fix.

**Verification:** Every allowed format, malformed files, embedded local-resource links and time/memory budgets.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/bookster/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/bookster/README.md).

<a id="cfg-format-transition"></a>

## CFG-FORMAT-TRANSITION. Injection through intermediate YAML

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'yaml|unmarshal|safe_load|template' .
~~~

Trace text → template → YAML → update object; type data at each boundary.

**Vulnerable example:**

**Reference:** lost_museum, RuCTF author write-up. A template generated YAML subsequently parsed into a MongoDB mutation map.

**Search:** String-formatted structured documents followed by unmarshal/parse and wholesale database updates. safe_load does not prevent unwanted fields; this differs from unsafe YAML constructors.

**Fix:** Typed structure → serializer, then explicit update-field projection; server-derived owner/role. Clients must not control MongoDB operation structure.

**Verification:** Newlines, colons, nested fields and normal text change only the intended field.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/lost_museum/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/lost_museum/README.md).

<a id="cfg-principal-context"></a>

## CFG-PRINCIPAL-CONTEXT. Clients modify authorization context

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'userspace|principal|currentUser|tenant' .
~~~

Trace every principal write; DSLs and request parameters must not mutate server authorization context.

**Vulnerable example:**

**Reference:** scp, RuCTF author write-up: a DSL modified userspace used for visibility control. **Search:** currentUser/userspace/principal/tenant assignments from expressions, parameters or intermediate state, and authorization-mode switches.

**Fix:** Derive the actor from a verified session and store it apart from mutable DSL state. Sensitive operations check the server-owned context.

**Verification:** Expressions cannot change principal; owned objects remain accessible and foreign objects hidden regardless of expression order.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/scp/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/scp/README.md).

<a id="cfg-auth-toctou"></a>

## CFG-AUTH-TOCTOU. Authorization races and identifier reuse

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'owner|tenant|middleware|await|UPDATE|DELETE' .
~~~

Find waits/state changes between checking and writing; require owner/version conditions in atomic mutations.

**Vulnerable example:**

**Reference:** stalker, RuCTF author write-up. ORM authorization snapshots were taken before waiting for the request body; deletion/recreation changed identifier meaning.

**Search:** Middleware objects/ID lists → await/I/O → unchecked mutation, cached ORM relationships and IDs unique only within part of a composite key.

**Fix:** Check ownership atomically in UPDATE/DELETE/SHARE itself, using transactions/row versions as needed and stable ID uniqueness. Preserve data during schema migration.

**Verification:** Deterministic check → delete/recreate → mutate interleaving never changes foreign records. Also test rollback and normal concurrency.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/stalker/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/stalker/README.md).

<a id="cfg-custom-crypto"></a>

## CFG-CUSTOM-CRYPTO. Algebraic leakage in custom cryptography

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'encrypt|decrypt|matrix|modulus|nonce' .
~~~

Write down input/output relationships and where secrets enter; review preserved algebraic relations with the protocol owner.

**Vulnerable example:**

**Reference:** solaris, RuCTF author write-up: a matrix construction preserved mathematical relations tied to a secret. **Search:** Custom RSA/matrix/arithmetic combinations, invariant input/output relations and insufficient randomness.

**Fix:** First identify the functional contract and mathematical leak. For ordinary encryption/authentication use standard library constructions with proper nonces and versioned formats. A cryptographic challenge may need an algorithm-specific repair. **Never generalize challenge-specific key-size reductions into security hardening.**

**Verification:** Normal client behavior and old data remain intact while the identified invariant disappears.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/solaris/README.md).

**Reference:** [primary source](https://github.com/HackerDom/ructf-finals-2023/blob/a7442769909e08c39716cb18d3d1c3a99324bbf8/writeups/solaris/README.md).

<a id="cfg-shared-backend-key"></a>

## CFG-SHARED-BACKEND-KEY. One credential spans all child environments

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'API_KEY|apikey|credential|environment|token' .
~~~

Trace shared-key distribution and backend resource/audience validation.

**Vulnerable example:**

**ENOWARS / replme, author write-up.** Compromising one child backend exposed a key trusted by the others.

**Fix:** Least privilege and credentials scoped to individual resources; do not rely solely on internal addresses.

**Verification:** Environment A's credential never authorizes actions in B.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex); [source/write-up 2](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/path-traversal.patch); [source/write-up 3](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/crc.patch); [source/write-up 4](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/util/encoding.go); [source/write-up 5](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/backend/controller/repl.go); [source/write-up 6](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/service/image/service/user.go).

**Reference:** [primary source](https://github.com/enowars/enowars8-service-replme/blob/3cdec50dd9a57f43f1c57f7b049319774a00e6c2/documentation/documentation/src/main.tex).

<a id="cfg-windows-names"></a>

## CFG-WINDOWS-NAMES. Filenames have different Windows meanings

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'filename|basename|glob|FindFirstFile|ToLower' .
~~~

Compare validated/database names with actual Windows lookup: case, wildcard, trailing dots/spaces and alternate streams.

**Vulnerable example:**

**ICC / MaScroll, author write-up.** Database/filesystem names disagreed on case and allowed characters.

**Fix:** Server-generated storage IDs, one policy for the actual operating system and separate ownership checks.

**Verification:** Case, wildcards/special characters and separators; old files stay accessible.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

**Reference:** [primary source](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/MaScroll/README.md).

<a id="cfg-proxy-redirect"></a>

## CFG-PROXY-REDIRECT. Reverse proxies follow redirects into trusted services

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'proxy_pass|redirect|Location|logout|internal' .
~~~

Trace redirects in internal HTTP clients and repeated destination checks; internal locations alone do not authenticate backend access.

**Vulnerable example:**

**ICC / NorthernFiles, author write-up.** An open redirect combined with proxy configuration exposed an internal endpoint through a chain.

**Fix:** Safe redirects and an explicit proxy contract; internal token issuers must independently authorize requests.

**Verification:** Internal/external redirects and normal logout.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

**Reference:** [primary source](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

<a id="cfg-protocol-key"></a>

## CFG-PROTOCOL-KEY. Degenerate values in cryptographic protocols

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'public_key|pubkey|group|identity|point' .
~~~

Validate decoding, group membership and rejection of degenerate elements according to the actual protocol.

**Vulnerable example:**

**ICC / NorthernFiles, author write-up.** Type-valid input reduced key agreement to a trivial value.

**Fix:** Protocol-specific group-element/degenerate-state validation; use a reviewed implementation where compatible.

**Verification:** Neutral/invalid elements, negative cases and client interoperability.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

**Reference:** [primary source](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/NorthernFiles/README.md).

<a id="cfg-aggregate-key"></a>

## CFG-AGGREGATE-KEY. Incorrect public-key aggregation

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'aggregate|coefficient|pubkey|subset' .
~~~

Compare coefficients and proof-of-possession with the chosen scheme; bound set-validation cost.

**Vulnerable example:**

**ICC / UberPendragon, author write-up.** Linear coefficients failed to provide expected rogue-key protection.

**Fix:** A reviewed aggregation scheme; where clients cannot change, justified protocol-specific rejection of degenerate sets with bounded cost.

**Verification:** Ordinary groups, duplicate keys, degenerate aggregates and load.

**A/D variant:** Source and version: [source/write-up 1](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/UberPendragon/README.md).

**Reference:** [primary source](https://github.com/CybersecNatLab/ICC2023-AD-CTF/blob/8ffa184ff2ce8f648258ed3c02ee2270e8e1c56c/sources/UberPendragon/README.md).

<a id="cfg-k8s-host"></a>

## CFG-K8S-HOST. Container shares host namespaces

**Search:** scanner rule CFG-K8S-HOST. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-K8S-HOST` for details. Regex: hostPID/hostIPC/hostNetwork:true and Compose pid/ipc/network_mode:host. No admission-policy or running-pod analysis.

**Vulnerable example:** Host-namespace access broadens the impact of workload compromise.

~~~config
hostPID: true
hostIPC: true
hostNetwork: true
~~~

**Fix:** Disable unnecessary host namespaces; implement required connectivity within approved competition topology and verify probes/ports.

~~~config
hostPID: false
hostIPC: false
hostNetwork: false
~~~

**Verification:** Service/checker works without host process/IPC visibility or unintended sockets.

Primary documentation: [reference 1](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

<a id="cfg-unconfined"></a>

## CFG-UNCONFINED. seccomp/AppArmor profile disabled

**Search:** scanner rule CFG-UNCONFINED. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-UNCONFINED` for details. Regex: seccomp/apparmor=unconfined or :unconfined and Kubernetes type:Unconfined. Unrelated YAML type keys may match.

**Vulnerable example:** Unconfined removes a layer of syscall/access restrictions.

~~~config
security_opt:
  - seccomp:unconfined
  - apparmor:unconfined
~~~

**Fix:** Restore the default or minimum compatible profile with narrow exceptions.

~~~config
security_opt:
  - no-new-privileges:true
# Keep the runtime default seccomp/AppArmor profiles.
~~~

**Verification:** Normal operations/checker work and the effective container applies the profile.

Primary documentation: [reference 1](https://docs.docker.com/engine/security/seccomp/).

<a id="cfg-priv-escalation"></a>

## CFG-PRIV-ESCALATION. Process privilege escalation allowed

**Search:** scanner rule CFG-PRIV-ESCALATION. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-PRIV-ESCALATION` for details. Regex: explicit allowPrivilegeEscalation:true. Review missing fields, defaults and interactions with privileged/CAP_SYS_ADMIN.

**Vulnerable example:** Permitted privilege escalation preserves setuid/file-capability paths.

~~~config
allowPrivilegeEscalation: true
~~~

**Fix:** Disable allowPrivilegeEscalation and remove privileged/CAP_SYS_ADMIN and unnecessary capabilities.

~~~config
allowPrivilegeEscalation: false
~~~

**Verification:** Required operations work and effective securityContext matches the manifest.

Primary documentation: [reference 1](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

<a id="cfg-actuator"></a>

## CFG-ACTUATOR. Spring Actuator exposes every endpoint

**Search:** scanner rule CFG-ACTUATOR. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-ACTUATOR` for details. Regex: flat property or MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE with *. Inspect nested YAML and active profiles using endpoints/exposure/include.

**Vulnerable example:** Broad management-endpoint exposure can disclose runtime/configuration or grant control.

~~~config
management.endpoints.web.exposure.include=*
~~~

**Fix:** Expose only necessary endpoints and restrict management access; inspect health details/custom SecurityFilterChain separately.

~~~config
management.endpoints.web.exposure.include=health
~~~

**Verification:** Health/checker works; env, heapdump, loggers, shutdown and unnecessary endpoints require approved admin access.

Primary documentation: [reference 1](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html).

<a id="cfg-h2-console"></a>

## CFG-H2-CONSOLE. H2 web console enabled

**Search:** scanner rule CFG-H2-CONSOLE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-H2-CONSOLE` for details. Regex: spring.h2.console.enabled/SPRING_H2_CONSOLE_ENABLED=true. Inspect nested YAML, aliases and active profiles.

**Vulnerable example:** A database console is a separate administrative surface with its own authentication and JDBC input.

~~~config
spring.h2.console.enabled=true
~~~

**Fix:** Disable in the runtime profile or provide protected local admin access; never remove application-wide auth/CSRF for it.

~~~config
spring.h2.console.enabled=false
~~~

**Verification:** Database operations work; console is not exposed to the game network.

Primary documentation: [reference 1](https://docs.spring.io/spring-boot/reference/data/sql.html#data.sql.h2-web-console).

<a id="cfg-tls-upstream"></a>

## CFG-TLS-UPSTREAM. Proxy does not verify upstream TLS

**Search:** scanner rule CFG-TLS-UPSTREAM. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-TLS-UPSTREAM` for details. Regex: proxy_ssl_verify/grpc_ssl_verify off. Missing directives, inheritance and effective values require complete nginx config review.

**Vulnerable example:** Upstream HTTPS without certificate verification does not identify the intended backend.

~~~config
proxy_ssl_verify off;
~~~

**Fix:** Enable verification, trusted CA and correct name/SNI; validate chain/intermediate depth for the actual upstream.

~~~config
proxy_ssl_verify on;
proxy_ssl_trusted_certificate /etc/nginx/trusted-ca.pem;
proxy_ssl_server_name on;
proxy_ssl_name notes.internal;
~~~

**Verification:** Correct backend works; wrong certificate/host fails without HTTP fallback.

Primary documentation: [reference 1](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify).

<a id="cfg-ssh-empty-password"></a>

## CFG-SSH-EMPTY-PASSWORD. SSHD permits empty passwords

**Search:** scanner rule CFG-SSH-EMPTY-PASSWORD. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-SSH-EMPTY-PASSWORD` for details. Regex: PermitEmptyPasswords yes. Recognizes sshd_config; include files with arbitrary names require explicit review.

**Vulnerable example:** When password authentication is available, an empty-password account can permit host access.

~~~config
PermitEmptyPasswords yes
~~~

**Fix:** Disallow empty passwords; review Match/PAM/accounts while retaining a working administration channel before applying changes.

~~~config
PermitEmptyPasswords no
~~~

**Verification:** Approved login works; empty passwords fail in every applicable Match context.

Primary documentation: [reference 1](https://man.openbsd.org/sshd_config#PermitEmptyPasswords).

<a id="cfg-sudo-all"></a>

## CFG-SUDO-ALL. Unrestricted passwordless sudo

**Search:** scanner rule CFG-SUDO-ALL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain CFG-SUDO-ALL` for details. Regex: NOPASSWD:ALL. Review aliases, includes, wildcard argv and dangerous allowed binaries; recognizes sudoers.

**Vulnerable example:** NOPASSWD:ALL turns runtime-user code execution into access to every permitted Runas target.

~~~config
app ALL=(ALL:ALL) NOPASSWD: ALL
~~~

**Fix:** Remove runtime sudo; move rare privileged operations into a minimal helper without arbitrary argv, shell or writable dependencies.

~~~config
# Runtime user has no sudo grant.
# Provision required resources before service startup.
~~~

**Verification:** Service works without sudo; effective rights contain neither ALL nor shell-escaping commands.

Primary documentation: [reference 1](https://www.sudo.ws/docs/man/sudoers.man/).

<a id="cfg-jwt-key-selection"></a>

## CFG-JWT-KEY-SELECTION. Untrusted kid/jku selects verification keys

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'kid|jku|x5u|jwks|JWK|keyfunc|getKey|IssuerSigningKeyResolver' .
~~~

Trace issuer, key-set URLs, local paths and kid lookup. Compare trusted registries against unverified token fields; scope cache keys by issuer and kid.

**Vulnerable example:** A token supplies a JWKS URL/key file or another issuer's kid, and the validator trusts the result.

**Fix:** Pin allowed issuers and their JWKS/keys server-side; kid is only an exact index within that issuer. Restrict algorithms/key types, caching and rotation; do not trust token-supplied jku/x5u.

**Verification:** Legitimate rotation works; unknown/cross-issuer kid and client URLs cannot change the trust domain. Key-fetch failure never authorizes.

Reference: [primary documentation](https://www.rfc-editor.org/rfc/rfc8725.html). The explanation and adaptation recipe were written for this catalog.

<a id="cfg-signed-request"></a>

## CFG-SIGNED-REQUEST. Signatures are not bound to operations or preventable replays

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'signature|signed_url|signedUrl|nonce|expires|timestamp|hmac|Content-Digest' .
~~~

List exact signed bytes: method, path, query, body, recipient, purpose and lifetime. Compare signer/verifier normalization and atomic one-use nonce handling.

**Vulnerable example:** A read signature authorizes mutation, bodies can be replaced, or a one-use webhook/payment is replayed.

**Fix:** Sign a canonical contract binding action/purpose, recipient and required request components; bound expiry/clock skew. Atomically record one-use nonces/idempotency keys with the mutation.

**Verification:** Method/path/body/recipient changes invalidate signatures. Concurrent replays produce one effect; permitted retries return the agreed result.

Reference: [primary documentation](https://www.rfc-editor.org/rfc/rfc9421.html). The explanation and adaptation recipe were written for this catalog.

<a id="cfg-rate-limit-identity"></a>

## CFG-RATE-LIMIT-IDENTITY. Senders choose their rate-limit identity

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'rate.?limit|throttle|X-Forwarded-For|X-Real-IP|req\.ip|remote_addr|client_ip' .
~~~

Compare limit keys with the actual trusted-proxy boundary. Test case/Unicode names, route aliases, multiple workers, expiry and backend failure.

**Vulnerable example:** Limits use arbitrary headers, one account spelling or worker-local memory; changing representation resets the budget.

**Fix:** Normalize identity consistently with authentication; trust proxy headers only from approved hops. Use atomic shared budgets for intended actors/operations while preserving legitimate shared-IP access.

**Verification:** Header/identity-form changes do not create a fresh budget; parallel workers honor limits and permitted checker traffic works.

Reference: [primary documentation](https://expressjs.com/en/guide/behind-proxies.html). The explanation and adaptation recipe were written for this catalog.

<a id="cfg-token-revocation"></a>

## CFG-TOKEN-REVOCATION. Password or role changes fail to revoke access

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'logout|revoke|revocation|token_version|session_version|password_changed|security_stamp|refresh_token' .
~~~

Trace login, refresh, logout, password changes, account deletion and role updates. Determine when APIs reload privileges, validate session/token versions and invalidate caches.

**Vulnerable example:** A deleted administrator retains an old JWT/session, or a revoked refresh token restores access.

**Fix:** Contractual expiry/revocation via session versions, denylists or short-lived access tokens with verified refresh. Rotate refresh tokens atomically and invalidate related caches.

**Verification:** After the chosen revocation event, old access/refresh tokens fail within the promised interval on every worker; legitimate re-login works.

Reference: [primary documentation](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). The explanation and adaptation recipe were written for this catalog.

<a id="cfg-fail-open"></a>

## CFG-FAIL-OPEN. Verification errors become permission

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'catch|except|finally|recover|fallback|default.*allow|on_error|unwrap_or|Result' .
~~~

Trace every auth/signature/ACL exception, timeout, nil/None/null and cleanup branch. Inspect catch/finally, next middleware and defaults.

**Vulnerable example:** Database/validator failure returns allow/default principal, a handler continues after 401, or finally overrides denial.

**Fix:** Deny by default before side effects. Distinguish authorization denial from temporary unavailability and terminate the processing chain; log errors without secrets.

**Verification:** Synthetic backend errors/timeouts, wrong types and nil results neither expose data nor mutate state; normal checks pass.

Reference: [primary documentation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html). The explanation and adaptation recipe were written for this catalog.

<a id="cfg-ldap-filter"></a>

## CFG-LDAP-FILTER. LDAP filters or DNs built as strings

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'ldap_search|ldap\.search|search_s|SearchFilter|DirContext|LdapName|Filter\.create|escape_filter' .
~~~

Trace search filters separately from DNs: their grammars differ. Check bind/search, wildcard handling, empty passwords and multiple-match selection.

**Vulnerable example:** Usernames become LDAP syntax; broadened filters select another record or several records with the first treated as the user.

**Fix:** Builders/parameter APIs or escaping specifically for filter values; construct DNs with a DN builder. Require exactly the intended match and a valid bind; search is not authentication.

**Verification:** Special characters remain values; zero/multiple matches and empty credentials cannot authenticate; normal users work.

Reference: [primary documentation](https://www.rfc-editor.org/rfc/rfc4515.html). The explanation and adaptation recipe were written for this catalog.

<a id="cfg-ci-trust"></a>

## CFG-CI-TRUST. Untrusted data and code cross CI trust boundaries

**Search:** manual review; no separate scanner rule. CFG-CI-TRUST is a catalog ID, not an automatic signal. Locate workflows and composite actions:

~~~bash
rg -n --hidden -g '*.yml' -g '*.yaml' -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'pull_request_target|workflow_run|permissions:|secrets\.|allow-unsafe-pr-checkout|checkout@|download-artifact@|head\.sha|git fetch|gh pr checkout|run:|script:|uses: \./' .
rg -n --hidden -g '*.yml' -g '*.yaml' -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '\$\{\{[^}]*github\.(event|head_ref)' .
~~~

Read complete jobs and called actions/reusable workflows. Trace event/ref/artifact control → conversion into shell/JavaScript, dependencies or executables → effective permissions, secrets, environment and runner. An event name alone proves no flaw. Multiline expressions, indirect outputs and composite-action inputs need review even without search matches.

**Vulnerable example:** The first boundary is interpolating event data directly into run/script source. Quoting an expression does not protect it: interpolation occurs before shell parsing.

~~~yaml
- name: Show title
  shell: bash
  run: printf '%s\n' "${{ github.event.pull_request.title }}"
~~~

A real workflow_run.head_branch case is documented in [GHSL-2025-099](https://securitylab.github.com/advisories/GHSL-2025-099_cross-platform-actions_action/). It affected a workflow in the action repository, not necessarily every project using the action.

The second boundary is executing PR code in a privileged job:

~~~yaml
on: pull_request_target
permissions:
  contents: write
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          allow-unsafe-pr-checkout: true
      - run: make test
        env:
          SERVICE_TOKEN: ${{ secrets.SERVICE_TOKEN }}
~~~

PRs can change tests, Makefiles, install hooks and local actions. An analogous workflow_run error downloads a prior PR artifact and executes its script. Correct run IDs and successful status establish provenance, not content trust. [GitHub pull_request_target/workflow_run trust](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target). A real PR → privileged workflow → PR-code execution chain appears in [Gradio GHSL-2024-150 through GHSL-2024-157](https://securitylab.github.com/advisories/GHSL-2024-150_GHSL-2024-157_Gradio/).

checkout v7 blocks unsafe fork-PR checkout by default for pull_request_target and workflow_run whose workflow_run.event matches pull_request*; the example explicitly disables protection. It does not protect every workflow_run. Protection was backported to supported major versions, but pinned old SHAs do not update themselves. Check the exact commit/backport; git fetch, third-party actions and artifacts bypass this checkout-specific boundary. [checkout change](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/). Also inspect effective repository event policy; workflow YAML alone cannot establish whether it applies. [GitHub event policy](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target#default-policy-for-pull_request_target).

**Fix:** Keep event data separate from executable source:

~~~yaml
- name: Show title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  shell: bash
  run: printf '%s\n' "$PR_TITLE"
~~~

The printf format is fixed and the value is one argument. Later eval, bash -c or JavaScript construction breaks the boundary again. Passing data through with is safe only if the receiving action handles it safely. [GitHub script-injection guidance](https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks).

Run ordinary PR checks in an unprivileged, secret-free workflow:

~~~yaml
on: pull_request
permissions:
  contents: read
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - run: make test
~~~

persist-credentials:false alone does not fix privileged PR-code execution. Separate trusted jobs for comments, labels or report publication: accept bounded schema-validated JSON/text, verify repo/run/head SHA/PR destination, and never execute/import artifacts. Download data outside the trusted workspace. Private-registry/API tests need a separate design; arbitrary PR code must not receive their secrets. pull_request_target limited to labels/comments can be justified. [GitHub Security Lab stage separation](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/).

**Verification:** Statically trace data and minimal effective permissions including repository settings. In an authorized test CI exercise fork PRs, new SHAs after approval, quoted/newline-containing titles as data, foreign run IDs, malformed schemas and oversized artifacts. Preserve normal checks/report publication; PR code receives neither secrets nor a persistent self-hosted runner with internal access. These workflows were not executed during the catalog review; the offline scanner does not determine effective permissions or Actions relationships.

<a id="cfg-docker-tcp"></a>

## CFG-DOCKER-TCP. Docker daemon listens on every TCP interface

**Search:** scanner rule CFG-DOCKER-TCP. Use `--explain CFG-DOCKER-TCP` for the exact detector contract. Regex with lexical exclusions: dockerd followed on the same line by -H/--host tcp://0.0.0.0 or [::]. Does not evaluate TLS flags, JSON daemon configuration, named interfaces or shell expansions; a TLS-protected listener still requires review.

**Vulnerable example:**

~~~shell
dockerd -H tcp://0.0.0.0:2375
~~~

**Fix:** Prefer local Docker access. Required remote management needs authenticated encrypted transport and a deliberately restricted management interface; never publish it as a team UI.

~~~shell
dockerd -H unix:///var/run/docker.sock
~~~

**Verification:** Unapproved LAN clients cannot control Docker; approved administration remains possible without exposing credentials.

[Primary reference 1](https://docs.docker.com/reference/cli/dockerd/#daemon-socket-option)

<a id="cfg-floating-image"></a>

## CFG-FLOATING-IMAGE. Explicit latest image tag

**Search:** scanner rule CFG-FLOATING-IMAGE. Use `--explain CFG-FLOATING-IMAGE` for the exact detector contract. Regex with lexical exclusions: Docker FROM or a bare YAML image key using an unquoted image:latest with no digest. Quoted YAML, untagged images, other mutable tags, ARG expansion and resolved architecture need deployment-model audit.

**Vulnerable example:**

~~~docker
FROM example.invalid/app:latest
~~~

**Fix:** Record the approved source version and architecture-specific image digest; populate the offline image inventory and verify imported images.

~~~docker
FROM example.invalid/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
~~~

**Verification:** Repeated offline starts use the approved bytes and architecture; no implicit pull or latest fallback occurs.

[Primary reference 1](https://docs.docker.com/reference/dockerfile/#from)

<a id="tpl-autoescape-off"></a>

## TPL-AUTOESCAPE-OFF. Template block disables autoescaping

**Search:** scanner rule TPL-AUTOESCAPE-OFF. Use `--explain TPL-AUTOESCAPE-OFF` for the exact detector contract. Regex excluding HTML/Jinja comments: Jinja/Twig autoescape false and Django autoescape off blocks. Does not evaluate template engine defaults, enclosing blocks or whether values are trusted.

**Vulnerable example:**

~~~template
{% autoescape false %}{{ message }}{% endautoescape %}
~~~

**Fix:** Retain autoescaping for untrusted text; sanitize supported HTML explicitly and review the output context.

~~~template
{{ message }}
~~~

**Verification:** User tags/attributes remain data and allowed formatting still works.

[Primary reference 1](https://jinja.palletsprojects.com/en/stable/templates/#autoescape-overrides)
