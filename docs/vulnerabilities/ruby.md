# Ruby / Rails: find, fix and verify

English | [Русский](ruby-RU.md)

[Catalog](README.md) · [Scanner](../offline-scanner.md) · [Patch verification](../patch-validation.md)

18 sections. Each follows **Search → Vulnerable example → Fix → Verification**.
Run `rg` from a local service checkout; searches only read files. Derive the actor/owner from a verified session, not request data. Adapt examples to the actual API and contract.

## Contents

- [RUBY-OBJECT — Ruby Marshal or unsafe YAML](#ruby-object)
- [RUBY-SHELL — Ruby shell string](#ruby-shell)
- [RUBY-EVAL — Ruby eval/ERB from data](#ruby-eval)
- [RUBY-PERMIT-ALL — Rails permits all parameters](#ruby-permit-all)
- [RUBY-CONSTANTIZE — String selects a Ruby class](#ruby-constantize)
- [RUBY-HTML-SAFE — Ruby html_safe/raw](#ruby-html-safe)
- [RUBY-SQL — Ruby SQL interpolation](#ruby-sql)
- [RUBY-IDOR — ActiveRecord lookup outside the owner's scope](#ruby-idor)
- [RUBY-PATH — Client filenames reach send_file and File.join](#ruby-path)
- [RUBY-REDIRECT — redirect_to accepts an external return_to](#ruby-redirect)
- [RUBY-CSRF — Rails controller disables CSRF](#ruby-csrf)
- [RUBY-REGEX-ANCHOR — ^ and $ match a line inside a multiline value](#ruby-regex-anchor)
- [RUBY-YAML-VERSION — YAML.load behavior depends on Psych version](#ruby-yaml-version)
- [RUBY-DESERIALIZE-COOKIE — Signed cookies are not necessarily confidential](#ruby-deserialize-cookie)
- [RUBY-SSRF — Client input reaches Net::HTTP or open-uri](#ruby-ssrf)
- [RUBY-CALLBACKS — Callbacks cause effects before authorization](#ruby-callbacks)
- [RUBY-TLS — Ruby HTTPS peer verification disabled](#ruby-tls)
- [RUBY-REDIRECT-INPUT — Rails redirect takes request params directly](#ruby-redirect-input)

<a id="ruby-object"></a>

## RUBY-OBJECT. Ruby Marshal or unsafe YAML

**Search:** scanner rule RUBY-OBJECT. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-OBJECT` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~ruby
record = Marshal.load(payload)
~~~

**Fix:** Use JSON or bounded YAML.safe_load with class/alias policy and schema; migrate trusted legacy data separately.

~~~ruby
record = JSON.parse(payload) # validate DTO schema and size
~~~

**Verification:** Arbitrary objects are not built; old valid data works.

<a id="ruby-shell"></a>

## RUBY-SHELL. Ruby shell string

**Search:** scanner rule RUBY-SHELL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-SHELL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~ruby
system(command)
~~~

**Fix:** Use fixed executable plus separate validated argv; backticks and %x also invoke shell.

~~~ruby
system("/usr/bin/file", "--", filename)
~~~

**Verification:** Metacharacters cannot become commands; normal files work.

<a id="ruby-eval"></a>

## RUBY-EVAL. Ruby eval/ERB from data

**Search:** scanner rule RUBY-EVAL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-EVAL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~ruby
result = eval(input)
~~~

**Fix:** Use trusted templates plus values or a restricted parser instead of executing data.

~~~ruby
result = JSON.parse(input) # validate expected schema
~~~

**Verification:** Ruby syntax stays data; normal input parses.

<a id="ruby-permit-all"></a>

## RUBY-PERMIT-ALL. Rails permits all parameters

**Search:** scanner rule RUBY-PERMIT-ALL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-PERMIT-ALL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~ruby
attrs = params.permit!
~~~

**Fix:** Allowlist editable fields; choose owner/role server-side and constrain nested params separately.

~~~ruby
attrs = params.require(:note).permit(:title, :body)
~~~

**Verification:** Owner/role/unknown nested fields do not apply; valid partial edits work.

**Reference:** [primary source](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters).

<a id="ruby-constantize"></a>

## RUBY-CONSTANTIZE. String selects a Ruby class

**Search:** scanner rule RUBY-CONSTANTIZE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-CONSTANTIZE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~ruby
klass = params[:type].constantize
~~~

**Fix:** Use a fixed map of allowed DTO types; safe_constantize only changes lookup errors, not the allowed classes.

~~~ruby
klass = {"text" => TextNote}.fetch(validated_type)
~~~

**Verification:** Unknown types cannot create objects; valid types remain compatible.

**Reference:** [primary source](https://api.rubyonrails.org/classes/ActiveSupport/Inflector.html).

<a id="ruby-html-safe"></a>

## RUBY-HTML-SAFE. Ruby html_safe/raw

**Search:** scanner rule RUBY-HTML-SAFE. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-HTML-SAFE` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~ruby
value = params[:text].html_safe
~~~

**Fix:** Use context-appropriate autoescape or a sanitizer for permitted HTML; HTML data is not ERB source.

~~~ruby
value = params[:text] # render with automatic escaping
~~~

**Verification:** Tags/quotes remain text and approved formatting works.

**Reference:** [primary source](https://guides.rubyonrails.org/security.html).

<a id="ruby-sql"></a>

## RUBY-SQL. Ruby SQL interpolation

**Search:** scanner rule RUBY-SQL. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-SQL` for details. Bounded textual heuristic, not a language parser or taint analysis. Comments, strings and same-named APIs can match; inspect actual execution and trust boundaries.

**Vulnerable example:**

~~~ruby
Note.where("title = '#{title}'")
~~~

**Fix:** Bind values with the ORM/driver API; select identifiers from a server allowlist.

~~~ruby
Note.where(title: title, owner_id: current_user.id)
~~~

**Verification:** Quotes remain values and tenant/owner conditions hold.

**Reference:** [primary source](https://guides.rubyonrails.org/active_record_querying.html).

<a id="ruby-idor"></a>

## RUBY-IDOR. ActiveRecord lookup outside the owner's scope

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e '\.find\(|find_by|params\[:id\]|current_user' .
~~~

Review read/update/destroy/export and association scopes; strong parameters do not authorize an object.

**Vulnerable example:**

`Note.find(params[:id])` can retrieve any user's record.

**Fix:** Query through `current_user.notes` or an explicit policy/shared-access scope; never take the owner from request parameters.

**Verification:** Owner, other user, anonymous caller, export/deletion and intended sharing.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

<a id="ruby-path"></a>

## RUBY-PATH. Client filenames reach send_file and File.join

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'send_file|File.join|File.read|Pathname|realpath' .
~~~

Trace the filename to the open operation; join does not enforce containment, and realpath alone does not prevent TOCTOU.

**Vulnerable example:**

`send_file(params[:path])` selects an arbitrary resource.

**Fix:** Resolve a server-side storage ID after policy checks; control the root and symlinks, bound the response and set Content-Disposition.

**Verification:** Another owner's ID, absolute path, outward symlink and legitimate download.

<a id="ruby-redirect"></a>

## RUBY-REDIRECT. redirect_to accepts an external return_to

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'redirect_to|return_to|allow_other_host|url_from' .
~~~

Check the installed Rails version and open-redirect protection settings; a raw return_to value is not a trusted URL.

**Vulnerable example:**

A parameter or `allow_other_host` permits an external destination.

**Fix:** Use a server-side route map or the installed Rails version's safe redirect mechanism with host validation.

**Verification:** Internal navigation works; external origins and ambiguous paths fail.

**Reference:** [primary source](https://guides.rubyonrails.org/security.html).

<a id="ruby-csrf"></a>

## RUBY-CSRF. Rails controller disables CSRF

**Search:** scanner rule RUBY-CSRF. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-CSRF` for details. Regex: skip_forgery_protection, skip_before_action/filter :verify_authenticity_token and allow_forgery_protection=false. Review only/except conditions.

Additional manual search for forms outside automatic coverage:

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'skip_forgery_protection|skip_before_action|protect_from_forgery|csrf' .
~~~

Review controller exceptions and cookie authentication on JSON endpoints.

**Vulnerable example:**

The cookie session remains active while CSRF middleware is disabled for API convenience.

**Fix:** Restore browser CSRF; narrow exceptions to an independently authenticated stateless API/webhook.

**Verification:** Valid POST works; missing/wrong authenticity token fails; authorized webhooks work.

**Reference:** [primary source](https://guides.rubyonrails.org/security.html).

**Scanner example before:**

~~~ruby
skip_forgery_protection
skip_before_action :verify_authenticity_token
~~~

**Fix template:**

~~~ruby
protect_from_forgery with: :exception
~~~

Primary documentation: [reference 1](https://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection/ClassMethods.html).

<a id="ruby-regex-anchor"></a>

## RUBY-REGEX-ANCHOR. ^ and $ match a line inside a multiline value

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'validates|format:|Regexp|match\?|\^|\$' .
~~~

Distinguish line boundaries from whole-field boundaries; test newlines and regexp timeouts.

**Vulnerable example:**

A name validator uses ^...$ and accepts one matching line inside a larger value.

**Fix:** Use `\A` and `\z` for the whole value, plus type/length checks; explicitly define the contract if multiline input is allowed.

**Verification:** Newlines at the beginning, end and middle, plus ordinary Unicode.

**Reference:** [primary source](https://guides.rubyonrails.org/security.html).

<a id="ruby-yaml-version"></a>

## RUBY-YAML-VERSION. YAML.load behavior depends on Psych version

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'YAML.load|Psych.load|safe_load|unsafe_load|Gemfile.lock' .
~~~

Check the actual Psych/Ruby version and permitted classes/aliases; RUBY-OBJECT deliberately does not classify every load as unsafe.

**Vulnerable example:**

The application assumes new Psych's safe semantics but runs an older object-instantiating version.

**Fix:** Explicit safe_load with minimal permitted types and a schema; pin compatible dependencies locally.

**Verification:** Arbitrary classes/aliases and legitimate legacy documents on the actual runtime.

**Reference:** [primary source](https://docs.ruby-lang.org/en/3.3/Psych.html).

<a id="ruby-deserialize-cookie"></a>

## RUBY-DESERIALIZE-COOKIE. Signed cookies are not necessarily confidential

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'cookies.signed|cookies.encrypted|session\[|secret_key_base' .
~~~

Inspect cookie contents; distinguish integrity from encryption, and possession of a signing key from authorization to an object.

**Vulnerable example:**

Private text is placed in a signed cookie under the mistaken assumption that the signature hides it.

**Fix:** Use encrypted cookies or server-side session storage for confidentiality; minimize data and lifetime and plan safe key rotation.

**Verification:** Normal sessions remain readable, clients cannot see private contents, and tampering is rejected.

<a id="ruby-ssrf"></a>

## RUBY-SSRF. Client input reaches Net::HTTP or open-uri

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'Net::HTTP|URI.open|open-uri|Faraday|HTTParty' .
~~~

Find URL parsing, redirects and DNS resolution in the actual adapter.

**Vulnerable example:**

A URL or redirect reaches an internal resource using the application's trust.

**Fix:** Use a fixed destination or a unified policy for every redirect and connection, with limits; URI.parse is not authorization.

**Verification:** Mock redirects/DNS, prohibited schemes, timeouts and the legitimate upstream.

**Reference:** [primary source](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

<a id="ruby-callbacks"></a>

## RUBY-CALLBACKS. Callbacks cause effects before authorization

**Search:** manual review; no separate scanner rule.

~~~bash
rg -n --hidden -g '!vendor/**' -g '!node_modules/**' -g '!.git/**' -e 'before_save|after_save|after_commit|after_find|validate|authorize' .
~~~

Compare the ordering of policy checks, instantiation, callbacks and transaction boundaries.

**Vulnerable example:**

A model writes a file or queues a task in a callback before authorization or commit.

**Fix:** Authorize before mutation; perform external effects after confirmed commit with contractual idempotency and compensation.

**Verification:** Rollback/denial leaves no effects; repeated tasks do not duplicate results.

<a id="ruby-tls"></a>

## RUBY-TLS. Ruby HTTPS peer verification disabled

**Search:** scanner rule RUBY-TLS. Run from DurkaHelper: `python3 -I -S scripts/defense_scan.py /path/to/service --patches`; use `--explain RUBY-TLS` for details. Regex: VERIFY_NONE. Does not establish whether the object is used for a real connection.

**Vulnerable example:** VERIFY_NONE leaves the TLS connection unverified.

~~~ruby
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
~~~

**Fix:** Restore peer/hostname checks and the trusted CA; verify actual HTTP client settings.

~~~ruby
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
http.ca_file = trusted_ca_file
~~~

**Verification:** Correct server works; invalid certificates cannot yield useful responses.

Primary documentation: [reference 1](https://docs.ruby-lang.org/en/master/OpenSSL/SSL/SSLContext.html).

<a id="ruby-redirect-input"></a>

## RUBY-REDIRECT-INPUT. Rails redirect takes request params directly

**Search:** scanner rule RUBY-REDIRECT-INPUT. Use `--explain RUBY-REDIRECT-INPUT` for the exact detector contract. Regex with lexical exclusions: redirect_to with params[...] or request.params[...], with optional opening parenthesis. Framework defaults may already reject external hosts; aliases, helpers and allow_other_host configuration need review.

**Vulnerable example:**

~~~ruby
redirect_to params[:next]
~~~

**Fix:** Use server-selected routes or an explicit redirect policy; preserve Rails' host checks and review the installed framework version.

~~~ruby
redirect_to account_path
~~~

**Verification:** Foreign and scheme-relative destinations fail; legitimate navigation works.

[Primary reference 1](https://api.rubyonrails.org/classes/ActionController/Redirecting.html)
