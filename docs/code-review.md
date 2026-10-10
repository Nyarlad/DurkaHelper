# Review an owned service

English | [Русский](code-review-RU.md)

Work on a local authorized source copy. Use the [scanner](offline-scanner.md) and [catalog](vulnerabilities/README.md) to locate concrete review points.

## Identify startup and dependencies

Evidence: `REVIEWED`; effect `READ-ONLY`; cwd the service checkout. Prerequisite: ripgrep. Expected: candidate manifests, not executed code. Output paths may be private. Rollback: none.

~~~bash
rg --files -g 'Dockerfile*' -g '*compose*' -g '*requirements*' -g '*lock*' \
  -g 'pyproject.toml' -g 'package.json' -g 'composer.json' -g 'go.mod' \
  -g 'pom.xml' -g '*gradle*' -g '*.csproj' -g 'Cargo.toml' -g 'Gemfile' \
  -g 'Makefile' -g 'CMakeLists.txt'
~~~

Trace entrypoint → process → configuration → routes → data. Never run unknown install hooks or source merely to inspect it. Compare lockfiles with the actual deployed image/runtime.

## Trace a request

1. Input source: body, URL, cookie, header, stored record, task or file.
2. Verified actor and permission for the specific object.
3. Parsing, normalization, serialization, templates and casts.
4. Sensitive operation and its actual arguments.
5. Exceptions, callbacks, awaits and alternative paths to the same operation.

Manual rg recipes identify where to start; zero matches do not establish safety. Correlate a normal owned request from approved logs/PCAP, then reproduce one invariant on an isolated copy. A denied operation must have no forbidden side effect.

After a compatible minimal patch, repeat the regression test, normal user workflow and reading of old records. Follow [deployment and rollback](patch-validation.md).
