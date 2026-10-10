# Vulnerability and remediation catalog

English | [Русский](README-RU.md)

One file per language, with SQL and configuration reviewed separately. Recipes are local and usable offline; primary references remain beside their relevant cases.

**294 sections, 174 scanner rules.** A section count is not a count of independent CWEs: language-specific implementations differ.

| Language / layer | Sections |
|---|---:|
| [Python](python.md) | 40 |
| [JavaScript / TypeScript](javascript.md) | 28 |
| [PHP](php.md) | 23 |
| [Go](go.md) | 19 |
| [Java](java.md) | 18 |
| [C# / .NET](csharp.md) | 20 |
| [C / C++](c-cpp.md) | 28 |
| [Ruby / Rails](ruby.md) | 18 |
| [Rust](rust.md) | 18 |
| [SQL / databases](sql.md) | 18 |
| [Configuration / trust boundaries](configuration.md) | 64 |

## Find and fix

1. Run the [offline scanner](../offline-scanner.md) against an authorized local service checkout.
2. Open each finding's exact section link.
3. Review manual-only language and configuration sections; their rg searches identify code to trace, not confirmed vulnerabilities.
4. Implement a compatible fix and verify owner/other-user behavior, legacy data and the competition checker. Use [patch verification](../patch-validation.md).

Every section follows **Search → Vulnerable example → Fix → Verification**.
Coverage: **174 automatic signals and 120 manual-only sections**.
Two formerly manual topics now have deliberately narrow automatic signals; their manual searches remain necessary for uncovered forms.

An empty report does not prove safety. Custom wrappers, generated code, version-specific defaults and business logic need manual review. The scanner does not import or execute the target or consult an online vulnerability feed.

## Example boundaries

Helpers such as validateOwnedResource and evaluateAllowedExpression represent logic you must implement; they are not ready-made dependencies. Patch templates are never applied automatically. Preserve normal behavior, authorization boundaries, legacy data and checker compatibility.

Keep data separate from code and arguments. A shell-free argv array still permits dangerous options accepted by the invoked program; validate the utility's own contract. A parser or type assertion is not authorization. Correct fixes may retain syntactic findings.

Historical A/D cases retain their source pins and attribution. Reviewed source semantics are not proof that every example has run under every supported language runtime. The catalog does not prescribe installing obsolete versions mentioned to explain historical behavior.

See [coverage and rule development](../development.md) for independent positive/negative fixtures and declared detector limits.
