# Contributing

English | [Русский](CONTRIBUTING-RU.md)

Start with [development and rule coverage](docs/development.md). Changes should improve defensive signal quality or operator reliability without executing scanned code or weakening offline/safety guarantees.

1. Create a focused branch and preserve unrelated work.
2. Reproduce defects with inert fixtures before fixing them.
3. Keep Python 3.10+ standard-library compatibility in the core.
4. Run the full unit suite and targeted coverage checks.
5. Update English documentation, its paired `-RU.md` translations and exact detector limitations with the code.
6. Review the [release/publication checklist](docs/release-checklist.md).

Every Markdown page has an adjacent `-RU.md` Russian translation. English remains the primary version; both are included in offline bundles. Update pairs together, keep commands, rule IDs and original section anchors unchanged, and preserve the language switch and Russian-to-Russian local links. Documentation checks verify pairs, executable examples and navigation.

Do not commit real credentials, logs, packet captures, operator profiles, target endpoints or user data. Use minimal synthetic cases; never post a working private target in an issue.

## Rules and examples

Each new or materially changed rule needs at least two independently authored positives and two safe/context-negative examples. Cover every claimed language form, comments/string examples, aliases/shadowing and safe alternatives. Before/after strings copied from rule metadata alone are not independent evidence.

Preserve existing rule IDs and explicit catalog anchors. Changed semantics must participate in report scope so incompatible scans cannot become a false-clean comparison. Describe what the rule cannot infer.

## Review and releases

Record exact source/image pins and executed platforms. Do not equate CI with target-machine, Docker Desktop, physical-client, capture or offline-stack acceptance. Follow the [security policy](SECURITY.md) for sensitive reports and retain upstream attribution.
