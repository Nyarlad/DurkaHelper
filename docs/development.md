# Development, contracts and rule coverage

English | [Русский](development-RU.md)

[Contributor guide](../CONTRIBUTING.md) · [Release checklist](release-checklist.md)

## Architecture

The core remains Python 3.10+ standard library. Source scanning, report comparison, defensive operations, packaging and synthetic integration are separate entrypoints. Never import a target service, execute its install hooks, evaluate profile shell commands or silently enable online updates.

| Area | Source of truth |
|---|---|
| Scanner behavior / metadata | [defense_scan.py](../scripts/defense_scan.py), [rule pack](../rules/defense.json) |
| Scope/context | [scope v2](../schemas/scanner-scope.v2.schema.json), [context v1](../schemas/scanner-context.v1.schema.json) |
| Operations | [defense_ops.py](../scripts/defense_ops.py), [profile](../schemas/profile.v1.schema.json), [snapshot](../schemas/snapshot.v1.schema.json), [comparison](../schemas/comparison.v1.schema.json) |
| Recovery/evidence | [backup manifest](../schemas/backup-manifest.v1.schema.json), [events](../schemas/event.v1.schema.json), [validation records](../schemas/validation-record.v1.schema.json) |
| Deployment policy | [model](../schemas/deployment-model.v1.schema.json), [policy](../schemas/deployment-policy.v1.schema.json), [audit](../schemas/deployment-audit.v1.schema.json) |
| External artifacts | [v2 complete-target/image-export manifest](../schemas/toolchain-manifest.v2.schema.json), [legacy v1 inventory](../schemas/toolchain-manifest.v1.schema.json), [pins](../config/toolchain.lock.json) |

Profiles are declarative. Platform adapters use fixed reviewed read-only commands. Invalid/partial/incomparable input exits 2; ordinary findings/check failures exit 1. New artifact writes require explicit destinations; operational mutations use explicit approval and scoped rollback.

## Add or change a rule

1. State the invariant, language-specific API and primary-source references.
2. Prefer extending an existing ID/family when semantics are the same; do not duplicate a detector to inflate counts.
3. Write English title, reason, fix, check, limitations, family, applicable CWE, review priority and signal kind. Preserve existing IDs and catalog anchors.
4. Add independently written positive and safe/context-negative strings to the fixture corpus. Every claimed language form needs at least two distinct positives and two negatives.
5. Test comments/string examples, aliases/rebinding/shadowing, similarly named user functions and safe alternatives appropriate to the engine.
6. Add/update the exact detector contract and patch guidance in the linked catalog section.
7. Run targeted tests, the ledger, the full suite and relevant platform checks.

Authored rule before/after examples do not count as independent evidence. Duplicate source strings do not increase coverage. New rules require the independent target; legacy gaps stay visible rather than receiving invented coverage.

Current inventory: 174 rules, 251 rule-language pairs and 347 independent fixture records. These numbers are not a statement that every legacy pair meets the new target.

Evidence: `REVIEWED`; effect `READ-ONLY` for coverage and temporary `WORKSPACE-WRITE` for unit tests. Cwd root; Python 3.10+ and ripgrep. Expected: no new required coverage gaps, test failures or broken local links.

```bash
python3 scripts/scanner_coverage.py --check --json
python3 -m unittest discover -s tests -v
```

Test code never executes vulnerable fixture strings. Container fixtures are separately opt-in and require an approved daemon/workspace. Expensive regex, malformed documents, oversized files, path/race failures, no-network/no-exec behavior and secret-safe output are regression requirements.

## Versioning

CLI versions identify behavior, not a promise that all deployment gates passed. Preserve backward-compatible flags and stable rule IDs. Additive outputs may require a minor version; changed meaning requires a new schema/scope contract and coordinated consumers.

Scanner 1.8.0 retains scope v2 and advances its semantic revision to bounded-source-signals.v3. Readers accept historical v2 semantics, but old/new semantic scopes are incomparable (exit 2). Rescan both sides with the same scanner/context before patch verification. Any change to scope or metadata sanitization must update defense_diff, patch-check, tests and docs together.

Toolchain manifest v2 distinguishes `complete-target` from the deliberately
partial `image-export` scope and binds completeness to the maintained deployment
contract. Historical v1 image and mixed inventories remain readable only as
partial legacy data and cannot be assembled as a full kit. Transported complete
kits require an independently retained expected manifest digest. A structurally
complete and authenticated manifest still needs an independent offline runtime
rehearsal and license review.

Human validation statuses use PASS/FAIL/PARTIAL/BLOCKED/NOT_RUN/SKIPPED_NOT_APPLICABLE; validation-record.v1 uses the lowercase equivalents. Do not coerce not_run into pass.

## Evidence and CI

Record commit/tree, platform/interpreter, tool versions, commands, scope, results and limitations. Test the exact extracted bundle, not just the checkout. Historical evidence is immutable context, not certification of a later commit.

The manual macOS ARM64 workflow is one bounded standard-runner job with minimal permissions and pinned action SHAs. It verifies architecture, core tests, CLI and packaging; it neither accesses private test hosts nor validates Docker Desktop or physical LAN clients. Use included quota only and verify spending remains disabled before dispatch.
