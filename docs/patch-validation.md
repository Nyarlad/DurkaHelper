# Patch verification, deployment and rollback

English | [Русский](patch-validation-RU.md)

[Defender quick sheet](defense-cheatsheet.md) · [Catalog](vulnerabilities/README.md)

One person owns deployment for each service. All initial checks use an isolated local copy of an authorized service. Adapt production commands only after confirming its actual startup/data contract. For the ordinary manual route: preserve originals, apply one small patch, run regression/normal-user/checker tests and scan again. No cards or manually transcribed hashes are required; section 4 is an optional advanced automated evidence gate, not a prerequisite for manual patching.

## 1. Preserve the before-state

Record code revision/local diff, immutable image ID, configuration sources, current data and rollback method. These are different assets: reverting code must not restore an old database over new-round records.

Evidence: `REVIEWED`; effect `READ-ONLY`; cwd service checkout with Git. Expected: actual revision and existing modifications. Output may contain private paths; do not broadcast it. Rollback: none.

```bash
git status --short
git rev-parse HEAD
git diff --check
```

Without Git, privately copy only the files being changed with suitable backup tools; checksum verification can be automatic. Never use broad git add, reset --hard or git clean as a generic workflow. [File backup](local-tools.md#backup-and-staging-restore) is bounded, but databases require native consistent dumps or a verified stopped-copy procedure.

## 2. Required behavioral matrix

| Check | Passing result |
|---|---|
| Defect regression | The same safe-behavior test fails before and passes after |
| Normal user | Login, create/read/update and expected sharing work |
| Authorization | Owner succeeds; another user/tenant and anonymous caller fail without side effects |
| Old data | Pre-patch records retain their format and accessibility |
| Persistence | New records survive an approved isolated restart |
| Alternative paths | Lists, exports, files, jobs and affected routes enforce the same rule |
| Input boundaries | Empty/wrong-type/Unicode/maximum values follow the contract |
| Dependency failure | Bounded, sanitized failure without default authorization |
| Checker | Actual tournament semantics and SLA remain satisfied |

Check absence of forbidden effects, not only status codes: denied reads contain no foreign body, denied writes leave rows unchanged and blocked URLs never call the HTTP client. [PY-SQL](vulnerabilities/python.md#py-sql) provides a small private-note example; test route/session integration as well as its helper.

## 3. Match the deployment mechanism

| Mechanism | Required action / pitfall |
|---|---|
| Source bind mount | Update only reviewed files; restart only if the process needs it |
| Code copied into an image | Build a new pinned image and recreate the owned service; restart alone does not rebuild |
| Native binary | Verify architecture/libraries/permissions and data compatibility |
| API plus workers | Update dependent processes consistently; old workers may retain old behavior |

Inspect entrypoints for destructive initialization/migrations and locate persistent data. Do not reconfigure game networks, remove volumes or rebuild unrelated components to apply a source patch.

Before production approval, rehearse the exact rollback command on a copy. It must restore code/image while preserving current data. Keep the old image locally; a mutable latest tag is not a rollback target.

## 4. Bound evidence to this patch

Collect before/after snapshots and scans with the same intended scope, followed by health and actual regression-test records. A result reused from another run cannot establish this patch's status.

The [validation-record schema](../schemas/validation-record.v1.schema.json) uses lowercase statuses. Each record's attributes must contain the exact SHA-256 of before_snapshot, after_snapshot, before_scanner, after_scanner and health inputs under their corresponding *_sha256 keys, plus one common run_id. Record time must follow the dependent evidence.

If deployment audit is required, include its audit/model/policy hashes in the same record. The audit is recomputed from model/policy; its source hash must correspond to the exact runtime configuration captured in the after-snapshot. It checks declared configuration, not running-daemon truth.

Evidence: `REVIEWED`; effect `READ-ONLY`; cwd root. Prerequisites: genuine private evidence at the example paths, current hashes/timestamps and matching scope. Expected: 0/pass, 1/regression or 2/incomplete. Never fabricate pass records merely to satisfy this gate. Rollback: none.

```bash
python3 scripts/defense_ops.py patch-check \
  --before ../private-results/before.json --after ../private-results/after.json \
  --before-scanner ../private-results/before-scan.json \
  --after-scanner ../private-results/after-scan.json \
  --health-result ../private-results/health.json \
  --validation-record ../private-results/regression.json \
  --deployment-audit ../private-results/deployment-audit.json \
  --deployment-model ../private-deployment/run-01/runtime-model.json \
  --deployment-policy ../private-deployment/run-01/runtime-policy.json \
  --require-deployment-audit
```

For source-only changes without deployment audit, omit all four deployment arguments explicitly. Required health/scanner/validation evidence still applies. Missing, stale, partial, not-run, mismatched or incomparable evidence cannot yield a clean pass.

Expected drift needs an explicitly reviewed [approved-drift record](../schemas/approved-drift.v1.schema.json), bound to both snapshot hashes and the exact categorized changes; pass it with --approved-drift. A broad wildcard approval is not supported.

## 5. Apply, observe, revert if necessary

After explicit approval, use only the rehearsed owned-service deployment path. Immediately repeat health, actual user/checker operations and old-data reads, then monitor a full relevant round window. Preserve a sanitized incident timeline if failure occurs.

Rollback code/image first according to the recorded plan. Data restoration is a separate high-impact decision: an old dump may erase new-round data. Do not rotate keys, migrate schemas or replace runtimes as incidental fixes.
