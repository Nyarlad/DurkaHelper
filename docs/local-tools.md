# Local tools and CLI reference

English | [Русский](local-tools-RU.md)

Advanced CLI reference, Python 3.10+, standard library only. For normal setup use the [complete deployment guide](MACOS_FULL_DEPLOYMENT_AND_TESTING.md); for scanning use the [scanner reference](offline-scanner.md). Keep outputs private. See [capabilities and limits](CAPABILITY_INVENTORY.md).

## Defense operations

`scripts/defense_ops.py` 2.2.0 uses declarative [profile.v1](../schemas/profile.v1.schema.json); profiles contain no shell commands. Start from the [synthetic example](../config/defense-profile.example.json) and explicitly select your own root, files, checks and limits.


```bash
python3 scripts/defense_ops.py preflight --profile config/defense-profile.example.json
python3 scripts/defense_ops.py snapshot --profile config/defense-profile.example.json \
  --root . --output ../private-results/baseline.json
python3 scripts/defense_ops.py compare ../private-results/baseline.json ../private-results/current.json
```

Adapters cover platform, processes, listeners, services and scoped Compose metadata where supported. Missing tools/permissions or incomplete collection is partial, never evidence that nothing changed. Baseline comparison requires matching scope.

Health only checks explicitly configured HTTP GET endpoints, without ambient proxies or redirects. It validates status and bounded content, not complete application behavior.


```bash
python3 scripts/defense_ops.py health --profile config/defense-profile.example.json
```

## Backup and staging restore

Only explicitly selected regular files/trees and already-created native database dumps are copied. Live database files are not a supported backup mechanism. The tool bounds counts/bytes, checks source stability and verifies SHA-256.


```bash
python3 scripts/defense_ops.py backup create --profile config/defense-profile.example.json \
  --root . --output ../private-results/backup-01
python3 scripts/defense_ops.py backup verify ../private-results/backup-01
python3 scripts/defense_ops.py restore-stage ../private-results/backup-01 \
  --target ../private-results/restore-01
python3 scripts/defense_ops.py restore-stage ../private-results/backup-01 \
  --target ../private-results/restore-01 --apply --approval-id restore-rehearsal-01
```

The staging target must be new/empty as required by prechecks; no production overwrite exists. Symlinks, traversal, special files, tampering, unstable inputs and unsupported secure publication fail closed. Windows does not support the POSIX mutation path.

## Deployment audit

`audit-deployment` checks declared, allowlisted metadata against explicit policy: roles, image pins/architecture, ports, mounts, privileges and health/resource expectations. It does not run Compose, inspect the live daemon or parse arbitrary YAML. Use the [deployment kit](../deployment/README.md) to generate the sanitized model/policy from trusted configuration.


```bash
python3 scripts/defense_ops.py audit-deployment \
  --model ../private-deployment/run-01/runtime-model.json \
  --policy ../private-deployment/run-01/runtime-policy.json
```

Do not hand-edit the model to conceal risks. A post-build source hash binds the exact runtime Compose bytes; the policy intentionally exposes unresolved root-user, missing health and emulation issues.

## Patch evidence, timelines and export

[Patch verification](patch-validation.md) explains strict evidence binding. Validation-record statuses are lowercase schema values: pass, fail, partial, blocked, not_run and skipped_not_applicable. A not_run entry is not a pass.

Timeline accepts normalized [event.v1](../schemas/event.v1.schema.json) records, not arbitrary raw application logs. Evidence export copies only supported structured/sanitized records, excludes raw PCAP/config/credentials and verifies checksums.


```bash
python3 scripts/defense_ops.py timeline --events ../private-results/events.jsonl \
  --output ../private-results/timeline.json
python3 scripts/defense_ops.py evidence --profile config/defense-profile.example.json \
  --input ../private-results/baseline.json --output ../private-results/evidence-01
```

## Small standalone utilities

| Utility | Purpose / limits |
|---|---|
| [http_probe.py](../scripts/http_probe.py) | Explicit one-shot GETs; default four workers, three-second socket timeout, 1 MiB body; no proxies/redirects, normal TLS verification |
| [log_summary.py](../scripts/log_summary.py) | Bounded JSONL counters only; optional level/integer status fields, malformed counts, no message/header/body output |
| [backup_config.py](../scripts/backup_config.py) | Allowlisted scalar JSON fields and SHA-256; no databases, volumes or full restoration |
| [health_service.py](../lab/health_service.py) | Synthetic loopback /health and /version service |

Effect: probes `READ-ONLY`, log summary `READ-ONLY`, config backup `WORKSPACE-WRITE`. Cwd root. These are demo inputs; [start the lab](../lab/README.md) first for the probe.

```bash
python3 scripts/http_probe.py config/services.example.json
python3 scripts/log_summary.py lab/fixtures/events.jsonl
python3 scripts/backup_config.py config/backup.example.json --root lab/fixtures
```

HTTP probe exits 0/all expected responses, 1/check failure, 2/invalid configuration. Log summary exits 1 for malformed input, not merely HTTP error statuses. Config backup writes a fresh artifacts/config-backups/config-* directory; never replace a full service configuration with this partial export. A secret under an arbitrary field name cannot be detected reliably—review the allowlist and values locally.
